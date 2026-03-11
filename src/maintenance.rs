use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext, PrunePolicy},
    config::{AppState, ClientConfig, Config, RepoConfig},
    ntfy::{self, NotificationSummary, NtfyConfig},
    ssh::{self, SshConfig, count_lockfiles, shutdown_server},
    wol,
};

pub struct MaintenanceArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub skip_check: bool,
    pub repo: Option<String>,
}

/// Run `omega-backup maintain` — Mode 2: Management maintenance workflow.
pub async fn run_maintenance(config: &Config, args: &MaintenanceArgs) -> Result<()> {
    if config.clients.is_empty() {
        anyhow::bail!("No clients configured in config.");
    }

    println!("Starting maintenance run...");

    // Step 1: Wake-on-LAN
    tracing::info!("Sending Wake-on-LAN to {}", config.server.host);
    wol::wake(&config.server.mac).context("Failed to send WoL packet")?;

    // Step 2: SSH poll
    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh = ssh.with_key(key);
    }

    println!("Waiting for backup server to come online...");
    ssh::poll_until_reachable(
        &ssh,
        Duration::from_secs(config.server.poll_interval_secs),
        Duration::from_secs(config.server.poll_timeout_secs),
    )
    .await
    .context("Backup server did not come online")?;

    let mut state = AppState::load().unwrap_or_default();
    let mut overall_success = true;
    let mut report_lines: Vec<String> = vec![];

    // Step 3: Process each client
    for client in &config.clients {
        println!("\n--- Maintaining client: {} ---", client.name);
        let result = maintain_client(config, client, &mut state, args).await;
        match result {
            Ok(lines) => {
                for line in &lines {
                    println!("  {line}");
                }
                report_lines.extend(lines);
            }
            Err(e) => {
                overall_success = false;
                let msg = format!("FAILED for {}: {e}", client.name);
                tracing::error!("{}", msg);
                println!("  {msg}");
                report_lines.push(msg);
            }
        }
    }

    // Save updated state
    if !args.dry_run {
        if let Err(e) = state.save() {
            tracing::warn!("Failed to save state: {}", e);
        }
    }

    // Step 4: ntfy report
    let message = report_lines.join("\n");
    if let Some(ref ntfy_cfg) = config.ntfy {
        let summary = NotificationSummary {
            client_name: "management".to_string(),
            success: overall_success,
            message: message.clone(),
            duration_secs: None,
            dedup_bytes: None,
        };
        let ncfg = NtfyConfig {
            url: &ntfy_cfg.url,
            token: ntfy_cfg.token.as_deref(),
            topic: &ntfy_cfg.topic,
        };
        if let Err(e) = ntfy::send_notification(&ncfg, &summary).await {
            tracing::warn!("Failed to send ntfy notification: {}", e);
        }
    }

    // Step 5: Shutdown server — only if no backup lockfiles are present
    if !args.dry_run {
        match count_lockfiles(&ssh).await {
            Ok(0) => {
                tracing::info!("No active backup lockfiles — shutting down server");
                println!("\nNo active backups — shutting down server.");
                let _ = shutdown_server(&ssh).await;
            }
            Ok(n) => {
                tracing::info!("{} backup lockfile(s) present — leaving server online", n);
                println!("\n{n} backup(s) still in progress — leaving server online.");
            }
            Err(e) => {
                tracing::warn!("Failed to count lockfiles, leaving server online: {}", e);
            }
        }
    }

    // Print summary
    println!("\n=== Maintenance Summary ===");
    for line in &report_lines {
        println!("  {line}");
    }
    println!("  Status: {}", if overall_success { "SUCCESS" } else { "FAILED" });

    if !overall_success {
        anyhow::bail!("Maintenance had failures — see messages above");
    }

    Ok(())
}

async fn maintain_client(
    config: &Config,
    client: &ClientConfig,
    state: &mut AppState,
    args: &MaintenanceArgs,
) -> Result<Vec<String>> {
    let mut lines = vec![];

    // Determine which repos to maintain
    let repos: Vec<&RepoConfig> = match &args.repo {
        Some(name) => {
            let repo = client.find_repo(name)
                .with_context(|| format!("Repo '{}' not found for client '{}'", name, client.name))?;
            vec![repo]
        }
        None => client.repos.iter().collect(),
    };

    // Determine if a full check is needed
    let needs_check = !args.skip_check && should_run_check(state, &client.name, config.borg.check_frequency_days);

    for repo in &repos {
        let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
            .with_ssh_key(&repo.ssh_key)
            .with_binary(&config.borg.binary)
            .with_dry_run(args.dry_run)
            .with_verbose(args.verbose)
            .with_lock_wait(config.borg.lock_wait_secs);

        let retention = repo.retention.as_ref().unwrap_or(&config.retention);
        let policy = PrunePolicy {
            keep_daily: retention.keep_daily,
            keep_weekly: retention.keep_weekly,
            keep_monthly: retention.keep_monthly,
            keep_yearly: retention.keep_yearly,
            prefix: Some(client.hostname.clone()),
        };

        // prune
        match borg::prune(&ctx, &policy).await {
            Ok(()) => lines.push(format!("{}/{}: prune OK", client.name, repo.name)),
            Err(e) if repo.optional => {
                tracing::warn!("{} prune failed (optional): {}", repo.name, e);
                lines.push(format!("{}/{}: prune WARN: {e}", client.name, repo.name));
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("prune failed for {}", repo.path)),
        }

        // compact
        match borg::compact(&ctx).await {
            Ok(()) => lines.push(format!("{}/{}: compact OK", client.name, repo.name)),
            Err(e) if repo.optional => {
                tracing::warn!("{} compact failed (optional): {}", repo.name, e);
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("compact failed for {}", repo.path)),
        }

        // check (only for non-optional repos or main repo)
        if repo.name == "main" || !repo.optional {
            if needs_check {
                borg::check(&ctx, true)
                    .await
                    .with_context(|| format!("check failed for {}", repo.path))?;
                lines.push(format!("{}/{}: check OK", client.name, repo.name));

                if !args.dry_run && repo.name == "main" {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    let cs = state.client_mut(&client.name);
                    cs.last_check_timestamp = Some(now);
                    cs.integrity_status = Some("ok".to_string());
                }
            } else {
                borg::check(&ctx, false)
                    .await
                    .with_context(|| format!("quick check failed for {}", repo.path))?;
                lines.push(format!("{}/{}: quick-check OK", client.name, repo.name));
            }
        }
    }

    Ok(lines)
}

pub(crate) fn should_run_check(state: &AppState, client_name: &str, frequency_days: u32) -> bool {
    let Some(cs) = state.client(client_name) else {
        return true; // Never checked — run check
    };
    let Some(ref last_check) = cs.last_check_timestamp else {
        return true;
    };

    // Parse timestamp
    let Ok(naive) = NaiveDateTime::parse_from_str(last_check, "%Y-%m-%dT%H:%M:%S") else {
        return true;
    };
    let last: DateTime<Local> = Local.from_local_datetime(&naive).single().unwrap_or_else(|| Local::now());
    let elapsed = Local::now().signed_duration_since(last);
    elapsed.num_days() >= frequency_days as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn days_ago(n: i64) -> String {
        (Local::now() - chrono::TimeDelta::days(n))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string()
    }

    #[test]
    fn test_no_client_state_needs_check() {
        let state = AppState::default();
        assert!(should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_no_check_timestamp_needs_check() {
        let mut state = AppState::default();
        state.client_mut("client1").last_backup_result = Some("success".to_string());
        // last_check_timestamp is None
        assert!(should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_recent_check_does_not_need_recheck() {
        let mut state = AppState::default();
        state.client_mut("client1").last_check_timestamp = Some(days_ago(0));
        assert!(!should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_old_check_needs_recheck() {
        let mut state = AppState::default();
        state.client_mut("client1").last_check_timestamp = Some("2000-01-01T00:00:00".to_string());
        assert!(should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_invalid_timestamp_needs_check() {
        let mut state = AppState::default();
        state.client_mut("client1").last_check_timestamp = Some("not-a-date".to_string());
        assert!(should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_exactly_at_boundary_needs_check() {
        let mut state = AppState::default();
        // 30 days ago: elapsed.num_days() == 30 >= 30 → true
        state.client_mut("client1").last_check_timestamp = Some(days_ago(30));
        assert!(should_run_check(&state, "client1", 30));
    }

    #[test]
    fn test_one_day_before_boundary_no_check() {
        let mut state = AppState::default();
        // 29 days ago: elapsed.num_days() == 29 < 30 → false
        state.client_mut("client1").last_check_timestamp = Some(days_ago(29));
        assert!(!should_run_check(&state, "client1", 30));
    }
}
