use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, BorgContext, PrunePolicy},
    config::{AppState, ClientConfig, Config, OperationRecord, OperationResult, OperationType, RepoConfig},
    log_line,
    ntfy::{self, NotificationSummary, NtfyConfig},
    ssh::{self, SshConfig, count_lockfiles},
    wol, LogSender,
};

pub struct MaintenanceArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub skip_check: bool,
    pub repo: Option<String>,
}

/// Run `omega-backup maintain` — Mode 2: Management maintenance workflow.
pub async fn run_maintenance(config: &Config, args: &MaintenanceArgs, log_tx: Option<LogSender>) -> Result<()> {
    if config.clients.is_empty() {
        anyhow::bail!("No clients configured in config.");
    }

    log_line(&log_tx, "Starting maintenance run...");

    // Build SSH config (used for WoL poll, lockfiles, and shutdown check)
    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh = ssh.with_key(key);
    }

    if config.server_is_local() {
        tracing::info!("Server is local — skipping Wake-on-LAN and SSH poll");
    } else {
        // Step 1: Wake-on-LAN
        tracing::info!("Sending Wake-on-LAN to {}", config.server.host);
        wol::wake(&config.server.mac).context("Failed to send WoL packet")?;

        // Step 2: SSH poll
        log_line(&log_tx, "Waiting for backup server to come online...");
        ssh::poll_until_reachable(
            &ssh,
            Duration::from_secs(config.server.poll_interval_secs),
            Duration::from_secs(config.server.poll_timeout_secs),
        )
        .await
        .context("Backup server did not come online")?;
    }

    let mut state = AppState::load().unwrap_or_default();
    let mut overall_success = true;
    let mut report_lines: Vec<String> = vec![];

    // Step 3: Process each client
    for client in &config.clients {
        log_line(&log_tx, format!("\n--- Maintaining client: {} ---", client.name));
        let result = maintain_client(config, client, &mut state, args, &log_tx).await;
        match result {
            Ok(lines) => {
                for line in &lines {
                    log_line(&log_tx, format!("  {line}"));
                }
                report_lines.extend(lines);
            }
            Err(e) => {
                overall_success = false;
                let msg = format!("FAILED for {}: {e}", client.name);
                tracing::error!("{}", msg);
                log_line(&log_tx, format!("  {msg}"));
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

    // Step 5: Report lockfile status (shutdown is handled by the server-side watcher)
    if !args.dry_run {
        match count_lockfiles(&ssh).await {
            Ok(0) => {
                tracing::info!("No active backup lockfiles — server will auto-shut down via watcher");
                log_line(&log_tx, "\nNo active backups — server will shut down automatically.");
            }
            Ok(n) => {
                tracing::info!("{} backup lockfile(s) present — leaving server online", n);
                log_line(&log_tx, format!("\n{n} backup(s) still in progress — leaving server online."));
            }
            Err(e) => {
                tracing::warn!("Failed to count lockfiles, leaving server online: {}", e);
            }
        }
    }

    // Print summary
    log_line(&log_tx, "\n=== Maintenance Summary ===");
    for line in &report_lines {
        log_line(&log_tx, format!("  {line}"));
    }
    log_line(&log_tx, format!("  Status: {}", if overall_success { "SUCCESS" } else { "FAILED" }));

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
    log_tx: &Option<LogSender>,
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
    let needs_check = !args.skip_check && should_run_check(state, &client.name, "main", config.schedule.check_frequency_days);

    for repo in &repos {
        let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
            .with_ssh_key(&repo.ssh_key)
            .with_binary(&config.borg.binary)
            .with_dry_run(args.dry_run)
            .with_verbose(args.verbose)
            .with_lock_wait(config.borg.lock_wait_secs)
            .with_log_tx(log_tx.clone());

        let retention = repo.retention.as_ref().unwrap_or(&config.retention);
        let policy = PrunePolicy {
            keep_daily: retention.keep_daily,
            keep_weekly: retention.keep_weekly,
            keep_monthly: retention.keep_monthly,
            keep_yearly: retention.keep_yearly,
            prefix: Some(client.hostname.clone()),
        };

        // prune
        let prune_start = std::time::Instant::now();
        match borg::prune(&ctx, &policy).await {
            Ok(()) => {
                lines.push(format!("{}/{}: prune OK", client.name, repo.name));
                if !args.dry_run {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Prune,
                        timestamp: now,
                        duration_secs: Some(prune_start.elapsed().as_secs_f64()),
                        result: OperationResult::Success,
                        message: None,
                        stats: None,
                    });
                }
            }
            Err(e) if repo.optional => {
                tracing::warn!("{} prune failed (optional): {}", repo.name, e);
                lines.push(format!("{}/{}: prune WARN: {e}", client.name, repo.name));
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("prune failed for {}", repo.path)),
        }

        // compact
        let compact_start = std::time::Instant::now();
        match borg::compact(&ctx).await {
            Ok(()) => {
                lines.push(format!("{}/{}: compact OK", client.name, repo.name));
                if !args.dry_run {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Compact,
                        timestamp: now,
                        duration_secs: Some(compact_start.elapsed().as_secs_f64()),
                        result: OperationResult::Success,
                        message: None,
                        stats: None,
                    });
                }
            }
            Err(e) if repo.optional => {
                tracing::warn!("{} compact failed (optional): {}", repo.name, e);
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("compact failed for {}", repo.path)),
        }

        // check (only for non-optional repos or main repo)
        if repo.name == "main" || !repo.optional {
            let check_start = std::time::Instant::now();
            if needs_check {
                borg::check(&ctx, true)
                    .await
                    .with_context(|| format!("check failed for {}", repo.path))?;
                lines.push(format!("{}/{}: check OK", client.name, repo.name));

                if !args.dry_run {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Check,
                        timestamp: now,
                        duration_secs: Some(check_start.elapsed().as_secs_f64()),
                        result: OperationResult::Success,
                        message: Some("full".to_string()),
                        stats: None,
                    });
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

/// Run integrity check only for a specific client (ignores check_frequency_days).
pub async fn run_check_only(
    config: &Config,
    client_name: &str,
    repo_filter: Option<&str>,
    dry_run: bool,
    verbose: bool,
    log_tx: Option<LogSender>,
) -> Result<()> {
    // Find client
    let client = config
        .clients
        .iter()
        .find(|c| c.name == client_name)
        .with_context(|| format!("Client '{}' not found in config", client_name))?;

    log_line(&log_tx, format!("Starting check for client: {}", client.name));

    if !config.server_is_local() {
        // Step 1: Wake-on-LAN
        tracing::info!("Sending Wake-on-LAN to {}", config.server.host);
        wol::wake(&config.server.mac).context("Failed to send WoL packet")?;

        // Step 2: SSH poll
        let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
            .with_timeout(config.server.poll_interval_secs as u32);
        if let Some(ref key) = config.server.admin_ssh_key {
            ssh = ssh.with_key(key);
        }

        log_line(&log_tx, "Waiting for backup server to come online...");
        ssh::poll_until_reachable(
            &ssh,
            Duration::from_secs(config.server.poll_interval_secs),
            Duration::from_secs(config.server.poll_timeout_secs),
        )
        .await
        .context("Backup server did not come online")?;
    } else {
        tracing::info!("Server is local — skipping Wake-on-LAN and SSH poll");
    }

    // Step 3: Determine repos
    let repos: Vec<&RepoConfig> = match repo_filter {
        Some(name) => {
            let repo = client
                .find_repo(name)
                .with_context(|| format!("Repo '{}' not found for client '{}'", name, client.name))?;
            vec![repo]
        }
        None => client.repos.iter().collect(),
    };

    let mut state = AppState::load().unwrap_or_default();
    let mut overall_success = true;
    let mut report_lines: Vec<String> = vec![];

    // Step 4: Run full check on each repo
    for repo in &repos {
        let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
            .with_ssh_key(&repo.ssh_key)
            .with_binary(&config.borg.binary)
            .with_dry_run(dry_run)
            .with_verbose(verbose)
            .with_lock_wait(config.borg.lock_wait_secs)
            .with_log_tx(log_tx.clone());

        log_line(&log_tx, format!("  Checking {}/{}...", client.name, repo.name));
        let check_start = std::time::Instant::now();
        match borg::check(&ctx, true).await {
            Ok(()) => {
                let line = format!("{}/{}: check OK", client.name, repo.name);
                log_line(&log_tx, format!("  {line}"));
                report_lines.push(line);

                if !dry_run {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Check,
                        timestamp: now,
                        duration_secs: Some(check_start.elapsed().as_secs_f64()),
                        result: OperationResult::Success,
                        message: Some("full".to_string()),
                        stats: None,
                    });
                }
            }
            Err(e) => {
                overall_success = false;
                let line = format!("{}/{}: check FAILED: {e}", client.name, repo.name);
                tracing::error!("{}", line);
                log_line(&log_tx, format!("  {line}"));
                report_lines.push(line);

                if !dry_run {
                    let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Check,
                        timestamp: now,
                        duration_secs: Some(check_start.elapsed().as_secs_f64()),
                        result: OperationResult::Failed,
                        message: Some(format!("{e:#}")),
                        stats: None,
                    });
                }
            }
        }
    }

    // Step 5: Save state
    if !dry_run {
        if let Err(e) = state.save() {
            tracing::warn!("Failed to save state: {}", e);
        }
    }

    // Step 6: ntfy
    if let Some(ref ntfy_cfg) = config.ntfy {
        let summary = ntfy::NotificationSummary {
            client_name: client.name.clone(),
            success: overall_success,
            message: report_lines.join("\n"),
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

    log_line(&log_tx, "\n=== Check Summary ===");
    for line in &report_lines {
        log_line(&log_tx, format!("  {line}"));
    }
    log_line(&log_tx, format!("  Status: {}", if overall_success { "SUCCESS" } else { "FAILED" }));

    if !overall_success {
        anyhow::bail!("Check had failures — see messages above");
    }

    Ok(())
}

pub fn should_run_check(state: &AppState, client_name: &str, repo_name: &str, frequency_days: u32) -> bool {
    state.is_overdue(client_name, repo_name, &OperationType::Check, frequency_days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OperationRecord;

    fn days_ago(n: i64) -> String {
        (Local::now() - chrono::TimeDelta::days(n))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string()
    }

    fn record_check(state: &mut AppState, client: &str, repo: &str, timestamp: String) {
        state.record_operation(client, repo, OperationRecord {
            operation: OperationType::Check,
            timestamp,
            duration_secs: None,
            result: OperationResult::Success,
            message: None,
            stats: None,
        });
    }

    #[test]
    fn test_no_client_state_needs_check() {
        let state = AppState::default();
        assert!(should_run_check(&state, "client1", "main", 30));
    }

    #[test]
    fn test_no_check_timestamp_needs_check() {
        let mut state = AppState::default();
        // Record a backup but no check
        state.record_operation("client1", "main", OperationRecord {
            operation: OperationType::Backup,
            timestamp: days_ago(0),
            duration_secs: None,
            result: OperationResult::Success,
            message: None,
            stats: None,
        });
        assert!(should_run_check(&state, "client1", "main", 30));
    }

    #[test]
    fn test_recent_check_does_not_need_recheck() {
        let mut state = AppState::default();
        record_check(&mut state, "client1", "main", days_ago(0));
        assert!(!should_run_check(&state, "client1", "main", 30));
    }

    #[test]
    fn test_old_check_needs_recheck() {
        let mut state = AppState::default();
        record_check(&mut state, "client1", "main", "2000-01-01T00:00:00".to_string());
        assert!(should_run_check(&state, "client1", "main", 30));
    }

    #[test]
    fn test_exactly_at_boundary_needs_check() {
        let mut state = AppState::default();
        record_check(&mut state, "client1", "main", days_ago(30));
        assert!(should_run_check(&state, "client1", "main", 30));
    }

    #[test]
    fn test_one_day_before_boundary_no_check() {
        let mut state = AppState::default();
        record_check(&mut state, "client1", "main", days_ago(29));
        assert!(!should_run_check(&state, "client1", "main", 30));
    }
}
