use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext, PrunePolicy},
    config::{AppState, ClientConfig, Config},
    ntfy::{self, NotificationSummary, NtfyConfig},
    ssh::{self, SshConfig, shutdown_server},
    wol,
};

pub struct MaintenanceArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub skip_check: bool,
    pub offsite: bool,
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
    let ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);

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
        };
        if let Err(e) = ntfy::send_notification(&ncfg, &summary).await {
            tracing::warn!("Failed to send ntfy notification: {}", e);
        }
    }

    // Step 5: Shutdown server
    if !args.dry_run {
        println!("\nShutting down server...");
        let _ = shutdown_server(&ssh).await;
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

    // Determine if a full check is needed
    let needs_check = !args.skip_check && should_run_check(state, &client.name, config.borg.check_frequency_days);

    // Main repo maintenance
    let main_ctx = BorgContext::new(&client.main_repo.path, &client.main_repo.passphrase_file)
        .with_ssh_key(&client.main_repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose);

    let policy = PrunePolicy {
        keep_daily: config.retention.keep_daily,
        keep_weekly: config.retention.keep_weekly,
        keep_monthly: config.retention.keep_monthly,
        keep_yearly: config.retention.keep_yearly,
        prefix: Some(client.hostname.clone()),
    };

    // prune
    borg::prune(&main_ctx, &policy)
        .await
        .with_context(|| format!("prune failed for {}", client.main_repo.path))?;
    lines.push(format!("{}: prune OK", client.name));

    // compact
    borg::compact(&main_ctx)
        .await
        .with_context(|| format!("compact failed for {}", client.main_repo.path))?;
    lines.push(format!("{}: compact OK", client.name));

    // check
    if needs_check {
        borg::check(&main_ctx, true)
            .await
            .with_context(|| format!("check failed for {}", client.main_repo.path))?;
        lines.push(format!("{}: check OK", client.name));

        if !args.dry_run {
            let now = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
            let cs = state.client_mut(&client.name);
            cs.last_check_timestamp = Some(now);
            cs.integrity_status = Some("ok".to_string());
        }
    } else {
        // Quick repo-level check
        borg::check(&main_ctx, false)
            .await
            .with_context(|| format!("quick check failed for {}", client.main_repo.path))?;
        lines.push(format!("{}: quick-check OK", client.name));
    }

    // Offsite repo maintenance (if enabled)
    if args.offsite {
        if let Some(ref offsite) = client.offsite_repo {
            let offsite_ctx = BorgContext::new(&offsite.path, &offsite.passphrase_file)
                .with_ssh_key(&offsite.ssh_key)
                .with_binary(&config.borg.binary)
                .with_dry_run(args.dry_run)
                .with_verbose(args.verbose);

            let offsite_retention = config.offsite_retention.as_ref().unwrap_or(&config.retention);
            let offsite_policy = PrunePolicy {
                keep_daily: offsite_retention.keep_daily,
                keep_weekly: offsite_retention.keep_weekly,
                keep_monthly: offsite_retention.keep_monthly,
                keep_yearly: offsite_retention.keep_yearly,
                prefix: Some(client.hostname.clone()),
            };

            match borg::prune(&offsite_ctx, &offsite_policy).await {
                Ok(()) => lines.push(format!("{}: offsite prune OK", client.name)),
                Err(e) if offsite.optional => {
                    tracing::warn!("Offsite prune failed (optional): {}", e);
                    lines.push(format!("{}: offsite prune WARN: {e}", client.name));
                }
                Err(e) => return Err(e).context("Offsite prune failed"),
            }

            match borg::compact(&offsite_ctx).await {
                Ok(()) => lines.push(format!("{}: offsite compact OK", client.name)),
                Err(e) if offsite.optional => {
                    tracing::warn!("Offsite compact failed (optional): {}", e);
                }
                Err(e) => return Err(e).context("Offsite compact failed"),
            }
        }
    }

    Ok(lines)
}

fn should_run_check(state: &AppState, client_name: &str, frequency_days: u32) -> bool {
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
