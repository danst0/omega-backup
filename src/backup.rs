use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{AppState, ClientConfig, Config},
    ntfy::{self, NotificationSummary, NtfyConfig},
    ssh::{self, SshConfig, count_lockfiles, remove_lockfile, set_lockfile, shutdown_server},
    wol,
};

pub struct BackupArgs {
    pub dry_run: bool,
    pub verbose: bool,
}

/// Run `omega-backup backup` — Mode 1: Client backup workflow.
pub async fn run_backup(config: &Config, args: &BackupArgs) -> Result<()> {
    if config.clients.is_empty() {
        anyhow::bail!("No clients configured. Run `omega-backup config` first.");
    }

    // Assume this machine is the first (and only) client in its own config
    let client = &config.clients[0];

    println!("Starting backup for client: {}", client.name);

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
    .context("Backup server did not come online in time")?;

    // Step 3: Set lockfile
    if !args.dry_run {
        set_lockfile(&ssh, &client.hostname)
            .await
            .context("Failed to set lockfile")?;
        tracing::info!("Set lockfile for {}", client.hostname);
    }

    let mut overall_success = true;
    let mut messages: Vec<String> = vec![];
    let mut total_duration = 0.0f64;
    let mut total_dedup = 0u64;

    // Step 4: borg create — main repo
    let main_result = run_create(config, client, &client.main_repo, args).await;
    match main_result {
        Ok(result) => {
            messages.push(format!(
                "Main backup: OK ({:.1}s, dedup {} B)",
                result.duration_secs, result.deduplicated_size
            ));
            total_duration += result.duration_secs;
            total_dedup += result.deduplicated_size;
            tracing::info!("Main backup complete: {}", result.archive_name);
        }
        Err(e) => {
            overall_success = false;
            messages.push(format!("Main backup FAILED: {e}"));
            tracing::error!("Main backup failed: {}", e);
        }
    }

    // Step 5: borg create — offsite repo (optional)
    if let Some(ref offsite) = client.offsite_repo {
        let offsite_result = run_create(config, client, offsite, args).await;
        match offsite_result {
            Ok(result) => {
                messages.push(format!(
                    "Offsite backup: OK ({:.1}s, dedup {} B)",
                    result.duration_secs, result.deduplicated_size
                ));
                total_duration += result.duration_secs;
                total_dedup += result.deduplicated_size;
                tracing::info!("Offsite backup complete: {}", result.archive_name);
            }
            Err(e) => {
                // Offsite failures are warnings, not hard errors
                messages.push(format!("Offsite backup FAILED (optional): {e}"));
                tracing::warn!("Offsite backup failed: {}", e);
            }
        }
    }

    // Step 6: Remove lockfile
    if !args.dry_run {
        let _ = remove_lockfile(&ssh, &client.hostname).await;
    }

    // Step 7: Update state
    let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let result_str = if overall_success { "success" } else { "failed" };
    if !args.dry_run {
        let mut state = AppState::load().unwrap_or_default();
        {
            let cs = state.client_mut(&client.name);
            cs.last_backup_timestamp = Some(timestamp.clone());
            cs.last_backup_result = Some(result_str.to_string());
        }
        if let Err(e) = state.save() {
            tracing::warn!("Failed to save state: {}", e);
        }
    }

    // Step 8: Send ntfy notification
    let summary_message = messages.join("\n");
    if let Some(ref ntfy_cfg) = config.ntfy {
        let summary = NotificationSummary {
            client_name: client.name.clone(),
            success: overall_success,
            message: summary_message.clone(),
            duration_secs: Some(total_duration),
            dedup_bytes: Some(total_dedup),
        };
        let ncfg = NtfyConfig {
            url: &ntfy_cfg.url,
            token: ntfy_cfg.token.as_deref(),
        };
        if let Err(e) = ntfy::send_notification(&ncfg, &summary).await {
            tracing::warn!("Failed to send ntfy notification: {}", e);
        }
    }

    // Step 9: Check lockfiles and potentially shut down server
    if !args.dry_run {
        match count_lockfiles(&ssh).await {
            Ok(0) => {
                tracing::info!("No more lockfiles — shutting down server");
                println!("All backups done — shutting down server.");
                let _ = shutdown_server(&ssh).await;
            }
            Ok(n) => {
                tracing::info!("{} lockfile(s) remaining — leaving server online", n);
                println!("{n} backup(s) still in progress — server stays online.");
            }
            Err(e) => {
                tracing::warn!("Failed to count lockfiles: {}", e);
            }
        }
    }

    // Print summary
    println!("\n=== Backup Summary ===");
    for msg in &messages {
        println!("  {msg}");
    }
    println!("  Total duration: {:.1}s", total_duration);
    println!("  Status: {}", if overall_success { "SUCCESS" } else { "FAILED" });

    if !overall_success {
        anyhow::bail!("Backup failed — see messages above");
    }

    Ok(())
}

async fn run_create(
    config: &Config,
    client: &ClientConfig,
    repo: &crate::config::RepoConfig,
    args: &BackupArgs,
) -> Result<borg::BorgCreateResult> {
    let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
        .with_ssh_key(&repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose);

    let result = borg::create(
        &ctx,
        &client.hostname,
        &repo.sources,
        &repo.compression,
        &repo.exclude_patterns,
    )
    .await
    .with_context(|| format!("borg create failed for {}", repo.path))?;

    Ok(result)
}
