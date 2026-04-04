use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{AppState, BackupStats, ClientConfig, Config, OperationRecord, OperationResult, OperationType, RepoBackend, RepoConfig},
    restic::{self, ResticContext},
    ntfy::{self, NotificationSummary, NtfyConfig},
    ssh::{self, SshConfig, count_lockfiles, remove_lockfile, set_lockfile},
    wol,
};

pub struct BackupArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub repo: Option<String>,
}

/// Run `omega-backup backup` — Mode 1: Client backup workflow.
pub async fn run_backup(config: &Config, args: &BackupArgs) -> Result<()> {
    if config.clients.is_empty() {
        anyhow::bail!("No clients configured. Run `omega-backup config` first.");
    }

    // Find the client entry for this machine by matching hostname
    let local_hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();

    let client = config
        .clients
        .iter()
        .find(|c| !c.hostname.is_empty() && c.hostname == local_hostname)
        .or_else(|| config.clients.first())
        .context("No client configured for this machine")?;

    if client.hostname.is_empty() {
        anyhow::bail!(
            "Client '{}' has an empty hostname. This looks like a management config — \
             run `omega-backup config` on the client machine to generate a proper client config.",
            client.name
        );
    }

    let main_repo = client.main_repo().context(
        format!("Client '{}' has no main repo configured.", client.name)
    )?;
    if main_repo.sources.is_empty() {
        anyhow::bail!(
            "Client '{}' has no backup sources configured. \
             Add sources to the main repo in config.toml.",
            client.name
        );
    }

    // Resolve which repos to back up
    let repos: Vec<&RepoConfig> = match &args.repo {
        Some(name) => {
            let repo = client.find_repo(name)
                .with_context(|| format!("Repo '{}' not found for client '{}'", name, client.name))?;
            vec![repo]
        }
        None => client.repos.iter().collect(),
    };

    println!("Starting backup for client: {}", client.name);

    let has_borg_repos = repos.iter().any(|r| r.is_borg());

    // Build SSH config (used for WoL poll, lockfiles, and shutdown check)
    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(10);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh = ssh.with_key(key);
    }

    if has_borg_repos {
        if config.server_is_local() {
            tracing::info!("Server is local — skipping Wake-on-LAN and SSH poll");
        } else {
            // Step 1: Wake-on-LAN
            tracing::info!("Sending Wake-on-LAN to {}", config.server.host);
            wol::wake(&config.server.mac, &config.server.broadcast).context("Failed to send WoL packet")?;

            // Step 2: SSH poll
            println!("Waiting for backup server to come online...");
            ssh::poll_until_reachable(
                &ssh,
                Duration::from_secs(config.server.poll_interval_secs),
                Duration::from_secs(config.server.poll_timeout_secs),
            )
            .await
            .context("Backup server did not come online in time")?;
        }

        // Step 3: Set lockfile
        if !args.dry_run {
            set_lockfile(&ssh, &client.hostname)
                .await
                .context("Failed to set lockfile")?;
            tracing::info!("Set lockfile for {}", client.hostname);
        }
    } else {
        tracing::info!("No borg repos selected — skipping WoL/SSH/lockfile");
    }

    let mut overall_success = true;
    let mut messages: Vec<String> = vec![];
    let mut total_duration = 0.0f64;
    let mut total_dedup = 0u64;
    let mut state = AppState::load().unwrap_or_default();

    // Step 4: backup each selected repo (borg or restic)
    for repo in &repos {
        let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();

        let backup_result: Result<(f64, BackupStats, String)> = match &repo.backend {
            RepoBackend::Borg { .. } => {
                run_borg_create(config, client, repo, args).await.map(|r| {
                    let label = r.archive_name.clone();
                    (r.duration_secs, BackupStats {
                        original_size: r.original_size,
                        compressed_size: r.compressed_size,
                        deduplicated_size: r.deduplicated_size,
                        archive_name: Some(r.archive_name),
                        files_new: None,
                        files_changed: None,
                        data_added: None,
                        snapshot_id: None,
                    }, label)
                })
            }
            RepoBackend::Restic { .. } => {
                run_restic_backup(config, repo, args).await.map(|r| {
                    let label = r.snapshot_id.clone();
                    (r.duration_secs, BackupStats {
                        original_size: 0,
                        compressed_size: 0,
                        deduplicated_size: 0,
                        archive_name: None,
                        files_new: Some(r.files_new),
                        files_changed: Some(r.files_changed),
                        data_added: Some(r.data_added),
                        snapshot_id: Some(r.snapshot_id),
                    }, label)
                })
            }
        };

        match backup_result {
            Ok((duration, stats, label)) => {
                let size_info = if stats.deduplicated_size > 0 {
                    format!("dedup {} B", stats.deduplicated_size)
                } else {
                    format!("added {} B", stats.data_added.unwrap_or(0))
                };
                messages.push(format!(
                    "{} backup: OK ({:.1}s, {})",
                    repo.name, duration, size_info
                ));
                total_duration += duration;
                total_dedup += stats.deduplicated_size.max(stats.data_added.unwrap_or(0));
                tracing::info!("{} backup complete: {}", repo.name, label);

                if !args.dry_run {
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Backup,
                        timestamp,
                        duration_secs: Some(duration),
                        result: OperationResult::Success,
                        message: None,
                        stats: Some(stats),
                    });
                }
            }
            Err(e) => {
                if repo.optional {
                    messages.push(format!("{} backup FAILED (optional): {e:#}", repo.name));
                    tracing::warn!("{} backup failed (optional): {}", repo.name, e);
                } else {
                    overall_success = false;
                    messages.push(format!("{} backup FAILED: {e:#}", repo.name));
                    tracing::error!("{} backup failed: {}", repo.name, e);
                }

                if !args.dry_run {
                    state.record_operation(&client.name, &repo.name, OperationRecord {
                        operation: OperationType::Backup,
                        timestamp,
                        duration_secs: None,
                        result: if repo.optional { OperationResult::Warning } else { OperationResult::Failed },
                        message: Some(format!("{e:#}")),
                        stats: None,
                    });
                }
            }
        }
    }

    // Step 5: Remove lockfile
    if has_borg_repos && !args.dry_run {
        let _ = remove_lockfile(&ssh, &client.hostname).await;
    }

    // Step 6: Save state
    if !args.dry_run {
        if let Err(e) = state.save() {
            tracing::warn!("Failed to save state: {}", e);
        }
    }

    // Step 7: Send ntfy notification
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
            topic: &ntfy_cfg.topic,
        };
        if let Err(e) = ntfy::send_notification(&ncfg, &summary).await {
            tracing::warn!("Failed to send ntfy notification: {}", e);
        }
    }

    // Step 8: Report lockfile status (shutdown is handled by the server-side watcher)
    if has_borg_repos && !args.dry_run {
        match count_lockfiles(&ssh).await {
            Ok(0) => {
                tracing::info!("No more lockfiles — server will auto-shut down via watcher");
                println!("All backups done — server will shut down automatically.");
            }
            Ok(n) => {
                tracing::info!("{} lockfile(s) remaining — server stays online", n);
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

async fn run_hook_commands(label: &str, commands: &[String], abort_on_failure: bool) -> Result<()> {
    for cmd_str in commands {
        tracing::info!("[hook:{}] Running: {}", label, cmd_str);
        let output = tokio::process::Command::new("sh")
            .args(["-c", cmd_str])
            .output()
            .await
            .with_context(|| format!("[hook:{}] Failed to spawn: {}", label, cmd_str))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines() {
            tracing::info!("[hook:{}] stdout: {}", label, line);
        }
        for line in stderr.lines() {
            tracing::info!("[hook:{}] stderr: {}", label, line);
        }

        let code = output.status.code().unwrap_or(-1);
        if code != 0 {
            let msg = format!(
                "[hook:{}] Command exited with code {}: {}",
                label, code, cmd_str
            );
            if abort_on_failure {
                anyhow::bail!("{}", msg);
            } else {
                tracing::warn!("{}", msg);
            }
        }
    }
    Ok(())
}

async fn run_borg_create(
    config: &Config,
    client: &ClientConfig,
    repo: &RepoConfig,
    args: &BackupArgs,
) -> Result<borg::BorgCreateResult> {
    let ctx = BorgContext::new(repo.path(), repo.passphrase_file())
        .with_ssh_key(repo.ssh_key())
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose)
        .with_lock_wait(config.borg.lock_wait_secs);

    if !args.dry_run {
        if let Some(ref cmds) = repo.pre_create_commands {
            run_hook_commands(&format!("pre:{}", repo.name), cmds, true)
                .await
                .with_context(|| format!("Pre-create hook failed for repo '{}'", repo.name))?;
        }
    }

    let borg_result = borg::create(
        &ctx,
        &client.hostname,
        &repo.sources,
        repo.compression(),
        &repo.exclude_patterns,
        &repo.exclude_patterns_from,
        &repo.exclude_if_present,
        repo.borg_filter(),
    )
    .await
    .with_context(|| format!("borg create failed for {}", repo.path()));

    if !args.dry_run {
        if let Some(ref cmds) = repo.post_create_commands {
            let _ = run_hook_commands(&format!("post:{}", repo.name), cmds, false).await;
        }
    }

    borg_result
}

async fn run_restic_backup(
    config: &Config,
    repo: &RepoConfig,
    args: &BackupArgs,
) -> Result<restic::ResticBackupResult> {
    let (restic_repo, password_file, rclone_config, extra_flags) = match &repo.backend {
        RepoBackend::Restic { repo: r, password_file, rclone_config, extra_flags } => {
            (r.as_str(), password_file.as_str(), rclone_config.as_deref(), extra_flags.clone())
        }
        _ => anyhow::bail!("run_restic_backup called on non-restic repo"),
    };

    let mut ctx = ResticContext::new(restic_repo, password_file)
        .with_binary(&config.restic.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose);
    if let Some(rc) = rclone_config {
        ctx = ctx.with_rclone_config(rc);
    }
    for flag in &extra_flags {
        ctx = ctx.with_extra_flag(flag);
    }

    if !args.dry_run {
        if let Some(ref cmds) = repo.pre_create_commands {
            run_hook_commands(&format!("pre:{}", repo.name), cmds, true)
                .await
                .with_context(|| format!("Pre-create hook failed for repo '{}'", repo.name))?;
        }
    }

    let result = restic::backup(
        &ctx,
        &repo.sources,
        &repo.exclude_patterns,
        &repo.exclude_patterns_from,
        &repo.exclude_if_present,
    )
    .await
    .with_context(|| format!("restic backup failed for {}", restic_repo));

    if !args.dry_run {
        if let Some(ref cmds) = repo.post_create_commands {
            let _ = run_hook_commands(&format!("post:{}", repo.name), cmds, false).await;
        }
    }

    result
}
