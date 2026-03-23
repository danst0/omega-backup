use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{AppState, ClientConfig, Config, RepoConfig},
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

    // Build SSH config (used for WoL poll, lockfiles, and shutdown check)
    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(10);
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

    let mut overall_success = true;
    let mut messages: Vec<String> = vec![];
    let mut total_duration = 0.0f64;
    let mut total_dedup = 0u64;

    // Step 4: borg create for each selected repo
    for repo in &repos {
        let result = run_create(config, client, repo, args).await;
        match result {
            Ok(create_result) => {
                messages.push(format!(
                    "{} backup: OK ({:.1}s, dedup {} B)",
                    repo.name, create_result.duration_secs, create_result.deduplicated_size
                ));
                total_duration += create_result.duration_secs;
                total_dedup += create_result.deduplicated_size;
                tracing::info!("{} backup complete: {}", repo.name, create_result.archive_name);
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
            }
        }
    }

    // Step 5: Remove lockfile
    if !args.dry_run {
        let _ = remove_lockfile(&ssh, &client.hostname).await;
    }

    // Step 6: Update state
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
    if !args.dry_run {
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

async fn run_create(
    config: &Config,
    client: &ClientConfig,
    repo: &RepoConfig,
    args: &BackupArgs,
) -> Result<borg::BorgCreateResult> {
    let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
        .with_ssh_key(&repo.ssh_key)
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
        &repo.compression,
        &repo.exclude_patterns,
        &repo.exclude_patterns_from,
        &repo.exclude_if_present,
        repo.borg_filter.as_deref(),
    )
    .await
    .with_context(|| format!("borg create failed for {}", repo.path));

    if !args.dry_run {
        if let Some(ref cmds) = repo.post_create_commands {
            let _ = run_hook_commands(&format!("post:{}", repo.name), cmds, false).await;
        }
    }

    borg_result
}
