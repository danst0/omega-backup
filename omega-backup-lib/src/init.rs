use anyhow::{Context, Result};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{self, ClientConfig, Config, RepoBackend},
    log_line,
    restic::{self, ResticContext},
    ssh::{self, SshConfig},
    wol, LogSender,
};

/// Run `omega-backup init [CLIENT]` — initialize borg repositories.
pub async fn run_init(config: &Config, client_filter: Option<&str>, dry_run: bool, verbose: bool, install_cron: bool, log_tx: Option<LogSender>) -> Result<()> {
    let clients: Vec<&ClientConfig> = if let Some(name) = client_filter {
        let client = config
            .find_client(name)
            .with_context(|| format!("Client '{}' not found in config", name))?;
        vec![client]
    } else {
        config.clients.iter().collect()
    };

    if clients.is_empty() {
        anyhow::bail!("No clients configured. Run `omega-backup config` first.");
    }

    // Wake the server once for all clients
    tracing::info!("Sending Wake-on-LAN to {}", config.server.host);
    wol::wake(&config.server.mac, &config.server.broadcast).context("Failed to send WoL packet")?;

    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh = ssh.with_key(key);
    }

    log_line(&log_tx, format!("Waiting for backup server {} to come online...", config.server.host));
    ssh::poll_until_reachable(
        &ssh,
        Duration::from_secs(config.server.poll_interval_secs),
        Duration::from_secs(config.server.poll_timeout_secs),
    )
    .await
    .context("Backup server did not come online in time")?;

    // Process each client
    for client in &clients {
        log_line(&log_tx, format!("\n--- Initializing client: {} ---", client.name));
        init_client(config, client, dry_run, verbose, &log_tx).await?;
    }

    log_line(&log_tx, "\nInitialization complete. Server remains online — perform further operations as needed.");

    if install_cron && !dry_run {
        log_line(&log_tx, format!("\nInstalling shutdown watcher cron job on {}...", config.server.host));
        ssh::install_shutdown_watcher(&ssh, config.server.shutdown_idle_minutes)
            .await
            .context("Failed to install shutdown watcher")?;
        log_line(&log_tx, format!(
            "Shutdown watcher installed (idle threshold: {} min). \
             The server will auto-shut down after {} minutes with no active backups.",
            config.server.shutdown_idle_minutes, config.server.shutdown_idle_minutes
        ));
    } else if install_cron && dry_run {
        log_line(&log_tx, format!("\n[dry-run] Would install shutdown watcher cron job on {}.", config.server.host));
    }

    Ok(())
}

/// Verify that a passphrase file exists for a main repo.
/// Main repo passphrases must be created beforehand — either by the client wizard
/// (`omega-backup config`) or received via `omega-backup config sync`.
fn require_passphrase_file(passphrase_file: &str, client_name: &str) -> Result<()> {
    let path = config::expand_tilde(passphrase_file);
    if path.exists() {
        return Ok(());
    }
    anyhow::bail!(
        "Passphrase file not found: {}\n\
         Run 'omega-backup config sync' on {client_name} first, \
         or 'omega-backup config' if this is the management host.",
        path.display()
    );
}

/// Ensure a passphrase file exists for a non-main repo, generating one if needed.
/// Non-main repos are managed exclusively by the management host, so auto-generation is safe.
fn ensure_passphrase_file(passphrase_file: &str) -> Result<()> {
    let path = config::expand_tilde(passphrase_file);
    if path.exists() {
        return Ok(());
    }
    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    // Generate 32 random bytes → 64-char hex string
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    let passphrase = hex::encode(bytes);
    std::fs::write(&path, &passphrase)
        .with_context(|| format!("Failed to write passphrase file: {}", path.display()))?;
    // Restrict permissions to owner only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    // This is only called during init, log to stdout (no log_tx available here)
    println!("  Generated passphrase → {}", path.display());
    Ok(())
}

async fn init_client(config: &Config, client: &ClientConfig, dry_run: bool, verbose: bool, log_tx: &Option<LogSender>) -> Result<()> {
    let keys_dir = config.keys_local_dir();

    for repo in &client.repos {
        if repo.name == "main" {
            // Main repo passphrase must already exist
            require_passphrase_file(repo.backend.password_file(), &client.name)?;
        } else {
            // Non-main repos: auto-generate passphrase if missing
            ensure_passphrase_file(repo.backend.password_file())?;
        }

        log_line(log_tx, format!("  Initializing {} repo: {}", repo.name, repo.backend.repo_path()));

        match &repo.backend {
            RepoBackend::Borg { path, passphrase_file, ssh_key, .. } => {
                let ctx = BorgContext::new(path, passphrase_file)
                    .with_ssh_key(ssh_key)
                    .with_binary(&config.borg.binary)
                    .with_dry_run(dry_run)
                    .with_verbose(verbose)
                    .with_lock_wait(config.borg.lock_wait_secs);

                match borg::init(&ctx, "repokey-blake2").await {
                    Ok(()) => {
                        let key_path = keys_dir.join(format!("{}-{}.key", client.name, repo.name));
                        if !dry_run {
                            log_line(log_tx, format!("  Exporting {} repo key → {}", repo.name, key_path.display()));
                            borg::export_key(&ctx, &key_path.display().to_string())
                                .await
                                .with_context(|| format!("Failed to export key for {}/{}", client.name, repo.name))?;
                        }
                    }
                    Err(e) if already_exists(&e) => {
                        log_line(log_tx, format!("  {} repo already exists, skipping.", repo.name));
                    }
                    Err(e) if repo.optional => {
                        tracing::warn!("{} repo init failed (optional, continuing): {}", repo.name, e);
                    }
                    Err(e) => return Err(e).context(format!("Failed to init {} repo for {}", repo.name, client.name)),
                }
            }
            RepoBackend::Restic { repo: restic_repo, password_file, rclone_config, extra_flags } => {
                let mut ctx = ResticContext::new(restic_repo, password_file)
                    .with_binary(&config.restic.binary)
                    .with_dry_run(dry_run)
                    .with_verbose(verbose);
                if let Some(rc) = rclone_config {
                    ctx = ctx.with_rclone_config(rc);
                }
                for flag in extra_flags {
                    ctx = ctx.with_extra_flag(flag);
                }

                match restic::init(&ctx).await {
                    Ok(()) => {
                        log_line(log_tx, format!("  {} restic repo initialized.", repo.name));
                    }
                    Err(e) if format!("{e}").contains("already initialized") => {
                        log_line(log_tx, format!("  {} repo already exists, skipping.", repo.name));
                    }
                    Err(e) if repo.optional => {
                        tracing::warn!("{} repo init failed (optional, continuing): {}", repo.name, e);
                    }
                    Err(e) => return Err(e).context(format!("Failed to init {} repo for {}", repo.name, client.name)),
                }
            }
        }
    }

    Ok(())
}

/// Check if a borg error indicates the repository already exists.
fn already_exists(err: &anyhow::Error) -> bool {
    format!("{err}").contains("A repository already exists")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_already_exists_matches_borg_message() {
        let err = anyhow::anyhow!("A repository already exists at /mnt/backup/repo");
        assert!(already_exists(&err));
    }

    #[test]
    fn test_already_exists_does_not_match_other_errors() {
        let err = anyhow::anyhow!("Permission denied: /mnt/backup/repo");
        assert!(!already_exists(&err));
    }

    #[test]
    fn test_already_exists_empty_message() {
        let err = anyhow::anyhow!("");
        assert!(!already_exists(&err));
    }

    #[test]
    fn test_already_exists_partial_phrase_does_not_match() {
        // "already exists" without "A repository" prefix
        let err = anyhow::anyhow!("File already exists");
        assert!(!already_exists(&err));
    }

    #[test]
    fn test_already_exists_exact_phrase() {
        let err = anyhow::anyhow!("A repository already exists");
        assert!(already_exists(&err));
    }
}
