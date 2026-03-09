use anyhow::{Context, Result};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{self, ClientConfig, Config},
    ssh::{self, SshConfig},
    wol,
};

/// Run `omega-backup init [CLIENT]` — initialize borg repositories.
pub async fn run_init(config: &Config, client_filter: Option<&str>, dry_run: bool, verbose: bool) -> Result<()> {
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
    wol::wake(&config.server.mac).context("Failed to send WoL packet")?;

    let mut ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh = ssh.with_key(key);
    }

    println!("Waiting for backup server {} to come online...", config.server.host);
    ssh::poll_until_reachable(
        &ssh,
        Duration::from_secs(config.server.poll_interval_secs),
        Duration::from_secs(config.server.poll_timeout_secs),
    )
    .await
    .context("Backup server did not come online in time")?;

    // Process each client
    for client in &clients {
        println!("\n--- Initializing client: {} ---", client.name);
        init_client(config, client, dry_run, verbose).await?;
    }

    println!("\nInitialization complete. Server remains online — perform further operations as needed.");
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

/// Ensure a passphrase file exists for an offsite repo, generating one if needed.
/// Offsite repos are managed exclusively by the management host, so auto-generation is safe.
fn ensure_offsite_passphrase_file(passphrase_file: &str) -> Result<()> {
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
    println!("  Generated offsite passphrase → {}", path.display());
    Ok(())
}

async fn init_client(config: &Config, client: &ClientConfig, dry_run: bool, verbose: bool) -> Result<()> {
    let keys_dir = config.keys_local_dir();

    // Verify passphrase file exists (must be created by wizard or config sync)
    require_passphrase_file(&client.main_repo.passphrase_file, &client.name)?;

    // Initialize main repo
    let ctx = BorgContext::new(&client.main_repo.path, &client.main_repo.passphrase_file)
        .with_ssh_key(&client.main_repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(dry_run)
        .with_verbose(verbose);

    println!("  Initializing main repo: {}", client.main_repo.path);
    match borg::init(&ctx, "repokey-blake2").await {
        Ok(()) => {
            // Export main key only for newly created repos
            let main_key_path = keys_dir.join(format!("{}-main.key", client.name));
            if !dry_run {
                println!("  Exporting main repo key → {}", main_key_path.display());
                borg::export_key(&ctx, &main_key_path.display().to_string())
                    .await
                    .with_context(|| format!("Failed to export main key for {}", client.name))?;
            }
        }
        Err(e) if already_exists(&e) => {
            println!("  Main repo already exists, skipping.");
        }
        Err(e) => return Err(e).context(format!("Failed to init main repo for {}", client.name)),
    }

    // Initialize offsite repo (if configured)
    if let Some(ref offsite) = client.offsite_repo {
        ensure_offsite_passphrase_file(&offsite.passphrase_file)?;
        let offsite_ctx = BorgContext::new(&offsite.path, &offsite.passphrase_file)
            .with_ssh_key(&offsite.ssh_key)
            .with_binary(&config.borg.binary)
            .with_dry_run(dry_run)
            .with_verbose(verbose);

        println!("  Initializing offsite repo: {}", offsite.path);
        match borg::init(&offsite_ctx, "repokey-blake2").await {
            Ok(()) => {
                let offsite_key_path = keys_dir.join(format!("{}-offsite.key", client.name));
                if !dry_run {
                    println!("  Exporting offsite repo key → {}", offsite_key_path.display());
                    borg::export_key(&offsite_ctx, &offsite_key_path.display().to_string())
                        .await
                        .with_context(|| format!("Failed to export offsite key for {}", client.name))?;
                }
            }
            Err(e) if already_exists(&e) => {
                println!("  Offsite repo already exists, skipping.");
            }
            Err(e) if offsite.optional => {
                tracing::warn!("Offsite repo init failed (optional, continuing): {}", e);
            }
            Err(e) => return Err(e).context("Offsite repo init failed"),
        }
    }

    Ok(())
}

/// Check if a borg error indicates the repository already exists.
fn already_exists(err: &anyhow::Error) -> bool {
    format!("{err}").contains("A repository already exists")
}
