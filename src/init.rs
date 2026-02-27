use anyhow::{Context, Result};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{ClientConfig, Config},
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

    let ssh = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);

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

async fn init_client(config: &Config, client: &ClientConfig, dry_run: bool, verbose: bool) -> Result<()> {
    let keys_dir = config.keys_local_dir();

    // Initialize main repo
    let ctx = BorgContext::new(&client.main_repo.path, &client.main_repo.passphrase_file)
        .with_ssh_key(&client.main_repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(dry_run)
        .with_verbose(verbose);

    println!("  Initializing main repo: {}", client.main_repo.path);
    borg::init(&ctx, "repokey-blake2")
        .await
        .with_context(|| format!("Failed to init main repo for {}", client.name))?;

    // Export main key
    let main_key_path = keys_dir.join(format!("{}-main.key", client.name));
    if !dry_run {
        println!("  Exporting main repo key → {}", main_key_path.display());
        borg::export_key(&ctx, &main_key_path.display().to_string())
            .await
            .with_context(|| format!("Failed to export main key for {}", client.name))?;
    }

    // Initialize offsite repo (if configured)
    if let Some(ref offsite) = client.offsite_repo {
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
            Err(e) if offsite.optional => {
                tracing::warn!("Offsite repo init failed (optional, continuing): {}", e);
            }
            Err(e) => return Err(e).context("Offsite repo init failed"),
        }
    }

    // Print instructions
    print_post_init_instructions(client, &keys_dir);

    Ok(())
}

fn print_post_init_instructions(client: &ClientConfig, keys_dir: &std::path::Path) {
    let main_key = keys_dir.join(format!("{}-main.key", client.name));

    println!("\n  Key files:");
    println!("    {}", main_key.display());

    println!("\n  Next steps:");
    println!(
        "    # Copy passphrase to management machine (out-of-band):"
    );
    println!(
        "    scp {} mgmt:/home/admin/.borg-keys/{}-main.pass",
        client.main_repo.passphrase_file,
        client.name
    );
    println!("\n    # Push key to GitHub (optional, disaster recovery):");
    println!("    omega-backup config push-key {}", client.name);
    println!("\n    # Or sync key+passphrase via mDNS (LAN):");
    println!("    omega-backup config sync  # (management must be running `config listen`)");
    println!("\n    IMPORTANT: Keep key files safe! Without them, backups cannot be restored.");
}
