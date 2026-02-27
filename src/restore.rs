use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::Config,
    ssh::{self, SshConfig},
    wol,
};

pub struct RestoreArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub list_count: usize,
    pub extract: bool,
    pub archive: Option<String>,
    pub paths: Vec<String>,
}

/// Run `omega-backup restore-test CLIENT` — Mode 3: Restore test workflow.
pub async fn run_restore_test(config: &Config, client_name: &str, args: &RestoreArgs) -> Result<()> {
    let client = config
        .find_client(client_name)
        .with_context(|| format!("Client '{}' not found in config", client_name))?;

    println!("Starting restore test for client: {}", client.name);

    // Step 1: Wake-on-LAN (server may be offline)
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

    let ctx = BorgContext::new(&client.main_repo.path, &client.main_repo.passphrase_file)
        .with_ssh_key(&client.main_repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose);

    // Step 3: List archives
    println!("\nListing the last {} archive(s):", args.list_count);
    let archives = borg::list(&ctx, args.list_count)
        .await
        .context("Failed to list archives")?;

    if archives.is_empty() {
        anyhow::bail!("No archives found in repository: {}", client.main_repo.path);
    }

    for (i, archive) in archives.iter().enumerate() {
        println!("  [{}] {}", i, archive.name);
    }

    // Determine which archive to use
    let archive_name = if let Some(ref name) = args.archive {
        name.clone()
    } else {
        // Use the most recent (last in list)
        archives.last().unwrap().name.clone()
    };

    println!("\nUsing archive: {archive_name}");

    // Step 4: Dry-run extract to verify integrity
    println!("Running dry-run extract (integrity check)...");
    borg::extract(&ctx, &archive_name, &args.paths, None, true)
        .await
        .with_context(|| format!("Dry-run extract failed for archive: {archive_name}"))?;
    println!("Dry-run extract: OK");

    // Step 5: Optional real extract
    if args.extract {
        let timestamp = Local::now().format("%Y%m%dT%H%M%S").to_string();
        let dest = format!("./restore-{timestamp}");
        println!("\nExtracting to: {dest}");

        borg::extract(&ctx, &archive_name, &args.paths, Some(&dest), false)
            .await
            .with_context(|| format!("Extract failed for archive: {archive_name}"))?;

        println!("Extract complete → {dest}");
    }

    println!("\n=== Restore Test Summary ===");
    println!("  Client: {}", client.name);
    println!("  Archive: {archive_name}");
    println!("  Dry-run extract: PASSED");
    if args.extract {
        println!("  Full extract: DONE");
    }
    println!("  Status: SUCCESS");
    println!("\nServer remains online — no automatic shutdown.");

    Ok(())
}
