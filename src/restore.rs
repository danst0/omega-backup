use anyhow::{Context, Result};
use chrono::Local;
use std::time::Duration;

use crate::{
    borg::{self, ArchiveInfo, BorgContext},
    config::Config,
    ssh::{self, SshConfig},
    wol,
};

pub struct RestoreArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub repo: String,
    pub list_count: usize,
    pub extract: bool,
    pub archive: Option<String>,
    pub paths: Vec<String>,
}

/// Select an archive from a list, either by explicit name or defaulting to the most recent.
pub fn select_archive<'a>(archives: &'a [ArchiveInfo], override_name: Option<&str>) -> Result<&'a ArchiveInfo> {
    if archives.is_empty() {
        anyhow::bail!("No archives available to select from");
    }
    if let Some(name) = override_name {
        archives
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("Archive '{name}' not found"))
    } else {
        // Most recent is the last entry returned by `borg list --last`
        Ok(archives.last().unwrap())
    }
}

/// Run `omega-backup restore-test CLIENT` — Mode 3: Restore test workflow.
pub async fn run_restore_test(config: &Config, client_name: &str, args: &RestoreArgs) -> Result<()> {
    let client = config
        .find_client(client_name)
        .with_context(|| format!("Client '{}' not found in config", client_name))?;

    let repo = client.find_repo(&args.repo)
        .with_context(|| format!("Repo '{}' not found for client '{}'", args.repo, client_name))?;

    println!("Starting restore test for client: {} (repo: {})", client.name, repo.name);

    // Step 1: Wake-on-LAN (server may be offline)
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

    let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
        .with_ssh_key(&repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose)
        .with_lock_wait(config.borg.lock_wait_secs);

    // Step 3: List archives
    println!("\nListing the last {} archive(s):", args.list_count);
    let archives = borg::list(&ctx, args.list_count)
        .await
        .context("Failed to list archives")?;

    if archives.is_empty() {
        anyhow::bail!("No archives found in repository: {}", repo.path);
    }

    for (i, archive) in archives.iter().enumerate() {
        println!("  [{}] {}", i, archive.name);
    }

    // Determine which archive to use
    let selected = select_archive(&archives, args.archive.as_deref())
        .with_context(|| format!("Failed to select archive for repo: {}", repo.path))?;
    let archive_name = selected.name.clone();

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
    println!("  Repo: {}", repo.name);
    println!("  Archive: {archive_name}");
    println!("  Dry-run extract: PASSED");
    if args.extract {
        println!("  Full extract: DONE");
    }
    println!("  Status: SUCCESS");
    println!("\nServer remains online — no automatic shutdown.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borg::ArchiveInfo;

    fn make_archive(name: &str) -> ArchiveInfo {
        ArchiveInfo { name: name.to_string(), date: "2026-01-01".to_string() }
    }

    #[test]
    fn test_select_archive_by_name() {
        let archives = vec![
            make_archive("host-2026-01-01T00:00:00"),
            make_archive("host-2026-01-02T00:00:00"),
            make_archive("host-2026-01-03T00:00:00"),
        ];
        let selected = select_archive(&archives, Some("host-2026-01-02T00:00:00")).unwrap();
        assert_eq!(selected.name, "host-2026-01-02T00:00:00");
    }

    #[test]
    fn test_select_archive_defaults_to_last() {
        let archives = vec![
            make_archive("host-2026-01-01T00:00:00"),
            make_archive("host-2026-01-02T00:00:00"),
            make_archive("host-2026-01-03T00:00:00"),
        ];
        let selected = select_archive(&archives, None).unwrap();
        assert_eq!(selected.name, "host-2026-01-03T00:00:00");
    }

    #[test]
    fn test_select_archive_single_entry() {
        let archives = vec![make_archive("only-archive")];
        let selected = select_archive(&archives, None).unwrap();
        assert_eq!(selected.name, "only-archive");
    }

    #[test]
    fn test_select_archive_empty_list_errors() {
        let result = select_archive(&[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No archives"));
    }

    #[test]
    fn test_select_archive_unknown_name_errors() {
        let archives = vec![make_archive("archive-a"), make_archive("archive-b")];
        let result = select_archive(&archives, Some("archive-c"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("archive-c"));
    }
}
