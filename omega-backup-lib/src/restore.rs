use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use std::time::Duration;

use crate::{
    borg::{self, ArchiveInfo, BorgContext},
    config::Config,
    log_line,
    ssh::{self, SshConfig},
    wol, LogSender,
};

pub struct RestoreArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub repo: String,
    pub list_count: usize,
    pub sample_count: usize,
    pub archive: Option<String>,
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

/// Run `omega-backup restore-test CLIENT` — Mode 3: Spot-check restore test.
///
/// Instead of downloading the entire archive, this picks N random files,
/// runs `borg extract --dry-run` on just those files to verify integrity
/// with minimal network traffic.
pub async fn run_restore_test(config: &Config, client_name: &str, args: &RestoreArgs, log_tx: Option<LogSender>) -> Result<()> {
    let client = config
        .find_client(client_name)
        .with_context(|| format!("Client '{}' not found in config", client_name))?;

    let repo = client.find_repo(&args.repo)
        .with_context(|| format!("Repo '{}' not found for client '{}'", args.repo, client_name))?;

    log_line(&log_tx, format!("Starting restore test for client: {} (repo: {})", client.name, repo.name));

    if config.server_is_local() {
        tracing::info!("Server is local — skipping Wake-on-LAN and SSH poll");
    } else {
        // Step 1: Wake-on-LAN (server may be offline)
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
    }

    let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
        .with_ssh_key(&repo.ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(args.dry_run)
        .with_verbose(args.verbose)
        .with_lock_wait(config.borg.lock_wait_secs);

    // Step 3: List archives
    log_line(&log_tx, format!("\nListing the last {} archive(s):", args.list_count));
    let archives = borg::list(&ctx, args.list_count)
        .await
        .context("Failed to list archives")?;

    if archives.is_empty() {
        anyhow::bail!("No archives found in repository: {}", repo.path);
    }

    for (i, archive) in archives.iter().enumerate() {
        log_line(&log_tx, format!("  [{}] {}", i, archive.name));
    }

    // Determine which archive to use
    let selected = select_archive(&archives, args.archive.as_deref())
        .with_context(|| format!("Failed to select archive for repo: {}", repo.path))?;
    let archive_name = selected.name.clone();

    log_line(&log_tx, format!("\nUsing archive: {archive_name}"));

    // Step 4: List files in the archive and pick random samples
    log_line(&log_tx, "Listing files in archive...");
    let all_files = borg::list_files(&ctx, &archive_name)
        .await
        .context("Failed to list files in archive")?;

    let regular_files: Vec<_> = all_files.iter().filter(|f| f.is_regular_file()).collect();

    if regular_files.is_empty() {
        anyhow::bail!("No regular files found in archive: {archive_name}");
    }

    let sample_count = args.sample_count.min(regular_files.len());
    let mut rng = rand::rng();
    let mut sampled: Vec<_> = regular_files.clone();
    sampled.shuffle(&mut rng);
    let sampled = &sampled[..sample_count];

    log_line(&log_tx, format!("\nSpot-checking {} random file(s) (out of {} total):", sample_count, regular_files.len()));
    for f in sampled {
        log_line(&log_tx, format!("  {} ({} bytes)", f.path, f.size));
    }

    // Step 5: Dry-run extract only the sampled files
    let paths: Vec<String> = sampled.iter().map(|f| f.path.clone()).collect();
    log_line(&log_tx, "\nRunning dry-run extract on selected files...");
    borg::extract(&ctx, &archive_name, &paths, None, true)
        .await
        .with_context(|| format!("Dry-run extract failed for archive: {archive_name}"))?;
    log_line(&log_tx, format!("Dry-run extract: OK — all {} file(s) passed integrity check", sample_count));

    log_line(&log_tx, "\n=== Restore Test Summary ===");
    log_line(&log_tx, format!("  Client: {}", client.name));
    log_line(&log_tx, format!("  Repo: {}", repo.name));
    log_line(&log_tx, format!("  Archive: {archive_name}"));
    log_line(&log_tx, format!("  Files in archive: {}", regular_files.len()));
    log_line(&log_tx, format!("  Files checked: {sample_count}"));
    log_line(&log_tx, "  Status: PASSED");
    log_line(&log_tx, "\nServer remains online — no automatic shutdown.");

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
