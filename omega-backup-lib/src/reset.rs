use anyhow::{Context, Result};
use std::time::Duration;

use crate::{
    borg::{self, BorgContext},
    config::{Config, RepoConfig},
    ssh::{self, SshConfig},
    wol,
};

pub struct ResetArgs {
    pub dry_run: bool,
    pub verbose: bool,
    pub repo: Option<String>,
    pub yes: bool,
}

/// Run `omega-backup reset CLIENT` — delete and reinitialize borg repositories.
pub async fn run_reset(config: &Config, client_name: &str, args: &ResetArgs) -> Result<()> {
    let client = config
        .find_client(client_name)
        .with_context(|| format!("Client '{}' not found in config", client_name))?;

    // Determine which repos to reset
    let repos: Vec<&RepoConfig> = match &args.repo {
        Some(name) => {
            let repo = client.find_repo(name)
                .with_context(|| format!("Repo '{}' not found for client '{}'", name, client_name))?;
            vec![repo]
        }
        None => client.repos.iter().collect(),
    };

    // Show what will be reset and confirm
    println!("Will reset the following for client '{}':", client_name);
    for repo in &repos {
        println!("  - {} repo: {}", repo.name, repo.path);
    }
    println!();
    println!("This will PERMANENTLY DELETE these repositories and reinitialize them.");

    if !args.yes && !args.dry_run {
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Are you sure?")
            .default(false)
            .interact()
            .context("Failed to read confirmation")?;
        if !confirmed {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Wake the server
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

    let keys_dir = config.keys_local_dir();
    let mut has_non_main = false;

    for repo in &repos {
        if repo.name != "main" {
            has_non_main = true;
        }

        println!("\n--- Resetting {} repo ---", repo.name);
        let server_path = parse_repo_server_path(&repo.path)?;
        let key_path = keys_dir.join(format!("{}-{}.key", client_name, repo.name));

        reset_repo(&ssh, &server_path, &key_path, args.dry_run).await?;

        reinit_repo(
            config,
            &repo.path,
            &repo.passphrase_file,
            &repo.ssh_key,
            &key_path,
            args.dry_run,
            args.verbose,
        )
        .await
        .with_context(|| format!("Failed to reinitialize {} repo", repo.name))?;

        println!("  {} repo reset complete.", repo.name);
    }

    println!("\nReset complete.");

    if has_non_main {
        println!();
        println!("Hint: Run `omega-backup config listen` on this machine, then");
        println!("      `omega-backup config sync` on the client to update its passphrases.");
    }

    Ok(())
}

/// Delete the remote repo directory and the local key file.
async fn reset_repo(
    ssh: &SshConfig,
    server_path: &str,
    local_key_path: &std::path::Path,
    dry_run: bool,
) -> Result<()> {
    // Delete remote repo
    let rm_cmd = format!("rm -rf {}", shell_escape(server_path));
    if dry_run {
        println!("  [dry-run] Would run via SSH: {}", rm_cmd);
    } else {
        println!("  Deleting remote repo: {}", server_path);
        ssh::run_command_strict(ssh, &rm_cmd)
            .await
            .with_context(|| format!("Failed to delete remote repo: {}", server_path))?;
    }

    // Delete local key file
    if local_key_path.exists() {
        if dry_run {
            println!("  [dry-run] Would delete local key: {}", local_key_path.display());
        } else {
            println!("  Deleting local key: {}", local_key_path.display());
            std::fs::remove_file(local_key_path)
                .with_context(|| format!("Failed to delete key file: {}", local_key_path.display()))?;
        }
    }

    Ok(())
}

/// Reinitialize a borg repo and export its key.
async fn reinit_repo(
    config: &Config,
    repo_path: &str,
    passphrase_file: &str,
    ssh_key: &str,
    key_export_path: &std::path::Path,
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    let ctx = BorgContext::new(repo_path, passphrase_file)
        .with_ssh_key(ssh_key)
        .with_binary(&config.borg.binary)
        .with_dry_run(dry_run)
        .with_verbose(verbose)
        .with_lock_wait(config.borg.lock_wait_secs);

    println!("  Initializing repo: {}", repo_path);
    borg::init(&ctx, "repokey-blake2").await?;

    if !dry_run {
        println!("  Exporting key → {}", key_export_path.display());
        borg::export_key(&ctx, &key_export_path.display().to_string()).await?;
    }

    Ok(())
}

/// Extract the server-side path from an SSH repo URL.
/// Supports `ssh://user@host/path/to/repo` and `user@host:path/to/repo`.
fn parse_repo_server_path(repo_url: &str) -> Result<String> {
    if let Some(rest) = repo_url.strip_prefix("ssh://") {
        // ssh://user@host/path/to/repo -> /path/to/repo
        if let Some(slash_pos) = rest.find('/') {
            Ok(rest[slash_pos..].to_string())
        } else {
            anyhow::bail!("Cannot parse repo path from URL: {}", repo_url);
        }
    } else if let Some(colon_pos) = repo_url.find(':') {
        // user@host:path/to/repo -> path/to/repo
        let path = &repo_url[colon_pos + 1..];
        if path.is_empty() {
            anyhow::bail!("Cannot parse repo path from URL: {}", repo_url);
        }
        Ok(path.to_string())
    } else {
        anyhow::bail!("Cannot parse repo path from URL: {}", repo_url);
    }
}

/// Basic shell escaping for a path (single-quote wrap).
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_url() {
        assert_eq!(
            parse_repo_server_path("ssh://backup@server/data/borg/client-main").unwrap(),
            "/data/borg/client-main"
        );
    }

    #[test]
    fn test_parse_scp_style() {
        assert_eq!(
            parse_repo_server_path("backup@server:/data/borg/client-offsite").unwrap(),
            "/data/borg/client-offsite"
        );
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_repo_server_path("just-a-path").is_err());
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("/data/borg/repo"), "'/data/borg/repo'");
        assert_eq!(shell_escape("it's a test"), "'it'\\''s a test'");
    }
}
