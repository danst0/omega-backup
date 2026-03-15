use anyhow::{Context, Result};
use crate::config::Config;

/// Compare two semver version strings and return `true` if `latest` is newer than `current`.
pub fn needs_update(current: &str, latest: &str) -> Result<bool> {
    let current_v = semver::Version::parse(current)
        .with_context(|| format!("Invalid current version: {current}"))?;
    let latest_v = semver::Version::parse(latest)
        .with_context(|| format!("Invalid latest version: {latest}"))?;
    Ok(latest_v > current_v)
}

pub async fn run_update(config: &Config, verbose: bool) -> Result<()> {
    let repo_owner = config.update.repo_owner.clone();
    let repo_name = config.update.repo_name.clone();

    // We must run self_update in a blocking task because it uses blocking I/O (reqwest blocking)
    let updated = tokio::task::spawn_blocking(move || {
        let status = self_update::backends::github::Update::configure()
            .repo_owner(&repo_owner)
            .repo_name(&repo_name)
            .bin_name("omega-backup")
            .show_download_progress(true)
            .show_output(verbose)
            .target("x86_64-unknown-linux-musl") // Force the musl target we build
            .no_confirm(true)
            .current_version(env!("CARGO_PKG_VERSION"))
            .build()
            .context("Failed to build update configuration")?;

        println!("Checking for updates...");
        status.update().context("Update failed")
    })
    .await
    .context("Update task panicked")??;

    if updated.updated() {
        println!("✅ Successfully updated to version {}!", updated.version());
    } else {
        println!("Already up to date (version {}).", updated.version());
    }

    Ok(())
}

pub async fn check_for_updates(config: &Config) -> Result<Option<String>> {
    if !config.update.check_enabled {
        return Ok(None);
    }
    
    // If pinned version is set, disable update checks to avoid nagging
    if config.update.pinned_version.is_some() {
        return Ok(None);
    }

    let repo_owner = config.update.repo_owner.clone();
    let repo_name = config.update.repo_name.clone();

    let new_version = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
        let updater = self_update::backends::github::Update::configure()
            .repo_owner(&repo_owner)
            .repo_name(&repo_name)
            .bin_name("omega-backup")
            .current_version(env!("CARGO_PKG_VERSION"))
            .target("x86_64-unknown-linux-musl")
            .build()
            .context("Failed to build update configuration")?;

        let latest_release = updater.get_latest_release()?;
        
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        let latest = semver::Version::parse(&latest_release.version)?;
        
        if latest > current {
            Ok(Some(latest_release.version))
        } else {
            Ok(None)
        }
    })
    .await
    .context("Update check task panicked")??;

    Ok(new_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_update_newer_version() {
        assert!(needs_update("0.4.0", "0.4.1").unwrap());
    }

    #[test]
    fn test_needs_update_same_version() {
        assert!(!needs_update("0.4.5", "0.4.5").unwrap());
    }

    #[test]
    fn test_needs_update_older_latest_does_not_need_update() {
        assert!(!needs_update("0.5.0", "0.4.9").unwrap());
    }

    #[test]
    fn test_needs_update_major_version_bump() {
        assert!(needs_update("1.0.0", "2.0.0").unwrap());
    }

    #[test]
    fn test_needs_update_minor_version_bump() {
        assert!(needs_update("1.2.0", "1.3.0").unwrap());
    }

    #[test]
    fn test_needs_update_invalid_current_version_errors() {
        assert!(needs_update("not-semver", "1.0.0").is_err());
    }

    #[test]
    fn test_needs_update_invalid_latest_version_errors() {
        assert!(needs_update("1.0.0", "also-bad").is_err());
    }
}
