use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use crate::config::Config;

pub async fn run_check(config: &Config) -> Result<()> {
    println!("\n=== Configuration Check ===\n");

    let mut checks_passed = true;

    // 1. Check config file path
    let config_path = crate::config::default_config_path();
    if config_path.exists() {
        println!("✅ Config file found: {}", config_path.display());
    } else {
        println!("❌ Config file missing: {}", config_path.display());
        checks_passed = false;
    }

    // 2. Check local borg binary
    let borg_bin = &config.borg.binary;
    match check_command(borg_bin, "--version").await {
        Ok(version) => println!("✅ Local borg found: {}", version.trim()),
        Err(e) => {
            println!("❌ Local borg binary '{}' not found or not executable: {}", borg_bin, e);
            checks_passed = false;
        }
    }

    // 3. Check SSH connectivity to server
    let server = &config.server;
    println!("ℹ️  Checking connectivity to {} ({}) as user '{}'...", server.host, server.mac, server.admin_user);
    
    // Simple ping check first (optional, might fail if ICMP blocked)
    // We skip ping and go straight to SSH which is what matters

    // SSH check: just run 'exit'
    // We need to find the admin key first. It's usually ~/.ssh/borg_<client>_admin_ed25519 or ~/.ssh/borg_mgmt_admin_ed25519
    // But config doesn't store the admin key path explicitly in a general way, it's convention.
    // However, the user running this might have their own ssh config. 
    // Let's try to SSH as admin_user@host. If it fails, we warn.
    
    let ssh_target = format!("{}@{}", server.admin_user, server.host);
    // We don't know the exact identity file to use without guessing from client name or role.
    // For now, let's just try `ssh -o BatchMode=yes -o ConnectTimeout=5 user@host exit`
    // This relies on ssh-agent or default keys.
    
    match check_ssh(&ssh_target).await {
        Ok(_) => println!("✅ SSH connection to {} successful", ssh_target),
        Err(e) => {
            println!("⚠️  SSH connection to {} failed: {}", ssh_target, e);
            println!("   (This might be expected if you haven't loaded keys into ssh-agent or use specific IdentityFile)");
            // Don't fail the whole check for this as it's environment-dependent
        }
    }

    // 4. Check keys directory
    let keys_dir = config.keys_local_dir();
    if keys_dir.exists() {
        if check_dir_writable(&keys_dir) {
            println!("✅ Keys directory writable: {}", keys_dir.display());
        } else {
            println!("❌ Keys directory not writable: {}", keys_dir.display());
            checks_passed = false;
        }
    } else {
        println!("⚠️  Keys directory does not exist: {}", keys_dir.display());
        // Might be fine if no keys generated yet
    }

    // 5. Check clients
    if config.clients.is_empty() {
        println!("ℹ️  No clients configured.");
    } else {
        println!("\nChecking {} clients...", config.clients.len());
        for client in &config.clients {
            let repo_path = &client.main_repo.path;
            // Parse repo path to see if it's local or remote
            // Usually ssh://user@host/path
            println!("   - {}: Repo {}", client.name, repo_path);
        }
    }

    println!();
    if checks_passed {
        println!("✅ Configuration looks good.");
        Ok(())
    } else {
        anyhow::bail!("❌ Some checks failed. See output above.");
    }
}

async fn check_command(cmd: &str, arg: &str) -> Result<String> {
    let output = Command::new(cmd)
        .arg(arg)
        .output()
        .await
        .context("Failed to execute command")?;
    
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        anyhow::bail!("Command failed with status {}", output.status)
    }
}

async fn check_ssh(target: &str) -> Result<()> {
    let status = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, "exit"])
        .status()
        .await
        .context("Failed to run ssh")?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("Exit code {}", status)
    }
}

fn check_dir_writable(path: &Path) -> bool {
    // Try to create a temp file
    let test_file = path.join(".write_test");
    if std::fs::write(&test_file, "").is_ok() {
        let _ = std::fs::remove_file(test_file);
        true
    } else {
        false
    }
}
