use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;
use tokio::process::Command;

use crate::config::{
    BorgConfig, ClientConfig, Config, DistributionConfig, KeysConfig, NtfyConfig,
    RepoConfig, RetentionConfig, ServerConfig, UpdateConfig, default_config_path, expand_tilde,
};

#[derive(Debug, Clone, Copy)]
enum Role {
    Client,
    Management,
}

/// Interactive config wizard entry point.
pub async fn run_wizard() -> Result<()> {
    println!("\nomega-backup — Interactive Setup Wizard\n");

    let role_items = vec!["client (runs backups)", "management (runs maintenance)"];
    let role_idx = Select::new()
        .with_prompt("What role does this machine have?")
        .items(&role_items)
        .default(0)
        .interact()
        .context("Selection failed")?;

    let role = if role_idx == 0 {
        Role::Client
    } else {
        Role::Management
    };

    match role {
        Role::Client => run_client_wizard().await,
        Role::Management => run_management_wizard().await,
    }
}

// ────────────────────────────────────────────────────────────────
// Client wizard
// ────────────────────────────────────────────────────────────────

async fn run_client_wizard() -> Result<()> {
    println!("\n=== Client Setup ===\n");

    let hostname_default = get_hostname().await.unwrap_or_else(|| "client1".to_string());

    let client_name: String = Input::new()
        .with_prompt("Client name (used as identifier)")
        .default(hostname_default.clone())
        .interact_text()
        .context("Input failed")?;

    let hostname: String = Input::new()
        .with_prompt("Hostname of this machine")
        .default(hostname_default)
        .interact_text()
        .context("Input failed")?;

    let server_host: String = Input::new()
        .with_prompt("Backup server hostname")
        .interact_text()
        .context("Input failed")?;

    let server_mac: String = prompt_mac_address(&server_host).await?;

    let server_user: String = Input::new()
        .with_prompt("Admin user on backup server (for lockfile/shutdown)")
        .default("admin".to_string())
        .interact_text()
        .context("Input failed")?;

    let ntfy_url: String = Input::new()
        .with_prompt("ntfy URL (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    let ntfy_token: Option<String> = if !ntfy_url.is_empty() {
        let tok: String = Input::new()
            .with_prompt("ntfy token (leave empty if not needed)")
            .allow_empty(true)
            .interact_text()
            .context("Input failed")?;
        if tok.is_empty() { None } else { Some(tok) }
    } else {
        None
    };

    let github_repo: String = Input::new()
        .with_prompt("GitHub repo URL for key backup (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    let sources_default = "/data /etc /home";
    let sources_input: String = Input::new()
        .with_prompt("Backup sources for main repo (space-separated)")
        .default(sources_default.to_string())
        .interact_text()
        .context("Input failed")?;
    let sources: Vec<String> = sources_input.split_whitespace().map(|s| s.to_string()).collect();

    let use_offsite = Confirm::new()
        .with_prompt("Configure an offsite repo?")
        .default(false)
        .interact()
        .context("Confirm failed")?;

    let offsite_sources: Vec<String> = if use_offsite {
        let offsite_default = "/data/paperless /data/docker-compose /etc /home";
        let input: String = Input::new()
            .with_prompt("Offsite repo backup sources (space-separated)")
            .default(offsite_default.to_string())
            .interact_text()
            .context("Input failed")?;
        input.split_whitespace().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };

    // Generate SSH keys
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

    let borg_main_key = ssh_dir.join(format!("borg_{client_name}_main_ed25519"));
    let borg_admin_key = ssh_dir.join(format!("borg_{client_name}_admin_ed25519"));

    println!("\nGenerating SSH keys...");
    generate_ssh_key(&borg_main_key, &format!("borg-{client_name}-main")).await?;
    generate_ssh_key(&borg_admin_key, &format!("borg-{client_name}-admin")).await?;

    let borg_offsite_key = if use_offsite {
        let key = ssh_dir.join(format!("borg_{client_name}_offsite_ed25519"));
        generate_ssh_key(&key, &format!("borg-{client_name}-offsite")).await?;
        Some(key)
    } else {
        None
    };

    // Generate passphrases
    let keys_dir = expand_tilde("~/.borg-keys");
    std::fs::create_dir_all(&keys_dir).context("Failed to create ~/.borg-keys")?;
    set_dir_permissions(&keys_dir, 0o700);

    let pass_main_path = keys_dir.join(format!("{client_name}-main.pass"));
    let pass_main = generate_passphrase();
    std::fs::write(&pass_main_path, &pass_main)
        .context("Failed to write main passphrase")?;
    set_file_permissions(&pass_main_path, 0o600);
    println!("Generated passphrase → {}", pass_main_path.display());

    let pass_offsite_path = if use_offsite {
        let p = keys_dir.join(format!("{client_name}-offsite.pass"));
        let pass = generate_passphrase();
        std::fs::write(&p, &pass).context("Failed to write offsite passphrase")?;
        set_file_permissions(&p, 0o600);
        println!("Generated offsite passphrase → {}", p.display());
        Some(p)
    } else {
        None
    };

    // Build config
    let server_base = format!("ssh://borguser@{server_host}");
    let main_repo = RepoConfig {
        path: format!("{server_base}/backup/repos/{client_name}"),
        ssh_key: borg_main_key.display().to_string(),
        passphrase_file: pass_main_path.display().to_string(),
        sources,
        compression: "auto,zstd".to_string(),
        exclude_patterns: vec!["sh:/home/*/.cache".to_string()],
        optional: false,
    };

    let offsite_repo = if use_offsite {
        Some(RepoConfig {
            path: format!("{server_base}/mnt/offsite/repos/{client_name}"),
            ssh_key: borg_offsite_key.as_ref().unwrap().display().to_string(),
            passphrase_file: pass_offsite_path.as_ref().unwrap().display().to_string(),
            sources: offsite_sources,
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            optional: true,
        })
    } else {
        None
    };

    let client = ClientConfig {
        name: client_name.clone(),
        hostname: hostname.clone(),
        main_repo,
        offsite_repo,
    };

    let ntfy = if ntfy_url.is_empty() {
        None
    } else {
        Some(NtfyConfig { url: ntfy_url, token: ntfy_token })
    };

    let config = Config {
        server: ServerConfig {
            host: server_host.clone(),
            mac: server_mac,
            admin_user: server_user,
            poll_interval_secs: 15,
            poll_timeout_secs: 300,
        },
        borg: BorgConfig::default(),
        ntfy,
        clients: vec![client],
        keys: KeysConfig {
            local_dir: "~/.borg-keys/".to_string(),
            github_repo: if github_repo.is_empty() { None } else { Some(github_repo) },
        },
        distribution: DistributionConfig::default(),
        retention: RetentionConfig::default(),
        offsite_retention: None,
        update: UpdateConfig::default(),
    };

    let config_path = default_config_path();
    config.save(&config_path)?;
    println!("\nConfig written to: {}", config_path.display());

    // Print manual steps
    print_client_instructions(&client_name, &borg_main_key, &borg_admin_key, borg_offsite_key.as_ref(), &server_host, &pass_main_path);

    Ok(())
}

fn print_client_instructions(
    name: &str,
    main_key: &PathBuf,
    admin_key: &PathBuf,
    offsite_key: Option<&PathBuf>,
    server_host: &str,
    pass_path: &PathBuf,
) {
    let main_pub = read_pubkey(main_key);
    let admin_pub = read_pubkey(admin_key);

    println!("\n{}", "=".repeat(60));
    println!("=== authorized_keys on the backup server ({server_host}) ===");
    println!("{}", "=".repeat(60));
    println!(
        r#"command="borg serve --append-only --restrict-to-path /backup/repos/{name}",restrict \
  ssh-ed25519 {main_pub} borg-{name}-main"#
    );
    if let Some(ok) = offsite_key {
        let offsite_pub = read_pubkey(ok);
        println!(
            r#"command="borg serve --append-only --restrict-to-path /mnt/offsite/repos/{name}",restrict \
  ssh-ed25519 {offsite_pub} borg-{name}-offsite"#
        );
    }
    println!(
        "\nssh-ed25519 {admin_pub} borg-{name}-admin"
    );

    println!("\n{}", "=".repeat(60));
    println!("=== Passphrase (send to management out-of-band) ===");
    println!("{}", "=".repeat(60));
    println!("  cat {}", pass_path.display());

    println!("\n{}", "=".repeat(60));
    println!("=== Next Steps ===");
    println!("{}", "=".repeat(60));
    println!("  1. omega-backup init {name}           # create repo, export key");
    println!("  2. omega-backup config push-key {name}  # push key to GitHub (optional)");
    println!("  3. omega-backup config sync           # sync key+passphrase with management");
}

// ────────────────────────────────────────────────────────────────
// Management wizard
// ────────────────────────────────────────────────────────────────

async fn run_management_wizard() -> Result<()> {
    println!("\n=== Management Setup ===\n");

    let server_host: String = Input::new()
        .with_prompt("Backup server hostname")
        .interact_text()
        .context("Input failed")?;

    let server_mac: String = prompt_mac_address(&server_host).await?;

    let server_user: String = Input::new()
        .with_prompt("Admin user on backup server (for shutdown)")
        .default("admin".to_string())
        .interact_text()
        .context("Input failed")?;

    let ntfy_url: String = Input::new()
        .with_prompt("ntfy URL (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    let ntfy_token: Option<String> = if !ntfy_url.is_empty() {
        let tok: String = Input::new()
            .with_prompt("ntfy token (leave empty if not needed)")
            .allow_empty(true)
            .interact_text()
            .context("Input failed")?;
        if tok.is_empty() { None } else { Some(tok) }
    } else {
        None
    };

    let github_repo: String = Input::new()
        .with_prompt("GitHub repo URL for key backup (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    // Collect clients
    let mut clients: Vec<ClientConfig> = vec![];
    println!("\nEnter client names (empty line to finish):");
    loop {
        let name: String = Input::new()
            .with_prompt("Client name (empty to finish)")
            .allow_empty(true)
            .interact_text()
            .context("Input failed")?;
        if name.is_empty() {
            break;
        }

        let keys_dir = expand_tilde("~/.borg-keys");
        let pass_main: String = Input::new()
            .with_prompt(format!(
                "  Path to main passphrase for {name}"
            ))
            .default(keys_dir.join(format!("{name}-main.pass")).display().to_string())
            .interact_text()
            .context("Input failed")?;

        let has_offsite = Confirm::new()
            .with_prompt(format!("  Does {name} have an offsite repo?"))
            .default(false)
            .interact()
            .context("Confirm failed")?;

        let offsite_pass: Option<String> = if has_offsite {
            let p: String = Input::new()
                .with_prompt(format!("  Path to offsite passphrase for {name}"))
                .default(keys_dir.join(format!("{name}-offsite.pass")).display().to_string())
                .interact_text()
                .context("Input failed")?;
            Some(p)
        } else {
            None
        };

        let server_base = format!("ssh://borgmgmt@{server_host}");
        let main_repo = RepoConfig {
            path: format!("{server_base}/backup/repos/{name}"),
            ssh_key: expand_tilde("~/.ssh/borg_mgmt_ed25519").display().to_string(),
            passphrase_file: pass_main,
            sources: vec![],
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            optional: false,
        };

        let offsite_repo = offsite_pass.map(|pass| RepoConfig {
            path: format!("{server_base}/mnt/offsite/repos/{name}"),
            ssh_key: expand_tilde("~/.ssh/borg_mgmt_ed25519").display().to_string(),
            passphrase_file: pass,
            sources: vec![],
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            optional: true,
        });

        clients.push(ClientConfig {
            name,
            hostname: String::new(),
            main_repo,
            offsite_repo,
        });
    }

    // Generate SSH keys
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

    let mgmt_key = ssh_dir.join("borg_mgmt_ed25519");
    let admin_key = ssh_dir.join("borg_mgmt_admin_ed25519");

    println!("\nGenerating SSH keys...");
    generate_ssh_key(&mgmt_key, "borg-mgmt").await?;
    generate_ssh_key(&admin_key, "borg-mgmt-admin").await?;

    let ntfy = if ntfy_url.is_empty() {
        None
    } else {
        Some(NtfyConfig { url: ntfy_url, token: ntfy_token })
    };

    // Use a dummy server config for management (server fields still needed)
    let config = Config {
        server: ServerConfig {
            host: server_host.clone(),
            mac: server_mac,
            admin_user: server_user,
            poll_interval_secs: 15,
            poll_timeout_secs: 300,
        },
        borg: BorgConfig::default(),
        ntfy,
        clients,
        keys: KeysConfig {
            local_dir: "~/.borg-keys/".to_string(),
            github_repo: if github_repo.is_empty() { None } else { Some(github_repo) },
        },
        distribution: DistributionConfig::default(),
        retention: RetentionConfig::default(),
        offsite_retention: None,
        update: UpdateConfig::default(),
    };

    let config_path = default_config_path();
    config.save(&config_path)?;
    println!("\nConfig written to: {}", config_path.display());

    print_management_instructions(&server_host, &mgmt_key, &admin_key);

    Ok(())
}

fn print_management_instructions(server_host: &str, mgmt_key: &PathBuf, admin_key: &PathBuf) {
    let mgmt_pub = read_pubkey(mgmt_key);
    let admin_pub = read_pubkey(admin_key);

    println!("\n{}", "=".repeat(60));
    println!("=== authorized_keys on the backup server ({server_host}) ===");
    println!("{}", "=".repeat(60));
    println!(
        r#"command="borg serve --restrict-to-path /backup/repos --restrict-to-path /mnt/offsite/repos",restrict \
  ssh-ed25519 {mgmt_pub} borg-mgmt"#
    );
    println!("\nssh-ed25519 {admin_pub} borg-mgmt-admin");

    println!("\n{}", "=".repeat(60));
    println!("=== Next Steps ===");
    println!("{}", "=".repeat(60));
    println!("  1. omega-backup config listen         # receive keys from clients");
    println!("  2. Receive passphrases out-of-band → store in ~/.borg-keys/");
}

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

async fn generate_ssh_key(path: &PathBuf, comment: &str) -> Result<()> {
    if path.exists() {
        println!("SSH key already exists: {}", path.display());
        return Ok(());
    }
    let status = Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            "-f", &path.display().to_string(),
            "-C", comment,
            "-N", "",
        ])
        .status()
        .await
        .context("Failed to run ssh-keygen")?;
    if !status.success() {
        anyhow::bail!("ssh-keygen failed for {}", path.display());
    }
    println!("Generated SSH key: {}", path.display());
    Ok(())
}

fn generate_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    use std::fmt::Write;
    let mut hex = String::new();
    for b in &bytes {
        write!(hex, "{:02x}", b).unwrap();
    }
    hex
}

fn read_pubkey(key_path: &PathBuf) -> String {
    let pub_path = PathBuf::from(format!("{}.pub", key_path.display()));
    if pub_path.exists() {
        let content = std::fs::read_to_string(&pub_path).unwrap_or_default();
        // Return only the key part (second field)
        let parts: Vec<&str> = content.trim().splitn(3, ' ').collect();
        if parts.len() >= 2 {
            return format!("{} {}", parts[0], parts[1]);
        }
        content.trim().to_string()
    } else {
        "<key not found>".to_string()
    }
}

/// Try to auto-discover the MAC address of `server_host` via ARP,
/// then show it as the default in an interactive prompt.
async fn prompt_mac_address(server_host: &str) -> Result<String> {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(format!("Looking up MAC address for {server_host}..."));
    pb.enable_steady_tick(Duration::from_millis(120));

    // Spawn blocking so the spinner keeps running
    let host = server_host.to_string();
    let discovered = tokio::task::spawn_blocking(move || crate::wol::discover_mac(&host))
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("task panicked")));

    pb.finish_and_clear();

    let default_mac = match discovered {
        Ok(mac) => {
            println!("  Auto-detected MAC: {mac}");
            mac
        }
        Err(e) => {
            println!("  Could not auto-detect MAC ({e}).");
            println!("  Make sure the server is online, or enter the MAC manually.");
            String::new()
        }
    };

    let mut prompt = Input::<String>::new()
        .with_prompt("Backup server MAC address (AA:BB:CC:DD:EE:FF)");
    if !default_mac.is_empty() {
        prompt = prompt.default(default_mac);
    }
    let mac = prompt.interact_text().context("Input failed")?;
    Ok(mac)
}

async fn get_hostname() -> Option<String> {
    let out = Command::new("hostname").output().await.ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(unix)]
fn set_file_permissions(path: &PathBuf, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &PathBuf, _mode: u32) {}

#[cfg(unix)]
fn set_dir_permissions(path: &PathBuf, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &PathBuf, _mode: u32) {}
