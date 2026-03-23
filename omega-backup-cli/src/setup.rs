use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;
use tokio::process::Command;

use omega_backup_lib::config::{
    BorgConfig, ClientConfig, Config, DistributionConfig, KeysConfig, MachineRole, NtfyConfig,
    RepoConfig, RetentionConfig, ServerConfig, UpdateConfig, default_config_path, expand_tilde,
};

#[derive(Debug, Clone, Copy)]
enum Role {
    Client,
    Management,
    Both,
}

/// Interactive config wizard entry point.
pub async fn run_wizard() -> Result<()> {
    println!("\nomega-backup — Interactive Setup Wizard\n");

    // Check if config already exists
    let config_path = default_config_path();
    if config_path.exists() {
        return run_existing_config_menu(&config_path).await;
    }

    run_fresh_wizard().await
}

/// Menu shown when a config already exists.
async fn run_existing_config_menu(config_path: &std::path::Path) -> Result<()> {
    println!("Existing config found: {}\n", config_path.display());

    let items = vec![
        "Add a repo to an existing client",
        "Edit an existing client",
        "Start fresh (overwrites current config)",
    ];
    let choice = Select::new()
        .with_prompt("What would you like to do?")
        .items(&items)
        .default(0)
        .interact()
        .context("Selection failed")?;

    match choice {
        0 => run_add_repo_wizard(config_path).await,
        1 => run_edit_client_wizard(config_path).await,
        2 => run_fresh_wizard().await,
        _ => unreachable!(),
    }
}

/// Fresh setup wizard (no existing config).
async fn run_fresh_wizard() -> Result<()> {
    let role_items = vec![
        "client (runs backups)",
        "management (runs maintenance)",
        "both (client + management on same machine)",
    ];
    let role_idx = Select::new()
        .with_prompt("What role does this machine have?")
        .items(&role_items)
        .default(0)
        .interact()
        .context("Selection failed")?;

    let role = match role_idx {
        0 => Role::Client,
        1 => Role::Management,
        2 => Role::Both,
        _ => unreachable!(),
    };

    match role {
        Role::Client => run_client_wizard().await,
        Role::Management => run_management_wizard().await,
        Role::Both => run_both_wizard().await,
    }
}

// ────────────────────────────────────────────────────────────────
// Add repo wizard
// ────────────────────────────────────────────────────────────────

async fn run_add_repo_wizard(config_path: &std::path::Path) -> Result<()> {
    let mut config = Config::load(config_path)?;

    if config.clients.is_empty() {
        anyhow::bail!("No clients configured. Run fresh setup first.");
    }

    let client_names: Vec<&str> = config.clients.iter().map(|c| c.name.as_str()).collect();
    let client_idx = Select::new()
        .with_prompt("Which client?")
        .items(&client_names)
        .default(0)
        .interact()
        .context("Selection failed")?;

    let client = &mut config.clients[client_idx];
    let client_name = client.name.clone();

    println!("\nAdding a new repo to client '{}'", client_name);
    println!("Existing repos: {}", client.repos.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", "));

    let repo_name: String = Input::new()
        .with_prompt("New repo name (e.g. offsite, nas)")
        .interact_text()
        .context("Input failed")?;

    if client.find_repo(&repo_name).is_some() {
        anyhow::bail!("Repo '{}' already exists for client '{}'", repo_name, client_name);
    }

    let server_host = &config.server.host;
    let repo_path: String = Input::new()
        .with_prompt("Repo path (SSH URL)")
        .default(format!("ssh://borguser@{}/mnt/{}/repos/{}", server_host, repo_name, client_name))
        .interact_text()
        .context("Input failed")?;

    let sources_input: String = Input::new()
        .with_prompt("Backup sources (space-separated, empty to inherit from main)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;
    let sources: Vec<String> = if sources_input.is_empty() {
        client.main_repo().map(|r| r.sources.clone()).unwrap_or_default()
    } else {
        sources_input.split_whitespace().map(|s| s.to_string()).collect()
    };

    let optional = Confirm::new()
        .with_prompt("Mark as optional (failures are warnings)?")
        .default(true)
        .interact()
        .context("Confirm failed")?;

    // Generate SSH key
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

    let ssh_key_path = ssh_dir.join(format!("borg_{}_{}_ed25519", client_name, repo_name));
    generate_ssh_key(&ssh_key_path, &format!("borg-{}-{}", client_name, repo_name)).await?;

    // Generate passphrase
    let keys_dir = expand_tilde("~/.borg-keys");
    std::fs::create_dir_all(&keys_dir).context("Failed to create ~/.borg-keys")?;
    set_dir_permissions(&keys_dir, 0o700);

    let pass_path = keys_dir.join(format!("{}-{}.pass", client_name, repo_name));
    if !pass_path.exists() {
        let passphrase = generate_passphrase();
        std::fs::write(&pass_path, &passphrase)
            .context("Failed to write passphrase")?;
        set_file_permissions(&pass_path, 0o600);
        println!("Generated passphrase → {}", pass_path.display());
    }

    let new_repo = RepoConfig {
        name: repo_name.clone(),
        path: repo_path,
        ssh_key: ssh_key_path.display().to_string(),
        passphrase_file: pass_path.display().to_string(),
        sources,
        compression: "auto,zstd".to_string(),
        exclude_patterns: vec![],
        exclude_patterns_from: vec![],
        exclude_if_present: vec![],
        borg_filter: None,
        optional,
        retention: None,
        pre_create_commands: None,
        post_create_commands: None,
    };

    client.repos.push(new_repo);
    config.save(config_path)?;
    println!("\nConfig updated: {}", config_path.display());
    println!("Added repo '{}' to client '{}'.", repo_name, client_name);
    println!("\nNext: run `omega-backup init {}` to initialize the new repo.", client_name);

    Ok(())
}

// ────────────────────────────────────────────────────────────────
// Edit client wizard
// ────────────────────────────────────────────────────────────────

async fn run_edit_client_wizard(config_path: &std::path::Path) -> Result<()> {
    let mut config = Config::load(config_path)?;

    if config.clients.is_empty() {
        anyhow::bail!("No clients configured.");
    }

    let client_names: Vec<&str> = config.clients.iter().map(|c| c.name.as_str()).collect();
    let client_idx = Select::new()
        .with_prompt("Which client to edit?")
        .items(&client_names)
        .default(0)
        .interact()
        .context("Selection failed")?;

    let client = &mut config.clients[client_idx];

    println!("\nEditing client '{}' (hostname: {})", client.name, client.hostname);

    let new_hostname: String = Input::new()
        .with_prompt("Hostname")
        .default(client.hostname.clone())
        .interact_text()
        .context("Input failed")?;
    client.hostname = new_hostname;

    // Edit each repo's sources and exclude patterns
    for repo in &mut client.repos {
        println!("\n  --- Repo: {} ---", repo.name);

        let sources_str = repo.sources.join(" ");
        let new_sources: String = Input::new()
            .with_prompt(format!("  Sources for {}", repo.name))
            .default(sources_str)
            .interact_text()
            .context("Input failed")?;
        repo.sources = new_sources.split_whitespace().map(|s| s.to_string()).collect();

        let excludes_str = repo.exclude_patterns.join(" ");
        let new_excludes: String = Input::new()
            .with_prompt(format!("  Exclude patterns for {}", repo.name))
            .default(excludes_str)
            .allow_empty(true)
            .interact_text()
            .context("Input failed")?;
        repo.exclude_patterns = if new_excludes.is_empty() {
            vec![]
        } else {
            new_excludes.split_whitespace().map(|s| s.to_string()).collect()
        };
    }

    // Per-repo SSH key regeneration
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

    let client_name = client.name.clone();
    let mut repos_with_new_keys: Vec<usize> = vec![];

    for (i, repo) in client.repos.iter_mut().enumerate() {
        println!("\n  --- SSH key for repo '{}' (current: {}) ---", repo.name, repo.ssh_key);
        let regen = Confirm::new()
            .with_prompt(format!("  Regenerate SSH key for repo '{}'?", repo.name))
            .default(false)
            .interact()
            .context("Confirm failed")?;

        if regen {
            let new_key_path = ssh_dir.join(format!("borg_{}_{}_ed25519", client_name, repo.name));

            // Rename old key pair to .bak so they are not lost
            if new_key_path.exists() {
                let bak = PathBuf::from(format!("{}.bak", new_key_path.display()));
                std::fs::rename(&new_key_path, &bak)
                    .with_context(|| format!("Failed to rename old key to {}", bak.display()))?;
                let pub_path = PathBuf::from(format!("{}.pub", new_key_path.display()));
                if pub_path.exists() {
                    let pub_bak = PathBuf::from(format!("{}.pub.bak", new_key_path.display()));
                    std::fs::rename(&pub_path, &pub_bak).ok();
                }
                println!("  Renamed old key to {}", bak.display());
            }

            generate_ssh_key(&new_key_path, &format!("borg-{client_name}-{}", repo.name)).await?;
            repo.ssh_key = new_key_path.display().to_string();
            repos_with_new_keys.push(i);
        }
    }

    config.save(config_path)?;
    println!("\nConfig updated: {}", config_path.display());

    if !repos_with_new_keys.is_empty() {
        println!("\nAdd the following entries to the backup server's authorized_keys:");
        for i in repos_with_new_keys {
            print_repo_key_instructions(&client_name, &config.clients[client_idx].repos[i]);
        }
    }

    Ok(())
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

    let ntfy_topic: String = if !ntfy_url.is_empty() {
        Input::new()
            .with_prompt("ntfy topic")
            .default("omega-backup".to_string())
            .interact_text()
            .context("Input failed")?
    } else {
        String::new()
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

    // Build repos
    let server_base = format!("ssh://borguser@{server_host}");
    let mut repos = vec![RepoConfig {
        name: "main".to_string(),
        path: format!("{server_base}/backup/repos/{client_name}"),
        ssh_key: borg_main_key.display().to_string(),
        passphrase_file: pass_main_path.display().to_string(),
        sources,
        compression: "auto,zstd".to_string(),
        exclude_patterns: vec!["sh:/home/*/.cache".to_string()],
        exclude_patterns_from: vec![],
        exclude_if_present: vec![],
        borg_filter: None,
        optional: false,
        retention: None,
        pre_create_commands: None,
        post_create_commands: None,
    }];

    if use_offsite {
        repos.push(RepoConfig {
            name: "offsite".to_string(),
            path: format!("{server_base}/mnt/offsite/repos/{client_name}"),
            ssh_key: borg_offsite_key.as_ref().unwrap().display().to_string(),
            passphrase_file: pass_offsite_path.as_ref().unwrap().display().to_string(),
            sources: offsite_sources,
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            exclude_patterns_from: vec![],
            exclude_if_present: vec![],
            borg_filter: None,
            optional: true,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        });
    }

    let client = ClientConfig {
        name: client_name.clone(),
        hostname: hostname.clone(),
        repos,
    };

    let ntfy = if ntfy_url.is_empty() {
        None
    } else {
        Some(NtfyConfig { url: ntfy_url, token: ntfy_token, topic: ntfy_topic })
    };

    let config = Config {
        role: Some(MachineRole::Client),
        server: ServerConfig {
            host: server_host.clone(),
            mac: server_mac,
            admin_user: server_user,
            admin_ssh_key: Some(borg_admin_key.display().to_string()),
            poll_interval_secs: 15,
            poll_timeout_secs: 300,
            shutdown_idle_minutes: 90,
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
    println!("  3. omega-backup config sync           # send your key+passphrase to management");
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

    let ntfy_topic: String = if !ntfy_url.is_empty() {
        Input::new()
            .with_prompt("ntfy topic")
            .default("omega-backup".to_string())
            .interact_text()
            .context("Input failed")?
    } else {
        String::new()
    };

    let github_repo: String = Input::new()
        .with_prompt("GitHub repo URL for key backup (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    // Set up ssh dir before client collection so per-client keys can be generated inline
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

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

        // Generate a dedicated SSH key for each repo of this client
        let main_key = ssh_dir.join(format!("borg_{name}_main_ed25519"));
        println!("\n  Generating SSH key for {name}/main...");
        generate_ssh_key(&main_key, &format!("borg-{name}-main")).await?;

        let server_base = format!("ssh://borgmgmt@{server_host}");
        let mut repos = vec![RepoConfig {
            name: "main".to_string(),
            path: format!("{server_base}/backup/repos/{name}"),
            ssh_key: main_key.display().to_string(),
            passphrase_file: pass_main,
            sources: vec![],
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            exclude_patterns_from: vec![],
            exclude_if_present: vec![],
            borg_filter: None,
            optional: false,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        }];

        if let Some(pass) = offsite_pass {
            let offsite_key = ssh_dir.join(format!("borg_{name}_offsite_ed25519"));
            println!("  Generating SSH key for {name}/offsite...");
            generate_ssh_key(&offsite_key, &format!("borg-{name}-offsite")).await?;

            repos.push(RepoConfig {
                name: "offsite".to_string(),
                path: format!("{server_base}/mnt/offsite/repos/{name}"),
                ssh_key: offsite_key.display().to_string(),
                passphrase_file: pass,
                sources: vec![],
                compression: "auto,zstd".to_string(),
                exclude_patterns: vec![],
                exclude_patterns_from: vec![],
                exclude_if_present: vec![],
                borg_filter: None,
                optional: true,
                retention: None,
                pre_create_commands: None,
                post_create_commands: None,
            });
        }

        clients.push(ClientConfig {
            name,
            hostname: String::new(),
            repos,
        });
    }

    // Generate passphrase for the local host's client entry (if any)
    let local_hostname = get_hostname().await.unwrap_or_default();
    if !local_hostname.is_empty() {
        if let Some(local_client) = clients.iter().find(|c| c.name == local_hostname) {
            let keys_dir = expand_tilde("~/.borg-keys");
            std::fs::create_dir_all(&keys_dir).context("Failed to create ~/.borg-keys")?;
            set_dir_permissions(&keys_dir, 0o700);

            if let Some(main_repo) = local_client.main_repo() {
                let pass_path = expand_tilde(&main_repo.passphrase_file);
                if !pass_path.exists() {
                    let passphrase = generate_passphrase();
                    std::fs::write(&pass_path, &passphrase)
                        .with_context(|| format!("Failed to write passphrase: {}", pass_path.display()))?;
                    set_file_permissions(&pass_path, 0o600);
                    println!("Generated passphrase for local host → {}", pass_path.display());
                } else {
                    println!("Passphrase already exists for local host: {}", pass_path.display());
                }
            }
        }
    }

    // Generate management + admin SSH keys (per-client keys were generated in the loop above)
    let mgmt_key = ssh_dir.join("borg_mgmt_ed25519");
    let admin_key = ssh_dir.join("borg_mgmt_admin_ed25519");

    println!("\nGenerating management SSH keys...");
    generate_ssh_key(&mgmt_key, "borg-mgmt").await?;
    generate_ssh_key(&admin_key, "borg-mgmt-admin").await?;

    let ntfy = if ntfy_url.is_empty() {
        None
    } else {
        Some(NtfyConfig { url: ntfy_url, token: ntfy_token, topic: ntfy_topic })
    };

    let config = Config {
        role: Some(MachineRole::Management),
        server: ServerConfig {
            host: server_host.clone(),
            mac: server_mac,
            admin_user: server_user,
            admin_ssh_key: Some(admin_key.display().to_string()),
            poll_interval_secs: 15,
            poll_timeout_secs: 300,
            shutdown_idle_minutes: 90,
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

    print_management_instructions(&server_host, &mgmt_key, &admin_key, &config.clients);

    Ok(())
}

fn print_management_instructions(server_host: &str, mgmt_key: &PathBuf, admin_key: &PathBuf, clients: &[ClientConfig]) {
    let mgmt_pub = read_pubkey(mgmt_key);
    let admin_pub = read_pubkey(admin_key);

    println!("\n{}", "=".repeat(60));
    println!("=== authorized_keys on the backup server ({server_host}) ===");
    println!("{}", "=".repeat(60));

    // Per-client, per-repo entries with restricted paths
    for client in clients {
        for repo in &client.repos {
            print_repo_key_instructions(&client.name, repo);
        }
    }

    // Unrestricted admin key for shutdown / lockfile operations
    println!("\n# Unrestricted admin key (for shutdown/lockfile management)");
    println!("ssh-ed25519 {admin_pub} borg-mgmt-admin");

    // Management key kept for backwards-compat / manual operations
    println!("\n# Management key (broad repo access, for manual operations)");
    println!(
        r#"command="borg serve --restrict-to-path /backup/repos --restrict-to-path /mnt/offsite/repos",restrict ssh-ed25519 {mgmt_pub} borg-mgmt"#
    );

    println!("\n{}", "=".repeat(60));
    println!("=== Next Steps ===");
    println!("{}", "=".repeat(60));
    println!("  1. omega-backup config listen         # receive keys from clients");
    println!("  2. Receive passphrases out-of-band → store in ~/.borg-keys/");
}

// ────────────────────────────────────────────────────────────────
// Both (client + management) wizard
// ────────────────────────────────────────────────────────────────

async fn run_both_wizard() -> Result<()> {
    println!("\n=== Combined Client + Management Setup ===\n");

    let hostname_default = get_hostname().await.unwrap_or_else(|| "client1".to_string());

    // --- Local client info (like client wizard) ---

    let client_name: String = Input::new()
        .with_prompt("Local client name (used as identifier)")
        .default(hostname_default.clone())
        .interact_text()
        .context("Input failed")?;

    let hostname: String = Input::new()
        .with_prompt("Hostname of this machine")
        .default(hostname_default)
        .interact_text()
        .context("Input failed")?;

    // --- Server info ---

    let server_host: String = Input::new()
        .with_prompt("Backup server hostname (use 'localhost' if this machine)")
        .default("localhost".to_string())
        .interact_text()
        .context("Input failed")?;

    let server_mac: String = if server_host == "localhost" || server_host == "127.0.0.1" {
        Input::new()
            .with_prompt("Backup server MAC address (can be empty for local server)")
            .allow_empty(true)
            .default("00:00:00:00:00:00".to_string())
            .interact_text()
            .context("Input failed")?
    } else {
        prompt_mac_address(&server_host).await?
    };

    let server_user: String = Input::new()
        .with_prompt("Admin user on backup server")
        .default("admin".to_string())
        .interact_text()
        .context("Input failed")?;

    // --- Notifications ---

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

    let ntfy_topic: String = if !ntfy_url.is_empty() {
        Input::new()
            .with_prompt("ntfy topic")
            .default("omega-backup".to_string())
            .interact_text()
            .context("Input failed")?
    } else {
        String::new()
    };

    let github_repo: String = Input::new()
        .with_prompt("GitHub repo URL for key backup (leave empty to skip)")
        .allow_empty(true)
        .interact_text()
        .context("Input failed")?;

    // --- Local client backup sources (like client wizard) ---

    let sources_default = "/data /etc /home";
    let sources_input: String = Input::new()
        .with_prompt("Backup sources for local client (space-separated)")
        .default(sources_default.to_string())
        .interact_text()
        .context("Input failed")?;
    let sources: Vec<String> = sources_input.split_whitespace().map(|s| s.to_string()).collect();

    let use_offsite = Confirm::new()
        .with_prompt("Configure an offsite repo for local client?")
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

    // --- SSH keys & passphrases for local client ---

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).context("Failed to create ~/.ssh")?;

    let borg_main_key = ssh_dir.join(format!("borg_{client_name}_main_ed25519"));
    let borg_admin_key = ssh_dir.join(format!("borg_{client_name}_admin_ed25519"));

    println!("\nGenerating SSH keys for local client...");
    generate_ssh_key(&borg_main_key, &format!("borg-{client_name}-main")).await?;
    generate_ssh_key(&borg_admin_key, &format!("borg-{client_name}-admin")).await?;

    let borg_offsite_key = if use_offsite {
        let key = ssh_dir.join(format!("borg_{client_name}_offsite_ed25519"));
        generate_ssh_key(&key, &format!("borg-{client_name}-offsite")).await?;
        Some(key)
    } else {
        None
    };

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

    // Build local client repos
    let server_base = format!("ssh://borguser@{server_host}");
    let mut local_repos = vec![RepoConfig {
        name: "main".to_string(),
        path: format!("{server_base}/backup/repos/{client_name}"),
        ssh_key: borg_main_key.display().to_string(),
        passphrase_file: pass_main_path.display().to_string(),
        sources,
        compression: "auto,zstd".to_string(),
        exclude_patterns: vec!["sh:/home/*/.cache".to_string()],
        exclude_patterns_from: vec![],
        exclude_if_present: vec![],
        borg_filter: None,
        optional: false,
        retention: None,
        pre_create_commands: None,
        post_create_commands: None,
    }];

    if use_offsite {
        local_repos.push(RepoConfig {
            name: "offsite".to_string(),
            path: format!("{server_base}/mnt/offsite/repos/{client_name}"),
            ssh_key: borg_offsite_key.as_ref().unwrap().display().to_string(),
            passphrase_file: pass_offsite_path.as_ref().unwrap().display().to_string(),
            sources: offsite_sources,
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            exclude_patterns_from: vec![],
            exclude_if_present: vec![],
            borg_filter: None,
            optional: true,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        });
    }

    let mut clients = vec![ClientConfig {
        name: client_name.clone(),
        hostname: hostname.clone(),
        repos: local_repos,
    }];

    // --- Additional remote clients (like management wizard) ---

    let add_remote = Confirm::new()
        .with_prompt("Add additional remote clients to manage?")
        .default(false)
        .interact()
        .context("Confirm failed")?;

    if add_remote {
        println!("\nEnter remote client names (empty line to finish):");
        loop {
            let name: String = Input::new()
                .with_prompt("Client name (empty to finish)")
                .allow_empty(true)
                .interact_text()
                .context("Input failed")?;
            if name.is_empty() {
                break;
            }

            let pass_main_remote: String = Input::new()
                .with_prompt(format!("  Path to main passphrase for {name}"))
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

            let main_key = ssh_dir.join(format!("borg_{name}_main_ed25519"));
            println!("\n  Generating SSH key for {name}/main...");
            generate_ssh_key(&main_key, &format!("borg-{name}-main")).await?;

            let mgmt_base = format!("ssh://borgmgmt@{server_host}");
            let mut repos = vec![RepoConfig {
                name: "main".to_string(),
                path: format!("{mgmt_base}/backup/repos/{name}"),
                ssh_key: main_key.display().to_string(),
                passphrase_file: pass_main_remote,
                sources: vec![],
                compression: "auto,zstd".to_string(),
                exclude_patterns: vec![],
                exclude_patterns_from: vec![],
                exclude_if_present: vec![],
                borg_filter: None,
                optional: false,
                retention: None,
                pre_create_commands: None,
                post_create_commands: None,
            }];

            if let Some(pass) = offsite_pass {
                let offsite_key = ssh_dir.join(format!("borg_{name}_offsite_ed25519"));
                println!("  Generating SSH key for {name}/offsite...");
                generate_ssh_key(&offsite_key, &format!("borg-{name}-offsite")).await?;

                repos.push(RepoConfig {
                    name: "offsite".to_string(),
                    path: format!("{mgmt_base}/mnt/offsite/repos/{name}"),
                    ssh_key: offsite_key.display().to_string(),
                    passphrase_file: pass,
                    sources: vec![],
                    compression: "auto,zstd".to_string(),
                    exclude_patterns: vec![],
                    exclude_patterns_from: vec![],
                    exclude_if_present: vec![],
                    borg_filter: None,
                    optional: true,
                    retention: None,
                    pre_create_commands: None,
                    post_create_commands: None,
                });
            }

            clients.push(ClientConfig {
                name,
                hostname: String::new(),
                repos,
            });
        }
    }

    // --- Management SSH keys ---

    let mgmt_key = ssh_dir.join("borg_mgmt_ed25519");
    let admin_key = ssh_dir.join("borg_mgmt_admin_ed25519");

    println!("\nGenerating management SSH keys...");
    generate_ssh_key(&mgmt_key, "borg-mgmt").await?;
    generate_ssh_key(&admin_key, "borg-mgmt-admin").await?;

    // --- Build and save config ---

    let ntfy = if ntfy_url.is_empty() {
        None
    } else {
        Some(NtfyConfig { url: ntfy_url, token: ntfy_token, topic: ntfy_topic })
    };

    let config = Config {
        role: Some(MachineRole::Both),
        server: ServerConfig {
            host: server_host.clone(),
            mac: server_mac,
            admin_user: server_user,
            admin_ssh_key: Some(admin_key.display().to_string()),
            poll_interval_secs: 15,
            poll_timeout_secs: 300,
            shutdown_idle_minutes: 90,
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

    print_management_instructions(&server_host, &mgmt_key, &admin_key, &config.clients);

    println!("\n{}", "=".repeat(60));
    println!("=== Dual-role Next Steps ===");
    println!("{}", "=".repeat(60));
    println!("  1. omega-backup init                  # create repos for all clients");
    println!("  2. omega-backup backup                # run a backup (client mode)");
    println!("  3. omega-backup maintain              # run maintenance (management mode)");

    Ok(())
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

/// Print the authorized_keys snippet for a single client repo key.
fn print_repo_key_instructions(client_name: &str, repo: &RepoConfig) {
    let key_path = PathBuf::from(&repo.ssh_key);
    let pubkey = read_pubkey(&key_path);

    // Extract filesystem path from ssh://user@host/path/to/repo
    let repo_path = if let Some(scheme_end) = repo.path.find("://") {
        let after_scheme = &repo.path[scheme_end + 3..];
        if let Some(slash_idx) = after_scheme.find('/') {
            after_scheme[slash_idx..].to_string()
        } else {
            repo.path.clone()
        }
    } else {
        repo.path.clone()
    };

    let comment = format!("borg-{client_name}-{}", repo.name);

    println!("\n{}", "=".repeat(60));
    println!("=== authorized_keys entry: {client_name} / {} ===", repo.name);
    println!("{}", "=".repeat(60));
    println!(
        r#"command="borg serve --restrict-to-path {repo_path}",restrict {pubkey} {comment}"#
    );
    println!("{}", "=".repeat(60));
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
