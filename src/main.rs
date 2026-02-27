mod backup;
mod borg;
mod config;
mod distribute;
mod init;
mod maintenance;
mod ntfy;
mod restore;
mod setup;
mod ssh;
mod wol;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use config::{Config, default_config_path, default_log_dir};

// ────────────────────────────────────────────────────────────────
// CLI Definition
// ────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "omega-backup",
    about = "BorgBackup orchestration CLI",
    version,
    long_about = None
)]
struct Cli {
    /// Config file path (default: ~/.config/omega-backup/config.toml)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Verbose output (use multiple times for more detail: -v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Dry run — do not execute borg commands
    #[arg(long)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Interactive setup wizard (no subcommand) or key distribution subcommands
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Initialize borg repositories (run once after config)
    Init {
        /// Only initialize this client (default: all clients)
        client: Option<String>,
    },

    /// Run a backup (client mode)
    Backup,

    /// Run maintenance: prune, compact, check (management mode)
    Maintain {
        /// Skip integrity check (prune+compact only)
        #[arg(long)]
        skip_check: bool,

        /// Also maintain offsite repos
        #[arg(long)]
        offsite: bool,
    },

    /// Discover the MAC address of a host via ARP (host must be online)
    DiscoverMac {
        /// Hostname or IP to look up
        host: String,
    },

    /// Run a restore test (management mode)
    RestoreTest {
        /// Client name to test
        client: String,

        /// Number of archives to list
        #[arg(long, default_value = "5")]
        list_count: usize,

        /// Perform actual extraction (in addition to dry-run)
        #[arg(long)]
        extract: bool,

        /// Specific archive name to test (default: most recent)
        #[arg(long)]
        archive: Option<String>,

        /// Only extract these paths (default: all)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Start local distribution server (management: receive keys, send config)
    Listen,

    /// Sync key + passphrase to management, receive config (client)
    Sync {
        /// Client name to sync for (default: first client in config)
        client: Option<String>,
    },

    /// Push keyfile to GitHub repo (optional disaster-recovery backup)
    PushKey {
        /// Client name whose key to push
        client: String,
    },
}

// ────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialise tracing
    init_tracing(cli.verbose);

    if let Err(e) = run(cli).await {
        tracing::error!("{:#}", e);
        std::process::exit(exit_code_for(&e));
    }
}

async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        // ── config (wizard or subcommand) ─────────────────────
        Commands::Config { action } => {
            match action {
                None => {
                    // No subcommand: run interactive wizard (no config file needed)
                    setup::run_wizard().await?;
                }
                Some(ConfigAction::Listen) => {
                    let config = load_config(&cli)?;
                    distribute::run_listen(&config).await?;
                }
                Some(ConfigAction::Sync { client }) => {
                    let config = load_config(&cli)?;
                    let client_name = client.clone().unwrap_or_else(|| {
                        config.clients.first().map(|c| c.name.clone()).unwrap_or_else(|| "client1".to_string())
                    });
                    distribute::run_sync(&config, &client_name).await?;
                }
                Some(ConfigAction::PushKey { client }) => {
                    let config = load_config(&cli)?;
                    distribute::push_key_to_github(&config, client).await?;
                }
            }
            return Ok(());
        }

        Commands::DiscoverMac { host } => {
            let host = host.clone();
            let mac = tokio::task::spawn_blocking(move || wol::discover_mac(&host))
                .await
                .context("Task panicked")??;
            println!("{mac}");
            return Ok(());
        }

        _ => {}
    }

    // All other commands require a config file
    let config = load_config(&cli)?;
    let verbose = cli.verbose > 0;
    let dry_run = cli.dry_run;

    // Log borg version on startup
    if let Some(version) = borg::detect_version(&config.borg.binary).await {
        tracing::debug!("Detected: {}", version);
    }

    match cli.command {
        Commands::Init { ref client } => {
            init::run_init(&config, client.as_deref(), dry_run, verbose).await?;
        }

        Commands::Backup => {
            let args = backup::BackupArgs { dry_run, verbose };
            backup::run_backup(&config, &args).await?;
        }

        Commands::Maintain { skip_check, offsite } => {
            let args = maintenance::MaintenanceArgs { dry_run, verbose, skip_check, offsite };
            maintenance::run_maintenance(&config, &args).await?;
        }

        Commands::RestoreTest { client, list_count, extract, archive, paths } => {
            let args = restore::RestoreArgs {
                dry_run,
                verbose,
                list_count,
                extract,
                archive,
                paths,
            };
            restore::run_restore_test(&config, &client, &args).await?;
        }

        // Already handled above
        Commands::Config { .. } | Commands::DiscoverMac { .. } => unreachable!(),
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

fn load_config(cli: &Cli) -> Result<Config> {
    let path = cli
        .config
        .clone()
        .unwrap_or_else(default_config_path);

    Config::load(&path).with_context(|| {
        format!(
            "Failed to load config from {}. Run `omega-backup config` first.",
            path.display()
        )
    })
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let log_dir = default_log_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    // File appender for persistent logs
    let file_appender = tracing_appender::rolling::daily(&log_dir, "omega-backup.log");
    let (_non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // The _guard must live for the program duration — store it in a static
    // (This is a common pattern; the guard flushes on drop)
    // We use Box::leak so it lives forever
    Box::leak(Box::new(_guard));

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // Separate file subscriber would require a subscriber stack (tracing-subscriber registry)
    // For simplicity, we log to stderr only; file logging can be added via env RUST_LOG_FILE
}

fn exit_code_for(err: &anyhow::Error) -> i32 {
    let msg = format!("{err:?}");
    if msg.contains("ConfigError") || msg.contains("config") {
        3
    } else if msg.contains("borg warning") {
        1
    } else {
        2
    }
}
