use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use omega_backup_lib::config::{AppState, Config, default_config_path};
use omega_backup_lib::ssh::{self, SshConfig};
use omega_backup_lib::{borg, init, maintenance, reset, restore, wol};

// ── Command / Event enums ──────────────────────────────────────

#[derive(Debug)]
pub enum BackendCommand {
    LoadConfig,
    RefreshStatus,
    CheckServerReachable,
    WakeServer,
    RunMaintenance {
        skip_check: bool,
        repo: Option<String>,
    },
    RunInit {
        client: Option<String>,
    },
    RunRestoreTest {
        client: String,
        repo: String,
        list_count: usize,
        sample_count: usize,
    },
    RunCheck {
        client: String,
        repo: Option<String>,
    },
    RunReset {
        client: String,
        repo: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    ConfigLoaded(Arc<Config>),
    StateUpdated(AppState),
    ServerStatus {
        online: bool,
        lockfiles: Vec<String>,
        borg_version: Option<String>,
    },
    OperationStarted {
        id: u64,
        description: String,
    },
    OperationLog {
        id: u64,
        line: String,
    },
    OperationCompleted {
        id: u64,
        success: bool,
        summary: String,
    },
    Error(String),
}

// ── Handle held by the UI ──────────────────────────────────────

#[derive(Clone)]
pub struct BackendHandle {
    cmd_tx: mpsc::UnboundedSender<BackendCommand>,
    pub ui_rx: async_channel::Receiver<UiEvent>,
}

impl BackendHandle {
    pub fn spawn() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ui_tx, ui_rx) = async_channel::unbounded();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(backend_loop(cmd_rx, ui_tx));
        });

        Self { cmd_tx, ui_rx }
    }

    pub fn send(&self, cmd: BackendCommand) {
        let _ = self.cmd_tx.send(cmd);
    }
}

// ── Backend event loop (runs on tokio thread) ──────────────────

static NEXT_OP_ID: AtomicU64 = AtomicU64::new(1);

fn next_op_id() -> u64 {
    NEXT_OP_ID.fetch_add(1, Ordering::Relaxed)
}

async fn backend_loop(
    mut cmd_rx: mpsc::UnboundedReceiver<BackendCommand>,
    ui_tx: async_channel::Sender<UiEvent>,
) {
    let mut config: Option<Arc<Config>> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            BackendCommand::LoadConfig => {
                let path = default_config_path();
                match Config::load(&path) {
                    Ok(cfg) => {
                        let cfg = Arc::new(cfg);
                        config = Some(cfg.clone());
                        let _ = ui_tx.send(UiEvent::ConfigLoaded(cfg)).await;
                        if let Ok(state) = AppState::load() {
                            let _ = ui_tx.send(UiEvent::StateUpdated(state)).await;
                        }
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::Error(format!("Failed to load config: {e:#}")))
                            .await;
                    }
                }
            }

            BackendCommand::RefreshStatus => {
                if let Ok(state) = AppState::load() {
                    let _ = ui_tx.send(UiEvent::StateUpdated(state)).await;
                }
            }

            BackendCommand::CheckServerReachable => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let ssh_cfg = ssh_config_from(cfg);
                let online = ssh::is_reachable(&ssh_cfg).await;
                let lockfiles = if online {
                    ssh::list_lockfile_names(&ssh_cfg).await.unwrap_or_default()
                } else {
                    vec![]
                };
                let borg_version = borg::detect_version(&cfg.borg.binary).await;
                let _ = ui_tx
                    .send(UiEvent::ServerStatus {
                        online,
                        lockfiles,
                        borg_version,
                    })
                    .await;
            }

            BackendCommand::WakeServer => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                match wol::wake(&cfg.server.mac) {
                    Ok(()) => {
                        let id = next_op_id();
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: format!(
                                    "Wake-on-LAN packet sent to {}",
                                    cfg.server.mac
                                ),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::Error(format!("WoL failed: {e:#}")))
                            .await;
                    }
                }
            }

            BackendCommand::RunMaintenance { skip_check, repo } => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let id = next_op_id();
                let _ = ui_tx
                    .send(UiEvent::OperationStarted {
                        id,
                        description: "Running maintenance".into(),
                    })
                    .await;
                let args = maintenance::MaintenanceArgs {
                    dry_run: false,
                    verbose: true,
                    skip_check,
                    repo,
                };
                match maintenance::run_maintenance(cfg, &args).await {
                    Ok(()) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: "Maintenance completed successfully".into(),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: false,
                                summary: format!("Maintenance failed: {e:#}"),
                            })
                            .await;
                    }
                }
                if let Ok(state) = AppState::load() {
                    let _ = ui_tx.send(UiEvent::StateUpdated(state)).await;
                }
            }

            BackendCommand::RunInit { client } => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let id = next_op_id();
                let _ = ui_tx
                    .send(UiEvent::OperationStarted {
                        id,
                        description: format!(
                            "Initializing {}",
                            client.as_deref().unwrap_or("all clients")
                        ),
                    })
                    .await;
                match init::run_init(cfg, client.as_deref(), false, true, false).await {
                    Ok(()) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: "Init completed successfully".into(),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: false,
                                summary: format!("Init failed: {e:#}"),
                            })
                            .await;
                    }
                }
            }

            BackendCommand::RunRestoreTest {
                client,
                repo,
                list_count,
                sample_count,
            } => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let id = next_op_id();
                let _ = ui_tx
                    .send(UiEvent::OperationStarted {
                        id,
                        description: format!("Restore test: {client}/{repo}"),
                    })
                    .await;
                let args = restore::RestoreArgs {
                    dry_run: false,
                    verbose: true,
                    repo,
                    list_count,
                    sample_count,
                    archive: None,
                };
                match restore::run_restore_test(cfg, &client, &args).await {
                    Ok(()) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: format!("Restore test passed for {client}"),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: false,
                                summary: format!("Restore test failed: {e:#}"),
                            })
                            .await;
                    }
                }
            }

            BackendCommand::RunCheck { client, repo } => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let id = next_op_id();
                let _ = ui_tx
                    .send(UiEvent::OperationStarted {
                        id,
                        description: format!("Integrity check: {client}"),
                    })
                    .await;
                match maintenance::run_check_only(cfg, &client, repo.as_deref(), false, true).await
                {
                    Ok(()) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: format!("Check passed for {client}"),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: false,
                                summary: format!("Check failed: {e:#}"),
                            })
                            .await;
                    }
                }
                if let Ok(state) = AppState::load() {
                    let _ = ui_tx.send(UiEvent::StateUpdated(state)).await;
                }
            }

            BackendCommand::RunReset { client, repo } => {
                let Some(ref cfg) = config else {
                    let _ = ui_tx.send(UiEvent::Error("Config not loaded".into())).await;
                    continue;
                };
                let id = next_op_id();
                let _ = ui_tx
                    .send(UiEvent::OperationStarted {
                        id,
                        description: format!("Resetting {client}"),
                    })
                    .await;
                let args = reset::ResetArgs {
                    dry_run: false,
                    verbose: true,
                    repo,
                    yes: true,
                };
                match reset::run_reset(cfg, &client, &args).await {
                    Ok(()) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: true,
                                summary: format!("Reset completed for {client}"),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx
                            .send(UiEvent::OperationCompleted {
                                id,
                                success: false,
                                summary: format!("Reset failed: {e:#}"),
                            })
                            .await;
                    }
                }
            }
        }
    }
}

fn ssh_config_from(cfg: &Config) -> SshConfig {
    let mut ssh_cfg = SshConfig::new(&cfg.server.host, &cfg.server.admin_user);
    if let Some(ref key) = cfg.server.admin_ssh_key {
        ssh_cfg = ssh_cfg.with_key(key);
    }
    ssh_cfg
}
