use anyhow::{Context, Result};
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH command failed with exit code {exit_code}: {stderr}")]
    CommandFailed { exit_code: i32, stderr: String },
    #[error("SSH process did not exit cleanly")]
    ProcessError,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub user: String,
    pub key_path: Option<String>,
    pub port: u16,
    pub connect_timeout_secs: u32,
}

impl SshConfig {
    pub fn new(host: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            key_path: None,
            port: 22,
            connect_timeout_secs: 5,
        }
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key_path = Some(key.into());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_timeout(mut self, secs: u32) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Build the base SSH arguments (without the remote command).
    fn base_args(&self) -> Vec<String> {
        let mut args = vec![
            "-o".to_string(),
            format!("ConnectTimeout={}", self.connect_timeout_secs),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
            "-o".to_string(),
            "ServerAliveInterval=10".to_string(),
            "-o".to_string(),
            "ServerAliveCountMax=3".to_string(),
            "-p".to_string(),
            self.port.to_string(),
        ];
        if let Some(ref key) = self.key_path {
            args.push("-i".to_string());
            args.push(key.clone());
        }
        args.push(format!("{}@{}", self.user, self.host));
        args
    }
}

#[derive(Debug)]
pub struct SshOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl SshOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Run a remote command via SSH, returning stdout/stderr/exit_code.
pub async fn run_command(cfg: &SshConfig, remote_cmd: &str) -> Result<SshOutput, SshError> {
    let mut args = cfg.base_args();
    args.push(remote_cmd.to_string());

    let output = Command::new("ssh")
        .args(&args)
        .output()
        .await?;

    Ok(SshOutput {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run a remote command and return Err if exit code != 0.
pub async fn run_command_strict(cfg: &SshConfig, remote_cmd: &str) -> Result<SshOutput> {
    let out = run_command(cfg, remote_cmd).await
        .context("SSH command execution failed")?;
    if !out.success() {
        return Err(SshError::CommandFailed {
            exit_code: out.exit_code,
            stderr: out.stderr.clone(),
        }
        .into());
    }
    Ok(out)
}

/// Check if the host is reachable via SSH (runs `true`).
pub async fn is_reachable(cfg: &SshConfig) -> bool {
    match run_command(cfg, "true").await {
        Ok(out) => out.success(),
        Err(_) => false,
    }
}

/// Poll SSH until reachable or timeout.
pub async fn poll_until_reachable(
    cfg: &SshConfig,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    use tokio::time::{sleep, Instant};

    let start = Instant::now();
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(format!("Waiting for {} to come online...", cfg.host));
    pb.enable_steady_tick(Duration::from_millis(120));

    loop {
        match run_command(cfg, "true").await {
            Ok(out) if out.success() => {
                pb.finish_with_message(format!("{} is online", cfg.host));
                return Ok(());
            }
            Ok(out) => {
                // Detect fatal errors that won't resolve by retrying
                if out.stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
                    pb.finish_and_clear();
                    anyhow::bail!(
                        "Host key for {} has changed — known_hosts entry is stale.\n\
                         Run on this machine:\n\
                         \n  ssh-keygen -R {}\n  ssh-keygen -R {}\n",
                        cfg.host, cfg.host, cfg.host
                    );
                }

                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    pb.finish_with_message(format!("Timeout waiting for {}", cfg.host));
                    anyhow::bail!(
                        "SSH host {} did not become reachable within {:?}",
                        cfg.host,
                        timeout
                    );
                }

                // Extract a readable hint: skip decorator lines (all @), take first real line
                let hint = out.stderr.lines()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.chars().all(|c| c == '@'))
                    .unwrap_or("")
                    .to_string();

                if hint.is_empty() {
                    pb.set_message(format!(
                        "Waiting for {} to come online... ({:.0}s elapsed)",
                        cfg.host,
                        elapsed.as_secs_f64()
                    ));
                } else {
                    pb.set_message(format!(
                        "Waiting for {} ({:.0}s) — {}",
                        cfg.host,
                        elapsed.as_secs_f64(),
                        hint
                    ));
                }
            }
            Err(_) => {
                // Could not spawn SSH at all — treat like unreachable
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    pb.finish_with_message(format!("Timeout waiting for {}", cfg.host));
                    anyhow::bail!(
                        "SSH host {} did not become reachable within {:?}",
                        cfg.host,
                        timeout
                    );
                }
                pb.set_message(format!(
                    "Waiting for {} to come online... ({:.0}s elapsed)",
                    cfg.host,
                    elapsed.as_secs_f64()
                ));
            }
        }
        sleep(poll_interval).await;
    }
}

/// Install the omega-shutdown-watcher cron job on the server.
///
/// Writes `~/bin/omega-shutdown-watcher.sh` and registers a cron entry that
/// runs it every minute. Idempotent — safe to call on repeated `init` runs.
pub async fn install_shutdown_watcher(cfg: &SshConfig, idle_minutes: u64) -> Result<()> {
    tracing::info!(
        "Installing shutdown watcher on {} (idle threshold: {} min)",
        cfg.host,
        idle_minutes
    );

    let script = format!(
        r#"#!/usr/bin/env bash
# omega-shutdown-watcher: auto-shutdown after ${{1:-{idle}}} minutes of backup inactivity.
# Managed by omega-backup — do not edit manually.
set -euo pipefail

IDLE_MINUTES="${{1:-{idle}}}"
IDLE_SECS=$(( IDLE_MINUTES * 60 ))
LOCK_PATTERN="/tmp/borg-lock-*"
STATE_FILE="/tmp/omega-backup-last-active"

lock_count=$(ls $LOCK_PATTERN 2>/dev/null | wc -l)
if [ "$lock_count" -gt 0 ]; then
    touch "$STATE_FILE"
    exit 0
fi

# No active backups — bail if server was not woken by omega-backup
[ -f "$STATE_FILE" ] || exit 0

last_active=$(stat -c %Y "$STATE_FILE")
now=$(date +%s)
idle_secs=$(( now - last_active ))

if [ "$idle_secs" -ge "$IDLE_SECS" ]; then
    logger -t omega-backup "Idle for ${{idle_secs}}s (>= ${{IDLE_SECS}}s) — shutting down"
    sudo shutdown -h now
fi
"#,
        idle = idle_minutes,
    );

    // Write the script, make it executable
    let write_script = format!(
        "mkdir -p ~/bin && cat > ~/bin/omega-shutdown-watcher.sh << 'OMEGA_EOF'\n{script}OMEGA_EOF\nchmod +x ~/bin/omega-shutdown-watcher.sh"
    );
    run_command_strict(cfg, &write_script)
        .await
        .context("Failed to write shutdown watcher script on server")?;

    // Install cron entry (idempotent: remove any previous omega-shutdown-watcher line first)
    let cron_entry = format!("* * * * * $HOME/bin/omega-shutdown-watcher.sh {idle_minutes}");
    let install_cron = format!(
        r#"( crontab -l 2>/dev/null | grep -v 'omega-shutdown-watcher'; echo '{cron_entry}' ) | crontab -"#
    );
    run_command_strict(cfg, &install_cron)
        .await
        .context("Failed to install shutdown watcher cron entry")?;

    tracing::info!("Shutdown watcher installed successfully");
    Ok(())
}

/// Set a lockfile on the remote server.
pub async fn set_lockfile(cfg: &SshConfig, hostname: &str) -> Result<()> {
    let cmd = format!("touch /tmp/borg-lock-{hostname}");
    run_command_strict(cfg, &cmd).await?;
    Ok(())
}

/// Remove the lockfile from the remote server.
pub async fn remove_lockfile(cfg: &SshConfig, hostname: &str) -> Result<()> {
    let cmd = format!("rm -f /tmp/borg-lock-{hostname}");
    run_command_strict(cfg, &cmd).await?;
    Ok(())
}

/// Count lockfiles on the remote server.
pub async fn count_lockfiles(cfg: &SshConfig) -> Result<usize> {
    let out = run_command(cfg, "ls /tmp/borg-lock-* 2>/dev/null | wc -l").await
        .context("Failed to count lockfiles")?;
    let count = out.stdout.trim().parse::<usize>().unwrap_or(0);
    Ok(count)
}

/// List hostnames that have active lockfiles on the remote server.
pub async fn list_lockfile_names(cfg: &SshConfig) -> Result<Vec<String>> {
    let out = run_command(cfg, "ls -1 /tmp/borg-lock-* 2>/dev/null").await
        .context("Failed to list lockfiles")?;
    let names: Vec<String> = out.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| l.trim().strip_prefix("/tmp/borg-lock-"))
        .map(|s| s.to_string())
        .collect();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SshConfig builder ────────────────────────────────────────

    #[test]
    fn test_ssh_config_new_defaults() {
        let cfg = SshConfig::new("server.local", "admin");
        assert_eq!(cfg.host, "server.local");
        assert_eq!(cfg.user, "admin");
        assert_eq!(cfg.port, 22);
        assert_eq!(cfg.connect_timeout_secs, 5);
        assert!(cfg.key_path.is_none());
    }

    #[test]
    fn test_ssh_config_with_key() {
        let cfg = SshConfig::new("host", "user").with_key("/home/user/.ssh/id_ed25519");
        assert_eq!(cfg.key_path.as_deref(), Some("/home/user/.ssh/id_ed25519"));
    }

    #[test]
    fn test_ssh_config_with_port() {
        let cfg = SshConfig::new("host", "user").with_port(2222);
        assert_eq!(cfg.port, 2222);
    }

    #[test]
    fn test_ssh_config_with_timeout() {
        let cfg = SshConfig::new("host", "user").with_timeout(60);
        assert_eq!(cfg.connect_timeout_secs, 60);
    }

    #[test]
    fn test_ssh_config_builder_chain() {
        let cfg = SshConfig::new("host", "user")
            .with_key("/tmp/key")
            .with_port(2222)
            .with_timeout(30);
        assert_eq!(cfg.key_path.as_deref(), Some("/tmp/key"));
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.connect_timeout_secs, 30);
    }

    // ── SshOutput::success ───────────────────────────────────────

    #[test]
    fn test_ssh_output_success_on_zero_exit_code() {
        let out = SshOutput { exit_code: 0, stdout: String::new(), stderr: String::new() };
        assert!(out.success());
    }

    #[test]
    fn test_ssh_output_not_success_on_nonzero_exit_code() {
        let out = SshOutput { exit_code: 1, stdout: String::new(), stderr: "error".into() };
        assert!(!out.success());
    }

    #[test]
    fn test_ssh_output_not_success_on_negative_exit_code() {
        let out = SshOutput { exit_code: -1, stdout: String::new(), stderr: String::new() };
        assert!(!out.success());
    }

    // ── SshConfig::base_args ─────────────────────────────────────

    #[test]
    fn test_base_args_ends_with_user_at_host() {
        let cfg = SshConfig::new("myhost", "myuser");
        let args = cfg.base_args();
        assert_eq!(args.last().unwrap(), "myuser@myhost");
    }

    #[test]
    fn test_base_args_includes_port() {
        let cfg = SshConfig::new("host", "user").with_port(2222);
        let args = cfg.base_args();
        let idx = args.iter().position(|a| a == "-p").expect("-p flag not found");
        assert_eq!(args[idx + 1], "2222");
    }

    #[test]
    fn test_base_args_includes_connect_timeout() {
        let cfg = SshConfig::new("host", "user").with_timeout(42);
        let args = cfg.base_args();
        assert!(args.iter().any(|a| a.contains("ConnectTimeout=42")),
            "ConnectTimeout not found in args: {args:?}");
    }

    #[test]
    fn test_base_args_includes_key_when_set() {
        let cfg = SshConfig::new("host", "user").with_key("/path/to/key");
        let args = cfg.base_args();
        let idx = args.iter().position(|a| a == "-i").expect("-i flag not found");
        assert_eq!(args[idx + 1], "/path/to/key");
    }

    #[test]
    fn test_base_args_no_key_flag_without_key() {
        let cfg = SshConfig::new("host", "user");
        let args = cfg.base_args();
        assert!(!args.contains(&"-i".to_string()));
    }

    #[test]
    fn test_base_args_includes_batch_mode() {
        let cfg = SshConfig::new("host", "user");
        let args = cfg.base_args();
        assert!(args.iter().any(|a| a.contains("BatchMode=yes")),
            "BatchMode not found in args: {args:?}");
    }
}
