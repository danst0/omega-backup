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
        if is_reachable(cfg).await {
            pb.finish_with_message(format!("{} is online", cfg.host));
            return Ok(());
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

        pb.set_message(format!(
            "Waiting for {} to come online... ({:.0}s elapsed)",
            cfg.host,
            elapsed.as_secs_f64()
        ));
        sleep(poll_interval).await;
    }
}

/// Send shutdown command to the server.
pub async fn shutdown_server(cfg: &SshConfig) -> Result<()> {
    tracing::info!("Sending shutdown command to {}", cfg.host);
    // We allow failure here since the connection may drop immediately
    let _ = run_command(cfg, "sudo shutdown -h now").await;
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
