use anyhow::{Context, Result};
use std::io::Write;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStderr, Command};
use std::process::Stdio;

#[derive(Debug, Error)]
pub enum ResticError {
    #[error("restic exited with error code {exit_code}: {stderr}")]
    Failed { exit_code: i32, stderr: String },
    #[error("restic password file not found: {0}")]
    PasswordFileNotFound(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct ResticContext {
    pub repo: String,
    pub password_file: String,
    pub rclone_config: Option<String>,
    pub binary: String,
    pub dry_run: bool,
    pub verbose: bool,
    pub extra_flags: Vec<String>,
    pub log_tx: Option<crate::LogSender>,
}

impl ResticContext {
    pub fn new(repo: impl Into<String>, password_file: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            password_file: password_file.into(),
            rclone_config: None,
            binary: "restic".to_string(),
            dry_run: false,
            verbose: false,
            extra_flags: Vec::new(),
            log_tx: None,
        }
    }

    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_rclone_config(mut self, path: impl Into<String>) -> Self {
        self.rclone_config = Some(path.into());
        self
    }

    pub fn with_extra_flag(mut self, flag: impl Into<String>) -> Self {
        self.extra_flags.push(flag.into());
        self
    }

    pub fn with_log_tx(mut self, tx: Option<crate::LogSender>) -> Self {
        self.log_tx = tx;
        self
    }

    fn password_file_path(&self) -> std::path::PathBuf {
        crate::config::expand_tilde(&self.password_file)
    }

    /// Build a Command with common env vars set.
    fn command(&self) -> Result<Command> {
        let pw_path = self.password_file_path();
        if !pw_path.exists() {
            return Err(ResticError::PasswordFileNotFound(self.password_file.clone()).into());
        }

        let mut cmd = Command::new(&self.binary);
        cmd.env("RESTIC_REPOSITORY", &self.repo);
        cmd.env("RESTIC_PASSWORD_FILE", pw_path);

        if let Some(ref rc) = self.rclone_config {
            let rc_path = crate::config::expand_tilde(rc);
            cmd.env("RCLONE_CONFIG", rc_path);
        }

        Ok(cmd)
    }

    /// Run a restic subcommand, returning (exit_code, stdout, stderr).
    async fn run(&self, args: &[&str]) -> Result<(i32, String, String)> {
        let mut cmd = self.command()?;
        cmd.args(args);

        tracing::debug!("Running: {} {}", self.binary, args.join(" "));

        let output = cmd.output().await.context("Failed to spawn restic process")?;
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if self.verbose && !stderr.is_empty() {
            for line in stderr.lines() {
                tracing::debug!("restic: {}", line);
            }
        }

        Ok((exit_code, stdout, stderr))
    }

    /// Run restic and check exit code: 0=ok, non-zero=error.
    async fn run_checked(&self, args: &[&str]) -> Result<(String, String)> {
        let (code, stdout, stderr) = self.run(args).await?;
        if code == 0 {
            Ok((stdout, stderr))
        } else {
            if !stderr.is_empty() {
                eprintln!("{stderr}");
            }
            Err(ResticError::Failed {
                exit_code: code,
                stderr,
            }
            .into())
        }
    }

    /// Run with streaming stderr output for live progress.
    async fn run_streaming(&self, args: &[&str]) -> Result<(i32, String, String)> {
        let mut cmd = self.command()?;
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        tracing::debug!("Running (streaming): {} {}", self.binary, args.join(" "));

        let mut child = cmd.spawn().context("Failed to spawn restic process")?;

        // Drain stdout in background
        let mut stdout_handle = child.stdout.take().expect("stdout piped");
        let stdout_task = tokio::spawn(async move {
            let mut buf = String::new();
            let _ = stdout_handle.read_to_string(&mut buf).await;
            buf
        });

        // Stream stderr
        let mut stderr_handle: ChildStderr = child.stderr.take().expect("stderr piped");
        let mut stderr_all = String::new();
        let mut pending = String::new();
        let mut chunk = vec![0u8; 2048];

        loop {
            match stderr_handle.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    loop {
                        let cr = pending.find('\r');
                        let nl = pending.find('\n');
                        match (cr, nl) {
                            (None, None) => break,
                            (Some(r), None) => {
                                let segment = pending[..r].to_string();
                                pending.drain(..=r);
                                if let Some(ref tx) = self.log_tx {
                                    let _ = tx.send(segment);
                                } else {
                                    eprint!("\r{}", segment);
                                    let _ = std::io::stderr().flush();
                                }
                            }
                            (None, Some(n)) => {
                                let line = pending[..n].to_string();
                                pending.drain(..=n);
                                stderr_all.push_str(&line);
                                stderr_all.push('\n');
                                if let Some(ref tx) = self.log_tx {
                                    let _ = tx.send(format!("{line}\n"));
                                } else if self.verbose {
                                    eprintln!("\r{}", line);
                                }
                            }
                            (Some(r), Some(n)) if r < n => {
                                let segment = pending[..r].to_string();
                                pending.drain(..=r);
                                if let Some(ref tx) = self.log_tx {
                                    let _ = tx.send(segment);
                                } else {
                                    eprint!("\r{}", segment);
                                    let _ = std::io::stderr().flush();
                                }
                            }
                            (_, Some(n)) => {
                                let line = pending[..n].to_string();
                                pending.drain(..=n);
                                stderr_all.push_str(&line);
                                stderr_all.push('\n');
                                if let Some(ref tx) = self.log_tx {
                                    let _ = tx.send(format!("{line}\n"));
                                } else if self.verbose {
                                    eprintln!("\r{}", line);
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if !pending.is_empty() {
            stderr_all.push_str(&pending);
        }

        if self.log_tx.is_none() {
            eprint!("\r{:width$}\r", "", width = 100);
            let _ = std::io::stderr().flush();
        }

        let status = child.wait().await.context("Failed to wait for restic process")?;
        let exit_code = status.code().unwrap_or(-1);
        let stdout = stdout_task.await.unwrap_or_default();

        Ok((exit_code, stdout, stderr_all))
    }

    /// Streaming variant of `run_checked`.
    async fn run_checked_streaming(&self, args: &[&str]) -> Result<(String, String)> {
        let (code, stdout, stderr) = self.run_streaming(args).await?;
        if code == 0 {
            Ok((stdout, stderr))
        } else {
            if !stderr.is_empty() {
                eprintln!("{stderr}");
            }
            Err(ResticError::Failed {
                exit_code: code,
                stderr,
            }
            .into())
        }
    }
}

// ── Result types ───────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ResticBackupResult {
    pub snapshot_id: String,
    pub files_new: u64,
    pub files_changed: u64,
    pub data_added: u64,
    pub duration_secs: f64,
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub short_id: String,
    pub time: String,
    pub hostname: String,
    pub paths: Vec<String>,
}

// ── Public functions ───────────────────────────────────────────

/// Initialize a new restic repository.
pub async fn init(ctx: &ResticContext) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would run: restic init -r {}", ctx.repo);
        return Ok(());
    }

    ctx.run_checked(&["init"]).await?;
    tracing::info!("Initialized restic repository: {}", ctx.repo);
    Ok(())
}

/// Create a backup snapshot.
pub async fn backup(
    ctx: &ResticContext,
    sources: &[String],
    excludes: &[String],
    excludes_from: &[String],
    exclude_if_present: &[String],
) -> Result<ResticBackupResult> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would run: restic backup {:?}", sources);
        return Ok(ResticBackupResult::default());
    }

    let mut args: Vec<String> = vec!["backup".to_string()];

    // Use JSON output for structured parsing
    args.push("--json".to_string());

    if ctx.verbose {
        args.push("--verbose".to_string());
    }

    for pattern in excludes {
        args.push("--exclude".to_string());
        args.push(pattern.clone());
    }

    for path in excludes_from {
        args.push("--exclude-file".to_string());
        args.push(path.clone());
    }

    for filename in exclude_if_present {
        args.push("--exclude-if-present".to_string());
        args.push(filename.clone());
    }

    for flag in &ctx.extra_flags {
        args.push(flag.clone());
    }

    for source in sources {
        args.push(source.clone());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let start = std::time::Instant::now();
    let (stdout, _stderr) = ctx.run_checked_streaming(&args_ref).await?;
    let duration_secs = start.elapsed().as_secs_f64();

    let result = parse_backup_json(&stdout, duration_secs);
    tracing::info!(
        "Created snapshot {} ({:.1}s, added: {} bytes)",
        result.snapshot_id,
        duration_secs,
        result.data_added,
    );
    Ok(result)
}

/// Forget old snapshots and prune unreferenced data.
pub async fn forget(
    ctx: &ResticContext,
    keep_daily: u32,
    keep_weekly: u32,
    keep_monthly: u32,
    keep_yearly: u32,
) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would prune {}", ctx.repo);
        return Ok(());
    }

    let kd = format!("--keep-daily={keep_daily}");
    let kw = format!("--keep-weekly={keep_weekly}");
    let km = format!("--keep-monthly={keep_monthly}");
    let ky = format!("--keep-yearly={keep_yearly}");
    let args = vec!["forget", "--prune", &kd, &kw, &km, &ky];

    ctx.run_checked(&args).await?;
    tracing::info!("Forgot/pruned repository: {}", ctx.repo);
    Ok(())
}

/// Check repository integrity.
pub async fn check(ctx: &ResticContext) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would check {}", ctx.repo);
        return Ok(());
    }

    ctx.run_checked_streaming(&["check"]).await?;
    tracing::info!("Checked repository: {}", ctx.repo);
    Ok(())
}

/// List snapshots.
pub async fn snapshots(ctx: &ResticContext) -> Result<Vec<SnapshotInfo>> {
    let (stdout, _) = ctx.run_checked(&["snapshots", "--json"]).await?;
    parse_snapshots_json(&stdout)
}

/// Restore a snapshot to a target directory.
pub async fn restore(
    ctx: &ResticContext,
    snapshot: &str,
    target: &str,
    dry_run: bool,
) -> Result<()> {
    let mut args = vec!["restore".to_string(), snapshot.to_string()];
    args.push("--target".to_string());
    args.push(target.to_string());
    if dry_run {
        args.push("--dry-run".to_string());
    }
    if ctx.verbose {
        args.push("--verbose".to_string());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ctx.run_checked_streaming(&args_ref).await?;
    Ok(())
}

/// Detect installed restic version.
pub async fn detect_version(binary: &str) -> Option<String> {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    Some(stdout.lines().next().unwrap_or("").to_string())
}

// ── JSON parsing helpers ───────────────────────────────────────

fn parse_backup_json(stdout: &str, duration: f64) -> ResticBackupResult {
    // restic --json outputs one JSON object per line.
    // The summary line has "message_type":"summary".
    let mut result = ResticBackupResult {
        duration_secs: duration,
        ..Default::default()
    };

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if val.get("message_type").and_then(|v| v.as_str()) == Some("summary") {
                result.snapshot_id = val["snapshot_id"].as_str().unwrap_or("").to_string();
                result.files_new = val["files_new"].as_u64().unwrap_or(0);
                result.files_changed = val["files_changed"].as_u64().unwrap_or(0);
                result.data_added = val["data_added"].as_u64().unwrap_or(0);
            }
        }
    }

    result
}

fn parse_snapshots_json(stdout: &str) -> Result<Vec<SnapshotInfo>> {
    let val: serde_json::Value = serde_json::from_str(stdout)
        .context("Failed to parse restic snapshots JSON")?;

    let arr = val.as_array()
        .context("Expected JSON array from restic snapshots")?;

    let mut snapshots = Vec::new();
    for item in arr {
        let id = item["id"].as_str().unwrap_or("").to_string();
        let short_id = item["short_id"].as_str().unwrap_or_else(|| {
            if id.len() >= 8 { &id[..8] } else { &id }
        }).to_string();
        let time = item["time"].as_str().unwrap_or("").to_string();
        let hostname = item["hostname"].as_str().unwrap_or("").to_string();
        let paths = item["paths"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        snapshots.push(SnapshotInfo {
            id,
            short_id,
            time,
            hostname,
            paths,
        });
    }

    Ok(snapshots)
}
