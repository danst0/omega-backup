use anyhow::{Context, Result};
use chrono::Local;
use std::collections::HashMap;
use thiserror::Error;
use tokio::process::Command;

#[derive(Debug, Error)]
pub enum BorgError {
    #[error("borg exited with error code {exit_code}: {stderr}")]
    Failed { exit_code: i32, stderr: String },
    #[error("borg warning (exit code 1): {stderr}")]
    Warning { stderr: String },
    #[error("borg passphrase file not found: {0}")]
    PassphraseFileNotFound(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct BorgContext {
    pub repo: String,
    pub passphrase_file: String,
    pub ssh_key: Option<String>,
    pub key_file: Option<String>,
    pub binary: String,
    pub dry_run: bool,
    pub verbose: bool,
}

impl BorgContext {
    pub fn new(repo: impl Into<String>, passphrase_file: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            passphrase_file: passphrase_file.into(),
            ssh_key: None,
            key_file: None,
            binary: "borg".to_string(),
            dry_run: false,
            verbose: false,
        }
    }

    pub fn with_ssh_key(mut self, key: impl Into<String>) -> Self {
        self.ssh_key = Some(key.into());
        self
    }

    pub fn with_key_file(mut self, key_file: impl Into<String>) -> Self {
        self.key_file = Some(key_file.into());
        self
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

    /// Read passphrase from file.
    fn read_passphrase(&self) -> Result<String> {
        let path = crate::config::expand_tilde(&self.passphrase_file);
        if !path.exists() {
            return Err(BorgError::PassphraseFileNotFound(
                self.passphrase_file.clone(),
            )
            .into());
        }
        let pass = std::fs::read_to_string(&path)
            .with_context(|| {
                format!("Failed to read passphrase file: {}", path.display())
            })?;
        Ok(pass.trim().to_string())
    }

    /// Build environment variables for borg.
    fn env_vars(&self) -> Result<HashMap<String, String>> {
        let mut env = HashMap::new();
        let passphrase = self.read_passphrase()?;
        env.insert("BORG_PASSPHRASE".to_string(), passphrase);

        if let Some(ref key) = self.ssh_key {
            let key_path = crate::config::expand_tilde(key);
            env.insert(
                "BORG_RSH".to_string(),
                format!("ssh -i {} -o BatchMode=yes -o StrictHostKeyChecking=accept-new", key_path.display()),
            );
        }

        if let Some(ref key_file) = self.key_file {
            let key_path = crate::config::expand_tilde(key_file);
            env.insert("BORG_KEY_FILE".to_string(), key_path.display().to_string());
        }

        Ok(env)
    }

    /// Run a borg subcommand, returning (exit_code, stdout, stderr).
    async fn run(&self, args: &[&str]) -> Result<(i32, String, String)> {
        let env = self.env_vars()?;

        let mut cmd = Command::new(&self.binary);
        cmd.args(args);
        for (k, v) in &env {
            cmd.env(k, v);
        }

        tracing::debug!("Running: {} {}", self.binary, args.join(" "));

        let output = cmd.output().await.context("Failed to spawn borg process")?;
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if self.verbose && !stderr.is_empty() {
            for line in stderr.lines() {
                tracing::debug!("borg: {}", line);
            }
        }

        Ok((exit_code, stdout, stderr))
    }

    /// Run borg and handle exit codes: 0=ok, 1=warning, 2+=error.
    async fn run_checked(&self, args: &[&str]) -> Result<(String, String)> {
        let (code, stdout, stderr) = self.run(args).await?;
        match code {
            0 => Ok((stdout, stderr)),
            1 => {
                tracing::warn!("borg warning: {}", stderr.trim());
                Ok((stdout, stderr))
            }
            _ => Err(BorgError::Failed {
                exit_code: code,
                stderr,
            }
            .into()),
        }
    }
}

#[derive(Debug, Default)]
pub struct BorgCreateResult {
    pub archive_name: String,
    pub original_size: u64,
    pub compressed_size: u64,
    pub deduplicated_size: u64,
    pub duration_secs: f64,
    pub had_warnings: bool,
}

/// Generate an archive name with timestamp: {hostname}-{YYYY-MM-DDTHH:MM:SS}
pub fn archive_name(hostname: &str) -> String {
    let now = Local::now();
    format!("{}-{}", hostname, now.format("%Y-%m-%dT%H:%M:%S"))
}

/// Initialize a new borg repository.
pub async fn init(ctx: &BorgContext, encryption: &str) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would run: borg init --encryption={} {}", encryption, ctx.repo);
        return Ok(());
    }

    let args = vec!["init", "--encryption", encryption, &ctx.repo];
    ctx.run_checked(&args).await?;
    tracing::info!("Initialized borg repository: {}", ctx.repo);
    Ok(())
}

/// Create a backup archive.
pub async fn create(
    ctx: &BorgContext,
    hostname: &str,
    sources: &[String],
    compression: &str,
    excludes: &[String],
) -> Result<BorgCreateResult> {
    let name = archive_name(hostname);
    let archive_ref = format!("{}::{}", ctx.repo, name);

    if ctx.dry_run {
        tracing::info!("[dry-run] Would run: borg create {} {:?}", archive_ref, sources);
        return Ok(BorgCreateResult {
            archive_name: name,
            ..Default::default()
        });
    }

    let mut args: Vec<String> = vec![
        "create".to_string(),
        "--compression".to_string(),
        compression.to_string(),
        "--stats".to_string(),
    ];

    if ctx.verbose {
        args.push("--progress".to_string());
        args.push("--list".to_string());
    }

    for pattern in excludes {
        args.push("--exclude".to_string());
        args.push(pattern.clone());
    }

    args.push(archive_ref.clone());
    for source in sources {
        args.push(source.clone());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let start = std::time::Instant::now();
    let (stdout, stderr) = ctx.run_checked(&args_ref).await?;
    let duration_secs = start.elapsed().as_secs_f64();

    let result = parse_create_stats(&stdout, &stderr, &name, duration_secs);
    tracing::info!(
        "Created archive {} ({:.1}s, dedup: {} bytes)",
        name,
        duration_secs,
        result.deduplicated_size
    );
    Ok(result)
}

fn parse_create_stats(stdout: &str, stderr: &str, name: &str, duration: f64) -> BorgCreateResult {
    // Parse `--stats` output from stderr (borg writes stats to stderr)
    let combined = format!("{stdout}{stderr}");
    let mut original = 0u64;
    let mut compressed = 0u64;
    let mut dedup = 0u64;

    for line in combined.lines() {
        if line.contains("This archive:") || line.contains("All archives:") {
            // skip summary lines with multiple values
        }
        if line.trim_start().starts_with("Original size:") {
            original = parse_size_bytes(line);
        } else if line.trim_start().starts_with("Compressed size:") {
            compressed = parse_size_bytes(line);
        } else if line.trim_start().starts_with("Deduplicated size:") {
            dedup = parse_size_bytes(line);
        }
    }

    BorgCreateResult {
        archive_name: name.to_string(),
        original_size: original,
        compressed_size: compressed,
        deduplicated_size: dedup,
        duration_secs: duration,
        had_warnings: false,
    }
}

fn parse_size_bytes(line: &str) -> u64 {
    // Example: "  Original size:      1.23 GB"
    // Just extract the numeric part and convert approximately
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 {
        if let Ok(val) = parts[parts.len() - 2].parse::<f64>() {
            let unit = parts[parts.len() - 1];
            let multiplier = match unit {
                "kB" => 1_000u64,
                "MB" => 1_000_000,
                "GB" => 1_000_000_000,
                "TB" => 1_000_000_000_000,
                "B" | _ => 1,
            };
            return (val * multiplier as f64) as u64;
        }
    }
    0
}

pub struct PrunePolicy {
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
    pub keep_yearly: u32,
    pub prefix: Option<String>,
}

/// Prune old archives.
pub async fn prune(ctx: &BorgContext, policy: &PrunePolicy) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would prune {}", ctx.repo);
        return Ok(());
    }

    let mut args = vec![
        "prune".to_string(),
        "--stats".to_string(),
        format!("--keep-daily={}", policy.keep_daily),
        format!("--keep-weekly={}", policy.keep_weekly),
        format!("--keep-monthly={}", policy.keep_monthly),
        format!("--keep-yearly={}", policy.keep_yearly),
    ];

    if let Some(ref prefix) = policy.prefix {
        args.push(format!("--glob-archives={prefix}-*"));
    }

    args.push(ctx.repo.clone());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ctx.run_checked(&args_ref).await?;
    tracing::info!("Pruned repository: {}", ctx.repo);
    Ok(())
}

/// Compact the repository (free unused space).
pub async fn compact(ctx: &BorgContext) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would compact {}", ctx.repo);
        return Ok(());
    }

    let args = &["compact", &ctx.repo];
    ctx.run_checked(args).await?;
    tracing::info!("Compacted repository: {}", ctx.repo);
    Ok(())
}

/// Check repository integrity.
pub async fn check(ctx: &BorgContext, full: bool) -> Result<()> {
    if ctx.dry_run {
        tracing::info!("[dry-run] Would check {} (full={})", ctx.repo, full);
        return Ok(());
    }

    let mut args: Vec<String> = vec!["check".to_string()];
    if full {
        args.push("--verify-data".to_string());
    }
    args.push(ctx.repo.clone());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    ctx.run_checked(&args_ref).await?;
    tracing::info!(
        "Checked repository: {} (full={})",
        ctx.repo,
        full
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    pub name: String,
    pub date: String,
}

/// List recent archives.
pub async fn list(ctx: &BorgContext, limit: usize) -> Result<Vec<ArchiveInfo>> {
    let last_str = limit.to_string();
    let args = &["list", "--last", &last_str, "--format={archive}{NL}", &ctx.repo];
    let (stdout, _) = ctx.run_checked(args).await?;

    let archives: Vec<ArchiveInfo> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| ArchiveInfo {
            name: l.trim().to_string(),
            date: String::new(),
        })
        .collect();

    Ok(archives)
}

/// Extract an archive or specific paths from it.
pub async fn extract(
    ctx: &BorgContext,
    archive: &str,
    paths: &[String],
    dest: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let archive_ref = format!("{}::{}", ctx.repo, archive);

    let mut args: Vec<String> = vec!["extract".to_string()];
    if dry_run {
        args.push("--dry-run".to_string());
    }
    if ctx.verbose {
        args.push("--list".to_string());
    }
    args.push(archive_ref);
    for path in paths {
        args.push(path.clone());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    if let Some(dir) = dest {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create destination directory: {dir}"))?;
        // borg extract must be run from the destination directory
        let env = ctx.env_vars()?;
        let mut cmd = Command::new(&ctx.binary);
        cmd.args(&args_ref).current_dir(dir);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let output = cmd.output().await.context("Failed to run borg extract")?;
        let exit_code = output.status.code().unwrap_or(-1);
        if exit_code >= 2 {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(BorgError::Failed { exit_code, stderr }.into());
        }
    } else {
        ctx.run_checked(&args_ref).await?;
    }

    Ok(())
}

/// Export the borg key to a file.
pub async fn export_key(ctx: &BorgContext, key_path: &str) -> Result<()> {
    let args = &["key", "export", &ctx.repo, key_path];
    ctx.run_checked(args).await?;
    tracing::info!("Exported borg key to: {}", key_path);
    Ok(())
}

/// Try to break any stale lock on the repository.
pub async fn break_lock(ctx: &BorgContext) -> Result<()> {
    let args = &["break-lock", &ctx.repo];
    let _ = ctx.run(args).await; // best-effort
    Ok(())
}

/// Detect installed borg version.
pub async fn detect_version(binary: &str) -> Option<String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = stdout.lines().next().unwrap_or("").to_string();
    Some(line)
}
