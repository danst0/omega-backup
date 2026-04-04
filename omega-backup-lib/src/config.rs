use anyhow::{Context, Result};
use chrono::{Local, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Config file not found at {0}")]
    NotFound(PathBuf),
    #[error("Failed to parse config: {0}")]
    ParseError(String),
    #[error("Invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub mac: String,
    pub admin_user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_ssh_key: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout_secs: u64,
    /// Minutes of backup inactivity before the server auto-shuts down (default: 90).
    #[serde(default = "default_shutdown_idle_minutes")]
    pub shutdown_idle_minutes: u64,
    /// Broadcast address for WoL packets (default: 255.255.255.255).
    #[serde(default = "default_broadcast")]
    pub broadcast: String,
}

fn default_poll_interval() -> u64 {
    15
}
fn default_poll_timeout() -> u64 {
    300
}
fn default_shutdown_idle_minutes() -> u64 {
    90
}
fn default_broadcast() -> String {
    "255.255.255.255".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BorgConfig {
    #[serde(default = "default_borg_binary")]
    pub binary: String,
    #[serde(default = "default_check_frequency")]
    pub check_frequency_days: u32,
    #[serde(default = "default_lock_wait_secs")]
    pub lock_wait_secs: u32,
}

fn default_borg_binary() -> String {
    "borg".to_string()
}
fn default_check_frequency() -> u32 {
    30
}
fn default_lock_wait_secs() -> u32 {
    300
}

impl Default for BorgConfig {
    fn default() -> Self {
        Self {
            binary: default_borg_binary(),
            check_frequency_days: default_check_frequency(),
            lock_wait_secs: default_lock_wait_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResticConfig {
    #[serde(default = "default_restic_binary")]
    pub binary: String,
}

fn default_restic_binary() -> String {
    "restic".to_string()
}

impl Default for ResticConfig {
    fn default() -> Self {
        Self {
            binary: default_restic_binary(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NtfyConfig {
    pub url: String,
    pub token: Option<String>,
    #[serde(default = "default_ntfy_topic")]
    pub topic: String,
}

fn default_ntfy_topic() -> String {
    "omega-backup".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RepoBackend {
    Borg {
        path: String,
        passphrase_file: String,
        ssh_key: String,
        #[serde(default = "default_compression")]
        compression: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        borg_filter: Option<String>,
    },
    Restic {
        /// Restic repository path, e.g. "rclone:gdrive:backup/client1"
        repo: String,
        /// Path to file containing the restic password
        password_file: String,
        /// Optional: path to rclone config (passed via RCLONE_CONFIG env)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rclone_config: Option<String>,
        /// Extra restic flags (e.g. ["--verbose", "--limit-upload=10000"])
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra_flags: Vec<String>,
    },
}

impl RepoBackend {
    pub fn is_borg(&self) -> bool {
        matches!(self, RepoBackend::Borg { .. })
    }

    pub fn is_restic(&self) -> bool {
        matches!(self, RepoBackend::Restic { .. })
    }

    /// Returns the repo path/URI for display purposes.
    pub fn repo_path(&self) -> &str {
        match self {
            RepoBackend::Borg { path, .. } => path,
            RepoBackend::Restic { repo, .. } => repo,
        }
    }

    /// Returns the password/passphrase file path.
    pub fn password_file(&self) -> &str {
        match self {
            RepoBackend::Borg { passphrase_file, .. } => passphrase_file,
            RepoBackend::Restic { password_file, .. } => password_file,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoConfig {
    pub name: String,
    pub backend: RepoBackend,
    pub sources: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub exclude_patterns_from: Vec<String>,
    #[serde(default)]
    pub exclude_if_present: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_create_commands: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_create_commands: Option<Vec<String>>,
}

impl RepoConfig {
    /// Create a new borg repo config with sensible defaults.
    pub fn new_borg(
        name: impl Into<String>,
        path: impl Into<String>,
        ssh_key: impl Into<String>,
        passphrase_file: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            backend: RepoBackend::Borg {
                path: path.into(),
                passphrase_file: passphrase_file.into(),
                ssh_key: ssh_key.into(),
                compression: default_compression(),
                borg_filter: None,
            },
            sources: Vec::new(),
            exclude_patterns: Vec::new(),
            exclude_patterns_from: Vec::new(),
            exclude_if_present: Vec::new(),
            optional: false,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        }
    }

    /// Create a new restic repo config with sensible defaults.
    pub fn new_restic(
        name: impl Into<String>,
        repo: impl Into<String>,
        password_file: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            backend: RepoBackend::Restic {
                repo: repo.into(),
                password_file: password_file.into(),
                rclone_config: None,
                extra_flags: Vec::new(),
            },
            sources: Vec::new(),
            exclude_patterns: Vec::new(),
            exclude_patterns_from: Vec::new(),
            exclude_if_present: Vec::new(),
            optional: false,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        }
    }

    pub fn is_borg(&self) -> bool {
        self.backend.is_borg()
    }

    pub fn is_restic(&self) -> bool {
        self.backend.is_restic()
    }

    /// Convenience: borg repo path. Panics if not a borg backend.
    pub fn path(&self) -> &str {
        match &self.backend {
            RepoBackend::Borg { path, .. } => path,
            _ => panic!("path() called on non-borg repo"),
        }
    }

    /// Convenience: borg passphrase file. Panics if not borg.
    pub fn passphrase_file(&self) -> &str {
        match &self.backend {
            RepoBackend::Borg { passphrase_file, .. } => passphrase_file,
            _ => panic!("passphrase_file() called on non-borg repo"),
        }
    }

    /// Convenience: borg ssh key. Panics if not borg.
    pub fn ssh_key(&self) -> &str {
        match &self.backend {
            RepoBackend::Borg { ssh_key, .. } => ssh_key,
            _ => panic!("ssh_key() called on non-borg repo"),
        }
    }

    /// Convenience: borg compression. Panics if not borg.
    pub fn compression(&self) -> &str {
        match &self.backend {
            RepoBackend::Borg { compression, .. } => compression,
            _ => panic!("compression() called on non-borg repo"),
        }
    }

    /// Convenience: borg filter. Panics if not borg.
    pub fn borg_filter(&self) -> Option<&str> {
        match &self.backend {
            RepoBackend::Borg { borg_filter, .. } => borg_filter.as_deref(),
            _ => panic!("borg_filter() called on non-borg repo"),
        }
    }
}

// Manual Deserialize for RepoConfig: supports both old borg-only format (no `type` field)
// and new tagged format (`type = "borg"` or `type = "restic"`).
impl<'de> Deserialize<'de> for RepoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = toml::Value::deserialize(deserializer)?;

        // Shared fields
        let name = value.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sources: Vec<String> = value.get("sources")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let exclude_patterns: Vec<String> = value.get("exclude_patterns")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let exclude_patterns_from: Vec<String> = value.get("exclude_patterns_from")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let exclude_if_present: Vec<String> = value.get("exclude_if_present")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let optional = value.get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let retention: Option<RetentionConfig> = value.get("retention")
            .and_then(|v| v.clone().try_into().ok());
        let pre_create_commands: Option<Vec<String>> = value.get("pre_create_commands")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect());
        let post_create_commands: Option<Vec<String>> = value.get("post_create_commands")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect());

        let repo_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("borg");

        let backend = match repo_type {
            "restic" => {
                let repo = value.get("repo")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("restic repo requires 'repo' field"))?
                    .to_string();
                let password_file = value.get("password_file")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("restic repo requires 'password_file' field"))?
                    .to_string();
                let rclone_config = value.get("rclone_config")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let extra_flags: Vec<String> = value.get("extra_flags")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                RepoBackend::Restic { repo, password_file, rclone_config, extra_flags }
            }
            _ => {
                // Default: borg (backward compat — no type field required)
                let path = value.get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("borg repo requires 'path' field"))?
                    .to_string();
                let ssh_key = value.get("ssh_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("borg repo requires 'ssh_key' field"))?
                    .to_string();
                let passphrase_file = value.get("passphrase_file")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("borg repo requires 'passphrase_file' field"))?
                    .to_string();
                let compression = value.get("compression")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto,zstd")
                    .to_string();
                let borg_filter = value.get("borg_filter")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                RepoBackend::Borg { path, passphrase_file, ssh_key, compression, borg_filter }
            }
        };

        Ok(RepoConfig {
            name,
            backend,
            sources,
            exclude_patterns,
            exclude_patterns_from,
            exclude_if_present,
            optional,
            retention,
            pre_create_commands,
            post_create_commands,
        })
    }
}

fn default_compression() -> String {
    "auto,zstd".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub name: String,
    pub hostname: String,
    pub repos: Vec<RepoConfig>,
}

impl ClientConfig {
    /// Find the main repo (name == "main").
    pub fn main_repo(&self) -> Option<&RepoConfig> {
        self.repos.iter().find(|r| r.name == "main")
    }

    /// Find a repo by name.
    pub fn find_repo(&self, name: &str) -> Option<&RepoConfig> {
        self.repos.iter().find(|r| r.name == name)
    }

    /// Iterate over all non-main repos.
    pub fn non_main_repos(&self) -> impl Iterator<Item = &RepoConfig> {
        self.repos.iter().filter(|r| r.name != "main")
    }
}

// Custom deserializer for backward compatibility: accepts both old format
// (main_repo + offsite_repo) and new format (repos array).
impl<'de> Deserialize<'de> for ClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct NewFormat {
            name: String,
            hostname: String,
            repos: Vec<RepoConfig>,
        }

        #[derive(Deserialize)]
        struct OldFormat {
            name: String,
            hostname: String,
            main_repo: RepoConfig,
            offsite_repo: Option<RepoConfig>,
        }

        let value = toml::Value::deserialize(deserializer)?;

        // Try new format first (has "repos" key)
        if value.get("repos").is_some() {
            let new: NewFormat = value
                .try_into()
                .map_err(serde::de::Error::custom)?;
            return Ok(ClientConfig {
                name: new.name,
                hostname: new.hostname,
                repos: new.repos,
            });
        }

        // Fall back to old format (has "main_repo" key)
        let old: OldFormat = value
            .try_into()
            .map_err(serde::de::Error::custom)?;

        let mut repos = vec![];
        let mut main = old.main_repo;
        main.name = "main".to_string();
        repos.push(main);

        if let Some(mut offsite) = old.offsite_repo {
            offsite.name = "offsite".to_string();
            repos.push(offsite);
        }

        Ok(ClientConfig {
            name: old.name,
            hostname: old.hostname,
            repos,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeysConfig {
    #[serde(default = "default_keys_local_dir")]
    pub local_dir: String,
    pub github_repo: Option<String>,
}

fn default_keys_local_dir() -> String {
    "~/.borg-keys/".to_string()
}

impl Default for KeysConfig {
    fn default() -> Self {
        Self {
            local_dir: default_keys_local_dir(),
            github_repo: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DistributionConfig {
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default = "default_listen_timeout")]
    pub listen_timeout_secs: u64,
    #[serde(default = "default_mdns_service")]
    pub mdns_service: String,
}

fn default_listen_timeout() -> u64 {
    300
}
fn default_mdns_service() -> String {
    "_omega-backup._tcp".to_string()
}

impl Default for DistributionConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            listen_timeout_secs: default_listen_timeout(),
            mdns_service: default_mdns_service(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScheduleConfig {
    #[serde(default = "default_backup_max_age_days")]
    pub backup_max_age_days: u32,
    #[serde(default = "default_prune_frequency_days")]
    pub prune_frequency_days: u32,
    #[serde(default = "default_schedule_check_frequency_days")]
    pub check_frequency_days: u32,
    #[serde(default = "default_restore_test_frequency_days")]
    pub restore_test_frequency_days: u32,
}

fn default_backup_max_age_days() -> u32 {
    2
}
fn default_prune_frequency_days() -> u32 {
    30
}
fn default_schedule_check_frequency_days() -> u32 {
    60
}
fn default_restore_test_frequency_days() -> u32 {
    30
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            backup_max_age_days: default_backup_max_age_days(),
            prune_frequency_days: default_prune_frequency_days(),
            check_frequency_days: default_schedule_check_frequency_days(),
            restore_test_frequency_days: default_restore_test_frequency_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetentionConfig {
    #[serde(default = "default_keep_daily")]
    pub keep_daily: u32,
    #[serde(default = "default_keep_weekly")]
    pub keep_weekly: u32,
    #[serde(default = "default_keep_monthly")]
    pub keep_monthly: u32,
    #[serde(default = "default_keep_yearly")]
    pub keep_yearly: u32,
}

fn default_keep_daily() -> u32 {
    7
}
fn default_keep_weekly() -> u32 {
    4
}
fn default_keep_monthly() -> u32 {
    12
}
fn default_keep_yearly() -> u32 {
    2
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            keep_daily: default_keep_daily(),
            keep_weekly: default_keep_weekly(),
            keep_monthly: default_keep_monthly(),
            keep_yearly: default_keep_yearly(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MachineRole {
    Client,
    Management,
    Both,
}

impl std::fmt::Display for MachineRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineRole::Client => write!(f, "client"),
            MachineRole::Management => write!(f, "management"),
            MachineRole::Both => write!(f, "both"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub role: Option<MachineRole>,
    pub server: ServerConfig,
    #[serde(default)]
    pub borg: BorgConfig,
    #[serde(default)]
    pub restic: ResticConfig,
    pub ntfy: Option<NtfyConfig>,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub keys: KeysConfig,
    #[serde(default)]
    pub distribution: DistributionConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    /// Deprecated: use per-repo retention overrides instead. Still accepted for backward compat.
    #[serde(default, skip_serializing)]
    pub offsite_retention: Option<RetentionConfig>,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    #[serde(default)]
    pub update: UpdateConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateConfig {
    #[serde(default = "default_update_check_enabled")]
    pub check_enabled: bool,
    #[serde(default = "default_repo_owner")]
    pub repo_owner: String,
    #[serde(default = "default_repo_name")]
    pub repo_name: String,
    pub pinned_version: Option<String>,
}

fn default_update_check_enabled() -> bool {
    true
}
fn default_repo_owner() -> String {
    "danst0".to_string()
}
fn default_repo_name() -> String {
    "omega-backup".to_string()
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            check_enabled: default_update_check_enabled(),
            repo_owner: default_repo_owner(),
            repo_name: default_repo_name(),
            pinned_version: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()).into());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Returns an error if the machine role doesn't match the expected role.
    pub fn require_role(&self, expected: MachineRole) -> Result<()> {
        if let Some(role) = self.role {
            let allowed = role == expected || role == MachineRole::Both;
            if !allowed {
                anyhow::bail!(
                    "This command requires role '{}', but this machine is configured as '{}'.",
                    expected,
                    role,
                );
            }
        }
        Ok(())
    }

    /// Returns true if the backup server is the local machine.
    pub fn server_is_local(&self) -> bool {
        let host = &self.server.host;
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return true;
        }
        if let Ok(local) = hostname::get() {
            if let Ok(local_str) = local.into_string() {
                return local_str == *host;
            }
        }
        false
    }

    pub fn load_from_default() -> Result<Self> {
        let path = default_config_path();
        Self::load(&path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.server.host.is_empty() {
            return Err(ConfigError::Invalid("server.host must not be empty".to_string()).into());
        }
        parse_mac_address(&self.server.mac)
            .map_err(|_| ConfigError::Invalid(format!("Invalid MAC address: {}", self.server.mac)))?;
        Ok(())
    }

    pub fn find_client(&self, name: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.name == name)
    }

    pub fn keys_local_dir(&self) -> PathBuf {
        expand_tilde(&self.keys.local_dir)
    }
}

pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("omega-backup")
        .join("config.toml")
}

pub fn default_state_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("~/.cache"))
        .join("omega-backup")
        .join("state.json")
}

pub fn default_log_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("omega-backup")
        .join("logs")
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/root"))
            .join(stripped)
    } else if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"))
    } else {
        PathBuf::from(path)
    }
}

pub fn parse_mac_address(mac: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("MAC address must have 6 octets separated by colons");
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("Invalid hex octet in MAC: {part}"))?;
    }
    Ok(bytes)
}

// ── Operation tracking types ────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Backup,
    Prune,
    Compact,
    Check,
    RestoreTest,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::Backup => write!(f, "backup"),
            OperationType::Prune => write!(f, "prune"),
            OperationType::Compact => write!(f, "compact"),
            OperationType::Check => write!(f, "check"),
            OperationType::RestoreTest => write!(f, "restore-test"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationResult {
    Success,
    Warning,
    Failed,
}

impl std::fmt::Display for OperationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationResult::Success => write!(f, "success"),
            OperationResult::Warning => write!(f, "warning"),
            OperationResult::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupStats {
    pub original_size: u64,
    pub compressed_size: u64,
    pub deduplicated_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_new: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_changed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_added: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperationRecord {
    pub operation: OperationType,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    pub result: OperationResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<BackupStats>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RepoState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup: Option<OperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_prune: Option<OperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compact: Option<OperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<OperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restore_test: Option<OperationRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<OperationRecord>,
}

/// Summary of a client's state across all its repos (for backward compat / GUI).
#[derive(Debug, Clone, Default)]
pub struct ClientSummary {
    pub last_backup_timestamp: Option<String>,
    pub last_backup_result: Option<OperationResult>,
    pub last_check_timestamp: Option<String>,
    pub integrity_status: Option<String>,
}

const MAX_HISTORY_PER_REPO: usize = 50;

// ── AppState (v2) ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AppState {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub repos: HashMap<String, RepoState>,
}

/// Legacy state format for migration from v1.
#[derive(Debug, Clone, Deserialize)]
struct LegacyClientState {
    last_backup_timestamp: Option<String>,
    last_backup_result: Option<String>,
    last_check_timestamp: Option<String>,
    integrity_status: Option<String>,
}

impl AppState {
    pub fn load() -> Result<Self> {
        let path = default_state_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read state file: {}", path.display()))?;

        if content.trim().is_empty() {
            return Ok(Self::default());
        }

        let value: serde_json::Value = serde_json::from_str(&content)
            .context("Failed to parse state file")?;

        // Detect format: v2 has a "version" key
        if value.get("version").and_then(|v| v.as_u64()).unwrap_or(0) >= 2 {
            let state: AppState = serde_json::from_value(value)
                .context("Failed to parse v2 state file")?;
            return Ok(state);
        }

        // Legacy format: HashMap<String, LegacyClientState>
        let legacy: HashMap<String, LegacyClientState> = serde_json::from_value(value)
            .context("Failed to parse legacy state file")?;
        let mut state = AppState { version: 2, repos: HashMap::new() };

        for (client_name, old) in legacy {
            let mut repo_state = RepoState::default();

            if let Some(ref ts) = old.last_backup_timestamp {
                let result = match old.last_backup_result.as_deref() {
                    Some("success") | Some("OK") => OperationResult::Success,
                    Some("WARNING") => OperationResult::Warning,
                    _ => OperationResult::Failed,
                };
                let record = OperationRecord {
                    operation: OperationType::Backup,
                    timestamp: ts.clone(),
                    duration_secs: None,
                    result,
                    message: None,
                    stats: None,
                };
                repo_state.history.push(record.clone());
                repo_state.last_backup = Some(record);
            }

            if let Some(ref ts) = old.last_check_timestamp {
                let result = match old.integrity_status.as_deref() {
                    Some("ok") | Some("OK") => OperationResult::Success,
                    Some("FAILED") => OperationResult::Failed,
                    _ => OperationResult::Warning,
                };
                let record = OperationRecord {
                    operation: OperationType::Check,
                    timestamp: ts.clone(),
                    duration_secs: None,
                    result,
                    message: old.integrity_status.clone(),
                    stats: None,
                };
                repo_state.history.push(record.clone());
                repo_state.last_check = Some(record);
            }

            let key = Self::repo_key(&client_name, "main");
            state.repos.insert(key, repo_state);
        }

        // Persist the migrated state
        if let Err(e) = state.save() {
            tracing::warn!("Failed to save migrated state: {}", e);
        }

        Ok(state)
    }

    pub fn save(&self) -> Result<()> {
        let path = default_state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
        }
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize state")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write state file: {}", path.display()))?;
        Ok(())
    }

    pub fn repo_key(client: &str, repo: &str) -> String {
        format!("{}/{}", client, repo)
    }

    pub fn repo_mut(&mut self, client: &str, repo: &str) -> &mut RepoState {
        let key = Self::repo_key(client, repo);
        self.repos.entry(key).or_default()
    }

    pub fn repo(&self, client: &str, repo: &str) -> Option<&RepoState> {
        let key = Self::repo_key(client, repo);
        self.repos.get(&key)
    }

    /// Record an operation: updates the matching `last_*` field and pushes to history.
    pub fn record_operation(&mut self, client: &str, repo: &str, record: OperationRecord) {
        let rs = self.repo_mut(client, repo);
        match record.operation {
            OperationType::Backup => rs.last_backup = Some(record.clone()),
            OperationType::Prune => rs.last_prune = Some(record.clone()),
            OperationType::Compact => rs.last_compact = Some(record.clone()),
            OperationType::Check => rs.last_check = Some(record.clone()),
            OperationType::RestoreTest => rs.last_restore_test = Some(record.clone()),
        }
        rs.history.insert(0, record);
        if rs.history.len() > MAX_HISTORY_PER_REPO {
            rs.history.truncate(MAX_HISTORY_PER_REPO);
        }
    }

    /// Check if an operation is overdue based on frequency_days.
    pub fn is_overdue(&self, client: &str, repo: &str, op: &OperationType, frequency_days: u32) -> bool {
        match self.days_since(client, repo, op) {
            Some(days) => days >= frequency_days as i64,
            None => true, // Never run → overdue
        }
    }

    /// Days since the last successful run of an operation type.
    pub fn days_since(&self, client: &str, repo: &str, op: &OperationType) -> Option<i64> {
        let rs = self.repo(client, repo)?;
        let record = match op {
            OperationType::Backup => rs.last_backup.as_ref(),
            OperationType::Prune => rs.last_prune.as_ref(),
            OperationType::Compact => rs.last_compact.as_ref(),
            OperationType::Check => rs.last_check.as_ref(),
            OperationType::RestoreTest => rs.last_restore_test.as_ref(),
        }?;
        parse_days_since(&record.timestamp)
    }

    /// Most recent backup across all repos for a client.
    pub fn client_last_backup(&self, client: &str) -> Option<&OperationRecord> {
        self.repos
            .iter()
            .filter(|(key, _)| key.starts_with(&format!("{}/", client)))
            .filter_map(|(_, rs)| rs.last_backup.as_ref())
            .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
    }

    /// Aggregate summary across all repos for a client (for GUI backward compat).
    pub fn client_summary(&self, client: &str) -> Option<ClientSummary> {
        let prefix = format!("{}/", client);
        let matching: Vec<_> = self.repos
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, rs)| rs)
            .collect();

        if matching.is_empty() {
            return None;
        }

        // Most recent backup across all repos
        let last_backup = matching.iter()
            .filter_map(|rs| rs.last_backup.as_ref())
            .max_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Most recent check across all repos
        let last_check = matching.iter()
            .filter_map(|rs| rs.last_check.as_ref())
            .max_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Worst integrity status (Failed > Warning > Success)
        let integrity = matching.iter()
            .filter_map(|rs| rs.last_check.as_ref())
            .map(|r| &r.result)
            .max_by(|a, b| {
                let rank = |r: &OperationResult| match r {
                    OperationResult::Success => 0,
                    OperationResult::Warning => 1,
                    OperationResult::Failed => 2,
                };
                rank(a).cmp(&rank(b))
            });

        Some(ClientSummary {
            last_backup_timestamp: last_backup.map(|r| r.timestamp.clone()),
            last_backup_result: last_backup.map(|r| r.result.clone()),
            last_check_timestamp: last_check.map(|r| r.timestamp.clone()),
            integrity_status: integrity.map(|r| r.to_string()),
        })
    }
}

/// Parse a timestamp string and return days elapsed since then.
fn parse_days_since(timestamp: &str) -> Option<i64> {
    let naive = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S").ok()?;
    let dt = Local.from_local_datetime(&naive).single()?;
    let elapsed = Local::now().signed_duration_since(dt);
    Some(elapsed.num_days())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── expand_tilde ─────────────────────────────────────────────

    #[test]
    fn test_expand_tilde_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~/foo/bar"), home.join("foo/bar"));
    }

    #[test]
    fn test_expand_tilde_solo() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~"), home);
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        assert_eq!(expand_tilde("/absolute/path"), std::path::PathBuf::from("/absolute/path"));
        assert_eq!(expand_tilde("relative/path"), std::path::PathBuf::from("relative/path"));
    }

    // ── parse_mac_address ────────────────────────────────────────

    #[test]
    fn test_parse_mac_valid_uppercase() {
        let mac = parse_mac_address("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_valid_lowercase() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_too_few_octets() {
        assert!(parse_mac_address("AA:BB:CC:DD:EE").is_err());
    }

    #[test]
    fn test_parse_mac_invalid_hex() {
        assert!(parse_mac_address("GG:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn test_parse_mac_wrong_separator() {
        assert!(parse_mac_address("AA-BB-CC-DD-EE-FF").is_err());
    }

    // ── Config::load ─────────────────────────────────────────────

    #[test]
    fn test_config_load_minimal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, r#"
[server]
host = "myserver"
mac = "AA:BB:CC:DD:EE:FF"
admin_user = "admin"
"#).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.server.host, "myserver");
        assert_eq!(cfg.server.mac, "AA:BB:CC:DD:EE:FF");
        // Defaults applied
        assert_eq!(cfg.borg.binary, "borg");
        assert_eq!(cfg.borg.check_frequency_days, 30);
        assert_eq!(cfg.retention.keep_daily, 7);
        assert_eq!(cfg.retention.keep_weekly, 4);
        assert!(cfg.clients.is_empty());
        assert!(cfg.ntfy.is_none());
    }

    #[test]
    fn test_config_load_not_found() {
        let err = Config::load(std::path::Path::new("/nonexistent/path/config.toml"))
            .unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("Config file"));
    }

    #[test]
    fn test_config_validate_empty_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[server]\nhost = \"\"\nmac = \"AA:BB:CC:DD:EE:FF\"\nadmin_user = \"admin\"\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn test_config_validate_invalid_mac() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[server]\nhost = \"s\"\nmac = \"not-a-mac\"\nadmin_user = \"admin\"\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    // ── Config::save + load round-trip ───────────────────────────

    #[test]
    fn test_config_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let original = Config {
            role: None,
            server: ServerConfig {
                host: "backup.local".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                admin_user: "borgadmin".to_string(),
                admin_ssh_key: None,
                poll_interval_secs: 20,
                poll_timeout_secs: 120,
                shutdown_idle_minutes: 90,
                broadcast: default_broadcast(),
            },
            borg: BorgConfig {
                binary: "/usr/bin/borg".to_string(),
                check_frequency_days: 14,
                lock_wait_secs: 300,
            },
            restic: ResticConfig::default(),
            ntfy: Some(NtfyConfig {
                url: "https://ntfy.example.com/topic".to_string(),
                token: Some("tk_test".to_string()),
                topic: "omega-backup".to_string(),
            }),
            clients: vec![],
            keys: KeysConfig::default(),
            distribution: DistributionConfig::default(),
            retention: RetentionConfig {
                keep_daily: 3,
                keep_weekly: 2,
                keep_monthly: 6,
                keep_yearly: 1,
            },
            offsite_retention: None,
            schedule: ScheduleConfig::default(),
            update: UpdateConfig::default(),
        };

        original.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(loaded.server.host, "backup.local");
        assert_eq!(loaded.server.mac, "11:22:33:44:55:66");
        assert_eq!(loaded.server.poll_interval_secs, 20);
        assert_eq!(loaded.borg.binary, "/usr/bin/borg");
        assert_eq!(loaded.borg.check_frequency_days, 14);
        assert_eq!(loaded.retention.keep_daily, 3);
        assert_eq!(loaded.retention.keep_monthly, 6);
        let ntfy = loaded.ntfy.unwrap();
        assert_eq!(ntfy.url, "https://ntfy.example.com/topic");
        assert_eq!(ntfy.token.as_deref(), Some("tk_test"));
    }

    #[test]
    fn test_config_load_old_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, r#"
[server]
host = "myserver"
mac = "AA:BB:CC:DD:EE:FF"
admin_user = "admin"

[[clients]]
name = "alpha"
hostname = "alpha.local"

[clients.main_repo]
path = "ssh://user@host/repo"
ssh_key = "/tmp/key"
passphrase_file = "/tmp/pass"
sources = ["/data"]

[clients.offsite_repo]
path = "ssh://user@host/offsite"
ssh_key = "/tmp/key2"
passphrase_file = "/tmp/pass2"
sources = ["/data"]
optional = true
"#).unwrap();
        let cfg = Config::load(&path).unwrap();
        let client = cfg.find_client("alpha").unwrap();
        assert_eq!(client.repos.len(), 2);
        assert_eq!(client.main_repo().unwrap().path(), "ssh://user@host/repo");
        assert_eq!(client.find_repo("offsite").unwrap().path(), "ssh://user@host/offsite");
        assert!(client.find_repo("offsite").unwrap().optional);
    }

    // ── AppState v2 serialisation ──────────────────────────────

    #[test]
    fn test_app_state_round_trip() {
        let mut state = AppState::default();
        state.version = 2;
        state.record_operation("client1", "main", OperationRecord {
            operation: OperationType::Backup,
            timestamp: "2026-02-27T02:00:00".to_string(),
            duration_secs: Some(12.5),
            result: OperationResult::Success,
            message: None,
            stats: Some(BackupStats {
                original_size: 1000,
                compressed_size: 800,
                deduplicated_size: 200,
                archive_name: Some("test-archive".to_string()),
                files_new: None,
                files_changed: None,
                data_added: None,
                snapshot_id: None,
            }),
        });

        let json = serde_json::to_string_pretty(&state).unwrap();
        let loaded: AppState = serde_json::from_str(&json).unwrap();

        let rs = loaded.repo("client1", "main").unwrap();
        let backup = rs.last_backup.as_ref().unwrap();
        assert_eq!(backup.timestamp, "2026-02-27T02:00:00");
        assert_eq!(backup.result, OperationResult::Success);
        assert_eq!(backup.stats.as_ref().unwrap().deduplicated_size, 200);
        assert_eq!(rs.history.len(), 1);
        assert!(loaded.repo("nonexistent", "main").is_none());
    }

    #[test]
    fn test_app_state_legacy_migration() {
        let legacy_json = r#"{
            "client1": {
                "last_backup_timestamp": "2026-02-27T02:00:00",
                "last_backup_result": "success",
                "last_check_timestamp": "2026-02-25T10:00:00",
                "integrity_status": "ok"
            }
        }"#;

        let value: serde_json::Value = serde_json::from_str(legacy_json).unwrap();
        // No "version" key, so this is legacy
        assert!(value.get("version").is_none());

        let legacy: std::collections::HashMap<String, LegacyClientState> =
            serde_json::from_value(value).unwrap();

        let mut state = AppState { version: 2, repos: std::collections::HashMap::new() };
        for (client_name, old) in legacy {
            let mut repo_state = RepoState::default();
            if let Some(ref ts) = old.last_backup_timestamp {
                let record = OperationRecord {
                    operation: OperationType::Backup,
                    timestamp: ts.clone(),
                    duration_secs: None,
                    result: OperationResult::Success,
                    message: None,
                    stats: None,
                };
                repo_state.history.push(record.clone());
                repo_state.last_backup = Some(record);
            }
            if let Some(ref ts) = old.last_check_timestamp {
                let record = OperationRecord {
                    operation: OperationType::Check,
                    timestamp: ts.clone(),
                    duration_secs: None,
                    result: OperationResult::Success,
                    message: old.integrity_status.clone(),
                    stats: None,
                };
                repo_state.history.push(record.clone());
                repo_state.last_check = Some(record);
            }
            state.repos.insert(AppState::repo_key(&client_name, "main"), repo_state);
        }

        let rs = state.repo("client1", "main").unwrap();
        assert_eq!(rs.last_backup.as_ref().unwrap().timestamp, "2026-02-27T02:00:00");
        assert_eq!(rs.last_check.as_ref().unwrap().result, OperationResult::Success);
        assert_eq!(rs.history.len(), 2);
    }

    #[test]
    fn test_record_operation_truncates_history() {
        let mut state = AppState { version: 2, repos: HashMap::new() };
        for i in 0..60 {
            state.record_operation("c", "main", OperationRecord {
                operation: OperationType::Backup,
                timestamp: format!("2026-01-{:02}T00:00:00", (i % 28) + 1),
                duration_secs: None,
                result: OperationResult::Success,
                message: None,
                stats: None,
            });
        }
        let rs = state.repo("c", "main").unwrap();
        assert_eq!(rs.history.len(), 50); // MAX_HISTORY_PER_REPO
    }

    #[test]
    fn test_client_summary() {
        let mut state = AppState { version: 2, repos: HashMap::new() };
        state.record_operation("client1", "main", OperationRecord {
            operation: OperationType::Backup,
            timestamp: "2026-03-20T02:00:00".to_string(),
            duration_secs: None,
            result: OperationResult::Success,
            message: None,
            stats: None,
        });
        state.record_operation("client1", "offsite", OperationRecord {
            operation: OperationType::Backup,
            timestamp: "2026-03-21T02:00:00".to_string(),
            duration_secs: None,
            result: OperationResult::Success,
            message: None,
            stats: None,
        });

        let summary = state.client_summary("client1").unwrap();
        // Should pick the most recent backup (offsite, 03-21)
        assert_eq!(summary.last_backup_timestamp.as_deref(), Some("2026-03-21T02:00:00"));
        assert!(state.client_summary("nonexistent").is_none());
    }

    // ── Config::find_client ──────────────────────────────────────

    #[test]
    fn test_find_client() {
        let cfg = Config {
            role: None,
            server: ServerConfig {
                host: "s".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                admin_user: "a".to_string(),
                admin_ssh_key: None,
                poll_interval_secs: 15,
                poll_timeout_secs: 300,
                shutdown_idle_minutes: 90,
                broadcast: default_broadcast(),
            },
            borg: BorgConfig::default(),
            restic: ResticConfig::default(),
            ntfy: None,
            clients: vec![
                ClientConfig {
                    name: "alpha".to_string(),
                    hostname: "alpha.local".to_string(),
                    repos: vec![dummy_repo("main")],
                },
                ClientConfig {
                    name: "beta".to_string(),
                    hostname: "beta.local".to_string(),
                    repos: vec![dummy_repo("main")],
                },
            ],
            keys: KeysConfig::default(),
            distribution: DistributionConfig::default(),
            retention: RetentionConfig::default(),
            offsite_retention: None,
            schedule: ScheduleConfig::default(),
            update: UpdateConfig::default(),
        };

        assert_eq!(cfg.find_client("alpha").unwrap().name, "alpha");
        assert_eq!(cfg.find_client("beta").unwrap().hostname, "beta.local");
        assert!(cfg.find_client("gamma").is_none());
    }

    fn dummy_repo(name: &str) -> RepoConfig {
        let mut r = RepoConfig::new_borg(
            name,
            "ssh://user@host/repo",
            "/tmp/key",
            "/tmp/pass",
        );
        r.sources = vec!["/data".to_string()];
        r
    }
}
