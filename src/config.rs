use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
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
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout_secs: u64,
}

fn default_poll_interval() -> u64 {
    15
}
fn default_poll_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BorgConfig {
    #[serde(default = "default_borg_binary")]
    pub binary: String,
    #[serde(default = "default_check_frequency")]
    pub check_frequency_days: u32,
}

fn default_borg_binary() -> String {
    "borg".to_string()
}
fn default_check_frequency() -> u32 {
    30
}

impl Default for BorgConfig {
    fn default() -> Self {
        Self {
            binary: default_borg_binary(),
            check_frequency_days: default_check_frequency(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NtfyConfig {
    pub url: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RepoConfig {
    pub path: String,
    pub ssh_key: String,
    pub passphrase_file: String,
    pub sources: Vec<String>,
    #[serde(default = "default_compression")]
    pub compression: String,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub optional: bool,
}

fn default_compression() -> String {
    "auto,zstd".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub name: String,
    pub hostname: String,
    pub main_repo: RepoConfig,
    pub offsite_repo: Option<RepoConfig>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub borg: BorgConfig,
    pub ntfy: Option<NtfyConfig>,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub keys: KeysConfig,
    #[serde(default)]
    pub distribution: DistributionConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    pub offsite_retention: Option<RetentionConfig>,
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

/// State tracking for clients
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ClientState {
    pub last_backup_timestamp: Option<String>,
    pub last_backup_result: Option<String>,
    pub last_check_timestamp: Option<String>,
    pub integrity_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AppState(pub std::collections::HashMap<String, ClientState>);

impl AppState {
    pub fn load() -> Result<Self> {
        let path = default_state_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read state file: {}", path.display()))?;
        let state: AppState = serde_json::from_str(&content)
            .context("Failed to parse state file")?;
        Ok(state)
    }

    pub fn save(&self) -> Result<()> {
        let path = default_state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create state directory: {}", parent.display()))?;
        }
        let content = serde_json::to_string_pretty(&self.0)
            .context("Failed to serialize state")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write state file: {}", path.display()))?;
        Ok(())
    }

    pub fn client_mut(&mut self, name: &str) -> &mut ClientState {
        self.0.entry(name.to_string()).or_default()
    }

    pub fn client(&self, name: &str) -> Option<&ClientState> {
        self.0.get(name)
    }
}
