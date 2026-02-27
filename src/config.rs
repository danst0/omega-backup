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
            server: ServerConfig {
                host: "backup.local".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                admin_user: "borgadmin".to_string(),
                poll_interval_secs: 20,
                poll_timeout_secs: 120,
            },
            borg: BorgConfig {
                binary: "/usr/bin/borg".to_string(),
                check_frequency_days: 14,
            },
            ntfy: Some(NtfyConfig {
                url: "https://ntfy.example.com/topic".to_string(),
                token: Some("tk_test".to_string()),
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

    // ── AppState serialisation ───────────────────────────────────

    #[test]
    fn test_app_state_round_trip() {
        let mut state = AppState::default();
        {
            let cs = state.client_mut("client1");
            cs.last_backup_timestamp = Some("2026-02-27T02:00:00".to_string());
            cs.last_backup_result = Some("success".to_string());
            cs.integrity_status = Some("ok".to_string());
        }

        let json = serde_json::to_string_pretty(&state.0).unwrap();
        let map: std::collections::HashMap<String, ClientState> =
            serde_json::from_str(&json).unwrap();
        let loaded = AppState(map);

        let cs = loaded.client("client1").unwrap();
        assert_eq!(cs.last_backup_timestamp.as_deref(), Some("2026-02-27T02:00:00"));
        assert_eq!(cs.last_backup_result.as_deref(), Some("success"));
        assert_eq!(cs.integrity_status.as_deref(), Some("ok"));
        assert!(loaded.client("nonexistent").is_none());
    }

    // ── Config::find_client ──────────────────────────────────────

    #[test]
    fn test_find_client() {
        let cfg = Config {
            server: ServerConfig {
                host: "s".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                admin_user: "a".to_string(),
                poll_interval_secs: 15,
                poll_timeout_secs: 300,
            },
            borg: BorgConfig::default(),
            ntfy: None,
            clients: vec![
                ClientConfig {
                    name: "alpha".to_string(),
                    hostname: "alpha.local".to_string(),
                    main_repo: dummy_repo(),
                    offsite_repo: None,
                },
                ClientConfig {
                    name: "beta".to_string(),
                    hostname: "beta.local".to_string(),
                    main_repo: dummy_repo(),
                    offsite_repo: None,
                },
            ],
            keys: KeysConfig::default(),
            distribution: DistributionConfig::default(),
            retention: RetentionConfig::default(),
            offsite_retention: None,
        };

        assert_eq!(cfg.find_client("alpha").unwrap().name, "alpha");
        assert_eq!(cfg.find_client("beta").unwrap().hostname, "beta.local");
        assert!(cfg.find_client("gamma").is_none());
    }

    fn dummy_repo() -> RepoConfig {
        RepoConfig {
            path: "ssh://user@host/repo".to_string(),
            ssh_key: "/tmp/key".to_string(),
            passphrase_file: "/tmp/pass".to_string(),
            sources: vec!["/data".to_string()],
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            optional: false,
        }
    }
}
