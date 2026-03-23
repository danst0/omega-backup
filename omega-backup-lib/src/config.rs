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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_ssh_key: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout_secs: u64,
    /// Minutes of backup inactivity before the server auto-shuts down (default: 90).
    #[serde(default = "default_shutdown_idle_minutes")]
    pub shutdown_idle_minutes: u64,
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
pub struct NtfyConfig {
    pub url: String,
    pub token: Option<String>,
    #[serde(default = "default_ntfy_topic")]
    pub topic: String,
}

fn default_ntfy_topic() -> String {
    "omega-backup".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoConfig {
    pub name: String,
    pub path: String,
    pub ssh_key: String,
    pub passphrase_file: String,
    pub sources: Vec<String>,
    #[serde(default = "default_compression")]
    pub compression: String,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub exclude_patterns_from: Vec<String>,
    #[serde(default)]
    pub exclude_if_present: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borg_filter: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_create_commands: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_create_commands: Option<Vec<String>>,
}

// Manual Deserialize for RepoConfig to handle missing `name` field (backward compat)
impl<'de> Deserialize<'de> for RepoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RepoConfigHelper {
            #[serde(default)]
            name: Option<String>,
            path: String,
            ssh_key: String,
            passphrase_file: String,
            #[serde(default)]
            sources: Vec<String>,
            #[serde(default = "default_compression")]
            compression: String,
            #[serde(default)]
            exclude_patterns: Vec<String>,
            #[serde(default)]
            exclude_patterns_from: Vec<String>,
            #[serde(default)]
            exclude_if_present: Vec<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            borg_filter: Option<String>,
            #[serde(default)]
            optional: bool,
            #[serde(default)]
            retention: Option<RetentionConfig>,
            #[serde(default)]
            pre_create_commands: Option<Vec<String>>,
            #[serde(default)]
            post_create_commands: Option<Vec<String>>,
        }
        let helper = RepoConfigHelper::deserialize(deserializer)?;
        Ok(RepoConfig {
            name: helper.name.unwrap_or_default(),
            path: helper.path,
            ssh_key: helper.ssh_key,
            passphrase_file: helper.passphrase_file,
            sources: helper.sources,
            compression: helper.compression,
            exclude_patterns: helper.exclude_patterns,
            exclude_patterns_from: helper.exclude_patterns_from,
            exclude_if_present: helper.exclude_if_present,
            borg_filter: helper.borg_filter,
            optional: helper.optional,
            retention: helper.retention,
            pre_create_commands: helper.pre_create_commands,
            post_create_commands: helper.post_create_commands,
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
            role: None,
            server: ServerConfig {
                host: "backup.local".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                admin_user: "borgadmin".to_string(),
                admin_ssh_key: None,
                poll_interval_secs: 20,
                poll_timeout_secs: 120,
                shutdown_idle_minutes: 90,
            },
            borg: BorgConfig {
                binary: "/usr/bin/borg".to_string(),
                check_frequency_days: 14,
                lock_wait_secs: 300,
            },
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
        assert_eq!(client.main_repo().unwrap().path, "ssh://user@host/repo");
        assert_eq!(client.find_repo("offsite").unwrap().path, "ssh://user@host/offsite");
        assert!(client.find_repo("offsite").unwrap().optional);
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
            role: None,
            server: ServerConfig {
                host: "s".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                admin_user: "a".to_string(),
                admin_ssh_key: None,
                poll_interval_secs: 15,
                poll_timeout_secs: 300,
                shutdown_idle_minutes: 90,
            },
            borg: BorgConfig::default(),
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
            update: UpdateConfig::default(),
        };

        assert_eq!(cfg.find_client("alpha").unwrap().name, "alpha");
        assert_eq!(cfg.find_client("beta").unwrap().hostname, "beta.local");
        assert!(cfg.find_client("gamma").is_none());
    }

    fn dummy_repo(name: &str) -> RepoConfig {
        RepoConfig {
            name: name.to_string(),
            path: "ssh://user@host/repo".to_string(),
            ssh_key: "/tmp/key".to_string(),
            passphrase_file: "/tmp/pass".to_string(),
            sources: vec!["/data".to_string()],
            compression: "auto,zstd".to_string(),
            exclude_patterns: vec![],
            exclude_patterns_from: vec![],
            exclude_if_present: vec![],
            borg_filter: None,
            optional: false,
            retention: None,
            pre_create_commands: None,
            post_create_commands: None,
        }
    }
}
