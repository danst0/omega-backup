use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime};
use std::collections::HashSet;
use crate::borg::{self, BorgContext};
use crate::config::{AppState, Config, ClientState};
use crate::ssh::{self, SshConfig};

pub async fn run_status(config: &Config) -> Result<()> {
    let state = AppState::load()?;

    // Sort clients by name for consistent output
    let mut clients = config.clients.clone();
    clients.sort_by(|a, b| a.name.cmp(&b.name));

    if clients.is_empty() {
        println!("No clients configured.");
        return Ok(());
    }

    // Build SSH config to check server
    let mut ssh_cfg = SshConfig::new(&config.server.host, &config.server.admin_user)
        .with_timeout(config.server.poll_interval_secs as u32);
    if let Some(ref key) = config.server.admin_ssh_key {
        ssh_cfg = ssh_cfg.with_key(key);
    }

    let server_online = ssh::is_reachable(&ssh_cfg).await;

    // Gather live data from server if reachable
    let active_hostnames: HashSet<String> = if server_online {
        match ssh::list_lockfile_names(&ssh_cfg).await {
            Ok(names) => names.into_iter().collect(),
            Err(e) => {
                tracing::warn!("Failed to list lockfiles: {}", e);
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };

    // Query latest archive for each client concurrently
    let archive_futures: Vec<_> = clients.iter().map(|client| {
        let repo = client.main_repo();
        let borg_binary = config.borg.binary.clone();
        let lock_wait = config.borg.lock_wait_secs;
        let online = server_online;
        async move {
            if !online {
                return (client.name.clone(), None);
            }
            let Some(repo) = repo else {
                return (client.name.clone(), None);
            };
            let ctx = BorgContext::new(&repo.path, &repo.passphrase_file)
                .with_ssh_key(&repo.ssh_key)
                .with_binary(borg_binary)
                .with_lock_wait(lock_wait);
            match borg::list_latest(&ctx).await {
                Ok(info) => (client.name.clone(), info),
                Err(e) => {
                    tracing::warn!("Failed to query repo for {}: {}", client.name, e);
                    (client.name.clone(), None)
                }
            }
        }
    }).collect();

    let archive_results = futures::future::join_all(archive_futures).await;
    let archive_map: std::collections::HashMap<String, _> = archive_results.into_iter().collect();

    // Print table
    println!("\n=== Backup Status ===\n");

    if !server_online {
        println!("  (server offline — showing cached data only)\n");
    }

    println!(
        "{:<20} | {:<19} | {:<10} | {:<10} | {:<19} | {:<10}",
        "Client", "Last Backup", "Age", "Status", "Last Check", "Integrity"
    );
    println!("{}", "-".repeat(99));

    for client in &clients {
        let client_state = state.client(&client.name).cloned().unwrap_or_default();
        let archive_info = archive_map.get(&client.name).and_then(|v| v.as_ref());
        let is_active = active_hostnames.contains(&client.hostname);
        print_client_row(&client.name, &client_state, archive_info, is_active);
    }

    println!();
    Ok(())
}

fn print_client_row(
    name: &str,
    state: &ClientState,
    archive: Option<&borg::ArchiveInfo>,
    is_active: bool,
) {
    // Prefer live archive data over cached state
    let (last_backup, age) = if let Some(info) = archive {
        let ts = format_borg_timestamp(&info.date);
        let age = format_age(&info.date);
        (ts, age)
    } else {
        let ts = format_timestamp(state.last_backup_timestamp.as_deref());
        (ts, "-".to_string())
    };

    let status = if is_active {
        "ACTIVE"
    } else {
        "-"
    };

    let last_check = format_timestamp(state.last_check_timestamp.as_deref());
    let integrity = state.integrity_status.as_deref().unwrap_or("-");

    println!(
        "{:<20} | {:<19} | {:<10} | {:<10} | {:<19} | {:<10}",
        name, last_backup, age, status, last_check, integrity
    );
}

/// Format a borg timestamp (e.g. "Mon, 2026-03-23 02:00:05") to "YYYY-MM-DD HH:MM".
fn format_borg_timestamp(ts: &str) -> String {
    if ts.is_empty() {
        return "-".to_string();
    }
    // Borg format: "Mon, 2026-03-23 02:00:05"
    // Try stripping the day-of-week prefix
    let date_part = if let Some((_dow, rest)) = ts.split_once(", ") {
        rest
    } else {
        ts
    };
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_part, "%Y-%m-%d %H:%M:%S") {
        dt.format("%Y-%m-%d %H:%M").to_string()
    } else {
        // Fallback: return as-is, truncated
        ts.chars().take(19).collect()
    }
}

/// Format age as human-friendly duration from a borg timestamp.
fn format_age(ts: &str) -> String {
    if ts.is_empty() {
        return "-".to_string();
    }
    let date_part = if let Some((_dow, rest)) = ts.split_once(", ") {
        rest
    } else {
        ts
    };
    let Ok(dt) = NaiveDateTime::parse_from_str(date_part, "%Y-%m-%d %H:%M:%S") else {
        return "-".to_string();
    };
    let now = Local::now().naive_local();
    let duration = now.signed_duration_since(dt);

    let total_secs = duration.num_seconds();
    if total_secs < 0 {
        return "future?".to_string();
    }

    let days = duration.num_days();
    let hours = duration.num_hours();
    let minutes = duration.num_minutes();

    if days > 0 {
        format!("{}d ago", days)
    } else if hours > 0 {
        format!("{}h ago", hours)
    } else if minutes > 0 {
        format!("{}m ago", minutes)
    } else {
        "just now".to_string()
    }
}

fn format_timestamp(ts: Option<&str>) -> String {
    match ts {
        Some(s) => {
            // Try to parse as RFC3339
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                dt.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
            } else {
                s.to_string() // Fallback if parsing fails
            }
        }
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_none_returns_dash() {
        assert_eq!(format_timestamp(None), "-");
    }

    #[test]
    fn test_format_timestamp_valid_utc_rfc3339() {
        let result = format_timestamp(Some("2026-01-15T10:30:00Z"));
        // Local time may differ from UTC, but date portion is stable for reasonable offsets
        assert!(result.contains("2026-01-15") || result.contains("2026-01-14"),
            "unexpected result: {result}");
        // Format must be "YYYY-MM-DD HH:MM"
        assert_eq!(result.len(), "2026-01-15 10:30".len());
    }

    #[test]
    fn test_format_timestamp_with_explicit_utc_offset() {
        let result = format_timestamp(Some("2026-06-01T12:00:00+00:00"));
        assert!(result.contains("2026-06-01") || result.contains("2026-05-31"),
            "unexpected result: {result}");
    }

    #[test]
    fn test_format_timestamp_garbage_falls_through() {
        let garbage = "not-a-timestamp";
        assert_eq!(format_timestamp(Some(garbage)), garbage);
    }

    #[test]
    fn test_format_timestamp_empty_string_falls_through() {
        assert_eq!(format_timestamp(Some("")), "");
    }

    #[test]
    fn test_format_timestamp_partial_date_falls_through() {
        let partial = "2026-01-15";
        assert_eq!(format_timestamp(Some(partial)), partial);
    }

    #[test]
    fn test_format_borg_timestamp() {
        assert_eq!(
            format_borg_timestamp("Mon, 2026-03-23 02:00:05"),
            "2026-03-23 02:00"
        );
    }

    #[test]
    fn test_format_borg_timestamp_empty() {
        assert_eq!(format_borg_timestamp(""), "-");
    }

    #[test]
    fn test_format_borg_timestamp_no_dow() {
        assert_eq!(
            format_borg_timestamp("2026-03-23 02:00:05"),
            "2026-03-23 02:00"
        );
    }

    #[test]
    fn test_format_age_empty() {
        assert_eq!(format_age(""), "-");
    }
}
