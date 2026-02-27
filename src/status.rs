use anyhow::Result;
use chrono::{DateTime, Local};
use crate::config::{AppState, Config, ClientState};

pub async fn run_status(config: &Config) -> Result<()> {
    let state = AppState::load()?;
    
    println!("\n=== Backup Status ===\n");
    
    // Headers
    println!(
        "{:<20} | {:<25} | {:<15} | {:<25} | {:<15}",
        "Client", "Last Backup", "Result", "Last Check", "Integrity"
    );
    println!("{}", "-".repeat(110));

    // Sort clients by name for consistent output
    let mut clients = config.clients.clone();
    clients.sort_by(|a, b| a.name.cmp(&b.name));

    if clients.is_empty() {
        println!("No clients configured.");
        return Ok(());
    }

    for client in clients {
        let client_state = state.client(&client.name).cloned().unwrap_or_default();
        print_client_row(&client.name, &client_state);
    }
    
    println!();
    Ok(())
}

fn print_client_row(name: &str, state: &ClientState) {
    let last_backup = format_timestamp(state.last_backup_timestamp.as_deref());
    let last_result = state.last_backup_result.as_deref().unwrap_or("-");
    let last_check = format_timestamp(state.last_check_timestamp.as_deref());
    let integrity = state.integrity_status.as_deref().unwrap_or("-");

    // Colorize result if possible (using ANSI codes directly for simplicity since we don't have colored crate)
    // Actually let's just use text indicators for now to avoid dependency issues or terminal compat
    
    println!(
        "{:<20} | {:<25} | {:<15} | {:<25} | {:<15}",
        name, last_backup, last_result, last_check, integrity
    );
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
