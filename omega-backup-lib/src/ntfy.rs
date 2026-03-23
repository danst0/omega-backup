use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NtfyError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),
    #[error("HTTP error {status}: {body}")]
    HttpError { status: u16, body: String },
}

#[derive(Debug, Clone)]
pub struct NotificationSummary {
    pub client_name: String,
    pub success: bool,
    pub message: String,
    pub duration_secs: Option<f64>,
    pub dedup_bytes: Option<u64>,
}

pub struct NtfyConfig<'a> {
    pub url: &'a str,
    pub token: Option<&'a str>,
    pub topic: &'a str,
}

/// Send a backup notification to ntfy.
pub async fn send_notification(cfg: &NtfyConfig<'_>, summary: &NotificationSummary) -> Result<()> {
    let client = Client::new();

    let title = notification_title(&summary.client_name, summary.success);
    let priority = notification_priority(summary.success);
    let tags = if summary.success {
        vec!["white_check_mark"]
    } else {
        vec!["x", "sos"]
    };
    let body = notification_body(&summary.message, summary.duration_secs, summary.dedup_bytes);

    let json_body = json!({
        "topic": cfg.topic,
        "title": title,
        "message": body,
        "priority": priority,
        "tags": tags,
    });

    let mut req = client
        .post(cfg.url)
        .header("Content-Type", "application/json")
        .body(json_body.to_string());

    if let Some(token) = cfg.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let response = req
        .send()
        .await
        .context("Failed to send ntfy notification")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(NtfyError::HttpError {
            status: status.as_u16(),
            body,
        }
        .into());
    }

    tracing::info!("Sent ntfy notification: {} (priority={})", title, priority);
    Ok(())
}

/// Send a simple text notification.
pub async fn send_simple(cfg: &NtfyConfig<'_>, title: &str, message: &str, urgent: bool) -> Result<()> {
    let client = Client::new();
    let priority: u8 = if urgent { 5 } else { 3 };

    let json_body = json!({
        "topic": cfg.topic,
        "title": title,
        "message": message,
        "priority": priority,
    });

    let mut req = client
        .post(cfg.url)
        .header("Content-Type", "application/json")
        .body(json_body.to_string());

    if let Some(token) = cfg.token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let response = req.send().await.context("Failed to send ntfy notification")?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(NtfyError::HttpError {
            status: status.as_u16(),
            body,
        }
        .into());
    }

    Ok(())
}

fn notification_title(client_name: &str, success: bool) -> String {
    if success {
        format!("Backup OK: {client_name}")
    } else {
        format!("Backup FAILED: {client_name}")
    }
}

fn notification_priority(success: bool) -> u8 {
    if success { 3 } else { 5 }
}

fn notification_body(message: &str, duration_secs: Option<f64>, dedup_bytes: Option<u64>) -> String {
    let mut body = message.to_string();
    if let Some(duration) = duration_secs {
        body.push_str(&format!("\nDuration: {:.1}s", duration));
    }
    if let Some(dedup) = dedup_bytes {
        body.push_str(&format!("\nDeduplicated: {} bytes", dedup));
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── notification_title ───────────────────────────────────────

    #[test]
    fn test_notification_title_success() {
        assert_eq!(notification_title("myclient", true), "Backup OK: myclient");
    }

    #[test]
    fn test_notification_title_failure() {
        assert_eq!(notification_title("myclient", false), "Backup FAILED: myclient");
    }

    #[test]
    fn test_notification_title_contains_client_name() {
        assert!(notification_title("desktop-01", true).contains("desktop-01"));
    }

    // ── notification_priority ────────────────────────────────────

    #[test]
    fn test_notification_priority_success_is_3() {
        assert_eq!(notification_priority(true), 3);
    }

    #[test]
    fn test_notification_priority_failure_is_5() {
        assert_eq!(notification_priority(false), 5);
    }

    // ── notification_body ────────────────────────────────────────

    #[test]
    fn test_notification_body_message_only() {
        assert_eq!(notification_body("Backup completed.", None, None), "Backup completed.");
    }

    #[test]
    fn test_notification_body_with_duration() {
        let body = notification_body("OK", Some(42.5), None);
        assert!(body.contains("Duration: 42.5s"), "body was: {body}");
    }

    #[test]
    fn test_notification_body_with_dedup() {
        let body = notification_body("OK", None, Some(1024));
        assert!(body.contains("Deduplicated: 1024 bytes"), "body was: {body}");
    }

    #[test]
    fn test_notification_body_with_all_fields() {
        let body = notification_body("main backup: OK", Some(10.0), Some(512));
        assert!(body.contains("main backup: OK"));
        assert!(body.contains("Duration: 10.0s"));
        assert!(body.contains("Deduplicated: 512 bytes"));
    }

    #[test]
    fn test_notification_body_duration_one_decimal_place() {
        let body = notification_body("", Some(1.0), None);
        assert!(body.contains("1.0s"), "body was: {body}");
        assert!(!body.contains("1.00s"), "too many decimal places in: {body}");
    }
}
