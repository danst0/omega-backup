use anyhow::{Context, Result};
use reqwest::Client;
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
}

/// Send a backup notification to ntfy.
pub async fn send_notification(cfg: &NtfyConfig<'_>, summary: &NotificationSummary) -> Result<()> {
    let client = Client::new();

    let title = if summary.success {
        format!("Backup OK: {}", summary.client_name)
    } else {
        format!("Backup FAILED: {}", summary.client_name)
    };

    // Priority 5 = urgent for errors, 3 = default for success
    let priority = if summary.success { "3" } else { "5" };
    let tags = if summary.success { "white_check_mark" } else { "x,sos" };

    let mut body = summary.message.clone();
    if let Some(duration) = summary.duration_secs {
        body.push_str(&format!("\nDuration: {:.1}s", duration));
    }
    if let Some(dedup) = summary.dedup_bytes {
        body.push_str(&format!("\nDeduplicated: {} bytes", dedup));
    }

    let mut req = client
        .post(cfg.url)
        .header("Title", &title)
        .header("Priority", priority)
        .header("Tags", tags)
        .body(body);

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
pub async fn send_simple(url: &str, token: Option<&str>, title: &str, message: &str, urgent: bool) -> Result<()> {
    let client = Client::new();
    let priority = if urgent { "5" } else { "3" };

    let mut req = client
        .post(url)
        .header("Title", title)
        .header("Priority", priority)
        .body(message.to_string());

    if let Some(token) = token {
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
