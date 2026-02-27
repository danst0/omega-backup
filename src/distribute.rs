use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

use crate::config::{Config, expand_tilde};

// ────────────────────────────────────────────────────────────────
// Crypto helpers (AES-256-GCM + HKDF)
// ────────────────────────────────────────────────────────────────

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;

fn derive_session_key(one_time_code: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, one_time_code.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"omega-backup-session-key", &mut key)
        .expect("HKDF expand failed");
    key
}

/// Encrypt plaintext bytes with AES-256-GCM.
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt nonce||ciphertext with AES-256-GCM.
pub fn decrypt(key_bytes: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("Ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed (wrong code?): {e}"))?;
    Ok(plaintext)
}

/// Generate a random one-time code (8 hex chars).
pub fn generate_one_time_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ────────────────────────────────────────────────────────────────
// Server state
// ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ReceivedData {
    passphrases: Vec<(String, String)>,  // (client_name, passphrase)
    keyfiles: Vec<(String, Vec<u8>)>,    // (client_name, keyfile_bytes)
}

#[derive(Clone)]
struct ServerState {
    session_key: Arc<[u8; 32]>,
    received: Arc<Mutex<ReceivedData>>,
    config_template: Arc<Vec<u8>>,
}

// ────────────────────────────────────────────────────────────────
// `omega-backup config listen` (management machine)
// ────────────────────────────────────────────────────────────────

pub async fn run_listen(config: &Config) -> Result<()> {
    let code = generate_one_time_code();
    println!("\n{}", "=".repeat(50));
    println!("  One-time code: {}", code);
    println!("  (Enter this code on each client when running `omega-backup config sync`)");
    println!("{}\n", "=".repeat(50));

    let session_key = Arc::new(derive_session_key(&code));

    // Load config template for distribution
    let config_path = crate::config::default_config_path();
    let config_bytes = if config_path.exists() {
        std::fs::read(&config_path).context("Failed to read config template")?
    } else {
        vec![]
    };

    let state = ServerState {
        session_key: session_key.clone(),
        received: Arc::new(Mutex::new(ReceivedData::default())),
        config_template: Arc::new(config_bytes),
    };

    let app = Router::new()
        .route("/passphrase", post(handle_post_passphrase))
        .route("/keyfile", post(handle_post_keyfile))
        .route("/config", get(handle_get_config))
        .with_state(state.clone());

    // Bind to a random port
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .context("Failed to bind TCP listener")?;
    let addr = listener.local_addr().context("Failed to get local address")?;
    let port = addr.port();

    println!("Distribution server listening on port {}", port);

    // Announce via mDNS
    let mdns = announce_mdns(port, &config.distribution.mdns_service).await?;

    println!("Announced via mDNS: {} on port {}", config.distribution.mdns_service, port);

    let timeout_secs = config.distribution.listen_timeout_secs;
    println!("Server will stop after {}s or Ctrl+C\n", timeout_secs);

    // Show spinner
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    pb.set_message("Waiting for clients...");
    pb.enable_steady_tick(Duration::from_millis(200));

    let server = tokio::spawn(async move {
        axum::serve(listener, app).await
    });

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
            pb.finish_with_message("Timeout reached, stopping server.");
        }
        _ = tokio::signal::ctrl_c() => {
            pb.finish_with_message("Interrupted, stopping server.");
        }
    }

    // Save received data
    {
        let data = state.received.lock().unwrap();
        save_received_data(&data, config).await?;
    }

    server.abort();
    drop(mdns);

    Ok(())
}

async fn save_received_data(data: &ReceivedData, config: &Config) -> Result<()> {
    let keys_dir = expand_tilde(&config.keys.local_dir);
    std::fs::create_dir_all(&keys_dir)?;

    for (client_name, passphrase) in &data.passphrases {
        let path = keys_dir.join(format!("{client_name}-main.pass"));
        std::fs::write(&path, passphrase)
            .with_context(|| format!("Failed to save passphrase for {client_name}"))?;
        println!("Saved passphrase for {client_name} → {}", path.display());
    }

    for (client_name, keyfile) in &data.keyfiles {
        let path = keys_dir.join(format!("{client_name}-main.key"));
        std::fs::write(&path, keyfile)
            .with_context(|| format!("Failed to save keyfile for {client_name}"))?;
        println!("Saved keyfile for {client_name} → {}", path.display());
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────
// Axum handlers
// ────────────────────────────────────────────────────────────────

async fn handle_post_passphrase(
    State(state): State<ServerState>,
    body: Bytes,
) -> impl IntoResponse {
    match decrypt(&state.session_key, &body) {
        Ok(plaintext) => {
            match serde_json::from_slice::<serde_json::Value>(&plaintext) {
                Ok(json) => {
                    let client_name = json["client_name"].as_str().unwrap_or("unknown").to_string();
                    let passphrase = json["passphrase"].as_str().unwrap_or("").to_string();
                    tracing::info!("Received passphrase from {}", client_name);
                    let mut recv = state.received.lock().unwrap();
                    recv.passphrases.push((client_name, passphrase));
                    (StatusCode::OK, "ok")
                }
                Err(e) => {
                    tracing::warn!("Failed to parse passphrase JSON: {}", e);
                    (StatusCode::BAD_REQUEST, "invalid json")
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to decrypt passphrase: {}", e);
            (StatusCode::UNAUTHORIZED, "decryption failed")
        }
    }
}

async fn handle_post_keyfile(
    State(state): State<ServerState>,
    body: Bytes,
) -> impl IntoResponse {
    match decrypt(&state.session_key, &body) {
        Ok(plaintext) => {
            match serde_json::from_slice::<serde_json::Value>(&plaintext) {
                Ok(json) => {
                    let client_name = json["client_name"].as_str().unwrap_or("unknown").to_string();
                    let keyfile_b64 = json["keyfile"].as_str().unwrap_or("");
                    // Decode from base64
                    let keyfile_bytes = base64_decode(keyfile_b64).unwrap_or_default();
                    tracing::info!("Received keyfile from {} ({} bytes)", client_name, keyfile_bytes.len());
                    let mut recv = state.received.lock().unwrap();
                    recv.keyfiles.push((client_name, keyfile_bytes));
                    (StatusCode::OK, "ok")
                }
                Err(e) => {
                    tracing::warn!("Failed to parse keyfile JSON: {}", e);
                    (StatusCode::BAD_REQUEST, "invalid json")
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to decrypt keyfile: {}", e);
            (StatusCode::UNAUTHORIZED, "decryption failed")
        }
    }
}

async fn handle_get_config(State(state): State<ServerState>) -> impl IntoResponse {
    match encrypt(&state.session_key, &state.config_template) {
        Ok(encrypted) => (StatusCode::OK, encrypted),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, vec![]),
    }
}

// ────────────────────────────────────────────────────────────────
// `omega-backup config sync` (client machine)
// ────────────────────────────────────────────────────────────────

pub async fn run_sync(config: &Config, client_name: &str) -> Result<()> {
    use dialoguer::Input;

    let code: String = Input::new()
        .with_prompt("Enter the one-time code shown on the management machine")
        .interact_text()
        .context("Input failed")?;

    let session_key = derive_session_key(code.trim());

    println!("Searching for management machine via mDNS...");

    let (addr, port) = browse_mdns(&config.distribution.mdns_service).await?;

    println!("Found management machine at {}:{}", addr, port);

    let base_url = format!("http://{addr}:{port}");
    let http = reqwest::Client::new();

    // Read passphrase
    let pass_path = expand_tilde(&config.keys.local_dir).join(format!("{client_name}-main.pass"));
    let passphrase = if pass_path.exists() {
        std::fs::read_to_string(&pass_path)
            .context("Failed to read passphrase file")?
            .trim()
            .to_string()
    } else {
        anyhow::bail!("Passphrase file not found: {}", pass_path.display());
    };

    // Send passphrase
    let pass_payload = serde_json::json!({
        "client_name": client_name,
        "passphrase": passphrase,
    });
    let encrypted_pass = encrypt(&session_key, pass_payload.to_string().as_bytes())?;
    let resp = http
        .post(format!("{base_url}/passphrase"))
        .body(encrypted_pass)
        .send()
        .await
        .context("Failed to send passphrase")?;
    if !resp.status().is_success() {
        anyhow::bail!("Server rejected passphrase: {}", resp.status());
    }
    println!("Sent passphrase to management machine.");

    // Send keyfile (if it exists)
    let key_path = expand_tilde(&config.keys.local_dir).join(format!("{client_name}-main.key"));
    if key_path.exists() {
        let keyfile_bytes = std::fs::read(&key_path).context("Failed to read keyfile")?;
        let keyfile_b64 = base64_encode(&keyfile_bytes);
        let key_payload = serde_json::json!({
            "client_name": client_name,
            "keyfile": keyfile_b64,
        });
        let encrypted_key = encrypt(&session_key, key_payload.to_string().as_bytes())?;
        let resp = http
            .post(format!("{base_url}/keyfile"))
            .body(encrypted_key)
            .send()
            .await
            .context("Failed to send keyfile")?;
        if !resp.status().is_success() {
            anyhow::bail!("Server rejected keyfile: {}", resp.status());
        }
        println!("Sent keyfile to management machine.");
    }

    // Receive config template
    let resp = http
        .get(format!("{base_url}/config"))
        .send()
        .await
        .context("Failed to fetch config template")?;
    if resp.status().is_success() {
        let encrypted_config = resp.bytes().await.context("Failed to read config response")?;
        let config_bytes = decrypt(&session_key, &encrypted_config)?;
        if !config_bytes.is_empty() {
            let config_path = crate::config::default_config_path();
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&config_path, &config_bytes)
                .context("Failed to write received config")?;
            println!("Received and saved config template → {}", config_path.display());
        }
    }

    println!("\nSync complete.");
    Ok(())
}

// ────────────────────────────────────────────────────────────────
// `omega-backup config push-key` (optional, DR backup)
// ────────────────────────────────────────────────────────────────

pub async fn push_key_to_github(config: &Config, client_name: &str) -> Result<()> {
    let github_repo = config.keys.github_repo.as_ref()
        .context("No github_repo configured in [keys]")?;

    let keys_dir = expand_tilde(&config.keys.local_dir);
    let key_path = keys_dir.join(format!("{client_name}-main.key"));

    if !key_path.exists() {
        anyhow::bail!("Keyfile not found: {}", key_path.display());
    }

    // Clone or use existing local repo
    let repo_dir = expand_tilde("~/.local/share/omega-backup/keyrepo");
    if !repo_dir.exists() {
        let status = tokio::process::Command::new("git")
            .args(["clone", github_repo, &repo_dir.display().to_string()])
            .status()
            .await
            .context("Failed to clone GitHub key repo")?;
        if !status.success() {
            anyhow::bail!("git clone failed");
        }
    }

    // Copy key file into repo
    let dest = repo_dir.join(format!("{client_name}-main.key"));
    std::fs::copy(&key_path, &dest)
        .context("Failed to copy keyfile into repo")?;

    // Commit and push
    for args in [
        vec!["add", dest.to_str().unwrap()],
        vec!["commit", "-m", &format!("Add keyfile for {client_name}")],
        vec!["push"],
    ] {
        let status = tokio::process::Command::new("git")
            .args(&args)
            .current_dir(&repo_dir)
            .status()
            .await
            .context("git command failed")?;
        if !status.success() {
            tracing::warn!("git {:?} returned non-zero (may be a no-op)", args);
        }
    }

    println!("Pushed keyfile for {client_name} to {github_repo}");
    Ok(())
}

// ────────────────────────────────────────────────────────────────
// mDNS helpers
// ────────────────────────────────────────────────────────────────

struct MdnsHandle(mdns_sd::ServiceDaemon);

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

async fn announce_mdns(port: u16, service_type: &str) -> Result<MdnsHandle> {
    use mdns_sd::{ServiceDaemon, ServiceInfo};

    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;

    let instance_name = format!("omega-backup-{}", std::process::id());

    let service = ServiceInfo::new(
        &format!("{}.", service_type),
        &instance_name,
        &format!("{}.local.", get_hostname_str()),
        (),
        port,
        None,
    )
    .context("Failed to create mDNS service info")?;

    mdns.register(service).context("Failed to register mDNS service")?;

    Ok(MdnsHandle(mdns))
}

async fn browse_mdns(service_type: &str) -> Result<(String, u16)> {
    use indicatif::{ProgressBar, ProgressStyle};
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
    let service_type_full = format!("{}.", service_type);
    let receiver = mdns.browse(&service_type_full).context("Failed to start mDNS browse")?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    pb.set_message("Browsing for management machine via mDNS...");
    pb.enable_steady_tick(Duration::from_millis(200));

    let timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                pb.finish_with_message("mDNS browse timeout");
                anyhow::bail!("Could not find management machine via mDNS within 30s");
            }
            event = tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(Duration::from_millis(500))
            }) => {
                if let Ok(Ok(ServiceEvent::ServiceResolved(info))) = event {
                    let addr = info.get_addresses()
                        .iter()
                        .next()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    let port = info.get_port();
                    pb.finish_with_message(format!("Found: {}:{}", addr, port));
                    let _ = mdns.shutdown();
                    return Ok((addr, port));
                }
            }
        }
    }
}

fn get_hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string())
}

// ────────────────────────────────────────────────────────────────
// Base64 helpers (no external dep needed for simple encode/decode)
// ────────────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    // Use a simple encoding via hex as fallback; ideally use base64 crate
    // For now we use hex encoding (always available)
    hex::encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).context("Failed to decode hex-encoded data")
}
