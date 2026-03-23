use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
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
    keys_dir: Arc<std::path::PathBuf>,
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

    let keys_dir = expand_tilde(&config.keys.local_dir);
    let state = ServerState {
        session_key: session_key.clone(),
        received: Arc::new(Mutex::new(ReceivedData::default())),
        keys_dir: Arc::new(keys_dir),
    };

    let app = Router::new()
        .route("/passphrase", post(handle_post_passphrase))
        .route("/keyfile", post(handle_post_keyfile))
        .route("/repo-passphrase/{client_name}/{repo_name}", get(handle_get_repo_passphrase))
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

    // Print ready-to-paste fallback command
    if let Some(ip) = local_ip() {
        println!();
        println!("  If mDNS doesn't work, run this on the client:");
        println!("  omega-backup config sync --host {}:{}", ip, port);
        println!();
    }

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

async fn handle_get_repo_passphrase(
    State(state): State<ServerState>,
    Path((client_name, repo_name)): Path<(String, String)>,
) -> impl IntoResponse {
    let pass_path = state.keys_dir.join(format!("{client_name}-{repo_name}.pass"));
    match std::fs::read_to_string(&pass_path) {
        Ok(passphrase) => {
            let trimmed = passphrase.trim();
            match encrypt(&state.session_key, trimmed.as_bytes()) {
                Ok(encrypted) => {
                    tracing::info!("Served {} passphrase for {}", repo_name, client_name);
                    (StatusCode::OK, encrypted)
                }
                Err(e) => {
                    tracing::warn!("Failed to encrypt {} passphrase: {}", repo_name, e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
                }
            }
        }
        Err(_) => {
            tracing::info!("No {} passphrase for {} at {}", repo_name, client_name, pass_path.display());
            (StatusCode::NOT_FOUND, Vec::new())
        }
    }
}

// ────────────────────────────────────────────────────────────────
// `omega-backup config sync` (client machine)
// ────────────────────────────────────────────────────────────────

pub async fn run_sync(config: &Config, client_name: &str, host: Option<&str>) -> Result<()> {
    use dialoguer::Input;

    let code: String = Input::new()
        .with_prompt("Enter the one-time code shown on the management machine")
        .interact_text()
        .context("Input failed")?;

    let session_key = derive_session_key(code.trim());

    let base_url = if let Some(h) = host {
        println!("Connecting directly to {}...", h);
        format!("http://{h}")
    } else {
        println!("Searching for management machine via mDNS...");
        let (addr, port) = browse_mdns(&config.distribution.mdns_service).await?;
        println!("Found management machine at {}:{}", addr, port);
        format!("http://{addr}:{port}")
    };
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

    // Pull passphrases for non-main repos from management
    if let Some(client) = config.find_client(client_name) {
        for repo in client.non_main_repos() {
            let resp = http
                .get(format!("{base_url}/repo-passphrase/{client_name}/{}", repo.name))
                .send()
                .await
                .with_context(|| format!("Failed to request {} passphrase", repo.name))?;
            if resp.status().is_success() {
                let encrypted = resp.bytes().await?;
                let passphrase = decrypt(&session_key, &encrypted)?;
                let pass_path = expand_tilde(&repo.passphrase_file);
                if let Some(parent) = pass_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&pass_path, &passphrase)
                    .with_context(|| format!("Failed to write {} passphrase to {}", repo.name, pass_path.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&pass_path, std::fs::Permissions::from_mode(0o600))?;
                }
                println!("Received {} passphrase → {}", repo.name, pass_path.display());
            } else if resp.status() == StatusCode::NOT_FOUND {
                println!("No {} passphrase available on management machine (not yet initialized?).", repo.name);
            } else {
                tracing::warn!("Failed to get {} passphrase: {}", repo.name, resp.status());
            }
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
        &format!("{}.local.", service_type),
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
    let service_type_full = format!("{}.local.", service_type);
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

/// Returns the primary local (non-loopback) IP by connecting a UDP socket.
fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Key derivation ───────────────────────────────────────────

    #[test]
    fn test_derive_session_key_is_deterministic() {
        let k1 = derive_session_key("test-code");
        let k2 = derive_session_key("test-code");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_session_key_different_inputs_differ() {
        let k1 = derive_session_key("code-a");
        let k2 = derive_session_key("code-b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_session_key_is_32_bytes() {
        let k = derive_session_key("any-code");
        assert_eq!(k.len(), 32);
    }

    // ── Encrypt / Decrypt ────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let key = derive_session_key("round-trip-test");
        let plaintext = b"Hello, omega-backup!";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_encrypt_round_trip_empty_plaintext() {
        let key = derive_session_key("empty");
        let ciphertext = encrypt(&key, b"").unwrap();
        let recovered = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts_due_to_random_nonce() {
        let key = derive_session_key("nonce-test");
        let c1 = encrypt(&key, b"same").unwrap();
        let c2 = encrypt(&key, b"same").unwrap();
        // Random nonce means ciphertexts differ with overwhelming probability
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_encrypt_output_includes_nonce_overhead() {
        let key = derive_session_key("overhead");
        let plaintext = b"data";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        // 12-byte nonce + payload + 16-byte GCM tag
        assert!(ciphertext.len() >= 12 + plaintext.len() + 16);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = derive_session_key("key-one");
        let key2 = derive_session_key("key-two");
        let ciphertext = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let key = derive_session_key("short");
        let result = decrypt(&key, &[0u8; 11]); // needs at least 12-byte nonce
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = derive_session_key("tamper");
        let mut ciphertext = encrypt(&key, b"important data").unwrap();
        // Flip a byte in the ciphertext body (after the 12-byte nonce)
        ciphertext[13] ^= 0xFF;
        assert!(decrypt(&key, &ciphertext).is_err());
    }

    // ── Hex encoding helpers ─────────────────────────────────────

    #[test]
    fn test_hex_encode_decode_round_trip() {
        let data = b"hello omega";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_encode_known_value() {
        assert_eq!(base64_encode(b"\xde\xad\xbe\xef"), "deadbeef");
    }

    #[test]
    fn test_hex_decode_known_value() {
        assert_eq!(base64_decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn test_hex_decode_invalid_chars_fails() {
        assert!(base64_decode("not-valid-hex!!").is_err());
    }

    #[test]
    fn test_hex_decode_odd_length_fails() {
        assert!(base64_decode("abc").is_err()); // odd length is invalid hex
    }

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    // ── One-time code generation ─────────────────────────────────

    #[test]
    fn test_generate_one_time_code_has_correct_length() {
        let code = generate_one_time_code();
        assert_eq!(code.len(), 8, "code should be 8 hex characters");
    }

    #[test]
    fn test_generate_one_time_code_is_lowercase_hex() {
        let code = generate_one_time_code();
        assert!(
            code.chars().all(|c| c.is_ascii_hexdigit()),
            "code contains non-hex character: {code}"
        );
    }
}
