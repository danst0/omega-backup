# Security Policy

This document outlines the security architecture of `omega-backup`, the measures taken to protect your data, and the known trade-offs made for automation and ease of use.

## Architecture Overview

`omega-backup` is an orchestration layer for [BorgBackup](https://www.borgbackup.org/). It manages the lifecycle of backups, including server wake-up (WoL), SSH connectivity, repository management, and secret distribution.

### 1. Data Encryption
All data managed by `omega-backup` is encrypted using Borg's native encryption.
- **Default Mode:** `repokey-blake2`.
- **Key Location:** Encrypted keys and passphrases are stored on the client machines.
- **Transport:** Data is encrypted *before* it leaves your machine and is transmitted over SSH.

### 2. Secret Storage
Secrets (SSH private keys, Borg passphrases, and exported repo keys) are stored locally on each client.
- **Default Directory:** `~/.borg-keys/`
- **Permissions:** The tool enforces `0600` (read/write only by the owner) on this directory and its contents.
- **Borg Passphrases:** Stored as plain text files within the restricted `~/.borg-keys/` directory.

### 3. SSH Security
The tool automates SSH connections to the backup server with the following security profile:
- **Authentication:** Uses SSH keys generated specifically for the backup task. These keys are typically created without a passphrase to allow for unattended automation.
- **Host Verification:** Uses `StrictHostKeyChecking=accept-new`. 
    - *Security Note:* This is a "Trust on First Use" (TOFU) model. It protects against future changes to the server's identity but is vulnerable to Man-in-the-Middle (MITM) attacks during the very first connection.
- **Access Control:** The tool expects (and during setup attempts to configure) the backup server to use `borg serve --restrict-to-path`. This ensures that even if a client's SSH key is compromised, the attacker can only access that specific client's backup repository.

### 4. Secret Distribution (`config sync`)
To simplify multi-machine setups, `omega-backup` includes a custom mechanism to share configuration and secrets over the local network.
- **Protocol:** Encrypted over HTTP using AES-256-GCM.
- **Key Exchange:** Uses a 32-bit session key derived from an 8-character hex "One-Time Code".
- **Limitations:** The 32-bit entropy is intended for short-lived sessions on trusted local networks. It is **not** resistant to high-speed brute-force attacks if the listener is left exposed for long periods.

## Known Security Trade-offs

1.  **Unprotected SSH Keys:** For automation to work without user intervention, the SSH private keys are stored without passphrases. Security relies entirely on the host machine's filesystem permissions.
2.  **Environment Variables:** Passphrases are passed to the Borg process via the `BORG_PASSPHRASE` environment variable. On some systems, this may be visible to other users via process listing tools (like `ps`).
3.  **GitHub Key Backup:** The optional `push-key` feature allows backing up your encrypted Borg keys to a private GitHub repository. This introduces a dependency on GitHub's security and your account's protection (MFA is strongly recommended).

## Best Practices

- **Limit Listener Use:** Only run `omega-backup config listen` while you are actively syncing a new machine. Do not leave it running.
- **Secure the Client:** Since the backup keys are stored in `~/.borg-keys/`, the security of your backups is tied to the security of your client machine. Use full-disk encryption (LUKS/FileVault) on your clients.
- **Monitor Notifications:** Configure the `ntfy` integration to receive alerts about successful or failed backups, which can help detect if a machine has stopped backing up or if unauthorized changes occurred.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please open a GitHub Issue or contact the maintainer directly.
