# omega-backup

A secure, high-performance [BorgBackup](https://www.borgbackup.org/) orchestration CLI written in Rust. `omega-backup` simplifies managing multi-machine backups by automating server wake-up (WoL), SSH connectivity, repository initialization, and automated maintenance tasks.

## Key Features

- **Automated Orchestration:** Manages server wake-up (WoL), SSH status monitoring, and automated shutdown after backup completion.
- **Multi-Machine Management:** Centralized configuration for multiple clients, each backing up to its own repository.
- **Secure Key Distribution:** Custom encrypted protocol for syncing Borg keys and passphrases across machines during initial setup.
- **Comprehensive Maintenance:** Integrated commands for pruning old archives, compacting repositories, and performing integrity checks.
- **Interactive Setup:** Guided wizard to generate configuration and initial security keys.
- **Restore Testing:** Built-in command to verify archive integrity and test extraction.
- **Notifications:** Integrated support for [ntfy](https://ntfy.sh/) for real-time backup status updates.

## Prerequisites

- **BorgBackup:** Must be installed on both client and server machines.
- **SSH:** Key-based authentication must be used between clients and the backup server.
- **Rust (optional):** Required to build from source.

## Getting Started

### 1. Installation

Clone the repository and build using Cargo:

```bash
git clone https://github.com/youruser/omega-backup.git
cd omega-backup
cargo build --release
```

The binary will be available at `target/release/omega-backup`.

### 2. Initial Setup

Run the interactive setup wizard to generate your initial configuration:

```bash
omega-backup config
```

The wizard will guide you through:
- Defining your backup server (Host, MAC address, Admin user).
- Generating SSH keys for backup tasks.
- Creating your first backup client and repository passphrase.

### 3. Initialize Repositories

Once configured, initialize your Borg repositories:

```bash
omega-backup init
```

### 4. Perform a Backup

Run a manual backup to verify everything is working:

```bash
omega-backup backup
```

## Usage

### Commands

- `omega-backup backup`: Performs a backup according to the client's configuration.
- `omega-backup maintain`: Prunes old archives, compacts space, and performs integrity checks.
- `omega-backup config listen`: Starts a local server to distribute configuration and keys to other machines.
- `omega-backup config sync`: Connects to a listener to receive configuration and keys.
- `omega-backup restore-test`: Lists recent archives and optionally performs a trial extraction.
- `omega-backup discover-mac <host>`: Utility to find the MAC address of a host on your local network.

## Architecture & Security

`omega-backup` is designed with a "security-first" mindset while prioritizing automation. 

- **Encryption:** All data is encrypted by Borg using `repokey-blake2` before transmission.
- **Restricted Access:** Encourages the use of `borg serve --restrict-to-path` on the server for granular access control.
- **Secret Storage:** All keys and passphrases are stored in `~/.borg-keys/` with `0600` permissions.

For a detailed analysis of the security architecture and trade-offs, see [SECURITY.md](SECURITY.md).

## Configuration

Configuration is stored in `~/.config/omega-backup/config.toml` by default. It supports multiple clients, custom retention policies, and global settings for Borg and notification services.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
