# omega-backup

[![Latest Release](https://img.shields.io/github/v/release/danst0/omega-backup)](https://github.com/danst0/omega-backup/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A secure, high-performance [BorgBackup](https://www.borgbackup.org/) orchestration CLI written in Rust. `omega-backup` simplifies managing multi-machine backups by automating server wake-up (WoL), SSH connectivity, repository initialization, and automated maintenance tasks.

## Key Features

- **Automated Orchestration:** Manages server wake-up (WoL), SSH status monitoring, and automated shutdown after backup completion.
- **Multi-Machine Management:** Centralized configuration for multiple clients, each with multiple named repositories.
- **Secure Key Distribution:** Custom encrypted protocol for syncing Borg keys and passphrases across machines during initial setup.
- **Comprehensive Maintenance:** Integrated commands for pruning old archives, compacting repositories, and performing integrity checks.
- **Interactive Setup:** Guided wizard to generate configuration and initial security keys.
- **Restore Testing:** Built-in command to verify archive integrity and test extraction.
- **Notifications:** Integrated support for [ntfy](https://ntfy.sh/) for real-time backup status updates.
- **Self-Updating:** Built-in `update` command to pull the latest release from GitHub.

## Prerequisites

- **BorgBackup:** Must be installed on both client and server machines.
- **SSH:** Key-based authentication must be configured between clients and the backup server.
- **Linux x86_64:** Pre-built binaries target Linux/x86_64 (musl, statically linked).
- **Rust (optional):** Required only to build from source.

## Installation

### Option 1: Binary Install (Recommended)

The easiest way to install is using the automated script, which downloads the latest statically-linked binary from GitHub Releases.

```bash
curl -sL https://raw.githubusercontent.com/danst0/omega-backup/main/install.sh | bash
```

The script installs to `~/.local/bin` if it is in your `PATH`, otherwise falls back to `/usr/local/bin` (requires sudo).

### Option 2: Build from Source

```bash
git clone https://github.com/danst0/omega-backup.git
cd omega-backup
cargo install --path .
```

## Getting Started

### 1. Initial Setup

Run the interactive setup wizard to generate your initial configuration:

```bash
omega-backup config
```

The wizard will guide you through:
- Defining your backup server (host, MAC address, admin user).
- Generating dedicated SSH keys for backup tasks.
- Creating your first backup client and repository passphrase.

### 2. Initialize Repositories

Once configured, initialize your Borg repositories on the server:

```bash
omega-backup init
```

### 3. Perform a Backup

Run a manual backup to verify everything is working:

```bash
omega-backup backup
```

## Usage

### Global Flags

These flags are available on every command:

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Path to config file (default: `~/.config/omega-backup/config.toml`) |
| `-v, -vv` | Increase log verbosity (`-v` = debug, `-vv` = trace) |
| `--dry-run` | Parse and validate without executing borg commands |

### Commands

| Command | Mode | Description |
|---|---|---|
| `config` | any | Run the interactive setup wizard |
| `config listen` | management | Start the local key-distribution server |
| `config sync [--client NAME] [--host HOST:PORT]` | client | Receive config and keys from listener |
| `config push-key <CLIENT>` | management | Push encrypted keyfile to a GitHub backup repo |
| `init [CLIENT]` | management | Initialize borg repositories (all or one client) |
| `backup [--repo NAME]` | client | Run a backup for the current machine |
| `maintain [--skip-check] [--repo NAME]` | management | Prune, compact, and check all client repositories |
| `restore-test <CLIENT> [--repo NAME] [--extract] [--archive NAME] [--path PATH]` | management | List archives and optionally test extraction |
| `status` | management | Show last backup and check timestamps for all clients |
| `check-config` | any | Validate configuration file and test SSH connectivity |
| `reset <CLIENT> [--repo NAME] [--yes]` | management | Delete and reinitialize repositories for a client |
| `discover-mac <HOST>` | any | Find the MAC address of a host via ARP |
| `update` | any | Update omega-backup to the latest GitHub release |
| `setup` | any | Alias for `config` |

### Examples

```bash
# Back up only the offsite repository
omega-backup backup --repo offsite

# Maintain all clients, skipping the full integrity check
omega-backup maintain --skip-check

# Test restore for a specific client and extract files
omega-backup restore-test myhost --extract --path /etc

# Sync config on a new client machine, skipping mDNS discovery
omega-backup config sync --host 192.168.1.10:54321

# Dry-run a backup to see what would happen
omega-backup --dry-run backup
```

## Architecture & Security

`omega-backup` is designed with a "security-first" mindset while prioritizing automation.

- **Encryption:** All data is encrypted by Borg using `repokey-blake2` before transmission.
- **Restricted Access:** Encourages the use of `borg serve --restrict-to-path` on the server for granular access control.
- **Secret Storage:** All keys and passphrases are stored in `~/.borg-keys/` with `0600` permissions.

For a detailed analysis of the security architecture and trade-offs, see [SECURITY.md](SECURITY.md).

## Configuration

Configuration is stored in `~/.config/omega-backup/config.toml` by default. See [`config.example.toml`](config.example.toml) for a fully annotated example covering multiple clients, multiple repositories per client, custom retention policies, ntfy notifications, and key distribution settings.

### File Paths

| Purpose | Default Path |
|---|---|
| Config | `~/.config/omega-backup/config.toml` |
| State (timestamps) | `~/.cache/omega-backup/state.json` |
| Logs | `~/.local/share/omega-backup/logs/omega-backup.log` |
| Keys & passphrases | `~/.borg-keys/` |

## Troubleshooting

**`Failed to load config` on first run**
Run `omega-backup config` to generate a config file.

**Backup hangs waiting for SSH**
Ensure `StrictHostKeyChecking` is not blocking the first connection. Run `omega-backup check-config` to test connectivity.

**`borg: command not found`**
Install [BorgBackup](https://borgbackup.readthedocs.io/en/stable/installation.html) on the machine where you are running the command. The `borg.binary` config key can point to a custom path.

**Server does not wake up**
Verify the MAC address with `omega-backup discover-mac <SERVER_HOST>` and confirm the server's network adapter supports Wake-on-LAN and that WoL is enabled in BIOS/firmware.

**Enable verbose logging**
```bash
omega-backup -vv backup
# or
RUST_LOG=trace omega-backup backup
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Borg warning (backup completed with warnings) |
| `2` | General error |
| `3` | Configuration error |

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to submit issues and pull requests.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
