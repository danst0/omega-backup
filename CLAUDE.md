# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run
cargo run -- <subcommand>

# Check (faster than build, no binary emitted)
cargo check

# Lint
cargo clippy

# Format
cargo fmt

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Enable debug/trace output at runtime
RUST_LOG=debug cargo run -- backup
RUST_LOG=trace cargo run -- maintain
```

There are currently no automated tests. The build produces a single binary: `target/release/omega-backup`.

## Architecture Overview

This is a single-crate async Rust CLI. `main.rs` owns the clap CLI definition and dispatches to workflow modules. All I/O is async via tokio.

### Two operating modes

- **Client mode** (`backup`): Runs on the machine being backed up. Wakes the server via WoL, waits for SSH, runs `borg create`, manages a lockfile, and triggers server shutdown when all clients are done.
- **Management mode** (`maintain`, `restore-test`, `init`): Runs on the management machine. Manages all clients' repos: prune, compact, check, restore testing.

### Module responsibilities

| Module | Role |
|---|---|
| `config.rs` | All structs (`Config`, `AppState`, `ClientConfig`, etc.), TOML load/validate/save, state.json tracking, path helpers |
| `main.rs` | CLI definition (clap derive), logging init, dispatch |
| `backup.rs` | Mode 1 workflow: WoL → SSH poll → borg create → lockfile → ntfy → shutdown |
| `maintenance.rs` | Mode 2 workflow: WoL → prune/compact/check → ntfy → shutdown |
| `restore.rs` | Mode 3 workflow: WoL → borg list → dry-run extract → optional extract |
| `init.rs` | One-time workflow: borg init + export-key for each client |
| `borg.rs` | Thin async wrappers around the `borg` binary (init, create, prune, compact, check, list, extract, export-key) |
| `ssh.rs` | SSH via system `ssh` binary; lockfile management on the server (`~/.omega-backup/locks/`) |
| `wol.rs` | UDP magic packet to port 9; ARP-based MAC discovery |
| `ntfy.rs` | HTTP POST to ntfy.sh with auth token support |
| `distribute.rs` | mDNS announce/browse + AES-256-GCM encrypted HTTP (axum) for key distribution between machines |
| `setup.rs` | Interactive setup wizard (dialoguer) |

### Key data flow patterns

**Borg execution:** All borg commands go through `BorgContext` in `borg.rs`, which builds the environment (`BORG_PASSPHRASE` from passphrase file, `BORG_RSH` for SSH key) and spawns borg as a subprocess via `tokio::process::Command`.

**Lockfile coordination:** After `borg create`, each client writes `~/.omega-backup/locks/<hostname>.lock` on the server via SSH. The last client to finish counts lockfiles and, if zero remain, issues `sudo shutdown -h now`. This coordinates multi-client shutdown without a central orchestrator.

**State tracking:** `AppState` (persisted to `~/.cache/omega-backup/state.json`) tracks per-client timestamps and check results. `check_frequency_days` is compared against `last_check_timestamp` to skip full borg checks when not due.

**Key distribution:** `config listen` starts an axum HTTP server on a random port announced via mDNS (`_omega-backup._tcp`). A one-time 8-char hex code is displayed; the session key is HKDF-derived from it. Client sends passphrase + keyfile (AES-256-GCM encrypted, hex-encoded), receives config template. Note: the code calls `base64_encode`/`base64_decode` but actually uses hex encoding (no base64 dep).

### Config structure

```
Config
├── server: ServerConfig        # host, MAC, admin_user, poll timing
├── borg: BorgConfig            # binary path, check_frequency_days
├── ntfy: Option<NtfyConfig>    # notification endpoint + token
├── clients: Vec<ClientConfig>  # each with main_repo + optional offsite_repo
├── keys: KeysConfig            # local_dir (~/.borg-keys/), optional github_repo
├── distribution: DistributionConfig  # mDNS service name, port, timeout
├── retention: RetentionConfig  # daily/weekly/monthly/yearly keep counts
└── offsite_retention: Option<RetentionConfig>
```

Each `ClientConfig` has a `name` (used in state keys and lockfile names), `hostname` (used in borg archive names), and `RepoConfig` entries with `path`, `ssh_key`, `passphrase_file`, `sources`, `compression`, `exclude_patterns`, `optional`.

### Exit codes

- `1` — borg warning
- `2` — general error
- `3` — config error / not found

### File paths (runtime)

- Config: `~/.config/omega-backup/config.toml`
- State: `~/.cache/omega-backup/state.json`
- Logs: `~/.local/share/omega-backup/logs/omega-backup.YYYY-MM-DD` (stderr only currently)
- Keys: `~/.borg-keys/<client>-main.{pass,key}`

### External dependencies required at runtime

- `borg` binary on both client and server
- `ssh` binary with key-based auth configured
- `sudo` on the server for shutdown (requires passwordless sudo for the backup user)
