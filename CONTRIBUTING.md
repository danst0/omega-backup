# Contributing to omega-backup

Thank you for your interest in contributing! This document covers how to set up a development environment, coding conventions, and the pull request process.

## Prerequisites

- **Rust** (stable toolchain) — install via [rustup](https://rustup.rs/)
- **BorgBackup** — required to run integration tests or manual testing
- **Git**

## Development Setup

```bash
git clone https://github.com/danst0/omega-backup.git
cd omega-backup

# Activate the local git hooks (runs cargo build + cargo test before every commit)
git config core.hooksPath .githooks

# Check that everything compiles
cargo check

# Build (debug)
cargo build

# Build (release)
cargo build --release
```

## Common Commands

```bash
# Compile and run
cargo run -- <subcommand>

# Run tests
cargo test

# Lint (must pass without warnings before submitting a PR)
cargo clippy -- -D warnings

# Format code (required before submitting a PR)
cargo fmt

# Enable debug output at runtime
RUST_LOG=debug cargo run -- backup
RUST_LOG=trace cargo run -- maintain
```

## Project Structure

| Directory / File | Purpose |
|---|---|
| `src/main.rs` | CLI definition (clap derive) and dispatch |
| `src/config.rs` | Config structs, TOML load/validate/save, state tracking |
| `src/backup.rs` | Client-mode backup workflow |
| `src/maintenance.rs` | Management-mode prune/compact/check workflow |
| `src/restore.rs` | Restore-test workflow |
| `src/init.rs` | One-time repository initialization |
| `src/borg.rs` | Async wrappers around the `borg` binary |
| `src/ssh.rs` | SSH helpers and lockfile management |
| `src/wol.rs` | UDP Wake-on-LAN and ARP-based MAC discovery |
| `src/ntfy.rs` | ntfy.sh notification client |
| `src/distribute.rs` | Encrypted key/config distribution over HTTP+mDNS |
| `src/setup.rs` | Interactive setup wizard |
| `src/status.rs` | Status display |
| `src/check.rs` | Config validation and connectivity checks |
| `src/reset.rs` | Repository reset workflow |
| `src/update.rs` | Self-update from GitHub Releases |

## Coding Conventions

- Format all code with `cargo fmt` before committing.
- Fix all `cargo clippy` warnings before submitting a PR.
- Keep commits focused and atomic. Use [Conventional Commits](https://www.conventionalcommits.org/) style (`feat:`, `fix:`, `chore:`, `docs:`, etc.).
- Avoid adding unnecessary dependencies to `Cargo.toml`.
- All user-facing error messages should be clear and actionable.

## Submitting Changes

1. **Open an issue first** for non-trivial changes to discuss the approach before investing time in implementation.
2. Fork the repository and create a branch: `git checkout -b feat/my-feature`.
3. Make your changes and ensure `cargo clippy` and `cargo fmt` pass.
4. Push to your fork and open a pull request against `main`.
5. Fill in the pull request template. Reference the issue your PR addresses.

## Reporting Bugs

Please use the [bug report issue template](https://github.com/danst0/omega-backup/issues/new?template=bug_report.yml). Include:
- The version of `omega-backup` (`omega-backup --version`)
- The version of BorgBackup (`borg --version`)
- Steps to reproduce
- The relevant log output (`RUST_LOG=debug omega-backup <command>`)

## Security Issues

Please do **not** report security vulnerabilities via GitHub Issues. See [SECURITY.md](SECURITY.md) for the private disclosure process.
