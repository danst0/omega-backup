# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.4.3] - 2026-03-11

### Added
- `--lock-wait` flag for `backup` to control how long to wait for an existing borg lock to clear.
- `--exclude-from` flag to pass a file of exclude patterns to `borg create`.
- `--filter` flag to control which file status characters borg prints during backup.

## [0.4.2] - 2026-03-11

### Added
- Setup wizard now generates a dedicated SSH key per client repo instead of reusing a shared management key.
- `edit client` wizard flow supports per-repo SSH key regeneration (renames the old key to `.bak`).
- `print_repo_key_instructions` helper prints the `authorized_keys` snippet with `borg serve --restrict-to-path` for each repo.
- `exclude_patterns_from` and `borg_filter` fields added to `RepoConfig` and passed to `borg create`.

## [0.4.1] - 2026-03-10

### Changed
- Refactored `ClientConfig` to support multiple named repositories via `[[clients.repos]]` (replacing the previous `main_repo` / `offsite_repo` split).
- Added a `name` field to `RepoConfig`; helper methods on `ClientConfig` replace the old typed accessors.
- Custom deserializer provides backward compatibility with the old `main_repo`/`offsite_repo` format.
- All workflow modules (`backup`, `maintain`, `init`, `reset`, `restore`) now iterate over the generic repo list.
- `--repo` flag replaces the `BackupTarget` enum on `backup`, `maintain`, and `reset`.
- `config sync` / `config listen` use a generic `/repo-passphrase/{client}/{repo}` route.
- Setup wizard supports add-repo, edit-client, and fresh-start flows.

### Deprecated
- `offsite_retention` top-level key (still read for backward compatibility; migrate to per-repo `[clients.repos.retention]`).

## [0.4.0] - 2026-03-10

### Added
- `status` command: shows last backup and check timestamps for all configured clients.
- `check-config` command: validates the configuration file and tests SSH connectivity.
- `setup` command: alias for `omega-backup config` (interactive wizard).
- `reset` command: deletes and reinitializes borg repositories for a client (`--repo`, `--yes`, `--dry-run`).
- Major refactor of the interactive setup wizard with merge-aware config editing.

## [0.3.9] - 2026-03-10

### Changed
- `config sync` and `config listen` distribution protocol improvements and reliability fixes.
- `reset` command stability improvements.

## [0.3.8] - 2026-03-09

### Added
- `reset <CLIENT>` command to delete and reinitialize borg repositories. Supports `--only main|offsite`, `--yes`, and `--dry-run`.

## [0.3.7] - 2026-03-09

### Added
- `--only main|offsite` flag on `backup` to target a single repository.

## [0.3.6] - 2026-03-09

### Added
- `backup` now validates `hostname` and `sources` fields before starting.

### Fixed
- ntfy notifications now use JSON publishing with a `topic` field (fixes delivery on some server configurations).
- Full borg error chain is now displayed on backup failure.

## [0.3.5] - 2026-03-09

### Changed
- `init` now requires a pre-existing passphrase file for main repos (pointing to `config sync` or the wizard). Offsite repos continue to auto-generate a passphrase.

## [0.3.4] - 2026-03-09

### Fixed
- `init` no longer fails if a repository already exists; it skips initialized repos gracefully.

## [0.3.3] - 2026-03-09

### Added
- `init` auto-generates passphrase files for offsite repos during initialization.

## [0.3.2] - 2026-03-08

### Added
- `exclude_if_present` config field: skip directories that contain a specified marker file (e.g. `.nobackup`).

## [0.3.1] - 2026-03-07

### Added
- Support for multiple named repositories per client in config (initial groundwork).

## [0.3.0] - 2026-03-06

### Fixed
- Borg no longer hangs on a relocated-repo confirmation prompt (`BORG_RELOCATED_REPO_ACCESS_IS_OK=yes` is set automatically).
- Dead SSH connections no longer block borg indefinitely (`ServerAliveInterval=10` added to `BORG_RSH`).

## [0.2.9] - 2026-03-06

### Added
- `--verbose` / `-v` flag on `backup` for file-level borg output (passes `--list` to `borg create`).

## [0.2.8] - 2026-03-06

### Added
- Live progress streaming during `borg create` (uses `--progress` and reads borg's stderr in real time).

## [0.2.7] - 2026-03-06

### Fixed
- SSH now bails immediately with a clear error message when the server's host key has changed (instead of prompting interactively and hanging).

## [0.2.6] - 2026-03-06

### Fixed
- `self_update` now uses `rustls` to avoid a runtime dependency on OpenSSL in statically linked musl builds.

## [0.2.5] – [0.2.2] - 2026-03-06

Internal stabilization and CI fixes.

## [0.2.1] - 2026-02-27

### Fixed
- Build: switched to `rustls-tls` for `reqwest` to support static musl builds.

### Changed
- Improved install script install-directory detection and error messages.

## [0.2.0] - 2026-02-27

### Added
- Automatic update check on startup: prints a notice if a newer release is available on GitHub.
- `update` command to self-update the binary from GitHub Releases.

## [0.1.2] - 2026-02-27

### Fixed
- CI: granted `write` permissions to `GITHUB_TOKEN` so the release workflow can create GitHub Releases.

## [0.1.1] - 2026-02-27

### Fixed
- Build: use `rustls-tls` for static musl builds.

## [0.1.0] - 2026-02-27

### Added
- Initial public release with binary distribution via GitHub Releases.
- Automated install script (`install.sh`).

[Unreleased]: https://github.com/danst0/omega-backup/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/danst0/omega-backup/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/danst0/omega-backup/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/danst0/omega-backup/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/danst0/omega-backup/compare/v0.3.9...v0.4.0
[0.3.9]: https://github.com/danst0/omega-backup/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/danst0/omega-backup/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/danst0/omega-backup/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/danst0/omega-backup/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/danst0/omega-backup/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/danst0/omega-backup/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/danst0/omega-backup/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/danst0/omega-backup/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/danst0/omega-backup/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/danst0/omega-backup/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/danst0/omega-backup/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/danst0/omega-backup/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/danst0/omega-backup/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/danst0/omega-backup/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/danst0/omega-backup/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/danst0/omega-backup/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/danst0/omega-backup/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/danst0/omega-backup/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/danst0/omega-backup/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/danst0/omega-backup/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/danst0/omega-backup/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danst0/omega-backup/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danst0/omega-backup/releases/tag/v0.1.0
