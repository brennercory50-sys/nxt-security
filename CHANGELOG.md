# Changelog

## [0.1.0] - Phase 0 + Phase 1

### Added
- Package layout: `nxtsec/` core subsystems and `modules/` security module packages.
- Normalized domain model: `Target`, `Assessment`, `Finding` (with dedup fingerprint), `Evidence`,
  severity/confidence/status enums, separate `REAL` and `LAB` modes.
- Strict target parser (domain, hostname, IPv4/IPv6, URL, CIDR, `file:`, `lab:`).
- Scope engine: allow/deny lists, CIDR containment, wildcard subdomains, loopback handling,
  deny-wins, default-refuse.
- Secret redaction for logs, JSON output and the audit log.
- Safe command runner: argv-only, no shell, resolved binaries, timeouts, output caps.
- Path traversal guards.
- Platform detection (Windows / Linux / macOS / Termux) with per-platform data directories.
- Layered config (defaults → YAML → local overrides → `NXTSEC_*` env).
- Structured logging (console, JSON, rotating JSONL file), always redacted.
- Event bus with failure isolation.
- Plugin contract: manifest, permission model, risk levels, policy enforcement, entry-point
  registry.
- SQLite database with migrations, finding dedup, evidence and audit log; PostgreSQL-ready interface.
- CLI: `version`, `config show|validate`, `scope show|check`, `plugins list`.
- 147 tests; ruff, black, strict mypy; CI on Linux and Windows.
