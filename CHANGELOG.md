# Changelog

## [0.2.0] - Phases 2–5

### Added
- CLI split into per-area command modules; `--help` on every command (tested).
- `nxtsec doctor [--json] [--strict]`: platform, Python, tools, config, scope, data dir, storage,
  database, plugins, interfaces, name resolution, privileges, environment; overall
  READY / DEGRADED / NOT READY. Flags credentials stored in YAML config as an ERROR.
- Tool registry with metadata and detection (INSTALLED, MISSING, OUTDATED, BROKEN, UNSUPPORTED)
  for python, git, nmap, tshark, dig, whois, curl, openssl, yara, docker. Never installs anything.
- `nxtsec tools list|check|info`.
- `nxtsec target parse|add|list|remove` with a persisted target inventory (DB migration 2);
  out-of-scope targets are refused by default and every change is audited.
- `nxtsec config path|init-scope`, `nxtsec logs`.

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
