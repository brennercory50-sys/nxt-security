# Changelog

## [0.6.0] - Phases 16 & 19 (findings engine + reporting)

### Added
- Finding triage engine (`nxtsec/findings/`): validated status state machine
  (`FindingStatus.can_transition`), append-only history and notes, severity-ordered
  listing with status/severity/module/open filters, lookup by id prefix; all changes audited.
- `nxtsec findings list|show|set-status|note|stats`.
- Reporting engine (`nxtsec/reporting/`): deterministic, fully redacted reports in Markdown,
  self-contained HTML (inline CSS, light/dark, no external requests), JSON and CSV, with
  executive summary, severity distribution, methodology, scope and per-finding detail.
- `nxtsec report [--assessment ID] [--format F] [--min-severity S] [--open] [-o FILE]`.
- Database: `get_finding`, `update_finding` (status column kept in sync with the JSON blob).

This closes the core loop: scan -> findings -> triage -> report.

## [0.5.0] - Phase 8 (recon, part 2: TLS certificates)

### Added
- TLS layer (`nxtsec/net/tls.py`, `cryptography`): connect to a target address, complete a
  handshake with SNI, and return the leaf certificate with negotiated version/cipher; verify
  against the system trust store and fall back to an unverified read (recording why) so an
  untrusted endpoint is still reported. RFC 6125 hostname matching and certificate parsing into
  the normalized `tls.certificate` observation.
- `tls.certificate` module: findings for expired, expiring-soon, untrusted/self-signed,
  hostname-mismatch and weak-key certificates — all about the operator's own endpoint.
- `nxtsec recon tls`; `-o KEY=VALUE` options added to all `recon` subcommands.
- Richer CLI rendering for DNS, relationship, IP and certificate observations.
- Shared test harness (`tests/support/tls_server.py`) that generates certificates and runs a
  real loopback TLS server, so certificate handling is tested over a genuine handshake offline.
- `cryptography` runtime dependency.

## [0.4.0] - Phase 8 (recon, part 1)

### Added
- Normalized observation model (`nxtsec/core/observations.py`): typed records for DNS,
  relationships, ports, IP info, HTTP, TLS, CT, subdomains, RDAP and well-known files.
  `ModuleResult.add()` and `ModuleContext.setting()` / `config`.
- DNS client (`nxtsec/net/dns.py`, dnspython): A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/PTR/SRV,
  configurable nameservers, normalized answers and status mapping.
- `dns.records` module: record enumeration, mail-exchanger/name-server/alias relationships,
  and informational/low findings for a domain's own SPF/DMARC posture.
- `ip.info` module: offline IP classification plus PTR lookups.
- `nxtsec recon dns|ip` convenience commands (run through the assessment engine).
- `dnspython` runtime dependency.

### Changed
- Moved the resolution helper to `nxtsec/net/resolve.py` (new `nxtsec.net` package).

### Deferred (known gap)
- HTTP metadata, TLS certificate inspection, certificate-transparency discovery and RDAP/WHOIS
  recon modules. Observation types for them exist; the modules are not yet implemented.

## [0.3.0] - Phases 6–7

### Added
- Scope: whole-scope and per-rule expiry (`{target, expires, note}`), operator attestation
  requirement for REAL-mode network work, content fingerprint recorded on every assessment,
  DNS pivot guard (`Scope.check_resolution`), `scope check --resolve`, richer `scope show`.
- Policy: strict LAB/REAL separation, CIDR size cap (`safety.max_cidr_hosts`),
  configurable `safety.max_risk_real` and `safety.require_attestation`.
- Assessment engine: plan → atomic claim → run-time re-authorization → per-module execution
  with crash isolation → COMPLETED / FAILED / CANCELLED; refusals and every module run audited.
- Write-once, hashed, read-only evidence store with custody metadata and verification.
- Finding occurrences across assessments (dedup keeps one record, links every assessment).
- Async execution: `JobRunner` thread pool, detached background workers, queue worker,
  cross-process cooperative cancellation.
- CLI: `scan run`, `jobs list|show|run|cancel|worker`, `logs --assessment`, `plugins show`.
- Seed modules: `dns.resolve`, `network.tcp_connect`, `forensics.hash`.
- DB migration 3 (job control, module runs, finding occurrences).

### Changed
- Built-in modules moved from top-level `modules/` to `nxtsec/modules/` (import-name collision).
- Console logs default to WARNING (`logging.console_level`); the file still records INFO.
- Operator name now comes from `getpass.getuser()`.

### Fixed
- Logging a module name crashed assessments (`module` is a reserved LogRecord attribute).
- Settings now resolve the data directory from the environment they were loaded with.
- Evidence whose DB record fails is removed instead of left orphaned on disk.
- Scope rules rejected malformed hostnames only loosely; they now use the target validator.

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
