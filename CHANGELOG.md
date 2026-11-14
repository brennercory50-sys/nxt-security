# Changelog

## [0.9.0] - Phase 18 (AI analysis layer)

### Added
- Provider-agnostic AI layer (`nxtsec/ai/`): `AIProvider` contract with four adapters —
  `offline` (deterministic, default, no network/key/package), `claude` (Anthropic SDK, lazy),
  `openai` and `local` (OpenAI-compatible, lazy; `local` defaults to an Ollama base URL).
  Provider chosen by `ai.provider`; unknown values fall back to offline.
- `AIAnalyst`: builds prompts from findings and produces analysis/summaries. **Findings are
  redacted before any prompt is sent**, so secrets never leave the process even with a remote
  provider; AI output is advisory only — `--annotate` attaches it as a finding note and never
  changes severity or status. Every call is audited (`ai.analyze`, `ai.summarize`).
- `nxtsec ai status|analyze|summarize`.
- Optional install extras: `.[claude]`, `.[openai]`.

### Security
- API keys are read only from environment variables (configurable name), never from YAML.
- AI is never the sole authority for a finding; a human always decides.

## [0.8.0] - Phase 15 (secret scanner)

### Added
- Secret-detection engine (`nxtsec/scanners/secrets.py`): typed provider rules (AWS, GitHub,
  Stripe, Google, Slack, Anthropic, OpenAI, OAuth), PEM private keys, JWTs, connection-URL
  passwords, sensitive assignments, and a high-entropy fallback; Shannon-entropy gating and
  placeholder filtering. Every match carries a MASKED value only — the engine never returns a
  secret in the clear.
- `secrets.scan` module: read-only walk of a file or source tree (skips vendored/build dirs,
  binaries and oversized files), one masked finding per secret (CWE-798) with rotation-first
  remediation. PASSIVE risk; READ_ONLY + LOCAL_FILES.
- `nxtsec scan secrets <path>` convenience command.

### Notes
- Pure offline static analysis; no network. Values are masked in the finding title, component,
  description, stored evidence and all CLI/report output, verified by tests that assert the raw
  secret never appears. Feeds the existing findings-triage and reporting loop.

## [0.7.0] - Phase 9 (network engine: nmap)

### Added
- Nmap integration (`nxtsec/integrations/nmap.py`): safe argv construction from a fixed set of
  non-destructive connect-scan profiles (connect / top-ports / service / quick) and an XML
  result parser producing normalized `net.host` / `net.port` / `net.service` observations.
- `network.nmap` module: resolves and scope-checks the target (DNS pivot guard), runs nmap
  through the safe runner (argv list, resolved binary, timeout), stores the raw XML as verified
  evidence, and degrades to an error if nmap is not installed. MEDIUM risk; NETWORK_ACCESS +
  EXEC_TOOLS.
- `nxtsec scan network <target> [--profile P]` convenience command.
- `HostStatus` and `Service` observation types; CLI rendering for the net.* observations.

### Notes
- Only connect scans (`-sT`) are shipped, so no raw sockets or root are required; no intrusive
  NSE scripts. Live scanning is unavailable in the build sandbox, so the parser is tested against
  captured nmap XML and the module against a stub nmap binary, with an end-to-end CLI run verified.

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
