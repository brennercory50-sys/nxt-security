# Architecture

## Principles
- **Default refuse.** Network operations run only against targets inside the configured scope.
- **The framework decides, not the module.** Modules declare permissions and risk; `Policy` grants them.
- **Normalized data.** Modules return `ModuleResult` (observations, findings, evidence), never raw terminal dumps.
- **One sanctioned path** for each dangerous operation: `run_command` for processes, `safe_join` for paths,
  `redact` for anything leaving the process.
- **No hard-coded paths.** Locations come from the platform adapter and config.

## Layout

```
nxtsec/
  core/        models, errors, ids, App context (wires everything)
  safety/      scope, redaction, execution, paths
  targets/     target parser
  config/      layered settings
  logging/     redacting structured logging
  events/      pub/sub bus
  plugins/     Plugin base, manifest, permissions, policy, registry
  database/    Database interface + SQLite backend + migrations
  platform/    OS / Termux detection, data dirs
  cli/         click-based `nxtsec` command (one module per command group)
  jobs/        AssessmentEngine, JobRunner, detached workers
  evidence/    write-once, hashed, read-only evidence store
  integrations/ external tool registry
  modules/     built-in security modules by domain (dns, network, forensics, …)
  findings/ reporting/ ai/   (later phases)
```

Built-in modules live in `nxtsec/modules/` rather than a top-level `modules/` package: a
top-level import name `modules` would collide with other installed distributions.

## Execution flow

```
CLI ─► App ─► parse_target ─► Assessment(queued)
                 │
                 ▼
       Policy.authorize(manifest, target, mode, scope)   ← raises on scope / permission / risk
                 │
                 ▼
       Plugin.run(target, ModuleContext) ─► ModuleResult
                 │
                 ▼
       Evidence store ─► Findings (dedup by fingerprint) ─► Correlation ─► Reports
```

Implemented through the evidence store and finding deduplication (Phase 7). Correlation and
reports arrive in Phases 17–19. See [assessments.md](assessments.md) for the job lifecycle.

## Key decisions
| Decision | Why |
|---|---|
| Python ≥ 3.10, stdlib-first | Runs on Windows, Linux and Termux without compilers. |
| `click` for the CLI | Mature, typed, good help output; avoids a heavier framework. |
| SQLite via stdlib `sqlite3` behind a `Database` interface | Zero-setup local use; PostgreSQL can be added as another backend. |
| Plugins via `nxtsec.plugins` entry points | Standard packaging; third-party plugins install with pip. |
| Deny-wins, CIDR must be fully contained | Prevents a broad range from sneaking past a narrow allow rule. |
| HIGH-risk modules must declare `LAB_ONLY_VALIDATION` | Exploit-style validation can never run in REAL mode. |
| Authorization checked at plan *and* run time | A queued job must not run on a scope that has since expired or shrunk. |
| Cancellation is a DB flag, checked cooperatively | Works across processes (CLI, background worker) without killing threads mid-write. |
| Evidence raw on disk, redacted in DB/CLI | Evidence stays faithful for verification; displayed data never leaks secrets. |
