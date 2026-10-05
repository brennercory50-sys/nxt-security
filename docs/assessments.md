# Assessments and jobs

An **assessment** runs one or more modules against one target, under one scope.

## Lifecycle

```
            plan()                     execute()
  request ─────────► QUEUED ───────────────────────► RUNNING ──► COMPLETED
     │                  │                               │    └──► FAILED
     │ refused          │ cancel()                      │ cancel()
     ▼                  ▼                               ▼
  (audit only)      CANCELLED                       CANCELLED (cooperative)
```

1. **Plan:** parse the target, then authorize *every* module (scope, attestation, permissions,
   risk, LAB/REAL mode, target type, CIDR size) and validate its options. Any refusal aborts the
   whole request and is written to the audit log. Nothing runs.
2. **Claim:** `QUEUED → RUNNING` is a single atomic database update, so two workers can never
   run the same assessment.
3. **Re-authorize:** the scope file is re-read. If it no longer authorizes the work (expired,
   rule removed), the assessment FAILS before any module runs. If it changed but still
   authorizes, the change is audited.
4. **Run modules in order.** Each run stores:
   - a module-run record (status, timings, observations, errors, commands),
   - the raw result as hashed, read-only evidence,
   - findings, deduplicated by fingerprint across all assessments.
   A crashing module is recorded as failed and the next module still runs.
5. **Finish:** COMPLETED if at least one module succeeded (failures are listed in `error`),
   FAILED if all failed, CANCELLED if cancelled.

## Running

```sh
nxtsec scan run 192.168.1.20 -m network.tcp_connect -o ports=22,80,443   # foreground
nxtsec scan run 192.168.1.20 -m dns.resolve --queue                     # queue only
nxtsec scan run 192.168.1.20 -m network.tcp_connect --background        # detached process
nxtsec scan run file:./suspicious -m forensics.hash

nxtsec jobs list [--status running]
nxtsec jobs show <id>            # module runs, observations, findings, evidence (re-verified)
nxtsec jobs run <id>             # execute a queued assessment
nxtsec jobs cancel <id>          # queued: cancelled now; running: stops at the next checkpoint
nxtsec jobs worker [--once]      # drain the queue continuously
nxtsec logs --assessment <id>
```

Exit codes for `scan run`: `0` completed, `1` failed/cancelled/invalid, `3` refused (out of scope).

## Options
`-o KEY=VALUE` applies to every module that understands `KEY`. Namespace it to target one
module: `-o network.tcp_connect.ports=22`. Namespaced wins over bare.

## Concurrency
- `JobRunner` runs assessments on a thread pool within one process.
- `--background` spawns `python -m nxtsec jobs run <id>` as a detached process (new session on
  POSIX, `DETACHED_PROCESS` on Windows). It logs to the normal JSON log file.
- Cancellation is a database flag checked between modules and via `ctx.check_cancelled()`,
  so it works across processes.

## Known limitation
If a worker process is killed outright (power loss, `kill -9`), its assessment stays RUNNING.
A reaper for stale jobs is planned with the scheduler (Phase 22).
