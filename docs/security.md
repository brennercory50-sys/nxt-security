# Security model

## Scope enforcement
`config/scope.yaml` (git-ignored; copy from `scope.example.yaml`) lists what you are authorized to test.
- Missing scope file ⇒ **every** network target is refused.
- `deny` overrides `allow`.
- A CIDR target is allowed only if it is *entirely* inside an allowed network and does not overlap a denied one.
- `*.example.com` matches subdomains, not the apex.
- `localhost` allows loopback addresses and loopback names only.
- `file:` and `lab:` targets are not network-scoped (the lab engine has its own controls).
- **Expiry:** the whole scope (`expires:`) or individual rules (`{target, expires, note}`) can
  expire. Dates mean end-of-day UTC. Expired rules are inactive; an expired scope refuses all
  network targets. `nxtsec doctor` warns 7 days ahead.
- **Attestation:** with `safety.require_attestation: true` (default), REAL-mode network operations
  are refused unless the scope has an `operator_attestation` sentence.
- **Fingerprint:** a SHA-256 of the scope content is stored on every assessment and in the audit
  log, so you can show exactly which authorization covered a test.
- **Hardening:** allow rules broader than /8 (e.g. `0.0.0.0/0`), wildcards on a bare TLD
  (`*.com`) and unknown keys (typos such as `alow:`) are rejected at load time.

## DNS pivot guard
Before connecting to an in-scope **hostname**, modules resolve it and call
`Scope.check_resolution`. The connection is refused if any address is denied, or is internal
(private, loopback, link-local, reserved, multicast, unspecified) without itself being in scope.
An allowed public name therefore cannot be pointed at `169.254.169.254`, your router, or an
internal range you never authorized. Check manually with `nxtsec scope check HOST --resolve`.

## LAB vs REAL
The two modes never mix: LAB mode accepts only `lab:` targets, and `lab:` targets require LAB mode.
HIGH-risk and `LAB_ONLY_VALIDATION` modules are refused in REAL mode.

## CIDR size
CIDR targets above `safety.max_cidr_hosts` (default 4096 addresses) are refused.

## Permissions and risk
Modules declare `READ_ONLY`, `LOCAL_FILES`, `WRITE_FILES`, `NETWORK_ACCESS`, `RAW_SOCKET`,
`EXTERNAL_API`, `EXEC_TOOLS`, `LAB_ONLY_VALIDATION`, and a risk level from `passive` to `high`.
In REAL mode the policy refuses `RAW_SOCKET`, `LAB_ONLY_VALIDATION` and anything above `medium` risk.

## Secrets
Redaction runs on every log handler, CLI JSON/YAML output and the audit log. Detected values are
masked (`sk_l****…1234`). Credentials are read from environment variables only, never from YAML.

## Evidence and audit
Every module run stores its raw result as evidence: SHA-256 hashed, written with exclusive
create (never overwritten), set read-only, and recorded with custody metadata. If the database
record cannot be written, the file is removed so no unrecorded artifact remains.
`nxtsec jobs show` re-verifies every hash. The audit log records plans, refusals (with the
reason), every module run, scope changes between planning and execution, cancellations and
completions, all redacted.

## Process execution
`run_command` takes an argv list (strings rejected), never uses a shell, resolves the binary to an
absolute path, enforces a timeout (max 6h), caps captured output, and redacts what it logs.

## Paths
`safe_join` resolves symlinks and rejects any path escaping its base; `safe_component` validates
single filenames.

## Out of scope by design
No credential theft, malware deployment, persistence, security-control evasion, destructive actions,
or attacks on arbitrary third-party systems.
