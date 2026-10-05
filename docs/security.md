# Security model

## Scope enforcement
`config/scope.yaml` (git-ignored; copy from `scope.example.yaml`) lists what you are authorized to test.
- Missing scope file ⇒ **every** network target is refused.
- `deny` overrides `allow`.
- A CIDR target is allowed only if it is *entirely* inside an allowed network and does not overlap a denied one.
- `*.example.com` matches subdomains, not the apex.
- `localhost` allows loopback addresses and loopback names only.
- `file:` and `lab:` targets are not network-scoped (the lab engine has its own controls).

## Permissions and risk
Modules declare `READ_ONLY`, `LOCAL_FILES`, `WRITE_FILES`, `NETWORK_ACCESS`, `RAW_SOCKET`,
`EXTERNAL_API`, `EXEC_TOOLS`, `LAB_ONLY_VALIDATION`, and a risk level from `passive` to `high`.
In REAL mode the policy refuses `RAW_SOCKET`, `LAB_ONLY_VALIDATION` and anything above `medium` risk.

## Secrets
Redaction runs on every log handler, CLI JSON/YAML output and the audit log. Detected values are
masked (`sk_l****…1234`). Credentials are read from environment variables only, never from YAML.

## Process execution
`run_command` takes an argv list (strings rejected), never uses a shell, resolves the binary to an
absolute path, enforces a timeout (max 6h), caps captured output, and redacts what it logs.

## Paths
`safe_join` resolves symlinks and rejects any path escaping its base; `safe_component` validates
single filenames.

## Out of scope by design
No credential theft, malware deployment, persistence, security-control evasion, destructive actions,
or attacks on arbitrary third-party systems.
