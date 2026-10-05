# CLI

Global options: `--config PATH`, `--no-log-file`, `-V/--version`, `-h/--help`.

| Command | Description |
|---|---|
| `nxtsec version [--json]` | Version and platform |
| `nxtsec config show [--json]` | Effective, redacted configuration |
| `nxtsec config validate` | Validate config and scope |
| `nxtsec scope show [--json]` | Active scope |
| `nxtsec scope check TARGET... [--json]` | In/out of scope; exit code 3 if any target is refused |
| `nxtsec plugins list [--json]` | Registered plugins and their permissions |

Commands from the roadmap (`doctor`, `tools`, `target`, `scan`, `recon`, …) are added phase by phase.
