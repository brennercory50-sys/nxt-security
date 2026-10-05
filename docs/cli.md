# CLI

Global options: `--config PATH`, `--no-log-file`, `-V/--version`, `-h/--help` (on every command).

| Command | Description |
|---|---|
| `nxtsec version [--json]` | Version and platform |
| `nxtsec doctor [--json] [--strict]` | Full system check; exit 1 if NOT READY (or not READY with `--strict`) |
| `nxtsec tools [list\|check\|info]` | Tool registry (see `tools.md`) |
| `nxtsec config show\|path\|validate\|init-scope` | Configuration |
| `nxtsec scope show\|check TARGET...` | Scope; `check` exits 3 if any target is refused |
| `nxtsec target parse\|add\|list\|remove` | Target inventory; `add` refuses out-of-scope targets unless `--allow-out-of-scope` |
| `nxtsec plugins list` | Registered plugins and permissions |
| `nxtsec logs [-n N] [--level L] [--raw]` | Recent log entries (already redacted) |

### Exit codes
`0` success · `1` error / not ready · `2` usage error · `3` out of scope.

### Not yet available
`scan`, `recon`, `dns`, `osint`, `forensic`, `evidence`, `findings`, `report`, `lab`, `jobs`
are registered only when their engines are implemented (Phases 7–20). They are deliberately
absent rather than stubbed.
