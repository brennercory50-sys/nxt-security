# CLI

Global options: `--config PATH`, `--no-log-file`, `-V/--version`, `-h/--help` (on every command).

| Command | Description |
|---|---|
| `nxtsec version [--json]` | Version and platform |
| `nxtsec doctor [--json] [--strict]` | Full system check; exit 1 if NOT READY (or not READY with `--strict`) |
| `nxtsec tools [list\|check\|info]` | Tool registry (see `tools.md`) |
| `nxtsec config show\|path\|validate\|init-scope` | Configuration |
| `nxtsec scope show\|check TARGET... [--resolve]` | Scope; `check` exits 3 if any target is refused; `--resolve` applies the DNS pivot guard |
| `nxtsec scan run TARGET -m MOD [-o K=V] [--lab] [--queue\|--background]` | Plan + run an assessment (see `assessments.md`) |
| `nxtsec jobs list\|show\|run\|cancel\|worker` | Inspect and control assessments |
| `nxtsec target parse\|add\|list\|remove` | Target inventory; `add` refuses out-of-scope targets unless `--allow-out-of-scope` |
| `nxtsec plugins list\|show NAME` | Registered modules, target types, risk, permissions |
| `nxtsec logs [-n N] [--level L] [--assessment ID] [--raw]` | Recent log entries (already redacted) |

### Exit codes
`0` success · `1` error / not ready · `2` usage error · `3` out of scope.

### Not yet available
`recon`, `dns`, `osint`, `forensic`, `evidence`, `findings`, `report`, `lab`
are registered only when their engines are implemented (Phases 8–20). They are deliberately
absent rather than stubbed.
