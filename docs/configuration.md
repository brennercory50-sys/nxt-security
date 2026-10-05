# Configuration

Precedence, lowest to highest:
1. Built-in defaults (`nxtsec/config/settings.py`)
2. `config/config.yaml` (or `--config PATH` / `NXTSEC_CONFIG`)
3. `config/local.yaml` (git-ignored)
4. Environment: `NXTSEC_<SECTION>__<KEY>`, e.g. `NXTSEC_LOGGING__LEVEL=DEBUG`

`nxtsec config show` prints the merged result (redacted) and its sources.

## Data directory
Override with `NXTSEC_HOME`. Defaults:

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\NXT-Security` |
| Linux / Termux | `$XDG_DATA_HOME/nxt-security` (`~/.local/share/nxt-security`) |
| macOS | `~/Library/Application Support/NXT-Security` |

It holds `nxtsec.db` and `logs/nxtsec.jsonl`.

## Safety and jobs
```yaml
safety:
  require_attestation: true   # REAL-mode network ops need operator_attestation in the scope
  max_cidr_hosts: 4096        # largest CIDR target accepted
  max_risk_real: medium       # modules above this risk run only in LAB mode
jobs:
  workers: 2
  poll_interval: 5            # seconds, for `nxtsec jobs worker`
logging:
  level: INFO                 # log file
  console_level: WARNING      # terminal
paths:
  evidence_dir: null          # default <home>/evidence
```

## Tools
Resolved from `PATH` unless set explicitly, e.g. on Windows:
```yaml
tools:
  nmap: { path: "C:/Program Files (x86)/Nmap/nmap.exe" }
```

## Credentials
Environment only. See `.env.example`.
