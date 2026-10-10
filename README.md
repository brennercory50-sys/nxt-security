# NXT-Security

A modular platform for **authorized** security research, defensive security
engineering, vulnerability assessment, forensics and lab practice.

> **Use only against systems you own or are explicitly authorized to test**,
> localhost, private labs, and intentionally vulnerable training targets.
> Scope enforcement is built in and refuses everything not listed in
> `config/scope.yaml`.

## Status

| Phase | Area | State |
|---|---|---|
| 0 | Repository audit | ✅ done |
| 1 | Core architecture (models, safety, config, logging, events, plugins, DB, CLI skeleton) | ✅ done |
| 2 | CLI structure (`doctor`, `tools`, `target`, `config`, `logs`) | ✅ done |
| 3 | Configuration (`config path`, `init-scope`, credential-in-config detection) | ✅ done |
| 4 | Tool registry (INSTALLED / MISSING / OUTDATED / BROKEN / UNSUPPORTED) | ✅ done |
| 5 | `nxtsec doctor` (+ `--json`) | ✅ done |
| 6 | Scope: expiry, attestation, fingerprint, DNS pivot guard, LAB/REAL separation | ✅ done |
| 7 | Assessment/job engine: lifecycle, evidence, cancellation, background workers | ✅ done |
| 8 | Recon engine: DNS records + mail-security, IP classification, TLS certificate inspection | 🟡 in progress (HTTP/CT/RDAP deferred) |
| 9+ | Network, web, vulnerability engines, … | ⏳ planned |

Nothing listed as planned exists yet. See `docs/architecture.md` for the roadmap.

## Quick start

```sh
./setup.sh              # Linux / macOS / Termux
.\setup.ps1             # Windows PowerShell

nxtsec --help
nxtsec version
nxtsec doctor
nxtsec tools
nxtsec target add 192.168.1.20 --label nas
nxtsec scan run 192.168.1.20 -m network.tcp_connect -o ports=22,80,443
nxtsec jobs list
nxtsec recon dns example.com        # DNS records + mail posture + IP info
nxtsec recon tls example.com        # certificate expiry, trust, hostname, key
nxtsec config validate
nxtsec scope show
nxtsec scope check 192.168.1.20 8.8.8.8     # exit code 3 if anything is out of scope
nxtsec plugins list
```

## Development

```sh
python -m pytest        # tests
python -m ruff check .  # lint
python -m black .       # format
python -m mypy          # strict type checking
```

Docs: [architecture](docs/architecture.md) · [configuration](docs/configuration.md) ·
[security](docs/security.md) · [plugins](docs/plugins.md) · [development](docs/development.md) ·
[CLI](docs/cli.md) · [tools](docs/tools.md) · [assessments](docs/assessments.md) ·
[modules](docs/modules.md)
