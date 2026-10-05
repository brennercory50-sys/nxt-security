# Contributing

1. Branch from `develop`; open PRs into `develop`. `main` holds released states.
2. Before pushing: `python -m ruff check . && python -m black --check . && python -m mypy && python -m pytest`.
3. Never commit secrets, `.env`, evidence, PCAPs, databases or personal files (`.gitignore` covers these).
4. External commands go through `nxtsec.safety.execution.run_command` only, never `subprocess` directly
   and never `shell=True`.
5. Any module that touches the network must declare `NETWORK_ACCESS` (or `EXTERNAL_API`/`RAW_SOCKET`)
   so the policy enforces scope before it runs.
6. New behaviour needs tests, including negative and malformed-input cases.
