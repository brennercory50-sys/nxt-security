# Development

```sh
./setup.sh  (or .\setup.ps1)
python -m pytest -q
python -m ruff check .
python -m black .
python -m mypy           # strict
```

Use `python -m mypy` rather than a globally installed `mypy` so it sees the project's stubs.

Tests live in `tests/unit/`. `conftest.py` sets `NXTSEC_HOME` to a temp directory so tests never
touch your real data. CI runs on Ubuntu and Windows with Python 3.10 and 3.12.

Branches: `main` (stable), `develop` (integration), feature branches from `develop`.
