#!/usr/bin/env sh
# Create a virtualenv and install NXT-Security in editable mode with dev tools.
# Works on Linux, macOS and Android/Termux. Installs nothing system-wide.
set -eu
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
"$PY" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
[ -f config/scope.yaml ] || cp config/scope.example.yaml config/scope.yaml
echo "Done. Activate with: . .venv/bin/activate   then run: nxtsec --help"
echo "Edit config/scope.yaml so it lists ONLY systems you are authorized to test."
