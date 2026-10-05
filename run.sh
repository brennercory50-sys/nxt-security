#!/usr/bin/env sh
# Run nxtsec from the project virtualenv: ./run.sh scope check 127.0.0.1
set -eu
cd "$(dirname "$0")"
exec .venv/bin/python -m nxtsec "$@"
