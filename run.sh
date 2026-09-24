#!/usr/bin/env bash
# Set up and run locally, or pass explicit backend commands for SSH/custom engines.
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { echo "Install Python 3.10 or newer, then run ./run.sh again." >&2; exit 1; }
exec python3 launch.py "$@"
