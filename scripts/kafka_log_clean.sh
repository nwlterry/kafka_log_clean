#!/usr/bin/env bash
# Thin wrapper so the tool can be run like the other nwlterry shell helpers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${ROOT}/kafka_log_clean.py" "$@"
