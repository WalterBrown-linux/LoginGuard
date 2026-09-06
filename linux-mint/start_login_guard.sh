#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

PYTHON_BIN="$SCRIPT_DIR/.venv-linux/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
    printf '%s\n' "Linux environment missing. Run: ./setup_linux.sh" >&2
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/login_guard.py"