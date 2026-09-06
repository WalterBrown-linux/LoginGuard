#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$HOME/.config/systemd/user"

if [[ ! -x "$SCRIPT_DIR/.venv-linux/bin/python" ]]; then
    printf '%s\n' "Linux environment missing. Run: ./setup_linux.sh" >&2
    exit 1
fi

mkdir -p "$SERVICE_DIR"
sed "s#^WorkingDirectory=.*#WorkingDirectory=$SCRIPT_DIR#; s#^ExecStart=.*#ExecStart=$SCRIPT_DIR/.venv-linux/bin/python $SCRIPT_DIR/login_guard.py#" \
    "$SCRIPT_DIR/login-guard.service" > "$SERVICE_DIR/login-guard.service"

systemctl --user daemon-reload
systemctl --user enable --now login-guard.service

printf '%s\n' "LoginGuard will start when your Linux desktop session starts."
printf '%s\n' "Check status with: systemctl --user status login-guard.service"