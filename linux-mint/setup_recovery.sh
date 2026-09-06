#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this installer with sudo." >&2
    exit 1
fi

recovery_user="loginrescue"
read -r -p "Existing Linux account to protect: " target_user
if [[ ! $target_user =~ ^[a-z_][a-z0-9_-]*$ || $target_user == root ]] || ! id "$target_user" >/dev/null 2>&1; then
    echo "Choose an existing non-root Linux account." >&2
    exit 1
fi
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if ! id "$recovery_user" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$recovery_user"
fi
usermod --append --groups sudo "$recovery_user"

echo "Set a new local password for $recovery_user. Do not reuse the $target_user password."
passwd "$recovery_user"

read -r -p "Recovery Gmail address: " recovery_email
read -r -p "Authorized command sender addresses (comma-separated): " command_from
read -r -s -p "Recovery Gmail app password: " app_password
echo
read -r -s -p "New RESTORE recovery secret: " recovery_secret
echo
read -r -s -p "Repeat the RESTORE recovery secret: " recovery_secret_again
echo

if [[ -z $recovery_email || -z $command_from || -z $app_password || -z $recovery_secret ]]; then
    echo "All recovery values are required." >&2
    exit 1
fi
if [[ $recovery_secret != "$recovery_secret_again" ]]; then
    echo "Recovery secrets did not match." >&2
    exit 1
fi
IFS=',' read -r -a command_senders <<< "$command_from"
for sender in "${command_senders[@]}"; do
    sender="${sender//[[:space:]]/}"
    if [[ -z $sender || $sender != *@*.* ]]; then
        echo "Each authorized sender must be a valid-looking email address." >&2
        exit 1
    fi
done
if [[ $recovery_email == *$'\n'* || $command_from == *$'\n'* || $app_password == *$'\n'* || $recovery_secret == *$'\n'* ]]; then
    echo "Recovery values cannot contain newlines." >&2
    exit 1
fi

printf '%s\n' "$target_user" > /etc/login-guard-target
chmod 0600 /etc/login-guard-target

install -d -m 0755 /usr/local/lib/login-guard
install -m 0755 "$source_dir/login_guard_recovery.py" /usr/local/lib/login-guard/
install -m 0755 "$source_dir/login-guard-account" /usr/local/sbin/login-guard-account
install -m 0755 "$source_dir/restore-account" /usr/local/sbin/restore-account
install -m 0644 "$source_dir/login-guard-recovery.service" /etc/systemd/system/
install -d -m 0700 /var/lib/login-guard-recovery

umask 077
config_tmp=$(mktemp)
printf '%s\n' \
    "EMAIL_USER=$recovery_email" \
    "EMAIL_APP_PASSWORD=${app_password// /}" \
    "COMMAND_FROM=$command_from" \
    "RECOVERY_SECRET=$recovery_secret" \
    "TARGET_USER=$target_user" \
    "POLL_SECONDS=30" > "$config_tmp"
install -m 0600 "$config_tmp" /etc/login-guard-recovery.env
rm -f "$config_tmp"

sudoers_tmp=$(mktemp)
printf '%s\n' \
    "$target_user ALL=(root) NOPASSWD: /usr/local/sbin/login-guard-account lock $target_user" \
    > "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
install -m 0440 "$sudoers_tmp" /etc/sudoers.d/login-guard-lockout
rm -f "$sudoers_tmp"

systemctl daemon-reload
systemctl enable --now login-guard-recovery.service

echo
echo "Recovery service installed."
echo "Authorized command senders: $command_from"
echo "Remote recovery subject: RESTORE <your recovery secret>"
