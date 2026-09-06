#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this installer with sudo." >&2
    exit 1
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
read -r -p "Existing Linux account to protect: " target_user
if [[ ! $target_user =~ ^[a-z_][a-z0-9_-]*$ || $target_user == root ]] || ! id "$target_user" >/dev/null 2>&1; then
    echo "Choose an existing non-root Linux account." >&2
    exit 1
fi

if [[ ! -f /etc/login-guard-target ]] || [[ $(cat /etc/login-guard-target) != "$target_user" ]]; then
    echo "Run setup_recovery.sh for the same account first." >&2
    exit 1
fi

read -r -p "Twilio Account SID (starts with AC): " account_sid
read -r -s -p "Twilio Auth Token: " auth_token
echo
read -r -p "Dedicated Twilio number (include +1): " twilio_number
read -r -p "Authorized sender phone numbers (comma-separated, include +1): " authorized_from
read -r -s -p "New SMS command secret: " sms_secret
echo
read -r -s -p "Repeat the SMS command secret: " sms_secret_again
echo

if [[ ! $account_sid =~ ^AC[0-9A-Fa-f]{32}$ ]]; then
    echo "The Account SID must start with AC and contain 32 hexadecimal characters after it." >&2
    exit 1
fi
if [[ -z $auth_token || -z $twilio_number || -z $authorized_from || -z $sms_secret ]]; then
    echo "All SMS configuration values are required." >&2
    exit 1
fi
if [[ $sms_secret != "$sms_secret_again" ]]; then
    echo "SMS command secrets did not match." >&2
    exit 1
fi
if [[ ! $twilio_number =~ ^\+[1-9][0-9]{7,14}$ ]]; then
    echo "The Twilio number must use international format, such as +17375551234." >&2
    exit 1
fi
IFS=',' read -r -a sender_numbers <<< "$authorized_from"
for sender in "${sender_numbers[@]}"; do
    sender="${sender//[[:space:]()-]/}"
    if [[ ! $sender =~ ^\+[1-9][0-9]{7,14}$ ]]; then
        echo "Every authorized sender must include its country code, such as +15551234567." >&2
        exit 1
    fi
done
for value in "$auth_token" "$sms_secret"; do
    if [[ $value == *$'\n'* || $value == *$'\r'* ]]; then
        echo "Secrets cannot contain newlines." >&2
        exit 1
    fi
done

install -d -m 0755 /usr/local/lib/login-guard
install -m 0755 "$source_dir/login_guard_sms.py" /usr/local/lib/login-guard/
install -m 0755 "$source_dir/restore-account" /usr/local/sbin/restore-account
install -m 0644 "$source_dir/login-guard-sms.service" /etc/systemd/system/
install -m 0644 "$source_dir/login-guard-recovery.service" /etc/systemd/system/
install -d -m 0700 /var/lib/login-guard-sms

umask 077
config_tmp=$(mktemp)
printf '%s\n' \
    "TWILIO_ACCOUNT_SID=$account_sid" \
    "TWILIO_AUTH_TOKEN=$auth_token" \
    "TWILIO_NUMBER=$twilio_number" \
    "AUTHORIZED_FROM=$authorized_from" \
    "SMS_SECRET=$sms_secret" \
    "TARGET_USER=$target_user" \
    "POLL_SECONDS=20" > "$config_tmp"
install -m 0600 "$config_tmp" /etc/login-guard-sms.env
rm -f "$config_tmp"

systemctl daemon-reload
systemctl restart login-guard-recovery.service
systemctl enable --now login-guard-sms.service

echo
echo "LoginGuard SMS receiver installed. Old messages were baselined and cannot execute."
echo "Allowed commands: TEST, LOCKOUT, RESTORE, SHUTDOWN"
