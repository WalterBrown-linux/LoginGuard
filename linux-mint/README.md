# LoginGuard for Linux Mint

LoginGuard sends a login email with a webcam photo, computer/user details and approximate public-IP location, then polls email for remote commands. Optional Linux root services restore a locked account by email and accept commands through Twilio SMS.

This folder is the Linux Mint variant. The [Windows implementation](../README.md) remains at the repository root. Do not mix their `.env` files or command generators: the root Windows version uses signed, expiring commands, whereas this Linux variant uses sender checks and a plaintext shared secret in the subject or SMS body. This variant enables webcam/location alerts and email command polling by default; Windows privacy-sensitive features are opt-in. Protect your command mailboxes and use separate secrets.

## What you must supply

This repository includes no working credentials or access to the author's infrastructure. **You must provision and administer your own server if you want a cloud/server deployment, and supply your own server IP addresses, credentials, tokens, firewall rules and any required cloud resources.** Nothing here provisions Google Cloud resources. Do not use someone else's server or credentials.

The current code runs on the computer being protected and contacts SMTP/IMAP, ipinfo.io and (optionally) Twilio directly. It has no custom relay client or server implementation and no setting for a private server IP. Legacy `SERVER_IP`, `SERVER_PASSWORD`, `RELAY_SECERT_KEY` (original spelling), `CLIENT_ID` and `WINDOWS_CAMERA*` settings are unused and intentionally omitted. To use a custom relay, you must implement and deploy that integration yourself; merely adding an IP to `.env` will not enable it. A cloud VM cannot photograph or lock your separate laptop with this code.

## 1. Prepare Linux Mint

The full account lockout/recovery functionality requires Linux, systemd, sudo, Python 3, Linux account tools and an existing non-root desktop account. A webcam and graphical session are needed for photographs and desktop locking. Storing these files on Windows does not convert the Linux helpers into Windows programs.

Install prerequisites on the Linux computer:

```sh
sudo apt update
sudo apt install git python3 python3-venv python3-pip libgl1 libglib2.0-0
git clone https://github.com/WalterBrown-linux/LoginGuard.git
cd LoginGuard/linux-mint
bash setup_linux.sh
```

Create environments afresh; do not copy a Windows or another computer's virtual environment. Paths used for the user service should not contain spaces or shell/sed metacharacters.

## 2. Configure login alerts

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env`. Blank required values deliberately prevent startup. Use your own accounts and long, unique secrets without whitespace; never reuse the examples from tests.

| Setting | Meaning |
| --- | --- |
| `SMTP_HOST` | Your provider's SMTP TLS hostname; defaults to Gmail. |
| `SMTP_PORT` | Implicit TLS SMTP port, normally 465; STARTTLS is not implemented. |
| `IMAP_HOST` | Your provider's IMAP TLS hostname. |
| `EMAIL_USER` | Required mailbox login used to send alerts and receive commands. |
| `EMAIL_APP_PASSWORD` | Required provider-issued mailbox app password; spaces are removed by the application. |
| `ALERT_TO` | Required address that receives photos and confirmations. |
| `COMMAND_FROM` | Required single sender email allowed to issue main-monitor commands. |
| `COMMAND_SECRET` | Required secret placed after the command in the subject. |
| `SMS_TO` | Optional email-to-SMS gateway address supplied by your carrier; this is separate from Twilio. Leave blank to disable. |
| `IPINFO_TOKEN` | Optional token from your own ipinfo.io account. Lookup still runs without a token. |
| `CAMERA_INDEX` | Local OpenCV camera number, initially 0. |
| `POLL_SECONDS` | Positive interval between mailbox checks, initially 30. |
| `CHECK_LOCK_EMAIL` | `true` to monitor commands; `false` to send the initial alert and exit. Required credential checks still apply. |

Use a mailbox whose provider permits app-password SMTP/IMAP access. All placeholder accounts, phone numbers and secrets in tests are synthetic. Public service hostnames in source are provider endpoints, not personal infrastructure.

## 3. Start and enable alerts

```sh
bash start_login_guard.sh
# After confirming alerts work:
bash install_linux_autostart.sh
systemctl --user status login-guard.service
```

Each process startup sends an alert. This is a startup monitor, not a PAM hook for every authentication. The user service starts with the desktop session. Its installer writes the current project path into the service.

Send a fresh email from `COMMAND_FROM` to `EMAIL_USER` with subject `LOCK your-secret`. Other actions are `LOGOFF`, `SHUTDOWN`, `HIBERNATE` and Linux-only `LOCKOUT`. These can terminate work; save files before testing. `LOCKOUT` requires step 4 and expires/locks the configured account, then terminates its session. Power actions depend on the operating system's permissions and hibernation support.

## 4. Optional independent Linux recovery

Keep a tested alternate administrator login available before enabling lockout. On the protected Linux computer:

```sh
sudo bash setup_recovery.sh
```

The installer asks for an existing non-root target username, creates the local `loginrescue` administrator if absent, adds it to the sudo group and prompts for its password. It then asks for your recovery Gmail mailbox, authorized sender emails (comma-separated), its app password and a new recovery secret. Use a separate mailbox and a distinct secret. It installs a root-owned fixed-target helper, a narrowly scoped sudo rule allowing the target to lock itself, and a system recovery service.

The target is recorded in root-only `/etc/login-guard-target`; it must match `TARGET_USER` in `/etc/login-guard-recovery.env`. That root-only file also holds `EMAIL_USER`, `EMAIL_APP_PASSWORD`, `COMMAND_FROM`, `RECOVERY_SECRET` and `POLL_SECONDS=30`. An optional `IMAP_HOST` entry overrides Gmail. These files use plain `KEY=value` lines, without quotes or multiline values. Do not change the target while an account is locked: saved recovery state belongs to that account.

Send `RESTORE your-recovery-secret` as a fresh email subject to the recovery mailbox. From an alternate administrator session, local recovery is:

```sh
sudo /usr/local/sbin/restore-account
sudo systemctl status login-guard-recovery.service
```

Recovery runs independently of the user's desktop. It cannot receive mail when the machine is powered off or disconnected. The generic `RESTORE` command and `restore-account` name replace the former account-specific names; update any personal automation accordingly.

## 5. Optional Twilio SMS control

Provision your own Twilio account and SMS-capable number before setup. Complete recovery setup first, then run:

```sh
sudo bash setup_sms.sh
```

Supply the same Linux target user, your `TWILIO_ACCOUNT_SID` (`AC` plus 32 hexadecimal characters), `TWILIO_AUTH_TOKEN`, dedicated `TWILIO_NUMBER`, comma-separated `AUTHORIZED_FROM` phone numbers, and a new `SMS_SECRET`. Use international phone format with `+` and country code. The installer writes these values plus `TARGET_USER` and `POLL_SECONDS=20` to root-only `/etc/login-guard-sms.env`.

The root service polls Twilio's API; it does not deploy a webhook/server. After the first poll baselines old messages, send `TEST your-sms-secret` to test authentication without a system action. Other SMS actions are `LOCKOUT`, `RESTORE` and `SHUTDOWN`. Inspect `sudo journalctl -u login-guard-sms.service` for results. TEST does not send an SMS reply. Commands require the configured sender number and matching secret.

## Windows support

Use the [root Windows implementation and installation instructions](../README.md). Its launchers, private configuration, signed-command generator and tests are separate from this Linux folder. Do not run the Linux root helpers or service installers on Windows.

## Verification and troubleshooting

```sh
python -m unittest discover -p 'test_login_guard*.py'
```

Tests mock mail, camera and system actions; they do not send messages or lock accounts. `test_sms.py` is a manual email-to-SMS send utility and contacts the configured provider when executed. Linux installation, hardware and real service behavior must be checked on your own Linux computer. Inspect `login_guard.log`, user service status and recovery/SMS journals locally; these can contain personal information.

## Privacy and sharing

Alerts intentionally contain user/computer identifiers, approximate IP location and photographs. The main alert also contains the command secret. Protect the recipient mailbox, photos and logs. Anyone with authorized mailbox/phone access and the corresponding secret can issue commands. This cleanup is not a full security audit.

`.gitignore` excludes real configuration, photos, logs, virtual environments, editor settings, key files and common backups. Share only Git-tracked source files; never upload a whole working folder or force-add ignored files. Installed `/etc` configuration and `/var/lib/login-guard-*` state are private and must not be bundled. Rotate any credentials previously shared through archives, messages or repositories; deleting a local copy does not revoke them.

To stop services, use `systemctl --user disable --now login-guard.service` and, if installed, `sudo systemctl disable --now login-guard-sms.service login-guard-recovery.service`. Restore a locked account before removing its helper or state.
