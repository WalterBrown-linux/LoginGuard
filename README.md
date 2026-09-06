# LoginGuard

LoginGuard is a small Python utility that sends an email when it starts. It can optionally attach a webcam image, include coarse public-IP location information, send a second message through an email-to-SMS gateway, and monitor a mailbox for signed remote actions.

In the Windows implementation, privacy-sensitive and remote-control features are **disabled by default**. The minimum configuration sends only a login alert email.

## Choose your platform

| Platform | Implementation and setup |
| --- | --- |
| Windows 10/11 | Use the files at the repository root and the instructions below. Existing Windows behavior and signed commands are unchanged. |
| Linux Mint with systemd | Use the separate [`linux-mint/` implementation and step-by-step guide](linux-mint/README.md), including optional account recovery and Twilio SMS services. |

The variants have separate configuration and command formats. Windows uses signed, expiring commands with privacy features off by default. The Linux Mint variant uses sender checks plus a plaintext shared secret and enables photo/location alerts and email command polling by default. Do not copy credentials or command subjects between variants.

Neither implementation requires a private relay or Google Cloud server. Each runs on the computer being protected and uses the configured service providers directly. Supply your own mail credentials, optional tokens, and (for Linux SMS) Twilio resources. If you add a custom server integration, provision your own server/cloud resources and use your own IP addresses and credentials; no personal infrastructure access is included.

### Linux Mint quick start

Run these commands on the Linux Mint computer, not in Windows PowerShell:

```sh
sudo apt update
sudo apt install git python3 python3-venv python3-pip libgl1 libglib2.0-0
git clone https://github.com/WalterBrown-linux/LoginGuard.git
cd LoginGuard/linux-mint
bash setup_linux.sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` with your own mailbox, app password, alert destination, allowed sender and unique command secret; the [Linux settings table](linux-mint/README.md#2-configure-login-alerts) explains every field. Then run `bash start_login_guard.sh`. After checking the alert, run `bash install_linux_autostart.sh` to enable startup with your desktop session. Follow the Linux guide before enabling account lockout/recovery or Twilio commands, and keep an alternate administrator login available.

The remaining instructions on this page apply to **Windows**.

## Important safety notes

- Use LoginGuard only on a computer and accounts you own or are authorized to administer.
- Never commit `.env`, `.login_guard_state.json`, photos, logs, or a virtual environment.
- Use a dedicated email account when possible. Do not put your normal email password in `.env`.
- `LOGOFF`, `SHUTDOWN`, and `HIBERNATE` can interrupt work or discard unsaved data. Enable only the actions you genuinely need.
- Webcam capture sends an image to the configured alert mailbox. IP location sends the computer's public IP to `ipinfo.io`. Both require explicit opt-in.

## Requirements

- Windows 10 or Windows 11 for the startup launchers and remote OS actions
- Python 3.10 or newer
- A mail account supporting SMTP over TLS and, if remote commands are enabled, IMAP over TLS
- An optional webcam

## 1. Install

Open PowerShell in the cloned repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

The virtual environment is local to your computer and is ignored by Git.

## 2. Create your private configuration

Copy the placeholder template:

```powershell
Copy-Item .env.example .env
notepad .env
```

Only edit `.env`. Keep `.env.example` filled with placeholders so it remains safe to publish.

### Required alert settings

| Field | What you enter |
|---|---|
| `EMAIL_USER` | The complete email address LoginGuard uses to send alerts, such as `your-account@example.com`. |
| `EMAIL_APP_PASSWORD` | An app-specific password created by your mail provider. Do not enter your normal account password. |
| `ALERT_TO` | The private email address that should receive login alerts. It may match `EMAIL_USER`, but a separate protected destination is preferable. |

The example uses Gmail's standard endpoints. For Gmail, enable two-step verification and create an app password for this application. Google notes that app passwords are intended for applications that cannot use Sign in with Google: <https://support.google.com/accounts/answer/185833>.

If you use another provider, replace these values with the provider's documented TLS endpoints:

| Field | Default | Meaning |
|---|---:|---|
| `SMTP_HOST` | `smtp.gmail.com` | Outgoing mail server hostname. |
| `SMTP_PORT` | `465` | SMTP-over-TLS port. This program expects implicit TLS, commonly port 465. |
| `IMAP_HOST` | `imap.gmail.com` | Incoming mail server used only for remote commands. |

### Optional SMS gateway

Set `SMS_TO` to an email-to-SMS gateway address supplied by your carrier. Leave it blank to disable the second notification.

```dotenv
SMS_TO=
```

Carrier gateways may retain message metadata and can change or discontinue service. The SMS message intentionally contains no photo, location details, command secret, or email destination.

### Optional webcam

Webcam capture is off by default:

```dotenv
CAPTURE_PHOTO=false
CAMERA_INDEX=0
KEEP_PHOTOS=false
MAX_SAVED_PHOTOS=10
```

- Change `CAPTURE_PHOTO` to `true` only after deciding that capturing and emailing an image is appropriate.
- `CAMERA_INDEX` selects the camera. Start with `0`; try `1` only if the wrong camera is selected.
- Keep `KEEP_PHOTOS=false` to delete the temporary JPEG after the delivery attempt and purge crash-orphaned captures on the next start. Set it to `true` only if you accept local retention in the ignored `photos` directory.
- `MAX_SAVED_PHOTOS` limits retained LoginGuard images when `KEEP_PHOTOS=true`; the default is 10 and the maximum is 100.

### Optional public-IP location

Location lookup is off by default:

```dotenv
IP_LOCATION_ENABLED=false
IPINFO_TOKEN=
```

When enabled, LoginGuard contacts `https://ipinfo.io/json`. That service necessarily receives the computer's public IP and returns coarse network/location information; it is not GPS. Add your own `IPINFO_TOKEN` only if your ipinfo account requires one.

## 3. Test the basic alert

Leave remote commands, camera capture, and IP location disabled for the first test:

```powershell
.\.venv\Scripts\python login_guard.py
```

The program should send one email to `ALERT_TO` and exit. Review the newest `login_guard_<process-id>.log` file if delivery fails. Each file rotates at approximately 1 MB with one backup, and LoginGuard keeps only the four newest process-log sets. Per-process files prevent simultaneous Windows startup runs from competing for the same file. The logs intentionally avoid recording recipients, command secrets, and photo paths.

To test an email-to-SMS gateway, first verify `SMS_TO`, then use the explicit acknowledgement flag:

```powershell
.\.venv\Scripts\python test_sms.py --send
```

Running `test_sms.py` without `--send` does not send a message.

## 4. Optional signed remote commands

Remote commands are disabled until you explicitly configure them. The template deliberately leaves `COMMAND_SECRET` and `DEVICE_ID` blank so commands cannot be enabled accidentally. The command protocol uses a short-lived timestamp, random one-time nonce, device identifier, and HMAC-SHA256 signature. Plaintext subjects such as `LOCK password` are rejected.

Generate a private random secret:

```powershell
.\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value only in your private `.env`, then fill these fields:

```dotenv
REMOTE_COMMANDS_ENABLED=true
COMMAND_FROM=your-trusted-command-sender@example.com
COMMAND_SECRET=paste_your_generated_random_secret_here
DEVICE_ID=my-laptop
ALLOWED_ACTIONS=LOCK
POLL_SECONDS=30
COMMAND_MAX_AGE_SECONDS=300
MAX_COMMAND_CANDIDATES=20
MAX_COMMAND_HEADER_BYTES=16384
```

| Field | What you enter or choose |
|---|---|
| `REMOTE_COMMANDS_ENABLED` | `true` to enable mailbox monitoring; otherwise keep `false`. |
| `COMMAND_FROM` | The complete address from which you will send commands. This is an additional filter; the HMAC signature is the actual authentication control. |
| `COMMAND_SECRET` | A unique random secret of at least 32 characters. Never email, post, reuse, or commit it. |
| `DEVICE_ID` | A short unique name containing no spaces, such as `home-laptop`. It binds a command to one configured device. |
| `ALLOWED_ACTIONS` | A comma-separated subset of `LOCK`, `LOGOFF`, `SHUTDOWN`, and `HIBERNATE`. Start with only `LOCK`. |
| `POLL_SECONDS` | Seconds between mailbox checks. Values below 10 are raised to 10. |
| `COMMAND_MAX_AGE_SECONDS` | How long a generated command remains valid. Allowed range is 30–3600 seconds; 300 is recommended. |
| `MAX_COMMAND_CANDIDATES` | Maximum new message headers examined per poll, from 1–100. |
| `MAX_COMMAND_HEADER_BYTES` | Largest command header accepted, from 1024–65536 bytes. |

Start LoginGuard once after enabling remote commands. On the first connection—or whenever the mailbox's IMAP identity changes—it records the newest existing message and deliberately executes nothing. This prevents old mailbox content from becoming a command.

Create a command subject locally:

```powershell
.\.venv\Scripts\python create_command.py LOCK
```

Copy the complete output into the **subject** of a new email. Send it from `COMMAND_FROM` to the mailbox in `EMAIL_USER` immediately. Do not add the command to the message body. Each subject expires and its nonce is accepted at most once.

To permit another action, add it explicitly, for example:

```dotenv
ALLOWED_ACTIONS=LOCK,HIBERNATE
```

Changing `COMMAND_SECRET` invalidates subjects made with the old secret. If the secret may have leaked, replace it immediately and restart LoginGuard.

## 5. Start hidden on Windows

After the normal PowerShell test succeeds, double-click `start_login_guard.bat`. The BAT and VBS files derive the repository path automatically; no machine-specific path needs to be edited.

To run at sign-in using Task Scheduler:

1. Open **Task Scheduler** and choose **Create Task**.
2. On **General**, use a descriptive name such as `LoginGuard` and select your own Windows account.
3. On **Triggers**, add **At log on** for that account.
4. On **Actions**, choose **Start a program** and select the full local path to `start_login_guard.bat`.
5. Set **Start in** to the local repository folder, without quotation marks.
6. Save the task, right-click it, and choose **Run** for a controlled test.

The path entered into your private Task Scheduler configuration is not stored in this repository.

## Files that must remain private

The included `.gitignore` excludes:

- `.env` and any local environment variants;
- `.login_guard_state.json`, which records mailbox progress and used nonces;
- `.login_guard_monitor.lock`, which prevents simultaneous command monitors;
- `photos/` and every `*.log*` file;
- `.venv/`, `venv/`, bytecode, caches, and editor files.

Before publishing a fork, check the staged file list with:

```powershell
git status --short
git diff --cached --name-only
```

If a real secret was ever committed, deleting the file in a later commit is insufficient: rotate the credential and remove it from published history.

## Data flow and privacy

- The SMTP provider receives the sending account, recipient, alert text, and optional webcam attachment.
- The IMAP provider is contacted only when remote commands are enabled.
- `ipinfo.io` is contacted only when `IP_LOCATION_ENABLED=true`.
- An SMS gateway is contacted only when `SMS_TO` is nonempty.
- Temporary and crash-orphaned photos are deleted unless `KEEP_PHOTOS=true`; retained images are limited by `MAX_SAVED_PHOTOS`.
- LoginGuard retains at most four per-process log sets, caps each file at approximately 1 MB, and avoids deliberately recording configured addresses and secrets.

## Run the offline tests

The unit tests mock email, camera, and operating-system actions; they do not send messages or execute a shutdown command.

```powershell
.\.venv\Scripts\python -m unittest -v test_login_guard.py
```

## License

Both the Windows and Linux Mint implementations are released under the [MIT License](LICENSE).
