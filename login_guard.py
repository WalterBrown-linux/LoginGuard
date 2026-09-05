"""LoginGuard: privacy-conscious Windows login alerts and optional remote actions."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import imaplib
import json
import logging
import os
import platform
import re
import secrets
import smtplib
import socket
import ssl
import subprocess
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header
from email.message import EmailMessage
from email.utils import parseaddr
from logging.handlers import RotatingFileHandler
from pathlib import Path

import cv2
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
PHOTOS_DIR = BASE_DIR / "photos"
LOG_FILE = BASE_DIR / f"login_guard_{os.getpid()}.log"
STATE_FILE = BASE_DIR / ".login_guard_state.json"
MONITOR_LOCK_FILE = BASE_DIR / ".login_guard_monitor.lock"

load_dotenv(BASE_DIR / ".env", override=False)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise RuntimeError(f"{name} must be true or false")
    return normalized == "true"


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")

EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")
ALERT_TO = os.getenv("ALERT_TO", "")
SMS_TO = os.getenv("SMS_TO", "")

REMOTE_COMMANDS_ENABLED = env_bool("REMOTE_COMMANDS_ENABLED", False)
COMMAND_FROM = os.getenv("COMMAND_FROM", "")
COMMAND_SECRET = os.getenv("COMMAND_SECRET", "")
DEVICE_ID = os.getenv("DEVICE_ID", "")
ALLOWED_ACTIONS = {
    action.strip().upper()
    for action in os.getenv("ALLOWED_ACTIONS", "LOCK").split(",")
    if action.strip()
}

CAMERA_INDEX = int(os.getenv("CAMERA_INDEX", "0"))
CAPTURE_PHOTO = env_bool("CAPTURE_PHOTO", False)
KEEP_PHOTOS = env_bool("KEEP_PHOTOS", False)
IP_LOCATION_ENABLED = env_bool("IP_LOCATION_ENABLED", False)
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

POLL_SECONDS = max(10, int(os.getenv("POLL_SECONDS", "30")))
MAX_COMMAND_CANDIDATES = min(100, max(1, int(os.getenv("MAX_COMMAND_CANDIDATES", "20"))))
MAX_COMMAND_HEADER_BYTES = min(
    65_536,
    max(1_024, int(os.getenv("MAX_COMMAND_HEADER_BYTES", "16384"))),
)
COMMAND_MAX_AGE_SECONDS = min(
    3_600,
    max(30, int(os.getenv("COMMAND_MAX_AGE_SECONDS", "300"))),
)
MAX_USED_NONCES = 1_000
MAX_SAVED_PHOTOS = min(100, max(1, int(os.getenv("MAX_SAVED_PHOTOS", "10"))))
VALID_ACTIONS = {"LOCK", "LOGOFF", "SHUTDOWN", "HIBERNATE"}

PHOTOS_DIR.mkdir(exist_ok=True)
logger = logging.getLogger("login_guard")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=1_000_000,
        backupCount=1,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

    # One small file per process avoids Windows rotation failures when an older
    # LoginGuard instance still has its log open. Keep only the newest four
    # process logs; a locked file is simply retried on a later launch.
    process_logs = sorted(
        BASE_DIR.glob("login_guard_[0-9]*.log"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old_log in process_logs[4:]:
        try:
            old_log.unlink()
            old_log.with_suffix(".log.1").unlink(missing_ok=True)
        except OSError:
            pass


def require_config() -> None:
    required = {
        "EMAIL_USER": EMAIL_USER,
        "EMAIL_APP_PASSWORD": EMAIL_APP_PASSWORD,
        "ALERT_TO": ALERT_TO,
    }
    if REMOTE_COMMANDS_ENABLED:
        required.update(
            {
                "COMMAND_FROM": COMMAND_FROM,
                "COMMAND_SECRET": COMMAND_SECRET,
                "DEVICE_ID": DEVICE_ID,
            }
        )
        if len(COMMAND_SECRET) < 32:
            raise RuntimeError("COMMAND_SECRET must contain at least 32 characters")
        if COMMAND_SECRET == "replace_with_at_least_32_random_characters":
            raise RuntimeError("Replace the public COMMAND_SECRET example before enabling commands")
        if not ALLOWED_ACTIONS or not ALLOWED_ACTIONS <= VALID_ACTIONS:
            raise RuntimeError(
                "ALLOWED_ACTIONS must contain only LOCK, LOGOFF, SHUTDOWN, or HIBERNATE"
            )

    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required configuration: {', '.join(missing)}")


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    result = ""
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="replace")
        else:
            result += part
    return result


def get_public_ip_location() -> dict[str, str]:
    """Return coarse public-IP location only when the operator opted in."""
    if not IP_LOCATION_ENABLED:
        return {"status": "disabled"}
    try:
        url = "https://ipinfo.io/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
        with urllib.request.urlopen(url, timeout=8) as response:
            data = json.loads(response.read(65_537).decode("utf-8"))
        return {
            "ip": str(data.get("ip", "unknown")),
            "city": str(data.get("city", "unknown")),
            "region": str(data.get("region", "unknown")),
            "country": str(data.get("country", "unknown")),
            "loc": str(data.get("loc", "unknown")),
            "org": str(data.get("org", "unknown")),
            "timezone": str(data.get("timezone", "unknown")),
        }
    except Exception:
        logger.exception("Location lookup failed")
        return {"error": "Location lookup failed"}


def capture_webcam_photo() -> Path | None:
    if not CAPTURE_PHOTO:
        return None
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    photo_path = PHOTOS_DIR / f"login_{timestamp}_{secrets.token_hex(4)}.jpg"
    cap = None
    try:
        backend = cv2.CAP_DSHOW if platform.system().lower() == "windows" else cv2.CAP_ANY
        cap = cv2.VideoCapture(CAMERA_INDEX, backend)
        if not cap.isOpened():
            logger.error("Could not open webcam")
            return None
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        time.sleep(1)
        frame = None
        success = False
        for _ in range(10):
            success, frame = cap.read()
            time.sleep(0.1)
        if not success or frame is None:
            logger.error("Could not read webcam frame")
            return None
        if not cv2.imwrite(str(photo_path), frame):
            logger.error("Could not save webcam photo")
            return None
        logger.info("Saved temporary webcam photo")
        return photo_path
    except Exception:
        logger.exception("Webcam capture failed")
        return None
    finally:
        if cap is not None:
            cap.release()


def prune_generated_photos() -> None:
    """Apply the configured retention limit to LoginGuard-generated images."""
    photos = sorted(
        PHOTOS_DIR.glob("login_*.jpg"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    keep = MAX_SAVED_PHOTOS if KEEP_PHOTOS else 0
    for old_photo in photos[keep:]:
        try:
            old_photo.unlink()
        except OSError:
            logger.exception("Could not remove an expired webcam photo")


def send_email(subject: str, body: str, to_address: str, attachment_path: Path | None = None) -> None:
    msg = EmailMessage()
    msg["From"] = EMAIL_USER
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment_path and attachment_path.is_file():
        msg.add_attachment(
            attachment_path.read_bytes(),
            maintype="image",
            subtype="jpeg",
            filename="login-alert.jpg",
        )
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
        server.send_message(msg)
    logger.info("Sent notification email")


def build_alert_body(location: dict[str, str]) -> str:
    username = os.getenv("USERNAME") or os.getenv("USER") or "unknown"
    location_lines = "\n".join(f"{key}: {value}" for key, value in location.items())
    command_status = "enabled" if REMOTE_COMMANDS_ENABLED else "disabled"
    return f"""Login alert from your computer.

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
User: {username}
Computer name: {socket.gethostname()}
System: {platform.platform()}

Approximate public-IP location:
{location_lines}

Remote email commands are {command_status}. See the local README for command creation.
The command secret is intentionally never included in an alert.
"""


def _default_command_state() -> dict[str, object]:
    return {"uidvalidity": "", "last_uid": 0, "used_nonces": []}


def load_command_state() -> dict[str, object]:
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("state is not an object")
        state["last_uid"] = max(0, int(state.get("last_uid", 0)))
        nonces = state.get("used_nonces", [])
        state["used_nonces"] = list(nonces)[-MAX_USED_NONCES:] if isinstance(nonces, list) else []
        state["uidvalidity"] = str(state.get("uidvalidity", ""))
        return state
    except FileNotFoundError:
        return _default_command_state()
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        logger.error("Command state is invalid; remote commands fail closed")
        raise RuntimeError("Invalid command state")


def save_command_state(state: dict[str, object]) -> None:
    temp_path = STATE_FILE.with_suffix(".tmp")
    temp_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    os.replace(temp_path, STATE_FILE)


def _mailbox_uidvalidity(mail: imaplib.IMAP4_SSL) -> str:
    response = mail.response("UIDVALIDITY")
    if not response or not response[1]:
        raise RuntimeError("Mailbox did not provide UIDVALIDITY")
    value = response[1][0]
    return value.decode("ascii", errors="strict") if isinstance(value, bytes) else str(value)


def _mailbox_uidnext(mail: imaplib.IMAP4_SSL) -> int:
    response = mail.response("UIDNEXT")
    if not response or not response[1]:
        raise RuntimeError("Mailbox did not provide UIDNEXT")
    value = response[1][0]
    text = value.decode("ascii", errors="strict") if isinstance(value, bytes) else str(value)
    uidnext = int(text)
    if uidnext < 1:
        raise RuntimeError("Mailbox returned an invalid UIDNEXT")
    return uidnext


def _command_payload(device_id: str, action: str, timestamp: int, nonce: str) -> str:
    return f"{device_id}|{action}|{timestamp}|{nonce}"


def build_command_subject(
    action: str,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> str:
    action = action.upper().strip()
    if not REMOTE_COMMANDS_ENABLED or action not in ALLOWED_ACTIONS:
        raise RuntimeError("Remote commands or this action are not enabled")
    if len(COMMAND_SECRET) < 32 or not DEVICE_ID:
        raise RuntimeError("Remote command configuration is incomplete")
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = secrets.token_urlsafe(18) if nonce is None else nonce
    payload = _command_payload(DEVICE_ID, action, timestamp, nonce)
    signature = hmac.new(COMMAND_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"LOGINGUARD {DEVICE_ID} {action} {timestamp} {nonce} {signature}"


def authorize_command_subject(
    subject: str,
    state: dict[str, object],
    *,
    now: int | None = None,
) -> tuple[str, str] | None:
    parts = subject.split()
    if len(parts) != 6 or parts[0] != "LOGINGUARD":
        return None
    _, device_id, action, timestamp_text, nonce, supplied_signature = parts
    action = action.upper()
    if device_id != DEVICE_ID or action not in ALLOWED_ACTIONS:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        return None
    try:
        timestamp = int(timestamp_text)
    except ValueError:
        return None
    now = int(time.time()) if now is None else now
    if timestamp > now + 60 or now - timestamp > COMMAND_MAX_AGE_SECONDS:
        return None
    if nonce in state.get("used_nonces", []):
        return None
    payload = _command_payload(device_id, action, timestamp, nonce)
    expected = hmac.new(COMMAND_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied_signature, expected):
        return None
    return action, nonce


def run_remote_action(action: str) -> bool:
    action = action.upper().strip()
    if not REMOTE_COMMANDS_ENABLED or action not in ALLOWED_ACTIONS:
        logger.warning("Rejected disabled remote action")
        return False
    logger.warning("Executing authorized remote action: %s", action)
    if action == "LOCK":
        if platform.system().lower() != "windows":
            return False
        return bool(ctypes.windll.user32.LockWorkStation())
    commands = {
        "LOGOFF": ["shutdown", "/l"],
        "SHUTDOWN": ["shutdown", "/s", "/f", "/t", "0"],
        "HIBERNATE": ["shutdown", "/h"],
    }
    command = commands.get(action)
    if command is None or platform.system().lower() != "windows":
        return False
    return subprocess.run(command, check=False).returncode == 0


@contextmanager
def exclusive_monitor_lock():
    """Allow only one command monitor to use the mailbox and replay state."""
    lock_file = MONITOR_LOCK_FILE.open("a+b")
    if lock_file.seek(0, os.SEEK_END) == 0:
        lock_file.write(b"0")
        lock_file.flush()
    lock_file.seek(0)
    try:
        if platform.system().lower() == "windows":
            import msvcrt

            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        try:
            yield False
        finally:
            lock_file.close()
        return
    try:
        yield True
    finally:
        try:
            lock_file.seek(0)
            if platform.system().lower() == "windows":
                import msvcrt

                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_file.close()


def check_for_remote_command() -> str | None:
    if not REMOTE_COMMANDS_ENABLED:
        return None
    mail = None
    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST)
        mail.login(EMAIL_USER, EMAIL_APP_PASSWORD)
        status, _ = mail.select("INBOX")
        if status != "OK":
            return None

        uidvalidity = _mailbox_uidvalidity(mail)
        uidnext = _mailbox_uidnext(mail)
        state = load_command_state()
        if state["uidvalidity"] != uidvalidity:
            state = _default_command_state()
            state["uidvalidity"] = uidvalidity
            state["last_uid"] = uidnext - 1
            save_command_state(state)
            logger.info("Command mailbox baseline established")
            return None

        first_uid = int(state["last_uid"]) + 1
        final_uid = min(uidnext - 1, first_uid + MAX_COMMAND_CANDIDATES - 1)
        for uid in range(first_uid, final_uid + 1):
            status, msg_data = mail.uid(
                "fetch",
                str(uid),
                f"(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]<0.{MAX_COMMAND_HEADER_BYTES}>)",
            )
            state["last_uid"] = uid
            if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                save_command_state(state)
                continue
            raw_headers = msg_data[0][1]
            if not isinstance(raw_headers, bytes) or len(raw_headers) >= MAX_COMMAND_HEADER_BYTES:
                save_command_state(state)
                continue
            msg = message_from_bytes(raw_headers)
            sender_email = parseaddr(msg.get("From", ""))[1].lower().strip()
            subject = decode_mime_header(msg.get("Subject", "")).strip()
            authorized = None
            if hmac.compare_digest(sender_email, COMMAND_FROM.lower().strip()):
                authorized = authorize_command_subject(subject, state)
            if authorized:
                action, nonce = authorized
                used_nonces = list(state.get("used_nonces", []))
                used_nonces.append(nonce)
                state["used_nonces"] = used_nonces[-MAX_USED_NONCES:]
                save_command_state(state)
                return action
            save_command_state(state)
        return None
    except Exception:
        logger.exception("Checking remote command email failed")
        return None
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                logger.warning("Mailbox logout failed")


def send_login_alert() -> None:
    location = get_public_ip_location()
    photo_path = capture_webcam_photo()
    try:
        send_email(
            subject="Computer login alert",
            body=build_alert_body(location),
            to_address=ALERT_TO,
            attachment_path=photo_path,
        )
        if SMS_TO:
            send_email(
                subject="Computer login alert",
                body="A LoginGuard alert was generated. Check your configured alert mailbox.",
                to_address=SMS_TO,
            )
    finally:
        if photo_path:
            if KEEP_PHOTOS:
                prune_generated_photos()
            else:
                try:
                    photo_path.unlink(missing_ok=True)
                    logger.info("Removed temporary webcam photo")
                except OSError:
                    logger.exception("Could not remove temporary webcam photo")


def monitor_for_remote_commands() -> None:
    with exclusive_monitor_lock() as acquired:
        if not acquired:
            logger.warning("Another LoginGuard command monitor is already running")
            return
        logger.info("Remote command monitor started")
        while True:
            action = check_for_remote_command()
            if action:
                try:
                    send_email(
                        subject=f"LoginGuard command received: {action}",
                        body=f"The computer received an authorized {action} command.",
                        to_address=ALERT_TO,
                    )
                except Exception:
                    logger.exception("Could not send command confirmation")
                run_remote_action(action)
                time.sleep(12)
            time.sleep(POLL_SECONDS)


def main() -> None:
    require_config()
    prune_generated_photos()
    logger.info("LoginGuard started")
    try:
        send_login_alert()
    except Exception:
        logger.exception("Failed to send login alert")
    if REMOTE_COMMANDS_ENABLED:
        monitor_for_remote_commands()


if __name__ == "__main__":
    main()
