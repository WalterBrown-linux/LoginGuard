import os
import cv2
import ssl
import time
import json
import socket
import imaplib
import smtplib
import logging
import platform
import shutil
import subprocess
import ctypes
import urllib.request
from pathlib import Path
from datetime import datetime
import getpass
from email.message import EmailMessage
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
PHOTOS_DIR = BASE_DIR / "photos"
LOG_FILE = BASE_DIR / "login_guard.log"

PHOTOS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

load_dotenv(BASE_DIR / ".env")


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")

EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")

ALERT_TO = os.getenv("ALERT_TO", "")
SMS_TO = os.getenv("SMS_TO", "")

COMMAND_FROM = os.getenv("COMMAND_FROM", "")
COMMAND_SECRET = os.getenv("COMMAND_SECRET", "")

CAMERA_INDEX = int(os.getenv("CAMERA_INDEX", "0"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
CHECK_LOCK_EMAIL = os.getenv("CHECK_LOCK_EMAIL", "true").lower() == "true"

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")


def require_config():
    required = {
        "EMAIL_USER": EMAIL_USER,
        "EMAIL_APP_PASSWORD": EMAIL_APP_PASSWORD,
        "ALERT_TO": ALERT_TO,
        "COMMAND_FROM": COMMAND_FROM,
        "COMMAND_SECRET": COMMAND_SECRET,
    }

    missing = [key for key, value in required.items() if not value]

    if missing:
        raise RuntimeError(f"Missing required .env values: {', '.join(missing)}")


def decode_mime_header(value):
    if not value:
        return ""

    decoded_parts = decode_header(value)
    result = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="replace")
        else:
            result += part

    return result


def get_public_ip_location():
    """
    Coarse public-IP location. This is not GPS.
    """
    try:
        url = "https://ipinfo.io/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"

        with urllib.request.urlopen(url, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))

        return {
            "ip": data.get("ip", "unknown"),
            "city": data.get("city", "unknown"),
            "region": data.get("region", "unknown"),
            "country": data.get("country", "unknown"),
            "loc": data.get("loc", "unknown"),
            "org": data.get("org", "unknown"),
            "timezone": data.get("timezone", "unknown"),
        }

    except Exception as exc:
        logging.exception("Location lookup failed")
        return {
            "error": f"Location lookup failed: {exc}",
        }


def capture_webcam_photo():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    photo_path = PHOTOS_DIR / f"login_{timestamp}.jpg"

    cap = None

    try:
        if platform.system().lower() == "windows":
            cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW)
        else:
            cap = cv2.VideoCapture(CAMERA_INDEX)

        if not cap.isOpened():
            logging.error("Could not open webcam")
            return None

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

        # Let the camera adjust exposure.
        time.sleep(1)

        frame = None
        success = False

        for _ in range(10):
            success, frame = cap.read()
            time.sleep(0.1)

        if not success or frame is None:
            logging.error("Could not read frame from webcam")
            return None

        cv2.imwrite(str(photo_path), frame)
        logging.info("Saved webcam photo: %s", photo_path)
        return photo_path

    except Exception:
        logging.exception("Webcam capture failed")
        return None

    finally:
        if cap is not None:
            cap.release()


def send_email(subject, body, to_address, attachment_path=None):
    msg = EmailMessage()
    msg["From"] = EMAIL_USER
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_path:
        attachment_path = Path(attachment_path)
        if attachment_path.exists():
            with open(attachment_path, "rb") as file:
                data = file.read()

            msg.add_attachment(
                data,
                maintype="image",
                subtype="jpeg",
                filename=attachment_path.name,
            )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
        server.send_message(msg)

    logging.info("Sent email to %s with subject %s", to_address, subject)


def build_alert_body(location):
    username = os.getenv("USERNAME") or os.getenv("USER") or "unknown"
    hostname = socket.gethostname()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    location_lines = "\n".join(f"{key}: {value}" for key, value in location.items())

    return f"""Login alert from your laptop.

Time: {now}
Windows/Linux user: {username}
Computer name: {hostname}
System: {platform.platform()}

Approximate public-IP location:
{location_lines}

Remote lock instructions:
Send a NEW email to {EMAIL_USER}
From: {COMMAND_FROM}
Subject exactly:
LOCK {COMMAND_SECRET}

Do not reply to this alert email. Send a fresh email with that exact subject.
"""


def run_remote_action(action):
    action = action.upper().strip()

    if action not in {"LOCK", "LOCKOUT", "LOGOFF", "SHUTDOWN", "HIBERNATE"}:
        logging.warning("Unknown remote action requested: %s", action)
        return False

    logging.warning("Remote command received: %s", action)

    if platform.system().lower() == "windows":
        windows_commands = {
            "LOGOFF": "shutdown /l",
            "SHUTDOWN": "shutdown /s /f /t 0",
            "HIBERNATE": "shutdown /h",
        }

        if action == "LOCK":
            ctypes.windll.user32.LockWorkStation()
            return True

        if action == "LOCKOUT":
            logging.error("LOCKOUT is only supported by the installed Linux helper")
            return False

        return os.system(windows_commands[action]) == 0

    linux_commands = {
        # Linux Mint Cinnamon runs under LightDM. dm-tool locks the active seat
        # even when cinnamon-screensaver is unavailable or broken.
        "LOCK": [
            ["dm-tool", "lock"],
            ["loginctl", "lock-session"],
            ["xdg-screensaver", "lock"],
        ],
        "LOCKOUT": [
            [
                "sudo",
                "-n",
                "/usr/local/sbin/login-guard-account",
                "lock",
                getpass.getuser(),
            ]
        ],
        "LOGOFF": [["loginctl", "terminate-user", getpass.getuser()]],
        "SHUTDOWN": [["systemctl", "poweroff"]],
        "HIBERNATE": [["systemctl", "hibernate"]],
    }

    for command in linux_commands[action]:
        if not command[-1] or not shutil.which(command[0]):
            continue

        try:
            subprocess.run(command, check=True)
            return True
        except (OSError, subprocess.CalledProcessError):
            logging.exception("Linux command failed: %s", command)

    logging.error("No working Linux command found for action: %s", action)
    return False


def check_for_remote_command():
    allowed_actions = ["LOCK", "LOCKOUT", "LOGOFF", "SHUTDOWN", "HIBERNATE"]

    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST)
        mail.login(EMAIL_USER, EMAIL_APP_PASSWORD)
        mail.select("INBOX")

        status, data = mail.search(None, '(UNSEEN)')

        if status != "OK":
            mail.logout()
            return None

        message_ids = data[0].split()

        for msg_id in message_ids:
            # RFC822/BODY[] fetches implicitly add the IMAP \Seen flag. Peek at
            # unread messages so only a validated command is marked as read by
            # the explicit store() call below.
            status, msg_data = mail.fetch(msg_id, "(BODY.PEEK[])")

            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = message_from_bytes(raw_email)

            subject = decode_mime_header(msg.get("Subject", "")).strip()
            sender_email = parseaddr(msg.get("From", ""))[1].lower().strip()

            parts = subject.split()

            if len(parts) != 2:
                continue

            action = parts[0].upper().strip()
            secret = parts[1].strip()

            if (
                sender_email == COMMAND_FROM.lower().strip()
                and action in allowed_actions
                and secret == COMMAND_SECRET
            ):
                mail.store(msg_id, "+FLAGS", "\\Seen")
                mail.logout()
                return action

        mail.logout()
        return None

    except Exception:
        logging.exception("Checking remote command email failed")
        return None


def send_login_alert():
    location = get_public_ip_location()
    photo_path = capture_webcam_photo()
    body = build_alert_body(location)

    subject = "Laptop login alert"

    send_email(
        subject=subject,
        body=body,
        to_address=ALERT_TO,
        attachment_path=photo_path,
    )

    if SMS_TO:
        try:
            sms_body = (
                "Laptop login alert. "
                f"Computer: {socket.gethostname()}. "
                f"Approx location: {location.get('city', 'unknown')}, "
                f"{location.get('region', 'unknown')}, "
                f"{location.get('country', 'unknown')}. "
                "Check your email for the photo."
            )

            send_email(
                subject="Laptop login alert",
                body=sms_body,
                to_address=SMS_TO,
                attachment_path=None,
            )

            logging.info("SMS alert sent")

        except Exception:
            logging.exception("SMS alert failed")


def monitor_for_remote_commands():
    logging.info("Remote command monitor started")

    while True:
        action = check_for_remote_command()

        if action:
            try:
                send_email(
                    subject=f"LoginGuard command received: {action}",
                    body=f"The laptop received your {action} command.",
                    to_address=ALERT_TO,
                )
            except Exception:
                logging.exception("Could not send command confirmation email")

            run_remote_action(action)
            time.sleep(12)

        time.sleep(POLL_SECONDS)


def main():
    require_config()

    logging.info("Login Guard started")

    try:
        send_login_alert()
    except Exception:
        logging.exception("Failed to send login alert")

    if CHECK_LOCK_EMAIL:
        monitor_for_remote_commands()


if __name__ == "__main__":
    main()
