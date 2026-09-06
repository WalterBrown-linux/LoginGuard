#!/usr/bin/python3
"""Minimal recovery-mail monitor for restoring the configured local account."""

import hmac
import imaplib
import logging
import os
import subprocess
import time
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path


CONFIG_FILE = Path("/etc/login-guard-recovery.env")
ACCOUNT_HELPER = "/usr/local/sbin/login-guard-account"


def load_config(path=CONFIG_FILE):
    values = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def decode_header_text(value):
    result = ""
    for part, encoding in decode_header(value or ""):
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="replace")
        else:
            result += part
    return result.strip()


def authorized_senders(config):
    """Return the normalized, de-duplicated configured sender addresses."""
    senders = []
    for value in config["COMMAND_FROM"].split(","):
        address = parseaddr(value.strip())[1].lower().strip()
        if address and address not in senders:
            senders.append(address)
    return senders


def check_for_restore(config):
    mail = None
    try:
        mail = imaplib.IMAP4_SSL(config.get("IMAP_HOST", "imap.gmail.com"))
        mail.login(
            config["EMAIL_USER"], config["EMAIL_APP_PASSWORD"].replace(" ", "")
        )
        mail.select("INBOX")

        allowed_senders = authorized_senders(config)
        message_ids = []
        for allowed_sender in allowed_senders:
            status, data = mail.search(
                None, "UNSEEN", "FROM", f'"{allowed_sender}"'
            )
            if status != "OK":
                continue
            for message_id in data[0].split():
                if message_id not in message_ids:
                    message_ids.append(message_id)

        for message_id in message_ids:
            status, message_data = mail.fetch(message_id, "(BODY.PEEK[])")
            if status != "OK" or not message_data or not message_data[0]:
                continue

            message = message_from_bytes(message_data[0][1])
            sender = parseaddr(message.get("From", ""))[1].lower().strip()
            subject = decode_header_text(message.get("Subject", ""))
            action, separator, supplied_secret = subject.partition(" ")

            if sender not in allowed_senders:
                continue
            if action.upper() != "RESTORE" or not separator:
                continue
            if not hmac.compare_digest(supplied_secret, config["RECOVERY_SECRET"]):
                continue

            subprocess.run(
                [ACCOUNT_HELPER, "unlock", config["TARGET_USER"]],
                check=True,
            )
            mail.store(message_id, "+FLAGS", "\\Seen")
            logging.warning("Restored account after valid recovery command")
            return True
        return False
    except Exception:
        logging.exception("Recovery mailbox check failed")
        return False
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    config = load_config()
    required = ["EMAIL_USER", "EMAIL_APP_PASSWORD", "COMMAND_FROM", "RECOVERY_SECRET", "TARGET_USER"]
    missing = [name for name in required if not config.get(name)]
    if missing:
        raise RuntimeError(f"Missing recovery configuration: {', '.join(missing)}")

    poll_seconds = int(config.get("POLL_SECONDS", "30"))
    logging.info("LoginGuard recovery monitor started")
    while True:
        check_for_restore(config)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
