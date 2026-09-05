"""Explicit opt-in utility for testing the configured SMS email gateway."""

from __future__ import annotations

import argparse
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description="Send one LoginGuard SMS-gateway test")
    parser.add_argument(
        "--send",
        action="store_true",
        help="required acknowledgement that this command sends a real message",
    )
    args = parser.parse_args()
    if not args.send:
        parser.error("No message sent. Re-run with --send after checking .env.")

    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
    email_user = os.getenv("EMAIL_USER", "")
    app_password = os.getenv("EMAIL_APP_PASSWORD", "")
    sms_to = os.getenv("SMS_TO", "")
    if not all((email_user, app_password, sms_to)):
        raise RuntimeError("EMAIL_USER, EMAIL_APP_PASSWORD, and SMS_TO are required")

    msg = EmailMessage()
    msg["From"] = email_user
    msg["To"] = sms_to
    msg["Subject"] = "LoginGuard test"
    msg.set_content("This is a LoginGuard SMS-gateway test.")
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        os.getenv("SMTP_HOST", "smtp.gmail.com"),
        int(os.getenv("SMTP_PORT", "465")),
        context=context,
    ) as server:
        server.login(email_user, app_password)
        server.send_message(msg)
    print("SMS-gateway test sent to the configured destination.")


if __name__ == "__main__":
    main()
