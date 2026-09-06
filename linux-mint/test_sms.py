import os
import ssl
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

def send_sms_test():
    load_dotenv(".env")

    email_user = os.getenv("EMAIL_USER")
    email_app_password = os.getenv("EMAIL_APP_PASSWORD")
    sms_to = os.getenv("SMS_TO")
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))

    missing = [
        name
        for name, value in {
            "EMAIL_USER": email_user,
            "EMAIL_APP_PASSWORD": email_app_password,
            "SMS_TO": sms_to,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing .env values: {', '.join(missing)}")

    msg = EmailMessage()
    msg["From"] = email_user
    msg["To"] = sms_to
    msg["Subject"] = "Test"
    msg.set_content("This is a LoginGuard text test.")

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
        server.login(email_user, email_app_password)
        server.send_message(msg)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Send one LoginGuard SMS-gateway test email"
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="required acknowledgement that this command sends a real message",
    )
    args = parser.parse_args()
    if not args.send:
        parser.error("No message sent. Re-run with --send after checking .env.")

    send_sms_test()