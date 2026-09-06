#!/usr/bin/python3
"""Poll Twilio for authenticated, fixed-scope LoginGuard SMS commands."""

import base64
import hmac
import json
import logging
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path


CONFIG_FILE = Path("/etc/login-guard-sms.env")
STATE_FILE = Path("/var/lib/login-guard-sms/state.json")
ACCOUNT_HELPER = "/usr/local/sbin/login-guard-account"
MAX_SEEN_IDS = 500


def load_config(path=CONFIG_FILE):
    values = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def normalize_phone(value):
    value = value.strip()
    if value.startswith("+") and value[1:].isdigit():
        return value
    digits = "".join(character for character in value if character.isdigit())
    if len(digits) == 10:
        return "+1" + digits
    if 11 <= len(digits) <= 15:
        return "+" + digits
    return ""


def authorized_numbers(config):
    numbers = []
    for value in config["AUTHORIZED_FROM"].split(","):
        number = normalize_phone(value)
        if number and number not in numbers:
            numbers.append(number)
    return numbers


def load_state(path=STATE_FILE):
    if not path.exists():
        return {"initialized": False, "seen_ids": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            "initialized": bool(data.get("initialized")),
            "seen_ids": list(data.get("seen_ids", []))[-MAX_SEEN_IDS:],
        }
    except (OSError, ValueError, TypeError):
        logging.exception("Could not read SMS state; safely baselining messages")
        return {"initialized": False, "seen_ids": []}


def save_state(state, path=STATE_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def fetch_messages(config):
    account_sid = config["TWILIO_ACCOUNT_SID"]
    query = urllib.parse.urlencode({"To": config["TWILIO_NUMBER"], "PageSize": 100})
    url = (
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/"
        f"Messages.json?{query}"
    )
    credentials = base64.b64encode(
        f'{account_sid}:{config["TWILIO_AUTH_TOKEN"]}'.encode("utf-8")
    ).decode("ascii")
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.load(response)
    return payload.get("messages", [])


def run_action(action, target_user):
    if action == "TEST":
        return True
    commands = {
        "LOCKOUT": [ACCOUNT_HELPER, "lock", target_user],
        "RESTORE": [ACCOUNT_HELPER, "unlock", target_user],
        "SHUTDOWN": ["/usr/bin/systemctl", "poweroff"],
    }
    command = commands.get(action)
    if command is None:
        return False
    subprocess.run(command, check=True)
    return True


def handle_message(message, config):
    sender = normalize_phone(message.get("from", ""))
    if sender not in authorized_numbers(config):
        logging.warning("Rejected SMS from an unauthorized number")
        return True

    action, separator, supplied_secret = message.get("body", "").strip().partition(" ")
    action = action.upper()
    if not separator or action not in {"TEST", "LOCKOUT", "RESTORE", "SHUTDOWN"}:
        logging.warning("Rejected SMS with an unsupported command")
        return True
    if not hmac.compare_digest(supplied_secret.strip(), config["SMS_SECRET"]):
        logging.warning("Rejected SMS with an invalid command secret")
        return True

    try:
        run_action(action, config["TARGET_USER"])
    except Exception:
        logging.exception("Authenticated SMS command failed: %s", action)
        return False
    logging.warning("Authenticated SMS command completed: %s", action)
    return True


def poll_once(config, state_path=STATE_FILE):
    messages = [
        message
        for message in fetch_messages(config)
        if message.get("direction") == "inbound"
        and normalize_phone(message.get("to", "")) == config["TWILIO_NUMBER"]
    ]
    state = load_state(state_path)
    current_ids = [message.get("sid") for message in messages if message.get("sid")]

    if not state["initialized"]:
        state = {"initialized": True, "seen_ids": current_ids[-MAX_SEEN_IDS:]}
        save_state(state, state_path)
        logging.info("SMS monitor baseline created; old messages will not execute")
        return 0

    seen = set(state["seen_ids"])
    handled = 0
    for message in reversed(messages):
        message_sid = message.get("sid")
        if not message_sid or message_sid in seen:
            continue
        if handle_message(message, config):
            state["seen_ids"].append(message_sid)
            state["seen_ids"] = state["seen_ids"][-MAX_SEEN_IDS:]
            save_state(state, state_path)
            seen.add(message_sid)
            handled += 1
    return handled


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    config = load_config()
    required = [
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_NUMBER",
        "AUTHORIZED_FROM",
        "SMS_SECRET",
        "TARGET_USER",
    ]
    missing = [name for name in required if not config.get(name)]
    if missing:
        raise RuntimeError(f"Missing SMS configuration: {', '.join(missing)}")

    config["TWILIO_NUMBER"] = normalize_phone(config["TWILIO_NUMBER"])
    if not config["TWILIO_NUMBER"] or not authorized_numbers(config):
        raise RuntimeError("Invalid Twilio or authorized sender phone number")

    logging.info("LoginGuard Twilio SMS monitor started")
    while True:
        try:
            poll_once(config)
        except Exception:
            logging.exception("Twilio SMS poll failed")
        time.sleep(int(config.get("POLL_SECONDS", "20")))


if __name__ == "__main__":
    main()
