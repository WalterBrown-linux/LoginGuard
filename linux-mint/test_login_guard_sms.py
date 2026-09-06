import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import login_guard_sms


class TestSmsMonitor(unittest.TestCase):
    CONFIG = {
        "TWILIO_ACCOUNT_SID": "AC" + "1" * 32,
        "TWILIO_AUTH_TOKEN": "token",
        "TWILIO_NUMBER": "+17375550000",
        "AUTHORIZED_FROM": "+15125550001,+15125550002",
        "SMS_SECRET": "private-secret",
        "TARGET_USER": "sampleuser",
    }

    def test_authorized_command_runs_fixed_helper(self):
        message = {
            "from": "+15125550002",
            "body": "RESTORE private-secret",
        }
        with patch("login_guard_sms.subprocess.run") as run:
            consumed = login_guard_sms.handle_message(message, self.CONFIG)
        self.assertTrue(consumed)
        run.assert_called_once_with(
            [login_guard_sms.ACCOUNT_HELPER, "unlock", "sampleuser"], check=True
        )

    def test_wrong_sender_or_secret_never_runs(self):
        messages = [
            {"from": "+15125559999", "body": "LOCKOUT private-secret"},
            {"from": "+15125550001", "body": "LOCKOUT wrong"},
        ]
        with patch("login_guard_sms.subprocess.run") as run:
            for message in messages:
                self.assertTrue(login_guard_sms.handle_message(message, self.CONFIG))
        run.assert_not_called()

    def test_command_allows_safe_noop_test(self):
        message = {
            "from": "+15125550001",
            "body": "TEST private-secret",
        }
        with patch("login_guard_sms.subprocess.run") as run:
            self.assertTrue(login_guard_sms.handle_message(message, self.CONFIG))
        run.assert_not_called()

    def test_first_poll_baselines_old_messages(self):
        messages = [{
            "sid": "SM-old",
            "direction": "inbound",
            "to": "+17375550000",
            "from": "+15125550001",
            "body": "SHUTDOWN private-secret",
        }]
        with tempfile.TemporaryDirectory() as directory, \
             patch("login_guard_sms.fetch_messages", return_value=messages), \
             patch("login_guard_sms.handle_message") as handle:
            state_path = Path(directory) / "state.json"
            self.assertEqual(login_guard_sms.poll_once(self.CONFIG, state_path), 0)
            handle.assert_not_called()
            state = json.loads(state_path.read_text())
            self.assertTrue(state["initialized"])
            self.assertEqual(state["seen_ids"], ["SM-old"])

    def test_new_message_runs_only_once(self):
        messages = [{
            "sid": "SM-new",
            "direction": "inbound",
            "to": "+17375550000",
            "from": "+15125550001",
            "body": "LOCKOUT private-secret",
        }]
        with tempfile.TemporaryDirectory() as directory, \
             patch("login_guard_sms.fetch_messages", return_value=messages), \
             patch("login_guard_sms.handle_message", return_value=True) as handle:
            state_path = Path(directory) / "state.json"
            login_guard_sms.save_state(
                {"initialized": True, "seen_ids": []}, state_path
            )
            self.assertEqual(login_guard_sms.poll_once(self.CONFIG, state_path), 1)
            self.assertEqual(login_guard_sms.poll_once(self.CONFIG, state_path), 0)
            handle.assert_called_once()


if __name__ == "__main__":
    unittest.main()
