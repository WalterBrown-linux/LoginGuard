from __future__ import annotations

import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

import login_guard


class LoginGuardTests(unittest.TestCase):
    def command_policy(self):
        return patch.multiple(
            login_guard,
            REMOTE_COMMANDS_ENABLED=True,
            COMMAND_FROM="commands@example.com",
            COMMAND_SECRET="a" * 48,
            DEVICE_ID="laptop-one",
            ALLOWED_ACTIONS={"LOCK"},
        )

    def test_alert_body_never_contains_command_secret(self):
        with self.command_policy():
            body = login_guard.build_alert_body({"status": "disabled"})
        self.assertNotIn("a" * 48, body)
        self.assertNotIn("commands@example.com", body)

    def test_remote_commands_are_disabled_by_default(self):
        with patch.object(login_guard, "REMOTE_COMMANDS_ENABLED", False), patch(
            "login_guard.imaplib.IMAP4_SSL"
        ) as imap:
            self.assertIsNone(login_guard.check_for_remote_command())
        imap.assert_not_called()

    def test_signed_command_is_accepted_once(self):
        state = {"uidvalidity": "1", "last_uid": 0, "used_nonces": []}
        with self.command_policy():
            subject = login_guard.build_command_subject(
                "LOCK", timestamp=1_000, nonce="valid_nonce_value_123"
            )
            accepted = login_guard.authorize_command_subject(subject, state, now=1_001)
            self.assertEqual(accepted, ("LOCK", "valid_nonce_value_123"))
            state["used_nonces"].append(accepted[1])
            self.assertIsNone(login_guard.authorize_command_subject(subject, state, now=1_001))

    def test_plaintext_legacy_subject_and_stale_command_are_rejected(self):
        state = {"uidvalidity": "1", "last_uid": 0, "used_nonces": []}
        with self.command_policy():
            self.assertIsNone(login_guard.authorize_command_subject("LOCK old-secret", state))
            subject = login_guard.build_command_subject(
                "LOCK", timestamp=1_000, nonce="valid_nonce_value_456"
            )
            self.assertIsNone(login_guard.authorize_command_subject(subject, state, now=2_000))

    def test_mailbox_first_run_baselines_existing_messages(self):
        mail = MagicMock()
        mail.select.return_value = ("OK", [b"3"])

        def response(name):
            return (name, [b"77"] if name == "UIDVALIDITY" else [b"13"])

        mail.response.side_effect = response
        with self.command_policy(), patch(
            "login_guard.imaplib.IMAP4_SSL", return_value=mail
        ), patch("login_guard.load_command_state", return_value=login_guard._default_command_state()), patch(
            "login_guard.save_command_state"
        ) as save:
            self.assertIsNone(login_guard.check_for_remote_command())
        saved = save.call_args.args[0]
        self.assertEqual(saved["uidvalidity"], "77")
        self.assertEqual(saved["last_uid"], 12)
        mail.uid.assert_not_called()

    def test_mailbox_fetch_is_header_only_and_candidate_bounded(self):
        mail = MagicMock()
        mail.select.return_value = ("OK", [b"100"])

        def response(name):
            return (name, [b"77"] if name == "UIDVALIDITY" else [b"101"])

        mail.response.side_effect = response
        raw = self._raw_headers("invalid", "other@example.com")

        def uid(command, *args):
            self.assertEqual(command, "fetch")
            return "OK", [(b"headers", raw)]

        mail.uid.side_effect = uid
        state = {"uidvalidity": "77", "last_uid": 0, "used_nonces": []}
        with self.command_policy(), patch.object(login_guard, "MAX_COMMAND_CANDIDATES", 4), patch(
            "login_guard.imaplib.IMAP4_SSL", return_value=mail
        ), patch("login_guard.load_command_state", return_value=state), patch(
            "login_guard.save_command_state"
        ):
            self.assertIsNone(login_guard.check_for_remote_command())
        fetches = [call for call in mail.uid.call_args_list if call.args[0] == "fetch"]
        self.assertEqual(len(fetches), 4)
        for call in fetches:
            self.assertIn("BODY.PEEK[HEADER.FIELDS", call.args[2])
            self.assertIn("<0.", call.args[2])
            self.assertNotIn("RFC822", call.args[2])

    def test_monitor_lock_rejects_a_second_process_instance(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(
            login_guard, "MONITOR_LOCK_FILE", Path(temp_dir) / "monitor.lock"
        ):
            with login_guard.exclusive_monitor_lock() as first:
                with login_guard.exclusive_monitor_lock() as second:
                    self.assertTrue(first)
                    self.assertFalse(second)

    def test_photo_retention_removes_orphans_and_caps_saved_images(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(
            login_guard, "PHOTOS_DIR", Path(temp_dir)
        ):
            photos = []
            for number in range(4):
                photo = Path(temp_dir) / f"login_{number}.jpg"
                photo.write_bytes(b"photo")
                photos.append(photo)

            with patch.object(login_guard, "KEEP_PHOTOS", False):
                login_guard.prune_generated_photos()
            self.assertFalse(any(photo.exists() for photo in photos))

            for number in range(4):
                (Path(temp_dir) / f"login_saved_{number}.jpg").write_bytes(b"photo")
            with patch.object(login_guard, "KEEP_PHOTOS", True), patch.object(
                login_guard, "MAX_SAVED_PHOTOS", 2
            ):
                login_guard.prune_generated_photos()
            self.assertEqual(len(list(Path(temp_dir).glob("login_*.jpg"))), 2)

    def test_public_placeholder_secret_is_rejected(self):
        with self.command_policy(), patch.object(
            login_guard,
            "COMMAND_SECRET",
            "replace_with_at_least_32_random_characters",
        ):
            with self.assertRaises(RuntimeError):
                login_guard.require_config()

    def test_temporary_photo_is_removed_even_when_email_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            photo = Path(temp_dir) / "capture.jpg"
            photo.write_bytes(b"not-a-real-photo")
            with patch("login_guard.capture_webcam_photo", return_value=photo), patch(
                "login_guard.get_public_ip_location", return_value={"status": "disabled"}
            ), patch("login_guard.send_email", side_effect=RuntimeError("offline")), patch.object(
                login_guard, "KEEP_PHOTOS", False
            ):
                with self.assertRaises(RuntimeError):
                    login_guard.send_login_alert()
            self.assertFalse(photo.exists())

    def test_disabled_action_cannot_reach_operating_system(self):
        with patch.object(login_guard, "REMOTE_COMMANDS_ENABLED", False), patch(
            "login_guard.subprocess.run"
        ) as run:
            self.assertFalse(login_guard.run_remote_action("SHUTDOWN"))
        run.assert_not_called()

    @staticmethod
    def _raw_headers(subject: str, sender: str) -> bytes:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        return msg.as_bytes()


if __name__ == "__main__":
    unittest.main()
