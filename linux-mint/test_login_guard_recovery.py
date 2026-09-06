import unittest
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import login_guard_recovery


class TestRecoveryMonitor(unittest.TestCase):
    CONFIG = {
        "EMAIL_USER": "recovery@example.com",
        "EMAIL_APP_PASSWORD": "app-password",
        "COMMAND_FROM": "owner@example.com",
        "RECOVERY_SECRET": "recovery-secret",
        "TARGET_USER": "sampleuser",
    }

    @staticmethod
    def make_email(subject, sender="Owner <owner@example.com>"):
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender
        message.set_content("Recovery command")
        return message.as_bytes()

    def test_valid_restore_uses_peek_and_unlocks(self):
        mail = MagicMock()
        mail.search.return_value = ("OK", [b"7"])
        mail.fetch.return_value = (
            "OK",
            [(None, self.make_email("RESTORE recovery-secret"))],
        )

        with patch("login_guard_recovery.imaplib.IMAP4_SSL", return_value=mail), \
             patch("login_guard_recovery.subprocess.run") as run:
            restored = login_guard_recovery.check_for_restore(self.CONFIG)

        self.assertTrue(restored)
        mail.fetch.assert_called_once_with(b"7", "(BODY.PEEK[])")
        run.assert_called_once_with(
            [login_guard_recovery.ACCOUNT_HELPER, "unlock", "sampleuser"], check=True
        )
        mail.store.assert_called_once_with(b"7", "+FLAGS", "\\Seen")

    def test_second_non_gmail_sender_is_authorized(self):
        config = dict(self.CONFIG)
        config["COMMAND_FROM"] = "owner@example.com, Parent <parent@example.net>"
        mail = MagicMock()
        mail.search.side_effect = [("OK", [b""]), ("OK", [b"11"])]
        mail.fetch.return_value = (
            "OK",
            [(None, self.make_email(
                "RESTORE recovery-secret", "Parent <PARENT@example.net>"
            ))],
        )

        with patch("login_guard_recovery.imaplib.IMAP4_SSL", return_value=mail), \
             patch("login_guard_recovery.subprocess.run") as run:
            restored = login_guard_recovery.check_for_restore(config)

        self.assertTrue(restored)
        self.assertEqual(mail.search.call_count, 2)
        mail.search.assert_any_call(
            None, "UNSEEN", "FROM", '"parent@example.net"'
        )
        run.assert_called_once()

    def test_sender_list_is_normalized_and_deduplicated(self):
        config = dict(self.CONFIG)
        config["COMMAND_FROM"] = (
            "Owner <OWNER@example.com>, parent@example.org, owner@example.com"
        )
        self.assertEqual(
            login_guard_recovery.authorized_senders(config),
            ["owner@example.com", "parent@example.org"],
        )

    def test_invalid_secret_neither_unlocks_nor_marks_read(self):
        mail = MagicMock()
        mail.search.return_value = ("OK", [b"8"])
        mail.fetch.return_value = (
            "OK",
            [(None, self.make_email("RESTORE wrong-secret"))],
        )

        with patch("login_guard_recovery.imaplib.IMAP4_SSL", return_value=mail), \
             patch("login_guard_recovery.subprocess.run") as run:
            restored = login_guard_recovery.check_for_restore(self.CONFIG)

        self.assertFalse(restored)
        run.assert_not_called()
        mail.store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
