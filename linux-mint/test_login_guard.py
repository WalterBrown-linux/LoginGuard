import sys
import subprocess
import unittest
from types import ModuleType
from unittest.mock import MagicMock, call, patch
from email.message import EmailMessage

# The tested module imports cv2 and dotenv at import time. Provide fake modules for tests.
sys.modules["cv2"] = MagicMock()
dotenv_module = ModuleType("dotenv")
dotenv_module.load_dotenv = lambda *args, **kwargs: None
sys.modules["dotenv"] = dotenv_module

import login_guard


class TestLoginGuardRemoteCommand(unittest.TestCase):
    def _make_raw_email(self, subject: str, sender: str) -> bytes:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg.set_content("Test body")
        return msg.as_bytes()

    def test_check_for_remote_command_returns_action_when_valid(self):
        raw_email = self._make_raw_email("LOCK secret", "Commands <user@example.com>")

        mail = MagicMock()
        mail.search.return_value = ("OK", [b"1"])
        mail.fetch.return_value = ("OK", [(None, raw_email)])

        with patch("login_guard.imaplib.IMAP4_SSL", return_value=mail), \
             patch.object(login_guard, "COMMAND_FROM", "user@example.com"), \
             patch.object(login_guard, "COMMAND_SECRET", "secret"):
            action = login_guard.check_for_remote_command()

        self.assertEqual(action, "LOCK")
        mail.fetch.assert_called_once_with(b"1", "(BODY.PEEK[])")
        mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")
        mail.logout.assert_called_once()

    def test_check_for_remote_command_returns_none_when_secret_invalid(self):
        raw_email = self._make_raw_email("LOCK wrongsecret", "Commands <user@example.com>")

        mail = MagicMock()
        mail.search.return_value = ("OK", [b"1"])
        mail.fetch.return_value = ("OK", [(None, raw_email)])

        with patch("login_guard.imaplib.IMAP4_SSL", return_value=mail), \
             patch.object(login_guard, "COMMAND_FROM", "user@example.com"), \
             patch.object(login_guard, "COMMAND_SECRET", "secret"):
            action = login_guard.check_for_remote_command()

        self.assertIsNone(action)
        mail.fetch.assert_called_once_with(b"1", "(BODY.PEEK[])")
        mail.store.assert_not_called()
        mail.logout.assert_called_once()

    def test_check_for_remote_command_returns_none_when_action_invalid(self):
        raw_email = self._make_raw_email("REBOOT secret", "Commands <user@example.com>")

        mail = MagicMock()
        mail.search.return_value = ("OK", [b"1"])
        mail.fetch.return_value = ("OK", [(None, raw_email)])

        with patch("login_guard.imaplib.IMAP4_SSL", return_value=mail), \
             patch.object(login_guard, "COMMAND_FROM", "user@example.com"), \
             patch.object(login_guard, "COMMAND_SECRET", "secret"):
            action = login_guard.check_for_remote_command()

        self.assertIsNone(action)
        mail.fetch.assert_called_once_with(b"1", "(BODY.PEEK[])")
        mail.store.assert_not_called()
        mail.logout.assert_called_once()

    def test_ordinary_unread_mail_stays_unread_before_valid_command(self):
        ordinary_email = self._make_raw_email(
            "Monthly statement", "Bank <alerts@example.net>"
        )
        command_email = self._make_raw_email(
            "LOCK secret", "Commands <user@example.com>"
        )

        mail = MagicMock()
        mail.search.return_value = ("OK", [b"1 2"])
        mail.fetch.side_effect = [
            ("OK", [(None, ordinary_email)]),
            ("OK", [(None, command_email)]),
        ]

        with patch("login_guard.imaplib.IMAP4_SSL", return_value=mail), \
             patch.object(login_guard, "COMMAND_FROM", "user@example.com"), \
             patch.object(login_guard, "COMMAND_SECRET", "secret"):
            action = login_guard.check_for_remote_command()

        self.assertEqual(action, "LOCK")
        self.assertEqual(
            mail.fetch.call_args_list,
            [
                call(b"1", "(BODY.PEEK[])"),
                call(b"2", "(BODY.PEEK[])"),
            ],
        )
        mail.store.assert_called_once_with(b"2", "+FLAGS", "\\Seen")
        mail.logout.assert_called_once()

    def test_check_for_remote_command_returns_none_when_search_fails(self):
        mail = MagicMock()
        mail.search.return_value = ("NO", [b""])

        with patch("login_guard.imaplib.IMAP4_SSL", return_value=mail), \
             patch.object(login_guard, "COMMAND_FROM", "user@example.com"), \
             patch.object(login_guard, "COMMAND_SECRET", "secret"):
            action = login_guard.check_for_remote_command()

        self.assertIsNone(action)
        mail.logout.assert_called_once()


class TestRemoteAction(unittest.TestCase):
    @patch("login_guard.subprocess.run")
    @patch("login_guard.shutil.which", return_value="/usr/bin/systemctl")
    @patch("login_guard.platform.system", return_value="Linux")
    def test_linux_lock_uses_lightdm(self, _system, _which, run):
        self.assertTrue(login_guard.run_remote_action("LOCK"))
        run.assert_called_once_with(["dm-tool", "lock"], check=True)

    @patch("login_guard.logging.exception")
    @patch("login_guard.subprocess.run")
    @patch("login_guard.shutil.which", return_value="/usr/bin/tool")
    @patch("login_guard.platform.system", return_value="Linux")
    def test_linux_lock_falls_back_to_loginctl(
        self, _system, _which, run, _logging_exception
    ):
        run.side_effect = [
            subprocess.CalledProcessError(1, ["dm-tool", "lock"]),
            None,
        ]

        self.assertTrue(login_guard.run_remote_action("LOCK"))
        self.assertEqual(
            run.call_args_list,
            [
                call(["dm-tool", "lock"], check=True),
                call(["loginctl", "lock-session"], check=True),
            ],
        )

    @patch("login_guard.subprocess.run")
    @patch("login_guard.shutil.which", return_value="/usr/bin/systemctl")
    @patch("login_guard.platform.system", return_value="Linux")
    def test_linux_shutdown_uses_systemctl(self, _system, _which, run):
        self.assertTrue(login_guard.run_remote_action("shutdown"))
        run.assert_called_once_with(["systemctl", "poweroff"], check=True)

    @patch("login_guard.subprocess.run")
    @patch("login_guard.shutil.which", return_value="/usr/bin/sudo")
    @patch("login_guard.platform.system", return_value="Linux")
    def test_linux_lockout_uses_fixed_privileged_helper(self, _system, _which, run):
        with patch("login_guard.getpass.getuser", return_value="sampleuser"):
            self.assertTrue(login_guard.run_remote_action("LOCKOUT"))
        run.assert_called_once_with(
            [
                "sudo",
                "-n",
                "/usr/local/sbin/login-guard-account",
                "lock",
                "sampleuser",
            ],
            check=True,
        )

    @patch("login_guard.platform.system", return_value="Linux")
    def test_unknown_remote_action_is_rejected(self, _system):
        self.assertFalse(login_guard.run_remote_action("REBOOT"))


if __name__ == "__main__":
    unittest.main()
