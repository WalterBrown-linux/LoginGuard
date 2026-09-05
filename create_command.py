"""Create a short-lived, one-time LoginGuard email subject."""

from __future__ import annotations

import argparse

import login_guard


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=sorted(login_guard.VALID_ACTIONS))
    args = parser.parse_args()
    login_guard.require_config()
    print(login_guard.build_command_subject(args.action))


if __name__ == "__main__":
    main()
