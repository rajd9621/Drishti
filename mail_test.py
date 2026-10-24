"""One-command email check for Drishti.

Run it with the email address that should receive a test code:

    python mail_test.py you@example.com

It prints what the server sees in .env (never the password itself), then
tries to send one real OTP email in the locked format and shows the exact
result, so a mail problem stops being a guessing game.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import mailer  # noqa: E402  (importing it loads the project .env)


def main() -> int:
    to = sys.argv[1] if len(sys.argv) > 1 else ""
    if "@" not in to:
        print("Give the email address that should get the test code:")
        print("    python mail_test.py you@example.com")
        return 2
    print("Drishti mail check")
    print("------------------")
    print("SMTP_HOST:", os.environ.get("SMTP_HOST") or "(not set)")
    print("SMTP_PORT:", os.environ.get("SMTP_PORT") or "587 (default)")
    print("SMTP_USER:", os.environ.get("SMTP_USER") or "(not set)")
    pw = os.environ.get("SMTP_PASS") or ""
    print("SMTP_PASS:", f"set ({len(pw.replace(' ', ''))} characters)"
          if pw else "(NOT SET - this is the usual reason no email goes out)")
    print("SMTP_FROM:", os.environ.get("SMTP_FROM") or "(the SMTP_USER)")
    if not mailer.smtp_configured():
        print()
        print("RESULT: SMTP is not fully configured, so the app is in LOG")
        print("mode and codes are only written to var/outbox.log.")
        print("Fix: open .env in this folder, fill SMTP_PASS with a Gmail")
        print("App Password (2-Step Verification must be ON for the Gmail")
        print("account; create it at myaccount.google.com > Security >")
        print("App passwords), save, and run this check again.")
        return 1
    print()
    print(f"Sending a test code to {to} ...")
    try:
        how = mailer.send_otp(to, "there", "483920", "login")
    except Exception as exc:
        print(f"RESULT: FAILED - {type(exc).__name__}: {exc}")
        print("The same error is saved in var/mail-error.log.")
        if "535" in str(exc) or "Username and Password not accepted" in str(exc):
            print("535 means Gmail rejected the login: the SMTP_PASS must be")
            print("a 16-character App Password, not the normal Gmail password,")
            print("and 2-Step Verification must be ON for that account.")
        return 1
    print(f"RESULT: {how} - check the inbox (and spam folder) of {to}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
