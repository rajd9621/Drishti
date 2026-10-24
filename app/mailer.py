"""Outgoing mail for Drishti: the OTP email in the locked format-3 design.

Two modes, chosen by environment:
  * SMTP mode: when SMTP_HOST, SMTP_USER and SMTP_PASS are set (in the real
    environment, or in a .env file in the project root), the mail goes out
    over SMTP as text + HTML, with the logo embedded inline (CID) so it
    renders inside the message instead of arriving as an attachment.
  * LOG mode (default, zero setup): the message is appended to
    var/outbox.log so the flow can be tested end to end with no mailbox.

MAIL_TEST_RECIPIENT is deliberately NOT supported: it would silently
redirect every user's code to one address.
"""
from __future__ import annotations

import os
import re
import smtplib
import ssl
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Importing config loads the project .env into the environment first and
# anchors all local files to the project root.
from .config import VAR_DIR

_TEMPLATE = Path(__file__).resolve().parent / "templates" / "otp_email.html"
_LOGO = Path(__file__).resolve().parent / "static" / "logo.png"


def _var_dir() -> str:
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    return str(VAR_DIR)


def _log_error(text: str) -> None:
    try:
        with open(os.path.join(_var_dir(), "mail-error.log"), "a",
                  encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass


def smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER")
                and os.environ.get("SMTP_PASS"))


def render_otp_html(name: str, code: str, purpose: str) -> str:
    """Render the locked format-3 template for one user and code."""
    first = (name or "").strip().split(" ")[0] or "there"
    if _TEMPLATE.exists():
        html = _TEMPLATE.read_text(encoding="utf-8")
    else:
        html = ("<html><body><p>Hi {n}, your Drishti code is {c}. "
                "It is valid for 10 minutes.</p></body></html>")
    html = html.replace("Hi Bhavya", f"Hi {first}")
    digits = list(str(code).zfill(6))[:6]
    counter = {"i": 0}

    def _swap(match):
        idx = counter["i"]
        counter["i"] += 1
        return f">{digits[idx]}<" if idx < len(digits) else match.group(0)

    # The six digit tiles are the only >digit< patterns in the template.
    html = re.sub(r">\d<", _swap, html)
    if purpose == "signup":
        html = html.replace("Your login code", "Your signup code")
        html = html.replace("finish logging in", "finish signing up")
        html = html.replace("Did not try to log in?", "Did not try to sign up?")
    html = html.replace('src="logo.png"', 'src="cid:drishti-logo"')
    return html


def otp_subject(purpose: str) -> str:
    return "Your Drishti signup code" if purpose == "signup" else "Your Drishti login code"


def _otp_text(name: str, code: str, purpose: str) -> str:
    first = (name or "").strip().split(" ")[0] or "there"
    verb = "signing up" if purpose == "signup" else "logging in"
    return (
        f"Hi {first}, here is your code to finish {verb}.\n"
        f"Code: {code}\n"
        "It is valid for 10 minutes and works only once.\n"
        "Did not try to log in? Ignore this email. Your account stays safe.\n"
    )


def send_otp(email: str, name: str, code: str, purpose: str) -> str:
    """Send one OTP email in the locked format. Returns 'SENT' or 'LOGGED'."""
    subject = otp_subject(purpose)
    text = _otp_text(name, code, purpose)
    html = render_otp_html(name, code, purpose)
    if smtp_configured():
        # Canonical structure for HTML mail with an embedded image:
        # related root -> alternative (text + HTML) + the logo as a CID part,
        # so the logo renders inside the message instead of as an attachment.
        msg = MIMEMultipart("related")
        msg["From"] = os.environ.get("SMTP_FROM") or os.environ["SMTP_USER"]
        msg["To"] = email
        msg["Subject"] = subject
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(text, "plain", "utf-8"))
        alt.attach(MIMEText(html, "html", "utf-8"))
        msg.attach(alt)
        if _LOGO.exists():
            img = MIMEImage(_LOGO.read_bytes(), "png")
            img.add_header("Content-ID", "<drishti-logo>")
            img.add_header("Content-Disposition", "inline", filename="logo.png")
            msg.attach(img)
        port = int(os.environ.get("SMTP_PORT", "587"))
        ctx = ssl.create_default_context()
        # Gmail shows App Passwords in spaced groups; the spaces are not
        # part of the password, so strip them before logging in.
        password = os.environ["SMTP_PASS"].replace(" ", "")
        try:
            with smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=20) as s:
                if os.environ.get("SMTP_TLS", "1") not in ("0", "false", "False"):
                    s.starttls(context=ctx)
                s.login(os.environ["SMTP_USER"], password)
                s.send_message(msg)
        except Exception as exc:
            _log_error(f"SMTP send to {email} failed: "
                       f"{type(exc).__name__}: {exc}")
            raise
        return "SENT"
    log = os.path.join(_var_dir(), "outbox.log")
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"\n---\nTO: {email}\nSUBJECT: {subject}\n{text}\n[HTML: format-3 template]\n")
    return "LOGGED"
