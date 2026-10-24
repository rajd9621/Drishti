"""Email + password + OTP accounts for Drishti.

Flow, for both login and signup:
  1. The user enters email and password on the login page (plus their name
     when signing up). The password is checked (login) or kept hashed with
     the pending signup, and a 6-digit code is emailed in the locked
     format-3 design.
  2. On the OTP screen the user enters the code. It is valid for 10 minutes
     and allows 3 attempts. Verifying it signs the user in (creating the
     account on first signup) and returns a session token.
  3. A new code can be resent 3 minutes after the previous one was sent,
     or right away once the old code is used up or expired.

Codes and passwords are stored hashed (PBKDF2 for passwords), sessions are
bearer tokens stored hashed, all in one SQLite file (var/drishti.db).
"""
from __future__ import annotations

import hashlib
import logging
import hmac
import os
import re
import secrets
import sqlite3
import time

from . import mailer
from .config import VAR_DIR

OTP_TTL_SECONDS = 600          # 10 minutes
OTP_MAX_ATTEMPTS = 3
RESEND_AFTER_SECONDS = 180     # resend a code after 3 minutes
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _db_path() -> str:
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    return str(VAR_DIR / "drishti.db")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS otps(
            email TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            name TEXT,
            password_hash TEXT,
            purpose TEXT NOT NULL DEFAULT 'login',
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            sent_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    # older databases (from the OTP-only version) gain the new columns
    for table, col, decl in (("users", "password_hash", "TEXT NOT NULL DEFAULT ''"),
                             ("otps", "password_hash", "TEXT"),
                             ("otps", "purpose", "TEXT NOT NULL DEFAULT 'login'")):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    return conn


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pw_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), 120_000).hex()
    return f"{salt}${dk}"


def _pw_ok(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    salt, _, dk = stored.partition("$")
    try:
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                   bytes.fromhex(salt), 120_000).hex()
    except ValueError:
        return False
    return hmac.compare_digest(calc, dk)


def _issue_code(conn, email: str, name: str | None, pw_hash: str | None,
                purpose: str, now: int) -> str:
    code = f"{secrets.randbelow(1000000):06d}"
    conn.execute(
        "INSERT OR REPLACE INTO otps(email, code_hash, name, password_hash,"
        " purpose, expires_at, attempts, sent_at) VALUES(?, ?, ?, ?, ?, ?, 0, ?)",
        (email, _hash(email + ":" + code), name, pw_hash, purpose,
         now + OTP_TTL_SECONDS, now))
    return code


def _send(email: str, name: str, code: str, purpose: str) -> tuple[bool, str]:
    """Returns (ok, how) where how is 'SENT' or 'LOGGED'.

    Mailer also writes a local diagnostic, and this logger makes the failure
    visible in Render's service logs (the local filesystem may be ephemeral).
    Never log the OTP, password, or SMTP credentials.
    """
    try:
        return True, mailer.send_otp(email, name, code, purpose)
    except Exception as exc:
        logging.exception("Drishti OTP email delivery failed (%s)", type(exc).__name__)
        return False, ""


def request_otp(email: str, password: str, name: str | None,
                mode: str) -> tuple[bool, str, dict]:
    """Step 1: check email + password, then email a fresh code.

    If a code is already on its way for this same login/signup, the user is
    sent straight to the OTP screen for it instead of being locked out.
    If the mail itself fails to send, no trace is kept, so they can retry
    at once. The third return value carries UI hints (already, resend_after).
    """
    email = (email or "").strip().lower()
    name = (name or "").strip()
    if not _EMAIL_RE.match(email):
        return False, "Please enter a valid email address.", {}
    if len(password or "") < 6:
        return False, "Password needs at least 6 characters.", {}
    if mode not in ("login", "signup"):
        mode = "login"
    now = int(time.time())
    with _db() as conn:
        user = conn.execute("SELECT id, name, password_hash FROM users"
                            " WHERE email = ?", (email,)).fetchone()
        if mode == "login":
            if user is None:
                return False, "No account with this email. Create one first.", {}
            if not _pw_ok(password, user["password_hash"]):
                return False, "Email or password is not right.", {}
            display, pw_hash = user["name"], None
        else:
            if user is not None:
                return False, "This email already has an account. Log in instead.", {}
            if len(name) < 2:
                return False, "Please enter your name.", {}
            display, pw_hash = name, _pw_hash(password)
        prev = conn.execute("SELECT * FROM otps WHERE email = ?", (email,)).fetchone()
        if prev and now <= prev["expires_at"] and prev["attempts"] < OTP_MAX_ATTEMPTS \
                and prev["purpose"] == mode \
                and (mode == "login" or _pw_ok(password, prev["password_hash"] or "")):
            remaining = max(0, RESEND_AFTER_SECONDS - (now - prev["sent_at"]))
            return True, (f"A code was already sent to {email}. Enter it here. "
                          f"It is valid for 10 minutes."), \
                {"already": True, "resend_after": remaining}
        code = _issue_code(conn, email, display, pw_hash, mode, now)
    ok, how = _send(email, display, code, mode)
    if not ok:
        with _db() as conn:
            conn.execute("DELETE FROM otps WHERE email = ?", (email,))
        return False, "Could not send the email right now. Please try again.", {}
    if how == "LOGGED":
        return True, ("Email is not configured on this server, so no email "
                      "went out. For testing, the code is saved in "
                      "var/outbox.log."), {"already": False,
                                           "resend_after": RESEND_AFTER_SECONDS}
    return True, f"A code was sent to {email}. It is valid for 10 minutes.", \
        {"already": False, "resend_after": RESEND_AFTER_SECONDS}


def resend_otp(email: str) -> tuple[bool, str]:
    """Send a fresh code for an in-progress login/signup, once the 3-minute
    wait is over (or the old code is used up / expired)."""
    email = (email or "").strip().lower()
    now = int(time.time())
    with _db() as conn:
        row = conn.execute("SELECT * FROM otps WHERE email = ?", (email,)).fetchone()
        if row is None:
            return False, "No sign-in is in progress for this email. Start again."
        if now - row["sent_at"] < RESEND_AFTER_SECONDS \
                and row["attempts"] < OTP_MAX_ATTEMPTS and now <= row["expires_at"]:
            wait = RESEND_AFTER_SECONDS - (now - row["sent_at"])
            return False, f"You can resend the code after {wait // 60}:{wait % 60:02d}."
        code = _issue_code(conn, email, row["name"], row["password_hash"],
                           row["purpose"], now)
        display, purpose = row["name"] or "", row["purpose"]
    ok, how = _send(email, display, code, purpose)
    if not ok:
        return False, "Could not send the email right now. Please try again."
    if how == "LOGGED":
        return True, ("Email is not configured on this server, so no email "
                      "went out. The new code is saved in var/outbox.log.")
    return True, f"A new code was sent to {email}. It is valid for 10 minutes."


def verify_otp(email: str, code: str) -> tuple[bool, str, dict | None, str | None]:
    """Step 2: check the code (3 attempts). On success returns
    (True, msg, user, raw_token) and creates the account for signups."""
    email = (email or "").strip().lower()
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return False, "Enter the 6-digit code from your email.", None, None
    now = int(time.time())
    with _db() as conn:
        row = conn.execute("SELECT * FROM otps WHERE email = ?", (email,)).fetchone()
        if row is None:
            return False, "No code was requested for this email. Ask for a new code.", None, None
        if row["attempts"] >= OTP_MAX_ATTEMPTS:
            return False, "Too many wrong tries. Resend a new code.", None, None
        if now > row["expires_at"]:
            return False, "This code has expired. Resend a new code.", None, None
        if _hash(email + ":" + code) != row["code_hash"]:
            conn.execute("UPDATE otps SET attempts = attempts + 1 WHERE email = ?",
                         (email,))
            left = OTP_MAX_ATTEMPTS - row["attempts"] - 1
            if left <= 0:
                return False, "Too many wrong tries. Resend a new code.", None, None
            return False, f"That code is not right. {left} {'try' if left == 1 else 'tries'} left.", None, None
        conn.execute("DELETE FROM otps WHERE email = ?", (email,))
        user = conn.execute("SELECT id, name, email FROM users WHERE email = ?",
                            (email,)).fetchone()
        if user is None:
            if row["purpose"] != "signup":
                return False, "No account with this email. Create one first.", None, None
            display = row["name"] or email.split("@")[0]
            cur = conn.execute(
                "INSERT INTO users(name, email, password_hash, created_at)"
                " VALUES(?, ?, ?, ?)",
                (display, email, row["password_hash"] or "", now))
            user = {"id": cur.lastrowid, "name": display, "email": email}
        else:
            user = {"id": user["id"], "name": user["name"], "email": user["email"]}
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO tokens(token_hash, user_id, created_at) VALUES(?, ?, ?)",
            (_hash(token), user["id"], now))
    return True, "Signed in.", {"who": user["name"], "email": user["email"]}, token


def user_for_token(token: str | None) -> dict | None:
    if not token:
        return None
    with _db() as conn:
        row = conn.execute(
            "SELECT u.name, u.email FROM tokens t JOIN users u ON u.id = t.user_id"
            " WHERE t.token_hash = ?", (_hash(token),)).fetchone()
    if row is None:
        return None
    return {"who": row["name"], "email": row["email"]}


def logout(token: str | None) -> None:
    if not token:
        return
    with _db() as conn:
        conn.execute("DELETE FROM tokens WHERE token_hash = ?", (_hash(token),))
