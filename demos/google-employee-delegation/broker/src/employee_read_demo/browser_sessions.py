"""Server-held localhost browser sessions and CSRF tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .admission import AdmissionStore


class SessionDenied(PermissionError):
    pass


@dataclass(frozen=True)
class BrowserSession:
    cookie: str
    csrf: str
    issuer: str | None
    subject: str | None
    expires_at: int


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class BrowserSessionStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS browser_sessions (
                token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL,
                issuer TEXT, subject TEXT, expires_at INTEGER NOT NULL
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def create(self, *, now: int | None = None) -> BrowserSession:
        now = int(time.time()) if now is None else now
        cookie = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        expires_at = now + 3600
        with self._connect() as db:
            db.execute("""INSERT INTO browser_sessions(token_hash,csrf,expires_at)
                VALUES(?,?,?)""", (_digest(cookie), csrf, expires_at))
        return BrowserSession(cookie, csrf, None, None, expires_at)

    def get(self, cookie: str, *, now: int | None = None) -> BrowserSession:
        now = int(time.time()) if now is None else now
        if not isinstance(cookie, str) or not 32 <= len(cookie) <= 128 or not cookie.isascii():
            raise SessionDenied("browser session is unavailable")
        with self._connect() as db:
            row = db.execute("""SELECT csrf,issuer,subject,expires_at FROM browser_sessions
                WHERE token_hash=?""", (_digest(cookie),)).fetchone()
        if row is None or now >= row[3]:
            raise SessionDenied("browser session is unavailable")
        return BrowserSession(cookie, row[0], row[1], row[2], row[3])

    def check_csrf(self, session: BrowserSession, token: str) -> None:
        if not isinstance(token, str) or not hmac.compare_digest(session.csrf, token):
            raise SessionDenied("CSRF token is unavailable")

    def login(self, session: BrowserSession, *, issuer: str, subject: str,
              now: int | None = None) -> BrowserSession:
        """Rotate the cookie and CSRF token when Google login succeeds."""
        now = int(time.time()) if now is None else now
        if not issuer or not subject:
            raise SessionDenied("Google identity is unavailable")
        next_cookie = secrets.token_urlsafe(32)
        next_csrf = secrets.token_urlsafe(32)
        expires_at = now + 3600
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT expires_at FROM browser_sessions WHERE token_hash=?",
                             (_digest(session.cookie),)).fetchone()
            if row is None or now >= row[0]:
                raise SessionDenied("browser session is unavailable")
            db.execute("DELETE FROM browser_sessions WHERE token_hash=?", (_digest(session.cookie),))
            db.execute("""INSERT INTO browser_sessions
                (token_hash,csrf,issuer,subject,expires_at) VALUES(?,?,?,?,?)""",
                (_digest(next_cookie), next_csrf, issuer, subject, expires_at))
            db.commit()
        return BrowserSession(next_cookie, next_csrf, issuer, subject, expires_at)

    def logout(self, session: BrowserSession) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM browser_sessions WHERE token_hash=?",
                       (_digest(session.cookie),))
