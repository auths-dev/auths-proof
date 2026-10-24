"""Google login and separate Drive consent with one-use PKCE state."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import requests
from google.auth.transport.requests import Request
from google.oauth2 import id_token

ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
LOGIN_SCOPES = frozenset({"openid", "email"})
CONNECT_SCOPES = LOGIN_SCOPES | {DRIVE_SCOPE}
AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


class OAuthRejected(PermissionError):
    pass


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    hosted_domain: str

    def validate(self) -> None:
        if not self.client_id or not self.client_secret or not self.hosted_domain:
            raise ValueError("Google OAuth configuration is incomplete")
        parsed = urlsplit(self.redirect_uri)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("redirect URI has an invalid port") from error
        loopback = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and port is not None
        external = parsed.scheme == "https" and parsed.hostname and port in {None, 443}
        if not (loopback or external) or parsed.username or parsed.password or not parsed.path.startswith("/"):
            raise ValueError("redirect URI must be registered loopback or HTTPS")
        if parsed.query or parsed.fragment:
            raise ValueError("redirect URI must be exact and parameter-free")


@dataclass(frozen=True)
class OAuthResult:
    kind: str
    issuer: str
    subject: str
    email: str | None
    scopes: frozenset[str]
    access_token: str
    refresh_token: str | None
    expires_in: int


class OAuthStateStore:
    def __init__(self, path: Path) -> None:
        from .admission import AdmissionStore
        self.path = path
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY, kind TEXT NOT NULL, nonce TEXT NOT NULL,
                verifier TEXT NOT NULL, expected_subject TEXT,
                expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def create(self, kind: str, expected_subject: str | None, now: int) -> tuple[str, str, str]:
        if kind not in {"login", "connect"} or (kind == "connect" and not expected_subject):
            raise ValueError("invalid OAuth lifecycle transition")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        with self._connect() as db:
            db.execute("INSERT INTO oauth_states(state,kind,nonce,verifier,expected_subject,expires) VALUES(?,?,?,?,?,?)",
                       (state, kind, nonce, verifier, expected_subject, now + 300))
        return state, nonce, verifier

    def consume(self, state: str, now: int) -> tuple[str, str, str, str | None]:
        if not state or len(state) > 128:
            raise OAuthRejected("OAuth state is invalid")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT kind,nonce,verifier,expected_subject,expires,used FROM oauth_states WHERE state=?",
                             (state,)).fetchone()
            if row is None or row[5] or now >= row[4]:
                raise OAuthRejected("OAuth state is unavailable")
            db.execute("UPDATE oauth_states SET used=1 WHERE state=?", (state,))
            db.commit()
            return row[0], row[1], row[2], row[3]


class GoogleOAuth:
    def __init__(self, config: GoogleOAuthConfig, states: OAuthStateStore) -> None:
        config.validate()
        self.config = config
        self.states = states

    def begin(self, kind: str, *, expected_subject: str | None = None) -> tuple[str, str]:
        state, nonce, verifier = self.states.create(kind, expected_subject, int(time.time()))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        scopes = LOGIN_SCOPES if kind == "login" else CONNECT_SCOPES
        parameters = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(sorted(scopes)),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "hd": self.config.hosted_domain,
        }
        if kind == "connect":
            parameters["access_type"] = "offline"
        return AUTHORIZE_URL + "?" + urlencode(parameters), state

    def complete(self, *, state: str, code: str, now: int | None = None) -> OAuthResult:
        now = int(time.time()) if now is None else now
        kind, nonce, verifier, expected_subject = self.states.consume(state, now)
        if not code or len(code) > 4096:
            raise OAuthRejected("authorization code is invalid")
        session = requests.Session()
        session.trust_env = False
        response = session.post(TOKEN_URL, data={
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        }, timeout=15, allow_redirects=False, stream=True)
        if response.status_code != 200:
            raise OAuthRejected("Google token exchange failed")
        raw = response.raw.read(32_769)
        if len(raw) > 32_768:
            raise OAuthRejected("Google token response exceeded limit")
        try:
            tokens = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise OAuthRejected("Google token response is invalid") from error
        token = tokens.get("id_token")
        if not isinstance(token, str) or len(token) > 16_384:
            raise OAuthRejected("Google ID token is missing")
        claims = id_token.verify_oauth2_token(token, Request(session=session), self.config.client_id)
        if (claims.get("iss") not in ISSUERS or claims.get("hd") != self.config.hosted_domain
                or claims.get("nonce") != nonce or claims.get("azp", self.config.client_id) != self.config.client_id):
            raise OAuthRejected("Google identity binding failed")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or (expected_subject is not None and subject != expected_subject):
            raise OAuthRejected("Google subject does not match enrollment")
        scopes = frozenset(tokens.get("scope", "").split())
        required = LOGIN_SCOPES if kind == "login" else CONNECT_SCOPES
        if not required.issubset(scopes):
            raise OAuthRejected("Google consent is incomplete")
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        expires_in = tokens.get("expires_in")
        if (not isinstance(access_token, str) or not access_token
                or (refresh_token is not None and not isinstance(refresh_token, str))
                or type(expires_in) is not int or not 1 <= expires_in <= 86_400):
            raise OAuthRejected("Google access token response is invalid")
        return OAuthResult(kind, claims["iss"], subject, claims.get("email"), scopes,
                           access_token, refresh_token, expires_in)
