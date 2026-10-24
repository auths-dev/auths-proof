"""Encrypted employee token custody bound to admission connection metadata."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .admission import AdmissionDenied, AdmissionStore
from .contracts import TaskDescriptor
from .google_oauth import CONNECT_SCOPES, OAuthResult


@dataclass(frozen=True)
class TokenLease:
    access_token: str
    expires_at: int


class TokenVault:
    def __init__(self, path: Path, *, encryption_key: bytes, client_id: str) -> None:
        self.path = path
        self.fernet = Fernet(encryption_key)
        self.client_id = client_id
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS credentials (
                connection TEXT PRIMARY KEY, ciphertext BLOB NOT NULL,
                client_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL,
                scopes TEXT NOT NULL, expires_at INTEGER NOT NULL,
                FOREIGN KEY(connection) REFERENCES connections(id)
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def link(self, *, company: str, employee_principal: str, binding_ref: str,
             identity: OAuthResult, now: int | None = None) -> str:
        if identity.kind != "connect" or not CONNECT_SCOPES.issubset(identity.scopes):
            raise AdmissionDenied("Drive consent is incomplete")
        if not all((company, employee_principal, binding_ref, identity.subject)):
            raise ValueError("connection binding is incomplete")
        now = int(time.time()) if now is None else now
        connection_id = secrets.token_urlsafe(32)
        ciphertext = self.fernet.encrypt(json.dumps({
            "access_token": identity.access_token,
            "refresh_token": identity.refresh_token,
        }, separators=(",", ":")).encode("utf-8"))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO connections(id,company,employee,binding_ref,generation) VALUES(?,?,?,?,1)",
                       (connection_id, company, employee_principal, binding_ref))
            db.execute("""INSERT INTO credentials
                (connection,ciphertext,client_id,issuer,subject,scopes,expires_at)
                VALUES(?,?,?,?,?,?,?)""", (
                    connection_id, ciphertext, self.client_id, identity.issuer, identity.subject,
                    " ".join(sorted(identity.scopes)), now + identity.expires_in,
                ))
            db.commit()
        return connection_id

    def lease(self, task: TaskDescriptor, *, now: int | None = None) -> TokenLease:
        now = int(time.time()) if now is None else now
        with self._connect() as db:
            row = db.execute("""SELECT c.company,c.employee,c.binding_ref,c.generation,c.status,
                t.ciphertext,t.client_id,t.issuer,t.subject,t.scopes,t.expires_at
                FROM connections c JOIN credentials t ON t.connection=c.id WHERE c.id=?""",
                (task.connection_id,)).fetchone()
        if row is None or row[:5] != (
            task.company_id, task.employee_principal, task.identity_binding_ref,
            task.connection_generation, "active",
        ) or row[6] != self.client_id or row[7] not in {"accounts.google.com", "https://accounts.google.com"}:
            raise AdmissionDenied("employee credential is unavailable")
        if not CONNECT_SCOPES.issubset(set(row[9].split())) or now + 30 >= row[10]:
            raise AdmissionDenied("employee consent expired or incomplete")
        try:
            token = json.loads(self.fernet.decrypt(row[5]))
        except (InvalidToken, ValueError, UnicodeDecodeError) as error:
            raise AdmissionDenied("employee credential cannot be decrypted") from error
        access = token.get("access_token")
        if not isinstance(access, str) or not access:
            raise AdmissionDenied("employee access token is unavailable")
        return TokenLease(access, row[10])

    def disconnect(self, connection_id: str) -> int:
        # Admission closes release before token deletion. A crash in between
        # leaves ciphertext inaccessible to the lease path.
        generation = AdmissionStore(self.path).disconnect(connection_id)
        with self._connect() as db:
            db.execute("DELETE FROM credentials WHERE connection=?", (connection_id,))
        return generation
