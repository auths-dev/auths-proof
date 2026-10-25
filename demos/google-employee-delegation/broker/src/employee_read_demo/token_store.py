"""Encrypted employee token custody bound to admission connection metadata."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
import requests

from .admission import AdmissionDenied, AdmissionStore
from .browser_sessions import BrowserSessionStore
from .contracts import TaskDescriptor
from .enrollment import EnrollmentStore
from .enrollment import EmployeeBinding
from .google_oauth import CONNECT_SCOPES, OAuthResult, TOKEN_URL, _bounded_json_response


@dataclass(frozen=True)
class TokenLease:
    access_token: str
    expires_at: int


def _exchange_refresh(client_id: str, client_secret: str, refresh_token: str) -> dict:
    session = requests.Session()
    session.trust_env = False
    try:
        with session.post(TOKEN_URL, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=15, allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise AdmissionDenied("Google refresh was refused")
            return _bounded_json_response(response, 32_768)
    except (requests.RequestException, ValueError, UnicodeDecodeError) as error:
        raise AdmissionDenied("Google refresh was unavailable") from error
    finally:
        session.close()


class TokenVault:
    def __init__(self, path: Path, *, encryption_key: bytes, client_id: str,
                 refresh_client_secret: str | None = None) -> None:
        self.path = path
        self.fernet = Fernet(encryption_key)
        self.client_id = client_id
        self.refresh_client_secret = refresh_client_secret
        EnrollmentStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS credentials (
                connection TEXT PRIMARY KEY, ciphertext BLOB NOT NULL,
                client_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL,
                scopes TEXT NOT NULL, expires_at INTEGER NOT NULL,
                refresh_nonce TEXT, refreshing_until INTEGER,
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
            binding = db.execute("""SELECT status FROM employee_bindings
                WHERE binding_ref=? AND company=? AND principal=? AND issuer=? AND subject=?""",
                (binding_ref, company, employee_principal, identity.issuer, identity.subject)).fetchone()
            if binding != ("active",):
                raise AdmissionDenied("Google subject is not bound to employee principal")
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
                FROM connections c JOIN credentials t ON t.connection=c.id
                JOIN employee_bindings b ON b.binding_ref=c.binding_ref
                WHERE c.id=? AND b.status='active' AND b.company=c.company
                AND b.principal=c.employee AND b.issuer=t.issuer AND b.subject=t.subject""",
                (task.connection_id,)).fetchone()
        if row is None or row[:5] != (
            task.company_id, task.employee_principal, task.identity_binding_ref,
            task.connection_generation, "active",
        ) or row[6] != self.client_id or row[7] not in {"accounts.google.com", "https://accounts.google.com"}:
            raise AdmissionDenied("employee credential is unavailable")
        if not CONNECT_SCOPES.issubset(set(row[9].split())):
            raise AdmissionDenied("employee consent is incomplete")
        if now + 30 >= row[10]:
            return self._refresh(task, now=now)
        try:
            token = json.loads(self.fernet.decrypt(row[5]))
        except (InvalidToken, ValueError, UnicodeDecodeError) as error:
            raise AdmissionDenied("employee credential cannot be decrypted") from error
        access = token.get("access_token")
        if not isinstance(access, str) or not access:
            raise AdmissionDenied("employee access token is unavailable")
        return TokenLease(access, row[10])

    def _refresh(self, task: TaskDescriptor, *, now: int) -> TokenLease:
        if not self.refresh_client_secret:
            raise AdmissionDenied("employee access token expired; refresh is not configured")
        nonce = secrets.token_urlsafe(24)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT c.company,c.employee,c.binding_ref,c.generation,c.status,
                t.ciphertext,t.client_id,t.issuer,t.subject,t.scopes,t.refresh_nonce,t.refreshing_until
                FROM connections c JOIN credentials t ON t.connection=c.id
                JOIN employee_bindings b ON b.binding_ref=c.binding_ref
                WHERE c.id=? AND b.status='active' AND b.company=c.company
                AND b.principal=c.employee AND b.issuer=t.issuer AND b.subject=t.subject""",
                (task.connection_id,)).fetchone()
            if (row is None or row[:5] != (
                    task.company_id, task.employee_principal, task.identity_binding_ref,
                    task.connection_generation, "active",
                ) or row[6] != self.client_id or not CONNECT_SCOPES.issubset(set(row[9].split()))
                    or (row[10] is not None and row[11] is not None and row[11] > now)):
                raise AdmissionDenied("employee refresh is unavailable")
            changed = db.execute("""UPDATE credentials SET refresh_nonce=?,refreshing_until=?
                WHERE connection=?""", (nonce, now + 30, task.connection_id)).rowcount
            if changed != 1:
                raise AdmissionDenied("employee refresh is unavailable")
            db.commit()
        try:
            token = json.loads(self.fernet.decrypt(row[5]))
            refresh_token = token.get("refresh_token")
            if not isinstance(refresh_token, str) or not refresh_token:
                raise AdmissionDenied("employee refresh token is unavailable")
            result = _exchange_refresh(self.client_id, self.refresh_client_secret, refresh_token)
            access = result.get("access_token")
            expires_in = result.get("expires_in")
            scopes = result.get("scope")
            if (not isinstance(access, str) or not access or type(expires_in) is not int
                    or not 1 <= expires_in <= 86_400 or (scopes is not None
                    and (not isinstance(scopes, str) or not CONNECT_SCOPES.issubset(set(scopes.split()))))):
                raise AdmissionDenied("Google refresh response is incomplete")
            rotated = result.get("refresh_token", refresh_token)
            if not isinstance(rotated, str) or not rotated:
                raise AdmissionDenied("Google refresh token is invalid")
            ciphertext = self.fernet.encrypt(json.dumps({
                "access_token": access, "refresh_token": rotated,
            }, separators=(",", ":")).encode("utf-8"))
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("""UPDATE credentials SET ciphertext=?,expires_at=?,
                    refresh_nonce=NULL,refreshing_until=NULL
                    WHERE connection=? AND refresh_nonce=? AND EXISTS (
                      SELECT 1 FROM connections WHERE id=? AND company=? AND employee=?
                      AND binding_ref=? AND generation=? AND status='active')
                    AND EXISTS (SELECT 1 FROM employee_bindings WHERE binding_ref=?
                      AND company=? AND principal=? AND issuer=? AND subject=? AND status='active')""", (
                        ciphertext, now + expires_in, task.connection_id, nonce,
                        task.connection_id, task.company_id, task.employee_principal,
                        task.identity_binding_ref, task.connection_generation,
                        task.identity_binding_ref, task.company_id, task.employee_principal,
                        row[7], row[8],
                    )).rowcount
                db.commit()
            if changed != 1:
                raise AdmissionDenied("connection changed during refresh")
            return TokenLease(access, now + expires_in)
        finally:
            with self._connect() as db:
                db.execute("""UPDATE credentials SET refresh_nonce=NULL,refreshing_until=NULL
                    WHERE connection=? AND refresh_nonce=?""", (task.connection_id, nonce))

    def disconnect(self, connection_id: str) -> int:
        # Admission closes release before token deletion. A crash in between
        # leaves ciphertext inaccessible to the lease path.
        generation = AdmissionStore(self.path).disconnect(connection_id)
        with self._connect() as db:
            db.execute("DELETE FROM credentials WHERE connection=?", (connection_id,))
        return generation

    def active_connection(self, connection_id: str, issuer: str, subject: str) -> bool:
        with self._connect() as db:
            row = db.execute("""SELECT 1 FROM connections c
                JOIN credentials t ON t.connection=c.id
                JOIN employee_bindings b ON b.binding_ref=c.binding_ref
                WHERE c.id=? AND c.status='active' AND b.status='active'
                AND c.company=b.company AND c.employee=b.principal
                AND t.issuer=? AND t.subject=? AND b.issuer=t.issuer
                AND b.subject=t.subject""", (connection_id, issuer, subject)).fetchone()
        return row is not None

    def connection_generation(self, connection_id: str,
                              employee: EmployeeBinding) -> int:
        with self._connect() as db:
            row = db.execute("""SELECT c.generation FROM connections c
                JOIN credentials t ON t.connection=c.id
                JOIN employee_bindings b ON b.binding_ref=c.binding_ref
                WHERE c.id=? AND c.status='active' AND b.status='active'
                AND c.company=? AND c.employee=? AND c.binding_ref=?
                AND b.company=c.company AND b.principal=c.employee
                AND t.issuer=? AND t.subject=? AND b.issuer=t.issuer
                AND b.subject=t.subject""", (
                    connection_id, employee.company_id, employee.principal,
                    employee.binding_ref, employee.issuer, employee.subject,
                )).fetchone()
        if row is None:
            raise AdmissionDenied("employee connection is unavailable")
        return row[0]

    def offboard(self, binding_ref: str, *, company: str | None = None) -> None:
        """Disable an employee and all their task/credential generations atomically."""
        BrowserSessionStore(self.path)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            binding = db.execute("""SELECT company,issuer,subject FROM employee_bindings
                WHERE binding_ref=? AND status='active'""", (binding_ref,)).fetchone()
            if binding is None or (company is not None and binding[0] != company):
                raise AdmissionDenied("employee binding is unavailable")
            db.execute("UPDATE employee_bindings SET status='disabled' WHERE binding_ref=?",
                       (binding_ref,))
            db.execute("""DELETE FROM browser_sessions
                WHERE company=? AND issuer=? AND subject=?""", binding)
            connections = [row[0] for row in db.execute(
                "SELECT id FROM connections WHERE binding_ref=?", (binding_ref,),
            )]
            for connection_id in connections:
                db.execute("""UPDATE connections SET generation=generation+1,status='disconnected'
                    WHERE id=? AND status='active'""", (connection_id,))
                db.execute("""UPDATE tasks SET status='revoked',revision=revision+1
                    WHERE connection=? AND status='active'""", (connection_id,))
                db.execute("DELETE FROM credentials WHERE connection=?", (connection_id,))
            db.commit()
