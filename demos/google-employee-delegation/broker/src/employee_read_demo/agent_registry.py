"""Registration of a distinct agent principal with one-use key possession."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .contracts import canonical_json
from .enrollment import EmployeeBinding, EnrollmentStore


class AgentDenied(PermissionError):
    pass


@dataclass(frozen=True)
class AgentBinding:
    company_id: str
    employee_binding_ref: str
    agent_principal: str
    identity_packet_sha256: str


def _principal(packet: bytes) -> str:
    from .authority_identity import authority_for_identity_packet
    try:
        principal, _ = authority_for_identity_packet(packet)
    except ValueError as exc:
        raise AgentDenied("agent identity packet is invalid")
    return principal


class AgentRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        EnrollmentStore(path)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS agent_challenges (
                    nonce TEXT PRIMARY KEY, company TEXT NOT NULL,
                    employee_binding TEXT NOT NULL, employee_principal TEXT NOT NULL,
                    agent_principal TEXT NOT NULL, packet_digest TEXT NOT NULL,
                    expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS registered_agents (
                    company TEXT NOT NULL, employee_binding TEXT NOT NULL,
                    agent_principal TEXT NOT NULL, identity_packet BLOB NOT NULL,
                    packet_digest TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                    PRIMARY KEY(company,employee_binding,agent_principal)
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _employee_active(self, db: sqlite3.Connection, employee: EmployeeBinding) -> bool:
        return db.execute("""SELECT 1 FROM employee_bindings WHERE binding_ref=?
            AND company=? AND person=? AND issuer=? AND subject=? AND principal=?
            AND status='active'""", (
                employee.binding_ref, employee.company_id, employee.logical_person_id,
                employee.issuer, employee.subject, employee.principal,
            )).fetchone() is not None

    def prepare(self, employee: EmployeeBinding, identity_packet: bytes,
                *, now: int | None = None) -> tuple[str, bytes, str]:
        if not 1 <= len(identity_packet) <= 4096:
            raise AgentDenied("agent identity packet is outside bounds")
        principal = _principal(identity_packet)
        if principal == employee.principal:
            raise AgentDenied("agent must hold a distinct key")
        with self._connect() as db:
            if not self._employee_active(db, employee):
                raise AgentDenied("employee enrollment is unavailable")
        now = int(time.time()) if now is None else now
        nonce = secrets.token_urlsafe(32)
        packet_digest = hashlib.sha256(identity_packet).hexdigest()
        expires = now + 300
        message = canonical_json({
            "contract": "auths.agent-registration/v1",
            "company_id": employee.company_id,
            "employee_binding_ref": employee.binding_ref,
            "employee_principal": employee.principal,
            "agent_principal": principal,
            "identity_packet_sha256": packet_digest,
            "nonce": nonce,
            "expires_at": expires,
        })
        with self._connect() as db:
            db.execute("""INSERT INTO agent_challenges
                (nonce,company,employee_binding,employee_principal,
                 agent_principal,packet_digest,expires) VALUES(?,?,?,?,?,?,?)""", (
                    nonce, employee.company_id, employee.binding_ref,
                    employee.principal, principal, packet_digest, expires,
                ))
        return nonce, message, principal

    async def complete(self, employee: EmployeeBinding, nonce: str,
                       identity_packet: bytes, signature: bytes,
                       *, now: int | None = None) -> AgentBinding:
        now = int(time.time()) if now is None else now
        if not 1 <= len(identity_packet) <= 4096 or not 1 <= len(signature) <= 256:
            raise AgentDenied("agent proof is outside bounds")
        principal = _principal(identity_packet)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT company,employee_binding,employee_principal,
                agent_principal,packet_digest,expires,used FROM agent_challenges
                WHERE nonce=?""", (nonce,)).fetchone()
            if (row is None or row[:5] != (
                    employee.company_id, employee.binding_ref,
                    employee.principal, principal,
                    hashlib.sha256(identity_packet).hexdigest(),
                ) or now >= row[5] or row[6]):
                raise AgentDenied("agent registration challenge is unavailable")
            db.execute("UPDATE agent_challenges SET used=1 WHERE nonce=?", (nonce,))
            db.commit()
        message = canonical_json({
            "contract": "auths.agent-registration/v1",
            "company_id": employee.company_id,
            "employee_binding_ref": employee.binding_ref,
            "employee_principal": employee.principal,
            "agent_principal": principal,
            "identity_packet_sha256": row[4],
            "nonce": nonce,
            "expires_at": row[5],
        })
        from auths.identity import IdentityOk, authenticate_message
        verified = await authenticate_message(identity_packet, message=message, signature=signature)
        if not isinstance(verified, IdentityOk) or verified.value.identity.to_bytes() != identity_packet:
            raise AgentDenied("agent key possession could not be verified")
        if int(time.time()) >= row[5]:
            raise AgentDenied("agent registration challenge expired")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._employee_active(db, employee):
                raise AgentDenied("employee enrollment changed during registration")
            try:
                db.execute("""INSERT INTO registered_agents
                    (company,employee_binding,agent_principal,identity_packet,packet_digest)
                    VALUES(?,?,?,?,?)""", (
                        employee.company_id, employee.binding_ref, principal,
                        identity_packet, row[4],
                    ))
            except sqlite3.IntegrityError as error:
                raise AgentDenied("agent is already registered") from error
            db.commit()
        return AgentBinding(employee.company_id, employee.binding_ref, principal, row[4])

    def lookup(self, employee: EmployeeBinding, principal: str) -> AgentBinding:
        with self._connect() as db:
            if not self._employee_active(db, employee):
                raise AgentDenied("employee enrollment is unavailable")
            row = db.execute("""SELECT packet_digest FROM registered_agents
                WHERE company=? AND employee_binding=? AND agent_principal=?
                AND status='active'""", (
                    employee.company_id, employee.binding_ref, principal,
                )).fetchone()
        if row is None:
            raise AgentDenied("agent is not registered for this employee")
        return AgentBinding(employee.company_id, employee.binding_ref, principal, row[0])
