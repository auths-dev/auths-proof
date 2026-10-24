"""Employee Google subject to Auths principal enrollment with key possession."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .admission import AdmissionStore
from .contracts import canonical_json, commitment
from .demo_co_contract import CompanyImport
from .google_oauth import OAuthResult


class EnrollmentDenied(PermissionError):
    pass


@dataclass(frozen=True)
class EmployeeBinding:
    company_id: str
    logical_person_id: str
    issuer: str
    subject: str
    principal: str
    binding_ref: str


@dataclass(frozen=True)
class VerifiedGoogleSubject:
    kind: str
    issuer: str
    subject: str


def _person(company: CompanyImport, identity: OAuthResult | VerifiedGoogleSubject) -> str:
    if not company.google_ready or not company.adoptable or identity.kind not in {"login", "connect"}:
        raise EnrollmentDenied("Google employee enrollment is unavailable")
    matching = [p for p in company.bundle["people"] if p["provider"] == "google"
                and p["status"] == "ready" and p.get("issuer") == identity.issuer
                and p.get("provider_subject") == identity.subject]
    if len(matching) != 1:
        raise EnrollmentDenied("Google subject is not one active company member")
    return matching[0]["logical_person_id"]


class EnrollmentStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        AdmissionStore(path)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS enrollment_challenges (
                  nonce TEXT PRIMARY KEY, company TEXT NOT NULL, person TEXT NOT NULL,
                  issuer TEXT NOT NULL, subject TEXT NOT NULL, packet_digest TEXT NOT NULL,
                  bundle_digest TEXT NOT NULL,
                  expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS employee_bindings (
                  binding_ref TEXT PRIMARY KEY, company TEXT NOT NULL, person TEXT NOT NULL,
                  issuer TEXT NOT NULL, subject TEXT NOT NULL, principal TEXT NOT NULL,
                  identity_packet BLOB NOT NULL, bundle_digest TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'active',
                  UNIQUE(company,issuer,subject), UNIQUE(company,principal)
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def prepare(self, company: CompanyImport, identity: OAuthResult | VerifiedGoogleSubject,
                identity_packet: bytes, *, now: int | None = None) -> tuple[str, bytes]:
        person = _person(company, identity)
        if not 1 <= len(identity_packet) <= 4096:
            raise ValueError("identity packet is outside bounds")
        now = int(time.time()) if now is None else now
        nonce = secrets.token_urlsafe(32)
        digest = hashlib.sha256(identity_packet).hexdigest()
        expires = now + 300
        message = canonical_json({
            "contract": "auths.employee-enrollment/v1",
            "company_id": company.bundle["company_id"],
            "logical_person_id": person,
            "issuer": identity.issuer,
            "subject": identity.subject,
            "identity_packet_sha256": digest,
            "nonce": nonce,
            "expires_at": expires,
        })
        with self._connect() as db:
            db.execute("""INSERT INTO enrollment_challenges
                (nonce,company,person,issuer,subject,packet_digest,bundle_digest,expires)
                VALUES(?,?,?,?,?,?,?,?)""",
                (nonce, company.bundle["company_id"], person, identity.issuer,
                 identity.subject, digest, company.bundle_sha256, expires))
        return nonce, message

    async def complete(self, company: CompanyImport, identity: OAuthResult | VerifiedGoogleSubject,
                       nonce: str, identity_packet: bytes, signature: bytes,
                       *, now: int | None = None) -> EmployeeBinding:
        person = _person(company, identity)
        now = int(time.time()) if now is None else now
        if not 1 <= len(identity_packet) <= 4096 or not 1 <= len(signature) <= 256:
            raise EnrollmentDenied("identity proof is outside bounds")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT company,person,issuer,subject,packet_digest,bundle_digest,expires,used
                FROM enrollment_challenges WHERE nonce=?""", (nonce,)).fetchone()
            if (row is None or row[:6] != (
                company.bundle["company_id"], person, identity.issuer, identity.subject,
                hashlib.sha256(identity_packet).hexdigest(), company.bundle_sha256,
            ) or row[7] != 0 or now >= row[6]):
                raise EnrollmentDenied("enrollment challenge is unavailable")
            db.execute("UPDATE enrollment_challenges SET used=1 WHERE nonce=?", (nonce,))
            db.commit()
        message = canonical_json({
            "contract": "auths.employee-enrollment/v1",
            "company_id": company.bundle["company_id"],
            "logical_person_id": person,
            "issuer": identity.issuer,
            "subject": identity.subject,
            "identity_packet_sha256": row[4],
            "nonce": nonce,
            "expires_at": row[6],
        })
        from auths.identity import IdentityOk, authenticate_message
        result = await authenticate_message(identity_packet, message=message, signature=signature)
        if not isinstance(result, IdentityOk):
            raise EnrollmentDenied("Auths key possession could not be verified")
        if int(time.time()) >= row[6]:
            raise EnrollmentDenied("enrollment challenge expired")
        from .authority_identity import authority_for_identity_packet
        principal, _ = authority_for_identity_packet(identity_packet)
        binding_ref = commitment("auths.employee-binding/v1", {
            "company_id": company.bundle["company_id"], "person": person,
            "issuer": identity.issuer, "subject": identity.subject,
            "principal": principal, "identity_packet_sha256": row[4],
            "bundle_sha256": company.bundle_sha256,
        })
        with self._connect() as db:
            try:
                db.execute("""INSERT INTO employee_bindings
                    (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                    VALUES(?,?,?,?,?,?,?,?)""", (
                        binding_ref, company.bundle["company_id"], person,
                        identity.issuer, identity.subject, principal, identity_packet,
                        company.bundle_sha256,
                    ))
            except sqlite3.IntegrityError as error:
                raise EnrollmentDenied("employee is already enrolled or key is assigned") from error
        return EmployeeBinding(company.bundle["company_id"], person, identity.issuer,
                               identity.subject, principal, binding_ref)

    def lookup(self, company: CompanyImport, identity: VerifiedGoogleSubject) -> EmployeeBinding:
        person = _person(company, identity)
        with self._connect() as db:
            row = db.execute("""SELECT principal,binding_ref FROM employee_bindings
                WHERE company=? AND person=? AND issuer=? AND subject=?
                AND bundle_digest=? AND status='active'""", (
                    company.bundle["company_id"], person, identity.issuer,
                    identity.subject, company.bundle_sha256,
                )).fetchone()
        if row is None:
            raise EnrollmentDenied("employee is not enrolled for this company generation")
        return EmployeeBinding(company.bundle["company_id"], person,
                               identity.issuer, identity.subject, row[0], row[1])
