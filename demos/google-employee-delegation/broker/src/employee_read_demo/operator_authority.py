"""Operator-custodied company root and bounded employee grants."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .admission import AdmissionStore
from .authority_identity import authority_for_identity_packet
from .enrollment import EmployeeBinding


class OperatorDenied(PermissionError):
    pass


@dataclass(frozen=True)
class EmployeeAuthority:
    employee_binding_ref: str
    employee_principal: str
    root_principal: str
    signed_grant: bytes
    root_evidence: bytes
    employee_evidence: bytes
    not_before: int
    expires_at: int


def _sign(key: Ed25519PrivateKey, unsigned, principal: str) -> bytes:
    from auths import _native

    prepared = _native.prepare_signing(unsigned, "raw-key-v1", principal,
                                       "ed25519-v1")
    signed = prepared.complete(key.sign(bytes(prepared.signing_preimage)))
    return bytes(_native.inspect_signed(signed))


class OperatorRoot:
    """A private, operator-owned seed; never constructed from an HTTP request."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("operator root seed must contain 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        public = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        from auths import _native

        self.principal, self.evidence = _native.raw_key_ed25519_authority_v1(public)

    def issue_employee(self, *, binding: EmployeeBinding, identity_packet: bytes,
                       service: str, now: int | None = None,
                       lifetime: int = 3600) -> EmployeeAuthority:
        from auths import _native

        principal, employee_evidence = authority_for_identity_packet(identity_packet)
        if principal != binding.principal or not 60 <= lifetime <= 3600:
            raise OperatorDenied("employee enrollment or grant lifetime is invalid")
        now = int(time.time()) if now is None else now
        audience = f"mcp://{service}"
        request = _native.GrantRequest(
            _native.Principal(binding.principal), "auths.mcp", 2,
            [("tools/call", f"{audience}/tools/google_drive_document_read")],
            now, now + lifetime, [audience], None, None, 1, None,
            "raw-key-baseline", [],
        )
        unsigned = _native.root_grant(_native.Principal(self.principal), request)
        signed = _sign(self._key, unsigned, self.principal)
        return EmployeeAuthority(binding.binding_ref, binding.principal,
                                 self.principal, signed, bytes(self.evidence),
                                 employee_evidence, now, now + lifetime)


class EmployeeAuthorityStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS employee_authorities (
                employee_binding TEXT PRIMARY KEY, employee_principal TEXT NOT NULL,
                root_principal TEXT NOT NULL, signed_grant BLOB NOT NULL,
                root_evidence BLOB NOT NULL, employee_evidence BLOB NOT NULL,
                not_before INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def save(self, authority: EmployeeAuthority, binding: EmployeeBinding) -> None:
        if (authority.employee_binding_ref != binding.binding_ref
                or authority.employee_principal != binding.principal):
            raise OperatorDenied("employee authority is not bound to enrollment")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("""SELECT 1 FROM employee_bindings WHERE binding_ref=?
                AND principal=? AND status='active'""", (
                    binding.binding_ref, binding.principal,
                )).fetchone()
            if active is None:
                raise OperatorDenied("employee enrollment is inactive")
            db.execute("""INSERT INTO employee_authorities
                (employee_binding,employee_principal,root_principal,signed_grant,
                 root_evidence,employee_evidence,not_before,expires_at)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    authority.employee_binding_ref, authority.employee_principal,
                    authority.root_principal, authority.signed_grant,
                    authority.root_evidence, authority.employee_evidence,
                    authority.not_before, authority.expires_at,
                ))
            db.commit()

    def load(self, binding: EmployeeBinding, *, now: int | None = None) -> EmployeeAuthority:
        now = int(time.time()) if now is None else now
        with self._connect() as db:
            row = db.execute("""SELECT root_principal,signed_grant,root_evidence,
                employee_evidence,not_before,expires_at FROM employee_authorities
                WHERE employee_binding=? AND employee_principal=? AND status='active'""", (
                    binding.binding_ref, binding.principal,
                )).fetchone()
            active = db.execute("""SELECT 1 FROM employee_bindings WHERE binding_ref=?
                AND principal=? AND status='active'""", (
                    binding.binding_ref, binding.principal,
                )).fetchone()
        if row is None or active is None or not row[4] <= now < row[5]:
            raise OperatorDenied("employee authority is unavailable")
        return EmployeeAuthority(binding.binding_ref, binding.principal,
                                 row[0], row[1], row[2], row[3], row[4], row[5])
