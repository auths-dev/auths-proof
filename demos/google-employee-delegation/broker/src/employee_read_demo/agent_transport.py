"""Proof-only agent transport over the closed document-read operation."""

from __future__ import annotations

import hmac
import base64
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .admission import AdmissionStore
from .agent_registry import AgentRegistry
from .authority import native_body_digest
from .authority_identity import authority_for_identity_packet
from .contracts import TaskDescriptor, canonical_json
from .enrollment import EmployeeBinding
from .google_drive import GoogleDriveReader
from .read_executor import GoogleReadPort, ReadOutcome, execute_read
from .receipts import ReceiptStore
from .task_approval import SignedTaskGrant, TaskApprovalStore
from .token_store import TokenVault


class AgentTransportDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ReadChallenge:
    task_id: str
    challenge: bytes
    issued_at: int
    expires_at: int


class AgentTransport:
    def __init__(self, path: Path, *, vault: TokenVault,
                 trusted_template: bytes, expected_root: str,
                 receipts: ReceiptStore,
                 provider_factory: Callable[[TaskDescriptor, TokenVault], GoogleReadPort] = GoogleDriveReader) -> None:
        self.path = path
        self.vault = vault
        self.trusted_template = trusted_template
        self.expected_root = expected_root
        self.receipts = receipts
        self.provider_factory = provider_factory
        TaskApprovalStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS agent_read_preparations (
                challenge BLOB PRIMARY KEY, task_id TEXT NOT NULL,
                call_index INTEGER NOT NULL, issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'issued'
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _package(self, task_id: str, *, now: int | None = None) -> tuple[TaskDescriptor, SignedTaskGrant, EmployeeBinding, bytes]:
        with self._connect() as db:
            row = db.execute("""SELECT b.company,b.person,b.issuer,b.subject,b.principal,
                b.binding_ref,a.identity_packet FROM task_proposals p
                JOIN employee_bindings b ON b.binding_ref=p.employee_binding
                JOIN registered_agents a ON a.company=b.company
                  AND a.employee_binding=b.binding_ref AND a.agent_principal=p.agent_principal
                WHERE p.id=? AND p.status='active' AND b.status='active'
                  AND a.status='active'""", (task_id,)).fetchone()
        if row is None:
            raise AgentTransportDenied("task is unavailable")
        employee = EmployeeBinding(*row[:6])
        task, package = TaskApprovalStore(self.path).active(task_id, employee, self.vault, now=now)
        if package.signed_employee_grant == package.signed_child_grant:
            raise AgentTransportDenied("grant chain is invalid")
        agent_principal, agent_evidence = authority_for_identity_packet(row[6])
        if agent_principal != task.agent_principal:
            raise AgentTransportDenied("agent identity changed")
        with self._connect() as db:
            root = db.execute("""SELECT root_principal FROM employee_authorities
                WHERE employee_binding=? AND status='active'""", (
                    employee.binding_ref,
                )).fetchone()
        if root != (self.expected_root,):
            raise AgentTransportDenied("trusted root changed")
        return task, package, employee, agent_evidence

    def export_package(self, task_id: str, employee: EmployeeBinding) -> dict:
        task, package, owner, agent_evidence = self._package(task_id)
        if owner != employee:
            raise AgentTransportDenied("task belongs to another employee")
        encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
        return {
            "contract": "auths.google-read-agent-package/v1",
            "task": asdict(task),
            "task_commitment": task.digest,
            "calls": [asdict(call) for call in task.calls()],
            "signed_employee_grant": encode(package.signed_employee_grant),
            "signed_child_grant": encode(package.signed_child_grant),
            "root_evidence": encode(package.root_evidence),
            "employee_evidence": encode(package.employee_evidence),
            "agent_evidence": encode(agent_evidence),
            "trusted_template": encode(self.trusted_template),
            "root_principal": self.expected_root,
        }

    def issue_challenge(self, task_id: str, body_digest: bytes,
                        *, now: int | None = None) -> ReadChallenge:
        now = int(time.time()) if now is None else now
        if len(body_digest) != 32:
            raise AgentTransportDenied("body digest is invalid")
        task, _, _, _ = self._package(task_id, now=now)
        matches = [index for index, call in enumerate(task.calls())
                   if native_body_digest(call, task.service) == body_digest]
        if len(matches) != 1:
            raise AgentTransportDenied("body is outside task")
        challenge = AdmissionStore(self.path).issue_challenge(task, body_digest, now=now)
        expires = min(now + 30, task.expires_at)
        with self._connect() as db:
            db.execute("""INSERT INTO agent_read_preparations
                (challenge,task_id,call_index,issued_at,expires_at)
                VALUES(?,?,?,?,?)""", (challenge, task_id, matches[0], now, expires))
        return ReadChallenge(task_id, challenge, now, expires)

    def execute(self, task_id: str, challenge: bytes, proof: bytes, action: bytes,
                *, now: int | None = None) -> ReadOutcome:
        from auths import _native

        now = int(time.time()) if now is None else now
        if (len(challenge) != 32 or not 1 <= len(proof) <= 262_144
                or not 1 <= len(action) <= 262_144):
            raise AgentTransportDenied("agent proof is outside bounds")
        task, package, _, agent_evidence = self._package(task_id, now=now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT call_index,issued_at,expires_at,status
                FROM agent_read_preparations WHERE challenge=? AND task_id=?""", (
                    challenge, task_id,
                )).fetchone()
            if row is None or row[3] != "issued" or now >= row[2]:
                raise AgentTransportDenied("read challenge is unavailable")
            db.execute("""UPDATE agent_read_preparations SET status='used'
                WHERE challenge=? AND status='issued'""", (challenge,))
            db.commit()
        command = task.calls()[row[0]]
        try:
            args = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(command)))
            call = _native.mcp_call(task.service, "google_drive_document_read", args)
            child = _native.parse_signed("grant", package.signed_child_grant)
            prepared = _native.prepare_mcp_call_action(
                call, _native.Principal(task.agent_principal), child,
                challenge, row[1], 30,
            )
            signed_action = _native.parse_signed(
                "action", _native.mcp_signed_action_from_proof(proof),
            )
            evidence = lambda raw: ("raw-key-v1", "application/vnd.auths.raw-key.v1", raw)
            template = _native.parse_trusted_context(self.trusted_template)
            context = template.bind_request(f"mcp://{task.service}", challenge, row[1])
            expected_proof, expected_action, _ = _native.assemble_mcp_proof(
                prepared, signed_action,
                [_native.parse_signed("grant", package.signed_employee_grant), child],
                [[evidence(package.root_evidence)], [evidence(package.employee_evidence)]],
                [evidence(agent_evidence)], context,
            )
            if (not hmac.compare_digest(proof, expected_proof)
                    or not hmac.compare_digest(action, expected_action)):
                raise AgentTransportDenied("proof does not match enrolled task chain")
        except AgentTransportDenied:
            raise
        except Exception as error:
            raise AgentTransportDenied("agent proof is invalid") from error
        return execute_read(
            task=task, challenge=challenge, proof=proof, action=action,
            trusted_template=self.trusted_template,
            store=AdmissionStore(self.path),
            provider=self.provider_factory(task, self.vault), receipts=self.receipts,
        )
