"""Activate a signed task only after a native company-rooted agent proof."""

from __future__ import annotations

import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .admission import AdmissionStore
from .authority import native_body_digest, verify_read
from .authority_identity import authority_for_identity_packet
from .contracts import TaskDescriptor, canonical_json
from .enrollment import EmployeeBinding
from .task_approval import TaskApprovalStore
from .token_store import TokenVault


class ActivationDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ActivationChallenge:
    task_id: str
    challenge: bytes
    agent_principal: str
    signing_preimage: bytes
    call: dict
    expires_at: int


class TaskActivationStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        TaskApprovalStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS task_activation_challenges (
                challenge BLOB PRIMARY KEY, task_id TEXT NOT NULL,
                employee_binding TEXT NOT NULL, call_index INTEGER NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'issued'
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _prepared(task: TaskDescriptor, child_grant: bytes, call_index: int,
                  challenge: bytes, issued_at: int):
        from auths import _native

        calls = task.calls()
        if not 0 <= call_index < len(calls):
            raise ActivationDenied("activation call is outside task")
        command = calls[call_index]
        arguments = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(command)))
        call = _native.mcp_call(task.service, "google_drive_document_read", arguments)
        prepared = _native.prepare_mcp_call_action(
            call, _native.Principal(task.agent_principal),
            _native.parse_signed("grant", child_grant), challenge, issued_at, 30,
        )
        signing = _native.prepare_signing(
            prepared.unsigned, "raw-key-v1", task.agent_principal, "ed25519-v1",
        )
        return command, prepared, signing

    def begin(self, task_id: str, employee: EmployeeBinding, vault: TokenVault,
              call_index: int, *, now: int | None = None) -> ActivationChallenge:
        now = int(time.time()) if now is None else now
        task, package = TaskApprovalStore(self.path).pending(task_id, employee, vault, now=now)
        challenge = secrets.token_bytes(32)
        command, _, signing = self._prepared(
            task, package.signed_child_grant, call_index, challenge, now,
        )
        expires = min(now + 30, task.expires_at)
        with self._connect() as db:
            db.execute("""INSERT INTO task_activation_challenges
                (challenge,task_id,employee_binding,call_index,issued_at,expires_at)
                VALUES(?,?,?,?,?,?)""", (
                    challenge, task_id, employee.binding_ref, call_index, now, expires,
                ))
        return ActivationChallenge(task_id, challenge, task.agent_principal,
                                   bytes(signing.signing_preimage), asdict(command), expires)

    def complete(self, task_id: str, employee: EmployeeBinding, vault: TokenVault,
                 challenge: bytes, signature: bytes, trusted_template: bytes,
                 expected_root: str, *, now: int | None = None) -> TaskDescriptor:
        from auths import _native

        now = int(time.time()) if now is None else now
        if len(challenge) != 32 or len(signature) != 64:
            raise ActivationDenied("agent activation proof is outside bounds")
        task, package = TaskApprovalStore(self.path).pending(task_id, employee, vault, now=now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT call_index,issued_at,expires_at,status
                FROM task_activation_challenges WHERE challenge=? AND task_id=?
                AND employee_binding=?""", (
                    challenge, task_id, employee.binding_ref,
                )).fetchone()
            if row is None or row[3] != "issued" or now >= row[2]:
                raise ActivationDenied("activation challenge is unavailable")
            db.execute("""UPDATE task_activation_challenges SET status='used'
                WHERE challenge=?""", (challenge,))
            db.commit()
        if package.signed_employee_grant == package.signed_child_grant:
            raise ActivationDenied("grant chain is invalid")
        with self._connect() as db:
            agent_row = db.execute("""SELECT identity_packet FROM registered_agents
                WHERE company=? AND employee_binding=? AND agent_principal=?
                AND status='active'""", (
                    employee.company_id, employee.binding_ref, task.agent_principal,
                )).fetchone()
            authority_row = db.execute("""SELECT root_principal FROM employee_authorities
                WHERE employee_binding=? AND status='active'""", (
                    employee.binding_ref,
                )).fetchone()
        if agent_row is None or authority_row != (expected_root,):
            raise ActivationDenied("agent or trusted root changed")
        agent_principal, agent_evidence = authority_for_identity_packet(agent_row[0])
        if agent_principal != task.agent_principal:
            raise ActivationDenied("agent key changed")
        command, prepared, signing = self._prepared(
            task, package.signed_child_grant, row[0], challenge, row[1],
        )
        try:
            signed_action = signing.complete(signature)
            evidence = lambda raw: ("raw-key-v1", "application/vnd.auths.raw-key.v1", raw)
            template = _native.parse_trusted_context(trusted_template)
            context = template.bind_request(f"mcp://{task.service}", challenge, row[1])
            proof, action, _ = _native.assemble_mcp_proof(
                prepared, signed_action,
                [_native.parse_signed("grant", package.signed_employee_grant),
                 _native.parse_signed("grant", package.signed_child_grant)],
                [[evidence(package.root_evidence)], [evidence(package.employee_evidence)]],
                [evidence(agent_evidence)], context,
            )
            verified = verify_read(
                proof=proof, action=action, trusted_template=trusted_template,
                challenge=challenge, evaluation_time=row[1], task=task,
            )
        except Exception as error:
            raise ActivationDenied("native activation proof was refused") from error
        if verified.command != command or native_body_digest(command, task.service) not in {
                native_body_digest(call, task.service) for call in task.calls()}:
            raise ActivationDenied("native proof did not bind approved call")
        AdmissionStore(self.path).enroll(task)
        with self._connect() as db:
            db.execute("""UPDATE task_proposals SET status='active'
                WHERE id=? AND status='approved_pending_activation'""", (task_id,))
        return task
