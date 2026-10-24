"""Employee signing of the exact reviewed child grant, pending native activation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .admission import AdmissionStore
from .agent_registry import AgentRegistry
from .authority_identity import authority_for_identity_packet
from .enrollment import EmployeeBinding
from .contracts import TaskDescriptor
from .operator_authority import EmployeeAuthorityStore
from .task_authority import plan_agent_grant
from .task_proposals import TaskDenied, TaskProposalStore
from .token_store import TokenVault


class ApprovalDenied(PermissionError):
    pass


@dataclass(frozen=True)
class PendingApproval:
    task_id: str
    task_commitment: str
    employee_principal: str
    agent_principal: str
    signing_preimage: bytes


@dataclass(frozen=True)
class SignedTaskGrant:
    task_id: str
    signed_child_grant: bytes
    signed_employee_grant: bytes
    root_evidence: bytes
    employee_evidence: bytes


class TaskApprovalStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        AdmissionStore(path)
        TaskProposalStore(path)
        EmployeeAuthorityStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS task_approvals (
                task_id TEXT PRIMARY KEY, employee_binding TEXT NOT NULL,
                task_digest TEXT NOT NULL, parent_digest TEXT NOT NULL,
                unsigned_grant BLOB NOT NULL, signing_preimage BLOB NOT NULL,
                signed_child BLOB, status TEXT NOT NULL,
                expires INTEGER NOT NULL
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _current(self, task_id: str, employee: EmployeeBinding,
                 vault: TokenVault, now: int):
        try:
            task = TaskProposalStore(self.path).get(task_id, employee, now=now)
            AgentRegistry(self.path).lookup(employee, task.agent_principal)
        except (TaskDenied, PermissionError) as error:
            raise ApprovalDenied("task proposal or agent is unavailable") from error
        if (task.employee_principal != employee.principal
                or task.identity_binding_ref != employee.binding_ref
                or vault.connection_generation(task.connection_id, employee)
                != task.connection_generation):
            raise ApprovalDenied("task binding or connection changed")
        parent = EmployeeAuthorityStore(self.path).load(employee, now=now)
        if parent.expires_at < task.expires_at:
            raise ApprovalDenied("employee grant expires before task")
        return task, parent

    def prepare(self, task_id: str, employee: EmployeeBinding,
                vault: TokenVault, *, now: int | None = None) -> PendingApproval:
        from auths import _native

        now = int(time.time()) if now is None else now
        task, parent = self._current(task_id, employee, vault, now)
        plan = plan_agent_grant(task, parent.signed_grant,
                                assurance_floor="raw-key-baseline")
        unsigned = bytes(_native.inspect_unsigned(plan.unsigned))
        signing = _native.prepare_signing(plan.unsigned, "raw-key-v1",
                                          employee.principal, "ed25519-v1")
        preimage = bytes(signing.signing_preimage)
        with self._connect() as db:
            db.execute("""INSERT INTO task_approvals
                (task_id,employee_binding,task_digest,parent_digest,
                 unsigned_grant,signing_preimage,status,expires)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    task.task_id, employee.binding_ref, task.digest,
                    hashlib.sha256(parent.signed_grant).hexdigest(),
                    unsigned, preimage, "prepared", task.expires_at,
                ))
        return PendingApproval(task.task_id, task.digest, employee.principal,
                               task.agent_principal, preimage)

    def complete(self, task_id: str, employee: EmployeeBinding,
                 signature: bytes, vault: TokenVault,
                 *, now: int | None = None) -> SignedTaskGrant:
        from auths import _native

        now = int(time.time()) if now is None else now
        if len(signature) != 64:
            raise ApprovalDenied("employee grant signature must be Ed25519")
        task, parent = self._current(task_id, employee, vault, now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT task_digest,parent_digest,unsigned_grant,
                signing_preimage,status,expires FROM task_approvals
                WHERE task_id=? AND employee_binding=?""", (
                    task_id, employee.binding_ref,
                )).fetchone()
            if (row is None or row[0] != task.digest
                    or row[1] != hashlib.sha256(parent.signed_grant).hexdigest()
                    or row[4] != "prepared" or now >= row[5]):
                raise ApprovalDenied("task signing request is unavailable")
            packet_row = db.execute("""SELECT identity_packet FROM employee_bindings
                WHERE binding_ref=? AND principal=? AND status='active'""", (
                    employee.binding_ref, employee.principal,
                )).fetchone()
            if packet_row is None:
                raise ApprovalDenied("employee enrollment is unavailable")
            principal, evidence = authority_for_identity_packet(packet_row[0])
            if principal != employee.principal or evidence != parent.employee_evidence:
                raise ApprovalDenied("employee key changed")
            projection = _native.decode_identity_descriptor_v1(packet_row[0])
            public_key = projection.relationships[0][3][0][1]
            try:
                _native.verify_ed25519_preimage_v1(public_key, row[3], signature)
            except Exception as error:
                raise ApprovalDenied("employee grant signature is invalid") from error
            unsigned = _native.parse_unsigned("grant", row[2])
            signing = _native.prepare_signing(unsigned, "raw-key-v1",
                                              employee.principal, "ed25519-v1")
            if bytes(signing.signing_preimage) != row[3]:
                raise ApprovalDenied("task signing request changed")
            signed = bytes(_native.inspect_signed(signing.complete(signature)))
            db.execute("""UPDATE task_approvals SET signed_child=?,status='signed'
                WHERE task_id=? AND status='prepared'""", (signed, task_id))
            db.execute("""UPDATE task_proposals SET status='approved_pending_activation'
                WHERE id=? AND status='prepared'""", (task_id,))
            db.commit()
        return SignedTaskGrant(task_id, signed, parent.signed_grant,
                               parent.root_evidence, parent.employee_evidence)

    def pending(self, task_id: str, employee: EmployeeBinding,
                vault: TokenVault, *, now: int | None = None) -> tuple[TaskDescriptor, SignedTaskGrant]:
        return self._package(task_id, employee, vault, "approved_pending_activation", now=now)

    def active(self, task_id: str, employee: EmployeeBinding,
               vault: TokenVault, *, now: int | None = None) -> tuple[TaskDescriptor, SignedTaskGrant]:
        return self._package(task_id, employee, vault, "active", now=now)

    def revoke(self, task_id: str, employee: EmployeeBinding) -> None:
        """Serialize employee revocation with the final content release gate."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT p.status FROM task_proposals p
                WHERE p.id=? AND p.company=? AND p.employee_binding=?""", (
                    task_id, employee.company_id, employee.binding_ref,
                )).fetchone()
            if row is None or row[0] not in {"active", "approved_pending_activation"}:
                raise ApprovalDenied("task is unavailable")
            db.execute("UPDATE tasks SET status='revoked', revision=revision+1 WHERE id=? AND status='active'", (task_id,))
            db.execute("UPDATE task_proposals SET status='revoked' WHERE id=?", (task_id,))
            db.commit()

    def _package(self, task_id: str, employee: EmployeeBinding,
                 vault: TokenVault, required_status: str,
                 *, now: int | None = None) -> tuple[TaskDescriptor, SignedTaskGrant]:
        now = int(time.time()) if now is None else now
        with self._connect() as db:
            task_row = db.execute("""SELECT descriptor,digest,status FROM task_proposals
                WHERE id=? AND company=? AND employee_binding=?""", (
                    task_id, employee.company_id, employee.binding_ref,
                )).fetchone()
            approval_row = db.execute("""SELECT task_digest,parent_digest,signed_child,status
                FROM task_approvals WHERE task_id=? AND employee_binding=?""", (
                    task_id, employee.binding_ref,
                )).fetchone()
            admission = db.execute("""SELECT digest,company,employee,agent,connection,
                generation,status FROM tasks WHERE id=?""", (task_id,)).fetchone()
        if (task_row is None or task_row[2] != required_status
                or approval_row is None or approval_row[3] != "signed"
                or not approval_row[2]):
            raise ApprovalDenied("signed task is unavailable")
        data = json.loads(task_row[0])
        data["file_ids"] = tuple(data["file_ids"])
        task = TaskDescriptor(**data)
        task.validate()
        if (task.digest != task_row[1] or task.digest != approval_row[0]
                or now >= task.expires_at
                or task.employee_principal != employee.principal
                or task.identity_binding_ref != employee.binding_ref):
            raise ApprovalDenied("signed task binding changed")
        if required_status == "active" and admission != (
                task.digest, task.company_id, task.employee_principal,
                task.agent_principal, task.connection_id,
                task.connection_generation, "active"):
            raise ApprovalDenied("task admission is unavailable")
        AgentRegistry(self.path).lookup(employee, task.agent_principal)
        if vault.connection_generation(task.connection_id, employee) != task.connection_generation:
            raise ApprovalDenied("employee connection changed")
        parent = EmployeeAuthorityStore(self.path).load(employee, now=now)
        if hashlib.sha256(parent.signed_grant).hexdigest() != approval_row[1]:
            raise ApprovalDenied("employee grant changed")
        package = SignedTaskGrant(task_id, approval_row[2], parent.signed_grant,
                                  parent.root_evidence, parent.employee_evidence)
        return task, package
