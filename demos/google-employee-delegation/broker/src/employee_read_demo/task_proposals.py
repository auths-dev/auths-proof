"""Employee-reviewed finite task proposals, before any grant is accepted."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Protocol

from .admission import AdmissionStore
from .agent_registry import AgentBinding
from .contracts import TaskDescriptor, canonical_json
from .demo_co_contract import CompanyImport
from .enrollment import EmployeeBinding
from .token_store import TokenVault


class TaskDenied(PermissionError):
    pass


class MetadataInspector(Protocol):
    def inspect_exact(self, command) -> None: ...


class TaskProposalStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS task_proposals (
                id TEXT PRIMARY KEY, descriptor BLOB NOT NULL, digest TEXT NOT NULL,
                company TEXT NOT NULL, employee_binding TEXT NOT NULL,
                agent_principal TEXT NOT NULL, status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def prepare(self, *, company: CompanyImport, employee: EmployeeBinding,
                agent: AgentBinding, connection_id: str,
                logical_resource_ids: tuple[str, ...], purpose: str,
                vault: TokenVault,
                inspector_factory: Callable[[TaskDescriptor], MetadataInspector],
                now: int | None = None) -> TaskDescriptor:
        if not company.google_ready or not company.adoptable:
            raise TaskDenied("Google company is unavailable")
        if (employee.company_id != company.bundle["company_id"]
                or agent.company_id != employee.company_id
                or agent.employee_binding_ref != employee.binding_ref
                or agent.agent_principal == employee.principal):
            raise TaskDenied("employee or agent binding is unavailable")
        if (not 1 <= len(logical_resource_ids) <= 8
                or len(set(logical_resource_ids)) != len(logical_resource_ids)):
            raise TaskDenied("select one to eight distinct documents")
        catalog = {resource["logical_resource_id"]: resource["provider_resource_id"]
                   for resource in company.bundle["resources"]
                   if resource["provider"] == "google_drive"
                   and resource["kind"] == "document" and resource["status"] == "ready"}
        if any(value not in catalog or not catalog[value] for value in logical_resource_ids):
            raise TaskDenied("selected document is unavailable")
        now = int(time.time()) if now is None else now
        generation = vault.connection_generation(connection_id, employee)
        task = TaskDescriptor(
            "auths.google-read-task/v1", employee.company_id,
            company.bundle["instance_id"], company.bundle_sha256,
            employee.principal, employee.binding_ref, agent.agent_principal,
            "atlas-drive", connection_id, generation,
            tuple(sorted(catalog[value] for value in logical_resource_ids)),
            "text", 262_144, 16, 4 * 1024 * 1024,
            now, now + 900, secrets.token_urlsafe(24), purpose,
        )
        task.validate()
        inspector = inspector_factory(task)
        for call in task.calls():
            inspector.inspect_exact(call)
        if vault.connection_generation(connection_id, employee) != generation:
            raise TaskDenied("employee connection changed during preparation")
        with self._connect() as db:
            db.execute("""INSERT INTO task_proposals
                (id,descriptor,digest,company,employee_binding,
                 agent_principal,status,created_at) VALUES(?,?,?,?,?,?,?,?)""", (
                    task.task_id, canonical_json(asdict(task)), task.digest,
                    employee.company_id, employee.binding_ref,
                    agent.agent_principal, "prepared", now,
                ))
        return task

    def get(self, task_id: str, employee: EmployeeBinding,
            *, now: int | None = None) -> TaskDescriptor:
        now = int(time.time()) if now is None else now
        with self._connect() as db:
            row = db.execute("""SELECT descriptor,digest,status FROM task_proposals
                WHERE id=? AND company=? AND employee_binding=?""", (
                    task_id, employee.company_id, employee.binding_ref,
                )).fetchone()
        if row is None or row[2] != "prepared":
            raise TaskDenied("task proposal is unavailable")
        data = json.loads(row[0])
        data["file_ids"] = tuple(data["file_ids"])
        task = TaskDescriptor(**data)
        if task.digest != row[1] or now >= task.expires_at:
            raise TaskDenied("task proposal changed or expired")
        return task
