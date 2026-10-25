from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.demo_co_contract import CompanyImport
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.task_proposals import TaskDenied, TaskProposalStore


class Vault:
    generation = 1
    def connection_generation(self, connection_id, employee):
        if connection_id != "connection-a" or employee.binding_ref != "binding-a":
            raise TaskDenied("connection unavailable")
        return self.generation


class Inspector:
    def __init__(self, expected):
        self.expected = expected
        self.calls = []
    def inspect_exact(self, command):
        self.calls.append(command.file_id)
        if command.file_id not in self.expected:
            raise TaskDenied("provider denied")


class TaskProposalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = TaskProposalStore(Path(self.temp.name) / "broker.sqlite3")
        self.now = int(time.time())
        self.employee = EmployeeBinding(
            "atlas-studio", "person-morgan", "https://accounts.google.com",
            "google-subject-a", "employee-principal", "binding-a",
        )
        self.agent = AgentBinding("atlas-studio", "binding-a", "agent-principal", "a" * 64)
        self.company = CompanyImport({
            "company_id": "atlas-studio", "instance_id": "live-01",
            "resources": [
                {"logical_resource_id": "doc-a", "provider_resource_id": "file-A",
                 "provider": "google_drive", "kind": "document", "status": "ready"},
                {"logical_resource_id": "doc-b", "provider_resource_id": "file-B",
                 "provider": "google_drive", "kind": "document", "status": "ready"},
            ],
        }, {}, "b" * 64, True, True)
        self.vault = Vault()

    def test_approved_catalog_and_employee_provider_check_precede_proposal(self) -> None:
        inspector = Inspector({"file-A", "file-B"})
        task = self.store.prepare(
            company=self.company, employee=self.employee, agent=self.agent,
            connection_id="connection-a", service="customer-drive-read",
            logical_resource_ids=("doc-b", "doc-a"),
            purpose="Summarize Project A", vault=self.vault,
            inspector_factory=lambda _: inspector, now=self.now,
        )
        self.assertEqual(task.file_ids, ("file-A", "file-B"))
        self.assertEqual(task.service, "customer-drive-read")
        self.assertEqual(inspector.calls, ["file-A", "file-B"])
        self.assertEqual(self.store.get(task.task_id, self.employee, now=self.now), task)
        snapshot = self.store.describe(task.task_id, self.employee, now=self.now)
        self.assertEqual(snapshot["status"], "prepared")
        self.assertEqual(snapshot["usage"]["remaining_calls"], task.max_calls)
        self.assertEqual(snapshot["approved_calls"][0]["file_id"], "file-A")
        outsider = EmployeeBinding("atlas-studio", "person-other", self.employee.issuer,
                                   "google-subject-b", "other-principal", "binding-b")
        with self.assertRaises(TaskDenied):
            self.store.describe(task.task_id, outsider, now=self.now)
        with self.assertRaises(TaskDenied):
            self.store.get(task.task_id, self.employee, now=task.expires_at)

    def test_outside_catalog_and_provider_denial_do_not_create_proposal(self) -> None:
        inspector = Inspector({"file-A"})
        with self.assertRaises(TaskDenied):
            self.store.prepare(
                company=self.company, employee=self.employee, agent=self.agent,
                connection_id="connection-a", service="customer-drive-read",
                logical_resource_ids=("doc-unknown",),
                purpose="Summarize Project A", vault=self.vault,
                inspector_factory=lambda _: inspector, now=self.now,
            )
        self.assertEqual(inspector.calls, [])
        with self.assertRaises(TaskDenied):
            self.store.prepare(
                company=self.company, employee=self.employee, agent=self.agent,
                connection_id="connection-a", service="customer-drive-read",
                logical_resource_ids=("doc-b",),
                purpose="Summarize Project A", vault=self.vault,
                inspector_factory=lambda _: inspector, now=self.now,
            )
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM task_proposals").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
