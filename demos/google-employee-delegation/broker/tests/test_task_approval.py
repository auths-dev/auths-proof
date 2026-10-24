from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.agent_registry import AgentBinding, AgentRegistry
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.demo_co_contract import CompanyImport
from employee_read_demo.enrollment import EmployeeBinding, EnrollmentStore
from employee_read_demo.google_oauth import CONNECT_SCOPES, OAuthResult
from employee_read_demo.operator_authority import EmployeeAuthorityStore, OperatorRoot
from employee_read_demo.task_approval import ApprovalDenied, TaskApprovalStore
from employee_read_demo.task_proposals import TaskProposalStore
from employee_read_demo.token_store import TokenVault


class _Inspector:
    def inspect_exact(self, command) -> None:
        assert command.file_id == "file-A"


class TaskApprovalTests(unittest.TestCase):
    def test_employee_signs_reviewed_child_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sqlite3"
            now = int(time.time())
            EnrollmentStore(path)
            employee_key = Ed25519PrivateKey.generate()
            employee_identity = create_raw_key_ed25519_identity(
                employee_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            principal, _ = authority_for_identity_packet(employee_identity.to_bytes())
            employee = EmployeeBinding("atlas-studio", "person-morgan",
                                       "https://accounts.google.com", "subject-a",
                                       principal, "binding-a")
            agent_key = Ed25519PrivateKey.generate()
            agent_identity = create_raw_key_ed25519_identity(
                agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            agent_principal, _ = authority_for_identity_packet(agent_identity.to_bytes())
            agent = AgentBinding(employee.company_id, employee.binding_ref,
                                 agent_principal, "unused-digest")
            with EnrollmentStore(path)._connect() as db:
                db.execute("""INSERT INTO employee_bindings
                    (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                    VALUES(?,?,?,?,?,?,?,?)""", (
                        employee.binding_ref, employee.company_id, employee.logical_person_id,
                        employee.issuer, employee.subject, employee.principal,
                        employee_identity.to_bytes(), "a" * 64,
                    ))
            with AgentRegistry(path)._connect() as db:
                db.execute("""INSERT INTO registered_agents
                    (company,employee_binding,agent_principal,identity_packet,packet_digest)
                    VALUES(?,?,?,?,?)""", (
                        agent.company_id, agent.employee_binding_ref,
                        agent.agent_principal, agent_identity.to_bytes(),
                        agent.identity_packet_sha256,
                    ))
            vault = TokenVault(path, encryption_key=Fernet.generate_key(), client_id="client-a")
            connection_id = vault.link(
                company=employee.company_id, employee_principal=employee.principal,
                binding_ref=employee.binding_ref,
                identity=OAuthResult("connect", employee.issuer, employee.subject, None,
                                     CONNECT_SCOPES, "access-token", "refresh-token", 3600),
                now=now,
            )
            root = OperatorRoot(b"\x35" * 32)
            parent = root.issue_employee(binding=employee,
                                         identity_packet=employee_identity.to_bytes(),
                                         service="atlas-drive", now=now - 1)
            EmployeeAuthorityStore(path).save(parent, employee)
            company = CompanyImport({
                "company_id": employee.company_id, "instance_id": "live-01",
                "resources": [{"logical_resource_id": "doc-a", "provider_resource_id": "file-A",
                               "provider": "google_drive", "kind": "document", "status": "ready"}],
            }, {}, "a" * 64, True, True)
            task = TaskProposalStore(path).prepare(
                company=company, employee=employee, agent=agent,
                connection_id=connection_id, logical_resource_ids=("doc-a",),
                purpose="Summarize Project A", vault=vault,
                inspector_factory=lambda _: _Inspector(), now=now,
            )
            approvals = TaskApprovalStore(path)
            pending = approvals.prepare(task.task_id, employee, vault, now=now)
            self.assertEqual(pending.task_commitment, task.digest)
            with self.assertRaises(ApprovalDenied):
                approvals.complete(task.task_id, employee, b"\0" * 64, vault, now=now)
            signed = approvals.complete(task.task_id, employee,
                                        employee_key.sign(pending.signing_preimage),
                                        vault, now=now)
            self.assertEqual(signed.signed_employee_grant, parent.signed_grant)
            self.assertEqual(bytes(_native.inspect_signed(
                _native.parse_signed("grant", signed.signed_child_grant))),
                signed.signed_child_grant)
            with self.assertRaises(ApprovalDenied):
                approvals.complete(task.task_id, employee,
                                   employee_key.sign(pending.signing_preimage),
                                   vault, now=now)


if __name__ == "__main__":
    unittest.main()
