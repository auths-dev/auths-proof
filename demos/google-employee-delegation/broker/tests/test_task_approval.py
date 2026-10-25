from __future__ import annotations

import tempfile
import time
import unittest
import json
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
from employee_read_demo.operator_cli import _template
from employee_read_demo.task_activation import ActivationDenied, TaskActivationStore
from employee_read_demo.task_approval import ApprovalDenied, TaskApprovalStore
from employee_read_demo.task_proposals import TaskProposalStore
from employee_read_demo.token_store import TokenVault
from employee_read_demo.agent_transport import AgentTransport, AgentTransportDenied
from employee_read_demo.authority import native_body_digest
from employee_read_demo.contracts import canonical_json
from employee_read_demo.receipts import ReceiptStore, verify_receipt


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
                connection_id=connection_id, service="atlas-drive",
                logical_resource_ids=("doc-a",),
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
            activations = TaskActivationStore(path)
            challenge = activations.begin(task.task_id, employee, vault, 0, now=now)
            self.assertEqual(challenge.agent_principal, agent_principal)
            with self.assertRaises(ActivationDenied):
                activations.complete(task.task_id, employee, vault,
                                     challenge.challenge, b"\0" * 64,
                                     _template(root, "atlas-drive", now - 60, now + 86400),
                                     root.principal, now=now)
            challenge = activations.begin(task.task_id, employee, vault, 0, now=now)
            active = activations.complete(
                task.task_id, employee, vault, challenge.challenge,
                agent_key.sign(challenge.signing_preimage),
                _template(root, "atlas-drive", now - 60, now + 86400),
                root.principal, now=now,
            )
            self.assertEqual(active, task)
            with self.assertRaises(ApprovalDenied):
                activations.begin(task.task_id, employee, vault, 0, now=now)
            class Provider:
                calls = 0

                def read_exact(self, command):
                    self.calls += 1
                    self.asserted = command
                    return b"Project A approved text"

            provider = Provider()
            template = _template(root, "atlas-drive", now - 60, now + 86400)
            receipts = ReceiptStore(path, Ed25519PrivateKey.generate())
            transport = AgentTransport(
                path, vault=vault, trusted_template=template,
                expected_root=root.principal, receipts=receipts,
                provider_factory=lambda _task, _vault: provider,
            )
            exported = transport.export_package(task.task_id, employee)
            self.assertEqual(exported["task_commitment"], task.digest)
            self.assertNotIn("access-token", json.dumps(exported))
            ticket = transport.issue_challenge(
                task.task_id, native_body_digest(task.calls()[0], task.service), now=now,
            )
            command = task.calls()[0]
            arguments = _native.canonicalize_mcp_arguments_json(canonical_json(command.__dict__))
            call = _native.mcp_call(task.service, "google_drive_document_read", arguments)
            child = _native.parse_signed("grant", signed.signed_child_grant)
            prepared = _native.prepare_mcp_call_action(
                call, _native.Principal(task.agent_principal), child,
                ticket.challenge, ticket.issued_at, 30,
            )
            signer = _native.prepare_signing(
                prepared.unsigned, "raw-key-v1", task.agent_principal, "ed25519-v1",
            )
            signed_action = signer.complete(agent_key.sign(bytes(signer.signing_preimage)))
            context = _native.parse_trusted_context(template).bind_request(
                f"mcp://{task.service}", ticket.challenge, ticket.issued_at,
            )
            evidence = lambda raw: ("raw-key-v1", "application/vnd.auths.raw-key.v1", raw)
            proof, action, _ = _native.assemble_mcp_proof(
                prepared, signed_action,
                [_native.parse_signed("grant", signed.signed_employee_grant), child],
                [[evidence(signed.root_evidence)], [evidence(signed.employee_evidence)]],
                [evidence(authority_for_identity_packet(agent_identity.to_bytes())[1])],
                context,
            )
            self.assertEqual(_native.mcp_signed_action_from_proof(proof),
                             _native.inspect_signed(signed_action))
            outcome = transport.execute(task.task_id, ticket.challenge, proof, action, now=now)
            self.assertEqual(outcome.content, b"Project A approved text")
            self.assertEqual(provider.calls, 1)
            self.assertIsNotNone(outcome.receipt_id)
            receipt = receipts.load(outcome.receipt_id)
            self.assertTrue(verify_receipt(receipt, receipts.public_key))
            with self.assertRaises(AgentTransportDenied):
                transport.execute(task.task_id, ticket.challenge, proof, action, now=now)
            self.assertEqual(provider.calls, 1)
            other = transport.issue_challenge(
                task.task_id, native_body_digest(task.calls()[0], task.service), now=now,
            )
            with self.assertRaises(AgentTransportDenied):
                transport.execute(task.task_id, other.challenge, proof, action, now=now)
            self.assertEqual(provider.calls, 1)

            from employee_read_agent.run import AgentKey, run_task

            class Broker:
                def challenge(self, task_id, body_digest):
                    ticket = transport.issue_challenge(task_id, body_digest)
                    return ticket.challenge, ticket.issued_at

                def call(self, task_id, challenge, proof, action):
                    result = transport.execute(task_id, challenge, proof, action)
                    return {"status": "release_committed", "content":
                            __import__("base64").urlsafe_b64encode(result.content).decode(),
                            "receipt_id": result.receipt_id}

            class Model:
                def select(self, purpose, file_ids):
                    self.asserted_purpose = purpose
                    return file_ids[:1]

                def summarize(self, purpose, sources):
                    assert sources == {"file-A": "Project A approved text"}
                    return "Project A approved text [file-A]"

            agent_seed = agent_key.private_bytes_raw()
            result = run_task(exported, AgentKey(agent_seed), Broker(), Model())
            self.assertEqual(result["summary"], "Project A approved text [file-A]")
            self.assertEqual(result["source_ids"], ["file-A"])
            self.assertEqual(provider.calls, 2)
            approvals.revoke(task.task_id, employee)
            with self.assertRaises((AgentTransportDenied, ApprovalDenied)):
                transport.issue_challenge(
                    task.task_id, native_body_digest(task.calls()[0], task.service), now=now,
                )


if __name__ == "__main__":
    unittest.main()
