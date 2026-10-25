from __future__ import annotations

import time
import unittest
import tempfile
from dataclasses import asdict, replace
from pathlib import Path

from auths import _native
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import native_body_digest
from employee_read_demo.contracts import canonical_json
from employee_read_demo.read_executor import execute_read
from employee_read_demo.receipts import ReceiptStore, SignedReadReceipt, verify_receipt
from employee_read_demo.task_authority import plan_agent_grant
from test_admission import task


class TaskAuthorityTests(unittest.TestCase):
    def test_native_child_plan_commits_all_approved_read_bodies(self) -> None:
        now = int(time.time())
        root_key = _native.DevelopmentEd25519Key.generate()
        employee_key = _native.DevelopmentEd25519Key.generate()
        agent_key = _native.DevelopmentEd25519Key.generate()
        baseline = task(now)
        descriptor = type(baseline)(**{**baseline.__dict__,
                                       "employee_principal": employee_key.principal,
                                       "agent_principal": agent_key.principal})
        root = _native.Principal(root_key.principal)
        employee = _native.Principal(descriptor.employee_principal)
        audience = f"mcp://{descriptor.service}"
        resource = f"{audience}/tools/google_drive_document_read"
        request = _native.GrantRequest(
            employee, "auths.mcp", 2, [("tools/call", resource)],
            descriptor.not_before - 1, descriptor.expires_at + 1,
            [audience], None, None, 1, None, "raw-key-baseline", [],
        )
        unsigned = _native.root_grant(root, request)
        signing = _native.prepare_signing(
            unsigned, root_key.principal_method,
            root_key.verification_method, root_key.suite,
        )
        parent = signing.complete(root_key.sign(signing.signing_preimage))
        plan = plan_agent_grant(descriptor, _native.inspect_signed(parent),
                                assurance_floor="raw-key-baseline")
        self.assertTrue(plan.diff.action_narrowed)
        self.assertEqual(plan.diff.delegation_depth, (1, 0))

    def test_real_chain_and_exact_action_pass_read_boundary(self) -> None:
        now = int(time.time())
        root_key = _native.DevelopmentEd25519Key.generate()
        employee_key = _native.DevelopmentEd25519Key.generate()
        agent_key = _native.DevelopmentEd25519Key.generate()
        baseline = task(now)
        descriptor = type(baseline)(**{**baseline.__dict__,
                                       "employee_principal": employee_key.principal,
                                       "agent_principal": agent_key.principal})
        audience = f"mcp://{descriptor.service}"
        resource = f"{audience}/tools/google_drive_document_read"
        request = _native.GrantRequest(
            _native.Principal(employee_key.principal), "auths.mcp", 2,
            [("tools/call", resource)], now - 60, now + 600,
            [audience], None, None, 1, None, "raw-key-baseline", [],
        )
        def sign(key, unsigned):
            signing = _native.prepare_signing(
                unsigned, key.principal_method, key.verification_method, key.suite,
            )
            return signing.complete(key.sign(signing.signing_preimage))
        root_grant = sign(root_key, _native.root_grant(
            _native.Principal(root_key.principal), request,
        ))
        plan = plan_agent_grant(descriptor, _native.inspect_signed(root_grant),
                                assurance_floor="raw-key-baseline")
        child_grant = sign(employee_key, plan.unsigned)
        command = descriptor.calls()[0]
        arguments = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(command)))
        call = _native.mcp_call(descriptor.service, "google_drive_document_read", arguments)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = AdmissionStore(Path(directory.name) / "broker.sqlite3")
        store.register_connection(
            connection_id=descriptor.connection_id, company=descriptor.company_id,
            employee=descriptor.employee_principal,
            binding_ref=descriptor.identity_binding_ref, generation=1,
        )
        store.enroll(descriptor)
        challenge = store.issue_challenge(descriptor, native_body_digest(command), now=now)
        prepared = _native.prepare_mcp_call_action(
            call, _native.Principal(agent_key.principal), child_grant, challenge, now, 30,
        )
        action = sign(agent_key, prepared.unsigned)
        assurance = _native.AssurancePolicy("raw-key-baseline", [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ])
        anchor = _native.TrustAnchor(
            root_key.principal, _native.Principal(root_key.principal),
            [root_key.principal_method], [("auths.mcp", 2)],
            [("tools/call", resource)], [audience], [audience],
            now - 60, now + 600, None, 2, "raw-key-baseline", None,
        )
        template = _native.compile_trusted_context(
            _native.self_contained_configuration(), None, 1, 1, 1,
            [anchor], assurance, None, None, "none-v1",
            [root_key.evidence_type], [],
        )
        context = template.bind_request(audience, challenge, now)
        def evidence(key):
            return (key.evidence_type, key.media_type, key.evidence)
        proof, canonical_action, _ = _native.assemble_mcp_proof(
            prepared, action, [root_grant, child_grant],
            [[evidence(root_key)], [evidence(employee_key)]],
            [evidence(agent_key)], context,
        )
        class Provider:
            calls = 0
            def read_exact(self, requested):
                self.calls += 1
                assert requested == command
                return b"approved text"
        provider = Provider()
        receipts = ReceiptStore(Path(directory.name) / "broker.sqlite3", Ed25519PrivateKey.generate())
        outside = replace(command, file_id="file-C")
        outside_arguments = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(outside)))
        outside_call = _native.mcp_call(descriptor.service, "google_drive_document_read",
                                        outside_arguments)
        outside_prepared = _native.prepare_mcp_call_action(
            outside_call, _native.Principal(agent_key.principal), child_grant,
            challenge, now, 30,
        )
        outside_action = sign(agent_key, outside_prepared.unsigned)
        outside_proof, outside_canonical_action, _ = _native.assemble_mcp_proof(
            outside_prepared, outside_action, [root_grant, child_grant],
            [[evidence(root_key)], [evidence(employee_key)]],
            [evidence(agent_key)], context,
        )
        with self.assertRaises(PermissionError):
            execute_read(
                task=descriptor, challenge=challenge, proof=outside_proof,
                action=outside_canonical_action,
                trusted_template=_native.inspect_trusted_context(template),
                store=store, provider=provider, receipts=receipts,
            )
        self.assertEqual(provider.calls, 0)
        outcome = execute_read(
            task=descriptor, challenge=challenge, proof=proof, action=canonical_action,
            trusted_template=_native.inspect_trusted_context(template), store=store,
            provider=provider, receipts=receipts,
        )
        self.assertEqual(outcome.content, b"approved text")
        self.assertEqual(provider.calls, 1)
        receipt = receipts.load(outcome.receipt_id)
        self.assertIsNotNone(receipt)
        self.assertTrue(verify_receipt(receipt, receipts.public_key))
        self.assertEqual(receipt.payload["release_stage"], "committed")
        self.assertNotIn(b"approved text", receipt.json_bytes())
        altered = SignedReadReceipt({**receipt.payload, "released_bytes": 1}, receipt.signature)
        self.assertFalse(verify_receipt(altered, receipts.public_key))
        with self.assertRaises(AdmissionDenied):
            execute_read(
                task=descriptor, challenge=challenge, proof=proof, action=canonical_action,
                trusted_template=_native.inspect_trusted_context(template), store=store,
                provider=provider,
            )
        self.assertEqual(provider.calls, 1)


if __name__ == "__main__":
    unittest.main()
