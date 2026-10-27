"""Human browser signature preimages and native task action assembly."""

from __future__ import annotations

import unittest

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.contracts import canonical_json
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.operator_authority import OperatorDenied, OperatorRoot
from employee_read_demo.task_write_authority import issue_task_write_authority
from employee_read_demo.task_write_proofs import (
    prepare_effect_plan_confirmation, prepare_exact_confirmation,
    prepare_recovered_child_confirmation,
    prepare_task_approval, task_commitment,
)


class TaskWriteProofTests(unittest.TestCase):
    def test_paired_task_recovery_requires_distinct_human_tool_grant(self) -> None:
        human_key = Ed25519PrivateKey.generate()
        public = human_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        identity = create_raw_key_ed25519_identity(public).to_bytes()
        human, _ = authority_for_identity_packet(identity)
        binding = EmployeeBinding(
            "atlas-studio", "person-jules", "https://accounts.google.com",
            "synthetic-subject", human, "synthetic-binding",
        )
        root = OperatorRoot(bytes([0x21]) * 32)
        ordinary = issue_task_write_authority(
            root, binding, identity,
            provider_service="google-docs-delegation-demo",
            provider_tool="replace_project_a_marker_v2", now=1000, lifetime=600,
        )
        paired = issue_task_write_authority(
            root, binding, identity,
            provider_service="google-drive-delegation-demo",
            provider_tool="create_project_a_document_v1",
            companion_write_service="google-docs-delegation-demo",
            companion_write_tool="populate_created_project_a_document_v1",
            now=1000, lifetime=600,
        )
        recovery = {
            "schema": "auths.agent-recovered-child/1",
            "task_id": "task-1", "task_commitment": "a" * 64,
            "plan_commitment": "b" * 64, "create_operation_id": "create-1",
            "candidate_id": "doc-1", "parent_id": "folder-1",
            "title": "Project A handoff", "marker": "ap071_" + "c" * 32,
            "content_commitment": "d" * 64,
            "attestation_commitment": "e" * 64,
            "expires_at": 1200,
        }
        with self.assertRaises(OperatorDenied):
            prepare_recovered_child_confirmation(ordinary, recovery, now=1100)
        prepared = prepare_recovered_child_confirmation(
            paired, recovery, now=1100,
        )
        signed = prepared.complete(
            human_key.sign(prepared.signing_preimage), now=1101,
        )
        self.assertGreater(len(signed.proof), 0)
        self.assertGreater(len(signed.action), 0)

    def test_browser_signature_yields_exact_task_and_confirmation_proofs(self) -> None:
        human_key = Ed25519PrivateKey.generate()
        public = human_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        identity = create_raw_key_ed25519_identity(public).to_bytes()
        human, _ = authority_for_identity_packet(identity)
        binding = EmployeeBinding(
            "atlas-studio", "person-jules", "https://accounts.google.com",
            "synthetic-subject", human, "synthetic-binding",
        )
        authority = issue_task_write_authority(
            OperatorRoot(bytes([0x21]) * 32), binding, identity,
            provider_service="google-docs-delegation-demo",
            provider_tool="replace_project_a_marker_v2", now=1000, lifetime=600,
        )
        card = {
            "schema": "auths.agent-task/3", "task_id": "task-1",
            "company_id": "atlas-studio", "initiator_principal": human, "approver_principal": human,
            "agent_principal": "agent-principal", "agent_key_fingerprint": "a" * 64,
            "connection_id": "jules-google", "connection_generation": 1,
            "connection_subject": "jules-subject", "read_scopes": [],
            "write_scopes": [{"handle": "working-doc", "recipe_digest": "b" * 64,
                              "verb": "edit", "connection_id": "jules-google",
                              "connection_generation": 1,
                              "connection_subject": "jules-subject"}],
            "delivery_channel": "agent-channel", "not_before": 1000,
            "expires_at": 1300, "max_provider_calls": 0,
            "max_releases": 0, "max_release_bytes": 0, "max_writes": 1,
            "write_approval_mode": "exact", "operator_policy_digest": "c" * 64,
            "purpose": "Edit the Project A working document",
        }
        prepared = prepare_task_approval(authority, card, now=1100)
        self.assertEqual(prepared.challenge, authority.challenge)
        signed = prepared.complete(human_key.sign(prepared.signing_preimage), now=1101)
        self.assertGreater(len(signed.proof), 0)
        self.assertGreater(len(signed.action), 0)
        commitment = task_commitment(card)
        self.assertEqual(commitment, bytes(_native.commit_canonical_v1(
            "auths.agent-task.v3",
            _native.canonicalize_mcp_arguments_json(canonical_json(card)),
        )).hex())
        intent = {
            "task_id": "task-1", "task_commitment": commitment,
            "operation_id": "write-1", "action_commitment": "d" * 64,
            "request_commitment": "e" * 64, "recipe_digest": "b" * 64,
            "resource_handle": "working-doc", "verb": "edit",
            "connection_id": "jules-google", "connection_generation": 1,
            "connection_subject": "jules-subject",
        }
        confirm = prepare_exact_confirmation(authority, intent, now=1110)
        confirmed = confirm.complete(human_key.sign(confirm.signing_preimage), now=1111)
        self.assertGreater(len(confirmed.proof), 0)
        self.assertGreater(len(confirmed.action), 0)
        effect_plan = {
            "schema": "auths.agent-effect-plan/1",
            "task_id": "task-1",
            "task_commitment": commitment,
            "create": {**intent, "operation_id": "create-1", "verb": "create"},
            "populate_recipe_digest": "f" * 64,
            "populate_operation_id": "populate-1",
            "initial_text": "Project A handoff draft",
            "expires_at": 1200,
        }
        prepared_plan = prepare_effect_plan_confirmation(
            authority, effect_plan, now=1110,
        )
        signed_plan = prepared_plan.complete(
            human_key.sign(prepared_plan.signing_preimage), now=1111,
        )
        self.assertGreater(len(signed_plan.proof), 0)
        self.assertGreater(len(signed_plan.action), 0)
        with self.assertRaises(OperatorDenied):
            prepare_effect_plan_confirmation(
                authority, {**effect_plan, "initial_text": "x" * 193}, now=1110,
            )
        with self.assertRaises(Exception):
            confirm.complete(bytes(64), now=1111)
        with self.assertRaises(OperatorDenied):
            prepared.complete(human_key.sign(prepared.signing_preimage), now=1401)


if __name__ == "__main__":
    unittest.main()
