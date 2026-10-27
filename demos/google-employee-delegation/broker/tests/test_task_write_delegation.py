"""Jules-style browser completion of a child grant for a separate agent."""

from __future__ import annotations

import base64
import unittest

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.operator_authority import OperatorDenied, OperatorRoot
from employee_read_demo.task_write_authority import issue_task_write_authority
from employee_read_demo.task_write_delegation import prepare_agent_delegation


def _identity():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    packet = create_raw_key_ed25519_identity(public).to_bytes()
    principal, _ = authority_for_identity_packet(packet)
    return key, packet, principal


class TaskWriteDelegationTests(unittest.TestCase):
    def test_browser_signature_produces_only_public_agent_handoff(self) -> None:
        human_key, human_packet, human = _identity()
        _, agent_packet, agent = _identity()
        binding = EmployeeBinding(
            "atlas-studio", "person-jules", "https://accounts.google.com",
            "synthetic-subject", human, "synthetic-binding",
        )
        authority = issue_task_write_authority(
            OperatorRoot(bytes([0x21]) * 32), binding, human_packet,
            provider_service="google-docs-delegation-demo",
            provider_tool="replace_project_a_marker_v2", now=1000, lifetime=600,
        )
        card = {
            "schema": "auths.agent-task/3", "task_id": "task-1",
            "initiator_principal": human, "approver_principal": human, "agent_principal": agent,
            "not_before": 1010, "expires_at": 1300,
            "write_scopes": [{"handle": "working-doc", "verb": "edit",
                              "recipe_digest": "a" * 64,
                              "connection_id": "jules-google",
                              "connection_generation": 1,
                              "connection_subject": "jules-subject"}],
        }
        pending = prepare_agent_delegation(
            authority, human_packet, agent_packet, card, "a" * 64,
        )
        with self.assertRaises(OperatorDenied):
            pending.complete(bytes(64), now=1100)
        package = pending.complete(human_key.sign(pending.signing_preimage), now=1100)
        self.assertEqual(package["agent_principal"], agent)
        self.assertEqual(package["recipe_digest"], "a" * 64)
        self.assertNotIn("token", str(package).lower())
        child = base64.urlsafe_b64decode(package["signed_child_grant_b64"])
        self.assertIsNotNone(_native.parse_signed("grant", child))
        with self.assertRaises(OperatorDenied):
            pending.complete(human_key.sign(pending.signing_preimage), now=1300)
        with self.assertRaises(OperatorDenied):
            prepare_agent_delegation(
                authority, human_packet, agent_packet,
                {**card, "agent_principal": human}, "a" * 64,
            )
        with self.assertRaises(OperatorDenied):
            prepare_agent_delegation(
                authority, human_packet, agent_packet, card, "b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
