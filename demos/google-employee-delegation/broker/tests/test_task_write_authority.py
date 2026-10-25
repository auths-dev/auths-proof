"""Native AP-071 authority for two reviewed provider write profiles."""

from __future__ import annotations

import json
import unittest

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.operator_authority import OperatorDenied, OperatorRoot
from employee_read_demo.task_write_authority import (
    APPROVAL_TOOL, CONFIRMATION_TOOL, TASK_SERVICE,
    issue_task_write_authority, plan_agent_read_grant, plan_agent_write_grant,
)


def _identity():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    identity = create_raw_key_ed25519_identity(public)
    principal, evidence = authority_for_identity_packet(identity.to_bytes())
    return key, identity, principal, evidence


def _evidence(raw: bytes) -> tuple[str, str, bytes]:
    return "raw-key-v1", "application/vnd.auths.raw-key.v1", bytes(raw)


def _verify_action(authority, *, service: str, tool: str, key, actor: str,
                   actor_evidence: bytes, terminal, grants, grant_evidence) -> None:
    now, challenge = 1100, authority.challenge
    arguments = _native.canonicalize_mcp_arguments_json(
        json.dumps({"task_id": "synthetic-task"}).encode("utf-8"),
    )
    call = _native.mcp_call(service, tool, arguments)
    prepared = _native.prepare_mcp_call_action(
        call, _native.Principal(actor), terminal, challenge, now, 30,
    )
    signing = _native.prepare_signing(
        prepared.unsigned, "raw-key-v1", actor, "ed25519-v1",
    )
    action = signing.complete(key.sign(bytes(signing.signing_preimage)))
    context = _native.parse_trusted_context(authority.trusted_template).bind_request(
        f"mcp://{service}", challenge, now,
    )
    proof, canonical_action, _ = _native.assemble_mcp_proof(
        prepared, action, grants, grant_evidence,
        [_evidence(actor_evidence)], context,
    )
    verdict, command = _native.verify_exact_mcp_command(
        proof, canonical_action, bytes(_native.inspect_trusted_context(context)),
        service, tool,
    )
    assert verdict.kind == "authorized", verdict.code
    assert command is not None


class TaskWriteAuthorityTests(unittest.TestCase):
    def test_human_and_agent_proofs_share_one_provider_neutral_trust(self) -> None:
        for service, tool, read_service, read_tool in (
            ("google-docs-delegation-demo", "replace_project_a_marker_v2",
             "google-drive-delegation-demo", "release_project_a_text_v2"),
            ("airtable-gateway-demo", "set_demo_status_v2",
             "airtable-read-demo", "release_demo_status_v2"),
        ):
            with self.subTest(service=service):
                human_key, human_identity, human, human_evidence = _identity()
                agent_key, _, agent, agent_evidence = _identity()
                binding = EmployeeBinding(
                    "atlas-studio", "person-jules", "https://accounts.google.com",
                    "synthetic-subject", human, "synthetic-binding",
                )
                root = OperatorRoot(bytes([0x21]) * 32)
                authority = issue_task_write_authority(
                    root, binding, human_identity.to_bytes(),
                    provider_service=service, provider_tool=tool,
                    read_service=read_service, read_tool=read_tool,
                    now=1000, lifetime=600,
                )
                self.assertEqual(authority.human_principal, human)
                self.assertEqual(authority.root_principal, root.principal)
                for task_tool, grant in (
                    (APPROVAL_TOOL, authority.approval_grant),
                    (CONFIRMATION_TOOL, authority.confirmation_grant),
                ):
                    signed_grant = _native.parse_signed("grant", grant.signed_grant)
                    _verify_action(
                        authority, service=TASK_SERVICE, tool=task_tool,
                        key=human_key, actor=human, actor_evidence=human_evidence,
                        terminal=signed_grant, grants=[signed_grant],
                        grant_evidence=[[_evidence(root.evidence)]],
                    )
                plan = plan_agent_write_grant(
                    authority, agent, not_before=1010, expires_at=1300,
                )
                signing = _native.prepare_signing(
                    plan.unsigned, "raw-key-v1", human, "ed25519-v1",
                )
                child = signing.complete(
                    human_key.sign(bytes(signing.signing_preimage)),
                )
                parent = _native.parse_signed(
                    "grant", authority.write_parent_grant.signed_grant,
                )
                _verify_action(
                    authority, service=service, tool=tool,
                    key=agent_key, actor=agent, actor_evidence=agent_evidence,
                    terminal=child, grants=[parent, child],
                    grant_evidence=[[_evidence(root.evidence)],
                                    [_evidence(human_evidence)]],
                )
                read_plan = plan_agent_read_grant(
                    authority, agent, not_before=1010, expires_at=1300,
                )
                read_signing = _native.prepare_signing(
                    read_plan.unsigned, "raw-key-v1", human, "ed25519-v1",
                )
                read_child = read_signing.complete(
                    human_key.sign(bytes(read_signing.signing_preimage)),
                )
                read_parent = _native.parse_signed(
                    "grant", authority.read_parent_grant.signed_grant,
                )
                _verify_action(
                    authority, service=read_service, tool=read_tool,
                    key=agent_key, actor=agent, actor_evidence=agent_evidence,
                    terminal=read_child, grants=[read_parent, read_child],
                    grant_evidence=[[_evidence(root.evidence)],
                                    [_evidence(human_evidence)]],
                )

    def test_invalid_profile_or_child_window_is_refused(self) -> None:
        _, human_identity, human, _ = _identity()
        _, _, agent, _ = _identity()
        binding = EmployeeBinding(
            "atlas-studio", "person-jules", "https://accounts.google.com",
            "synthetic-subject", human, "synthetic-binding",
        )
        root = OperatorRoot(bytes([0x21]) * 32)
        for service, tool in ((TASK_SERVICE, "set_demo_status_v2"),
                              ("airtable-gateway-demo", "bad/tool")):
            with self.assertRaises(OperatorDenied):
                issue_task_write_authority(
                    root, binding, human_identity.to_bytes(),
                    provider_service=service, provider_tool=tool,
                    now=1000, lifetime=600,
                )
        for read_service, read_tool in (
            ("airtable-read-demo", None),
            (TASK_SERVICE, "release_demo_status_v2"),
            ("airtable-gateway-demo", "set_demo_status_v2"),
        ):
            with self.assertRaises(OperatorDenied):
                issue_task_write_authority(
                    root, binding, human_identity.to_bytes(),
                    provider_service="airtable-gateway-demo",
                    provider_tool="set_demo_status_v2",
                    read_service=read_service, read_tool=read_tool,
                    now=1000, lifetime=600,
                )
        authority = issue_task_write_authority(
            root, binding, human_identity.to_bytes(),
            provider_service="airtable-gateway-demo",
            provider_tool="set_demo_status_v2", now=1000, lifetime=600,
        )
        for start, end in ((999, 1300), (1100, 1601), (1200, 1100)):
            with self.assertRaises(OperatorDenied):
                plan_agent_write_grant(
                    authority, agent, not_before=start, expires_at=end,
                )
        with self.assertRaises(OperatorDenied):
            plan_agent_write_grant(
                authority, human, not_before=1100, expires_at=1300,
            )


if __name__ == "__main__":
    unittest.main()
