"""The optional browser execution path keeps preflight before provider entry."""

from __future__ import annotations

import json
import hashlib
import base64
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.task_write_intent import ReviewedWrite


class TaskWriteExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.task_id = "test-task"
        self.task_dir = self.root / self.task_id
        self.task_dir.mkdir(mode=0o700)
        for name in ("task.proof", "task.action", "confirmation.proof",
                     "confirmation.action", "agent.proof", "agent.action"):
            path = self.task_dir / name
            path.write_bytes(b"signed-test-artifact")
            os.chmod(path, 0o600)
        self.events: list[str] = []
        self.review = ReviewedWrite(
            {"task_id": self.task_id}, {"document_id": "working-doc"},
            "POST", "https://docs.googleapis.com/v1/documents/working-doc:batchUpdate",
            "application/json", "{}",
        )
        self.flow = TaskWriteConfirmationFlow(
            authority_path=self.root / "authority",
            installation_path=self.root / "installation",
            recipe_path=self.root / "recipe",
            profile_lock_path=self.root / "lock",
            private_output_dir=self.root,
            gateway_binary=self.root / "gateway",
            gateway_sha256="a" * 64,
            preflight=lambda card, review: self.events.append("preflight"),
            gateway_state_dir=self.root / "gateway-state",
        )
        self.flow._binary = lambda: self.root / "gateway"
        self.flow._review = lambda task_id, employee, agent, now: (
            {"task_id": task_id}, self.review,
        )

    def test_submit_preflights_then_returns_gateway_result(self) -> None:
        def run(command, **kwargs):
            self.events.append("gateway")
            self.assertEqual(command[1], "task-submit")
            self.assertEqual(command[command.index("--task-id") + 1], self.task_id)
            return subprocess.CompletedProcess(
                command, 0, json.dumps({
                    "outcome": "response-recorded", "status": 200,
                }).encode(), b"",
            )

        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   side_effect=run):
            result = self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                      now=1000)
        self.assertEqual(self.events, ["preflight", "gateway"])
        self.assertEqual(result, {"outcome": "response-recorded", "status": 200})

    def test_unexpected_gateway_field_is_not_returned_or_retried(self) -> None:
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, b'{"outcome":"unknown","private":"leak"}', b"")) as run:
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                 now=1000)
        self.assertEqual(run.call_count, 1)

    def test_failed_preflight_never_invokes_gateway(self) -> None:
        def deny(card, review):
            raise OperatorDenied("Doc revision changed")

        self.flow.preflight = deny
        with patch("employee_read_demo.task_write_confirmation.subprocess.run") as run:
            with self.assertRaises(OperatorDenied):
                self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                 now=1000)
        run.assert_not_called()

    def test_lost_gateway_result_is_not_retried(self) -> None:
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("task-submit", 90)) as run:
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                 now=1000)
        self.assertEqual(run.call_count, 1)

    def test_activation_uses_private_task_artifacts_once(self) -> None:
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, b'{"outcome":"task-activated"}\n', b"")) as run:
            self.flow.activate(self.task_id)
        command = run.call_args.args[0]
        self.assertEqual(command[1], "task-activate")
        self.assertEqual(command[command.index("--proof") + 1],
                         str(self.task_dir / "task.proof"))

    def test_revoke_checks_task_owner_then_calls_gateway_once(self) -> None:
        card = self.task_dir / "task-card.json"
        card.write_text(json.dumps({
            "task_id": self.task_id,
            "company_id": "atlas",
            "human_principal": "human-1",
        }), encoding="utf-8")
        os.chmod(card, 0o600)
        employee = EmployeeBinding("atlas", "jules", "issuer", "subject",
                                   "human-1", "binding")
        with patch("employee_read_demo.task_write_confirmation.subprocess.run") as run:
            with self.assertRaisesRegex(OperatorDenied, "not owned"):
                self.flow.revoke(task_id=self.task_id, employee=EmployeeBinding(
                    "atlas", "other", "issuer", "other-subject", "other-human", "binding",
                ))
            run.assert_not_called()
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, b'{"outcome":"task-revoked"}\n', b"")) as run:
            self.flow.revoke(task_id=self.task_id, employee=employee)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1], "task-revoke")
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, b'{"outcome":"task-revoked","private":"leak"}', b"")):
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self.flow.revoke(task_id=self.task_id, employee=employee)

    def test_status_reports_only_the_gateway_redacted_contract(self) -> None:
        card = self.task_dir / "task-card.json"
        card.write_text(json.dumps({
            "task_id": self.task_id,
            "company_id": "atlas",
            "human_principal": "human-1",
        }), encoding="utf-8")
        os.chmod(card, 0o600)
        employee = EmployeeBinding("atlas", "jules", "issuer", "subject",
                                   "human-1", "binding")
        status = {
            "schema": "auths.gateway-agent-task-status/1", "task_id": self.task_id,
            "expires_at": 2000, "revoked": False,
            "provider_calls": 1, "max_provider_calls": 2,
            "releases": 1, "max_releases": 1,
            "released_bytes": 5, "max_release_bytes": 64,
            "writes": 0, "max_writes": 1,
            "reads": [{"operation_id": "read-1", "stage": "agent-acknowledged",
                       "released_bytes": 5}],
            "write_operations": [],
        }
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, json.dumps(status).encode(), b"")) as run:
            self.assertEqual(self.flow.status(task_id=self.task_id, employee=employee), status)
        self.assertEqual(run.call_args.args[0][1], "task-status")
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, json.dumps({**status, "private": "leak"}).encode(), b"")):
            with self.assertRaisesRegex(OperatorDenied, "status is unavailable"):
                self.flow.status(task_id=self.task_id, employee=employee)

    def test_one_effect_plan_records_exact_draft_before_any_provider_write(self) -> None:
        self.flow.companion_recipe_path = self.root / "populate-recipe"
        self.flow.companion_profile_lock_path = self.root / "populate-lock"
        draft = self.task_dir / "agent-draft.json"
        draft.write_text("Agent's approved Project A handoff", encoding="utf-8")
        draft.chmod(0o600)
        pending_child = {
            "create_operation_id": "create-1", "create_recipe_digest": "c" * 64,
            "populate_recipe_digest": "d" * 64,
            "parent_handle": "project-a-folder", "title": "Project A handoff",
            "marker": "ap071_" + "e" * 32,
        }
        card = {"task_id": self.task_id, "expires_at": 2000,
                "pending_child": pending_child}
        reviewed = ReviewedWrite(
            {"task_id": self.task_id, "operation_id": "create-1",
             "recipe_digest": "c" * 64, "resource_handle": "project-a-folder",
             "verb": "create"},
            {"title": pending_child["title"],
             "recovery_marker": pending_child["marker"]},
            "POST", "https://www.googleapis.com/drive/v3/files",
            "application/json", "{}",
        )
        self.flow._review = lambda task_id, employee, agent, now: (card, reviewed)
        self.flow._agent_draft = lambda task_id, employee, agent, packet, card: (
            draft.read_text(encoding="utf-8"),
            hashlib.sha256(draft.read_bytes()).hexdigest(),
        )
        package = SimpleNamespace(
            companion_write=SimpleNamespace(recipe_digest="d" * 64),
            authority=object(),
        )

        def complete(signature: bytes, *, now: int):
            self.assertEqual(signature, b"signed-by-jules")
            return SimpleNamespace(proof=b"human-proof", action=b"human-action")

        human_action = SimpleNamespace(
            signing_preimage=b"exact-plan-preimage", expires_at=1300,
            complete=complete,
        )
        with (
            patch("employee_read_demo.task_write_confirmation.load_task_write_package",
                  return_value=package),
            patch("employee_read_demo.task_write_confirmation.task_commitment",
                  return_value="a" * 64),
            patch("employee_read_demo.task_write_confirmation.prepare_effect_plan_confirmation",
                  return_value=human_action),
        ):
            prepared = self.flow.prepare_effect_plan(
                task_id=self.task_id, employee=None, agent=None,
                agent_identity_packet=b"packet", now=1000,
            )
            self.assertEqual(prepared.plan["initial_text"],
                             "Agent's approved Project A handoff")
            self.assertEqual(prepared.plan["create"], reviewed.intent)
            self.assertEqual(prepared.plan["expires_at"], 1180)
            self.assertEqual(prepared.signing_preimage, b"exact-plan-preimage")
            with patch("employee_read_demo.task_write_confirmation.subprocess.run") as run:
                draft.write_text("altered after review", encoding="utf-8")
                with self.assertRaisesRegex(OperatorDenied, "proposal changed"):
                    self.flow.complete_effect_plan(
                        nonce=prepared.nonce, employee=None, agent=None,
                        agent_identity_packet=b"packet",
                        signature=b"signed-by-jules", now=1001,
                    )
                run.assert_not_called()

            draft.write_text("Agent's approved Project A handoff", encoding="utf-8")
            prepared = self.flow.prepare_effect_plan(
                task_id=self.task_id, employee=None, agent=None,
                agent_identity_packet=b"packet", now=1002,
            )
            with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                       return_value=subprocess.CompletedProcess(
                           [], 0, b'{"outcome":"effect-plan-recorded"}\n', b"")) as run:
                self.flow.complete_effect_plan(
                    nonce=prepared.nonce, employee=None, agent=None,
                    agent_identity_packet=b"packet",
                    signature=b"signed-by-jules", now=1003,
                )
            command = run.call_args.args[0]
            self.assertEqual(command[1], "task-record-effect-plan")
            self.assertEqual(command[command.index("--recipe-digest") + 1], "c" * 64)
            self.assertEqual((self.task_dir / "effect-plan.proof").read_bytes(),
                             b"human-proof")
            self.assertEqual((self.task_dir / "effect-plan.action").read_bytes(),
                             b"human-action")
            self.assertEqual(json.loads((self.task_dir / "effect-plan.json").read_bytes()),
                             prepared.plan)
            self.assertNotIn("task-submit", command)

    def test_owner_verifies_agent_signature_and_read_before_plan_review(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        packet = b"registered-agent-identity"
        agent = AgentBinding("atlas", "binding", "agent-1",
                             hashlib.sha256(packet).hexdigest())
        source = self.task_dir / "agent-source.bin"
        source.write_bytes(b"Project A is ready for review.")
        source.chmod(0o600)
        card = {"task_id": self.task_id,
                "read_scopes": [{"handle": "source-1"}]}
        statement = {
            "schema": "auths.agent-draft/1", "task_id": self.task_id,
            "task_commitment": "a" * 64, "agent_principal": "agent-1",
            "source_resource_handle": "source-1", "read_operation_id": "read-1",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "source_bytes": 30,
            "content": "Project A is ready for review. [source-1]",
        }
        original_content = statement["content"]
        canonical = lambda value: json.dumps(value, sort_keys=True,
                                             separators=(",", ":"),
                                             ensure_ascii=False).encode()
        envelope = {
            "statement": statement,
            "signature_b64": base64.b64encode(
                key.sign(b"auths.agent-draft/1\0" + canonical(statement)),
            ).decode().rstrip("="),
        }
        draft = self.task_dir / "agent-draft.json"
        draft.write_bytes(canonical(envelope))
        draft.chmod(0o600)
        with (
            patch("employee_read_demo.task_write_confirmation.raw_key_public_for_identity_packet",
                  return_value=public),
            patch("employee_read_demo.task_agent_draft.task_commitment",
                  return_value="a" * 64),
            patch.object(self.flow, "_acknowledged_reads",
                         return_value={"read-1": 30}) as reads,
            patch("employee_read_demo.task_write_confirmation.subprocess.run",
                  return_value=subprocess.CompletedProcess(
                      [], 0, b'{"outcome":"source-matched"}\n', b"")) as compare,
        ):
            text, digest = self.flow._agent_draft(
                self.task_id, None, agent, packet, card,
            )
            self.assertEqual(text, statement["content"])
            self.assertEqual(digest, hashlib.sha256(draft.read_bytes()).hexdigest())
            reads.assert_called_once()
            self.assertEqual(compare.call_args.args[0][1], "task-release-compare")
            self.assertEqual(compare.call_args.kwargs["input"],
                             statement["source_sha256"].encode())
            envelope["statement"]["content"] = "Changed [source-1]"
            draft.write_bytes(canonical(envelope))
            with self.assertRaisesRegex(OperatorDenied, "signature"):
                self.flow._agent_draft(self.task_id, None, agent, packet, card)
            with self.assertRaisesRegex(OperatorDenied, "identity"):
                self.flow._agent_draft(
                    self.task_id, None, agent, b"wrong-packet", card,
                )
            envelope["statement"]["content"] = original_content
            draft.write_bytes(canonical(envelope))
            compare.return_value = subprocess.CompletedProcess(
                [], 2, b"", b"gateway.release.source-mismatch",
            )
            with self.assertRaisesRegex(OperatorDenied, "source differs"):
                self.flow._agent_draft(self.task_id, None, agent, packet, card)
            source.unlink()
            with self.assertRaisesRegex(OperatorDenied, "private agent source is unavailable"):
                self.flow._agent_draft(self.task_id, None, agent, packet, card)


if __name__ == "__main__":
    unittest.main()
