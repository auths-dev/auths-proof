"""The browser recovery review must display only one pinned unknown create."""

import base64
import hashlib
import json
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
from employee_read_demo.contracts import commitment
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.google_create_preflight import _canonical_json
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_recovery_operator import DOMAIN, SCHEMA
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.task_write_proofs import task_commitment


class RecoveryReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.task_id = "task-recovery"
        self.directory = self.root / self.task_id
        self.directory.mkdir(mode=0o700)
        self.employee = EmployeeBinding("atlas-studio", "jules", "issuer", "subject",
                                        "human-key", "binding")
        self.agent = AgentBinding("atlas-studio", "binding", "agent-key", "a" * 64)
        self.card = {
            "schema": "auths.agent-task/2", "task_id": self.task_id,
            "company_id": "atlas-studio", "human_principal": "human-key",
            "agent_principal": "agent-key", "write_approval_mode": "exact",
            "pending_child": {"create_operation_id": "create-1"},
            "expires_at": 1300,
        }
        self.flow = TaskWriteConfirmationFlow(
            authority_path=self.root / "authority",
            installation_path=self.root / "installation",
            recipe_path=self.root / "recipe",
            profile_lock_path=self.root / "lock",
            companion_recipe_path=self.root / "companion",
            companion_profile_lock_path=self.root / "companion-lock",
            private_output_dir=self.root,
            gateway_binary=self.root / "gateway",
            gateway_sha256="a" * 64,
            gateway_state_dir=self.root / "gateway-state",
        )
        self.flow._binary = lambda: self.root / "gateway"
        self.flow._owned_task_card = lambda task_id, employee: self.card
        self.signer = Ed25519PrivateKey.generate()
        public = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pin = {"public_key_hex": public.hex(), "rule_digest": "1" * 64}
        self.plan = {
            "schema": "auths.agent-effect-plan/1", "task_id": self.task_id,
            "initial_text": "Approved Project A handoff",
        }
        plan_path = self.directory / "effect-plan.json"
        plan_path.write_bytes(_canonical_json(self.plan))
        plan_path.chmod(0o600)
        self.inputs = {
            "schema": "auths.gateway-task-create-recovery-inputs/1",
            "task_id": self.task_id,
            "task_commitment": task_commitment(self.card),
            "plan_commitment": commitment("auths.agent-effect-plan.v1", self.plan),
            "content_commitment": hashlib.sha256(
                b"auths.agent-effect-plan-content/1\0"
                + self.plan["initial_text"].encode()).hexdigest(),
            "create_operation_id": "create-1",
            "create_recipe_digest": "4" * 64,
            "action_commitment": "5" * 64,
            "request_commitment": "6" * 64,
            "populate_recipe_digest": "7" * 64,
            "connection_id": "jules-connection",
            "connection_generation": 1,
            "connection_subject": "jules-google-subject",
            "recovery_rule_digest": "1" * 64,
            "recovery_key_sha256": hashlib.sha256(public).hexdigest(),
            "parent_id": "project-a-folder",
            "title": "Handoff",
            "marker": "ap071_marker",
            "plan_expires_at": 1200,
            "attempt_stage": "unknown",
            "authority": "none",
        }
        self.statement = {
            "schema": SCHEMA,
            **{name: self.inputs[name] for name in (
                "task_id", "task_commitment", "plan_commitment",
                "content_commitment", "create_operation_id",
                "create_recipe_digest", "action_commitment",
                "request_commitment", "parent_id", "title", "marker",
                "connection_id", "connection_generation", "connection_subject",
                "recovery_rule_digest")},
            "candidate_id": "child-1",
            "search_report_sha256": "8" * 64,
            "producer_observation_sha256": "9" * 64,
            "baseline_sha256": "a" * 64,
            "candidate_metadata_sha256": "b" * 64,
            "checked_at": 990,
            "valid_until": 1110,
        }
        self._save_report()

    def _save_report(self):
        signature = self.signer.sign(DOMAIN + _canonical_json(self.statement))
        report = _canonical_json({
            "statement": self.statement,
            "signature_b64": base64.b64encode(signature).decode().rstrip("="),
        })
        path = self.directory / "recovery-attestation.json"
        path.write_bytes(report)
        path.chmod(0o600)

    def _review(self):
        result = subprocess.CompletedProcess(
            [], 0, _canonical_json(self.inputs), b"")
        with (patch("employee_read_demo.task_write_confirmation.subprocess.run",
                    return_value=result) as run,
              patch("employee_read_demo.task_write_confirmation._installation",
                    return_value={"recovery_attestation": self.pin})):
            reviewed = self.flow._recovery_review(
                self.task_id, self.employee, self.agent, 1000)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1], "task-create-recovery-inputs")
        return reviewed

    def test_review_joins_signed_candidate_to_original_unknown_attempt(self):
        inputs, statement, report, approved_text = self._review()
        self.assertEqual(inputs["authority"], "none")
        self.assertEqual(statement["candidate_id"], "child-1")
        self.assertEqual(report, (self.directory / "recovery-attestation.json").read_bytes())
        self.assertEqual(approved_text, self.plan["initial_text"])

    def test_changed_candidate_or_search_digest_is_refused(self):
        self.statement["candidate_id"] = "child-2"
        self._save_report()
        self._review()
        payload = json.loads((self.directory / "recovery-attestation.json").read_bytes())
        payload["statement"]["search_report_sha256"] = "c" * 64
        (self.directory / "recovery-attestation.json").write_bytes(_canonical_json(payload))
        with self.assertRaisesRegex(OperatorDenied, "signature is invalid"):
            self._review()

    def test_known_response_cannot_be_reviewed_as_response_less(self):
        self.inputs["attempt_stage"] = "recorded"
        with self.assertRaisesRegex(OperatorDenied, "disagrees with task"):
            self._review()

    def test_submission_uses_original_proofs_and_recovery_signature_once(self):
        for name in ("agent.proof", "agent.action", "recovery.proof",
                     "recovery.action"):
            path = self.directory / name
            path.write_bytes(b"signed")
            path.chmod(0o600)
        self.flow._recovery_review = lambda *args: (
            self.inputs, self.statement, b"report", self.plan["initial_text"])
        response = {"schema": "auths.gateway-child-recovery/1",
                    "outcome": "child-bound", "source": "recovered",
                    "child_id": "child-1"}
        with (patch("employee_read_demo.task_write_confirmation.load_task_write_package",
                    return_value=SimpleNamespace(recipe_digest="4" * 64)),
              patch("employee_read_demo.task_write_confirmation.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, _canonical_json(response), b"")) as run):
            result = self.flow.submit_recovered_child(
                task_id=self.task_id, employee=self.employee, agent=self.agent)
        self.assertEqual(result, response)
        command = run.call_args.args[0]
        self.assertEqual(command[1], "task-recover-child")
        self.assertEqual(command[command.index("--agent-proof") + 1],
                         str(self.directory / "agent.proof"))
        self.assertEqual(command[command.index("--recovery-proof") + 1],
                         str(self.directory / "recovery.proof"))

    def test_lost_gateway_recovery_result_is_not_retried(self):
        for name in ("agent.proof", "agent.action", "recovery.proof",
                     "recovery.action"):
            path = self.directory / name
            path.write_bytes(b"signed")
            path.chmod(0o600)
        self.flow._recovery_review = lambda *args: (
            self.inputs, self.statement, b"report", self.plan["initial_text"])
        with (patch("employee_read_demo.task_write_confirmation.load_task_write_package",
                    return_value=SimpleNamespace(recipe_digest="4" * 64)),
              patch("employee_read_demo.task_write_confirmation.subprocess.run",
                    side_effect=subprocess.TimeoutExpired("task-recover-child", 90)) as run):
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self.flow.submit_recovered_child(
                    task_id=self.task_id, employee=self.employee, agent=self.agent)
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
