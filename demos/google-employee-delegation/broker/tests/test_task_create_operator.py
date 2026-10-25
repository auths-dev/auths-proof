"""The planned create handoff preserves its producer baseline before entry."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_create_operator import (
    reconcile_planned_child, submit_planned_create, submit_planned_population,
)


class PlannedCreateOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task_id = "task-1"
        self.task_dir = self.root / self.task_id
        self.task_dir.mkdir(mode=0o700)
        self.state_dir = self.root / "gateway-state"
        self.state_dir.mkdir(mode=0o700)
        self.generation = self.root / "generation-0002"
        self.generation.mkdir(mode=0o700)
        self.baseline = self.generation / "google-write-observation.json"
        self.now = int(datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc).timestamp())
        self.observation = {
            "schema_version": "demo-co/google-write-observation/v1",
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64,
            "observed_at": datetime.fromtimestamp(
                self.now - 60, timezone.utc,
            ).isoformat(),
            "document_id": "working-doc", "tab_id": "tab-1",
            "revision_id": "rev-1", "content_sha256": "b" * 64,
            "content_byte_count": 65, "original_marker_count": 1,
        }
        self._write(self.baseline, self.observation)
        self.card = {
            "task_id": self.task_id, "company_id": "atlas-studio",
            "connection_subject": "jules-subject",
            "connection_id": "jules-connection", "connection_generation": 1,
            "pending_child": {
                "parent_handle": "project-a-folder", "title": CHILD_TITLE,
                "marker": "ap071_" + "c" * 32,
                "create_recipe_digest": "d" * 64,
                "create_operation_id": "create-1",
            },
        }
        self._write(self.task_dir / "task-card.json", self.card)
        for name in ("agent.proof", "agent.action", "effect-plan.proof",
                     "effect-plan.action"):
            self._write(self.task_dir / name, b"signed")
        self.pins = SimpleNamespace(
            producer=SimpleNamespace(company="atlas-studio",
                                     jules_subject="jules-subject"),
            connection_id="jules-connection", connection_generation=1,
        )
        self.evidence = {
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "document_id": "working-doc",
            "folder_id": "project-a-folder",
        }

    @staticmethod
    def _write(path: Path, value: dict | bytes) -> None:
        raw = (json.dumps(value, sort_keys=True).encode()
               if type(value) is dict else value)
        path.write_bytes(raw)
        os.chmod(path, 0o600)

    def _submit(self, **kwargs):
        return submit_planned_create(
            gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
            gateway_state_dir=self.state_dir, task_dir=self.task_dir,
            task_id=self.task_id, write_evidence_path=self.root / "evidence",
            credential_pins_path=self.root / "pins", baseline_path=self.baseline,
            baseline_sha256=hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
            now=self.now, **kwargs,
        )

    def _population_fixture(self) -> tuple[Path, dict, dict]:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, b'{"outcome":"response-recorded","status":200}', b"",
                    ))):
            self._submit()
        plan = {
            "schema": "auths.agent-effect-plan/1", "task_id": self.task_id,
            "task_commitment": "a" * 64,
            "create": {"operation_id": "create-1"},
            "populate_recipe_digest": "b" * 64,
            "populate_operation_id": "populate-1", "expires_at": self.now + 100,
        }
        package = {
            "schema": "auths.ap071-agent-write-package/1",
            "task_id": self.task_id, "recipe_digest": "b" * 64,
        }
        inputs = {
            "schema": "auths.gateway-task-populate-preflight-inputs/1",
            "task_id": self.task_id, "task_commitment": "a" * 64,
            "plan_commitment": "f" * 64, "create_operation_id": "create-1",
            "child_id": "child-1", "populate_recipe_digest": "b" * 64,
            "preflight_rule_digest": "c" * 64,
            "connection_id": "jules-connection", "connection_generation": 1,
            "connection_subject": "jules-subject",
        }
        report = {"statement": inputs | {
            "schema": "auths.gateway-task-populate-preflight/1",
            "valid_until": self.now + 60,
        }, "signature_b64": "signed-jules-report"}
        preflight_path = self.root / "preflight.json"
        self._write(self.task_dir / "effect-plan.json", plan)
        self._write(self.task_dir / "agent-companion-write-package.json", package)
        self._write(self.task_dir / "populate.proof", b"agent-populate-proof")
        self._write(self.task_dir / "populate.action", b"agent-populate-action")
        self._write(preflight_path, report)
        return preflight_path, report, inputs

    def test_v2_baseline_is_pinned_before_four_child_create(self) -> None:
        self.evidence.update({
            "customer_id": "customer-1", "jules_subject": "jules-subject",
            "drive_id": "drive-A", "folder_id": "project-a-folder",
        })
        self.pins.producer.evidence_sha256 = "f" * 64
        historical = self.root / "generation-0004"
        historical.mkdir(mode=0o700)
        blank_path = historical / "google-preserved-blank-observation.json"
        def at(seconds):
            return datetime.fromtimestamp(self.now + seconds,
                                          timezone.utc).isoformat()
        blank = {
            "schema_version": "demo-co/google-preserved-blank-observation/v1",
            "status": "observed_blank", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject",
            "source_verification_sha256": "f" * 64,
            "drive_id": "drive-A", "folder_id": "project-a-folder",
            "observed_at": at(-200), "original_baseline_generation": 3,
            "original_baseline_sha256": "1" * 64,
            "original_baseline_observed_at": at(-280),
            "preserved_child_created_at": at(-250),
            "preserved_child_id": "old-child",
            "preserved_child_title": CHILD_TITLE,
            "preserved_marker": "ap071_" + "2" * 32,
            "blank_export_sha256": hashlib.sha256(b"\xef\xbb\xbf").hexdigest(),
            "blank_export_byte_count": 3,
            "blank_layout": "section-break-then-newline-paragraph/v1",
            "direct_child_count": 3, "tab_id": "t.0",
            "admin_revision_id": "revision-old",
            "working_document_sha256": "3" * 64,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        self._write(blank_path, blank)
        blank_sha = hashlib.sha256(blank_path.read_bytes()).hexdigest()
        self.generation = self.root / "generation-0005"
        self.generation.mkdir(mode=0o700)
        self.baseline = self.generation / "google-create-v2-baseline.json"
        v2 = {
            "schema_version": "demo-co/google-create-v2-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject",
            "source_verification_sha256": "f" * 64,
            "drive_id": "drive-A", "folder_id": "project-a-folder",
            "observed_at": at(-60), "preserved_blank_generation": 4,
            "preserved_blank_sha256": blank_sha,
            "working_document_id": "working-doc",
            "working_content_sha256": "3" * 64,
            "working_content_byte_count": 20,
            "preserved_child_id": "old-child",
            "preserved_child_title": CHILD_TITLE,
            "preserved_child_created_at": at(-250),
            "preserved_marker": "ap071_" + "2" * 32,
            "preserved_content_sha256": "4" * 64,
            "preserved_content_byte_count": 148,
            "preserved_state": "populated", "direct_child_count": 3,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        self._write(self.baseline, v2)
        pins_path = self.root / "v2-pins.json"
        self._write(pins_path, {
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject",
            "source_verification_sha256": "f" * 64,
            "drive_id": "drive-A", "folder_id": "project-a-folder",
            "working_document_id": "working-doc",
            "original_baseline_generation": 3,
            "original_baseline_sha256": "1" * 64,
            "preserved_blank_generation": 4,
            "preserved_blank_sha256": blank_sha,
            "baseline_generation": 5,
            "baseline_sha256": hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
            "preserved_child_id": "old-child",
            "preserved_marker": "ap071_" + "2" * 32,
        })
        def run(command, **kwargs):
            record = json.loads((self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(record["schema"], "auths.ap071-pre-create-baseline/2")
            self.assertEqual(record["preserved_blank_sha256"], blank_sha)
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"response-recorded","status":200}', b"",
            )
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run) as gateway):
            with self.assertRaisesRegex(OperatorDenied, "v2 pre-create"):
                self._submit(v2_pins_path=pins_path)
            gateway.assert_not_called()
            result = self._submit(v2_pins_path=pins_path,
                                  preserved_blank_path=blank_path)
            self.assertEqual(result["baseline_generation"], 5)
            self.assertEqual(result["gateway_outcome"], "response-recorded")
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                self._submit(v2_pins_path=pins_path,
                             preserved_blank_path=blank_path)
            gateway.assert_called_once()

    def test_baseline_is_durable_before_one_gateway_create(self) -> None:
        def run(command, **kwargs):
            record = json.loads((self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(record["generation"], 2)
            self.assertEqual(record["create_operation_id"], "create-1")
            self.assertEqual(command[1], "task-submit")
            self.assertIn("--recorded-effect-plan", command)
            self.assertNotIn("--confirmation-proof", command)
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"response-recorded","status":200}', b"",
            )
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run) as gateway):
            result = self._submit()
            self.assertEqual(result["gateway_outcome"], "response-recorded")
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                self._submit()
            gateway.assert_called_once()

    def test_stale_or_mismatched_baseline_never_enters_gateway(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run") as gateway):
            for changed in (
                {"observed_at": datetime.fromtimestamp(
                    self.now - 301, timezone.utc).isoformat()},
                {"document_id": "other-doc"},
                {"original_marker_count": -1},
            ):
                with self.subTest(changed=changed):
                    self._write(self.baseline, self.observation | changed)
                    with self.assertRaisesRegex(OperatorDenied, "baseline"):
                        self._submit()
            gateway.assert_not_called()
            self.assertFalse((self.task_dir / "pre-create-baseline.json").exists())

    def test_uncertain_gateway_result_preserves_original_baseline(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=subprocess.TimeoutExpired("gateway", 90)) as gateway):
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self._submit()
            self.assertTrue((self.task_dir / "pre-create-baseline.json").exists())
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                self._submit()
            gateway.assert_called_once()

    def test_reconciliation_uses_original_action_and_baseline_without_create(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, b'{"outcome":"response-recorded","status":200}', b"",
                    ))):
            self._submit()
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps({
                            "schema": "auths.gateway-child-reconciliation/1",
                            "outcome": "child-bound", "child_id": "child-1",
                        }).encode(), b"",
                    )) as gateway):
            result = reconcile_planned_child(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id,
            )
            self.assertEqual(result["child_id"], "child-1")
            self.assertEqual(result["baseline_generation"], 2)
            command = gateway.call_args.args[0]
            self.assertEqual(command[1], "task-reconcile-child")
            self.assertNotIn("task-submit", command)
            self.assertNotIn("--confirmation-proof", command)
            self.assertEqual(command[command.index("--agent-action") + 1],
                             str(self.task_dir / "agent.action"))
            gateway.assert_called_once()

    def test_population_enters_once_with_recorded_plan_and_jules_child(self) -> None:
        preflight_path, report, inputs = self._population_fixture()

        def run(command, **kwargs):
            if command[1] == "task-populate-preflight-inputs":
                return subprocess.CompletedProcess(command, 0,
                                                   json.dumps(inputs).encode(), b"")
            self.assertEqual(command[1], "task-submit")
            self.assertIn("--recorded-effect-plan", command)
            self.assertEqual(command[command.index("--recipe-digest") + 1], "b" * 64)
            self.assertTrue((self.task_dir / "populate-entry.json").exists())
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"response-recorded","status":200}', b"",
            )

        def populate():
            return submit_planned_population(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, preflight_path=preflight_path, now=self.now,
            )

        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run) as gateway):
            altered = json.loads(json.dumps(report))
            altered["statement"]["child_id"] = "other-child"
            self._write(preflight_path, altered)
            with self.assertRaisesRegex(OperatorDenied, "differs"):
                populate()
            self.assertFalse((self.task_dir / "populate-entry.json").exists())
            self._write(preflight_path, report)
            result = populate()
            self.assertEqual(result["child_id"], "child-1")
            self.assertEqual(result["gateway_outcome"], "response-recorded")
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                populate()
            self.assertEqual(gateway.call_count, 4)

    def test_only_recorded_pre_entry_denial_can_recover_population(self) -> None:
        preflight_path, report, inputs = self._population_fixture()
        status = {
            "schema": "auths.gateway-agent-task-status/1",
            "task_id": self.task_id, "writes": 1,
            "write_operations": ["create-1"],
        }
        submissions = 0

        def run(command, **kwargs):
            nonlocal submissions
            if command[1] == "task-populate-preflight-inputs":
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(inputs).encode(), b"",
                )
            if command[1] == "task-status":
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(status).encode(), b"",
                )
            self.assertEqual(command[1], "task-submit")
            submissions += 1
            return subprocess.CompletedProcess(
                command, 0,
                (b'{"outcome":"denied"}' if submissions == 1
                 else b'{"outcome":"response-recorded","status":200}'), b"",
            )

        def populate(*, recover=False):
            return submit_planned_population(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, preflight_path=preflight_path,
                now=self.now, recover_pre_entry_denial=recover,
            )

        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run)):
            self.assertEqual(populate()["gateway_outcome"], "denied")
            self.assertEqual(submissions, 1)
            self.assertTrue((self.task_dir / "populate-result.json").exists())
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                populate()
            refreshed = json.loads(json.dumps(report))
            refreshed["signature_b64"] = "fresh-jules-report"
            self._write(preflight_path, refreshed)
            status["writes"] = 2
            status["write_operations"].append("populate-1")
            with self.assertRaisesRegex(OperatorDenied, "may have entered"):
                populate(recover=True)
            self.assertEqual(submissions, 1)
            self.assertFalse((self.task_dir / "populate-recovery-entry.json").exists())
            status["writes"] = 1
            status["write_operations"] = ["create-1"]
            self.assertEqual(populate(recover=True)["gateway_outcome"],
                             "response-recorded")
            self.assertEqual(submissions, 2)
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                populate(recover=True)

    def test_unknown_population_outcome_never_opens_recovery(self) -> None:
        preflight_path, report, inputs = self._population_fixture()
        submissions = 0

        def run(command, **kwargs):
            nonlocal submissions
            if command[1] == "task-populate-preflight-inputs":
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(inputs).encode(), b"",
                )
            if command[1] == "task-status":
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "schema": "auths.gateway-agent-task-status/1",
                    "task_id": self.task_id, "writes": 1,
                    "write_operations": ["create-1"],
                }).encode(), b"")
            submissions += 1
            return subprocess.CompletedProcess(command, 1, b"", b"lost response")

        def populate(*, recover=False):
            return submit_planned_population(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, preflight_path=preflight_path,
                now=self.now, recover_pre_entry_denial=recover,
            )

        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run)):
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                populate()
            refreshed = json.loads(json.dumps(report))
            refreshed["signature_b64"] = "fresh-jules-report"
            self._write(preflight_path, refreshed)
            with self.assertRaisesRegex(OperatorDenied, "cannot be proved"):
                populate(recover=True)
            self.assertEqual(submissions, 1)


if __name__ == "__main__":
    unittest.main()
