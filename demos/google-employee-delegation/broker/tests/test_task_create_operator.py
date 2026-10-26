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

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_negative_handoff import NegativeCreateTarget
from employee_read_demo.google_create_preflight import JulesCreateRecoverySearchResult
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_create_operator import (
    _recorded_baseline_is_valid, reconcile_planned_child, submit_planned_create,
    submit_planned_population, search_planned_created_child,
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
            "tab_id": "tab-1",
            "folder_id": "project-a-folder",
            "drive_id": "drive-A",
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
            "schema": "auths.gateway-task-populate-preflight/2",
            "valid_until": self.now + 60,
        }, "signature_b64": "signed-jules-report"}
        preflight_path = self.root / "preflight.json"
        self._write(self.task_dir / "effect-plan.json", plan)
        self._write(self.task_dir / "agent-companion-write-package.json", package)
        self._write(self.task_dir / "populate.proof", b"agent-populate-proof")
        self._write(self.task_dir / "populate.action", b"agent-populate-action")
        self._write(preflight_path, report)
        return preflight_path, report, inputs

    def test_negative_create_uses_only_the_pinned_run_folder_and_marker(self) -> None:
        target = NegativeCreateTarget(
            "negative-run", "multiple", "ap071_" + "c" * 32,
            "scratch-run-folder", 24, "a" * 64,
        )
        self.card["pending_child"]["parent_handle"] = target.parent_id
        self._write(self.task_dir / "task-card.json", self.card)
        baseline_path = self.root / "generation-0025" / "google-create-negative-baseline.json"
        baseline_path.parent.mkdir(mode=0o700)
        self._write(baseline_path, {"observed_at": self.observation["observed_at"]})
        baseline_sha = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
        sources = tuple(self.root / f"source-{index}" for index in range(3))
        extra = {
            "negative_setup_path": self.root / "generation-0024" /
                                   "google-create-negative-setup.json",
            "negative_setup_sha256": target.setup_sha256,
            "negative_v4_pins_path": self.root / "v4-final-pins.json",
            "negative_source_paths": sources,
        }

        def gateway(command, **kwargs):
            recorded = json.loads(
                (self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(recorded["schema"],
                             "auths.ap071-pre-create-baseline-negative/1")
            self.assertEqual(recorded["observation_sha256"], baseline_sha)
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"unknown"}', b"",
            )

        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.load_v4_final_pins",
                    return_value=object()),
              patch("employee_read_demo.task_create_operator."
                    "validate_negative_precreate_baseline",
                    return_value=(target, 25, {
                        "observed_at": self.observation["observed_at"],
                    })),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=gateway) as entered):
            self.card["pending_child"]["parent_handle"] = "project-a-folder"
            self._write(self.task_dir / "task-card.json", self.card)
            with self.assertRaisesRegex(OperatorDenied, "scratch|Project A"):
                submit_planned_create(
                    gateway_binary=self.root / "gateway",
                    gateway_sha256="e" * 64, gateway_state_dir=self.state_dir,
                    task_dir=self.task_dir, task_id=self.task_id,
                    write_evidence_path=self.root / "evidence",
                    credential_pins_path=self.root / "pins",
                    baseline_path=baseline_path, baseline_sha256=baseline_sha,
                    now=self.now, **extra,
                )
            entered.assert_not_called()
            self.card["pending_child"]["parent_handle"] = target.parent_id
            self._write(self.task_dir / "task-card.json", self.card)
            result = submit_planned_create(
                gateway_binary=self.root / "gateway",
                gateway_sha256="e" * 64, gateway_state_dir=self.state_dir,
                task_dir=self.task_dir, task_id=self.task_id,
                write_evidence_path=self.root / "evidence",
                credential_pins_path=self.root / "pins",
                baseline_path=baseline_path, baseline_sha256=baseline_sha,
                now=self.now, **extra,
            )
            self.assertEqual(result["gateway_outcome"], "unknown")
            entered.assert_called_once()

    def test_zero_case_is_dropped_before_gateway_and_cannot_be_retried(self) -> None:
        target = NegativeCreateTarget(
            "negative-zero", "zero", "ap071_" + "c" * 32,
            "scratch-zero", 24, "a" * 64,
        )
        self.card["pending_child"]["parent_handle"] = target.parent_id
        self._write(self.task_dir / "task-card.json", self.card)
        baseline_path = self.root / "generation-0025" / "google-create-negative-baseline.json"
        baseline_path.parent.mkdir(mode=0o700)
        self._write(baseline_path, {"observed_at": self.observation["observed_at"]})
        baseline_sha = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
        extra = {
            "negative_setup_path": self.root / "setup",
            "negative_setup_sha256": target.setup_sha256,
            "negative_v4_pins_path": self.root / "v4-pins",
            "negative_source_paths": tuple(self.root / f"source-{index}"
                                           for index in range(3)),
            "pre_provider_uncertainty_for_test": True,
        }
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.load_v4_final_pins",
                    return_value=object()),
              patch("employee_read_demo.task_create_operator."
                    "validate_negative_precreate_baseline",
                    return_value=(target, 25, {
                        "observed_at": self.observation["observed_at"],
                    })),
              patch("employee_read_demo.task_create_operator.subprocess.run") as gateway):
            kwargs = dict(
                gateway_binary=self.root / "gateway",
                gateway_sha256="e" * 64, gateway_state_dir=self.state_dir,
                task_dir=self.task_dir, task_id=self.task_id,
                write_evidence_path=self.root / "evidence",
                credential_pins_path=self.root / "pins",
                baseline_path=baseline_path, baseline_sha256=baseline_sha,
                now=self.now, **extra,
            )
            outcome = submit_planned_create(**kwargs)
            self.assertEqual(outcome["gateway_outcome"],
                             "pre-provider-uncertain")
            gateway.assert_not_called()
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                submit_planned_create(**kwargs)
            gateway.assert_not_called()

    def test_recovery_search_records_only_candidate_evidence(self) -> None:
        self._write(self.task_dir / "pre-create-baseline.json", {
            "schema": "auths.ap071-pre-create-baseline/1",
            "task_id": self.task_id, "create_operation_id": "create-1",
            "marker": self.card["pending_child"]["marker"],
            "generation": 2, "observation_sha256": "a" * 64,
            "observed_at": "2026-10-25T11:59:00Z",
        })
        self._write(self.task_dir / "effect-plan.json", {
            "schema": "auths.agent-effect-plan/1", "task_id": self.task_id,
            "create": {
                "operation_id": "create-1", "resource_handle": "project-a-folder",
                "recipe_digest": "d" * 64, "connection_id": "jules-connection",
                "connection_generation": 1, "connection_subject": "jules-subject",
            },
        })
        status = {
            "schema": "auths.gateway-agent-task-status/1",
            "task_id": self.task_id, "writes": 1,
            "write_operations": ["create-1"],
        }
        for candidate_count in (0, 1, 2):
            with self.subTest(candidate_count=candidate_count):
                candidate_id = "child-1" if candidate_count == 1 else None
                result = JulesCreateRecoverySearchResult(
                    candidate_id, candidate_count, "project-a-folder",
                    "drive-A", self.card["pending_child"]["marker"],
                    ("b" * 64,), "c" * 64 if candidate_id else None,
                    self.now, "jules-connection", 1, "jules-subject",
                )
                report_path = self.task_dir / f"recovery-search-{candidate_count}.json"
                with (patch("employee_read_demo.task_create_operator._gateway",
                            return_value=self.root / "gateway"),
                      patch("employee_read_demo.task_create_operator._credential_pins",
                            return_value=self.pins),
                      patch("employee_read_demo.task_create_operator.validate_write_handoff",
                            return_value=self.evidence),
                      patch("employee_read_demo.task_create_operator._run_gateway",
                            return_value=json.dumps(status).encode()),
                      patch("employee_read_demo.task_create_operator.search_jules_created_child",
                            return_value=result) as search):
                    output = search_planned_created_child(
                        gateway_binary=self.root / "gateway",
                        gateway_sha256="e" * 64,
                        gateway_state_dir=self.state_dir,
                        task_dir=self.task_dir, task_id=self.task_id,
                        write_evidence_path=self.root / "evidence",
                        grant_path=self.root / "grant",
                        credential_pins_path=self.root / "pins",
                        report_path=report_path, now=self.now,
                    )
                self.assertEqual(output["candidate_count"], candidate_count)
                self.assertEqual(output["authority"], "none")
                self.assertEqual(search.call_args.args[3],
                                 self.card["pending_child"]["marker"])
                recorded = json.loads(report_path.read_bytes())
                self.assertEqual(recorded["result"]["candidate_id"], candidate_id)
                self.assertEqual(recorded["authority"], "none")
        status["write_operations"] = ["different-operation"]
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator._run_gateway",
                    return_value=json.dumps(status).encode()),
              patch("employee_read_demo.task_create_operator.search_jules_created_child") as search,
              self.assertRaises(OperatorDenied)):
            search_planned_created_child(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, write_evidence_path=self.root / "evidence",
                grant_path=self.root / "grant", credential_pins_path=self.root / "pins",
                report_path=self.task_dir / "recovery-search-refused.json", now=self.now,
            )
            search.assert_not_called()

        status["write_operations"] = ["create-1"]
        incomplete_report = self.task_dir / "recovery-search-incomplete.json"
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator._run_gateway",
                    return_value=json.dumps(status).encode()),
              patch("employee_read_demo.task_create_operator.search_jules_created_child",
                    side_effect=ContractRejected("incompleteSearch")),
              self.assertRaisesRegex(OperatorDenied, "search is incomplete")):
            search_planned_created_child(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, write_evidence_path=self.root / "evidence",
                grant_path=self.root / "grant", credential_pins_path=self.root / "pins",
                report_path=incomplete_report, now=self.now,
            )
        self.assertFalse(incomplete_report.exists())

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

    def test_v3_baseline_is_pinned_before_six_child_create(self) -> None:
        self.evidence.update({
            "customer_id": "customer-1", "jules_subject": "jules-subject",
            "drive_id": "drive-A", "folder_id": "project-a-folder",
        })
        self.pins.producer.evidence_sha256 = "f" * 64
        generation = self.root / "generation-0016"
        generation.mkdir(mode=0o700)
        baseline = generation / "google-create-v3-baseline.json"
        self._write(baseline, {"observed_at": self.observation["observed_at"]})
        baseline_sha = hashlib.sha256(baseline.read_bytes()).hexdigest()
        roles = ("working", "jules_probe", "preserved_first",
                 "second_auths", "clean_edit")
        pins_path = self.root / "v3-pins.json"
        self._write(pins_path, {
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject", "drive_id": "drive-A",
            "folder_id": "project-a-folder",
            "source_verification_sha256": "f" * 64,
            "source_v2_final_sha256": "1" * 64,
            "source_edit_final_sha256": "2" * 64,
            "source_working_observation_sha256": "3" * 64,
            "baseline_generation": 16, "baseline_sha256": baseline_sha,
            "neighbors": [{"role": role,
                           "document_id": ("working-doc" if index == 0
                                           else f"neighbor-{index}"),
                           "raw_content_sha256": f"{index + 4:x}" * 64,
                           "raw_content_byte_count": 10 + index}
                          for index, role in enumerate(roles)],
            "preserved_marker": "ap071_" + "a" * 32,
            "second_marker": "ap071_" + "b" * 32,
        })
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.validate_create_v3_precreate_baseline",
                    return_value={"observed_at": self.observation["observed_at"]}),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, b'{"outcome":"response-recorded"}', b"",
                    )) as gateway):
            result = submit_planned_create(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, write_evidence_path=self.root / "evidence",
                credential_pins_path=self.root / "pins",
                baseline_path=baseline, baseline_sha256=baseline_sha,
                v3_pins_path=pins_path, now=self.now,
            )
            self.assertEqual(result["baseline_generation"], 16)
            record = json.loads((self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(record["schema"], "auths.ap071-pre-create-baseline/3")
            self.assertTrue(_recorded_baseline_is_valid(record, self.task_id))
            gateway.assert_called_once()

    def test_v4_baseline_is_durable_before_seventh_child_create(self) -> None:
        self.evidence.update({
            "customer_id": "customer-1", "jules_subject": "jules-subject",
            "drive_id": "drive-A", "folder_id": "project-a-folder",
        })
        self.pins.producer.evidence_sha256 = "f" * 64
        generation = self.root / "generation-0021"
        generation.mkdir(mode=0o700)
        baseline = generation / "google-create-v4-baseline.json"
        self._write(baseline, {"observed_at": self.observation["observed_at"]})
        baseline_sha = hashlib.sha256(baseline.read_bytes()).hexdigest()
        roles = ("working", "jules_probe", "preserved_first", "second_auths",
                 "clean_edit", "recovered_first")
        pins_path = self.root / "v4-pins.json"
        self._write(pins_path, {
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject", "drive_id": "drive-A",
            "folder_id": "project-a-folder",
            "source_verification_sha256": "f" * 64,
            "source_v3_baseline_generation": 18,
            "source_v3_baseline_sha256": "1" * 64,
            "source_v3_final_generation": 20,
            "source_v3_final_sha256": "2" * 64,
            "baseline_generation": 21, "baseline_sha256": baseline_sha,
            "neighbors": [{"role": role,
                           "document_id": ("working-doc" if index == 0
                                           else f"neighbor-{index}"),
                           "raw_content_sha256": f"{index + 3:x}" * 64,
                           "raw_content_byte_count": 10 + index}
                          for index, role in enumerate(roles)],
            "prior_markers": ["ap071_" + value * 32 for value in "abc"],
        })

        def entered(command, **kwargs):
            record = json.loads((self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(record["schema"], "auths.ap071-pre-create-baseline/4")
            self.assertEqual(record["generation"], 21)
            self.assertTrue(_recorded_baseline_is_valid(record, self.task_id))
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"response-recorded"}', b"",
            )

        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.validate_create_v4_precreate_baseline",
                    return_value={"observed_at": self.observation["observed_at"]}),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=entered) as gateway):
            result = submit_planned_create(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id, write_evidence_path=self.root / "evidence",
                credential_pins_path=self.root / "pins",
                baseline_path=baseline, baseline_sha256=baseline_sha,
                v4_pins_path=pins_path, now=self.now,
            )
            self.assertEqual(result["baseline_generation"], 21)
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                submit_planned_create(
                    gateway_binary=self.root / "gateway",
                    gateway_sha256="e" * 64,
                    gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                    task_id=self.task_id, write_evidence_path=self.root / "evidence",
                    credential_pins_path=self.root / "pins",
                    baseline_path=baseline, baseline_sha256=baseline_sha,
                    v4_pins_path=pins_path, now=self.now,
                )
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
                    side_effect=[
                        subprocess.CompletedProcess([], 1, b"", b"unbound"),
                        subprocess.CompletedProcess(
                            [], 0, json.dumps({
                                "schema": "auths.gateway-child-reconciliation/1",
                                "outcome": "child-bound", "child_id": "child-1",
                            }).encode(), b"",
                        ),
                    ]) as gateway):
            result = reconcile_planned_child(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id,
            )
            self.assertEqual(result["child_id"], "child-1")
            self.assertEqual(result["baseline_generation"], 2)
            command = gateway.call_args_list[1].args[0]
            self.assertEqual(command[1], "task-reconcile-child")
            self.assertNotIn("task-submit", command)
            self.assertNotIn("--confirmation-proof", command)
            self.assertEqual(command[command.index("--agent-action") + 1],
                             str(self.task_dir / "agent.action"))
            self.assertEqual(gateway.call_count, 2)

    def test_recorded_create_binding_is_read_without_second_reconcile(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, b'{"outcome":"observed","status":200}', b"",
                    ))):
            self._submit()
        bound = {
            "schema": "auths.gateway-task-populate-preflight-inputs/1",
            "task_id": self.task_id, "create_operation_id": "create-1",
            "parent_id": "project-a-folder", "marker": "ap071_" + "c" * 32,
            "child_id": "child-1",
        }
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps(bound).encode(), b"",
                    )) as gateway):
            result = reconcile_planned_child(
                gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
                gateway_state_dir=self.state_dir, task_dir=self.task_dir,
                task_id=self.task_id,
            )
            self.assertEqual(result["child_id"], "child-1")
            self.assertEqual(gateway.call_count, 1)
            self.assertEqual(gateway.call_args.args[0][1],
                             "task-populate-preflight-inputs")

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
