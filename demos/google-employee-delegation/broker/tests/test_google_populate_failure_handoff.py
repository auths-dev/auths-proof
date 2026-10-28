"""The population-failure setup names only a pinned scratch run."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_v4_handoff import (
    CreateV4BaselinePins, CreateV4CandidateBlankPins, CreateV4FinalPins,
    CreateV4NeighborPins,
)
from employee_read_demo.google_populate_failure_handoff import (
    join_populate_denial_recovery, validate_populate_failure_setup,
    validate_populate_precreate_baseline,
)


class PopulateFailureSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        source = CreateV4BaselinePins(
            company="atlas-studio", instance="test-instance",
            definition_hash="1" * 64, customer_id="customer-1",
            jules_subject="jules-1", drive_id="drive-1", folder_id="project-a",
            source_verification_sha256="2" * 64,
            source_v3_baseline_generation=18,
            source_v3_baseline_sha256="3" * 64,
            source_v3_final_generation=20,
            source_v3_final_sha256="4" * 64,
            baseline_generation=21, baseline_sha256="5" * 64,
            neighbors=tuple(CreateV4NeighborPins(
                role, f"old-{index}", "1" * 64, 8,
            ) for index, role in enumerate((
                "working", "jules_probe", "preserved_first", "second_auths",
                "clean_edit", "recovered_first",
            ))),
            prior_markers=tuple("ap071_" + char * 32 for char in "ade"),
        )
        candidate = CreateV4CandidateBlankPins(
            source, 22, "6" * 64, "old-seventh", "ap071_" + "b" * 32,
        )
        self.v4 = CreateV4FinalPins(candidate, 23, "7" * 64, "8" * 64, 40)
        self.source_paths = tuple(self.root / f"source-{index}" for index in range(3))
        self.setup_path = (self.root / "generation-0033"
                           / "google-populate-failure-setup.json")
        self.setup = {
            "schema_version": "demo-co/google-populate-failure-setup/v1",
            "status": "ready", "attribution": "producer_setup_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-1",
            "project_a_folder_id": "project-a", "jules_subject": "jules-1",
            "source_v4_baseline_generation": 21,
            "source_v4_baseline_sha256": "5" * 64,
            "source_v4_final_generation": 23,
            "source_v4_final_sha256": "7" * 64,
            "run_id": "populate-drop", "marker": "ap071_" + "c" * 32,
            "scratch_root_id": "scratch-root", "run_folder_id": "run-folder",
            "observed_at": "2026-10-26T12:00:00+00:00",
        }

    def _write(self) -> str:
        self.setup_path.parent.mkdir(mode=0o700, exist_ok=True)
        raw = json.dumps(self.setup, sort_keys=True).encode()
        self.setup_path.write_bytes(raw)
        os.chmod(self.setup_path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def _validate(self, digest: str):
        with patch(
            "employee_read_demo.google_populate_failure_handoff."
            "validate_create_v4_observation",
        ):
            return validate_populate_failure_setup(
                *self.source_paths, self.setup_path, digest, self.v4,
            )

    def test_pinned_setup_identifies_only_one_scratch_run(self) -> None:
        target = self._validate(self._write())
        self.assertEqual(target.parent_id, "run-folder")
        self.assertEqual(target.marker, "ap071_" + "c" * 32)
        self.assertEqual(target.setup_generation, 33)
        self.assertEqual(target.case, "populate-failure")

    def test_changed_bytes_and_reused_marker_are_refused(self) -> None:
        digest = self._write()
        self.setup["marker"] = "ap071_" + "b" * 32
        self._write()
        with self.assertRaisesRegex(ContractRejected, "pinned bytes"):
            self._validate(digest)
        with self.assertRaisesRegex(ContractRejected, "frozen v4"):
            self._validate(hashlib.sha256(self.setup_path.read_bytes()).hexdigest())

    def test_precreate_requires_fresh_complete_zero_match(self) -> None:
        setup_sha = self._write()
        baseline_path = (self.root / "generation-0034"
                         / "google-populate-precreate-baseline.json")
        baseline_path.parent.mkdir(mode=0o700)
        baseline = {
            "schema_version": "demo-co/google-populate-precreate-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-1",
            "project_a_folder_id": "project-a",
            "scratch_root_id": "scratch-root", "run_folder_id": "run-folder",
            "run_id": "populate-drop", "marker": "ap071_" + "c" * 32,
            "setup_generation": 33, "setup_sha256": setup_sha,
            "project_a_direct_child_count": 8,
            "provider_search_complete": True, "provider_match_count": 0,
            "run_child_count": 0, "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
            "observed_at": "2026-10-26T12:01:00+00:00",
        }

        def check(now: int):
            raw = json.dumps(baseline, sort_keys=True).encode()
            baseline_path.write_bytes(raw)
            os.chmod(baseline_path, 0o600)
            with patch(
                "employee_read_demo.google_populate_failure_handoff."
                "validate_create_v4_observation",
            ):
                return validate_populate_precreate_baseline(
                    *self.source_paths, self.setup_path, setup_sha,
                    baseline_path, hashlib.sha256(raw).hexdigest(), self.v4,
                    now=now,
                )

        self.assertEqual(check(1793016120)[1], 34)
        baseline["provider_search_complete"] = False
        with self.assertRaises(ContractRejected):
            check(1793016120)
        baseline["provider_search_complete"] = True
        with self.assertRaisesRegex(ContractRejected, "stale"):
            check(1793016421)


class PopulateRecoveryJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.task = Path(temporary.name) / "task-1"
        self.task.mkdir(mode=0o700)
        self.plan = {
            "schema": "auths.agent-effect-plan/2", "task_id": "task-1",
            "initial_text": "approved text", "populate_operation_id": "populate-1",
            "create": {"operation_id": "create-1", "resource_handle": "folder-1"},
        }
        self.baseline = {
            "schema": "auths.ap071-pre-create-baseline-populate-failure/1",
            "task_id": "task-1", "create_operation_id": "create-1",
            "parent_id": "folder-1", "marker": "ap071_" + "a" * 32,
            "generation": 34, "observation_sha256": "a" * 64,
        }
        self.entry = {
            "schema": "auths.ap071-populate-entry/1", "task_id": "task-1",
            "child_id": "child-1", "populate_operation_id": "populate-1",
            "baseline_sha256": "a" * 64, "preflight_sha256": "b" * 64,
        }
        self.first = {
            "schema": "auths.ap071-populate-result/1", "task_id": "task-1",
            "populate_operation_id": "populate-1", "outcome": "denied",
        }
        self.recovery_entry = self.entry | {"preflight_sha256": "c" * 64}
        self.recovery_result = self.first | {"outcome": "response-recorded"}
        self.status = {
            "schema": "auths.gateway-agent-task-status/1", "task_id": "task-1",
            "revoked": True, "provider_calls": 1, "releases": 1,
            "released_bytes": 51, "writes": 2,
            "write_operations": ["create-1", "populate-1"],
        }
        self.claims = [
            {"operation_id": "create-1", "stage": "observed",
             "response_status": 200},
            {"operation_id": "populate-1", "stage": "response-recorded",
             "response_status": 200},
        ]
        self.provider = {
            "authority": "provider_state_only", "child_id": "child-1",
            "precreate_generation": 34, "recovery_generation": 37,
            "precreate_sha256": "a" * 64, "run_folder_id": "folder-1",
            "marker": "ap071_" + "a" * 32,
            "expected_raw_sha256": hashlib.sha256(
                b"\xef\xbb\xbfapproved text").hexdigest(),
        }
        self._save()

    def _save(self) -> None:
        for name, document in (
            ("effect-plan.json", self.plan),
            ("pre-create-baseline.json", self.baseline),
            ("populate-entry.json", self.entry),
            ("populate-result.json", self.first),
            ("populate-recovery-entry.json", self.recovery_entry),
            ("populate-recovery-result.json", self.recovery_result),
        ):
            path = self.task / name
            path.write_text(json.dumps(document, sort_keys=True))
            path.chmod(0o600)

    def test_one_denial_then_one_same_child_population_is_joined(self) -> None:
        result = join_populate_denial_recovery(
            self.task, self.status, self.claims, self.provider,
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["denied_population_provider_entries"], 0)

    def test_changed_child_or_extra_provider_entry_is_refused(self) -> None:
        self.recovery_entry["child_id"] = "child-2"
        self._save()
        with self.assertRaises(ContractRejected):
            join_populate_denial_recovery(
                self.task, self.status, self.claims, self.provider,
            )
        self.recovery_entry["child_id"] = "child-1"
        self._save()
        with self.assertRaises(ContractRejected):
            join_populate_denial_recovery(
                self.task, self.status, self.claims + [self.claims[1]],
                self.provider,
            )


if __name__ == "__main__":
    unittest.main()
