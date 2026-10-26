"""A negative search records a refusal and never grants a created child."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_negative_handoff import (
    CreateNegativePins, NegativeCreateTarget,
)
from employee_read_demo.google_create_preflight import JulesCreateRecoverySearchResult
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_negative_recovery_operator import (
    join_negative_refusal_observation, record_negative_create_refusal,
)


class NegativeRecoveryOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task_id = "task-negative"
        self.task_dir = self.root / self.task_id
        self.task_dir.mkdir(mode=0o700)
        self.marker = "ap071_" + "e" * 32
        self.credential = SimpleNamespace(
            producer=SimpleNamespace(jules_subject="jules-subject"),
            connection_id="jules-connection", connection_generation=1,
        )
        self._write("task-card.json", {
            "task_id": self.task_id,
            "connection_subject": "jules-subject",
            "pending_child": {
                "parent_handle": "scratch-run", "title": CHILD_TITLE,
                "marker": self.marker, "create_operation_id": "create-1",
            },
        })
        self._write("effect-plan.json", {
            "create": {
                "operation_id": "create-1", "resource_handle": "scratch-run",
                "connection_id": "jules-connection",
                "connection_generation": 1,
                "connection_subject": "jules-subject",
            },
        })
        self._write("pre-create-baseline.json", {
            "schema": "auths.ap071-pre-create-baseline-negative/1",
            "task_id": self.task_id,
            "create_operation_id": "create-1", "marker": self.marker,
            "generation": 25, "observation_sha256": "b" * 64,
            "observed_at": "2026-10-26T12:00:00+00:00",
        })

    def _write(self, name: str, document: dict) -> None:
        path = self.task_dir / name
        path.write_bytes(json.dumps(document).encode())
        os.chmod(path, 0o600)

    def _run(self, case: str, *, wrong_writes: bool = False):
        target = NegativeCreateTarget(
            "run-one", case, self.marker, "scratch-run", 24, "a" * 64,
        )
        writes = 0 if case == "zero" else 1
        status = {
            "schema": "auths.gateway-agent-task-status/1",
            "task_id": self.task_id,
            "writes": writes + int(wrong_writes),
            "write_operations": [] if writes == 0 else ["create-1"],
            "provider_calls": 0, "releases": 0,
        }
        recovery = {
            "schema": "auths.gateway-task-create-recovery-inputs/1",
            "task_id": self.task_id, "attempt_stage": "unknown",
            "authority": "none", "parent_id": "scratch-run",
            "marker": self.marker, "title": CHILD_TITLE,
            "create_operation_id": "create-1",
            "connection_subject": "jules-subject",
        }
        search = JulesCreateRecoverySearchResult(
            None, 0 if case == "zero" else 2, "scratch-run",
            "drive-1", self.marker, ("c" * 64,), None, 1000,
            "jules-connection", 1, "jules-subject",
        )

        def gateway(*args):
            command = args[3]
            return recovery if command == "task-create-recovery-inputs" else status

        with (patch("employee_read_demo.task_negative_recovery_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_negative_recovery_operator._credential_pins",
                    return_value=self.credential),
              patch("employee_read_demo.task_negative_recovery_operator."
                    "load_v4_final_pins", return_value=object()),
              patch("employee_read_demo.task_negative_recovery_operator."
                    "validate_negative_precreate_baseline",
                    return_value=(target, 25, {})),
              patch("employee_read_demo.task_negative_recovery_operator._gateway_json",
                    side_effect=gateway),
              patch("employee_read_demo.task_negative_recovery_operator."
                    "search_jules_created_child",
                    side_effect=(ContractRejected("incompleteSearch")
                                 if case == "incomplete" else None),
                    return_value=search) as provider):
            args = dict(
                gateway_binary=self.root / "gateway",
                gateway_sha256="d" * 64,
                gateway_state_dir=self.root / "state",
                task_dir=self.task_dir, task_id=self.task_id,
                write_evidence_path=self.root / "evidence",
                credential_pins_path=self.root / "credential-pins",
                grant_path=self.root / "grant",
                source_v4_paths=tuple(self.root / f"source-{index}"
                                      for index in range(3)),
                v4_pins_path=self.root / "v4-pins",
                setup_path=self.root / "setup",
                setup_sha256="a" * 64,
                baseline_path=self.root / "baseline",
                baseline_sha256="b" * 64,
                inject_incomplete_search_for_test=case == "incomplete",
                now=1000,
            )
            if wrong_writes:
                with self.assertRaisesRegex(OperatorDenied, "attempt count"):
                    record_negative_create_refusal(**args)
                provider.assert_not_called()
                return None
            result = record_negative_create_refusal(**args)
            provider.assert_called_once()
            return result

    def test_zero_and_multiple_record_no_child_authority(self) -> None:
        for case in ("zero", "multiple"):
            with self.subTest(case=case):
                report = self._run(case)
                self.assertEqual(report["search_status"], case)
                self.assertEqual(report["authority"], "none")
                self.assertFalse(report["child_bound"])
                self.assertTrue((self.task_dir / "negative-refusal.json").is_file())
                (self.task_dir / "negative-refusal.json").unlink()

    def test_incomplete_fault_is_labeled_and_wrong_count_stops_search(self) -> None:
        self._run("multiple", wrong_writes=True)
        report = self._run("incomplete")
        self.assertEqual(report["search_status"], "injected-incomplete")
        self.assertTrue(report["injected_incomplete_search"])
        self.assertIsNone(report["candidate_count"])

    def test_join_keeps_provider_inventory_separate_from_auths_refusal(self) -> None:
        refusal = self._run("multiple")
        pins = CreateNegativePins(
            object(), "run-one", "multiple", self.marker,
            "scratch-root", "scratch-run", "seed", 24, "a" * 64,
            25, "b" * 64, 26, "c" * 64,
        )
        paths = tuple(self.root / f"source-{index}" for index in range(3))
        kwargs = dict(
            task_dir=self.task_dir, task_id=self.task_id,
            source_v4_paths=paths, setup_path=self.root / "setup",
            baseline_path=self.root / "baseline",
            observation_path=self.root / "after", pins=pins,
        )
        with patch("employee_read_demo.task_negative_recovery_operator."
                   "validate_create_recovery_negative_observation",
                   return_value={
                       "case": "multiple", "run_id": "run-one",
                       "authority": "none", "provider_match_count": 2,
                       "new_child_ids": ["new"],
                   }):
            joined = join_negative_refusal_observation(**kwargs)
            self.assertEqual(joined["provider_match_count"], 2)
            self.assertEqual(joined["authority"], "none")
        (self.task_dir / "negative-joined.json").unlink()
        self._write("negative-refusal.json", refusal | {"candidate_count": 1})
        with patch("employee_read_demo.task_negative_recovery_operator."
                   "validate_create_recovery_negative_observation",
                   return_value={
                       "case": "multiple", "run_id": "run-one",
                       "authority": "none", "provider_match_count": 2,
                       "new_child_ids": ["new"],
                   }):
            with self.assertRaisesRegex(OperatorDenied, "count"):
                join_negative_refusal_observation(**kwargs)
