"""Frozen v3 producer evidence must match the five-child operator baseline."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_v3_handoff import (
    CreateV3BaselinePins, CreateV3CandidateBlankPins, CreateV3FinalPins,
    CreateV3NeighborPins, validate_create_v3_candidate_blank,
    validate_create_v3_observation, validate_create_v3_precreate_baseline,
)


class CreateV3ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.baseline_at = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
        self.baseline_path = (self.root / "generation-0016" /
                              "google-create-v3-baseline.json")
        self.baseline_path.parent.mkdir()
        self.final_path = (self.root / "generation-0017" /
                           "google-create-observation-v3.json")
        self.final_path.parent.mkdir()
        self.neighbors = tuple(CreateV3NeighborPins(
            role, f"doc-{index}", f"{index + 1:x}" * 64, 10 + index,
        ) for index, role in enumerate((
            "working", "jules_probe", "preserved_first", "second_auths",
            "clean_edit",
        )))
        self.baseline = {
            "schema_version": "demo-co/google-create-v3-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "a" * 64,
            "observed_at": self.baseline_at.isoformat(),
            "customer_id": "customer-1", "jules_subject": "subject-1",
            "drive_id": "drive-A", "folder_id": "folder-A",
            "direct_child_count": 5,
            "neighbors": [asdict(item) for item in self.neighbors],
            "preserved_marker": "ap071_" + "a" * 32,
            "second_marker": "ap071_" + "b" * 32,
            "source_verification_sha256": "c" * 64,
            "source_v2_final_sha256": "d" * 64,
            "source_edit_final_sha256": "e" * 64,
            "source_working_observation_sha256": "f" * 64,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        baseline_sha = self._write(self.baseline_path, self.baseline)
        self.pins = CreateV3BaselinePins(
            company="atlas-studio", instance="test-instance",
            definition_hash="a" * 64, customer_id="customer-1",
            jules_subject="subject-1", drive_id="drive-A",
            folder_id="folder-A", source_verification_sha256="c" * 64,
            source_v2_final_sha256="d" * 64,
            source_edit_final_sha256="e" * 64,
            source_working_observation_sha256="f" * 64,
            baseline_generation=16, baseline_sha256=baseline_sha,
            neighbors=self.neighbors,
            preserved_marker="ap071_" + "a" * 32,
            second_marker="ap071_" + "b" * 32,
        )
        self.final = {
            "schema_version": "demo-co/google-create-observation/v3",
            "status": "ready", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "a" * 64,
            "observed_at": (self.baseline_at + timedelta(minutes=2)).isoformat(),
            "baseline_generation": 16, "baseline_sha256": baseline_sha,
            "baseline_observed_at": self.baseline["observed_at"],
            "customer_id": "customer-1", "jules_subject": "subject-1",
            "drive_id": "drive-A", "folder_id": "folder-A",
            "direct_child_count": 6, "new_child_id": "doc-new",
            "new_child_title": CHILD_TITLE,
            "new_child_created_at":
                (self.baseline_at + timedelta(minutes=1)).isoformat(),
            "new_marker": "ap071_" + "c" * 32,
            "new_marker_match_count": 1,
            "new_tab_id": "tab-1", "new_admin_revision_id": "rev-1",
            "new_content_sha256": "1" * 64,
            "new_content_byte_count": 42,
            "neighbors_match_baseline": True,
            "preserved_marker_match_count": 1,
            "second_marker_match_count": 1,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        final_sha = self._write(self.final_path, self.final)
        self.final_pins = CreateV3FinalPins(
            baseline=self.pins, observation_generation=17,
            observation_sha256=final_sha,
            new_child_id="doc-new", new_marker="ap071_" + "c" * 32,
            new_content_sha256="1" * 64, new_content_byte_count=42,
        )
        self.candidate_path = self.final_path.with_name(
            "google-create-v3-candidate-blank.json",
        )
        self.candidate = {
            "schema_version": "demo-co/google-create-v3-candidate-blank/v1",
            "status": "observed_blank", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "a" * 64,
            "observed_at": (self.baseline_at + timedelta(minutes=2)).isoformat(),
            "baseline_generation": 16, "baseline_sha256": baseline_sha,
            "baseline_observed_at": self.baseline["observed_at"],
            "customer_id": "customer-1", "jules_subject": "subject-1",
            "drive_id": "drive-A", "folder_id": "folder-A",
            "direct_child_count": 6, "candidate_id": "doc-new",
            "candidate_title": CHILD_TITLE,
            "candidate_created_at":
                (self.baseline_at + timedelta(minutes=1)).isoformat(),
            "candidate_marker": "ap071_" + "c" * 32,
            "candidate_marker_match_count": 1,
            "candidate_tab_id": "tab-1", "candidate_admin_revision_id": "rev-1",
            "blank_export_sha256": hashlib.sha256(b"\xef\xbb\xbf").hexdigest(),
            "blank_export_byte_count": 3,
            "blank_layout": "section-break-then-newline-paragraph/v1",
            "neighbors_match_baseline": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        candidate_sha = self._write(self.candidate_path, self.candidate)
        self.candidate_pins = CreateV3CandidateBlankPins(
            baseline=self.pins, observation_generation=17,
            observation_sha256=candidate_sha, candidate_id="doc-new",
            marker="ap071_" + "c" * 32,
        )

    @staticmethod
    def _write(path: Path, value: dict) -> str:
        raw = json.dumps(value, sort_keys=True).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_exact_five_child_baseline_and_six_child_final(self) -> None:
        observed = validate_create_v3_precreate_baseline(
            self.baseline_path, self.pins,
            now=int((self.baseline_at + timedelta(minutes=1)).timestamp()),
        )
        self.assertEqual(observed["direct_child_count"], 5)
        validate_create_v3_observation(
            self.baseline_path, self.final_path, self.final_pins,
        )

    def test_stale_or_changed_baseline_and_late_child_are_refused(self) -> None:
        with self.assertRaisesRegex(ContractRejected, "stale"):
            validate_create_v3_precreate_baseline(
                self.baseline_path, self.pins,
                now=int((self.baseline_at + timedelta(minutes=6)).timestamp()),
            )
        self.baseline["neighbors"][4]["document_id"] = "unexpected-child"
        changed_sha = self._write(self.baseline_path, self.baseline)
        changed_pins = replace(self.pins, baseline_sha256=changed_sha)
        with self.assertRaisesRegex(ContractRejected, "fixture pins"):
            validate_create_v3_precreate_baseline(
                self.baseline_path, changed_pins,
                now=int((self.baseline_at + timedelta(minutes=1)).timestamp()),
            )
        self._write(self.baseline_path, self.baseline | {
            "neighbors": [asdict(item) for item in self.neighbors],
        })
        self.final["new_child_created_at"] = (
            self.baseline_at + timedelta(minutes=6)).isoformat()
        self.final["observed_at"] = (
            self.baseline_at + timedelta(minutes=7)).isoformat()
        late_sha = self._write(self.final_path, self.final)
        with self.assertRaisesRegex(ContractRejected, "five-minute window"):
            validate_create_v3_observation(
                self.baseline_path, self.final_path,
                replace(self.final_pins, observation_sha256=late_sha),
            )

    def test_exact_blank_candidate_and_tampering_are_refused(self) -> None:
        observed = validate_create_v3_candidate_blank(
            self.baseline_path, self.candidate_path, self.candidate_pins,
        )
        self.assertEqual(observed["candidate_id"], "doc-new")
        for change in (
            {"candidate_marker": "ap071_" + "d" * 32},
            {"neighbors_match_baseline": False},
            {"blank_export_byte_count": 4},
            {"blank_export_sha256": "0" * 64},
            {"candidate_id": "another-child"},
            {"baseline_sha256": "0" * 64},
            {"candidate_created_at":
                (self.baseline_at + timedelta(minutes=6)).isoformat()},
        ):
            with self.subTest(change=change):
                altered = self.candidate | change
                digest = self._write(self.candidate_path, altered)
                with self.assertRaises(ContractRejected):
                    validate_create_v3_candidate_blank(
                        self.baseline_path, self.candidate_path,
                        replace(self.candidate_pins, observation_sha256=digest),
                    )
        self._write(self.candidate_path, self.candidate)


if __name__ == "__main__":
    unittest.main()
