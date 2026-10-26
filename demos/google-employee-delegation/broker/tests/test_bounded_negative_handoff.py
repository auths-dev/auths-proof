from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from employee_read_demo.bounded_negative_handoff import (
    BoundedNegativePins, validate_bounded_negative,
    validate_bounded_negative_observation,
)
from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.edit_rerun_handoff import OPTION_A, OPTION_B
from employee_read_demo.write_handoff import WriteHandoffPins


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def save(path: Path, value: dict) -> str:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
    os.chmod(path, 0o600)
    return digest(path.read_bytes())


class BoundedNegativeHandoffTests(unittest.TestCase):
    def test_accepts_pinned_fixture_and_rejects_tampered_choice(self) -> None:
        now = int(datetime(2026, 10, 26, 2, 0, tzinfo=timezone.utc).timestamp())
        marker = "AP071-NEG-62e394bb6eb62df674bd4035"
        raw_before = b"\xef\xbb\xbf" + marker.encode()
        producer = WriteHandoffPins(
            "atlas-studio", "live-test-atlas", "a" * 64,
            "customer-1", "jules-subject", "jules@example.test", "b" * 64,
        )
        source = {"folder_id": "project-a-folder", "drive_id": "drive-1",
                  "document_id": "source-doc"}
        baseline = {
            "schema_version": "demo-co/google-bounded-negative-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "company": producer.company, "instance": producer.instance,
            "definition_hash": producer.definition_hash,
            "observed_at": "2026-10-26T01:58:00Z",
            "jules_subject": producer.jules_subject,
            "drive_id": source["drive_id"],
            "project_a_folder_id": source["folder_id"],
            "scratch_root_id": "scratch-root",
            "document_id": "scratch-doc",
            "document_title": "Demo Co AP-071 Bounded Upfront Negative",
            "logical_id": "ap071-bounded-upfront-negative-doc",
            "marker": marker, "marker_count": 1,
            "tab_id": "t.0", "jules_revision_id": "revision-1",
            "raw_byte_count": len(raw_before), "raw_sha256": digest(raw_before),
            "exact_scratch_root_children": True,
            "scratch_root_child_count": 5, "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True, "jules_can_edit": True,
            "source_scratch_plan_generation": 38,
            "source_scratch_plan_sha256": "c" * 64,
            "source_v4_baseline_generation": 21,
            "source_v4_baseline_sha256": "d" * 64,
            "source_v4_final_generation": 23,
            "source_v4_final_sha256": "e" * 64,
        }
        choices = {
            "schema_version": "demo-co/google-bounded-negative-choices/v1",
            "status": "ready", "attribution": "precommitted_provider_expectation",
            "company": producer.company, "instance": producer.instance,
            "definition_hash": producer.definition_hash,
            "observed_at": "2026-10-26T01:59:00Z",
            "baseline_generation": 41,
            "baseline_raw_sha256": digest(raw_before),
            "baseline_raw_byte_count": len(raw_before),
            "document_id": baseline["document_id"], "marker": marker,
            "replacement_rule": "replace_single_marker_in_exact_raw_export/v1",
        }
        for letter, replacement in (("a", OPTION_A), ("b", OPTION_B)):
            raw = b"\xef\xbb\xbf" + replacement.encode()
            choices[f"option_{letter}_text_sha256"] = digest(replacement.encode())
            choices[f"option_{letter}_text_byte_count"] = len(replacement.encode())
            choices[f"option_{letter}_expected_raw_sha256"] = digest(raw)
            choices[f"option_{letter}_expected_raw_byte_count"] = len(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_dir = root / "generation-0041"
            choices_dir = root / "generation-0042"
            before_dir.mkdir(mode=0o700)
            choices_dir.mkdir(mode=0o700)
            before_path = before_dir / "google-bounded-negative-baseline.json"
            choices_path = choices_dir / "google-bounded-negative-choices.json"
            baseline_sha = save(before_path, baseline)
            choices["baseline_sha256"] = baseline_sha
            choices_sha = save(choices_path, choices)
            pins = BoundedNegativePins(
                producer, baseline_sha, choices_sha, "scratch-root",
                "c" * 64, "d" * 64, "e" * 64,
            )
            target = validate_bounded_negative(
                before_path, choices_path, pins, source_evidence=source, now=now)
            self.assertEqual(target.document_id, "scratch-doc")
            self.assertEqual([choice["replacement"] for choice in
                              target.allowed_arguments()], [OPTION_A, OPTION_B])

            choices["option_b_expected_raw_sha256"] = "f" * 64
            tampered_sha = save(choices_path, choices)
            with self.assertRaisesRegex(ContractRejected, "choice commitment"):
                validate_bounded_negative(
                    before_path, choices_path, replace(pins, choices_sha256=tampered_sha),
                    source_evidence=source, now=now)
            choices["option_b_expected_raw_sha256"] = digest(
                b"\xef\xbb\xbf" + OPTION_B.encode())
            self.assertEqual(save(choices_path, choices), choices_sha)
            with self.assertRaisesRegex(ContractRejected, "stale"):
                validate_bounded_negative(
                    before_path, choices_path, pins,
                    source_evidence=source, now=now + 3601)

            observation_dir = root / "generation-0043"
            observation_dir.mkdir(mode=0o700)
            observation_path = observation_dir / "google-bounded-negative-observation.json"
            raw_a = b"\xef\xbb\xbf" + OPTION_A.encode()
            observation = {
                "schema_version": "demo-co/google-bounded-negative-observation/v1",
                "status": "option_a_exact", "attribution": "provider_state_only",
                "company": producer.company, "instance": producer.instance,
                "definition_hash": producer.definition_hash,
                "observed_at": "2026-10-26T02:00:00Z",
                "baseline_generation": 41, "baseline_sha256": baseline_sha,
                "choices_generation": 42, "choices_sha256": choices_sha,
                "drive_id": source["drive_id"],
                "project_a_folder_id": source["folder_id"],
                "scratch_root_id": "scratch-root", "document_id": "scratch-doc",
                "tab_id": "t.0", "marker": marker, "selected_choice": "A",
                "raw_sha256": digest(raw_a), "raw_byte_count": len(raw_a),
                "final_admin_revision_id": "revision-2",
                "final_jules_revision_id": "revision-2",
                "revision_changed_from_baseline": True,
                "jules_export_matches_admin": True,
                "exact_expected_content": True, "provider_entry_attested": False,
                "original_marker_count": 0,
                "scratch_root_child_count": 5,
                "exact_scratch_root_children": True,
                "original_seven_unchanged": True,
                "canonical_project_a_unchanged": True,
                "canonical_project_b_unchanged": True,
            }
            observation_sha = save(observation_path, observation)
            accepted = validate_bounded_negative_observation(
                observation_path, observation_sha256=observation_sha,
                baseline_path=before_path, choices_path=choices_path,
                pins=pins, target=target, task_not_before=now - 60, now=now)
            self.assertEqual((accepted.raw_sha256, accepted.raw_byte_count),
                             (digest(raw_a), len(raw_a)))
            observation["raw_sha256"] = "f" * 64
            tampered_sha = save(observation_path, observation)
            with self.assertRaisesRegex(ContractRejected, "after-state"):
                validate_bounded_negative_observation(
                    observation_path, observation_sha256=tampered_sha,
                    baseline_path=before_path, choices_path=choices_path,
                    pins=pins, target=target, task_not_before=now - 60, now=now)
