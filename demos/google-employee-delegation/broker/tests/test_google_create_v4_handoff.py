"""The v4 producer joins one blank seventh child to one final observation."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_v4_handoff import (
    CreateV4BaselinePins, CreateV4CandidateBlankPins, CreateV4FinalPins,
    CreateV4NeighborPins, validate_create_v4_candidate_blank,
    validate_create_v4_observation, validate_create_v4_precreate_baseline,
    validate_create_v4_recovery_handoff,
)
from employee_read_demo.task_recovery_operator import (
    _candidate_pins, attest_response_less_candidate,
    current_recovery_attestation_rule_digest,
)


class CreateV4ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.at = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
        self.baseline_path = self.root / "generation-0021" / "google-create-v4-baseline.json"
        self.candidate_path = (self.root / "generation-0022" /
                               "google-create-v4-candidate-blank.json")
        self.final_path = self.root / "generation-0023" / "google-create-observation-v4.json"
        for path in (self.baseline_path, self.candidate_path, self.final_path):
            path.parent.mkdir(mode=0o700)
        roles = ("working", "jules_probe", "preserved_first", "second_auths",
                 "clean_edit", "recovered_first")
        self.neighbors = tuple(CreateV4NeighborPins(
            role, f"doc-{index}", f"{index + 1:x}" * 64, 10 + index,
        ) for index, role in enumerate(roles))
        markers = tuple("ap071_" + value * 32 for value in "abc")
        common = {
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "customer_id": "customer-1",
            "jules_subject": "subject-1", "drive_id": "drive-A",
            "folder_id": "folder-A",
        }
        self.baseline = common | {
            "schema_version": "demo-co/google-create-v4-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": self.at.isoformat(), "direct_child_count": 6,
            "neighbors": [asdict(item) for item in self.neighbors],
            "prior_markers": list(markers),
            "source_v3_baseline_generation": 18,
            "source_v3_baseline_sha256": "2" * 64,
            "source_v3_final_generation": 20,
            "source_v3_final_sha256": "3" * 64,
            "source_verification_sha256": "4" * 64,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        baseline_sha = self._write(self.baseline_path, self.baseline)
        self.baseline_pins = CreateV4BaselinePins(
            **common, source_verification_sha256="4" * 64,
            source_v3_baseline_generation=18,
            source_v3_baseline_sha256="2" * 64,
            source_v3_final_generation=20,
            source_v3_final_sha256="3" * 64,
            baseline_generation=21, baseline_sha256=baseline_sha,
            neighbors=self.neighbors, prior_markers=markers,
        )
        self.candidate = common | {
            "schema_version": "demo-co/google-create-v4-candidate-blank/v1",
            "status": "observed_blank", "attribution": "provider_state_only",
            "observed_at": (self.at + timedelta(minutes=2)).isoformat(),
            "baseline_generation": 21, "baseline_sha256": baseline_sha,
            "baseline_observed_at": self.baseline["observed_at"],
            "direct_child_count": 7, "candidate_id": "doc-new",
            "candidate_title": CHILD_TITLE,
            "candidate_created_at": (self.at + timedelta(minutes=1)).isoformat(),
            "candidate_marker": "ap071_" + "d" * 32,
            "candidate_marker_match_count": 1,
            "candidate_tab_id": "tab-1", "candidate_admin_revision_id": "rev-1",
            "blank_layout": "section-break-then-newline-paragraph/v1",
            "blank_export_sha256": hashlib.sha256(b"\xef\xbb\xbf").hexdigest(),
            "blank_export_byte_count": 3, "neighbors_match_baseline": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        candidate_sha = self._write(self.candidate_path, self.candidate)
        self.candidate_pins = CreateV4CandidateBlankPins(
            baseline=self.baseline_pins, observation_generation=22,
            observation_sha256=candidate_sha, candidate_id="doc-new",
            marker="ap071_" + "d" * 32,
        )
        self.final = common | {
            "schema_version": "demo-co/google-create-observation/v4",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": (self.at + timedelta(minutes=3)).isoformat(),
            "baseline_generation": 21, "baseline_sha256": baseline_sha,
            "candidate_generation": 22, "candidate_sha256": candidate_sha,
            "baseline_observed_at": self.baseline["observed_at"],
            "direct_child_count": 7, "new_child_id": "doc-new",
            "new_child_title": CHILD_TITLE,
            "new_child_created_at": self.candidate["candidate_created_at"],
            "new_marker": "ap071_" + "d" * 32,
            "new_marker_match_count": 1, "new_tab_id": "tab-1",
            "new_admin_revision_id": "rev-2", "new_content_sha256": "5" * 64,
            "new_content_byte_count": 44, "exact_expected_content": True,
            "neighbors_match_baseline": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        final_sha = self._write(self.final_path, self.final)
        self.final_pins = CreateV4FinalPins(
            candidate=self.candidate_pins, observation_generation=23,
            observation_sha256=final_sha,
            new_content_sha256="5" * 64, new_content_byte_count=44,
        )

    @staticmethod
    def _write(path: Path, value: dict) -> str:
        raw = json.dumps(value, sort_keys=True).encode()
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def test_exact_six_to_seven_evidence_and_private_pin_decoder(self) -> None:
        baseline = validate_create_v4_precreate_baseline(
            self.baseline_path, self.baseline_pins,
            now=int((self.at + timedelta(minutes=1)).timestamp()),
        )
        self.assertEqual(baseline["direct_child_count"], 6)
        candidate = validate_create_v4_candidate_blank(
            self.baseline_path, self.candidate_path, self.candidate_pins,
        )
        self.assertEqual(candidate["candidate_id"], "doc-new")
        validate_create_v4_observation(
            self.baseline_path, self.candidate_path, self.final_path,
            self.final_pins,
        )
        pin_path = self.root / "candidate-pins.json"
        self._write(pin_path, asdict(self.candidate_pins))
        self.assertEqual(_candidate_pins(pin_path), self.candidate_pins)

    def test_changed_lineage_candidate_and_final_are_refused(self) -> None:
        with self.assertRaisesRegex(ContractRejected, "stale"):
            validate_create_v4_precreate_baseline(
                self.baseline_path, self.baseline_pins,
                now=int((self.at + timedelta(minutes=6)).timestamp()),
            )
        altered = self.baseline | {"source_v3_final_sha256": "0" * 64}
        changed_sha = self._write(self.baseline_path, altered)
        with self.assertRaises(ContractRejected):
            validate_create_v4_precreate_baseline(
                self.baseline_path,
                replace(self.baseline_pins, baseline_sha256=changed_sha),
                now=int((self.at + timedelta(minutes=1)).timestamp()),
            )
        self._write(self.baseline_path, self.baseline)
        for change in (
            {"candidate_id": "other-child"},
            {"blank_export_sha256": "0" * 64},
            {"jules_project_b_write_denied": False},
        ):
            with self.subTest(change=change):
                digest = self._write(self.candidate_path, self.candidate | change)
                with self.assertRaises(ContractRejected):
                    validate_create_v4_candidate_blank(
                        self.baseline_path, self.candidate_path,
                        replace(self.candidate_pins, observation_sha256=digest),
                    )
        self._write(self.candidate_path, self.candidate)
        for change in (
            {"candidate_sha256": "0" * 64},
            {"new_child_id": "other-child"},
            {"exact_expected_content": False},
            {"new_content_byte_count": 45},
        ):
            with self.subTest(change=change):
                digest = self._write(self.final_path, self.final | change)
                with self.assertRaises(ContractRejected):
                    validate_create_v4_observation(
                        self.baseline_path, self.candidate_path,
                        self.final_path,
                        replace(self.final_pins, observation_sha256=digest),
                    )

    def test_recovery_join_rejects_nonunique_or_wrong_search(self) -> None:
        report_path = self.root / "recovery-search-v4.json"
        report = {
            "schema": "auths.ap071-create-recovery-search/1",
            "task_id": "task-1", "create_operation_id": "create-1",
            "baseline_sha256": self.baseline_pins.baseline_sha256,
            "authority": "none",
            "result": {
                "candidate_id": "doc-new", "candidate_count": 1,
                "parent_id": "folder-A", "drive_id": "drive-A",
                "marker_value": "ap071_" + "d" * 32,
                "page_sha256": ["6" * 64], "metadata_sha256": "7" * 64,
                "checked_at": int((self.at + timedelta(minutes=2)).timestamp()),
                "connection_id": "jules-connection", "connection_generation": 1,
                "connection_subject": "subject-1", "status": "single",
            },
        }

        def check(value: dict) -> dict:
            digest = self._write(report_path, value)
            return validate_create_v4_recovery_handoff(
                self.baseline_path, self.candidate_path, report_path,
                self.candidate_pins, task_id="task-1",
                create_operation_id="create-1",
                connection_id="jules-connection", connection_generation=1,
                search_report_sha256=digest,
            )

        self.assertEqual(check(report)["candidate_id"], "doc-new")
        for changed in (
            report | {"baseline_sha256": "0" * 64},
            report | {"result": report["result"] | {"candidate_count": 2}},
            report | {"result": report["result"] | {"status": "zero"}},
            report | {"result": report["result"] | {"marker_value": "ap071_" + "e" * 32}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ContractRejected):
                check(changed)

        check(report)
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        now = int((self.at + timedelta(minutes=3)).timestamp())
        inputs = {
            "schema": "auths.gateway-task-create-recovery-inputs/1",
            "task_id": "task-1", "task_commitment": "8" * 64,
            "plan_commitment": "9" * 64, "content_commitment": "a" * 64,
            "create_operation_id": "create-1", "create_recipe_digest": "b" * 64,
            "action_commitment": "c" * 64, "request_commitment": "d" * 64,
            "populate_recipe_digest": "e" * 64,
            "connection_id": "jules-connection", "connection_generation": 1,
            "connection_subject": "subject-1",
            "recovery_rule_digest": current_recovery_attestation_rule_digest(),
            "recovery_key_sha256": hashlib.sha256(public).hexdigest(),
            "parent_id": "folder-A", "title": CHILD_TITLE,
            "marker": "ap071_" + "d" * 32,
            "plan_expires_at": now + 300,
            "attempt_stage": "unknown", "authority": "none",
        }
        signed = attest_response_less_candidate(
            inputs, self.baseline_path, self.candidate_path,
            report_path, self.candidate_pins,
            search_report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
            signing_key=signer, now=now,
        )
        statement = json.loads(signed)["statement"]
        self.assertEqual(statement["candidate_id"], "doc-new")
        self.assertEqual(statement["producer_observation_sha256"],
                         self.candidate_pins.observation_sha256)


if __name__ == "__main__":
    unittest.main()
