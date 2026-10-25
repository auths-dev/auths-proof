"""The second-create producer stages must agree before Auths accepts them."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_v2_handoff import (
    CreateV2BaselinePins, CreateV2Pins,
    validate_create_v2_observation, validate_create_v2_precreate_baseline,
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class CreateV2HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.common = {
            "company": "atlas-studio", "instance": "live-test-atlas-20261025",
            "definition_hash": "a" * 64, "customer_id": "C0218tf2n",
            "jules_subject": "113654555744401103740",
            "source_verification_sha256": "b" * 64,
            "drive_id": "drive-A", "folder_id": "folder-A",
        }
        self.old_id, self.new_id = "old-child", "new-child"
        self.old_marker, self.new_marker = "ap071_" + "c" * 32, "ap071_" + "d" * 32
        self.old_content_hash = digest(b"preserved first child")
        self.working_hash = digest(b"working document")
        self.new_content_hash = digest(b"new agent draft")
        self.blank = self.common | {
            "schema_version": "demo-co/google-preserved-blank-observation/v1",
            "status": "observed_blank", "attribution": "provider_state_only",
            "observed_at": "2026-10-25T16:47:00Z",
            "original_baseline_generation": 3,
            "original_baseline_sha256": "e" * 64,
            "original_baseline_observed_at": "2026-10-25T16:45:00Z",
            "preserved_child_created_at": "2026-10-25T16:46:00Z",
            "preserved_child_id": self.old_id,
            "preserved_child_title": "Auths AP-071 Project A handoff",
            "preserved_marker": self.old_marker,
            "blank_export_sha256": digest(b"\xef\xbb\xbf"),
            "blank_export_byte_count": 3,
            "blank_layout": "section-break-then-newline-paragraph/v1",
            "direct_child_count": 3, "tab_id": "t.0",
            "admin_revision_id": "old-revision",
            "working_document_sha256": self.working_hash,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        self.baseline = self.common | {
            "schema_version": "demo-co/google-create-v2-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": "2026-10-25T18:00:00Z",
            "preserved_blank_generation": 4,
            "preserved_blank_sha256": "",  # Filled after writing blank.
            "working_document_id": "working-doc",
            "working_content_sha256": self.working_hash,
            "working_content_byte_count": 16,
            "preserved_child_id": self.old_id,
            "preserved_child_title": "Auths AP-071 Project A handoff",
            "preserved_child_created_at": "2026-10-25T16:46:00Z",
            "preserved_marker": self.old_marker,
            "preserved_content_sha256": self.old_content_hash,
            "preserved_content_byte_count": 21,
            "preserved_state": "populated",
            "direct_child_count": 3,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        self.final = self.common | {
            "schema_version": "demo-co/google-create-observation/v2",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": "2026-10-25T18:03:00Z",
            "preserved_blank_generation": 4,
            "preserved_blank_sha256": "",
            "v2_baseline_generation": 5,
            "v2_baseline_sha256": "",
            "v2_baseline_observed_at": "2026-10-25T18:00:00Z",
            "new_child_id": self.new_id,
            "new_child_title": "Auths AP-071 Project A handoff",
            "new_child_created_at": "2026-10-25T18:01:00Z",
            "new_child_mime_type": "application/vnd.google-apps.document",
            "new_marker": self.new_marker,
            "new_marker_match_count": 1,
            "new_tab_id": "t.0", "new_admin_revision_id": "new-revision",
            "new_content_sha256": self.new_content_hash,
            "new_content_byte_count": 15,
            "preserved_child_id": self.old_id,
            "preserved_child_title": "Auths AP-071 Project A handoff",
            "preserved_child_created_at": "2026-10-25T16:46:00Z",
            "preserved_marker": self.old_marker,
            "preserved_marker_match_count": 1,
            "preserved_content_sha256": self.old_content_hash,
            "preserved_content_byte_count": 21,
            "preserved_state": "populated",
            "preserved_matches_precreate_baseline": True,
            "preserved_original_blank": True,
            "working_document_sha256": self.working_hash,
            "working_document_matches_precreate_baseline": True,
            "direct_child_count": 4,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }

    def write(self, name: str, document: dict) -> tuple[Path, str]:
        path = self.root / name
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        path.write_bytes(raw)
        return path, digest(raw)

    def staged(self) -> tuple[Path, Path, Path, CreateV2Pins]:
        blank_path, blank_hash = self.write("blank.json", self.blank)
        self.baseline["preserved_blank_sha256"] = blank_hash
        self.final["preserved_blank_sha256"] = blank_hash
        baseline_path, baseline_hash = self.write("baseline.json", self.baseline)
        self.final["v2_baseline_sha256"] = baseline_hash
        final_path, final_hash = self.write("final.json", self.final)
        pins = CreateV2Pins(
            company=self.common["company"], instance=self.common["instance"],
            definition_hash=self.common["definition_hash"],
            customer_id=self.common["customer_id"],
            jules_subject=self.common["jules_subject"],
            source_verification_sha256=self.common["source_verification_sha256"],
            original_baseline_generation=3,
            original_baseline_sha256="e" * 64,
            preserved_blank_generation=4, preserved_blank_sha256=blank_hash,
            v2_baseline_generation=5, v2_baseline_sha256=baseline_hash,
            observation_sha256=final_hash,
            drive_id=self.common["drive_id"], folder_id=self.common["folder_id"],
            working_document_id="working-doc",
            preserved_child_id=self.old_id, preserved_marker=self.old_marker,
            new_child_id=self.new_id, new_marker=self.new_marker,
            new_content_sha256=self.new_content_hash,
            new_content_byte_count=15,
        )
        return blank_path, baseline_path, final_path, pins

    def test_three_stages_match(self) -> None:
        validate_create_v2_observation(*self.staged())

    def test_fresh_precreate_baseline_accepts_preserved_populated_child(self) -> None:
        blank, baseline, _, pins = self.staged()
        precreate = CreateV2BaselinePins(
            company=pins.company, instance=pins.instance,
            definition_hash=pins.definition_hash,
            customer_id=pins.customer_id, jules_subject=pins.jules_subject,
            source_verification_sha256=pins.source_verification_sha256,
            drive_id=pins.drive_id, folder_id=pins.folder_id,
            working_document_id=pins.working_document_id,
            original_baseline_generation=pins.original_baseline_generation,
            original_baseline_sha256=pins.original_baseline_sha256,
            preserved_blank_generation=pins.preserved_blank_generation,
            preserved_blank_sha256=pins.preserved_blank_sha256,
            baseline_generation=pins.v2_baseline_generation,
            baseline_sha256=pins.v2_baseline_sha256,
            preserved_child_id=pins.preserved_child_id,
            preserved_marker=pins.preserved_marker,
        )
        now = 1792951320  # 2026-10-25 18:02 UTC.
        self.assertEqual(validate_create_v2_precreate_baseline(
            blank, baseline, precreate, now=now,
        )["preserved_state"], "populated")
        for changed in (
            replace(precreate, preserved_child_id="other-child"),
            replace(precreate, source_verification_sha256="f" * 64),
            replace(precreate, baseline_generation=4),
        ):
            with self.subTest(changed=changed), self.assertRaises(ContractRejected):
                validate_create_v2_precreate_baseline(
                    blank, baseline, changed, now=now,
                )
        with self.assertRaises(ContractRejected):
            validate_create_v2_precreate_baseline(
                blank, baseline, precreate, now=now + 241,
            )
        self.baseline["direct_child_count"] = 4
        altered, altered_hash = self.write("altered-baseline.json", self.baseline)
        with self.assertRaises(ContractRejected):
            validate_create_v2_precreate_baseline(
                blank, altered, replace(precreate, baseline_sha256=altered_hash),
                now=now,
            )

    def test_changed_preserved_content_refused_even_with_new_digest(self) -> None:
        blank, baseline, _, pins = self.staged()
        self.final["preserved_content_sha256"] = digest(b"changed old child")
        final, final_hash = self.write("changed.json", self.final)
        with self.assertRaises(ContractRejected):
            validate_create_v2_observation(
                blank, baseline, final,
                replace(pins, observation_sha256=final_hash),
            )

    def test_late_create_refused_even_with_new_digest(self) -> None:
        blank, baseline, _, pins = self.staged()
        self.final["new_child_created_at"] = "2026-10-25T18:06:00Z"
        self.final["observed_at"] = "2026-10-25T18:07:00Z"
        final, final_hash = self.write("late.json", self.final)
        with self.assertRaises(ContractRejected):
            validate_create_v2_observation(
                blank, baseline, final,
                replace(pins, observation_sha256=final_hash),
            )

    def test_other_working_document_refused_even_with_relinked_hashes(self) -> None:
        blank, _, _, pins = self.staged()
        self.baseline["working_document_id"] = "other-working-doc"
        baseline, baseline_hash = self.write("other-baseline.json", self.baseline)
        self.final["v2_baseline_sha256"] = baseline_hash
        final, final_hash = self.write("other-final.json", self.final)
        with self.assertRaises(ContractRejected):
            validate_create_v2_observation(
                blank, baseline, final,
                replace(pins, v2_baseline_sha256=baseline_hash,
                        observation_sha256=final_hash),
            )

    def test_same_child_or_marker_cannot_be_pinned(self) -> None:
        *_, pins = self.staged()
        with self.assertRaises(ContractRejected):
            replace(pins, new_child_id=self.old_id).validate()
        with self.assertRaises(ContractRejected):
            replace(pins, new_marker=self.old_marker).validate()


if __name__ == "__main__":
    unittest.main()
