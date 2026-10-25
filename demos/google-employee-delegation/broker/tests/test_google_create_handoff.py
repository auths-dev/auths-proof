from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import (
    CHILD_TITLE,
    CreateObservationPins,
    inspect_create_observation,
    validate_create_observation,
)


def _observation() -> dict:
    return {
        "schema_version": "demo-co/google-create-observation/v1",
        "status": "ready", "attribution": "provider_state_only",
        "company": "atlas-studio", "instance": "live-test-atlas",
        "definition_hash": "a" * 64,
        "observed_at": "2026-10-25T10:06:00+00:00",
        "source_verification_sha256": "b" * 64,
        "working_baseline_generation": 2,
        "working_baseline_sha256": "c" * 64,
        "working_baseline_observed_at": "2026-10-25T10:00:00+00:00",
        "customer_id": "customer-1", "jules_subject": "jules-subject",
        "drive_id": "drive-1", "folder_id": "project-a-folder",
        "child_id": "created-doc-1", "child_title": CHILD_TITLE,
        "child_created_at": "2026-10-25T10:03:00+00:00",
        "child_mime_type": "application/vnd.google-apps.document",
        "marker_key": "auths_operation_marker",
        "marker_value": "ap071_" + "d" * 32,
        "child_parent_exact": True, "marker_match_count": 1,
        "direct_child_count": 3,
        "tab_id": "tab-1", "admin_revision_id": "rev-1",
        "content_sha256": "e" * 64, "content_byte_count": 27,
        "canonical_project_a_unchanged": True,
        "canonical_project_b_unchanged": True,
        "working_document_sha256": "f" * 64,
        "working_document_matches_expected": True,
        "jules_project_b_write_denied": True,
    }


def _write(path: Path, document: dict) -> str:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class GoogleCreateHandoffTests(unittest.TestCase):
    def test_pinned_observation_reports_provider_state_without_agent_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "google-create-observation.json"
            document = _observation()
            digest = _write(path, document)
            pins = CreateObservationPins(
                company=document["company"], instance=document["instance"],
                definition_hash=document["definition_hash"],
                customer_id=document["customer_id"],
                jules_subject=document["jules_subject"],
                source_verification_sha256=document["source_verification_sha256"],
                working_baseline_generation=2,
                working_baseline_sha256=document["working_baseline_sha256"],
                drive_id=document["drive_id"], folder_id=document["folder_id"],
                child_id=document["child_id"], marker_value=document["marker_value"],
                expected_content_sha256=document["content_sha256"],
                expected_content_byte_count=document["content_byte_count"],
                observation_sha256=digest,
            )
            validate_create_observation(path, pins)
            status = inspect_create_observation(path, pins)
            self.assertEqual(status.status, "provider_state_observed")
            self.assertEqual(status.attribution, "provider_state_only")
            self.assertNotIn(document["content_sha256"], repr(status))

            for mutation in (
                {"child_id": "different-child"},
                {"marker_value": "ap071_" + "0" * 32},
                {"content_sha256": "0" * 64},
                {"child_parent_exact": False},
                {"marker_match_count": 2},
                {"canonical_project_b_unchanged": False},
                {"child_created_at": "2026-10-25T10:08:00+00:00"},
            ):
                altered = document | mutation
                altered_digest = _write(path, altered)
                with self.assertRaises(ContractRejected):
                    validate_create_observation(
                        path, replace(pins, observation_sha256=altered_digest),
                    )
            self.assertEqual(inspect_create_observation().status, "not_configured")


if __name__ == "__main__":
    unittest.main()
