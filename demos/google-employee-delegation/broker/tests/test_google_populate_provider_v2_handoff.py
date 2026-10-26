"""A frozen producer after-state must match the whole approved run."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_populate_failure_handoff import (
    PopulateFailureTarget, _pinned_observation,
)
from employee_read_demo.google_populate_provider_v2_handoff import (
    FINAL_SCHEMA, FINAL_SCHEMA_SHA256, INVENTORY_SCHEMA,
    INVENTORY_SCHEMA_SHA256, ProviderV2SourcePins,
    validate_populate_provider_final_v2,
)


class ProducerV2ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = "Source-backed Project A handoff"
        self.raw = b"\xef\xbb\xbf" + self.text.encode()
        self.raw_sha256 = hashlib.sha256(self.raw).hexdigest()
        self.marker = "ap071_" + "a" * 32
        self.source = ProviderV2SourcePins("source-doc", "c" * 64, 51)
        self.target = PopulateFailureTarget(
            "new-run", self.marker, "run-folder", 44, "a" * 64,
        )
        self.common = {
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-one",
            "project_a_folder_id": "project-a",
            "scratch_root_id": "scratch-root", "run_folder_id": "run-folder",
            "run_id": "new-run", "marker": self.marker,
        }
        self.setup = {"observed_at": "2026-10-26T10:00:00Z",
                      "scratch_root_id": "scratch-root"}
        self.precreate = {"observed_at": "2026-10-26T10:02:00Z"}
        self.inventory = self.common | {
            "schema_version": "demo-co/google-populate-provider-inventory/v1",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": "2026-10-26T10:01:00Z",
            "setup_generation": 44, "setup_sha256": "a" * 64,
            "run_folder_empty": True, "scratch_root_child_count": 2,
            "source_document_id": self.source.document_id,
            "source_raw_sha256": self.source.raw_sha256,
            "source_raw_byte_count": self.source.raw_byte_count,
            "source_jules_export_matches_admin": True,
            "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "sibling_pins": [
                {"file_id": "old-doc", "parent_id": "other-folder",
                 "name": "older", "mime_type":
                    "application/vnd.google-apps.document",
                 "raw_sha256": "d" * 64, "raw_byte_count": 9,
                 "revision_id": "old-revision"},
                {"file_id": "other-folder", "parent_id": "scratch-root",
                 "name": "other", "mime_type":
                    "application/vnd.google-apps.folder",
                 "raw_sha256": None, "raw_byte_count": None,
                 "revision_id": None},
                {"file_id": "run-folder", "parent_id": "scratch-root",
                 "name": "new", "mime_type":
                    "application/vnd.google-apps.folder",
                 "raw_sha256": None, "raw_byte_count": None,
                 "revision_id": None},
            ],
        }
        self.blank = {
            "schema_version": "demo-co/google-populate-blank-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-one",
            "run_folder_id": "run-folder", "run_id": "new-run",
            "marker": self.marker, "setup_generation": 44,
            "setup_sha256": "a" * 64, "child_id": "new-child",
            "child_created_at": "2026-10-26T10:03:00Z",
            "observed_at": "2026-10-26T10:04:00Z",
            "child_title": "Auths AP-071 Project A handoff",
            "project_a_direct_child_count": 8,
            "marker_match_count": 1, "run_child_count": 1,
            "raw_byte_count": 3,
            "raw_sha256": hashlib.sha256(b"\xef\xbb\xbf").hexdigest(),
            "tab_id": "tab-one", "admin_revision_id": "blank-revision",
            "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        self.final = self.common | {
            "schema_version": "demo-co/google-populate-provider-final/v2",
            "status": "exact_populated", "attribution": "provider_state_only",
            "observed_at": "2026-10-26T10:05:00Z",
            "inventory_generation": 45, "inventory_sha256": "b" * 64,
            "blank_baseline_generation": 47,
            "blank_baseline_sha256": "e" * 64,
            "child_id": "new-child",
            "child_created_at": self.blank["child_created_at"],
            "tab_id": "tab-one", "blank_admin_revision_id": "blank-revision",
            "observed_admin_revision_id": "written-revision",
            "revision_changed": True,
            "blank_raw_sha256": self.blank["raw_sha256"],
            "observed_raw_sha256": self.raw_sha256,
            "observed_raw_byte_count": len(self.raw),
            "expected_raw_sha256": self.raw_sha256,
            "expected_raw_byte_count": len(self.raw),
            "exact_expected_content": True,
            "still_exactly_blank": False,
            "run_marker_occurrences_in_content": 0,
            "provider_match_count": 1, "run_child_count": 1,
            "scratch_root_child_count": 2,
            "exact_sibling_inventory_unchanged": True,
            "source_document_id": self.source.document_id,
            "source_raw_sha256": self.source.raw_sha256,
            "source_raw_byte_count": self.source.raw_byte_count,
            "source_unchanged": True,
            "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "provider_entry_attested": False,
            "retry_authorized": False,
        }
        baseline = SimpleNamespace(**{
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-one",
            "folder_id": "project-a", "jules_subject": "jules-subject",
        })
        self.v4 = SimpleNamespace(candidate=SimpleNamespace(baseline=baseline))

    def consume(self) -> dict:
        with (patch("employee_read_demo.google_populate_provider_v2_handoff."
                    "_pinned_observation", side_effect=[
                        (45, self.inventory), (47, self.blank), (48, self.final),
                    ]),
              patch("employee_read_demo.google_populate_provider_v2_handoff."
                    "validate_populate_precreate_baseline",
                    return_value=(self.target, 46, self.precreate)),
              patch("employee_read_demo.google_populate_provider_v2_handoff."
                    "_load", return_value=(self.setup, b""))):
            return validate_populate_provider_final_v2(
                (Path("v4-a"), Path("v4-b"), Path("v4-c")),
                Path("setup"), "a" * 64,
                Path("inventory"), "b" * 64,
                Path("precreate"), "f" * 64,
                Path("blank"), "e" * 64,
                Path("final"), "0" * 64,
                self.v4, expected_text=self.text, source=self.source,
            )

    def test_exact_report_is_provider_state_only(self) -> None:
        result = self.consume()
        self.assertEqual(result["status"], "exact_populated")
        self.assertEqual(result["child_id"], "new-child")
        self.assertEqual(result["authority"], "provider_state_only")
        self.assertIs(result["retry_authorized"], False)

    def test_swaps_and_nonexact_states_are_refused(self) -> None:
        for document, field, value in (
            (self.inventory, "source_raw_sha256", "0" * 64),
            (self.inventory, "sibling_pins", []),
            (self.blank, "child_id", "other-child"),
            (self.blank, "raw_sha256", "0" * 64),
            (self.final, "child_id", "other-child"),
            (self.final, "blank_baseline_sha256", "0" * 64),
            (self.final, "observed_raw_sha256", "0" * 64),
            (self.final, "status", "still_blank"),
            (self.final, "retry_authorized", True),
        ):
            with self.subTest(field=field, value=value):
                original = document[field]
                document[field] = value
                try:
                    with self.assertRaises(ContractRejected):
                        self.consume()
                finally:
                    document[field] = original
        original = self.inventory["sibling_pins"]
        changed = copy.deepcopy(original)
        changed[0]["parent_id"] = "absent-folder"
        self.inventory["sibling_pins"] = changed
        try:
            with self.assertRaises(ContractRejected):
                self.consume()
        finally:
            self.inventory["sibling_pins"] = original

    def test_vendored_producer_schema_bytes_are_frozen(self) -> None:
        for name, digest, fixture in (
                (INVENTORY_SCHEMA, INVENTORY_SCHEMA_SHA256, self.inventory),
                (FINAL_SCHEMA, FINAL_SCHEMA_SHA256, self.final)):
            raw = files("employee_read_demo").joinpath(
                "schemas", name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            schema = json.loads(raw)
            self.assertEqual(set(schema["required"]),
                             set(schema["properties"]))
            validator = Draft202012Validator(schema)
            self.assertEqual(list(validator.iter_errors(fixture)), [])
            absent = dict(fixture)
            absent.pop("attribution")
            self.assertTrue(list(validator.iter_errors(absent)))

    def test_private_artifact_requires_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation-0045"
            generation.mkdir(mode=0o700)
            path = generation / "google-populate-provider-inventory.json"
            raw = json.dumps(self.inventory, sort_keys=True).encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            observed_generation, observed = _pinned_observation(
                path, digest, path.name,
                INVENTORY_SCHEMA, INVENTORY_SCHEMA_SHA256,
            )
            self.assertEqual(observed_generation, 45)
            self.assertEqual(observed["run_folder_id"], "run-folder")
            with self.assertRaises(ContractRejected):
                _pinned_observation(
                    path, "0" * 64, path.name,
                    INVENTORY_SCHEMA, INVENTORY_SCHEMA_SHA256,
                )


if __name__ == "__main__":
    unittest.main()
