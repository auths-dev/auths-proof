from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import (
    CHILD_TITLE,
    CreateRecoverySearch,
    CreatedChildContinuationTarget,
    CreatedChildMetadataPins,
    CreateObservationPins,
    created_child_docs_url,
    created_child_edit_access_url,
    created_child_metadata_url,
    inspect_create_observation,
    prepare_create_inputs,
    validate_created_child_metadata,
    validate_created_child_docs_read,
    validate_created_child_edit_access,
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
    def test_existing_child_continuation_pins_exact_text_and_fresh_revision(self) -> None:
        text = "Project A handoff from the separate agent"
        pin = {
            "schema": "auths.ap071-created-child-continuation/1",
            "child_id": "child_ABC-123", "parent_id": "project-a-folder",
            "drive_id": "shared-drive-1", "title": CHILD_TITLE,
            "marker_value": "ap071_" + "d" * 32,
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "text_bytes": len(text.encode()),
        }
        target = CreatedChildContinuationTarget.from_document(pin)
        action = {"document_id": pin["child_id"], "tab_id": "t.0",
                  "required_revision_id": "rev-1", "text": text}
        target.require_exact_action(action, child_id=pin["child_id"],
                                    tab_id="t.0", revision_id="rev-1")
        for change in ({"document_id": "other-child"},
                       {"tab_id": "other-tab"},
                       {"required_revision_id": "old-revision"},
                       {"text": text + "!"}):
            with self.subTest(change=change), self.assertRaises(ContractRejected):
                target.require_exact_action(action | change,
                                            child_id=pin["child_id"],
                                            tab_id="t.0", revision_id="rev-1")
        with self.assertRaises(ContractRejected):
            CreatedChildContinuationTarget.from_document(pin | {"extra": True})

    def test_recovery_search_exhausts_pages_without_granting_child_authority(self) -> None:
        marker = "ap071_" + "d" * 32
        search = CreateRecoverySearch(
            parent_id="project-a-folder", drive_id="shared-drive-1",
            marker_value=marker,
        )
        first = parse_qs(urlparse(search.next_url()).query)
        self.assertEqual(first["corpora"], ["drive"])
        self.assertEqual(first["driveId"], ["shared-drive-1"])
        self.assertIn("'project-a-folder' in parents", first["q"][0])
        self.assertIn("value='" + marker + "'", first["q"][0])
        with self.assertRaises(ContractRejected):
            search.single_candidate()
        search.accept_page({"incompleteSearch": False, "files": [],
                            "nextPageToken": "page-2"})
        second = parse_qs(urlparse(search.next_url()).query)
        self.assertEqual(second["pageToken"], ["page-2"])
        child = {
            "id": "child_ABC-123", "name": CHILD_TITLE,
            "mimeType": "application/vnd.google-apps.document",
            "parents": ["project-a-folder"], "driveId": "shared-drive-1",
            "properties": {"auths_operation_marker": marker},
            "trashed": False, "createdTime": "2026-10-25T10:03:00Z",
        }
        search.accept_page({"incompleteSearch": False, "files": [child]})
        self.assertEqual(search.single_candidate(), child["id"])
        with self.assertRaises(ContractRejected):
            search.next_url()

        for bad_page in (
            {"incompleteSearch": True, "files": [child]},
            {"files": [child]},
            {"incompleteSearch": False, "files": [child | {"name": "other"}]},
            {"incompleteSearch": False, "files": [child, child]},
            {"incompleteSearch": False, "files": [child], "nextPageToken": ""},
        ):
            with self.subTest(page=bad_page), self.assertRaises(ContractRejected):
                CreateRecoverySearch(
                    parent_id="project-a-folder", drive_id="shared-drive-1",
                    marker_value=marker,
                ).accept_page(bad_page)
        zero = CreateRecoverySearch(parent_id="project-a-folder",
                                    drive_id="shared-drive-1", marker_value=marker)
        zero.accept_page({"incompleteSearch": False, "files": []})
        self.assertIsNone(zero.single_candidate())
        multiple = CreateRecoverySearch(parent_id="project-a-folder",
                                        drive_id="shared-drive-1", marker_value=marker)
        multiple.accept_page({"incompleteSearch": False,
                              "files": [child, child | {"id": "other-child"}]})
        self.assertIsNone(multiple.single_candidate())
        capped = CreateRecoverySearch(parent_id="project-a-folder",
                                      drive_id="shared-drive-1", marker_value=marker)
        for page in range(3):
            capped.accept_page({"incompleteSearch": False, "files": [],
                                "nextPageToken": f"page-{page}"})
        with self.assertRaises(ContractRejected):
            capped.accept_page({"incompleteSearch": False, "files": [child],
                                "nextPageToken": "page-4"})
        with self.assertRaises(ContractRejected):
            capped.single_candidate()
        repeated = CreateRecoverySearch(parent_id="project-a-folder",
                                        drive_id="shared-drive-1", marker_value=marker)
        repeated.accept_page({"incompleteSearch": False, "files": [],
                              "nextPageToken": "page-1"})
        with self.assertRaises(ContractRejected):
            repeated.accept_page({"incompleteSearch": False, "files": [],
                                  "nextPageToken": "page-1"})

    def test_jules_child_revision_and_capability_are_exact_and_bounded(self) -> None:
        pins = CreatedChildMetadataPins(
            candidate_id="child_ABC-123", parent_id="project-a-folder",
            drive_id="shared-drive-1", title=CHILD_TITLE,
            marker_value="ap071_" + "d" * 32,
        )
        self.assertEqual(created_child_docs_url(pins),
                         "https://docs.googleapis.com/v1/documents/child_ABC-123"
                         "?includeTabsContent=true")
        self.assertEqual(created_child_edit_access_url(pins),
                         "https://www.googleapis.com/drive/v3/files/child_ABC-123"
                         "?supportsAllDrives=true&fields=id,parents,capabilities(canEdit)")
        blank_body = {"content": [{"endIndex": 1,
                                    "sectionBreak": {"sectionStyle": {
                                        "columnSeparatorStyle": "NONE",
                                        "contentDirection": "LEFT_TO_RIGHT",
                                        "sectionType": "CONTINUOUS"}}},
                                   {"startIndex": 1, "endIndex": 2,
                                    "paragraph": {"elements": [
                                        {"startIndex": 1, "endIndex": 2,
                                         "textRun": {"content": "\n", "textStyle": {}}}],
                                                  "paragraphStyle": {
                                                      "direction": "LEFT_TO_RIGHT",
                                                      "namedStyleType": "NORMAL_TEXT"}}}]}
        document = {"documentId": pins.candidate_id, "revisionId": "rev-1",
                    "tabs": [{"tabProperties": {"tabId": "t.0"},
                              "documentTab": {"body": blank_body}, "childTabs": []}]}
        revision = validate_created_child_docs_read(document, pins)
        self.assertEqual((revision.revision_id, revision.tab_id), ("rev-1", "t.0"))
        for changed in (
            {"documentId": "other-child"}, {"revisionId": ""},
            {"revisionId": "x" * 129}, {"revisionId": "rev\n1"},
            {"tabs": []}, {"tabs": document["tabs"] * 2},
            {"tabs": [{**document["tabs"][0], "childTabs": [{}]}]},
            {"tabs": [{**document["tabs"][0], "tabProperties": {"tabId": ""}}]},
            {"tabs": [{**document["tabs"][0], "documentTab": None}]},
            {"tabs": [{**document["tabs"][0], "documentTab": {"body": {"content": []}}}]},
            {"tabs": [{**document["tabs"][0], "documentTab": {"body": {
                "content": blank_body["content"] * 2}}}]},
            {"tabs": [{**document["tabs"][0], "documentTab": {"body": {
                "content": [{**blank_body["content"][0], "endIndex": 3}]}}}]},
            {"tabs": [{**document["tabs"][0], "documentTab": {"body": {
                "content": [blank_body["content"][0],
                            {**blank_body["content"][1], "paragraph": {
                    "elements": [{"startIndex": 1, "endIndex": 6,
                                  "textRun": {"content": "text\n"}}]}}]}}}]},
        ):
            with self.subTest(changed=changed), self.assertRaises(ContractRejected):
                validate_created_child_docs_read(document | changed, pins)
        access = {"id": pins.candidate_id, "parents": [pins.parent_id],
                  "capabilities": {"canEdit": True}}
        validate_created_child_edit_access(access, pins)
        for changed in ({"id": "other-child"}, {"parents": ["project-b"]},
                        {"capabilities": {"canEdit": False}}, {"capabilities": {}}):
            with self.subTest(changed=changed), self.assertRaises(ContractRejected):
                validate_created_child_edit_access(access | changed, pins)

    def test_response_derived_child_metadata_requires_exact_google_state(self) -> None:
        pins = CreatedChildMetadataPins(
            candidate_id="child_ABC-123", parent_id="project-a-folder",
            drive_id="shared-drive-1", title=CHILD_TITLE,
            marker_value="ap071_" + "d" * 32,
        )
        self.assertEqual(
            created_child_metadata_url(pins),
            "https://www.googleapis.com/drive/v3/files/child_ABC-123"
            "?supportsAllDrives=true&fields="
            "id,name,mimeType,parents,driveId,properties,trashed,createdTime",
        )
        metadata = {
            "id": pins.candidate_id, "name": pins.title,
            "mimeType": "application/vnd.google-apps.document",
            "parents": [pins.parent_id], "driveId": pins.drive_id,
            "properties": {"auths_operation_marker": pins.marker_value},
            "trashed": False, "createdTime": "2026-10-25T10:03:00Z",
        }
        self.assertEqual(
            validate_created_child_metadata(metadata, pins).isoformat(),
            "2026-10-25T10:03:00+00:00",
        )
        for altered in (
            {"id": "other-child"},
            {"name": "Different title"},
            {"mimeType": "text/plain"},
            {"parents": [pins.parent_id, "project-b-folder"]},
            {"driveId": "other-drive"},
            {"properties": {}},
            {"trashed": True},
            {"createdTime": "2026-10-25T10:03:00"},
        ):
            with self.subTest(altered=altered), self.assertRaises(ContractRejected):
                validate_created_child_metadata(metadata | altered, pins)
        with self.assertRaises(ContractRejected):
            created_child_metadata_url(replace(pins, candidate_id="../other"))

    def test_create_inputs_use_pinned_parent_and_fresh_opaque_markers(self) -> None:
        first = prepare_create_inputs("project-a-folder", pinned_folder_id="project-a-folder")
        second = prepare_create_inputs("project-a-folder", pinned_folder_id="project-a-folder")
        self.assertEqual(first["title"], CHILD_TITLE)
        self.assertRegex(first["recovery_marker"], r"^ap071_[0-9a-f]{32}$")
        self.assertNotEqual(first["recovery_marker"], second["recovery_marker"])
        with self.assertRaises(ContractRejected):
            prepare_create_inputs("project-b", pinned_folder_id="project-a-folder")

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
