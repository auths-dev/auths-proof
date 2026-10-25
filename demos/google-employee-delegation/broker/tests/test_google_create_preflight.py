from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE, CreatedChildMetadataPins
from employee_read_demo.google_create_preflight import (
    preflight_jules_created_child, search_jules_created_child,
)


class _Session:
    def __init__(self) -> None:
        self.trust_env = True
        self.headers = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


class JulesChildPreflightTests(unittest.TestCase):
    def test_lost_response_search_rechecks_one_child_without_minting_authority(self) -> None:
        marker = "ap071_" + "d" * 32
        child = {
            "id": "child_ABC-123", "name": CHILD_TITLE,
            "mimeType": "application/vnd.google-apps.document",
            "parents": ["project-a-folder"], "driveId": "shared-drive-1",
            "properties": {"auths_operation_marker": marker},
            "trashed": False, "createdTime": "2026-10-25T10:03:00Z",
        }
        credential = SimpleNamespace(producer=SimpleNamespace())
        session = _Session()
        pages = [{"incompleteSearch": False, "files": [],
                  "nextPageToken": "page-2"},
                 {"incompleteSearch": False, "files": [child]},
                 child]
        with (patch("employee_read_demo.google_create_preflight.validate_write_handoff",
                    return_value={"folder_id": "project-a-folder",
                                  "drive_id": "shared-drive-1"}),
              patch("employee_read_demo.google_create_preflight.lease_jules_write_token",
                    return_value=SimpleNamespace(access_token="secret-test-token",
                                                 expires_at=1200)),
              patch("employee_read_demo.google_create_preflight.requests.Session",
                    return_value=session),
              patch("employee_read_demo.google_create_preflight._bounded_get",
                    side_effect=[json.dumps(page).encode() for page in pages]) as read):
            candidate = search_jules_created_child(
                Path("evidence.json"), Path("grant.json"), credential, marker,
                connection_id="jules-google", connection_generation=1, now=1000,
            )
        self.assertEqual(candidate, child["id"])
        self.assertEqual(read.call_count, 3)
        self.assertIn("pageToken=page-2", read.call_args_list[1].args[1])
        self.assertIn("/child_ABC-123?", read.call_args_list[2].args[1])
        self.assertTrue(session.closed)

        for files in ([], [child, child | {"id": "other-child"}]):
            with (patch("employee_read_demo.google_create_preflight.validate_write_handoff",
                        return_value={"folder_id": "project-a-folder",
                                      "drive_id": "shared-drive-1"}),
                  patch("employee_read_demo.google_create_preflight.lease_jules_write_token",
                        return_value=SimpleNamespace(access_token="secret-test-token",
                                                     expires_at=1200)),
                  patch("employee_read_demo.google_create_preflight.requests.Session",
                        return_value=_Session()),
                  patch("employee_read_demo.google_create_preflight._bounded_get",
                        return_value=json.dumps({"incompleteSearch": False,
                                                 "files": files}).encode()) as read):
                self.assertIsNone(search_jules_created_child(
                    Path("evidence.json"), Path("grant.json"), credential, marker,
                    connection_id="jules-google", connection_generation=1, now=1000,
                ))
                self.assertEqual(read.call_count, 1)

    def test_three_bounded_jules_reads_pin_child_capability_and_blank_revision(self) -> None:
        pins = CreatedChildMetadataPins(
            candidate_id="child_ABC-123", parent_id="project-a-folder",
            drive_id="shared-drive-1", title=CHILD_TITLE,
            marker_value="ap071_" + "d" * 32,
        )
        metadata = {
            "id": pins.candidate_id, "name": pins.title,
            "mimeType": "application/vnd.google-apps.document",
            "parents": [pins.parent_id], "driveId": pins.drive_id,
            "properties": {"auths_operation_marker": pins.marker_value},
            "trashed": False, "createdTime": "2026-10-25T10:03:00Z",
        }
        access = {"id": pins.candidate_id, "parents": [pins.parent_id],
                  "capabilities": {"canEdit": True}}
        document = {"documentId": pins.candidate_id, "revisionId": "revision-1",
                    "tabs": [{"tabProperties": {"tabId": "t.0"},
                              "childTabs": [], "documentTab": {"body": {"content": [
                                  {"startIndex": 1, "endIndex": 2,
                                   "paragraph": {"elements": [{
                                       "startIndex": 1, "endIndex": 2,
                                       "textRun": {"content": "\n"}}]}}]}}}]}
        responses = [json.dumps(value).encode() for value in
                     (metadata, access, document)]
        session = _Session()
        credential = SimpleNamespace(
            producer=SimpleNamespace(jules_subject="jules-subject"),
            connection_id="jules-google",
            connection_generation=1,
        )
        with (patch("employee_read_demo.google_create_preflight.validate_write_handoff",
                    return_value={"folder_id": pins.parent_id,
                                  "drive_id": pins.drive_id}),
              patch("employee_read_demo.google_create_preflight.lease_jules_write_token",
                    return_value=SimpleNamespace(access_token="secret-test-token",
                                                 expires_at=1200)) as lease,
              patch("employee_read_demo.google_create_preflight.requests.Session",
                    return_value=session),
              patch("employee_read_demo.google_create_preflight._bounded_get",
                    side_effect=responses) as read):
            result = preflight_jules_created_child(
                Path("evidence.json"), Path("grant.json"), credential, pins,
                connection_id="jules-google", connection_generation=1, now=1000,
            )
        self.assertEqual((result.child_id, result.tab_id, result.revision_id),
                         (pins.candidate_id, "t.0", "revision-1"))
        self.assertEqual((result.connection_id, result.connection_generation,
                          result.connection_subject),
                         ("jules-google", 1, "jules-subject"))
        self.assertEqual((result.metadata_sha256, result.capability_sha256,
                          result.docs_sha256),
                         tuple(hashlib.sha256(raw).hexdigest() for raw in responses))
        self.assertTrue(session.closed)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.headers["Authorization"], "Bearer secret-test-token")
        self.assertEqual(lease.call_count, 1)
        self.assertEqual(read.call_count, 3)
        self.assertIn("drive/v3/files/child_ABC-123", read.call_args_list[0].args[1])
        self.assertIn("capabilities(canEdit)", read.call_args_list[1].args[1])
        self.assertIn("includeTabsContent=true", read.call_args_list[2].args[1])

        with patch("employee_read_demo.google_create_preflight.validate_write_handoff",
                   return_value={"folder_id": "another-folder",
                                 "drive_id": pins.drive_id}):
            with self.assertRaises(ContractRejected):
                preflight_jules_created_child(
                    Path("evidence.json"), Path("grant.json"), credential, pins,
                    connection_id="jules-google", connection_generation=1, now=1000,
                )


if __name__ == "__main__":
    unittest.main()
