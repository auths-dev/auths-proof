from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.google_write_preflight import (
    BOUNDED_NEGATIVE_LOGICAL_ID, EditTarget, WritePreflightDenied,
    preflight_jules_edit,
)


class _Session:
    def __init__(self) -> None:
        self.trust_env = True
        self.headers = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


class BoundedNegativePreflightTests(unittest.TestCase):
    def test_checks_scratch_parent_and_owner_before_document(self) -> None:
        drive = "drive-1"
        folder = "project-a-folder"
        scratch = "scratch-root"
        document = "negative-doc"
        marker = "AP071-NEG-62e394bb6eb62df674bd4035"
        raw = b"\xef\xbb\xbf" + marker.encode()
        owner = "demo-co/v1:live-test-atlas/atlas-studio"
        scratch_owner = "demo-co/v1:live-test-atlas/atlas-studio-recovery-negative"

        def item(item_id: str, name: str, mime: str, logical_id: str,
                 ownership: str, parent: str | None, capability: str) -> dict:
            return {
                "id": item_id, "name": name, "mimeType": mime,
                "driveId": drive, "parents": [] if parent is None else [parent],
                "appProperties": {"demo_co_owner": ownership,
                                  "demo_co_logical_id": logical_id},
                "capabilities": {capability: True},
            }

        folder_record = item(folder, "Project A", "application/vnd.google-apps.folder",
                             "ap071-project-a-folder", owner, None,
                             "canAddChildren")
        scratch_record = item(scratch, "Demo Co AP-071 Recovery Negatives",
                              "application/vnd.google-apps.folder",
                              "ap071-negative-root", scratch_owner, folder,
                              "canAddChildren")
        document_record = item(document, "Demo Co AP-071 Bounded Upfront Negative",
                               "application/vnd.google-apps.document",
                               BOUNDED_NEGATIVE_LOGICAL_ID, scratch_owner,
                               scratch, "canEdit")
        docs_record = {"documentId": document, "revisionId": "revision-1",
                       "tabs": [{"tabProperties": {"tabId": "t.0"}}]}
        evidence = {"folder_id": folder, "folder_title": "Project A",
                    "drive_id": drive, "document_id": "old-working-doc",
                    "document_title": "Old Working Doc", "tab_id": "t.0",
                    "marker": "old-marker", "baseline_sha256": "0" * 64,
                    "baseline_byte_count": 10}
        target = EditTarget(document, document_record["name"],
                            BOUNDED_NEGATIVE_LOGICAL_ID, scratch, drive,
                            "t.0", marker, hashlib.sha256(raw).hexdigest(), len(raw))
        pins = SimpleNamespace(producer=SimpleNamespace(
            instance="live-test-atlas", company="atlas-studio"))

        def run(root_record: dict) -> tuple[object, _Session, object]:
            session = _Session()
            responses = [folder_record, root_record, document_record, docs_record]
            encoded = [json.dumps(value).encode() for value in responses] + [raw]
            with (patch("employee_read_demo.google_write_preflight.validate_write_handoff",
                        return_value=evidence),
                  patch("employee_read_demo.google_write_preflight.lease_jules_write_token",
                        return_value=SimpleNamespace(access_token="test-only",
                                                     expires_at=2000)),
                  patch("employee_read_demo.google_write_preflight.requests.Session",
                        return_value=session),
                  patch("employee_read_demo.google_write_preflight._bounded_get",
                        side_effect=encoded) as read):
                result = preflight_jules_edit(
                    Path("evidence.json"), Path("grant.json"), pins,
                    connection_id="conn-test", connection_generation=1,
                    target=target, now=1000)
            return result, session, read

        accepted, session, read = run(scratch_record)
        self.assertEqual((accepted.document_id, accepted.revision_id,
                          accepted.marker_count), (document, "revision-1", 1))
        self.assertEqual(read.call_count, 5)
        self.assertTrue(session.closed)

        for bad_root in (
            scratch_record | {"parents": ["other-folder"]},
            scratch_record | {"appProperties": {
                "demo_co_owner": owner,
                "demo_co_logical_id": "ap071-negative-root"}},
        ):
            with self.assertRaisesRegex(WritePreflightDenied, "scratch root drifted"):
                run(bad_root)
