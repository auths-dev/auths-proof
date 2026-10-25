from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from employee_read_demo.write_handoff import (WriteHandoffPending, WriteHandoffPins,
                                               inspect_write_handoff)


class WriteHandoffTests(unittest.TestCase):
    def test_missing_producer_contract_cannot_activate_write(self) -> None:
        status = inspect_write_handoff()
        self.assertEqual(status.status, "write_not_configured")
        self.assertFalse(status.ready)
        with self.assertRaises(WriteHandoffPending):
            status.require_ready()

    def test_unreviewed_file_cannot_activate_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claimed-ready.json"
            path.write_text(json.dumps({"status": "ready", "token": "do-not-read"}))
            status = inspect_write_handoff(path)
            self.assertEqual(status.status, "write_not_configured")
            self.assertNotIn("do-not-read", repr(status))
            with self.assertRaises(WriteHandoffPending):
                status.require_ready()

    def test_pinned_producer_generation_is_validated_but_not_activated(self) -> None:
        evidence = {
            "schema_version": "demo-co/google-write-verification/v1",
            "status": "ready", "company": "atlas-studio",
            "instance": "live-test-atlas-20261025",
            "definition_hash": "a" * 64, "dataset_version": "v1",
            "customer_id": "customer-1", "observed_at": "2026-10-25T10:00:00Z",
            "jules_subject": "subject-1", "jules_email": "jules@example.test",
            "granted_scopes": ["openid", "https://www.googleapis.com/auth/userinfo.email",
                               "https://www.googleapis.com/auth/drive.file"],
            "drive_id": "drive-1", "folder_id": "folder-1",
            "folder_title": "Project A", "folder_can_add_children": True,
            "document_id": "document-1", "document_title": "Working Doc",
            "document_mime_type": "application/vnd.google-apps.document",
            "document_can_edit": True, "project_b_write_capability_denied": True,
            "tab_id": "t.0", "revision_id": "revision-1",
            "marker": "[[AUTHs:PROJECT_A]]", "baseline_sha256": "b" * 64,
            "baseline_byte_count": 65, "probe_document_id": "probe-1",
            "probe_created_as_jules": True, "probe_edited_as_jules": True,
            "probe_sha256": "c" * 64, "cleanup_logical_ids": ["working-doc"],
            "canonical_documents_mutated": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "write-evidence.json"
            path.write_text(json.dumps(evidence))
            pins = WriteHandoffPins(
                company="atlas-studio", instance="live-test-atlas-20261025",
                definition_hash="a" * 64, customer_id="customer-1",
                jules_subject="subject-1", jules_email="jules@example.test",
                evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            status = inspect_write_handoff(path, pins)
            self.assertTrue(status.producer_ready)
            self.assertFalse(status.ready)
            self.assertEqual(status.status, "write_not_configured")
            with self.assertRaises(WriteHandoffPending):
                status.require_ready()
            evidence["probe_edited_as_jules"] = False
            path.write_text(json.dumps(evidence))
            self.assertEqual(inspect_write_handoff(path, pins).status, "producer_rejected")
