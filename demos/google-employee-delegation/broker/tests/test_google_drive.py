from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch

from employee_read_demo.google_drive import GoogleDenied, GoogleDriveReader
from employee_read_demo.token_store import TokenLease
from test_admission import task


class FakeVault:
    def __init__(self) -> None:
        self.leases = 0

    def lease(self, descriptor, *, now=None) -> TokenLease:
        self.leases += 1
        return TokenLease("synthetic-employee-token", int(time.time()) + 600)


class GoogleDriveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = task(int(time.time()))
        self.vault = FakeVault()
        self.reader = GoogleDriveReader(self.task, self.vault)

    def test_approved_document_uses_only_fixed_metadata_and_content_gets(self) -> None:
        calls: list[str] = []
        def get(path: str, token: str, limit: int):
            self.assertEqual(token, "synthetic-employee-token")
            calls.append(path)
            if len(calls) == 1:
                return 200, json.dumps({
                    "id": "file-A", "mimeType": "application/vnd.google-apps.document",
                    "capabilities": {"canDownload": True},
                }).encode(), "application/json"
            return 200, b"approved synthetic document", "text/plain"
        with patch("employee_read_demo.google_drive._get", get):
            body = self.reader.read_exact(self.task.calls()[0])
        self.assertEqual(body, b"approved synthetic document")
        self.assertEqual(calls, [
            "/drive/v3/files/file-A?fields=id,mimeType,size,trashed,capabilities(canDownload)",
            "/drive/v3/files/file-A/export?mimeType=text%2Fplain",
        ])

    def test_outside_task_refuses_before_token_lease(self) -> None:
        altered = type(self.task.calls()[0])(**{**self.task.calls()[0].__dict__, "file_id": "file-C"})
        with self.assertRaises(GoogleDenied):
            self.reader.read_exact(altered)
        self.assertEqual(self.vault.leases, 0)

    def test_provider_download_restriction_blocks_content_get(self) -> None:
        def get(path: str, token: str, limit: int):
            return 200, json.dumps({
                "id": "file-A", "mimeType": "text/plain",
                "capabilities": {"canDownload": False},
            }).encode(), "application/json"
        with patch("employee_read_demo.google_drive._get", get):
            with self.assertRaises(GoogleDenied):
                self.reader.read_exact(self.task.calls()[0])


if __name__ == "__main__":
    unittest.main()
