from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch

from employee_read_demo.google_drive import (
    GoogleDenied, GoogleDriveReader, GoogleUnavailable, ProviderTrace, _get,
)
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
        def get(path: str, token: str, limit: int, trace: ProviderTrace, phase: str):
            self.assertEqual(token, "synthetic-employee-token")
            calls.append(path)
            trace.requests_started += 1
            if len(calls) == 1:
                body = json.dumps({
                    "id": "file-A", "mimeType": "application/vnd.google-apps.document",
                    "capabilities": {"canDownload": True},
                }).encode()
                trace.response_bytes += len(body)
                return 200, body, "application/json"
            body = b"approved synthetic document"
            trace.response_bytes += len(body)
            return 200, body, "text/plain"
        with patch("employee_read_demo.google_drive._get", get):
            body = self.reader.read_exact(self.task.calls()[0])
        self.assertEqual(body, b"approved synthetic document")
        self.assertEqual(calls, [
            "/drive/v3/files/file-A?fields=id,mimeType,size,trashed,capabilities(canDownload)",
            "/drive/v3/files/file-A/export?mimeType=text%2Fplain",
        ])
        self.assertEqual(self.reader.trace.requests_started, 2)
        self.assertGreater(self.reader.trace.response_bytes, len(body))

    def test_outside_task_refuses_before_token_lease(self) -> None:
        altered = type(self.task.calls()[0])(**{**self.task.calls()[0].__dict__, "file_id": "file-C"})
        with self.assertRaises(GoogleDenied):
            self.reader.read_exact(altered)
        self.assertEqual(self.vault.leases, 0)

    def test_provider_download_restriction_blocks_content_get(self) -> None:
        def get(path: str, token: str, limit: int, trace: ProviderTrace, phase: str):
            trace.requests_started += 1
            return 200, json.dumps({
                "id": "file-A", "mimeType": "text/plain",
                "capabilities": {"canDownload": False},
            }).encode(), "application/json"
        with patch("employee_read_demo.google_drive._get", get):
            with self.assertRaises(GoogleDenied):
                self.reader.read_exact(self.task.calls()[0])

    def test_preparation_inspects_only_metadata(self) -> None:
        calls: list[str] = []
        def get(path: str, token: str, limit: int, trace: ProviderTrace, phase: str):
            trace.requests_started += 1
            calls.append(path)
            return 200, json.dumps({
                "id": "file-A", "mimeType": "text/plain", "size": "100",
                "capabilities": {"canDownload": True},
            }).encode(), "application/json"
        with patch("employee_read_demo.google_drive._get", get):
            self.reader.inspect_exact(self.task.calls()[0])
        self.assertEqual(len(calls), 1)
        self.assertIn("fields=id,mimeType", calls[0])

    def test_streamed_bytes_remain_observed_when_response_exceeds_limit(self) -> None:
        class Response:
            status = 200
            body = b"123456"

            def getheader(self, name, default=None):
                return {"Content-Encoding": "identity", "Content-Type": "text/plain"}.get(name, default)

            def read(self, amount):
                part, self.body = self.body[:amount], self.body[amount:]
                return part

        class Connection:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, path, headers):
                self.method = method

            def getresponse(self):
                return Response()

            def close(self):
                pass

        trace = ProviderTrace()
        with patch("employee_read_demo.google_drive._PinnedGoogleConnection", Connection):
            with self.assertRaises(GoogleUnavailable):
                _get("/fixed", "synthetic-token", 5, trace, "metadata")
        self.assertEqual(trace.requests_started, 1)
        self.assertEqual(trace.response_bytes, 6)


if __name__ == "__main__":
    unittest.main()
