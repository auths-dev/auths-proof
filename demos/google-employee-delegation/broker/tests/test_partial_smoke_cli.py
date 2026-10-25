from __future__ import annotations

import hashlib
import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.contracts import canonical_json
from employee_read_demo.existing_consent_smoke import EXISTING_GRANT_SCOPES
from employee_read_demo.google_oauth import TOKEN_URL
from employee_read_demo.partial_smoke_cli import run


class PartialSmokeCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.report_path = folder / "report.json"
        self.client_path = folder / "client.json"
        self.grant_path = folder / "grant.json"
        self.now = int(time.time())
        self.body = b"synthetic project A text"
        self.report = {
            "schema_version": "demo-co/google-partial-probe/v1",
            "qualification": "partial_only_not_full_google_verification",
            "full_google_ready": False, "passed": True,
            "company": "atlas-studio", "instance": "live-test-atlas-20261025",
            "customer_id": "C0218tf2n", "primary_domain": "auths.dev",
            "definition_hash": "a" * 64,
            "identities": {"person-jules": {"email": "jules@auths.dev",
                                           "google_subject": "synthetic-sub", "suspended": False}},
            "probes": [
                {"person": "person-jules", "resource": "doc-project-a-status",
                 "file_id": "file-A", "expected": "allow", "observed": "allow",
                 "passed": True, "content_sha256": hashlib.sha256(self.body).hexdigest()},
                {"person": "person-jules", "resource": "doc-project-b-plan",
                 "file_id": "file-B", "expected": "allow", "observed": "allow",
                 "passed": True, "content_sha256": "b" * 64},
            ],
        }
        self._write(self.report_path, self.report)
        self._write(self.client_path, {"installed": {"client_id": "synthetic-client",
                                                     "token_uri": TOKEN_URL}})
        self._write(self.grant_path, {
            "client_id": "synthetic-client", "client_secret": "synthetic-secret",
            "refresh_token": "synthetic-refresh", "token": "synthetic-access",
            "token_uri": TOKEN_URL, "universe_domain": "googleapis.com",
            "scopes": sorted(EXISTING_GRANT_SCOPES),
            "expiry": datetime.fromtimestamp(self.now + 600, timezone.utc).isoformat(),
        })

    def _write(self, path: Path, value: dict) -> None:
        path.write_bytes(canonical_json(value))
        path.chmod(0o600)

    def test_report_pins_and_existing_grant_drive_reader_compose(self) -> None:
        calls = []

        def get(path, token, limit, trace, phase):
            self.assertEqual(token, "synthetic-access")
            calls.append((path, phase))
            trace.begin(phase)
            if phase == "metadata":
                return 200, json.dumps({"id": "file-A", "mimeType": "application/vnd.google-apps.document",
                                        "capabilities": {"canDownload": True}}).encode(), "application/json"
            return 200, self.body, "text/plain"

        raw = self.report_path.read_bytes()
        with (patch("employee_read_demo.existing_consent_smoke._userinfo",
                    return_value={"sub": "synthetic-sub", "email": "jules@auths.dev",
                                  "email_verified": True, "hd": "auths.dev"}),
              patch("employee_read_demo.google_drive._get", get)):
            result = run(self.report_path, hashlib.sha256(raw).hexdigest(),
                         self.client_path, self.grant_path, now=self.now)
        self.assertEqual(result["project_a"]["provider_requests"], 2)
        self.assertEqual(result["project_b_outside_task"]["provider_requests"], 0)
        self.assertEqual([phase for _, phase in calls], ["metadata", "content"])
        self.assertFalse(result["native_employee_agent_proof"])

    def test_changed_report_digest_denies_before_credential(self) -> None:
        with patch("employee_read_demo.existing_consent_smoke._private_grant") as grant:
            with self.assertRaises(ValueError):
                run(self.report_path, "0" * 64, self.client_path, self.grant_path, now=self.now)
        grant.assert_not_called()


if __name__ == "__main__":
    unittest.main()
