from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.google_write_credential import (
    WriteCredentialDenied, WriteCredentialPins, lease_jules_write_token,
)
from employee_read_demo.write_handoff import WriteHandoffPins


class GoogleWriteCredentialTests(unittest.TestCase):
    def lease(self, evidence_path: Path, grant_path: Path,
              pins: WriteCredentialPins, *, now: int):
        return lease_jules_write_token(
            evidence_path, grant_path, pins, connection_id="jules-write-1",
            connection_generation=1, now=now,
        )

    def pins(self) -> WriteCredentialPins:
        return WriteCredentialPins(
            producer=WriteHandoffPins(
                company="atlas-studio", instance="live-test-atlas-20261025",
                definition_hash="a" * 64, customer_id="customer-1",
                jules_subject="subject-1", jules_email="jules@example.test",
                evidence_sha256="b" * 64,
            ),
            client_id="desktop-client-1", primary_domain="example.test",
            connection_id="jules-write-1", connection_generation=1,
        )

    def grant(self, *, expiry: datetime, scopes: list[str] | None = None) -> dict:
        return {
            "account": "jules@example.test", "client_id": "desktop-client-1",
            "client_secret": "private-client-secret", "refresh_token": "private-refresh",
            "token": "private-access", "token_uri": "https://oauth2.googleapis.com/token",
            "universe_domain": "googleapis.com", "expiry": expiry.isoformat(),
            "scopes": scopes or [
                "openid", "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/drive.file",
            ],
        }

    def test_exact_client_scopes_and_subject_yield_short_bearer(self) -> None:
        now = int(datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp())
        with tempfile.TemporaryDirectory() as directory:
            grant_path = Path(directory) / "grant.json"
            grant_path.write_text(json.dumps(self.grant(
                expiry=datetime.fromtimestamp(now + 600, timezone.utc))))
            grant_path.chmod(0o600)
            with patch("employee_read_demo.google_write_credential.validate_write_handoff"), \
                 patch("employee_read_demo.google_write_credential._userinfo", return_value={
                     "sub": "subject-1", "email": "jules@example.test",
                     "email_verified": True, "hd": "example.test",
                 }):
                lease = self.lease(Path("evidence"), grant_path, self.pins(), now=now)
                self.assertEqual(lease.expires_at, now + 600)
                self.assertEqual(lease.access_token, "private-access")
                self.assertNotIn("private-access", repr(lease))
                with self.assertRaises(WriteCredentialDenied):
                    lease_jules_write_token(Path("evidence"), grant_path, self.pins(),
                                            connection_id="other", connection_generation=1,
                                            now=now)

    def test_broad_scope_and_wrong_subject_are_refused(self) -> None:
        now = int(datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp())
        with tempfile.TemporaryDirectory() as directory:
            grant_path = Path(directory) / "grant.json"
            grant = self.grant(expiry=datetime.fromtimestamp(now + 600, timezone.utc),
                               scopes=["openid", "https://www.googleapis.com/auth/userinfo.email",
                                       "https://www.googleapis.com/auth/drive"])
            grant_path.write_text(json.dumps(grant))
            grant_path.chmod(0o600)
            with patch("employee_read_demo.google_write_credential.validate_write_handoff"), \
                 patch("employee_read_demo.google_write_credential._userinfo") as userinfo:
                with self.assertRaises(WriteCredentialDenied):
                    self.lease(Path("evidence"), grant_path, self.pins(), now=now)
                userinfo.assert_not_called()
            grant["scopes"][-1] = "https://www.googleapis.com/auth/drive.file"
            grant_path.write_text(json.dumps(grant))
            with patch("employee_read_demo.google_write_credential.validate_write_handoff"), \
                 patch("employee_read_demo.google_write_credential._userinfo", return_value={
                     "sub": "someone-else", "email": "jules@example.test",
                     "email_verified": True, "hd": "example.test",
                 }):
                with self.assertRaises(WriteCredentialDenied):
                    self.lease(Path("evidence"), grant_path, self.pins(), now=now)

    def test_expiring_grant_refreshes_and_rechecks_subject(self) -> None:
        now = int(datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp())
        with tempfile.TemporaryDirectory() as directory:
            grant_path = Path(directory) / "grant.json"
            grant_path.write_text(json.dumps(self.grant(
                expiry=datetime.fromtimestamp(now + 20, timezone.utc))))
            grant_path.chmod(0o600)
            with patch("employee_read_demo.google_write_credential.validate_write_handoff"), \
                 patch("employee_read_demo.google_write_credential._exchange_refresh", return_value={
                     "access_token": "new-access", "expires_in": 3600,
                     "scope": "openid https://www.googleapis.com/auth/userinfo.email "
                              "https://www.googleapis.com/auth/drive.file",
                 }), \
                 patch("employee_read_demo.google_write_credential._userinfo", return_value={
                     "sub": "subject-1", "email": "jules@example.test",
                     "email_verified": True, "hd": "example.test",
                 }) as userinfo:
                lease = self.lease(Path("evidence"), grant_path, self.pins(), now=now)
                self.assertEqual(lease.expires_at, now + 3600)
                userinfo.assert_called_once_with("new-access")
