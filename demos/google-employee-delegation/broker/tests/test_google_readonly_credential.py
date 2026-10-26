"""A provider-readable excluded file still needs a checked Jules bearer."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.google_readonly_credential import (
    ReadOnlyCredentialDenied, ReadOnlyCredentialPins,
    lease_jules_readonly_token,
)
from employee_read_demo.project_b_grants_handoff import ProjectBGrantPins


class ReadOnlyCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pins = ReadOnlyCredentialPins(
            project_b=ProjectBGrantPins(
                company="atlas-studio", instance="live-test-atlas-20261025",
                definition_hash="a" * 64, jules_subject="subject-jules",
                document_id="project-b-doc", drive_id="drive-1",
                evidence_sha256="b" * 64,
            ),
            client_id="desktop-client", primary_domain="auths.dev",
            connection_id="conn-review", connection_generation=1,
        )
        self.grant = {
            "client_id": "desktop-client", "token_uri":
                "https://oauth2.googleapis.com/token",
            "universe_domain": "googleapis.com",
            "scopes": ["openid",
                       "https://www.googleapis.com/auth/userinfo.email",
                       "https://www.googleapis.com/auth/drive.readonly"],
            "token": "stale-token", "expiry": "2026-10-25T00:00:00Z",
            "client_secret": "private-client-secret",
            "refresh_token": "private-refresh-token",
        }
        self.claims = {
            "sub": "subject-jules", "email": "jules@auths.dev",
            "email_verified": True, "hd": "auths.dev",
        }

    def _lease(self):
        return lease_jules_readonly_token(
            Path("/private/evidence"), Path("/private/grant"), self.pins,
            connection_id="conn-review", connection_generation=1,
            now=1792976400,
        )

    def test_refresh_checks_exact_scope_and_live_subject(self) -> None:
        with (patch("employee_read_demo.google_readonly_credential."
                    "validate_project_b_grants") as evidence,
              patch("employee_read_demo.google_readonly_credential._private_grant",
                    return_value=self.grant),
              patch("employee_read_demo.google_readonly_credential._exchange_refresh",
                    return_value={
                        "access_token": "fresh-token", "expires_in": 3600,
                        "scope": " ".join(self.grant["scopes"]),
                    }) as refresh,
              patch("employee_read_demo.google_readonly_credential._userinfo",
                    return_value=self.claims) as userinfo):
            lease = self._lease()
        evidence.assert_called_once()
        refresh.assert_called_once()
        userinfo.assert_called_once_with("fresh-token")
        self.assertEqual(lease.access_token, "fresh-token")
        self.assertEqual(lease.expires_at, 1792980000)

    def test_write_scope_or_wrong_subject_is_refused(self) -> None:
        with (patch("employee_read_demo.google_readonly_credential."
                    "validate_project_b_grants"),
              patch("employee_read_demo.google_readonly_credential._private_grant",
                    return_value=self.grant),
              patch("employee_read_demo.google_readonly_credential._exchange_refresh",
                    return_value={"access_token": "fresh", "expires_in": 3600}),
              patch("employee_read_demo.google_readonly_credential._userinfo",
                    return_value=self.claims | {"sub": "other"})):
            with self.assertRaises(ReadOnlyCredentialDenied):
                self._lease()
            self.grant["scopes"][-1] = (
                "https://www.googleapis.com/auth/drive.file")
            with self.assertRaises(ReadOnlyCredentialDenied):
                self._lease()

    def test_changed_connection_generation_is_refused_before_grant_read(self) -> None:
        with patch("employee_read_demo.google_readonly_credential._private_grant") as grant:
            with self.assertRaises(ReadOnlyCredentialDenied):
                lease_jules_readonly_token(
                    Path("/private/evidence"), Path("/private/grant"), self.pins,
                    connection_id="conn-review", connection_generation=2,
                    now=1792976400,
                )
            grant.assert_not_called()


if __name__ == "__main__":
    unittest.main()
