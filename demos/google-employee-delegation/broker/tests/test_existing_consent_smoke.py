from __future__ import annotations

import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.existing_consent_smoke import (
    EXISTING_GRANT_SCOPES, ExistingConsentDenied, ExistingConsentPins,
    ExistingDemoCoConsentLease, USERINFO_URL, _userinfo,
)
from employee_read_demo.google_drive import GoogleDenied, GoogleDriveReader
from employee_read_demo.google_oauth import TOKEN_URL
from test_admission import task


class ExistingConsentSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "jules.json"
        self.now = int(time.time())
        descriptor = task(self.now)
        self.task = type(descriptor)(**{
            **descriptor.__dict__, "company_id": "atlas-studio",
            "instance_id": "live-test-atlas-20261025",
        })
        self.pins = ExistingConsentPins(
            "atlas-studio", "live-test-atlas-20261025", "person-jules",
            "C0218tf2n", "auths.dev", "jules@auths.dev", "google-subject-jules",
            "demo-co-client-id", self.task.employee_principal,
            self.task.identity_binding_ref, self.task.connection_id,
            self.task.connection_generation, self.task.task_id, self.task.file_ids,
        )
        self.grant = {
            "client_id": "demo-co-client-id", "client_secret": "synthetic-secret",
            "refresh_token": "synthetic-refresh", "token": "synthetic-access",
            "token_uri": TOKEN_URL, "universe_domain": "googleapis.com",
            "scopes": sorted(EXISTING_GRANT_SCOPES),
            "expiry": datetime.fromtimestamp(self.now + 600, timezone.utc).isoformat(),
        }
        self._write()

    def _write(self) -> None:
        self.path.write_text(json.dumps(self.grant), encoding="utf-8")
        self.path.chmod(0o600)

    def _claims(self) -> dict:
        return {"sub": "google-subject-jules", "email": "jules@auths.dev",
                "email_verified": True, "hd": "auths.dev"}

    def test_matching_task_and_verified_google_subject_lease_existing_token(self) -> None:
        with patch("employee_read_demo.existing_consent_smoke._userinfo", return_value=self._claims()) as check:
            lease = ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)
        self.assertEqual(lease.access_token, "synthetic-access")
        check.assert_called_once_with("synthetic-access")

    def test_wrong_task_is_denied_before_secret_file_or_network(self) -> None:
        other = type(self.task)(**{**self.task.__dict__, "connection_id": "different"})
        with patch("employee_read_demo.existing_consent_smoke._private_grant") as secret:
            with self.assertRaises(ExistingConsentDenied):
                ExistingDemoCoConsentLease(self.path, self.pins).lease(other, now=self.now)
        secret.assert_not_called()
        broader = type(self.task)(**{**self.task.__dict__, "file_ids": ("file-A", "file-C")})
        with patch("employee_read_demo.existing_consent_smoke._private_grant") as secret:
            with self.assertRaises(ExistingConsentDenied):
                ExistingDemoCoConsentLease(self.path, self.pins).lease(broader, now=self.now)
        secret.assert_not_called()

    def test_reader_refuses_outside_document_before_secret_or_google_request(self) -> None:
        reader = GoogleDriveReader(self.task, ExistingDemoCoConsentLease(self.path, self.pins))
        wrong = type(self.task.calls()[0])(**{
            **self.task.calls()[0].__dict__, "file_id": "outside-document",
        })
        with (patch("employee_read_demo.existing_consent_smoke._private_grant") as secret,
              patch("employee_read_demo.google_drive._get") as provider):
            with self.assertRaises(GoogleDenied):
                reader.read_exact(wrong)
        secret.assert_not_called()
        provider.assert_not_called()

    def test_google_subject_and_domain_are_required(self) -> None:
        claims = {**self._claims(), "sub": "different"}
        with patch("employee_read_demo.existing_consent_smoke._userinfo", return_value=claims):
            with self.assertRaises(ExistingConsentDenied):
                ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)
        claims = {**self._claims(), "hd": None}
        with patch("employee_read_demo.existing_consent_smoke._userinfo", return_value=claims):
            with self.assertRaises(ExistingConsentDenied):
                ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)

    def test_missing_scope_or_private_file_denies_before_userinfo(self) -> None:
        self.grant["scopes"] = ["openid", "email"]
        self._write()
        with patch("employee_read_demo.existing_consent_smoke._userinfo") as userinfo:
            with self.assertRaises(ExistingConsentDenied):
                ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)
        userinfo.assert_not_called()
        self.grant["scopes"] = sorted(EXISTING_GRANT_SCOPES)
        self._write()
        self.path.chmod(0o644)
        with self.assertRaises(ExistingConsentDenied):
            ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)

    def test_expired_token_refreshes_only_after_pin_checks(self) -> None:
        self.grant["expiry"] = datetime.fromtimestamp(self.now - 1, timezone.utc).isoformat()
        self._write()
        with (patch("employee_read_demo.existing_consent_smoke._exchange_refresh",
                    return_value={"access_token": "refreshed-access", "expires_in": 3600,
                                  "scope": " ".join(sorted(EXISTING_GRANT_SCOPES))}) as refresh,
              patch("employee_read_demo.existing_consent_smoke._userinfo",
                    return_value=self._claims()) as userinfo):
            lease = ExistingDemoCoConsentLease(self.path, self.pins).lease(self.task, now=self.now)
        self.assertEqual(lease.access_token, "refreshed-access")
        refresh.assert_called_once_with("demo-co-client-id", "synthetic-secret", "synthetic-refresh")
        userinfo.assert_called_once_with("refreshed-access")
        self.assertEqual(json.loads(self.path.read_text())["token"], "synthetic-access")

    def test_userinfo_uses_fixed_get_without_redirect_or_proxy(self) -> None:
        class Response:
            status_code = 200
            headers = {"Content-Type": "application/json", "Content-Encoding": "identity"}

            class Raw:
                def read(self, count):
                    return json.dumps({"sub": "google-subject-jules"}).encode()

            raw = Raw()

            def close(self):
                pass

        class Session:
            trust_env = True

            def get(self, url, *, headers, timeout, allow_redirects, stream):
                self.asserted = (url, headers, timeout, allow_redirects, stream, self.trust_env)
                return Response()

            def close(self):
                pass

        session = Session()
        with patch("employee_read_demo.existing_consent_smoke.requests.Session", return_value=session):
            self.assertEqual(_userinfo("synthetic-access")["sub"], "google-subject-jules")
        self.assertEqual(session.asserted, (
            USERINFO_URL,
            {"Authorization": "Bearer synthetic-access", "Accept-Encoding": "identity"},
            15, False, True, False,
        ))


if __name__ == "__main__":
    unittest.main()
