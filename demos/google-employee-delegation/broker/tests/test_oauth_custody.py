from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.google_oauth import (
    CONNECT_SCOPES, GoogleOAuth, GoogleOAuthConfig, OAuthRejected,
    OAuthResult, OAuthStateStore,
)
from employee_read_demo.token_store import TokenVault
from test_admission import task


class OAuthCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "broker.sqlite3"
        self.now = int(time.time())

    def test_state_is_one_use_and_connect_requires_bound_subject(self) -> None:
        states = OAuthStateStore(self.path)
        oauth = GoogleOAuth(GoogleOAuthConfig(
            "client-id", "operator-secret", "http://127.0.0.1:8765/api/v1/google/callback",
            "example.invalid",
        ), states)
        uri, state = oauth.begin("connect", expected_subject="google-subject-a")
        query = parse_qs(urlsplit(uri).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertIn("https://www.googleapis.com/auth/drive.readonly", query["scope"][0])
        self.assertEqual(states.consume(state, int(time.time()))[3], "google-subject-a")
        with self.assertRaises(OAuthRejected):
            states.consume(state, int(time.time()))

    def test_encrypted_token_is_bound_and_disconnect_closes_lease(self) -> None:
        vault = TokenVault(self.path, encryption_key=Fernet.generate_key(), client_id="client-id")
        result = OAuthResult("connect", "https://accounts.google.com", "google-subject-a",
                             "employee@example.invalid", CONNECT_SCOPES, "synthetic-access-token",
                             None, 3600)
        connection_id = vault.link(company="atlas-studio", employee_principal="employee-principal",
                                   binding_ref="binding-1", identity=result, now=self.now)
        descriptor = task(self.now)
        descriptor = type(descriptor)(**{**descriptor.__dict__, "connection_id": connection_id})
        AdmissionStore(self.path).enroll(descriptor)
        self.assertEqual(vault.lease(descriptor, now=self.now).access_token, "synthetic-access-token")
        self.assertNotIn(b"synthetic-access-token", self.path.read_bytes())
        self.assertEqual(vault.disconnect(connection_id), 2)
        with self.assertRaises(AdmissionDenied):
            vault.lease(descriptor, now=self.now)


if __name__ == "__main__":
    unittest.main()
