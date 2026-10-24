from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import VerifiedRead, native_body_digest
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
        with vault._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    "binding-1", "atlas-studio", "person-a", result.issuer, result.subject,
                    "employee-principal", b"synthetic-identity", "a" * 64,
                ))
        wrong = OAuthResult(**{**result.__dict__, "subject": "google-subject-b"})
        with self.assertRaises(AdmissionDenied):
            vault.link(company="atlas-studio", employee_principal="employee-principal",
                       binding_ref="binding-1", identity=wrong, now=self.now)
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

    def test_refresh_is_generation_checked_and_cannot_resurrect_disconnect(self) -> None:
        vault = TokenVault(self.path, encryption_key=Fernet.generate_key(), client_id="client-id",
                           refresh_client_secret="operator-secret")
        result = OAuthResult("connect", "https://accounts.google.com", "google-subject-a",
                             None, CONNECT_SCOPES, "old-access", "old-refresh", 1)
        with vault._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    "binding-1", "atlas-studio", "person-a", result.issuer, result.subject,
                    "employee-principal", b"synthetic-identity", "a" * 64,
                ))
        connection_id = vault.link(company="atlas-studio", employee_principal="employee-principal",
                                   binding_ref="binding-1", identity=result, now=self.now)
        descriptor = type(task(self.now))(**{**task(self.now).__dict__, "connection_id": connection_id})
        def disconnect_then_return(client_id: str, client_secret: str, refresh_token: str) -> dict:
            self.assertEqual(refresh_token, "old-refresh")
            vault.disconnect(connection_id)
            return {"access_token": "new-access", "expires_in": 3600}
        with patch("employee_read_demo.token_store._exchange_refresh", disconnect_then_return):
            with self.assertRaises(AdmissionDenied):
                vault.lease(descriptor, now=self.now + 2)
        with self.assertRaises(AdmissionDenied):
            vault.lease(descriptor, now=self.now + 3)

    def test_parallel_refresh_is_refused_and_success_retains_subject(self) -> None:
        vault = TokenVault(self.path, encryption_key=Fernet.generate_key(), client_id="client-id",
                           refresh_client_secret="operator-secret")
        result = OAuthResult("connect", "https://accounts.google.com", "google-subject-a",
                             None, CONNECT_SCOPES, "old-access", "old-refresh", 1)
        with vault._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    "binding-1", "atlas-studio", "person-a", result.issuer, result.subject,
                    "employee-principal", b"synthetic-identity", "a" * 64,
                ))
        connection_id = vault.link(company="atlas-studio", employee_principal="employee-principal",
                                   binding_ref="binding-1", identity=result, now=self.now)
        descriptor = type(task(self.now))(**{**task(self.now).__dict__, "connection_id": connection_id})
        def exchange(client_id: str, client_secret: str, refresh_token: str) -> dict:
            with self.assertRaises(AdmissionDenied):
                vault.lease(descriptor, now=self.now + 2)
            return {"access_token": "new-access", "expires_in": 3600}
        with patch("employee_read_demo.token_store._exchange_refresh", exchange):
            lease = vault.lease(descriptor, now=self.now + 2)
        self.assertEqual(lease.access_token, "new-access")
        self.assertEqual(vault.lease(descriptor, now=self.now + 3).access_token, "new-access")

    def test_offboarding_closes_admission_and_token_custody(self) -> None:
        vault = TokenVault(self.path, encryption_key=Fernet.generate_key(), client_id="client-id")
        result = OAuthResult("connect", "https://accounts.google.com", "google-subject-a",
                             None, CONNECT_SCOPES, "access", None, 3600)
        with vault._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    "binding-1", "atlas-studio", "person-a", result.issuer, result.subject,
                    "employee-principal", b"synthetic-identity", "a" * 64,
                ))
        connection_id = vault.link(company="atlas-studio", employee_principal="employee-principal",
                                   binding_ref="binding-1", identity=result, now=self.now)
        descriptor = type(task(self.now))(**{**task(self.now).__dict__, "connection_id": connection_id})
        store = AdmissionStore(self.path)
        store.enroll(descriptor)
        command = descriptor.calls()[0]
        challenge = store.issue_challenge(descriptor, native_body_digest(command), now=self.now)
        reservation = store.claim(descriptor, VerifiedRead(command, b"x" * 32, "authorized"),
                                  challenge, now=self.now)
        vault.offboard("binding-1")
        with self.assertRaises(AdmissionDenied):
            store.release(reservation, b"content", now=self.now)
        with self.assertRaises(AdmissionDenied):
            vault.lease(descriptor, now=self.now)


if __name__ == "__main__":
    unittest.main()
