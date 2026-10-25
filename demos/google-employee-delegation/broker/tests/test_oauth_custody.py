from __future__ import annotations

import json
import gzip
import io
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests
import urllib3
from cryptography.fernet import Fernet

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import VerifiedRead, native_body_digest
from employee_read_demo.browser_sessions import BrowserSessionStore, SessionDenied
from employee_read_demo.google_oauth import (
    CONNECT_SCOPES, GoogleOAuth, GoogleOAuthConfig, OAuthRejected,
    OAuthResult, OAuthStateStore,
    _bounded_json_response, normalize_scopes,
)
from employee_read_demo.operator_cli import offboard_employee
from employee_read_demo.token_store import TokenVault
from test_admission import task


class OAuthCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "broker.sqlite3"
        self.now = int(time.time())

    def test_desktop_loopback_origin_is_valid_redirect(self) -> None:
        GoogleOAuthConfig("client-id", "synthetic-secret", "http://127.0.0.1:8765",
                          "example.invalid").validate()

    def test_google_email_scope_aliases_normalize_to_one_custody_scope(self) -> None:
        self.assertEqual(normalize_scopes(["openid", "email",
                                           "https://www.googleapis.com/auth/drive.readonly"]),
                         CONNECT_SCOPES)
        self.assertEqual(normalize_scopes(CONNECT_SCOPES), CONNECT_SCOPES)

    def test_compressed_token_json_is_decoded_with_post_decompression_limit(self) -> None:
        payload = b'{"access_token":"synthetic-access"}'
        def response():
            result = requests.Response()
            result.status_code = 200
            result.raw = urllib3.response.HTTPResponse(
                body=io.BytesIO(gzip.compress(payload)),
                headers={"Content-Encoding": "gzip"}, preload_content=False,
            )
            return result
        self.assertEqual(_bounded_json_response(response(), len(payload)),
                         {"access_token": "synthetic-access"})
        with self.assertRaises(ValueError):
            _bounded_json_response(response(), len(payload) - 1)

    def test_state_is_one_use_and_connect_requires_bound_subject(self) -> None:
        states = OAuthStateStore(self.path)
        oauth = GoogleOAuth(GoogleOAuthConfig(
            "client-id", "operator-secret", "http://127.0.0.1:8765",
            "example.invalid",
        ), states)
        browser = BrowserSessionStore(self.path)
        anonymous = browser.create()
        session = browser.login(anonymous, issuer="https://accounts.google.com",
                                subject="google-subject-a")
        with self.assertRaises(OAuthRejected):
            oauth.begin("connect", browser_cookie=session.cookie,
                        expected_subject="google-subject-b")
        uri, state = oauth.begin("connect", browser_cookie=session.cookie,
                                expected_subject="google-subject-a")
        query = parse_qs(urlsplit(uri).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertIn("https://www.googleapis.com/auth/drive.readonly", query["scope"][0])
        with self.assertRaises(OAuthRejected):
            states.consume(state, int(time.time()), browser.create().cookie)
        self.assertEqual(states.consume(state, int(time.time()), session.cookie)[3],
                         "google-subject-a")
        with self.assertRaises(OAuthRejected):
            states.consume(state, int(time.time()), session.cookie)

    def test_browser_session_rotates_and_checks_csrf(self) -> None:
        sessions = BrowserSessionStore(self.path)
        original = sessions.create(now=self.now)
        sessions.check_csrf(original, original.csrf)
        with self.assertRaises(SessionDenied):
            sessions.check_csrf(original, "wrong")
        signed_in = sessions.login(original, issuer="https://accounts.google.com",
                                   subject="google-subject-a", now=self.now)
        self.assertNotEqual(original.cookie, signed_in.cookie)
        self.assertNotEqual(original.csrf, signed_in.csrf)
        with self.assertRaises(SessionDenied):
            sessions.get(original.cookie, now=self.now)
        self.assertEqual(sessions.get(signed_in.cookie, now=self.now).subject,
                         "google-subject-a")
        connected = sessions.set_connection(signed_in, "connection-a", now=self.now)
        self.assertEqual(connected.connection_id, "connection-a")
        self.assertEqual(sessions.get(signed_in.cookie, now=self.now).connection_id,
                         "connection-a")

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
        self.assertTrue(vault.active_connection(connection_id, result.issuer, result.subject))
        descriptor = task(self.now)
        descriptor = type(descriptor)(**{**descriptor.__dict__, "connection_id": connection_id})
        AdmissionStore(self.path).enroll(descriptor)
        self.assertEqual(vault.lease(descriptor, now=self.now).access_token, "synthetic-access-token")
        self.assertNotIn(b"synthetic-access-token", self.path.read_bytes())
        self.assertEqual(vault.disconnect(connection_id), 2)
        self.assertFalse(vault.active_connection(connection_id, result.issuer, result.subject))
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
        key = Fernet.generate_key()
        vault = TokenVault(self.path, encryption_key=key, client_id="client-id")
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
        sessions = BrowserSessionStore(self.path)
        browser = sessions.login(sessions.create(now=self.now),
                                 issuer=result.issuer, subject=result.subject,
                                 company="atlas-studio", now=self.now)
        with vault._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    "other-binding", "other-company", "other-person", result.issuer,
                    result.subject, "other-principal", b"other-identity", "b" * 64,
                ))
        other_browser = sessions.login(sessions.create(now=self.now),
                                       issuer=result.issuer, subject=result.subject,
                                       company="other-company", now=self.now)
        descriptor = type(task(self.now))(**{**task(self.now).__dict__, "connection_id": connection_id})
        store = AdmissionStore(self.path)
        store.enroll(descriptor)
        command = descriptor.calls()[0]
        challenge = store.issue_challenge(descriptor, native_body_digest(command, descriptor.service), now=self.now)
        reservation = store.claim(descriptor, VerifiedRead(command, b"x" * 32, "authorized"),
                                  challenge, now=self.now)
        with self.assertRaises(AdmissionDenied):
            vault.offboard("binding-1", company="different-company")
        self.assertEqual(sessions.get(browser.cookie, now=self.now).subject, result.subject)
        config = Path(self.temp.name) / "oauth.json"
        config.write_text(json.dumps({
            "client_id": "client-id", "client_secret": "synthetic-secret",
            "redirect_uri": "http://127.0.0.1:8765",
            "hosted_domain": "example.invalid",
        }))
        config.chmod(0o600)
        key_file = Path(self.temp.name) / "fernet.key"
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        self.assertEqual(offboard_employee(self.path, "binding-1", "atlas-studio",
                                           config, key_file)["status"], "offboarded")
        with self.assertRaises(AdmissionDenied):
            store.release(reservation, b"content", now=self.now)
        with self.assertRaises(AdmissionDenied):
            vault.lease(descriptor, now=self.now)
        with self.assertRaises(SessionDenied):
            sessions.get(browser.cookie, now=self.now)
        self.assertEqual(sessions.get(other_browser.cookie, now=self.now).company,
                         "other-company")
        with self.assertRaises(SessionDenied):
            sessions.login(sessions.create(now=self.now), issuer=result.issuer,
                           subject=result.subject, company="atlas-studio", now=self.now)


if __name__ == "__main__":
    unittest.main()
