from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from auths.identity.authoring import create_raw_key_ed25519_identity, prepare_identity_message
from employee_read_demo.demo_co_contract import CompanyImport
from employee_read_demo.enrollment import EnrollmentDenied, EnrollmentStore, VerifiedGoogleSubject
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.google_oauth import LOGIN_SCOPES, OAuthResult
from employee_read_demo.jules_write_context import JulesWriteContext


class EnrollmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EnrollmentStore(Path(self.temp.name) / "broker.sqlite3")
        self.company = CompanyImport({
            "company_id": "atlas-studio",
            "people": [{"provider": "google", "status": "ready", "issuer": "https://accounts.google.com",
                        "provider_subject": "subject-a", "logical_person_id": "person-morgan"}],
        }, {}, "a" * 64, True, True)
        self.login = OAuthResult("login", "https://accounts.google.com", "subject-a", None,
                                 LOGIN_SCOPES, "synthetic-login-token", None, 3600)

    def test_key_possession_binds_exact_google_subject_and_replays_fail(self) -> None:
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        identity = create_raw_key_ed25519_identity(public)
        nonce, message = self.store.prepare(self.company, self.login, identity.to_bytes())
        prepared = prepare_identity_message(identity, message=message)
        signature = key.sign(prepared.signing_preimage)
        binding = asyncio.run(self.store.complete(
            self.company, self.login, nonce, identity.to_bytes(), signature,
        ))
        self.assertEqual(binding.principal, authority_for_identity_packet(identity.to_bytes())[0])
        self.assertNotEqual(binding.principal, identity.identity_id)
        self.assertEqual(binding.subject, "subject-a")
        self.assertEqual(self.store.lookup(self.company, VerifiedGoogleSubject(
            "connect", binding.issuer, binding.subject,
        )), binding)
        with self.assertRaises(EnrollmentDenied):
            asyncio.run(self.store.complete(self.company, self.login, nonce, identity.to_bytes(), signature))

    def test_unmapped_subject_cannot_prepare(self) -> None:
        other = OAuthResult("login", "https://accounts.google.com", "subject-b", None,
                            LOGIN_SCOPES, "synthetic-login-token", None, 3600)
        with self.assertRaises(EnrollmentDenied):
            self.store.prepare(self.company, other, b"identity")

    def test_jules_only_context_enrolls_one_google_subject_without_full_import(self) -> None:
        context = JulesWriteContext(
            {"company_id": "atlas-studio", "instance_id": "live-test-atlas",
             "people": [{"logical_person_id": "jules", "provider": "google",
                         "status": "ready", "provider_subject": "jules-subject"}]},
            "c" * 64, "jules-subject",
        )
        self.assertFalse(context.google_ready)
        self.assertFalse(context.adoptable)
        login = OAuthResult("login", "https://accounts.google.com", "jules-subject",
                            None, LOGIN_SCOPES, "synthetic-login-token", None, 3600)
        key = Ed25519PrivateKey.generate()
        identity = create_raw_key_ed25519_identity(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
        nonce, message = self.store.prepare(context, login, identity.to_bytes())
        signature = key.sign(prepare_identity_message(
            identity, message=message,
        ).signing_preimage)
        binding = asyncio.run(self.store.complete(
            context, login, nonce, identity.to_bytes(), signature,
        ))
        self.assertEqual(binding.logical_person_id, "jules")
        self.assertEqual(self.store.lookup(context, VerifiedGoogleSubject(
            "login", login.issuer, login.subject,
        )), binding)
        for subject, issuer in (("other-subject", login.issuer),
                                (login.subject, "https://untrusted.example")):
            with self.assertRaisesRegex(EnrollmentDenied, "pinned Jules"):
                self.store.lookup(context, VerifiedGoogleSubject(
                    "login", issuer, subject,
                ))


if __name__ == "__main__":
    unittest.main()
