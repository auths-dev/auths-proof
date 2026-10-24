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
from employee_read_demo.google_oauth import LOGIN_SCOPES, OAuthResult


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
        self.assertEqual(binding.principal, identity.identity_id)
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


if __name__ == "__main__":
    unittest.main()
