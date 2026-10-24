from __future__ import annotations

import unittest

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity

from employee_read_demo.authority_identity import authority_for_identity_packet


class AuthorityIdentityTests(unittest.TestCase):
    def test_proven_identity_key_derives_verifier_accepted_principal(self) -> None:
        key = _native.DevelopmentEd25519Key.from_seed(b"\x6a" * 32)
        identity = create_raw_key_ed25519_identity(bytes(key.public_key))
        principal, evidence = authority_for_identity_packet(identity.to_bytes())
        self.assertEqual(principal, key.principal)
        self.assertEqual(evidence, bytes(key.evidence))
        self.assertNotEqual(principal, identity.identity_id)

    def test_invalid_identity_packet_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            authority_for_identity_packet(b"untrusted")


if __name__ == "__main__":
    unittest.main()
