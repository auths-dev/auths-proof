"""The partial lab must require a real browser-key signature before any read."""

from __future__ import annotations

import base64
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.partial_delegation_lab import PartialDelegationLab, PartialInputs


class PartialDelegationLabTests(unittest.TestCase):
    def test_wrong_browser_signature_is_one_use_and_never_opens_read_state(self) -> None:
        inputs = PartialInputs(
            "a" * 64, "b" * 64, "C0218tf2n", "auths.dev", "test-subject",
            "jules@auths.dev", "test-client", "file-project-a", "c" * 64,
            "file-project-b",
        )
        lab = PartialDelegationLab(inputs, Path("/unopened/private/grant"))
        self.addCleanup(lab.close)
        browser = Ed25519PrivateKey.generate()
        public = browser.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with patch("employee_read_demo.partial_delegation_lab.ExistingDemoCoConsentLease.lease"):
            prepared = lab.prepare(public)
        self.assertFalse(prepared["browser_google_identity_verified"])
        preimage = prepared["signing_preimage"]
        raw = base64.urlsafe_b64decode(preimage + "=" * (-len(preimage) % 4))
        wrong = Ed25519PrivateKey.generate().sign(raw)
        with self.assertRaises(InvalidSignature):
            lab.approve_and_run(wrong)
        self.assertFalse(lab.db.exists())
        with self.assertRaises(ValueError):
            lab.approve_and_run(browser.sign(raw))


if __name__ == "__main__":
    unittest.main()
