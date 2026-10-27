from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_recovery_operator import (
    current_recovery_attestation_rule_digest,
)
from employee_read_demo.task_recovery_setup import (
    prepare_recovery_attestation_installation,
)
from employee_read_demo.task_write_card import _installation


class TaskRecoverySetupTests(unittest.TestCase):
    def test_recovery_signer_is_distinct_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "paired.json"
            seed = root / "recovery.seed"
            output = root / "recovery-installation.json"
            existing = Ed25519PrivateKey.generate().public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw,
            ).hex()
            config = {
                "schema": "auths.gateway-task-installation/4",
                "recipe_digests": ["a" * 64, "b" * 64],
                "pins": {
                    "company_id": "atlas-studio", "initiator_principal": "human", "approver_principal": "human",
                    "agent_principal": "agent", "agent_key_fingerprint": "c" * 64,
                    "connection_id": "jules-google", "connection_generation": 1,
                    "connection_subject": "jules", "delivery_channel": "agent-channel",
                    "operator_policy_digest": "d" * 64,
                    "allow_bounded_writes": False, "permitted_read_scopes": [],
                },
                "populate_preflight": {
                    "public_key_hex": existing, "rule_digest": "e" * 64,
                },
            }
            base.write_text(json.dumps(config))
            os.chmod(base, 0o600)
            result = prepare_recovery_attestation_installation(
                base, seed_out=seed, installation_out=output,
            )
            self.assertEqual(os.stat(seed).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            public = Ed25519PrivateKey.from_private_bytes(
                seed.read_bytes(),
            ).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            self.assertNotEqual(public, existing)
            installed = _installation(output)
            self.assertEqual(installed["recovery_attestation"], {
                "public_key_hex": public,
                "rule_digest": current_recovery_attestation_rule_digest(),
            })
            self.assertEqual(result["public_key_hex"], public)
            self.assertNotIn(seed.read_bytes().hex(), output.read_text())
            with self.assertRaises(OperatorDenied):
                prepare_recovery_attestation_installation(
                    base, seed_out=seed, installation_out=output,
                )

    def test_missing_preflight_cannot_install_recovery_signer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "paired.json"
            base.write_text(json.dumps({
                "schema": "auths.gateway-task-installation/4",
                "recipe_digests": ["a" * 64, "b" * 64],
                "pins": {
                    "company_id": "atlas-studio", "initiator_principal": "human", "approver_principal": "human",
                    "agent_principal": "agent", "agent_key_fingerprint": "c" * 64,
                    "connection_id": "jules-google", "connection_generation": 1,
                    "connection_subject": "jules", "delivery_channel": "agent-channel",
                    "operator_policy_digest": "d" * 64,
                    "allow_bounded_writes": False, "permitted_read_scopes": [],
                },
            }))
            os.chmod(base, 0o600)
            seed = root / "recovery.seed"
            output = root / "recovery-installation.json"
            with self.assertRaises(OperatorDenied):
                prepare_recovery_attestation_installation(
                    base, seed_out=seed, installation_out=output,
                )
            self.assertFalse(seed.exists())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
