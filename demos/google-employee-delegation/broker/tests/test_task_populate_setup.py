from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.google_create_preflight import (
    current_populate_preflight_rule_digest,
)
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_populate_setup import (
    prepare_populate_preflight_installation,
)
from employee_read_demo.task_write_card import _installation


class TaskPopulateSetupTests(unittest.TestCase):
    def test_private_signer_and_pins_are_ready_before_task_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            seed = root / "preflight.seed"
            output = root / "task-installation.json"
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
            }
            base.write_text(json.dumps(config))
            os.chmod(base, 0o600)
            result = prepare_populate_preflight_installation(
                base, seed_out=seed, installation_out=output,
            )
            self.assertEqual(os.stat(seed).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(len(seed.read_bytes()), 32)
            public = Ed25519PrivateKey.from_private_bytes(
                seed.read_bytes()).public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw,
                ).hex()
            installed = json.loads(output.read_bytes())
            self.assertEqual(installed["populate_preflight"], {
                "public_key_hex": public,
                "rule_digest": current_populate_preflight_rule_digest(),
            })
            self.assertEqual(result["public_key_hex"], public)
            self.assertNotIn(seed.read_bytes().hex(), output.read_text())
            recovered = installed | {"recovery_attestation": {
                "public_key_hex": public, "rule_digest": "f" * 64,
            }}
            recovery_path = root / "recovery-installation.json"
            recovery_path.write_text(json.dumps(recovered))
            os.chmod(recovery_path, 0o600)
            self.assertEqual(_installation(recovery_path), recovered)
            recovered["recovery_attestation"]["rule_digest"] = "invalid"
            recovery_path.write_text(json.dumps(recovered))
            with self.assertRaises(OperatorDenied):
                _installation(recovery_path)
            with self.assertRaises(OperatorDenied):
                prepare_populate_preflight_installation(
                    base, seed_out=seed, installation_out=output,
                )
            self.assertEqual(os.stat(seed).st_mode & 0o777, 0o600)

    def test_incomplete_pair_cannot_generate_signer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps({
                "schema": "auths.gateway-task-installation/4",
                "recipe_digests": ["a" * 64],
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
            seed = root / "preflight.seed"
            output = root / "task-installation.json"
            with self.assertRaises(OperatorDenied):
                prepare_populate_preflight_installation(
                    base, seed_out=seed, installation_out=output,
                )
            self.assertFalse(seed.exists())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
