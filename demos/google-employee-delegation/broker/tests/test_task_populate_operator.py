from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_preflight import (
    JulesCreatedChildPreflight, current_populate_preflight_rule_digest,
)
from employee_read_demo.google_write_credential import WriteCredentialPins
from employee_read_demo.google_populate_failure_handoff import PopulateFailureTarget
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_populate_operator import record_jules_populate_preflight
from employee_read_demo.write_handoff import WriteHandoffPins


class TaskPopulateOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.gateway = self.root / "gateway"
        self.gateway.write_bytes(b"pinned gateway")
        self.gateway.chmod(0o700)
        self.seed_path = self.root / "preflight.seed"
        self.seed_path.write_bytes(b"\x55" * 32)
        self.seed_path.chmod(0o600)
        self.signer = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
        self.pins = WriteCredentialPins(
            producer=WriteHandoffPins(
                company="atlas", instance="fixture", definition_hash="a" * 64,
                customer_id="customer", jules_subject="jules-subject",
                jules_email="jules@example.test", evidence_sha256="b" * 64,
            ),
            client_id="client", primary_domain="example.test",
            connection_id="jules-google", connection_generation=1,
        )
        self.installation = {
            "populate_preflight": {
                "public_key_hex": self.signer.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw,
                ).hex(),
                "rule_digest": current_populate_preflight_rule_digest(),
            },
        }
        self.inputs = {
            "schema": "auths.gateway-task-populate-preflight-inputs/1",
            "task_id": "task-create-1", "task_commitment": "a" * 64,
            "plan_commitment": "b" * 64,
            "create_operation_id": "create-1", "child_id": "child_ABC-123",
            "populate_recipe_digest": "c" * 64,
            "preflight_rule_digest": current_populate_preflight_rule_digest(),
            "connection_id": "jules-google", "connection_generation": 1,
            "connection_subject": "jules-subject",
            "parent_id": "project-a-folder", "title": CHILD_TITLE,
            "marker": "ap071_" + "e" * 32,
            "plan_expires_at": 2_000_000_000,
        }
        self.arguments = dict(
            gateway_binary=self.gateway,
            gateway_sha256=hashlib.sha256(self.gateway.read_bytes()).hexdigest(),
            gateway_state_dir=self.root,
            installation_path=self.root / "installation.json",
            write_evidence_path=self.root / "evidence.json",
            grant_path=self.root / "grant.json",
            credential_pins_path=self.root / "credential-pins.json",
            signing_seed_path=self.seed_path,
            report_dir=self.root,
            task_id="task-create-1",
        )

    def test_records_signed_jules_report_from_journal_derived_child(self) -> None:
        observed = JulesCreatedChildPreflight(
            child_id="child_ABC-123", tab_id="t.0", revision_id="revision-1",
            created_at=datetime(2026, 10, 25, tzinfo=timezone.utc),
            checked_at=1_800_000_000, connection_id="jules-google",
            connection_generation=1, connection_subject="jules-subject",
            metadata_sha256="1" * 64, capability_sha256="2" * 64,
            docs_sha256="3" * 64,
        )
        gateway_calls: list[list[str]] = []

        def gateway_output(_binary: Path, args: list[str], *, limit: int) -> bytes:
            gateway_calls.append(args)
            if args[0] == "task-populate-preflight-inputs":
                return json.dumps(self.inputs).encode()
            self.assertEqual(args[0], "task-record-populate-preflight")
            self.assertEqual(limit, 4096)
            report_path = Path(args[args.index("--report") + 1])
            self.assertEqual(os.stat(report_path).st_mode & 0o777, 0o600)
            report = json.loads(report_path.read_bytes())
            statement = report["statement"]
            self.assertEqual(statement["child_id"], self.inputs["child_id"])
            self.assertEqual(statement["plan_commitment"], self.inputs["plan_commitment"])
            self.assertEqual(statement["provider_values"]["required_revision_id"],
                             "revision-1")
            return b'{"outcome":"populate-preflight-recorded"}\n'

        with (
            patch("employee_read_demo.task_populate_operator._installation",
                  return_value=self.installation),
            patch("employee_read_demo.task_populate_operator._credential_pins",
                  return_value=self.pins),
            patch("employee_read_demo.task_populate_operator.validate_write_handoff",
                  return_value={"folder_id": "project-a-folder",
                                "drive_id": "shared-drive-1"}),
            patch("employee_read_demo.task_populate_operator._run_gateway",
                  side_effect=gateway_output),
            patch("employee_read_demo.google_create_preflight.preflight_jules_created_child",
                  return_value=observed) as google_reads,
        ):
            result = record_jules_populate_preflight(**self.arguments)
        self.assertEqual(result["status"], "populate_preflight_recorded")
        self.assertEqual(result["child_id"], self.inputs["child_id"])
        self.assertEqual(len(gateway_calls), 2)
        self.assertEqual(gateway_calls[0][0], "task-populate-preflight-inputs")
        self.assertEqual(gateway_calls[1][0], "task-record-populate-preflight")
        google_reads.assert_called_once()

    def test_changed_connection_or_rule_is_refused_before_google(self) -> None:
        for field, value in (("connection_subject", "other-person"),
                             ("preflight_rule_digest", "f" * 64)):
            with self.subTest(field=field):
                inputs = self.inputs | {field: value}
                with (
                    patch("employee_read_demo.task_populate_operator._installation",
                          return_value=self.installation),
                    patch("employee_read_demo.task_populate_operator._credential_pins",
                          return_value=self.pins),
                    patch("employee_read_demo.task_populate_operator._run_gateway",
                          return_value=json.dumps(inputs).encode()) as gateway,
                    patch("employee_read_demo.task_populate_operator.validate_write_handoff") as evidence,
                    patch("employee_read_demo.task_populate_operator.attest_jules_created_child") as google_reads,
                ):
                    with self.assertRaises(OperatorDenied):
                        record_jules_populate_preflight(**self.arguments)
                gateway.assert_called_once()
                evidence.assert_not_called()
                google_reads.assert_not_called()

    def test_changed_installed_signer_code_pin_is_refused_before_gateway(self) -> None:
        changed = {"populate_preflight": self.installation["populate_preflight"] |
                   {"rule_digest": "f" * 64}}
        with (
            patch("employee_read_demo.task_populate_operator._installation",
                  return_value=changed),
            patch("employee_read_demo.task_populate_operator._run_gateway") as gateway,
            patch("employee_read_demo.task_populate_operator.attest_jules_created_child")
            as google_reads,
        ):
            with self.assertRaisesRegex(OperatorDenied, "code changed"):
                record_jules_populate_preflight(**self.arguments)
        gateway.assert_not_called()
        google_reads.assert_not_called()

    def test_scratch_parent_requires_recorded_setup_before_google(self) -> None:
        self.inputs["parent_id"] = "scratch-run-folder"
        task_dir = self.root / self.inputs["task_id"]
        task_dir.mkdir(mode=0o700)
        record = {
            "schema": "auths.ap071-pre-create-baseline-populate-failure/1",
            "task_id": self.inputs["task_id"],
            "marker": self.inputs["marker"],
            "parent_id": "wrong-folder",
            "setup_generation": 33, "setup_sha256": "d" * 64,
        }
        path = task_dir / "pre-create-baseline.json"
        path.write_text(json.dumps(record))
        path.chmod(0o600)
        target = PopulateFailureTarget(
            "populate-drop", self.inputs["marker"], "scratch-run-folder",
            33, "d" * 64,
        )
        arguments = self.arguments | {
            "populate_failure_setup_path": self.root / "setup.json",
            "populate_failure_setup_sha256": "d" * 64,
            "source_v4_paths": tuple(self.root / f"source-{i}" for i in range(3)),
            "source_v4_pins_path": self.root / "v4-pins.json",
        }
        with (
            patch("employee_read_demo.task_populate_operator._installation",
                  return_value=self.installation),
            patch("employee_read_demo.task_populate_operator._credential_pins",
                  return_value=self.pins),
            patch("employee_read_demo.task_populate_operator.validate_write_handoff",
                  return_value={"folder_id": "project-a-folder",
                                "drive_id": "shared-drive-1"}),
            patch("employee_read_demo.task_populate_operator._run_gateway",
                  return_value=json.dumps(self.inputs).encode()),
            patch("employee_read_demo.task_populate_operator.load_v4_final_pins"),
            patch("employee_read_demo.task_populate_operator."
                  "validate_populate_failure_setup", return_value=target),
            patch("employee_read_demo.task_populate_operator."
                  "attest_jules_created_child") as google_reads,
        ):
            with self.assertRaisesRegex(OperatorDenied, "differs from setup"):
                record_jules_populate_preflight(**arguments)
        google_reads.assert_not_called()


if __name__ == "__main__":
    unittest.main()
