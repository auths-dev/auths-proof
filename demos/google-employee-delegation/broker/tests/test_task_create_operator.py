"""The planned create handoff preserves its producer baseline before entry."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_create_operator import submit_planned_create


class PlannedCreateOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task_id = "task-1"
        self.task_dir = self.root / self.task_id
        self.task_dir.mkdir(mode=0o700)
        self.state_dir = self.root / "gateway-state"
        self.state_dir.mkdir(mode=0o700)
        self.generation = self.root / "generation-0002"
        self.generation.mkdir(mode=0o700)
        self.baseline = self.generation / "google-write-observation.json"
        self.now = int(datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc).timestamp())
        self.observation = {
            "schema_version": "demo-co/google-write-observation/v1",
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64,
            "observed_at": datetime.fromtimestamp(
                self.now - 60, timezone.utc,
            ).isoformat(),
            "document_id": "working-doc", "tab_id": "tab-1",
            "revision_id": "rev-1", "content_sha256": "b" * 64,
            "content_byte_count": 65, "original_marker_count": 1,
        }
        self._write(self.baseline, self.observation)
        self.card = {
            "task_id": self.task_id, "company_id": "atlas-studio",
            "connection_subject": "jules-subject",
            "connection_id": "jules-connection", "connection_generation": 1,
            "pending_child": {
                "parent_handle": "project-a-folder", "title": CHILD_TITLE,
                "marker": "ap071_" + "c" * 32,
                "create_recipe_digest": "d" * 64,
                "create_operation_id": "create-1",
            },
        }
        self._write(self.task_dir / "task-card.json", self.card)
        for name in ("agent.proof", "agent.action", "effect-plan.proof",
                     "effect-plan.action"):
            self._write(self.task_dir / name, b"signed")
        self.pins = SimpleNamespace(
            producer=SimpleNamespace(company="atlas-studio",
                                     jules_subject="jules-subject"),
            connection_id="jules-connection", connection_generation=1,
        )
        self.evidence = {
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "document_id": "working-doc",
            "folder_id": "project-a-folder",
        }

    @staticmethod
    def _write(path: Path, value: dict | bytes) -> None:
        raw = (json.dumps(value, sort_keys=True).encode()
               if type(value) is dict else value)
        path.write_bytes(raw)
        os.chmod(path, 0o600)

    def _submit(self):
        return submit_planned_create(
            gateway_binary=self.root / "gateway", gateway_sha256="e" * 64,
            gateway_state_dir=self.state_dir, task_dir=self.task_dir,
            task_id=self.task_id, write_evidence_path=self.root / "evidence",
            credential_pins_path=self.root / "pins", baseline_path=self.baseline,
            baseline_sha256=hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
            now=self.now,
        )

    def test_baseline_is_durable_before_one_gateway_create(self) -> None:
        def run(command, **kwargs):
            record = json.loads((self.task_dir / "pre-create-baseline.json").read_bytes())
            self.assertEqual(record["generation"], 2)
            self.assertEqual(record["create_operation_id"], "create-1")
            self.assertEqual(command[1], "task-submit")
            self.assertIn("--recorded-effect-plan", command)
            self.assertNotIn("--confirmation-proof", command)
            return subprocess.CompletedProcess(
                command, 0, b'{"outcome":"response-recorded","status":200}', b"",
            )
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=run) as gateway):
            result = self._submit()
            self.assertEqual(result["gateway_outcome"], "response-recorded")
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                self._submit()
            gateway.assert_called_once()

    def test_stale_or_mismatched_baseline_never_enters_gateway(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run") as gateway):
            for changed in (
                {"observed_at": datetime.fromtimestamp(
                    self.now - 301, timezone.utc).isoformat()},
                {"document_id": "other-doc"},
                {"original_marker_count": -1},
            ):
                with self.subTest(changed=changed):
                    self._write(self.baseline, self.observation | changed)
                    with self.assertRaisesRegex(OperatorDenied, "baseline"):
                        self._submit()
            gateway.assert_not_called()
            self.assertFalse((self.task_dir / "pre-create-baseline.json").exists())

    def test_uncertain_gateway_result_preserves_original_baseline(self) -> None:
        with (patch("employee_read_demo.task_create_operator._gateway",
                    return_value=self.root / "gateway"),
              patch("employee_read_demo.task_create_operator._credential_pins",
                    return_value=self.pins),
              patch("employee_read_demo.task_create_operator.validate_write_handoff",
                    return_value=self.evidence),
              patch("employee_read_demo.task_create_operator.subprocess.run",
                    side_effect=subprocess.TimeoutExpired("gateway", 90)) as gateway):
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self._submit()
            self.assertTrue((self.task_dir / "pre-create-baseline.json").exists())
            with self.assertRaisesRegex(OperatorDenied, "already handed off"):
                self._submit()
            gateway.assert_called_once()


if __name__ == "__main__":
    unittest.main()
