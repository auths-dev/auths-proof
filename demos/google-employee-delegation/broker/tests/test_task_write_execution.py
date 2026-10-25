"""The optional browser execution path keeps preflight before provider entry."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.task_write_intent import ReviewedWrite


class TaskWriteExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.task_id = "test-task"
        self.task_dir = self.root / self.task_id
        self.task_dir.mkdir(mode=0o700)
        for name in ("task.proof", "task.action", "confirmation.proof",
                     "confirmation.action", "agent.proof", "agent.action"):
            path = self.task_dir / name
            path.write_bytes(b"signed-test-artifact")
            os.chmod(path, 0o600)
        self.events: list[str] = []
        self.review = ReviewedWrite(
            {"task_id": self.task_id}, {"document_id": "working-doc"},
            "POST", "https://docs.googleapis.com/v1/documents/working-doc:batchUpdate",
            "application/json", "{}",
        )
        self.flow = TaskWriteConfirmationFlow(
            authority_path=self.root / "authority",
            installation_path=self.root / "installation",
            recipe_path=self.root / "recipe",
            profile_lock_path=self.root / "lock",
            private_output_dir=self.root,
            gateway_binary=self.root / "gateway",
            gateway_sha256="a" * 64,
            preflight=lambda card, review: self.events.append("preflight"),
            gateway_state_dir=self.root / "gateway-state",
        )
        self.flow._binary = lambda: self.root / "gateway"
        self.flow._review = lambda task_id, employee, agent, now: (
            {"task_id": task_id}, self.review,
        )

    def test_submit_preflights_then_returns_only_redacted_gateway_result(self) -> None:
        def run(command, **kwargs):
            self.events.append("gateway")
            self.assertEqual(command[1], "task-submit")
            self.assertEqual(command[command.index("--task-id") + 1], self.task_id)
            return subprocess.CompletedProcess(
                command, 0, json.dumps({
                    "outcome": "response-recorded", "status": 200,
                    "untrusted_private_field": "never return this",
                }).encode(), b"",
            )

        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   side_effect=run):
            result = self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                      now=1000)
        self.assertEqual(self.events, ["preflight", "gateway"])
        self.assertEqual(result, {"outcome": "response-recorded", "status": 200})

    def test_failed_preflight_never_invokes_gateway(self) -> None:
        def deny(card, review):
            raise OperatorDenied("Doc revision changed")

        self.flow.preflight = deny
        with patch("employee_read_demo.task_write_confirmation.subprocess.run") as run:
            with self.assertRaises(OperatorDenied):
                self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                 now=1000)
        run.assert_not_called()

    def test_lost_gateway_result_is_not_retried(self) -> None:
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("task-submit", 90)) as run:
            with self.assertRaisesRegex(OperatorDenied, "outcome is unknown"):
                self.flow.submit(task_id=self.task_id, employee=None, agent=None,
                                 now=1000)
        self.assertEqual(run.call_count, 1)

    def test_activation_uses_private_task_artifacts_once(self) -> None:
        with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, b'{"outcome":"task-activated"}\n', b"")) as run:
            self.flow.activate(self.task_id)
        command = run.call_args.args[0]
        self.assertEqual(command[1], "task-activate")
        self.assertEqual(command[command.index("--proof") + 1],
                         str(self.task_dir / "task.proof"))


if __name__ == "__main__":
    unittest.main()
