"""Project only an exact gateway-reviewed request into human confirmation."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_write_intent import project_exact_write
from employee_read_demo.task_write_proofs import task_commitment


REFERENCE = Path(__file__).resolve().parents[2] / "write_reference"


class TaskWriteIntentTests(unittest.TestCase):
    def test_closed_google_request_becomes_exact_human_intent(self) -> None:
        recipe = json.loads((REFERENCE / "recipe.json").read_text())
        digest = "a" * 64
        card = {
            "schema": "auths.agent-task/1", "task_id": "task-1",
            "agent_principal": "agent-1", "connection_id": "jules-google",
            "connection_generation": 2, "connection_subject": "jules-subject",
            "write_scopes": [{"handle": "working-doc", "recipe_digest": digest,
                              "verb": "edit"}],
        }
        arguments = {
            "task_id": "task-1", "task_commitment": task_commitment(card),
            "recipe_digest": digest, "operator_namespace": "google-docs-demo",
            "operation_id": "edit-1", "document_id": "working-doc",
        }
        review = {
            "schema": "auths.gateway-submission-review/1",
            "actors": ["agent-1"], "action_commitment": "b" * 64,
            "arguments": arguments,
            "request": {
                "method": "POST", "url": "https://docs.googleapis.com/v1/documents/working-doc:batchUpdate",
                "content_type": "application/json", "body": '{"requests":[]}',
                "headers": [], "idempotency_key": None,
            },
        }
        projected = project_exact_write(card, review, recipe, digest)
        self.assertEqual(projected.intent["task_commitment"], task_commitment(card))
        self.assertEqual(projected.intent["resource_handle"], "working-doc")
        self.assertEqual(projected.intent["action_commitment"], "b" * 64)
        self.assertEqual(projected.method, "POST")
        for changed in (
            {**review, "actors": ["other-agent"]},
            {**review, "arguments": {**arguments, "document_id": "outside"}},
            {**review, "request": {**review["request"], "url": "https://elsewhere.example/x"}},
        ):
            with self.assertRaises(OperatorDenied):
                project_exact_write(card, changed, recipe, digest)


if __name__ == "__main__":
    unittest.main()
