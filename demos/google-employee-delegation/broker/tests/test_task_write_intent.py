"""Project only an exact gateway-reviewed request into human confirmation."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from employee_read_demo.contracts import canonical_json
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_write_intent import project_exact_write
from employee_read_demo.task_write_proofs import task_commitment


REFERENCE = Path(__file__).resolve().parents[2] / "write_reference"


class TaskWriteIntentTests(unittest.TestCase):
    def test_native_enrolled_writer_fixture_has_identical_signing_arguments(self) -> None:
        from auths import _native

        repository = Path(__file__).resolve().parents[4]
        fixture = json.loads((repository / "product/runtime/auths-gateway/fixtures/enrolled-write-review-v1.json").read_bytes())
        self.assertEqual(fixture["schema"], "auths.gateway-enrolled-write-review-fixture/1")
        review = fixture["review"]
        projected = project_exact_write(fixture["card"], review,
                                        fixture["recipe"], fixture["recipe_digest"])
        expected = review["confirmation_arguments"].encode()
        actual = bytes(_native.canonicalize_mcp_arguments_json(
            canonical_json({"write": projected.intent})))
        self.assertEqual(actual, expected)
        self.assertNotEqual(projected.intent["writer"]["principal"],
                            fixture["card"]["agent_principal"])
        self.assertEqual(projected.intent["writer"]["instance_generation"], 5)

    def test_closed_google_request_becomes_exact_human_intent(self) -> None:
        recipe = json.loads((REFERENCE / "recipe.json").read_text())
        digest = "a" * 64
        card = {
            "schema": "auths.agent-task/4", "task_id": "task-1",
            "agent_principal": "agent-1", "connection_id": "jules-google",
            "connection_generation": 2, "connection_subject": "jules-subject",
            "delegation": {"partition_generation": 7, "permitted_channels": {
                "agent-b": {"principal": "agent-2", "instance_generation": 5}}},
            "write_scopes": [{"handle": "working-doc", "recipe_digest": digest,
                              "verb": "edit", "connection_id": "jules-google",
                              "connection_generation": 2,
                              "connection_subject": "jules-subject"}],
        }
        arguments = {
            "task_id": "task-1", "task_commitment": task_commitment(card),
            "recipe_digest": digest, "operator_namespace": "google-docs-demo",
            "operation_id": "edit-1", "document_id": "working-doc",
        }
        review = {
            "schema": "auths.gateway-submission-review/1",
            "actors": ["agent-2"], "action_commitment": "b" * 64,
            "arguments": arguments,
            "request": {
                "method": "POST", "url": "https://docs.googleapis.com/v1/documents/working-doc:batchUpdate",
                "content_type": "application/json", "body": '{"requests":[]}',
                "headers": [], "idempotency_key": None,
            },
        }
        intent = {
            "task_id": card["task_id"], "task_commitment": task_commitment(card),
            "operation_id": "edit-1", "action_commitment": "b" * 64,
            "request_commitment": "c" * 64, "recipe_digest": digest,
            "resource_handle": "working-doc", "verb": "edit",
            "connection_id": "jules-google", "connection_generation": 2,
            "connection_subject": "jules-subject",
            "writer": {"engagement_commitment": task_commitment(card),
                       "partition_generation": 7, "enrollment_commitment": "d" * 64,
                       "principal": "agent-2", "instance_generation": 5},
        }
        submission = review
        review = {"schema": "auths.gateway-task-write-review/1", "submission": submission,
                  "intent": intent, "confirmation_arguments": canonical_json({"write": intent}).decode()}
        projected = project_exact_write(card, review, recipe, digest)
        self.assertEqual(projected.intent["task_commitment"], task_commitment(card))
        self.assertEqual(projected.intent["resource_handle"], "working-doc")
        self.assertEqual(projected.intent["action_commitment"], "b" * 64)
        self.assertEqual(projected.method, "POST")
        self.assertEqual(canonical_json({"write": projected.intent}).decode(), review["confirmation_arguments"])
        self.assertEqual(projected.intent["writer"]["principal"], "agent-2")
        # The presenter preserves the native digest; it must not implement a
        # second request-commitment algorithm from the displayed HTTP fields.
        self.assertEqual(projected.intent["request_commitment"], "c" * 64)
        for changed in (
            {**review, "submission": {**submission, "actors": ["other-agent"]}},
            {**review, "submission": {**submission, "arguments": {**arguments, "document_id": "outside"}}},
            {**review, "submission": {**submission, "request": {**submission["request"], "url": "https://elsewhere.example/x"}}},
            {**review, "confirmation_arguments": canonical_json({"write": {**intent, "writer": {**intent["writer"], "principal": "agent-1"}}}).decode()},
            {**review, "schema": "auths.gateway-submission-review/1"},
        ):
            with self.assertRaises(OperatorDenied):
                project_exact_write(card, changed, recipe, digest)


if __name__ == "__main__":
    unittest.main()
