"""The agent signs only the draft Jules approved and the reported child."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from employee_read_agent.draft import author_signed_draft
from employee_read_agent.planned_populate import planned_populate_arguments
from employee_read_agent.run import AgentKey


class _Model:
    def draft(self, purpose: str, sources: dict[str, str]) -> str:
        return "Project A handoff is ready. [source-1]"


class PlannedPopulateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = AgentKey(b"\x53" * 32)
        self.task_commitment = "a" * 64
        recipe_path = (Path(__file__).parents[2] / "populate_reference" / "recipe.json")
        self.recipe = json.loads(recipe_path.read_text())
        self.package = {
            "schema": "auths.ap071-agent-write-package/1",
            "agent_principal": self.key.principal,
            "service": self.recipe["service"], "tool": self.recipe["tool"],
            "task_id": "task-1", "task_commitment": self.task_commitment,
            "recipe_digest": "b" * 64, "expires_at": 1200,
        }
        self.draft = json.loads(author_signed_draft(
            source=b"Project A source context", source_resource_handle="source-1",
            read_operation_id="read-1", task_id="task-1",
            task_commitment=self.task_commitment,
            agent_principal=self.key.principal, purpose="Draft handoff",
            model=_Model(), key=self.key.private,
        ))
        self.plan = {
            "schema": "auths.agent-effect-plan/2",
            "task_id": "task-1", "task_commitment": self.task_commitment,
            "create": {
                "task_id": "task-1", "task_commitment": self.task_commitment,
                "operation_id": "create-1", "verb": "create",
                "connection_subject": "jules-subject",
                "connection_generation": 1,
            },
            "populate_recipe_digest": "b" * 64,
            "populate_operation_id": "populate-1",
            "initial_text": self.draft["statement"]["content"],
            "expires_at": 1100,
        }
        self.preflight = {
            "statement": {
                "schema": "auths.gateway-task-populate-preflight/2",
                "task_id": "task-1", "task_commitment": self.task_commitment,
                "create_operation_id": "create-1",
                "populate_recipe_digest": "b" * 64,
                "connection_subject": "jules-subject",
                "connection_generation": 1,
                "child_id": "child-1",
                "provider_values": {"tab_id": "tab-1", "required_revision_id": "rev-1"},
                "checked_at": 990,
                "valid_until": 1050,
            },
            "signature_b64": "gateway-verifies-this-report",
        }

    def _arguments(self, **overrides):
        inputs = {"package": self.package, "plan": self.plan,
                  "preflight": self.preflight, "draft": self.draft,
                  "recipe": self.recipe, "key": self.key, "now": 1000}
        return planned_populate_arguments(**(inputs | overrides))

    def test_exact_draft_becomes_bounded_population_arguments(self) -> None:
        arguments = self._arguments()
        self.assertEqual(arguments, {
            "operator_namespace": "google-docs-populate-demo",
            "operation_id": "populate-1", "recipe_digest": "b" * 64,
            "task_id": "task-1", "task_commitment": self.task_commitment,
            "document_id": "child-1", "tab_id": "tab-1",
            "required_revision_id": "rev-1",
            "text": self.draft["statement"]["content"],
        })

    def test_changed_plan_draft_or_preflight_refuses_before_native_signing(self) -> None:
        altered_plan = self.plan | {"initial_text": "Different text [source-1]"}
        with self.assertRaisesRegex(ValueError, "differs"):
            self._arguments(plan=altered_plan)
        altered_draft = json.loads(json.dumps(self.draft))
        altered_draft["statement"]["content"] = "Different text [source-1]"
        with self.assertRaisesRegex(ValueError, "differs|signature"):
            self._arguments(draft=altered_draft)
        altered_preflight = json.loads(json.dumps(self.preflight))
        altered_preflight["statement"]["create_operation_id"] = "other-create"
        with self.assertRaisesRegex(ValueError, "differs"):
            self._arguments(preflight=altered_preflight)
        with self.assertRaisesRegex(ValueError, "differs"):
            self._arguments(now=1050)


if __name__ == "__main__":
    unittest.main()
