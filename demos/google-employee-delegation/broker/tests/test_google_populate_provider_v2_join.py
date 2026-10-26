"""The provider's exact bytes must belong to one signed task and attempt."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.contracts import commitment
from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_populate_provider_v2_join import (
    join_populate_provider_final_v2,
)
from employee_read_demo.google_populate_provider_v2_owner import (
    owner_provider_v2_effect,
)
from employee_read_demo.task_write_proofs import task_commitment


class ProviderV2TaskJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.task = Path(temporary.name) / "task-one"
        self.task.mkdir(mode=0o700)
        self.preflight_path = self.task / (
            "populate-preflight-task-one-1234567890abcdef.json"
        )
        self.text = "Project A handoff from source"
        self.raw = b"\xef\xbb\xbf" + self.text.encode()
        self.card = {
            "schema": "auths.agent-task/2", "task_id": "task-one",
            "company_id": "atlas-studio",
            "human_principal": "key:sha256:human",
            "agent_principal": "key:sha256:agent",
            "write_approval_mode": "exact", "max_provider_calls": 1,
            "max_releases": 1, "max_release_bytes": 16_384,
            "max_writes": 2,
            "connection_id": "jules-write", "connection_generation": 4,
            "connection_subject": "jules-subject",
            "read_scopes": [{"handle": "source-doc",
                             "connection_subject": "jules-subject"}],
            "write_scopes": [{"handle": "run-folder",
                              "recipe_digest": "a" * 64,
                              "verb": "create"}],
            "pending_child": {
                "parent_handle": "run-folder",
                "title": "Auths AP-071 Project A handoff",
                "marker": "ap071_" + "1" * 32,
                "create_operation_id": "create-one",
                "create_recipe_digest": "a" * 64,
                "populate_recipe_digest": "b" * 64,
            },
        }
        self.plan = {
            "schema": "auths.agent-effect-plan/1",
            "task_id": "task-one",
            "task_commitment": task_commitment(self.card),
            "create": {
                "task_id": "task-one", "operation_id": "create-one",
                "recipe_digest": "a" * 64,
                "resource_handle": "run-folder",
                "verb": "create",
                "connection_id": "jules-write",
                "connection_generation": 4,
                "connection_subject": "jules-subject",
            },
            "populate_recipe_digest": "b" * 64,
            "populate_operation_id": "populate-one",
            "initial_text": self.text,
        }
        self.provider = {
            "schema": "auths.ap071-populate-provider-final-join/1",
            "authority": "provider_state_only",
            "status": "exact_populated", "content_matches": True,
            "retry_authorized": False,
            "company_id": "atlas-studio",
            "jules_subject": "jules-subject",
            "run_folder_id": "run-folder",
            "marker": self.card["pending_child"]["marker"],
            "child_id": "child-one", "tab_id": "tab-one",
            "source_document_id": "source-doc",
            "source_raw_byte_count": 51,
            "setup_generation": 44, "setup_sha256": "c" * 64,
            "precreate_generation": 46,
            "precreate_sha256": "d" * 64,
            "precreate_observed_at": "2026-10-26T10:02:00Z",
            "final_generation": 48,
            "final_sha256": "e" * 64,
            "expected_raw_sha256": hashlib.sha256(self.raw).hexdigest(),
            "expected_raw_byte_count": len(self.raw),
        }
        self.baseline = {
            "schema": "auths.ap071-pre-create-baseline-populate-failure/1",
            "task_id": "task-one", "create_operation_id": "create-one",
            "marker": self.provider["marker"], "generation": 46,
            "observation_sha256": "d" * 64,
            "observed_at": "2026-10-26T10:02:00Z",
            "parent_id": "run-folder",
            "setup_generation": 44, "setup_sha256": "c" * 64,
        }
        self.preflight = {
            "statement": {
                "schema": "auths.gateway-task-populate-preflight/2",
                "task_id": "task-one",
                "task_commitment": self.plan["task_commitment"],
                "plan_commitment": commitment(
                    "auths.agent-effect-plan.v1", self.plan,
                ),
                "create_operation_id": "create-one",
                "child_id": "child-one",
                "populate_recipe_digest": "b" * 64,
                "connection_id": "jules-write",
                "connection_generation": 4,
                "connection_subject": "jules-subject",
                "provider_values": {
                    "tab_id": "tab-one",
                    "required_revision_id": "jules-blank-revision",
                },
                "evidence_digests": {
                    "metadata": "1" * 64,
                    "capability": "2" * 64,
                    "document": "3" * 64,
                },
            },
            "signature_b64": "A" * 86,
        }
        self.lineage = {
            "schema": "auths.gateway-task-population-lineage/1",
            "task_id": "task-one",
            "plan_commitment": self.preflight["statement"]["plan_commitment"],
            "create_operation_id": "create-one",
            "populate_operation_id": "populate-one",
            "child_id": "child-one",
            "preflight_signature_sha256": hashlib.sha256(
                base64.b64decode(self.preflight["signature_b64"] + "==")
            ).hexdigest(),
        }
        self.entry = {
            "schema": "auths.ap071-populate-entry/1",
            "task_id": "task-one", "child_id": "child-one",
            "populate_operation_id": "populate-one",
            "baseline_sha256": "d" * 64,
            "preflight_sha256": "",
        }
        self.result = {
            "schema": "auths.ap071-populate-result/1",
            "task_id": "task-one", "populate_operation_id": "populate-one",
            "outcome": "response-recorded",
        }
        self.activity = {
            "schema": "auths.gateway-agent-task-activity/1",
            "task": {
                "schema": "auths.gateway-agent-task-status/1",
                "task_id": "task-one", "provider_calls": 1,
                "releases": 1, "released_bytes": 51,
                "max_provider_calls": 1, "max_releases": 1,
                "max_writes": 2, "writes": 2,
                "write_operations": ["create-one", "populate-one"],
                "reads": [{"operation_id": "read-one",
                           "stage": "agent-acknowledged",
                           "released_bytes": 51}],
            },
            "write_attempts": [
                {"operation_id": "create-one", "stage": "unknown",
                 "response_status": None},
                {"operation_id": "populate-one",
                 "stage": "response-recorded", "response_status": 200},
            ],
        }

    def write_records(self) -> None:
        records = {
            "task-card.json": self.card,
            "effect-plan.json": self.plan,
            "pre-create-baseline.json": self.baseline,
            "populate-entry.json": self.entry,
            "populate-result.json": self.result,
            self.preflight_path.name: self.preflight,
        }
        preflight_raw = json.dumps(
            self.preflight, sort_keys=True, separators=(",", ":")
        ).encode()
        self.entry["preflight_sha256"] = hashlib.sha256(preflight_raw).hexdigest()
        for name, value in records.items():
            path = self.task / name
            path.write_bytes(json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode())
            path.chmod(0o600)

    def join(self) -> dict:
        self.write_records()
        return join_populate_provider_final_v2(
            self.task, self.preflight_path,
            self.activity, self.lineage, self.provider,
        )

    def test_one_response_and_exact_provider_state_join(self) -> None:
        verdict = self.join()
        self.assertEqual(verdict["status"], "joined")
        self.assertEqual(verdict["population_outcome"], "response-recorded")
        self.assertIs(verdict["retry_authorized"], False)
        self.assertNotIn("expected_raw_sha256", verdict)

    def test_task_plan_child_and_attempt_swaps_are_refused(self) -> None:
        baseline = (copy.deepcopy(self.card), copy.deepcopy(self.plan),
                    copy.deepcopy(self.preflight), copy.deepcopy(self.provider),
                    copy.deepcopy(self.activity), copy.deepcopy(self.lineage))
        changes = (
            (self.card, "task_id", "task-two"),
            (self.card["pending_child"], "marker", "ap071_" + "9" * 32),
            (self.plan, "initial_text", "Project B handoff from source"),
            (self.preflight["statement"], "plan_commitment", "0" * 64),
            (self.preflight["statement"], "child_id", "other-child"),
            (self.provider, "child_id", "other-child"),
            (self.activity["task"], "writes", 1),
            (self.activity["write_attempts"][1], "stage", "claimed-no-attempt"),
            (self.lineage, "preflight_signature_sha256", "0" * 64),
        )
        for document, field, value in changes:
            with self.subTest(field=field, value=value):
                original = document[field]
                document[field] = value
                try:
                    with self.assertRaises(ContractRejected):
                        self.join()
                finally:
                    document[field] = original
        self.assertEqual(self.card, baseline[0])
        self.assertEqual(self.plan, baseline[1])
        self.assertEqual(self.preflight, baseline[2])
        self.assertEqual(self.provider, baseline[3])
        self.assertEqual(self.activity, baseline[4])
        self.assertEqual(self.lineage, baseline[5])

    def test_unknown_response_is_not_promoted_to_success(self) -> None:
        self.result["outcome"] = "unknown"
        self.activity["write_attempts"][1]["stage"] = "unknown"
        self.activity["write_attempts"][1]["response_status"] = None
        verdict = self.join()
        self.assertEqual(verdict["population_outcome"], "unknown")
        self.assertIs(verdict["retry_authorized"], False)
        self.activity["write_attempts"][1]["stage"] = "response-recorded"
        with self.assertRaises(ContractRejected):
            self.join()

    def test_gateway_readback_keeps_provider_verdict_separate(self) -> None:
        self.result["outcome"] = "observed-by-provider"
        self.activity["write_attempts"][1]["stage"] = "observed-by-provider"
        verdict = self.join()
        self.assertEqual(verdict["population_outcome"], "observed-by-provider")
        self.assertEqual(verdict["provider_state"], "exact_populated")
        self.assertIs(verdict["retry_authorized"], False)

    def test_malformed_provider_and_activity_are_rejected(self) -> None:
        original_provider = self.provider
        original_activity = self.activity
        try:
            self.provider = {"schema": original_provider["schema"]}
            with self.assertRaises(ContractRejected):
                self.join()
            self.provider = original_provider
            self.activity = []
            with self.assertRaises(ContractRejected):
                self.join()
        finally:
            self.provider = original_provider
            self.activity = original_activity

    def test_response_stage_requires_successful_response(self) -> None:
        attempt = self.activity["write_attempts"][1]
        for status in (None, 404, True):
            with self.subTest(status=status):
                attempt["response_status"] = status
                with self.assertRaises(ContractRejected):
                    self.join()
        attempt["response_status"] = 200
        self.result["outcome"] = "observed"
        attempt["stage"] = "observed"
        attempt["observation_match"] = False
        with self.assertRaises(ContractRejected):
            self.join()

    def test_create_stage_cannot_claim_a_failed_response(self) -> None:
        create = self.activity["write_attempts"][0]
        create["stage"] = "response-recorded"
        create["response_status"] = 403
        with self.assertRaises(ContractRejected):
            self.join()

    def test_owner_view_recomputes_from_private_pinned_evidence(self) -> None:
        self.write_records()
        manifest = {
            "schema": "auths.ap071-provider-v2-evidence/1",
            "task_id": "task-one",
            "source_v4_paths": [str(self.task / name)
                                for name in ("v4-baseline", "v4-blank", "v4-final")],
            "v4_pins_path": str(self.task / "v4-pins.json"),
            "source": {"document_id": "source-doc", "raw_sha256": "c" * 64,
                       "raw_byte_count": 51},
            "preflight_name": self.preflight_path.name,
        }
        for name in ("setup", "inventory", "precreate", "blank", "final"):
            manifest[name] = {"path": str(self.task / name), "sha256": "f" * 64}
        path = self.task / "provider-v2-evidence.json"
        path.write_text(json.dumps(manifest))
        path.chmod(0o600)
        with (patch("employee_read_demo.google_populate_provider_v2_owner."
                    "load_v4_final_pins", return_value=object()),
              patch("employee_read_demo.google_populate_provider_v2_owner."
                    "validate_populate_provider_final_v2",
                    return_value=self.provider) as consume):
            result = owner_provider_v2_effect(self.task, self.activity,
                                              self.lineage)
            self.assertEqual(result["provider_state"], "exact_populated")
            self.assertEqual(result["task_id"], "task-one")
            self.assertNotIn("expected_raw_sha256", result)
            self.assertEqual(consume.call_args.kwargs["expected_text"], self.text)
            manifest["final"]["sha256"] = "bad"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ContractRejected):
                owner_provider_v2_effect(self.task, self.activity, self.lineage)


if __name__ == "__main__":
    unittest.main()
