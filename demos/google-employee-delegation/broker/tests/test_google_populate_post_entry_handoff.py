"""Post-entry response loss must never be mistaken for pre-entry recovery."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from employee_read_demo.contracts import commitment
from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_populate_failure_handoff import (
    PopulateFailureTarget, join_populate_post_entry, validate_populate_post_entry,
)


class PostEntryProviderTests(unittest.TestCase):
    def test_exact_same_child_and_bytes_are_required(self) -> None:
        text = "Source-backed exact content"
        digest = hashlib.sha256(b"\xef\xbb\xbf" + text.encode()).hexdigest()
        common = {
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-one",
            "run_id": "post-entry", "run_folder_id": "run-one",
            "marker": "ap071_" + "a" * 32,
            "original_seven_unchanged": True,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
        }
        blank = common | {
            "schema_version": "demo-co/google-populate-blank-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "setup_generation": 44, "setup_sha256": "a" * 64,
            "child_title": "Auths AP-071 Project A handoff",
            "marker_match_count": 1, "run_child_count": 1,
            "raw_byte_count": 3,
            "raw_sha256": hashlib.sha256(b"\xef\xbb\xbf").hexdigest(),
            "child_id": "child-one", "tab_id": "t.0",
            "admin_revision_id": "blank-revision",
            "child_created_at": "2026-10-26T02:35:08Z",
            "observed_at": "2026-10-26T02:35:46Z",
        }
        post = common | {
            "schema_version": "demo-co/google-populate-post-entry-observation/v1",
            "status": "exact_populated", "attribution": "provider_state_only",
            "project_a_folder_id": "project-a", "scratch_root_id": "scratch",
            "child_id": "child-one", "child_created_at": blank["child_created_at"],
            "tab_id": "t.0", "blank_baseline_generation": 47,
            "blank_baseline_sha256": "b" * 64,
            "blank_admin_revision_id": "blank-revision",
            "blank_raw_sha256": blank["raw_sha256"],
            "observed_admin_revision_id": "new-revision",
            "revision_changed": True, "provider_match_count": 1,
            "run_child_count": 1, "exact_scratch_root_children": True,
            "bounded_document_unchanged": True,
            "bounded_observation_generation": 43,
            "bounded_observation_sha256": "c" * 64,
            "exact_expected_content": True, "still_exactly_blank": False,
            "provider_entry_attested": False, "retry_authorized": False,
            "run_marker_occurrences_in_content": 0,
            "expected_raw_byte_count": len(b"\xef\xbb\xbf" + text.encode()),
            "observed_raw_byte_count": len(b"\xef\xbb\xbf" + text.encode()),
            "expected_raw_sha256": digest, "observed_raw_sha256": digest,
            "observed_at": "2026-10-26T02:37:20Z",
        }
        precreate = {"observed_at": "2026-10-26T02:34:46Z"}
        setup = {"scratch_root_id": "scratch"}
        source = SimpleNamespace(company="atlas-studio", instance="test-instance",
                                 definition_hash="1" * 64, drive_id="drive-one",
                                 folder_id="project-a")
        v4 = SimpleNamespace(candidate=SimpleNamespace(baseline=source))
        target = PopulateFailureTarget("post-entry", common["marker"],
                                       "run-one", 44, "a" * 64)

        def validate() -> dict:
            with (patch("employee_read_demo.google_populate_failure_handoff."
                        "_pinned_observation", side_effect=[(47, blank), (48, post)]),
                  patch("employee_read_demo.google_populate_failure_handoff."
                        "validate_populate_precreate_baseline",
                        return_value=(target, 46, precreate)),
                  patch("employee_read_demo.google_populate_failure_handoff."
                        "_load", return_value=(setup, b""))):
                return validate_populate_post_entry(
                    (Path("v4-a"), Path("v4-b"), Path("v4-c")),
                    Path("setup"), "a" * 64,
                    Path("precreate"), "d" * 64,
                    Path("blank"), "b" * 64,
                    Path("post"), "e" * 64, v4, expected_text=text,
                    bounded_observation_generation=43,
                    bounded_observation_sha256="c" * 64,
                )

        self.assertEqual(validate()["status"], "exact_populated")
        post["observed_raw_sha256"] = "0" * 64
        with self.assertRaises(ContractRejected):
            validate()


class PostEntryJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.task = Path(temporary.name) / "task-one"
        self.task.mkdir(mode=0o700)
        self.text = "Source-backed exact content"
        self.create = "create-one"
        self.populate = "populate-one"
        self.provider = {
            "authority": "provider_state_only", "retry_authorized": False,
            "status": "exact_populated", "run_folder_id": "folder-one",
            "marker": "ap071_" + "a" * 32, "child_id": "child-one",
            "precreate_generation": 46, "precreate_sha256": "a" * 64,
            "post_generation": 48,
            "expected_raw_sha256": hashlib.sha256(
                b"\xef\xbb\xbf" + self.text.encode()).hexdigest(),
        }
        self.records = {
            "task-card.json": {
                "task_id": "task-one", "agent_principal": "agent-one",
                "pending_child": {
                    "parent_handle": "folder-one",
                    "marker": "ap071_" + "a" * 32,
                    "create_operation_id": self.create,
                    "populate_recipe_digest": "d" * 64,
                },
            },
            "effect-plan.json": {
                "schema": "auths.agent-effect-plan/1", "task_id": "task-one",
                "initial_text": self.text,
                "populate_operation_id": self.populate,
                "populate_recipe_digest": "d" * 64,
                "create": {"operation_id": self.create,
                           "resource_handle": "folder-one"},
            },
            "pre-create-baseline.json": {
                "schema": "auths.ap071-pre-create-baseline-populate-failure/1",
                "task_id": "task-one", "create_operation_id": self.create,
                "generation": 46, "observation_sha256": "a" * 64,
                "parent_id": "folder-one", "marker": "ap071_" + "a" * 32,
            },
            "populate-entry.json": {
                "schema": "auths.ap071-populate-entry/1",
                "task_id": "task-one", "child_id": "child-one",
                "populate_operation_id": self.populate,
                "baseline_sha256": "a" * 64,
                "preflight_sha256": "b" * 64,
            },
            "populate-result.json": {
                "schema": "auths.ap071-populate-result/1",
                "task_id": "task-one", "populate_operation_id": self.populate,
                "outcome": "unknown",
            },
        }
        self.gateway = {
            "schema": "auths.gateway-agent-task-status/1",
            "task_id": "task-one", "revoked": True,
            "provider_calls": 1, "releases": 1, "released_bytes": 51,
            "writes": 2,
            "write_operations": [self.create, self.populate],
        }
        self.support = {
            "schema": "auths.gateway-support-bundle/1",
            "build_sha256": "c" * 64,
            "attempts": {
                "listed": 2, "truncated": False,
                "by_stage": {"observed": 1, "unknown": 1},
                "identifiers": [{"stage": "observed"}, {"stage": "unknown"}],
            },
        }
        self.review = {
            "schema": "auths.gateway-submission-review/1",
            "actors": ["agent-one"],
            "arguments": {
                "task_id": "task-one", "operation_id": self.populate,
                "document_id": "child-one", "text": self.text,
            },
            "request": {
                "method": "POST", "url": "https://docs.google.test/child-one",
                "content_type": "application/json", "headers": [],
                "body": '{"text":"Source-backed exact content"}',
            },
        }
        request = self.review["request"]
        self.arm = {
            "schema": "auths.development-populate-response-loss-arm/1",
            "task_id": "task-one", "operation_id": self.populate,
            "request_commitment": commitment(
                "auths.agent-write-request.v1", {
                    "method": request["method"], "url": request["url"],
                    "content_type": request["content_type"],
                    "headers": request["headers"],
                    "body_hex": request["body"].encode().hex(),
                },
            ),
        }
        self._save()

    def _save(self) -> None:
        for name, record in self.records.items():
            path = self.task / name
            path.write_text(json.dumps(record, sort_keys=True))
            path.chmod(0o600)

    def _join(self) -> dict:
        return join_populate_post_entry(
            self.task, self.gateway, self.support, self.arm, self.review,
            self.provider, gateway_sha256="c" * 64,
        )

    def test_one_unknown_attempt_and_exact_provider_state_join(self) -> None:
        self.assertEqual(self._join()["status"], "accepted")
        self.assertFalse(self._join()["retry_authorized"])

    def test_recovery_or_changed_request_is_refused(self) -> None:
        recovery = self.task / "populate-recovery-entry.json"
        recovery.write_text("{}")
        with self.assertRaisesRegex(ContractRejected, "pre-entry recovery"):
            self._join()
        recovery.unlink()
        self.review["request"]["body"] += " "
        with self.assertRaises(ContractRejected):
            self._join()

    def test_second_attempt_or_falsely_known_outcome_is_refused(self) -> None:
        self.support["attempts"]["listed"] = 3
        with self.assertRaises(ContractRejected):
            self._join()
        self.support["attempts"]["listed"] = 2
        self.records["populate-result.json"]["outcome"] = "response-recorded"
        self._save()
        with self.assertRaises(ContractRejected):
            self._join()


if __name__ == "__main__":
    unittest.main()
