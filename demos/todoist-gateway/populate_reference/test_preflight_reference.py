"""Synthetic hostile cases for the independent Todoist population rule."""

import json
import unittest

from preflight_reference import (
    MAX_METADATA_BYTES,
    ChildPins,
    PreflightRejected,
    evaluate_bound_blank_task,
)


PINS = ChildPins(
    task_id="task-ABC-123",
    project_id="project-123",
    title="Approved handoff",
    recovery_marker="ap071_0123456789abcdef",
)


def metadata(**changes: object) -> bytes:
    fields = {
        "id": PINS.task_id,
        "project_id": PINS.project_id,
        "content": PINS.title,
        "description": PINS.recovery_marker,
        "irrelevant_provider_field": "permitted",
    }
    fields.update(changes)
    return json.dumps(fields, separators=(",", ":")).encode()


class TodoistPreflightReferenceTests(unittest.TestCase):
    def test_only_the_bound_blank_child_produces_empty_provider_values(self) -> None:
        raw = metadata()
        facts = evaluate_bound_blank_task(raw, PINS)
        self.assertEqual(facts.child_id, PINS.task_id)
        self.assertEqual(facts.provider_values, {})
        self.assertEqual(len(facts.metadata_sha256), 64)

    def test_changed_provider_facts_and_wrong_types_fail_closed(self) -> None:
        for name, replacement in (
            ("id", "task-other"),
            ("project_id", "project-other"),
            ("content", "Changed title"),
            ("description", "Already populated"),
            ("id", 123),
            ("project_id", [PINS.project_id]),
            ("content", None),
            ("description", {"text": PINS.recovery_marker}),
        ):
            with self.subTest(name=name, replacement=replacement):
                with self.assertRaises(PreflightRejected):
                    evaluate_bound_blank_task(metadata(**{name: replacement}), PINS)

    def test_ambiguous_or_unbounded_provider_response_fails_closed(self) -> None:
        valid = metadata()
        hostile = (
            b'{"id":"first","id":"second"}',
            b"[]",
            b"not-json",
            valid + b" " * MAX_METADATA_BYTES,
            valid.replace(b'"id":', b'"id":"duplicate","id":', 1),
            valid.replace(b'"irrelevant_provider_field":"permitted"',
                          b'"irrelevant_provider_field":NaN'),
        )
        for raw in hostile:
            with self.subTest(raw=raw[:32]):
                with self.assertRaises(PreflightRejected):
                    evaluate_bound_blank_task(raw, PINS)

    def test_bad_pins_cannot_authorize_a_response(self) -> None:
        for pins in (
            ChildPins("task/escape", PINS.project_id, PINS.title, PINS.recovery_marker),
            ChildPins(PINS.task_id, PINS.project_id, PINS.title, "short"),
            ChildPins(PINS.task_id, PINS.project_id, "", PINS.recovery_marker),
            ChildPins(None, PINS.project_id, PINS.title, PINS.recovery_marker),
        ):
            with self.subTest(pins=pins):
                with self.assertRaises(PreflightRejected):
                    evaluate_bound_blank_task(metadata(), pins)


if __name__ == "__main__":
    unittest.main()
