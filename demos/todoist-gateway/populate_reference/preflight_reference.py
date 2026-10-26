"""Test-only Todoist preflight oracle for a bound, unpopulated task.

The caller must obtain ``metadata_raw`` from a fresh, credential-bearing
GET /api/v1/tasks/{bound_task_id} under the task's pinned connection. This
pure evaluator cannot authenticate the GET or sign a gateway attestation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

MAX_METADATA_BYTES = 16_384
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_MARKER = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")


class PreflightRejected(ValueError):
    """The provider response does not prove the pinned blank child."""


@dataclass(frozen=True)
class ChildPins:
    task_id: str
    project_id: str
    title: str
    recovery_marker: str

    def validate(self) -> None:
        if (
            not isinstance(self.task_id, str)
            or not _ID.fullmatch(self.task_id)
            or not isinstance(self.project_id, str)
            or not _ID.fullmatch(self.project_id)
        ):
            raise PreflightRejected("invalid bound child or project ID")
        if not isinstance(self.title, str) or not 1 <= len(self.title.encode("utf-8")) <= 96:
            raise PreflightRejected("invalid pinned title")
        if not isinstance(self.recovery_marker, str) or not _MARKER.fullmatch(
            self.recovery_marker
        ):
            raise PreflightRejected("invalid pinned recovery marker")


@dataclass(frozen=True)
class PreflightFacts:
    child_id: str
    metadata_sha256: str
    provider_values: dict[str, str]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightRejected("duplicate provider response key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> object:
    raise PreflightRejected("non-finite provider metadata number")


def evaluate_bound_blank_task(metadata_raw: bytes, pins: ChildPins) -> PreflightFacts:
    """Require exact scalar identity, parent, title and untouched marker.

    A successful result supplies the domain facts for an operator-pinned
    preflight signer. This recipe needs no late-bound provider values; the
    gateway separately binds child, task, plan, connection and expiry.
    """
    pins.validate()
    if not isinstance(metadata_raw, bytes) or not 1 <= len(metadata_raw) <= MAX_METADATA_BYTES:
        raise PreflightRejected("provider metadata exceeds bounds")
    try:
        metadata = json.loads(
            metadata_raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreflightRejected("invalid provider metadata JSON") from error
    if not isinstance(metadata, dict):
        raise PreflightRejected("provider metadata must be an object")
    expected = {
        "id": pins.task_id,
        "project_id": pins.project_id,
        "content": pins.title,
        "description": pins.recovery_marker,
    }
    for name, value in expected.items():
        if type(metadata.get(name)) is not str or metadata[name] != value:
            raise PreflightRejected(f"provider metadata {name} differs from pinned child")
    return PreflightFacts(
        child_id=pins.task_id,
        metadata_sha256=hashlib.sha256(metadata_raw).hexdigest(),
        provider_values={},
    )
