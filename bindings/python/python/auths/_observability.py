"""Bounded Auths telemetry and redacted support evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence, Tuple, Union, runtime_checkable

AttributeValue = Union[str, int, bool]
MAX_EVENTS = 256
MAX_ATTRIBUTES = 32
MAX_TEXT_BYTES = 256
SENSITIVE_ATTRIBUTE_PARTS = (
    "proof",
    "signature",
    "private",
    "credential",
    "secret",
    "token",
    "payload",
    "cbor",
    "public_key",
    "idempotency_key",
)


@dataclass(frozen=True)
class AuthsEvent:
    name: str
    operation: str
    stage: str
    outcome: str
    observed_at: int
    attributes: Tuple[Tuple[str, AttributeValue], ...] = ()

    def __post_init__(self) -> None:
        fields = (self.name, self.operation, self.stage, self.outcome)
        if any(not value or len(value.encode()) > MAX_TEXT_BYTES for value in fields):
            raise ValueError("telemetry event contains an invalid field")
        attributes = tuple(self.attributes)
        _validate_attributes(attributes)
        object.__setattr__(self, "attributes", attributes)


@runtime_checkable
class Telemetry(Protocol):
    def emit(self, event: AuthsEvent) -> None: ...


class DecisionTimeline:
    def __init__(self) -> None:
        self._events: list[AuthsEvent] = []

    def append(self, event: AuthsEvent) -> None:
        if type(event) is not AuthsEvent:
            raise TypeError("timeline accepts AuthsEvent values")
        if len(self._events) >= MAX_EVENTS:
            raise ValueError("decision timeline is full")
        self._events.append(event)

    def snapshot(self) -> Tuple[AuthsEvent, ...]:
        return tuple(self._events)


def support_bundle(
    events: Sequence[AuthsEvent],
    *,
    runtime: Mapping[str, AttributeValue],
) -> bytes:
    values = tuple(events)
    if len(values) > MAX_EVENTS or any(
        type(value) is not AuthsEvent for value in values
    ):
        raise ValueError("support bundle event collection is invalid")
    runtime_values = tuple(runtime.items())
    _validate_attributes(runtime_values)
    document = {
        "schema": "auths.python-support-bundle/1",
        "runtime": {key: runtime[key] for key in sorted(runtime)},
        "events": [
            {
                "name": event.name,
                "operation": event.operation,
                "stage": event.stage,
                "outcome": event.outcome,
                "observedAt": event.observed_at,
                "attributes": {key: value for key, value in sorted(event.attributes)},
            }
            for event in values
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _validate_attributes(
    attributes: Sequence[Tuple[str, AttributeValue]],
) -> None:
    if len(attributes) > MAX_ATTRIBUTES:
        raise ValueError("telemetry contains too many attributes")
    names: set[str] = set()
    for key, value in attributes:
        normalized = key.lower().replace("-", "_")
        if (
            not key
            or len(key.encode()) > MAX_TEXT_BYTES
            or key in names
            or any(part in normalized for part in SENSITIVE_ATTRIBUTE_PARTS)
        ):
            raise ValueError("telemetry attribute name is invalid")
        if type(value) is str and len(value.encode()) > MAX_TEXT_BYTES:
            raise ValueError("telemetry attribute value is too large")
        if type(value) is int and not -(1 << 63) <= value < (1 << 63):
            raise ValueError("telemetry integer is outside supported bounds")
        if type(value) not in (str, int, bool):
            raise TypeError(
                "telemetry attributes must be low-cardinality scalar values"
            )
        names.add(key)


__all__ = ["AuthsEvent", "DecisionTimeline", "Telemetry", "support_bundle"]
