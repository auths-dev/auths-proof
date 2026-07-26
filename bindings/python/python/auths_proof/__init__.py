"""Idiomatic embedded Auths Proof Protocol V1 verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, Union

from ._native import verify_v1

VerdictKind = Literal["authorized", "denied", "indeterminate"]
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]
_MAX_RESULT_BYTES: Final = 16 * 1024 * 1024
_MAX_DEPTH: Final = 64
_AUTHORIZED_TOKEN: Final = object()


@dataclass(frozen=True)
class Explanation:
    """Stable, non-sensitive result explanation."""

    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class VerificationMetrics:
    """Deterministic input and verifier-work counters."""

    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


class VerifiedAction:
    """Canonical action bytes constructible only by this verifier wrapper."""

    __slots__ = ("_canonical_action",)

    def __init__(self, token: object, canonical_action: bytes) -> None:
        if token is not _AUTHORIZED_TOKEN:
            raise TypeError("VerifiedAction is sealed")
        self._canonical_action = bytes(canonical_action)

    @property
    def canonical_bytes(self) -> bytes:
        """Returns an immutable copy of the authorized canonical action."""

        return bytes(self._canonical_action)


@dataclass(frozen=True)
class Authorized:
    """Exact authority was established."""

    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: bytes | None
    local_configuration: bytes
    result_cbor: bytes
    action: VerifiedAction


@dataclass(frozen=True)
class Denied:
    """Available trustworthy facts established rejection."""

    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: bytes | None
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class Indeterminate:
    """A required trustworthy fact or implementation was unavailable."""

    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: bytes | None
    local_configuration: bytes
    result_cbor: bytes


VerificationResult = Union[Authorized, Denied, Indeterminate]


def verify(
    proof_cbor: bytes,
    canonical_action_cbor: bytes,
    trusted_context_cbor: bytes,
) -> VerificationResult:
    """Runs the complete embedded three-input V1 verification operation."""

    result_cbor = bytes(
        verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    )
    (
        kind,
        code,
        stage,
        metrics,
        required_configuration,
        local_configuration,
    ) = _decode_result(result_cbor)
    explanation = _explain(kind, code)
    common = {
        "code": code,
        "stage": stage,
        "explanation": explanation,
        "metrics": metrics,
        "required_configuration": required_configuration,
        "local_configuration": local_configuration,
        "result_cbor": result_cbor,
    }
    if kind == "authorized":
        return Authorized(
            kind="authorized",
            action=VerifiedAction(_AUTHORIZED_TOKEN, canonical_action_cbor),
            **common,
        )
    if kind == "denied":
        return Denied(kind="denied", **common)
    return Indeterminate(kind="indeterminate", **common)


class _Reader:
    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes) -> None:
        if not data or len(data) > _MAX_RESULT_BYTES:
            raise ValueError("Auths result exceeds byte bounds")
        self._data = data
        self._offset = 0

    @property
    def complete(self) -> bool:
        return self._offset == len(self._data)

    def _take(self) -> int:
        if self._offset >= len(self._data):
            raise ValueError("truncated CBOR result")
        value = self._data[self._offset]
        self._offset += 1
        return value

    def head(self) -> tuple[int, int]:
        initial = self._take()
        major = initial >> 5
        additional = initial & 31
        if additional < 24:
            return major, additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise ValueError("indefinite CBOR is not canonical")
        value = 0
        for _ in range(width):
            value = (value << 8) | self._take()
        minimum = {1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[width]
        if value < minimum:
            raise ValueError("non-minimal CBOR integer")
        return major, value

    def uint(self) -> int:
        major, value = self.head()
        if major != 0:
            raise ValueError("expected CBOR unsigned integer")
        return value

    def text(self) -> str:
        major, length = self.head()
        if major != 3 or length > len(self._data) - self._offset:
            raise ValueError("invalid CBOR text")
        end = self._offset + length
        value = self._data[self._offset : end].decode("utf-8", errors="strict")
        self._offset = end
        return value

    def nullable_bytes(self, expected_length: int) -> bytes | None:
        major, length = self.head()
        if major == 7 and length == 22:
            return None
        if (
            major != 2
            or length != expected_length
            or length > len(self._data) - self._offset
        ):
            raise ValueError("invalid CBOR bytes")
        end = self._offset + length
        value = bytes(self._data[self._offset : end])
        self._offset = end
        return value

    def bytes(self, expected_length: int) -> bytes:
        value = self.nullable_bytes(expected_length)
        if value is None:
            raise ValueError("unexpected CBOR null")
        return value

    def map(self) -> int:
        major, length = self.head()
        if major != 5 or length > 1_000_000:
            raise ValueError("invalid CBOR map")
        return length

    def skip(self, depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError("CBOR depth exceeded")
        major, argument = self.head()
        if major in (0, 1):
            return
        if major in (2, 3):
            if argument > len(self._data) - self._offset:
                raise ValueError("truncated CBOR value")
            self._offset += argument
            return
        if major == 4:
            for _ in range(argument):
                self.skip(depth + 1)
            return
        if major == 5:
            for _ in range(argument):
                self.skip(depth + 1)
                self.skip(depth + 1)
            return
        if major == 7 and argument in (20, 21, 22):
            return
        raise ValueError("unsupported CBOR result value")


def _decode_result(
    data: bytes,
) -> tuple[
    VerdictKind,
    str,
    VerificationStage,
    VerificationMetrics,
    bytes | None,
    bytes,
]:
    reader = _Reader(data)
    fields = reader.map()
    decision: int | None = None
    stage_number: int | None = None
    code: str | None = None
    metrics: VerificationMetrics | None = None
    required_configuration: bytes | None = None
    local_configuration: bytes | None = None
    abi_version: int | None = None
    previous_key = -1
    for _ in range(fields):
        key = reader.uint()
        if key <= previous_key:
            raise ValueError("result map keys are not canonical")
        previous_key = key
        if key == 0:
            decision = reader.uint()
        elif key == 1:
            stage_number = reader.uint()
        elif key == 2:
            if reader.map() != 2 or reader.uint() != 0:
                raise ValueError("unsupported result code shape")
            reader.uint()
            code_key = reader.uint()
            if code_key != 1:
                raise ValueError("unsupported result code shape")
            code = reader.text()
        elif key == 11:
            metrics = _decode_metrics(reader)
        elif key == 13:
            required_configuration = reader.nullable_bytes(32)
        elif key == 14:
            local_configuration = reader.bytes(32)
        elif key == 15:
            abi_version = reader.uint()
        else:
            reader.skip()
    if not reader.complete:
        raise ValueError("trailing CBOR result bytes")
    kinds: dict[int, VerdictKind] = {
        0: "authorized",
        1: "denied",
        2: "indeterminate",
    }
    stages: dict[int, VerificationStage] = {
        0: "decode",
        1: "resolve",
        2: "principal-control",
        3: "authority",
        4: "complete",
    }
    if (
        decision not in kinds
        or stage_number not in stages
        or code is None
        or metrics is None
        or local_configuration is None
        or abi_version != 2
    ):
        raise ValueError("incomplete Auths result")
    return (
        kinds[decision],
        code,
        stages[stage_number],
        metrics,
        required_configuration,
        local_configuration,
    )


def _decode_metrics(reader: _Reader) -> VerificationMetrics:
    fields = reader.map()
    values: dict[int, int] = {}
    previous_key = -1
    for _ in range(fields):
        key = reader.uint()
        if key <= previous_key:
            raise ValueError("metrics map keys are not canonical")
        previous_key = key
        values[key] = reader.uint()
    if set(values) != set(range(7)):
        raise ValueError("incomplete Auths metrics")
    return VerificationMetrics(*[values[index] for index in range(7)])


def _explain(kind: VerdictKind, code: str) -> Explanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this action"
    elif kind == "denied":
        message = "the supplied proof does not authorize this exact action"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return Explanation(code=code, message=message, retryable=kind == "indeterminate")


__all__ = [
    "Authorized",
    "Denied",
    "Explanation",
    "Indeterminate",
    "VerificationMetrics",
    "VerificationResult",
    "VerifiedAction",
    "verify",
]
