"""Inert verification diagnostics for caller-supplied engines."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Literal, Mapping, Optional, Protocol, Tuple, runtime_checkable

from ._native import (
    decode_diagnostic_result_v1,
    diagnostic_input_limits_v1,
    native_abi_version,
)
from ._inspection import VerificationMetrics, VerificationStage, VerdictKind


@runtime_checkable
class DiagnosticEngine(Protocol):
    def verify_v1(
        self,
        proof_cbor: bytes,
        canonical_action_cbor: bytes,
        trusted_context_cbor: bytes,
    ) -> bytes: ...


@dataclass(frozen=True)
class DiagnosticExplanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class DiagnosticResult:
    effect_capable: Literal[False]
    kind: VerdictKind
    code: str
    stage: VerificationStage
    explanation: DiagnosticExplanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    submitted_action_cbor: bytes


@dataclass(frozen=True)
class RuntimeDiagnostic:
    package_version: str
    native_abi: int
    required_native_abi: int
    coherent: bool
    capabilities: Tuple[str, ...]
    profiles: Tuple[str, ...]
    trust_configuration: Optional[bytes]
    adapters: Tuple[Tuple[str, int], ...]


class DiagnosticVerifier:
    def __init__(self, engine: DiagnosticEngine) -> None:
        if not callable(getattr(engine, "verify_v1", None)):
            raise TypeError("diagnostic engine must expose verify_v1")
        self._engine = engine

    def verify(
        self,
        proof_cbor: bytes,
        canonical_action_cbor: bytes,
        trusted_context_cbor: bytes,
    ) -> DiagnosticResult:
        proof = _bounded_bytes(proof_cbor, 0)
        action = _bounded_bytes(canonical_action_cbor, 1)
        context = _bounded_bytes(trusted_context_cbor, 2)
        try:
            encoded = self._engine.verify_v1(proof, action, context)
        except Exception:
            raise ValueError("diagnostic engine failed") from None
        if type(encoded) is not bytes:
            raise TypeError("diagnostic engine returned a non-byte result")
        try:
            native = decode_diagnostic_result_v1(encoded)
        except (TypeError, ValueError, RuntimeError):
            raise ValueError("diagnostic engine returned an invalid result") from None
        return DiagnosticResult(
            effect_capable=False,
            kind=native.kind,
            code=native.code,
            stage=native.stage,
            explanation=_explanation(native.kind, native.code),
            metrics=VerificationMetrics(*native.metrics),
            required_configuration=native.required_configuration,
            local_configuration=bytes(native.local_configuration),
            result_cbor=bytes(native.result_cbor),
            submitted_action_cbor=action,
        )


def create_diagnostic_verifier(engine: DiagnosticEngine) -> DiagnosticVerifier:
    return DiagnosticVerifier(engine)


def runtime_diagnostic(
    *,
    trust_configuration: Optional[bytes] = None,
    adapters: Optional[Mapping[str, int]] = None,
) -> RuntimeDiagnostic:
    try:
        version = importlib.metadata.version("auths")
    except importlib.metadata.PackageNotFoundError:
        version = "source-tree"
    native_abi = native_abi_version()
    required = 2
    trust = None if trust_configuration is None else bytes(trust_configuration)
    if trust is not None and len(trust) != 32:
        raise ValueError("trust configuration commitment must contain 32 bytes")
    adapter_values = tuple(sorted((adapters or {}).items()))
    if any(
        not name or type(version) is not int or version < 1
        for name, version in adapter_values
    ):
        raise ValueError("adapter contract declarations are invalid")
    return RuntimeDiagnostic(
        package_version=version,
        native_abi=native_abi,
        required_native_abi=required,
        coherent=native_abi == required,
        capabilities=(
            "identity",
            "verification",
            "authority",
            "delegation",
            "doctor",
            "plans",
            "runtime-state",
        ),
        profiles=("auths.mcp/1",),
        trust_configuration=trust,
        adapters=adapter_values,
    )


def _bounded_bytes(value: bytes, index: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError("diagnostic verifier inputs must be bytes")
    limits = diagnostic_input_limits_v1()
    if not value or len(value) > limits[index]:
        raise ValueError("diagnostic verifier input is outside native limits")
    return bytes(value)


def _explanation(kind: VerdictKind, code: str) -> DiagnosticExplanation:
    messages = {
        "authorized": "the diagnostic engine reported authority for this action",
        "denied": "the diagnostic engine reported that authority was not established",
        "indeterminate": "the diagnostic engine reported that a required fact was unavailable",
    }
    return DiagnosticExplanation(code, messages[kind], kind == "indeterminate")


__all__ = [
    "DiagnosticEngine",
    "DiagnosticExplanation",
    "DiagnosticResult",
    "DiagnosticVerifier",
    "RuntimeDiagnostic",
    "create_diagnostic_verifier",
    "runtime_diagnostic",
]
