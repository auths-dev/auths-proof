from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from inspect import isawaitable
from typing import (
    Awaitable,
    Callable,
    Literal,
    Mapping,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

from ._mechanism_conformance import CONFORMANCE_CATALOG
from .custody import ProviderOperationError, Signer, SigningRequest
from .integrations import development
from .profiles import mcp
from .profiles.mcp import McpClosedProvider, McpHandlerOutcome, McpToolContext
from .workflow import ReviewField


@dataclass(frozen=True)
class ConformanceMetadata:
    implementation: str
    version: str
    runtime: str = "python"
    capabilities: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ConformanceCaseResult:
    id: str
    classification: Literal["deterministic"]
    passed: bool


@dataclass(frozen=True)
class ConformanceReport:
    schema: Literal["auths.conformance-report/1"]
    suite: str
    suite_version: int
    semantic_subject: Literal["auths.mechanism-profile-conformance/1"]
    implementation: str
    implementation_version: str
    runtime: str
    capabilities: Tuple[str, ...]
    results: Tuple[ConformanceCaseResult, ...]
    passed: bool
    claim: Literal["test-results-only-not-security-certification"]


@dataclass(frozen=True)
class AtomicReservationRecord:
    key: str
    commitment: bytes
    value: bytes


class AtomicReservationStoreCandidate(Protocol):
    async def reserve(
        self, record: AtomicReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]: ...

    async def aclose(self) -> None: ...

    async def reopen(self) -> AtomicReservationStoreCandidate: ...


class ByteTransportCandidate(Protocol):
    async def exchange(
        self,
        packet: bytes,
        *,
        maximum_bytes: int,
        cancellation: asyncio.Event,
    ) -> bytes: ...

    async def aclose(self) -> None: ...


FactoryResult = Union[object, Awaitable[object]]
AtomicStoreFactory = Callable[[], FactoryResult]
ByteTransportFactory = Callable[[Callable[[bytes], Awaitable[bytes]]], FactoryResult]
McpProviderFactory = Callable[..., McpClosedProvider]


async def certify_signer(
    factory: Callable[[], FactoryResult], metadata: ConformanceMetadata
) -> ConformanceReport:
    outcomes = []
    for case in (
        "transaction-binding",
        "principal-binding",
        "descriptor-binding",
        "request-binding",
    ):
        outcomes.append((f"signer/{case}", await _signer_binding_case(factory, case)))
    outcomes.append(("signer/expiry", await _signer_rejection_case(factory, "expiry")))
    outcomes.append(
        ("signer/duplicate", await _signer_rejection_case(factory, "duplicate"))
    )
    outcomes.append(
        ("signer/cancellation", await _signer_rejection_case(factory, "cancellation"))
    )
    outcomes.append(
        ("signer/disposal", await _signer_rejection_case(factory, "disposal"))
    )
    return _report("signer-custody/1", metadata, outcomes)


async def certify_atomic_store(
    factory: AtomicStoreFactory, metadata: ConformanceMetadata
) -> ConformanceReport:
    record = _reservation("case", 1, b"\x03")
    outcomes = [
        (
            "atomic-store/acquire",
            await _atomic_case(
                factory, lambda store: _equals_reservation(store, record, "acquired")
            ),
        ),
        (
            "atomic-store/exact-replay",
            await _atomic_case(factory, lambda store: _exact_replay(store, record)),
        ),
        (
            "atomic-store/conflict",
            await _atomic_case(factory, lambda store: _conflict(store, record)),
        ),
        (
            "atomic-store/concurrent-single-winner",
            await _atomic_case(factory, lambda store: _concurrent(store, record)),
        ),
        (
            "atomic-store/bounded-record",
            await _atomic_case(factory, _bounded_record),
        ),
    ]
    first = await _resolve(factory())
    second = await _resolve(factory())
    try:
        isolated = (
            await first.reserve(record) == "acquired"
            and await second.reserve(record) == "acquired"
        )
    except Exception:
        isolated = False
    finally:
        await _close(first)
        await _close(second)
    outcomes.append(("atomic-store/isolated-instances", isolated))
    outcomes.append(
        (
            "atomic-store/reopen-durability-claim",
            await _durability_case(factory, record, metadata),
        )
    )
    return _report("atomic-reservation-store/1", metadata, outcomes)


async def certify_byte_transport(
    factory: ByteTransportFactory, metadata: ConformanceMetadata
) -> ConformanceReport:
    async def exact(packet: bytes) -> bytes:
        return packet

    async def oversized(_: bytes) -> bytes:
        return b"x" * 17

    outcomes = [
        (
            "byte-transport/exact-bytes",
            await _transport_case(
                factory,
                exact,
                lambda transport: _exchange_equals(transport, b"abc", 16, b"abc"),
            ),
        ),
        (
            "byte-transport/bounded-input",
            await _transport_case(
                factory,
                exact,
                lambda transport: _exchange_rejected(transport, b"x" * 17, 16),
            ),
        ),
        (
            "byte-transport/bounded-output",
            await _transport_case(
                factory,
                oversized,
                lambda transport: _exchange_rejected(transport, b"x", 16),
            ),
        ),
        (
            "byte-transport/cancellation",
            await _transport_case(factory, exact, _cancelled_exchange),
        ),
        (
            "byte-transport/disposal",
            await _transport_case(factory, exact, _disposed_exchange, close=False),
        ),
    ]
    return _report("bounded-byte-transport/1", metadata, outcomes)


async def certify_mcp_provider(
    factory: McpProviderFactory, metadata: ConformanceMetadata
) -> ConformanceReport:
    outcomes = []
    calls = 0
    request_bound = False

    async def publish(
        arguments: Mapping[str, object], context: McpToolContext
    ) -> object:
        nonlocal calls, request_bound
        calls += 1
        request_bound = (
            arguments.get("report") == "weekly"
            and context.service == "development"
            and context.tool == "publish_report"
        )
        return {"ok": True}

    auths = await development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    )
    try:
        action = mcp.call_tool(name="publish_report", arguments={"report": "weekly"})
        exact = factory(tools={"publish_report": publish})
        completed = await auths.execute(
            action=action, provider=exact, request_id="conformance-exact"
        )
        outcomes.append(
            (
                "mcp/exact-call",
                completed.kind == "completed" and calls == 1 and request_bound,
            )
        )
        denied = await auths.execute(
            action=mcp.call_tool(name="delete_report", arguments={}),
            provider=exact,
            request_id="conformance-denied",
        )
        outcomes.append(
            ("mcp/deny-before-entry", denied.kind == "denied" and calls == 1)
        )
        concurrent = await asyncio.gather(
            auths.execute(
                action=action,
                provider=exact,
                request_id="conformance-concurrent",
            ),
            auths.execute(
                action=action,
                provider=exact,
                request_id="conformance-concurrent",
            ),
        )
        outcomes.append(
            (
                "mcp/concurrent-single-entry",
                sorted(value.kind for value in concurrent)
                == ["completed", "exact-replay"]
                and calls == 2,
            )
        )
    except Exception:
        _ensure_outcomes(
            outcomes,
            "mcp/exact-call",
            "mcp/deny-before-entry",
            "mcp/concurrent-single-entry",
        )
    finally:
        await auths.aclose()

    ambiguous_calls = 0

    async def ambiguous(
        arguments: Mapping[str, object], context: McpToolContext
    ) -> object:
        nonlocal ambiguous_calls
        ambiguous_calls += 1
        return McpHandlerOutcome("possible", cause="unknown")

    async def forbidden(
        arguments: Mapping[str, object], context: McpToolContext
    ) -> object:
        nonlocal ambiguous_calls
        ambiguous_calls += 100
        return None

    async def reconcile(execution_id: str, service: str) -> McpHandlerOutcome[object]:
        return McpHandlerOutcome("applied", {"ok": True})

    recovery = await development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    )
    try:
        pending = await recovery.execute(
            action=mcp.call_tool(name="publish_report", arguments={}),
            provider=factory(tools={"publish_report": ambiguous}),
            request_id="conformance-recovery",
        )
        outcomes.append(
            (
                "mcp/ambiguous-no-blind-retry",
                pending.kind == "recoverable" and ambiguous_calls == 1,
            )
        )
        resumed = await recovery.resume(
            reference=pending.reference,
            provider=factory(tools={"publish_report": forbidden}, reconcile=reconcile),
        )
        outcomes.append(
            (
                "mcp/reconcile-without-reentry",
                resumed.kind == "completed" and ambiguous_calls == 1,
            )
        )
    except Exception:
        _ensure_outcomes(
            outcomes,
            "mcp/ambiguous-no-blind-retry",
            "mcp/reconcile-without-reentry",
        )
    finally:
        await recovery.aclose()

    service_auths = await development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    )
    try:
        await service_auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={}),
            provider=factory(service="other", tools={"publish_report": publish}),
        )
        outcomes.append(("mcp/service-binding", False))
    except Exception:
        outcomes.append(("mcp/service-binding", True))
    finally:
        await service_auths.aclose()

    async def oversized(
        arguments: Mapping[str, object], context: McpToolContext
    ) -> object:
        return "x" * 1_048_577

    bounded_auths = await development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    )
    try:
        result = await bounded_auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={}),
            provider=factory(tools={"publish_report": oversized}),
        )
        outcomes.append(("mcp/bounded-output", result.kind != "completed"))
    except Exception:
        outcomes.append(("mcp/bounded-output", True))
    finally:
        await bounded_auths.aclose()
    return _report("auths.mcp/1/provider/1", metadata, outcomes)


async def _signer_binding_case(factory: Callable[[], FactoryResult], case: str) -> bool:
    signer = await _resolve(factory())
    try:
        request = await _signing_request(signer, case)
        response = await signer.sign(request)
        if case == "transaction-binding":
            return response.transaction_digest == request.transaction_digest
        if case == "principal-binding":
            return (
                response.principal.principal.value == request.principal.principal.value
            )
        if case == "descriptor-binding":
            return response.principal.matches(request.principal)
        return response.request_id == request.request_id
    except Exception:
        return False
    finally:
        await _close(signer)


async def _signer_rejection_case(
    factory: Callable[[], FactoryResult], case: str
) -> bool:
    signer = await _resolve(factory())
    try:
        request = await _signing_request(signer, case)
        if case == "expiry":
            request = SigningRequest(
                request.request_id,
                request.object_kind,
                request.object_id,
                request.principal,
                request.transaction_digest,
                request.signing_preimage,
                int(time.time()) - 1,
                request.display,
            )
            return await _provider_rejected(
                signer.sign(request), ("rejected", "timeout")
            )
        if case == "duplicate":
            await signer.sign(request)
            return await _provider_rejected(signer.sign(request), ("rejected",))
        if case == "cancellation":
            task = asyncio.create_task(signer.sign(request))
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return True
            return False
        await signer.aclose()
        return await _provider_rejected(
            signer.sign(request), ("cancelled", "unsupported")
        )
    except Exception:
        return False
    finally:
        await _close(signer)


async def _signing_request(signer: Signer, suffix: str) -> SigningRequest:
    principal = await signer.public_identity()
    return SigningRequest(
        f"conformance.{suffix}",
        "action",
        b"\x01" * 32,
        principal,
        b"\x02" * 32,
        b"\x03\x04\x05",
        int(time.time()) + 60,
        (ReviewField("Conformance", suffix),),
    )


async def _provider_rejected(
    awaitable: Awaitable[object], expected: Sequence[str]
) -> bool:
    try:
        await awaitable
        return False
    except ProviderOperationError as error:
        return error.kind in expected
    except Exception:
        return False


async def _atomic_case(
    factory: AtomicStoreFactory,
    exercise: Callable[[AtomicReservationStoreCandidate], Awaitable[bool]],
) -> bool:
    store = await _resolve(factory())
    try:
        return await exercise(store)
    except Exception:
        return False
    finally:
        await _close(store)


async def _equals_reservation(
    store: AtomicReservationStoreCandidate,
    record: AtomicReservationRecord,
    expected: str,
) -> bool:
    return await store.reserve(record) == expected


async def _exact_replay(
    store: AtomicReservationStoreCandidate, record: AtomicReservationRecord
) -> bool:
    return (
        await store.reserve(record) == "acquired"
        and await store.reserve(record) == "exact-replay"
    )


async def _conflict(
    store: AtomicReservationStoreCandidate, record: AtomicReservationRecord
) -> bool:
    return (
        await store.reserve(record) == "acquired"
        and await store.reserve(_reservation("case", 2, b"\x04")) == "conflict"
    )


async def _concurrent(
    store: AtomicReservationStoreCandidate, record: AtomicReservationRecord
) -> bool:
    values = await asyncio.gather(*(store.reserve(record) for _ in range(8)))
    return values.count("acquired") == 1 and values.count("exact-replay") == 7


async def _bounded_record(store: AtomicReservationStoreCandidate) -> bool:
    try:
        await store.reserve(_reservation("oversized", 1, b"x" * 262_145))
        return False
    except (Exception, asyncio.CancelledError):
        return True


async def _durability_case(
    factory: AtomicStoreFactory,
    record: AtomicReservationRecord,
    metadata: ConformanceMetadata,
) -> bool:
    if "durable-reopen" not in metadata.capabilities:
        return True
    first = await _resolve(factory())
    second = None
    try:
        if await first.reserve(record) != "acquired":
            return False
        reopen = getattr(first, "reopen", None)
        if not callable(reopen):
            return False
        second = await _resolve(reopen())
        return await second.reserve(record) == "exact-replay"
    except Exception:
        return False
    finally:
        if second is not None:
            await _close(second)
        await _close(first)


async def _transport_case(
    factory: ByteTransportFactory,
    deliver: Callable[[bytes], Awaitable[bytes]],
    exercise: Callable[[ByteTransportCandidate], Awaitable[bool]],
    *,
    close: bool = True,
) -> bool:
    transport = await _resolve(factory(deliver))
    try:
        return await exercise(transport)
    except Exception:
        return False
    finally:
        if close:
            await _close(transport)


async def _exchange_equals(
    transport: ByteTransportCandidate,
    packet: bytes,
    maximum: int,
    expected: bytes,
) -> bool:
    return (
        await transport.exchange(
            packet, maximum_bytes=maximum, cancellation=asyncio.Event()
        )
        == expected
    )


async def _exchange_rejected(
    transport: ByteTransportCandidate, packet: bytes, maximum: int
) -> bool:
    try:
        await transport.exchange(
            packet, maximum_bytes=maximum, cancellation=asyncio.Event()
        )
        return False
    except (Exception, asyncio.CancelledError):
        return True


async def _cancelled_exchange(transport: ByteTransportCandidate) -> bool:
    cancellation = asyncio.Event()
    cancellation.set()
    try:
        await transport.exchange(b"x", maximum_bytes=16, cancellation=cancellation)
        return False
    except (asyncio.CancelledError, Exception):
        return True


async def _disposed_exchange(transport: ByteTransportCandidate) -> bool:
    await transport.aclose()
    return await _exchange_rejected(transport, b"x", 16)


def _report(
    suite: str,
    metadata: ConformanceMetadata,
    outcomes: Sequence[Tuple[str, bool]],
) -> ConformanceReport:
    expected = next(
        (
            candidate
            for candidate in CONFORMANCE_CATALOG["suites"]
            if candidate["id"] == suite
        ),
        None,
    )
    if expected is None:
        raise ValueError("unknown Auths conformance suite")
    supplied = dict(outcomes)
    results = tuple(
        ConformanceCaseResult(
            candidate["id"],
            candidate["classification"],
            supplied.get(candidate["id"]) is True,
        )
        for candidate in expected["cases"]
    )
    capabilities = tuple(
        _bounded(value, "capability") for value in metadata.capabilities
    )
    return ConformanceReport(
        "auths.conformance-report/1",
        suite,
        1,
        "auths.mechanism-profile-conformance/1",
        _bounded(metadata.implementation, "implementation"),
        _bounded(metadata.version, "implementation version"),
        _bounded(metadata.runtime, "runtime"),
        capabilities,
        results,
        all(result.passed for result in results),
        "test-results-only-not-security-certification",
    )


def _reservation(key: str, byte: int, value: bytes) -> AtomicReservationRecord:
    return AtomicReservationRecord(key, bytes([byte]) * 32, bytes(value))


async def _resolve(value: FactoryResult):
    return await value if isawaitable(value) else value


async def _close(value: object) -> None:
    close = getattr(value, "aclose", None)
    if callable(close):
        await close()


def _ensure_outcomes(outcomes: list, *case_ids: str) -> None:
    present = {identifier for identifier, _ in outcomes}
    outcomes.extend(
        (identifier, False) for identifier in case_ids if identifier not in present
    )


def _bounded(value: str, name: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 128
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError(f"invalid conformance {name}")
    return value


__all__ = [
    "AtomicReservationRecord",
    "AtomicReservationStoreCandidate",
    "ByteTransportCandidate",
    "CONFORMANCE_CATALOG",
    "ConformanceCaseResult",
    "ConformanceMetadata",
    "ConformanceReport",
    "certify_atomic_store",
    "certify_byte_transport",
    "certify_mcp_provider",
    "certify_signer",
]
