from __future__ import annotations

import asyncio
import time

from auths._native import Principal
from auths.framework import PrincipalDescriptor, ProviderOperationError, SigningResponse
from auths.testkit import (
    ConformanceMetadata,
    certify_atomic_store,
    certify_byte_transport,
    certify_mcp_provider,
    certify_signer,
)
from auths.profiles import mcp


METADATA = ConformanceMetadata("test.candidate", "1")
PRINCIPAL = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")


class ConformantSigner:
    kind = "conformance"
    lifecycle = "ephemeral"

    def __init__(self) -> None:
        self.closed = False
        self.requests: set[str] = set()
        self.principal = PrincipalDescriptor(
            PRINCIPAL, "raw-key-v1", PRINCIPAL.value, "ed25519-v1"
        )

    async def public_identity(self):
        if self.closed:
            raise ProviderOperationError("cancelled")
        return self.principal

    async def sign(self, request):
        if self.closed:
            raise ProviderOperationError("cancelled")
        if request.expires_at < int(time.time()):
            raise ProviderOperationError("rejected")
        if request.request_id in self.requests:
            raise ProviderOperationError("rejected")
        self.requests.add(request.request_id)
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            b"x" * 64,
        )

    async def aclose(self) -> None:
        self.closed = True


class AtomicStore:
    def __init__(self) -> None:
        self.records: dict[str, bytes] = {}

    async def reserve(self, record):
        if len(record.value) > 262_144:
            raise ValueError("bounded record")
        current = self.records.get(record.key)
        if current is None:
            self.records[record.key] = record.commitment
            return "acquired"
        return "exact-replay" if current == record.commitment else "conflict"

    async def aclose(self) -> None:
        pass


class ByteTransport:
    def __init__(self, deliver) -> None:
        self.deliver = deliver
        self.closed = False

    async def exchange(self, packet, *, maximum_bytes, cancellation):
        if self.closed or cancellation.is_set():
            raise asyncio.CancelledError
        if not packet or len(packet) > maximum_bytes:
            raise ValueError("bounded input")
        result = await self.deliver(bytes(packet))
        if not result or len(result) > maximum_bytes:
            raise ValueError("bounded output")
        return bytes(result)

    async def aclose(self) -> None:
        self.closed = True


def test_auths_owned_mechanism_and_mcp_suites_execute_every_case() -> None:
    async def scenario() -> None:
        reports = (
            await certify_signer(ConformantSigner, METADATA),
            await certify_atomic_store(AtomicStore, METADATA),
            await certify_byte_transport(
                lambda deliver: ByteTransport(deliver), METADATA
            ),
            await certify_mcp_provider(
                lambda **options: mcp.development_provider(**options), METADATA
            ),
        )
        for report in reports:
            assert report.passed, report.results
            assert report.claim == "test-results-only-not-security-certification"
            assert all(
                result.classification == "deterministic" for result in report.results
            )

    asyncio.run(scenario())


def test_atomic_suite_detects_false_reservation_implementation() -> None:
    class Broken:
        async def reserve(self, record):
            return "acquired"

        async def aclose(self) -> None:
            pass

    report = asyncio.run(certify_atomic_store(Broken, METADATA))
    assert not report.passed
    results = {result.id: result.passed for result in report.results}
    assert not results["atomic-store/exact-replay"]
    assert not results["atomic-store/concurrent-single-winner"]
    durability = asyncio.run(
        certify_atomic_store(
            AtomicStore,
            ConformanceMetadata(
                "test.candidate", "1", capabilities=("durable-reopen",)
            ),
        )
    )
    durability_results = {result.id: result.passed for result in durability.results}
    assert not durability_results["atomic-store/reopen-durability-claim"]


def test_conformance_detects_binding_substitution_retry_and_redaction_faults() -> None:
    class BrokenSigner(ConformantSigner):
        async def sign(self, request):
            return SigningResponse(
                "substituted",
                request.principal,
                request.transaction_digest,
                b"x" * 64,
            )

    class SubstitutingTransport(ByteTransport):
        async def exchange(self, packet, *, maximum_bytes, cancellation):
            if self.closed or cancellation.is_set():
                raise asyncio.CancelledError
            return b"substituted"

    async def scenario() -> None:
        binding = await certify_signer(BrokenSigner, METADATA)
        assert not next(
            result.passed
            for result in binding.results
            if result.id == "signer/request-binding"
        )
        substitution = await certify_byte_transport(
            lambda deliver: SubstitutingTransport(deliver), METADATA
        )
        assert not next(
            result.passed
            for result in substitution.results
            if result.id == "byte-transport/exact-bytes"
        )

        def retrying_factory(**options):
            tools = {}
            for name, handler in options["tools"].items():

                async def duplicate(arguments, context, handler=handler):
                    await handler(arguments, context)
                    return await handler(arguments, context)

                tools[name] = duplicate
            return mcp.development_provider(
                tools=tools,
                service=options.get("service", "development"),
                reconcile=options.get("reconcile"),
            )

        retry = await certify_mcp_provider(retrying_factory, METADATA)
        assert not next(
            result.passed for result in retry.results if result.id == "mcp/exact-call"
        )
        try:
            await certify_atomic_store(
                AtomicStore,
                ConformanceMetadata("secret\nmaterial", "1"),
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unbounded report metadata was accepted")

    asyncio.run(scenario())
