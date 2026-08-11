"""Transport and framework adapter boundaries without Auths semantics."""

from __future__ import annotations

import asyncio
from typing import Generic, Protocol, TypeVar, runtime_checkable

InputT = TypeVar("InputT", contravariant=True)
OutputT = TypeVar("OutputT", covariant=True)


@runtime_checkable
class IdentityTransport(Protocol):
    contract_version: int

    async def exchange(self, packet: bytes, *, maximum_bytes: int) -> bytes: ...


@runtime_checkable
class FrameworkAdapter(Protocol, Generic[InputT, OutputT]):
    contract_version: int

    async def handle(self, value: InputT) -> OutputT: ...


async def exchange_identity(
    transport: IdentityTransport,
    packet: bytes,
    *,
    maximum_bytes: int = 128 * 1024,
    timeout: float = 10.0,
) -> bytes:
    value = bytes(packet)
    if not value or maximum_bytes < 1 or maximum_bytes > 16 * 1024 * 1024:
        raise ValueError("identity exchange input is outside supported bounds")
    if len(value) > maximum_bytes or timeout <= 0 or timeout > 300:
        raise ValueError("identity exchange input is outside supported bounds")
    result = await asyncio.wait_for(
        transport.exchange(value, maximum_bytes=maximum_bytes), timeout
    )
    if type(result) is not bytes or not result or len(result) > maximum_bytes:
        raise ValueError("identity transport returned an invalid packet")
    return result


__all__ = ["FrameworkAdapter", "IdentityTransport", "exchange_identity"]
