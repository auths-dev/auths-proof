from __future__ import annotations

from dataclasses import dataclass as _dataclass
from typing import Literal as _Literal, Protocol as _Protocol


@_dataclass(frozen=True)
class ReservationRecord:
    key: str
    commitment: bytes
    value: bytes


_ReservationDecision = _Literal["acquired", "exact-replay", "conflict"]


class ReservationStore(_Protocol):
    @property
    def contract(self) -> _Literal["atomic-reservation-store/2"]: ...
    @property
    def kind(self) -> str: ...
    @property
    def durability(self) -> _Literal["ephemeral", "single-machine-durable"]: ...
    async def reserve(self, record: ReservationRecord) -> _ReservationDecision: ...
    async def aclose(self) -> None: ...


__all__ = ["ReservationRecord", "ReservationStore"]
