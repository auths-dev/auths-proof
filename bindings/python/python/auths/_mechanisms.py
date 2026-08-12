from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol


@dataclass(frozen=True)
class AtomicReservationRecord:
    key: str
    commitment: bytes
    value: bytes


class AtomicReservationStore(Protocol):
    async def reserve(
        self, record: AtomicReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]: ...

    async def aclose(self) -> None: ...

    async def reopen(self) -> AtomicReservationStore: ...
