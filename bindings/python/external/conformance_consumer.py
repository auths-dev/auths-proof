from __future__ import annotations

import asyncio
from typing import Dict, Literal

from auths.adapters.reservations import ReservationRecord
from auths.testkit import run_reservation_store_conformance


_BACKINGS: Dict[str, Dict[str, bytes]] = {}


class AtomicStore:
    contract: Literal["atomic-reservation-store/2"] = "atomic-reservation-store/2"
    kind: str = "installed-memory-reference"
    durability: Literal["ephemeral"] = "ephemeral"

    def __init__(self, name: str) -> None:
        self._records = _BACKINGS.setdefault(name, {})

    async def reserve(
        self, record: ReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        if len(record.value) > 262_144:
            raise ValueError("bounded record")
        current = self._records.get(record.key)
        if current is None:
            self._records[record.key] = record.commitment
            return "acquired"
        return "exact-replay" if current == record.commitment else "conflict"

    async def aclose(self) -> None:
        return None


def open_store(name: str) -> AtomicStore:
    return AtomicStore(name)


async def main() -> None:
    report = await run_reservation_store_conformance(open_store)
    if not report.passed:
        raise SystemExit(f"installed conformance failed: {report.cases!r}")


asyncio.run(main())
