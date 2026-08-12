from __future__ import annotations

import asyncio

from auths.testkit import ConformanceMetadata, certify_atomic_store


class AtomicStore:
    def __init__(self) -> None:
        self._records: dict[str, bytes] = {}

    async def reserve(self, record):
        if len(record.value) > 262_144:
            raise ValueError("bounded record")
        current = self._records.get(record.key)
        if current is None:
            self._records[record.key] = record.commitment
            return "acquired"
        return "exact-replay" if current == record.commitment else "conflict"

    async def aclose(self) -> None:
        pass


async def main() -> None:
    report = await certify_atomic_store(
        AtomicStore,
        ConformanceMetadata("installed.atomic-store", "1"),
    )
    if not report.passed:
        raise SystemExit(f"installed conformance failed: {report.results!r}")


asyncio.run(main())
