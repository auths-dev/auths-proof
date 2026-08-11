"""Durable SQLite implementation of Auths runtime-store ports."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Literal, Mapping, Optional, Tuple, Union, cast

from auths.runtime import (
    BudgetReservation,
    ChallengeClaim,
    CommandState,
    LifecycleState,
    RuntimeKernel,
)


class SQLiteRuntimeStore:
    def __init__(
        self,
        path: Union[str, Path],
        *,
        budget_ceilings: Optional[Mapping[str, int]] = None,
    ) -> None:
        self._path = str(Path(path))
        ceilings = dict(budget_ceilings or {})
        if any(not key or value < 0 or value > (1 << 63) - 1 for key, value in ceilings.items()):
            raise ValueError("invalid budget ceiling")
        self._initialize(ceilings)

    async def issue(self, challenge: bytes, *, expires_at: int) -> bool:
        value = bytes(challenge)
        if len(value) != 32 or expires_at < 0:
            raise ValueError("invalid challenge")
        return await asyncio.to_thread(self._issue, value, expires_at)

    async def claim(self, challenge: bytes, *, now: int) -> ChallengeClaim:
        return await asyncio.to_thread(self._claim, bytes(challenge), now)

    async def reserve(
        self, action_commitment: bytes, algebra: str, amount: int
    ) -> BudgetReservation:
        commitment = bytes(action_commitment)
        if len(commitment) != 32 or not algebra or amount < 0 or amount > (1 << 63) - 1:
            raise ValueError("invalid budget reservation")
        return await asyncio.to_thread(self._reserve, commitment, algebra, amount)

    async def load(self, command_id: str) -> Optional[CommandState]:
        return await asyncio.to_thread(self._load, command_id)

    async def compare_and_swap(
        self, expected_revision: Optional[int], state: CommandState
    ) -> Literal["stored", "conflict"]:
        return await asyncio.to_thread(self._compare_and_swap, expected_revision, state)

    async def put(
        self, receipt_id: str, receipt: bytes
    ) -> Literal["stored", "duplicate"]:
        return await asyncio.to_thread(self._put, receipt_id, bytes(receipt))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self, ceilings: Mapping[str, int]) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS challenges (
                    challenge BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, claimed INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS budget_ceilings (
                    algebra TEXT PRIMARY KEY, ceiling INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS budget_reservations (
                    commitment BLOB PRIMARY KEY, algebra TEXT NOT NULL, amount INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY, action BLOB NOT NULL, authority BLOB NOT NULL,
                    context BLOB NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL,
                    idempotency_key TEXT NOT NULL, observed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY, receipt BLOB NOT NULL
                );
                """
            )
            for algebra, ceiling in ceilings.items():
                connection.execute(
                    "INSERT INTO budget_ceilings(algebra, ceiling) VALUES(?, ?) "
                    "ON CONFLICT(algebra) DO UPDATE SET ceiling=excluded.ceiling",
                    (algebra, ceiling),
                )

    def _issue(self, challenge: bytes, expires_at: int) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO challenges VALUES(?, ?, 0)",
                (challenge, expires_at),
            )
            return cursor.rowcount == 1

    def _claim(self, challenge: bytes, now: int) -> ChallengeClaim:
        if len(challenge) != 32 or now < 0:
            raise ValueError("invalid challenge claim")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT expires_at, claimed FROM challenges WHERE challenge=?", (challenge,)
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return "missing"
            expires_at, claimed = cast(Tuple[int, int], row)
            if now > expires_at:
                connection.execute("COMMIT")
                return "expired"
            if claimed:
                connection.execute("COMMIT")
                return "duplicate"
            connection.execute(
                "UPDATE challenges SET claimed=1 WHERE challenge=?", (challenge,)
            )
            connection.execute("COMMIT")
            return "claimed"

    def _reserve(
        self, commitment: bytes, algebra: str, amount: int
    ) -> BudgetReservation:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT algebra, amount FROM budget_reservations WHERE commitment=?",
                (commitment,),
            ).fetchone()
            if existing is not None:
                if cast(Tuple[str, int], existing) != (algebra, amount):
                    connection.execute("ROLLBACK")
                    raise ValueError("action commitment is bound to another reservation")
                connection.execute("COMMIT")
                return "duplicate"
            ceiling_row = connection.execute(
                "SELECT ceiling FROM budget_ceilings WHERE algebra=?", (algebra,)
            ).fetchone()
            if ceiling_row is None:
                connection.execute("COMMIT")
                return "unavailable"
            used_row = connection.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM budget_reservations WHERE algebra=?",
                (algebra,),
            ).fetchone()
            ceiling = cast(Tuple[int], ceiling_row)[0]
            used = cast(Tuple[int], used_row)[0]
            if not RuntimeKernel().additive_capacity(
                ceiling=ceiling, committed=used, active=0, requested=amount
            ):
                connection.execute("COMMIT")
                return "exhausted"
            connection.execute(
                "INSERT INTO budget_reservations VALUES(?, ?, ?)",
                (commitment, algebra, amount),
            )
            connection.execute("COMMIT")
            return "reserved"

    def _load(self, command_id: str) -> Optional[CommandState]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT command_id, action, authority, context, state, revision, "
                "idempotency_key, observed_at FROM commands WHERE command_id=?",
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        values = cast(Tuple[str, bytes, bytes, bytes, str, int, str, int], row)
        return CommandState(
            values[0],
            values[1],
            values[2],
            values[3],
            cast(LifecycleState, values[4]),
            values[5],
            values[6],
            values[7],
        )

    def _compare_and_swap(
        self, expected_revision: Optional[int], state: CommandState
    ) -> Literal["stored", "conflict"]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revision FROM commands WHERE command_id=?", (state.command_id,)
            ).fetchone()
            revision = None if row is None else cast(Tuple[int], row)[0]
            if revision != expected_revision:
                connection.execute("COMMIT")
                return "conflict"
            connection.execute(
                "INSERT INTO commands VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(command_id) DO UPDATE SET action=excluded.action, "
                "authority=excluded.authority, context=excluded.context, state=excluded.state, "
                "revision=excluded.revision, idempotency_key=excluded.idempotency_key, "
                "observed_at=excluded.observed_at",
                (
                    state.command_id,
                    state.action_commitment,
                    state.authority_commitment,
                    state.context_commitment,
                    state.state,
                    state.revision,
                    state.idempotency_key,
                    state.observed_at,
                ),
            )
            connection.execute("COMMIT")
            return "stored"

    def _put(self, receipt_id: str, receipt: bytes) -> Literal["stored", "duplicate"]:
        if not receipt_id or not receipt:
            raise ValueError("invalid receipt")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT receipt FROM receipts WHERE receipt_id=?", (receipt_id,)
            ).fetchone()
            if row is not None:
                if cast(Tuple[bytes], row)[0] != receipt:
                    connection.execute("ROLLBACK")
                    raise ValueError("receipt identifier is bound to different bytes")
                connection.execute("COMMIT")
                return "duplicate"
            connection.execute("INSERT INTO receipts VALUES(?, ?)", (receipt_id, receipt))
            connection.execute("COMMIT")
            return "stored"


__all__ = ["SQLiteRuntimeStore"]
