"""Rust-owned execution lifecycle with replaceable state and effect ports."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import (
    Generic,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    TypeVar,
    Union,
    cast,
    runtime_checkable,
)

from ._native import (
    runtime_additive_capacity_v1,
    runtime_exclusive_capacity_v1,
    runtime_replay_v1,
    runtime_transition_v1,
)

LifecycleState = Literal[
    "decision-recorded",
    "reserved",
    "execution-intent-recorded",
    "executing",
    "committed",
    "released",
    "outcome-unknown",
    "reconciled-committed",
    "reconciled-released",
]
RuntimeOperation = Literal[
    "record-decision",
    "reserve",
    "record-execution-intent",
    "authorize-credential",
    "start-attempt",
    "mark-provider-call-entered",
    "commit",
    "release",
    "mark-outcome-unknown",
    "reconcile-effect",
    "reconcile-non-effect",
    "reconcile-inconclusive",
]
ReplayClass = Literal["absent", "exact-replay", "conflict"]
ChallengeClaim = Literal["claimed", "duplicate", "expired", "missing"]
BudgetReservation = Literal["reserved", "duplicate", "exhausted", "unavailable"]


@dataclass(frozen=True)
class TransitionGates:
    core_authorized: bool = False
    policy_eligible: bool = False
    configuration_matches: bool = False
    not_revoked: bool = False
    not_expired: bool = False
    capacity_available: bool = False
    execution_intent_present: bool = False
    credential_authorized: bool = False
    attempt_present: bool = False
    provider_call_entered: bool = False
    cancellation_allowed: bool = False
    definite_effect: bool = False
    definite_non_effect: bool = False
    reconciliation_fresh: bool = False
    reconciliation_matches: bool = False


@dataclass(frozen=True)
class RuntimeApplied:
    kind: Literal["applied", "observation-only"]
    state: LifecycleState


@dataclass(frozen=True)
class RuntimeRejected:
    kind: Literal["rejected"]
    code: str


RuntimeTransition = Union[RuntimeApplied, RuntimeRejected]


class RuntimeKernel:
    def transition(
        self,
        current: Optional[LifecycleState],
        operation: RuntimeOperation,
        gates: TransitionGates,
    ) -> RuntimeTransition:
        kind, value = runtime_transition_v1(
            current,
            operation,
            gates.core_authorized,
            gates.policy_eligible,
            gates.configuration_matches,
            gates.not_revoked,
            gates.not_expired,
            gates.capacity_available,
            gates.execution_intent_present,
            gates.credential_authorized,
            gates.attempt_present,
            gates.provider_call_entered,
            gates.cancellation_allowed,
            gates.definite_effect,
            gates.definite_non_effect,
            gates.reconciliation_fresh,
            gates.reconciliation_matches,
        )
        if kind == "rejected":
            if value is None:
                raise RuntimeError("native runtime omitted the rejection code")
            return RuntimeRejected("rejected", value)
        if value is None:
            raise RuntimeError("native runtime omitted the applied state")
        return RuntimeApplied(
            cast(Literal["applied", "observation-only"], kind),
            cast(LifecycleState, value),
        )

    def replay(self, record_exists: bool, commitments_equal: bool) -> ReplayClass:
        return cast(ReplayClass, runtime_replay_v1(record_exists, commitments_equal))

    def additive_capacity(
        self, *, ceiling: int, committed: int, active: int, requested: int
    ) -> bool:
        return runtime_additive_capacity_v1(ceiling, committed, active, requested)

    def exclusive_capacity(
        self, *, has_live_owner: bool, owner_is_exact_replay: bool
    ) -> bool:
        return runtime_exclusive_capacity_v1(has_live_owner, owner_is_exact_replay)


@dataclass(frozen=True)
class CommandState:
    command_id: str
    action_commitment: bytes
    authority_commitment: bytes
    context_commitment: bytes
    state: LifecycleState
    revision: int
    idempotency_key: str
    observed_at: int

    def __post_init__(self) -> None:
        for name in ("action_commitment", "authority_commitment", "context_commitment"):
            value = bytes(getattr(self, name))
            if len(value) != 32:
                raise ValueError(name.replace("_", " ") + " must contain 32 bytes")
            object.__setattr__(self, name, value)
        if not self.command_id or not self.idempotency_key or self.revision < 0:
            raise ValueError("invalid command state")


@runtime_checkable
class Clock(Protocol):
    def now(self) -> int: ...


@runtime_checkable
class ChallengeStore(Protocol):
    async def issue(self, challenge: bytes, *, expires_at: int) -> bool: ...
    async def claim(self, challenge: bytes, *, now: int) -> ChallengeClaim: ...


@runtime_checkable
class BudgetStore(Protocol):
    async def reserve(
        self, action_commitment: bytes, algebra: str, amount: int
    ) -> BudgetReservation: ...


@runtime_checkable
class ReceiptStore(Protocol):
    async def put(
        self, receipt_id: str, receipt: bytes
    ) -> Literal["stored", "duplicate"]: ...


@runtime_checkable
class CommandStore(Protocol):
    async def load(self, command_id: str) -> Optional[CommandState]: ...
    async def compare_and_swap(
        self, expected_revision: Optional[int], state: CommandState
    ) -> Literal["stored", "conflict"]: ...


CommandT = TypeVar("CommandT", contravariant=True)
ResultT = TypeVar("ResultT", covariant=True)


@runtime_checkable
class ClosedExecutor(Protocol, Generic[CommandT, ResultT]):
    async def execute(self, command: CommandT, *, idempotency_key: str) -> ResultT: ...


@runtime_checkable
class Reconciler(Protocol, Generic[ResultT]):
    async def reconcile(self, idempotency_key: str) -> Optional[ResultT]: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class InMemoryRuntimeStore(CommandStore, ReceiptStore, ChallengeStore, BudgetStore):
    def __init__(self, *, budget_ceilings: Optional[Mapping[str, int]] = None) -> None:
        self._commands: dict[str, CommandState] = {}
        self._receipts: dict[str, bytes] = {}
        self._challenges: dict[bytes, Tuple[int, bool]] = {}
        self._budget_ceilings = dict(budget_ceilings or {})
        self._budget_used: dict[str, int] = {}
        self._budget_reservations: dict[bytes, Tuple[str, int]] = {}
        self._lock = asyncio.Lock()

    async def issue(self, challenge: bytes, *, expires_at: int) -> bool:
        value = bytes(challenge)
        if len(value) != 32 or expires_at < 0:
            raise ValueError("invalid challenge")
        async with self._lock:
            if value in self._challenges:
                return False
            self._challenges[value] = (expires_at, False)
            return True

    async def claim(self, challenge: bytes, *, now: int) -> ChallengeClaim:
        value = bytes(challenge)
        async with self._lock:
            record = self._challenges.get(value)
            if record is None:
                return "missing"
            expires_at, claimed = record
            if now > expires_at:
                return "expired"
            if claimed:
                return "duplicate"
            self._challenges[value] = (expires_at, True)
            return "claimed"

    async def reserve(
        self, action_commitment: bytes, algebra: str, amount: int
    ) -> BudgetReservation:
        commitment = bytes(action_commitment)
        if len(commitment) != 32 or not algebra or amount < 0:
            raise ValueError("invalid budget reservation")
        async with self._lock:
            existing = self._budget_reservations.get(commitment)
            if existing is not None:
                if existing != (algebra, amount):
                    raise ValueError(
                        "action commitment is bound to another reservation"
                    )
                return "duplicate"
            ceiling = self._budget_ceilings.get(algebra)
            if ceiling is None:
                return "unavailable"
            used = self._budget_used.get(algebra, 0)
            if not RuntimeKernel().additive_capacity(
                ceiling=ceiling, committed=used, active=0, requested=amount
            ):
                return "exhausted"
            self._budget_used[algebra] = used + amount
            self._budget_reservations[commitment] = (algebra, amount)
            return "reserved"

    async def load(self, command_id: str) -> Optional[CommandState]:
        async with self._lock:
            return self._commands.get(command_id)

    async def compare_and_swap(
        self, expected_revision: Optional[int], state: CommandState
    ) -> Literal["stored", "conflict"]:
        async with self._lock:
            current = self._commands.get(state.command_id)
            revision = None if current is None else current.revision
            if revision != expected_revision:
                return "conflict"
            self._commands[state.command_id] = state
            return "stored"

    async def put(
        self, receipt_id: str, receipt: bytes
    ) -> Literal["stored", "duplicate"]:
        value = bytes(receipt)
        async with self._lock:
            current = self._receipts.get(receipt_id)
            if current is not None:
                if current != value:
                    raise ValueError("receipt identifier is bound to different bytes")
                return "duplicate"
            self._receipts[receipt_id] = value
            return "stored"

    async def snapshot(self) -> Mapping[str, CommandState]:
        async with self._lock:
            return MappingProxyType(dict(self._commands))


__all__ = [
    "BudgetStore",
    "BudgetReservation",
    "ChallengeStore",
    "ChallengeClaim",
    "Clock",
    "ClosedExecutor",
    "CommandState",
    "CommandStore",
    "InMemoryRuntimeStore",
    "LifecycleState",
    "ReceiptStore",
    "Reconciler",
    "ReplayClass",
    "RuntimeApplied",
    "RuntimeKernel",
    "RuntimeOperation",
    "RuntimeRejected",
    "RuntimeTransition",
    "SystemClock",
    "TransitionGates",
]
