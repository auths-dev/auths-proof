"""The reference runner cannot touch a credential before exact authorization."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from auths.attempts import AttemptRecord, TerminalState
from auths.execution import (
    Attempted, NotExecuted, Observation, ProviderAccepted, ProviderUnknown, run_once,
)
from auths.self_hosted import ExactMcpTool, StringField
from auths.testkit import development_mcp_artifacts


@dataclass(frozen=True)
class Command:
    value: str


CONTRACT = ExactMcpTool(
    service="example-service", name="set_value_v1", command_type=Command,
    fields={"value": StringField(min_length=1, max_length=32)},
)


class MemoryAttempts:
    def __init__(self) -> None:
        self.claimed: bytes | None = None
        self.state: str | None = None

    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool:
        if self.claimed is not None:
            return False
        self.claimed = action_commitment
        self.state = "attempting"
        return True

    def read(self, action_commitment: bytes) -> AttemptRecord | None:
        return None

    def finish(self, action_commitment: bytes, state: TerminalState) -> AttemptRecord:
        self.state = state
        return AttemptRecord(action_commitment, "one", state)


class Adapter:
    def __init__(self, *, unknown: bool = False) -> None:
        self.credential_calls = 0
        self.invoke_calls = 0
        self.unknown = unknown

    def credential(self) -> str:
        self.credential_calls += 1
        return "not-a-real-token"

    async def invoke(self, command: Command, credential: str) -> ProviderAccepted[str] | ProviderUnknown:
        self.invoke_calls += 1
        assert command.value == "approved"
        assert credential == "not-a-real-token"
        return ProviderUnknown("provider.timeout") if self.unknown else ProviderAccepted("accepted")

    async def observe(self, command: Command) -> Observation:
        return "not_observed" if self.unknown else "observed"


@pytest.mark.asyncio
async def test_denial_and_replay_never_open_credential() -> None:
    artifacts = development_mcp_artifacts(
        service="example-service", name="set_value_v1", arguments={"value": "approved"},
    )
    other = development_mcp_artifacts(
        service="example-service", name="other_v1", arguments={"value": "approved"},
    )
    store = MemoryAttempts()
    adapter = Adapter()
    denied = await run_once(
        contract=CONTRACT, proof=other.proof, action=other.action,
        trusted_context=other.trusted_context, attempts=store,
        operation_key="one", adapter=adapter,
    )
    assert isinstance(denied, NotExecuted)
    assert adapter.credential_calls == 0
    assert store.claimed is None
    accepted = await run_once(
        contract=CONTRACT, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context, attempts=store,
        operation_key="one", adapter=adapter,
    )
    assert isinstance(accepted, Attempted)
    assert accepted.provider.kind == "accepted"
    replay = await run_once(
        contract=CONTRACT, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context, attempts=store,
        operation_key="one", adapter=adapter,
    )
    assert isinstance(replay, NotExecuted)
    assert replay.kind == "replay"
    assert adapter.credential_calls == 1
    assert adapter.invoke_calls == 1


@pytest.mark.asyncio
async def test_unknown_is_persisted_and_not_retried() -> None:
    artifacts = development_mcp_artifacts(
        service="example-service", name="set_value_v1", arguments={"value": "approved"},
    )
    store = MemoryAttempts()
    adapter = Adapter(unknown=True)
    result = await run_once(
        contract=CONTRACT, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context, attempts=store,
        operation_key="one", adapter=adapter,
    )
    assert isinstance(result, Attempted)
    assert result.provider.kind == "unknown"
    assert result.observation == "not_observed"
    assert store.state == "unknown"
    assert adapter.invoke_calls == 1
