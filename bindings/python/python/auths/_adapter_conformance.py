"""Synthetic, local conformance for application-owned provider adapters.

The kit exercises observable SDK ordering and conservative outcomes. It does
not qualify a developer's request mapping or any live provider behavior.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Generic, Literal, TypeVar

from .attempts import AttemptRecord, AttemptStore, TerminalState
from .execution import (
    Attempted,
    NotExecuted,
    Observation,
    ProviderAccepted,
    ProviderAdapter,
    ProviderOutcome,
    ProviderRejected,
    ProviderUnknown,
    RunResult,
    reconcile_read_only,
    run_once,
)
from .self_hosted import ExactMcpTool

if TYPE_CHECKING:
    from .testkit import ConformanceReport

CommandT = TypeVar("CommandT")
CredentialT = TypeVar("CredentialT")
ResultT = TypeVar("ResultT")
Scenario = Literal["accepted", "rejected", "unknown", "timeout", "observation-unavailable"]

_SCENARIOS: tuple[tuple[Scenario, str], ...] = (
    ("accepted", "authorized-one-write-and-replay"),
    ("accepted", "denied-before-credential"),
    ("accepted", "mutated-action-before-credential"),
    ("accepted", "invalid-trust-before-credential"),
    ("accepted", "credential-unavailable-before-provider"),
    ("accepted", "competing-claim"),
    ("accepted", "claim-failure-before-credential"),
    ("accepted", "finish-failure-after-provider-entry"),
    ("accepted", "replay-after-restart"),
    ("accepted", "post-entry-interruption-unknown"),
    ("rejected", "definite-no-effect-rejection"),
    ("unknown", "unknown-no-blind-retry"),
    ("timeout", "timeout-no-blind-retry"),
    ("observation-unavailable", "unavailable-observation"),
)
_MANDATORY_CASE_IDS = frozenset(case_id for _, case_id in _SCENARIOS)


class ScriptedProvider:
    """Test-only provider port; adapters must explicitly wire their fake I/O to it."""

    def __init__(self, scenario: Scenario, trace: list[str]) -> None:
        self.scenario = scenario
        self.trace = trace
        self.writes = 0
        self.reads = 0

    async def write(self, request: object, credential: object) -> ProviderOutcome[str]:
        """Record one bounded fake provider entry; never inspect credentials."""
        del request, credential
        self.trace.append("provider-write")
        self.writes += 1
        if self.scenario == "timeout":
            raise TimeoutError("synthetic provider timeout")
        if self.scenario == "unknown":
            return ProviderUnknown("synthetic-outcome-unknown")
        if self.scenario == "rejected":
            return ProviderRejected("synthetic-definite-no-effect")
        return ProviderAccepted("synthetic-accepted")

    async def read(self, request: object) -> Observation:
        del request
        self.trace.append("provider-read")
        self.reads += 1
        return "unavailable" if self.scenario == "observation-unavailable" else "observed"


class _MemoryAttempts(AttemptStore):
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.records: dict[bytes, AttemptRecord] = {}
        self.keys: set[str] = set()

    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool:
        self.trace.append("claim")
        if action_commitment in self.records or operation_key in self.keys:
            return False
        self.keys.add(operation_key)
        self.records[action_commitment] = AttemptRecord(action_commitment, operation_key, "attempting")
        return True

    def read(self, action_commitment: bytes) -> AttemptRecord | None:
        return self.records.get(action_commitment)

    def finish(self, action_commitment: bytes, state: TerminalState) -> AttemptRecord:
        previous = self.records[action_commitment]
        if previous.state != "attempting":
            raise ValueError("attempt already finished")
        record = AttemptRecord(action_commitment, previous.operation_key, state)
        self.records[action_commitment] = record
        return record


class _ObservedAdapter(Generic[CommandT, CredentialT, ResultT]):
    def __init__(
        self, adapter: ProviderAdapter[CommandT, CredentialT, ResultT], trace: list[str]
    ) -> None:
        self.adapter = adapter
        self.trace = trace

    def credential(self) -> CredentialT:
        self.trace.append("credential")
        return self.adapter.credential()

    async def invoke(
        self, command: CommandT, credential: CredentialT
    ) -> ProviderOutcome[ResultT]:
        self.trace.append("invoke")
        return await self.adapter.invoke(command, credential)

    async def observe(self, command: CommandT) -> Observation:
        self.trace.append("observe")
        return await self.adapter.observe(command)


class _InterruptedAdapter(_ObservedAdapter[CommandT, CredentialT, ResultT]):
    async def invoke(
        self, command: CommandT, credential: CredentialT
    ) -> ProviderOutcome[ResultT]:
        await super().invoke(command, credential)
        raise RuntimeError("synthetic post-entry interruption")


async def run_self_hosted_adapter_conformance(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    adapter_factory: Callable[[ScriptedProvider], ProviderAdapter[CommandT, CredentialT, ResultT]],
) -> ConformanceReport:
    """Exercise a developer adapter against local proof and scripted provider cases.

    A passing report is test evidence, never Auths qualification of provider
    semantics. Factory code runs only in this unprivileged local test process.
    """
    from .testkit import ConformanceCase, _report, development_mcp_artifacts

    artifacts = development_mcp_artifacts(
        service=contract.service, name=contract.name, arguments=contract.encode(command)
    )
    cases: list[ConformanceCase] = []

    async def exercise(scenario: Scenario, case_id: str) -> None:
        trace: list[str] = []
        provider = ScriptedProvider(scenario, trace)
        adapter = _ObservedAdapter(adapter_factory(provider), trace)
        attempts = _MemoryAttempts(trace)

        async def attempt(
            *,
            candidate_contract: ExactMcpTool[CommandT] = contract,
            candidate_action: bytes = artifacts.action,
            candidate_context: bytes = artifacts.trusted_context,
            candidate_adapter: ProviderAdapter[CommandT, CredentialT, ResultT] = adapter,
        ) -> RunResult[CommandT, ResultT]:
            return await run_once(
                contract=candidate_contract,
                proof=artifacts.proof,
                action=candidate_action,
                trusted_context=candidate_context,
                attempts=attempts,
                operation_key="synthetic-operation",
                adapter=candidate_adapter,
                expected_command=command,
            )

        try:
            if case_id == "denied-before-credential":
                other = ExactMcpTool(
                    service=contract.service, name="auths_test_wrong_tool",
                    command_type=contract.command_type, fields=contract.fields,
                )
                result = await attempt(candidate_contract=other)
                if not isinstance(result, NotExecuted) or result.kind != "denied":
                    raise ValueError("wrong exact tool was not denied")
                if provider.writes or "claim" in trace or "credential" in trace:
                    raise ValueError("denial reached claim or provider")
            elif case_id == "mutated-action-before-credential":
                altered = bytearray(artifacts.action)
                altered[-1] ^= 1
                try:
                    result = await attempt(candidate_action=bytes(altered))
                    if not isinstance(result, NotExecuted):
                        raise TypeError("mutated action produced an attempt")
                except (TypeError, ValueError):
                    pass
                if provider.writes or "claim" in trace or "credential" in trace:
                    raise ValueError("mutated action reached claim or provider")
            elif case_id == "invalid-trust-before-credential":
                try:
                    result = await attempt(candidate_context=b"not-a-trusted-context")
                    if not isinstance(result, NotExecuted):
                        raise TypeError("invalid trust produced an attempt")
                except (TypeError, ValueError):
                    pass
                if provider.writes or "claim" in trace or "credential" in trace:
                    raise ValueError("invalid trust reached claim or provider")
            elif case_id == "credential-unavailable-before-provider":
                class NoCredential:
                    def credential(self) -> CredentialT:
                        trace.append("credential")
                        raise RuntimeError("synthetic credential unavailable")

                    async def invoke(self, command: CommandT, credential: CredentialT) -> ProviderOutcome[ResultT]:
                        del command, credential
                        raise AssertionError("provider must not be entered")

                    async def observe(self, command: CommandT) -> Observation:
                        del command
                        raise AssertionError("observation must not be entered")

                result = await attempt(candidate_adapter=NoCredential())
                record = next(iter(attempts.records.values()), None)
                if (
                    not isinstance(result, NotExecuted) or result.kind != "pre-entry-failed"
                    or record is None or record.state != "rejected" or provider.writes
                ):
                    raise ValueError("credential failure crossed provider boundary")
            elif case_id == "competing-claim":
                results = await asyncio.gather(attempt(), attempt())
                if provider.writes != 1 or sum(isinstance(value, Attempted) for value in results) != 1:
                    raise ValueError("competing calls entered provider more than once")
            elif case_id == "claim-failure-before-credential":
                class ClaimFailure(_MemoryAttempts):
                    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool:
                        del action_commitment, operation_key
                        self.trace.append("claim")
                        raise RuntimeError("synthetic claim storage failure")

                attempts = ClaimFailure(trace)
                try:
                    await attempt()
                except RuntimeError:
                    pass
                else:
                    raise ValueError("claim failure was hidden")
                if provider.writes or "credential" in trace:
                    raise ValueError("claim failure reached credential or provider")
            elif case_id == "finish-failure-after-provider-entry":
                class FinishFailure(_MemoryAttempts):
                    def finish(self, action_commitment: bytes, state: TerminalState) -> AttemptRecord:
                        del action_commitment, state
                        self.trace.append("finish")
                        raise RuntimeError("synthetic finish storage failure")

                attempts = FinishFailure(trace)
                try:
                    await attempt()
                except RuntimeError:
                    pass
                else:
                    raise ValueError("finish failure was hidden")
                record = next(iter(attempts.records.values()), None)
                replay = await attempt()
                if (
                    provider.writes != 1 or record is None or record.state != "attempting"
                    or not isinstance(replay, NotExecuted) or replay.kind != "replay"
                ):
                    raise ValueError("finish failure permitted a second provider write")
            elif case_id == "replay-after-restart":
                result = await attempt()
                fresh_adapter = _ObservedAdapter(adapter_factory(provider), trace)
                replay = await attempt(candidate_adapter=fresh_adapter)
                if (
                    not isinstance(result, Attempted) or not isinstance(replay, NotExecuted)
                    or replay.kind != "replay" or provider.writes != 1
                ):
                    raise ValueError("fresh runner context repeated a claimed write")
                before = provider.writes
                await reconcile_read_only(authorization=result.authorization, adapter=fresh_adapter)
                if provider.writes != before:
                    raise ValueError("fresh runner reconciliation wrote to provider")
            elif case_id == "post-entry-interruption-unknown":
                interrupted = _InterruptedAdapter(adapter_factory(provider), trace)
                try:
                    await attempt(candidate_adapter=interrupted)
                except RuntimeError:
                    pass
                else:
                    raise ValueError("post-entry interruption was hidden")
                record = next(iter(attempts.records.values()), None)
                replay = await attempt()
                if (
                    provider.writes != 1 or record is None or record.state != "unknown"
                    or not isinstance(replay, NotExecuted) or replay.kind != "replay"
                ):
                    raise ValueError("post-entry interruption lost unknown state or retried")
            else:
                try:
                    result = await attempt()
                except (TimeoutError, RuntimeError):
                    if scenario != "timeout":
                        raise
                    result = None
                record = next(iter(attempts.records.values()), None)
                if provider.writes != 1 or record is None:
                    raise ValueError("adapter did not use the scripted provider once")
                if scenario == "accepted":
                    if not isinstance(result, Attempted) or not isinstance(result.provider, ProviderAccepted) or result.observation != "observed":
                        raise ValueError("accepted provider result was misclassified")
                    if trace.index("claim") > trace.index("credential") or trace.index("credential") > trace.index("provider-write"):
                        raise ValueError("credential or provider entry preceded claim")
                    replay = await attempt()
                    if not isinstance(replay, NotExecuted) or replay.kind != "replay" or provider.writes != 1:
                        raise ValueError("replay entered provider")
                elif scenario == "rejected":
                    if not isinstance(result, Attempted) or not (
                        (isinstance(result.provider, ProviderRejected) and record.state == "rejected")
                        or (isinstance(result.provider, ProviderUnknown) and record.state == "unknown")
                    ):
                        raise ValueError("synthetic no-effect result was overstated")
                elif scenario in ("unknown", "timeout"):
                    if record.state != "unknown" or (
                        result is not None and (
                            not isinstance(result, Attempted)
                            or not isinstance(result.provider, ProviderUnknown)
                        )
                    ):
                        raise ValueError("possible effect was not retained as unknown")
                    replay = await attempt()
                    if not isinstance(replay, NotExecuted) or replay.kind != "replay" or provider.writes != 1:
                        raise ValueError("unknown effect was retried")
                    if isinstance(result, Attempted):
                        before = provider.writes
                        await reconcile_read_only(authorization=result.authorization, adapter=adapter)
                        if provider.writes != before:
                            raise ValueError("reconciliation repeated a write")
                elif scenario == "observation-unavailable":
                    if not isinstance(result, Attempted) or result.observation == "observed":
                        raise ValueError("unavailable observation was overstated")
        except Exception as error:  # noqa: BLE001 -- report arbitrary consumer adapter failures
            cases.append(ConformanceCase(case_id, "failed", "contract-mismatch", type(error).__name__[:128]))
        else:
            cases.append(ConformanceCase(case_id, "passed", None, None))

    for scenario, case_id in _SCENARIOS:
        await exercise(scenario, case_id)
    return _report("self-hosted-provider-adapter/1", cases, "1")
