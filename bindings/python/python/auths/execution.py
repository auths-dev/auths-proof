"""Conservative local execution ordering for self-hosted exact MCP commands.

The application owns its token and can bypass this runner. Provider outcomes
and observations are application claims, never Auths-qualified receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, fields as dataclass_fields
from typing import Any, Generic, Literal, Protocol, TypeVar, Union, cast

from .attempts import AttemptStore
from .self_hosted import AuthorizedCommand, ExactMcpTool, verify_command

CommandT = TypeVar("CommandT")
CommandContraT = TypeVar("CommandContraT", contravariant=True)
CredentialT = TypeVar("CredentialT")
ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class ProviderAccepted(Generic[ResultT]):
    value: ResultT
    kind: Literal["accepted"] = "accepted"


@dataclass(frozen=True)
class ProviderRejected:
    """Adapter attests a definite rejection with no applied effect."""

    code: str
    kind: Literal["rejected"] = "rejected"


@dataclass(frozen=True)
class ProviderUnknown:
    """Adapter cannot rule out an applied effect; never retry blindly."""

    code: str
    kind: Literal["unknown"] = "unknown"


ProviderOutcome = Union[ProviderAccepted[ResultT], ProviderRejected, ProviderUnknown]
Observation = Literal["observed", "not_observed", "unavailable"]


class ProviderAdapter(Protocol[CommandContraT, CredentialT, ResultT]):
    """App-owned exact request, credential, and read-only observation."""

    def credential(self) -> CredentialT: ...

    async def invoke(
        self, command: CommandContraT, credential: CredentialT
    ) -> ProviderOutcome[ResultT]: ...

    async def observe(self, command: CommandContraT) -> Observation: ...


@dataclass(frozen=True)
class NotExecuted:
    kind: Literal["denied", "indeterminate", "replay", "pre-entry-failed"]
    code: str


@dataclass(frozen=True)
class Attempted(Generic[CommandT, ResultT]):
    """Local outcome; the provider/observation fields are adapter claims."""

    authorization: AuthorizedCommand[CommandT]
    provider: ProviderOutcome[ResultT]
    observation: Observation | None


RunResult = Union[NotExecuted, Attempted[CommandT, ResultT]]


async def run_once(
    *,
    contract: ExactMcpTool[CommandT],
    proof: bytes,
    action: bytes,
    trusted_context: bytes,
    attempts: AttemptStore,
    operation_key: str,
    adapter: ProviderAdapter[CommandT, CredentialT, ResultT],
    expected_command: CommandT | None = None,
) -> RunResult[CommandT, ResultT]:
    """Verify, atomically claim, then and only then access the credential.

    A failure after entering `invoke` is conservatively unknown unless the
    adapter returns an explicit definite rejection. A crash leaves the claim
    in `attempting`; recovery must mark it unknown before observation.
    """
    verdict = verify_command(
        contract=contract, proof=proof, action=action,
        trusted_context=trusted_context,
    )
    if not isinstance(verdict, AuthorizedCommand):
        return NotExecuted(verdict.kind, verdict.code)
    if expected_command is not None and (
        type(expected_command) is not type(verdict.command)
        or any(
            type(getattr(expected_command, field.name))
            is not type(getattr(verdict.command, field.name))
            or getattr(expected_command, field.name) != getattr(verdict.command, field.name)
            for field in dataclass_fields(cast(Any, verdict.command))
        )
    ):
        return NotExecuted("denied", "self-hosted.expected-command-mismatch")
    commitment = verdict.action_commitment
    if not attempts.claim_once(commitment, operation_key):
        return NotExecuted("replay", "self-hosted.attempt-already-claimed")
    try:
        credential = adapter.credential()
    except Exception:
        attempts.finish(commitment, "rejected")
        return NotExecuted("pre-entry-failed", "self-hosted.credential-unavailable")
    try:
        provider = await adapter.invoke(verdict.command, credential)
    except BaseException:
        attempts.finish(commitment, "unknown")
        raise
    if isinstance(provider, ProviderAccepted):
        attempts.finish(commitment, "confirmed")
    elif isinstance(provider, ProviderRejected):
        attempts.finish(commitment, "rejected")
    elif isinstance(provider, ProviderUnknown):
        attempts.finish(commitment, "unknown")
    else:
        attempts.finish(commitment, "unknown")
        raise TypeError("provider adapter returned an invalid outcome")
    observation: Observation | None = None
    if isinstance(provider, ProviderAccepted):
        try:
            observation = await adapter.observe(verdict.command)
            if observation not in ("observed", "not_observed", "unavailable"):
                observation = "unavailable"
        except Exception:
            observation = "unavailable"
    return Attempted(verdict, provider, observation)


async def reconcile_read_only(
    *,
    authorization: AuthorizedCommand[CommandT],
    adapter: ProviderAdapter[CommandT, CredentialT, ResultT],
) -> Observation:
    """Observe a previously verified command; never repeat its provider write."""
    try:
        result = await adapter.observe(authorization.command)
        return result if result in ("observed", "not_observed", "unavailable") else "unavailable"
    except Exception:
        return "unavailable"


__all__ = [
    "Attempted", "NotExecuted", "Observation", "ProviderAccepted",
    "ProviderAdapter", "ProviderOutcome", "ProviderRejected", "ProviderUnknown",
    "RunResult", "reconcile_read_only", "run_once",
]
