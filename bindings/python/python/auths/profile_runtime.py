"""Narrow generated-profile extension ABI.

This module is public for generated packages, not an arbitrary execution API.
Only immutable descriptors produced by the Auths generator are accepted.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import dataclasses
import hashlib
import os
import re
import stat
from dataclasses import InitVar, dataclass
from datetime import timedelta
from typing import Any, Awaitable, Dict, Generic, Literal, Mapping, Optional, Tuple, Type, TypeVar, Union, final

from ._cbor import decode as _decode
from ._cbor import encode as _encode
from ._public import (
    EffectState, EnteredBoundaries, ErrorInfo, RecommendedAction, RetryClass,
    parse_error_info, parse_portable_receipt,
)
from ._session import (
    Client, OperationMetadata, OperationOptions, OperationState, RecoveryHandle, RecoveryOptions,
    _PostWriteRequestError, _ProfileInvocationTicket, _conflict_error, _denied_error,
    _is_post_write_request_error,
    _not_applied_error, _partial_error, _recovery_required_error,
    _report_qualification_cancellation, _report_qualification_result,
    _receipt_integrity_error,
    _unavailable_error,
)

_T = TypeVar("_T")
_P = TypeVar("_P")
_G = TypeVar("_G")

PROFILE_CLIENT_RUNTIME = "auths.profile-client-runtime/1"
_OUTCOME_TOKEN = object()
_Completion = Literal["fresh", "replayed", "reconciled"]
_QUALIFICATION_RESULT: contextvars.ContextVar[Optional[Tuple[object, bytes, bytes]]] = (
    contextvars.ContextVar("auths_qualification_result", default=None)
)
_QUALIFICATION_CANCELLATION: contextvars.ContextVar[Optional[Tuple[object, bytes]]] = (
    contextvars.ContextVar("auths_qualification_cancellation", default=None)
)

__all__ = [
    "PROFILE_CLIENT_RUNTIME",
    "BoundProfile",
    "Completed",
    "Conflict",
    "Denied",
    "NotApplied",
    "Partial",
    "ProfileDescriptor",
    "ProfileFile",
    "ProfileOutcome",
    "RecoveryRequired",
    "ReceiptIntegrityFailed",
    "Unavailable",
    "bind_profile",
]


@dataclass(frozen=True)
class ProfileDescriptor:
    profile_id: str
    version: int
    collection_route: str
    profile_client_runtime: str
    runtime_contract_digest: bytes
    error_projection_digest: bytes
    preparation_evidence: Optional[str]
    request_bytes: int
    response_bytes: int
    execution_milliseconds: int
    receipt_count: int
    receipt_bytes: int
    profile_api: Mapping[str, object]
    input_type: str
    success_type: str
    partial_type: Optional[str]
    progress_type: Optional[str]


@final
class ProfileFile:
    """A bounded generated-profile input sourced from one local file.

    Generated clients accept this only for byte fields whose profile schema
    explicitly declares ``sourceConvenience: \"file\"``. The path is kept out
    of reprs and error messages; the bytes are read immediately before the
    profile request is encoded.
    """

    __slots__ = ("_path",)
    _path: str

    def __init__(self, path: Union[str, os.PathLike[str]]) -> None:
        selected = os.fspath(path)
        if not isinstance(selected, str) or not selected:
            raise TypeError("profile file path must be non-empty text")
        object.__setattr__(self, "_path", selected)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ProfileFile is immutable")

    def __repr__(self) -> str:
        return "ProfileFile(<redacted>)"

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ProfileFile is sealed")


@dataclass(frozen=True)
class _SealedOutcome:
    _token: InitVar[object]

    def __post_init__(self, token: object) -> None:
        if token is not _OUTCOME_TOKEN:
            raise TypeError("profile outcomes are sealed")


@dataclass(frozen=True)
class Completed(_SealedOutcome, Generic[_T]):
    kind: Literal["completed"]
    value: _T


@dataclass(frozen=True)
class Denied(_SealedOutcome):
    kind: Literal["denied"]
    operation_id: str
    issue: ErrorInfo
    receipt_ids: Tuple[str, ...]


@dataclass(frozen=True)
class Unavailable(_SealedOutcome):
    kind: Literal["unavailable"]
    operation_id: Optional[str]
    issue: ErrorInfo
    receipt_ids: Tuple[str, ...]


@dataclass(frozen=True)
class Conflict(_SealedOutcome):
    kind: Literal["conflict"]
    operation_id: str
    issue: ErrorInfo
    recovery: RecoveryHandle
    receipt_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NotApplied(_SealedOutcome):
    kind: Literal["not-applied"]
    operation_id: str
    issue: ErrorInfo
    receipt_ids: Tuple[str, ...]
    completion: _Completion


@dataclass(frozen=True)
class Partial(_SealedOutcome, Generic[_P]):
    kind: Literal["partial"]
    operation_id: str
    issue: ErrorInfo
    details: _P
    receipt_ids: Tuple[str, ...]
    completion: _Completion


@dataclass(frozen=True)
class RecoveryRequired(_SealedOutcome, Generic[_G]):
    kind: Literal["recovery-required"]
    operation_id: str
    issue: ErrorInfo
    recovery: RecoveryHandle
    receipt_ids: Tuple[str, ...]
    progress: Optional[_G]


@dataclass(frozen=True)
class ReceiptIntegrityFailed(_SealedOutcome):
    kind: Literal["receipt-integrity-failed"]
    operation_id: str
    issue: ErrorInfo
    state: OperationState
    effect: EffectState
    terminal: bool
    receipt_ids: Tuple[str, ...]


ProfileOutcome = Union[
    Completed[_T], Denied, Unavailable, Conflict, NotApplied,
    Partial[_P], RecoveryRequired[_G], ReceiptIntegrityFailed,
]


class BoundProfile(Generic[_T, _P, _G]):
    def __init__(
        self,
        client: Client,
        descriptor: ProfileDescriptor,
        connection: Optional[str],
        input_class: Type[object],
        success_class: Type[_T],
        partial_class: Optional[Type[_P]] = None,
        progress_class: Optional[Type[_G]] = None,
    ) -> None:
        if connection is not None and not _lower_token(connection, 64):
            raise ValueError("connection alias is outside the closed grammar")
        if descriptor.profile_client_runtime != PROFILE_CLIENT_RUNTIME:
            raise ValueError("generated profile client runtime mismatch")
        _bounded_integer(descriptor.request_bytes, 1, 64 * 1024 * 1024, "request_bytes")
        _bounded_integer(descriptor.response_bytes, 1, 64 * 1024 * 1024, "response_bytes")
        _bounded_integer(descriptor.execution_milliseconds, 1, 300_000, "execution_milliseconds")
        _bounded_integer(descriptor.receipt_count, 1, 64, "receipt_count")
        _bounded_integer(descriptor.receipt_bytes, 1, descriptor.response_bytes, "receipt_bytes")
        if descriptor.preparation_evidence not in (None, "protected-lease"):
            raise ValueError("unknown preparation evidence contract")
        self._client = client
        self._descriptor = descriptor
        self._connection = connection
        self._input_class = input_class
        self._success_class = success_class
        self._partial_class = partial_class
        self._progress_class = progress_class

    async def invoke(
        self, value: object, options: Optional[OperationOptions] = None
    ) -> _T:
        outcome = await self.invoke_outcome(value, options)
        if isinstance(outcome, Completed):
            return outcome.value
        _raise_outcome(outcome)
        raise AssertionError("unreachable")

    async def invoke_outcome(
        self, value: object, options: Optional[OperationOptions] = None
    ) -> ProfileOutcome[_T, _P, _G]:
        result_token = _QUALIFICATION_RESULT.set(None)
        cancellation_token = _QUALIFICATION_CANCELLATION.set(None)
        try:
            outcome = await self._invoke_outcome_inner(value, options)
            retained = _QUALIFICATION_RESULT.get()
            if retained is not None and retained[0] is outcome:
                await _complete_qualification_handoff(_report_qualification_result(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1], retained[2],
                ))
            return outcome
        except BaseException as error:
            retained = _QUALIFICATION_CANCELLATION.get()
            if retained is not None and retained[0] is error:
                await _complete_qualification_handoff(_report_qualification_cancellation(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1],
                ))
            raise
        finally:
            _QUALIFICATION_RESULT.reset(result_token)
            _QUALIFICATION_CANCELLATION.reset(cancellation_token)

    async def _qualification_invoke_encoded_outcome(
        self, encoded_input: bytes, options: Optional[OperationOptions] = None,
    ) -> ProfileOutcome[_T, _P, _G]:
        """Exercise a rejected wire input in the protected qualification runtime.

        This is deliberately private and is available only while the installed
        SDK is connected to the Linux qualification result handoff.  It lets
        the common hostile-input runner prove agent-side canonicality and
        profile-bound checks without weakening the generated public API.
        """
        if self._client._qualification_socket_for(
            self._descriptor.profile_id, self._descriptor.version,
        ) is None:
            raise ValueError("encoded qualification input is outside qualification")
        if not isinstance(encoded_input, bytes) or not 1 <= len(encoded_input) <= 16_777_216:
            raise ValueError("encoded qualification input is outside its hard bound")
        result_token = _QUALIFICATION_RESULT.set(None)
        cancellation_token = _QUALIFICATION_CANCELLATION.set(None)
        try:
            selected = _profile_operation_options(
                options, self._descriptor.execution_milliseconds,
            )
            deadline = asyncio.get_running_loop().time() + selected.timeout.total_seconds()
            outcome = await self._invoke_leader(
                os.urandom(16), selected.idempotency_key, encoded_input,
                deadline - selected.recovery_wait.total_seconds(), deadline,
                selected.recovery_wait, None,
            )
            retained = _QUALIFICATION_RESULT.get()
            if retained is not None and retained[0] is outcome:
                await _complete_qualification_handoff(_report_qualification_result(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1], retained[2],
                ))
            return outcome
        except BaseException as error:
            retained = _QUALIFICATION_CANCELLATION.get()
            if retained is not None and retained[0] is error:
                await _complete_qualification_handoff(_report_qualification_cancellation(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1],
                ))
            raise
        finally:
            _QUALIFICATION_RESULT.reset(result_token)
            _QUALIFICATION_CANCELLATION.reset(cancellation_token)

    async def _invoke_outcome_inner(
        self, value: object, options: Optional[OperationOptions],
    ) -> ProfileOutcome[_T, _P, _G]:
        descriptor = self._descriptor
        selected = _profile_operation_options(options, descriptor.execution_milliseconds)
        deadline = asyncio.get_running_loop().time() + selected.timeout.total_seconds()
        advancement_deadline = deadline - selected.recovery_wait.total_seconds()
        capability = self._client._profile_capability(descriptor.profile_id, descriptor.version)
        if (
            capability.runtime_digest != descriptor.runtime_contract_digest
            or capability.error_digest != descriptor.error_projection_digest
            or capability.operation_protocol != "auths.profile-operation/1"
        ):
            raise _unavailable_error(
                _local_issue("client.profile-contract-mismatch", "profile contract digest mismatch"),
                None, (),
            )
        encoded_input = _encode_profile_input(
            descriptor.profile_api, descriptor.input_type, value, self._input_class
        )
        if not 1 <= len(encoded_input) <= descriptor.request_bytes:
            raise ValueError("profile input is outside the declared bound")
        if selected.idempotency_key is None or not isinstance(self._client, Client):
            return await self._invoke_leader(
                os.urandom(16), selected.idempotency_key, encoded_input, advancement_deadline,
                deadline, selected.recovery_wait, None,
            )
        fingerprint = hashlib.sha256(_encode({1: encoded_input, 2: self._connection})).digest()
        scope = f"{descriptor.profile_id}/{descriptor.version}:{selected.idempotency_key}"
        while True:
            ticket = self._client._begin_profile_invocation(
                scope, fingerprint, os.urandom(16),
            )
            if ticket.role in ("follower", "observer"):
                try:
                    identity, cancellation_observed = await _wait_coordinated_identity(ticket, deadline)
                    if identity is None:
                        if cancellation_observed:
                            raise asyncio.CancelledError
                        continue
                    outcome = await self._observe_coordinated(ticket, identity, deadline)
                    _QUALIFICATION_RESULT.set(None)
                    return outcome
                finally:
                    self._client._finish_profile_invocation(ticket)
            conflict_operation = None
            if ticket.role == "conflict-probe":
                identity, cancellation_observed = await _wait_coordinated_identity(ticket, deadline)
                if identity is None:
                    self._client._finish_profile_invocation(ticket)
                    if cancellation_observed:
                        raise asyncio.CancelledError
                    continue
                conflict_operation = identity[1]
            return await self._invoke_leader(
                ticket.request_id, selected.idempotency_key, encoded_input,
                advancement_deadline, deadline, selected.recovery_wait, ticket,
                conflict_operation,
            )

    async def _invoke_leader(
        self,
        request_id: bytes,
        idempotency_key: Optional[str],
        encoded_input: bytes,
        advancement_deadline: float,
        deadline: float,
        recovery_wait: timedelta,
        ticket: Optional[_ProfileInvocationTicket],
        conflict_operation: Optional[str] = None,
    ) -> ProfileOutcome[_T, _P, _G]:
        try:
            coordination = ticket if ticket is not None and ticket.role == "conflict-probe" else None
            evidence_handle, replayed_outcome, cancellation = await self._acquire_preparation_evidence(
                request_id, idempotency_key, encoded_input,
                advancement_deadline, deadline, coordination,
            )
            if replayed_outcome is not None:
                wire = _profile_outcome(replayed_outcome, request_id, self._descriptor)
                self._publish_initial(ticket, wire)
                if ticket is not None and ticket.role == "conflict-probe":
                    return self._project_conflict_probe(wire, conflict_operation)
                if cancellation is None:
                    return await self._drive_outcome(
                        request_id, wire, advancement_deadline, deadline, recovery_wait,
                    )
                return await self._drive_cancelled_outcome(
                    request_id, wire, deadline, recovery_wait, cancellation,
                )
            if cancellation is not None:
                if evidence_handle is not None:
                    evidence_handle[:] = b"\x00" * len(evidence_handle)
                raise cancellation
            prepare = _encode({
                1: 1, 2: request_id, 3: idempotency_key,
                4: self._descriptor.runtime_contract_digest, 5: encoded_input,
                6: self._connection,
                7: bytes(evidence_handle) if evidence_handle is not None else None,
            })
            if evidence_handle is not None:
                evidence_handle[:] = b"\x00" * len(evidence_handle)
            cancellation = None
            try:
                raw = await _profile_request(
                    self._client, "POST", self._descriptor.collection_route, prepare,
                    _remaining_timeout(advancement_deadline), coordination,
                )
                wire = _profile_outcome(raw, request_id, self._descriptor)
            except BaseException as error:
                if not _is_post_write_request_error(error) and not isinstance(error, ValueError):
                    raise
                if isinstance(error, _PostWriteRequestError) and isinstance(
                    error.cause, (asyncio.CancelledError, asyncio.TimeoutError),
                ):
                    cancellation = error.cause
                raw = await _profile_request(
                    self._client, "POST", self._descriptor.collection_route, prepare,
                    _remaining_timeout(deadline), coordination,
                )
                wire = _profile_outcome(raw, request_id, self._descriptor)
            self._publish_initial(ticket, wire)
            if ticket is not None and ticket.role == "conflict-probe":
                return self._project_conflict_probe(wire, conflict_operation)
            if cancellation is None:
                return await self._drive_outcome(
                    request_id, wire, advancement_deadline, deadline, recovery_wait,
                )
            return await self._drive_cancelled_outcome(
                request_id, wire, deadline, recovery_wait, cancellation,
            )
        finally:
            if ticket is not None:
                self._client._finish_profile_invocation(ticket)

    def _project_conflict_probe(
        self, wire: Dict[int, Any], expected_operation: Optional[str],
    ) -> ProfileOutcome[_T, _P, _G]:
        if wire.get(2) not in ("conflict", "receipt-integrity-failed") or expected_operation is None:
            raise ValueError("changed idempotency intent did not return Conflict")
        operation = _operation_id(wire.get(4))
        if operation != expected_operation:
            raise ValueError("idempotency conflict changed operation identity")
        _bind_recovery_response(
            wire, (expected_operation, self._descriptor.profile_id, self._descriptor.version),
            self._descriptor,
        )
        projected = self._project_and_retain(wire)
        if isinstance(projected, Conflict) and (
            projected.issue.code != "operation.idempotency-conflict"
            or projected.issue.correlation_id != expected_operation
            or projected.issue.execution_reference != expected_operation
        ):
            raise ValueError("changed idempotency intent returned an unrelated conflict")
        return projected

    def _publish_initial(
        self, ticket: Optional[_ProfileInvocationTicket], wire: Dict[int, Any],
    ) -> None:
        if ticket is None or ticket.role != "leader":
            return
        raw_operation = wire.get(4)
        if not isinstance(raw_operation, str):
            self._client._publish_profile_invocation(ticket, None)
            return
        operation = _operation_id(raw_operation)
        _bind_recovery_response(
            wire, (operation, self._descriptor.profile_id, self._descriptor.version), self._descriptor,
        )
        self._client._publish_profile_invocation(ticket, operation, _encode(wire))

    async def _observe_coordinated(
        self, ticket: _ProfileInvocationTicket, identity: Tuple[bytes, str, bytes], deadline: float,
    ) -> ProfileOutcome[_T, _P, _G]:
        request_id, operation, initial_bytes = identity
        expected = (operation, self._descriptor.profile_id, self._descriptor.version)
        fallback: Optional[Tuple[bytes, Tuple[str, ...]]] = None
        if initial_bytes:
            try:
                initial = _profile_outcome(initial_bytes, request_id, self._descriptor)
                if _operation_id(initial.get(4)) != operation:
                    raise ValueError("coordinated snapshot changed operation identity")
                if initial.get(2) == "ready":
                    recovery = _bytes(initial.get(7)); _assert_recovery_identity(recovery, expected)
                    fallback = (recovery, ())
                    commitment = initial.get(5)
                    if not isinstance(commitment, bytes) or len(commitment) != 32:
                        raise ValueError("invalid preparation commitment")
                    _optional_text(initial.get(8))
                    fallback = (recovery, _receipt_ids([initial.get(6)], self._descriptor))
                elif initial.get(2) == "in-progress":
                    recovery = _bytes(initial.get(8)); _assert_recovery_identity(recovery, expected)
                    fallback = (recovery, ())
                    _validate_in_progress(initial, self._descriptor)
                    receipts = _receipt_id_list(initial.get(7), self._descriptor.receipt_count)
                    if initial.get(6) == "possible":
                        return _recovery_required(operation, RecoveryHandle.from_bytes(recovery), receipts)
                    fallback = (recovery, receipts)
                else:
                    return self._project_and_retain(_coordinated_replay_wire(initial))
            except (TypeError, ValueError):
                # Preserve the durable operation identity and ask the fixed
                # status route instead of treating an undecodable DTO as null.
                pass
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                if fallback is None:
                    raise asyncio.TimeoutError("profile operation deadline exceeded")
                return _recovery_required(operation, RecoveryHandle.from_bytes(fallback[0]), fallback[1])
            try:
                raw = await asyncio.wait_for(
                    self._client._profile_invocation_status(
                        ticket, f"{self._descriptor.collection_route}/{operation}",
                        timedelta(seconds=min(1.0, remaining)),
                    ), timeout=remaining,
                )
            except (
                asyncio.CancelledError, asyncio.TimeoutError, OSError, ValueError,
                _PostWriteRequestError,
            ):
                _consume_current_cancellation()
                if fallback is None:
                    continue
                return _recovery_required(operation, RecoveryHandle.from_bytes(fallback[0]), fallback[1])
            try:
                wire = _profile_outcome(raw, request_id, self._descriptor)
                if _operation_id(wire.get(4)) != operation:
                    raise ValueError("coordinated status changed operation identity")
                _bind_recovery_response(wire, expected, self._descriptor)
                if wire.get(2) == "ready":
                    recovery = _bytes(wire.get(7))
                    _assert_recovery_identity(recovery, expected)
                    fallback = (recovery, ())
                    commitment = wire.get(5)
                    if not isinstance(commitment, bytes) or len(commitment) != 32:
                        raise ValueError("invalid preparation commitment")
                    _optional_text(wire.get(8))
                    fallback = (recovery, _receipt_ids([wire.get(6)], self._descriptor))
                elif wire.get(2) == "in-progress":
                    recovery = _bytes(wire.get(8))
                    _assert_recovery_identity(recovery, expected)
                    fallback = (recovery, ())
                    _validate_in_progress(wire, self._descriptor)
                    receipts = _receipt_id_list(wire.get(7), self._descriptor.receipt_count)
                    if wire.get(6) == "possible":
                        return _recovery_required(operation, RecoveryHandle.from_bytes(recovery), receipts)
                    fallback = (recovery, receipts)
                else:
                    return self._project_and_retain(_coordinated_replay_wire(wire))
            except (TypeError, ValueError):
                if fallback is None:
                    raise
                return _recovery_required(operation, RecoveryHandle.from_bytes(fallback[0]), fallback[1])
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                if fallback is None:
                    raise asyncio.TimeoutError("profile operation deadline exceeded")
                return _recovery_required(operation, RecoveryHandle.from_bytes(fallback[0]), fallback[1])
            await asyncio.sleep(min(0.025, remaining))

    async def _drive_outcome(
        self,
        request_id: bytes,
        initial: Dict[int, Any],
        advancement_deadline: float,
        deadline: float,
        recovery_wait: timedelta,
    ) -> ProfileOutcome[_T, _P, _G]:
        descriptor = self._descriptor
        wire = initial
        if wire.get(2) == "ready":
            operation = _operation_id(wire.get(4))
            prepared_recovery = _bytes(wire.get(7))
            _assert_recovery_identity(
                prepared_recovery, (operation, descriptor.profile_id, descriptor.version),
            )
            try:
                commitment = wire.get(5)
                if not isinstance(commitment, bytes) or len(commitment) != 32:
                    raise ValueError("invalid preparation commitment")
                _optional_text(wire.get(8))
                prepared_receipts = _receipt_ids([wire.get(6)], descriptor)
            except (TypeError, ValueError):
                return _recovery_required(
                    operation, RecoveryHandle.from_bytes(prepared_recovery), (),
                )
            execute = _encode({1: 1, 2: request_id, 3: operation, 4: commitment})
            recovery_deadline = min(
                deadline,
                asyncio.get_running_loop().time() + recovery_wait.total_seconds(),
            )
            try:
                raw = await self._client._request(
                    "POST", f"{descriptor.collection_route}/{operation}/execute",
                    execute, _remaining_timeout(advancement_deadline),
                )
                wire = _profile_outcome(raw, request_id, descriptor)
            except BaseException:
                return await self._recover_within_deadline(
                    request_id, operation, prepared_recovery,
                    prepared_receipts, recovery_deadline,
                )
            if wire.get(2) == "in-progress":
                return await self._wait_for_accepted_execute(
                    request_id, operation, wire, prepared_recovery,
                    prepared_receipts, recovery_deadline,
                )
        if wire.get(2) == "in-progress":
            operation = _operation_id(wire.get(4))
            recovery = _bytes(wire.get(8))
            _assert_recovery_identity(
                recovery, (operation, descriptor.profile_id, descriptor.version),
            )
            try:
                _validate_in_progress(wire, descriptor)
                receipts = _receipt_id_list(wire.get(7), descriptor.receipt_count)
            except (TypeError, ValueError):
                return _recovery_required(operation, RecoveryHandle.from_bytes(recovery), ())
            return await self._wait_for_accepted_execute(
                request_id, operation, wire, recovery, receipts,
                min(
                    deadline,
                    asyncio.get_running_loop().time() + recovery_wait.total_seconds(),
                ),
            )
        return self._project_and_retain(wire)

    async def _drive_cancelled_outcome(
        self,
        request_id: bytes,
        wire: Dict[int, Any],
        deadline: float,
        recovery_wait: timedelta,
        cancellation: BaseException,
    ) -> ProfileOutcome[_T, _P, _G]:
        projected_here = False
        recovery_deadline = min(
            deadline,
            asyncio.get_running_loop().time() + recovery_wait.total_seconds(),
        )
        if wire.get(2) == "ready":
            operation = _operation_id(wire.get(4))
            recovery = _bytes(wire.get(7))
            _assert_recovery_identity(
                recovery, (operation, self._descriptor.profile_id, self._descriptor.version),
            )
            receipts: Tuple[str, ...] = ()
            try:
                commitment = wire.get(5)
                if not isinstance(commitment, bytes) or len(commitment) != 32:
                    raise ValueError("invalid preparation commitment")
                _optional_text(wire.get(8))
                receipts = _receipt_ids([wire.get(6)], self._descriptor)
            except (TypeError, ValueError):
                pass
            outcome = await self._recover_within_deadline(
                request_id, operation, recovery, receipts, recovery_deadline,
            )
        elif wire.get(2) == "in-progress":
            operation = _operation_id(wire.get(4))
            recovery = _bytes(wire.get(8))
            _assert_recovery_identity(
                recovery, (operation, self._descriptor.profile_id, self._descriptor.version),
            )
            receipts = ()
            try:
                _validate_in_progress(wire, self._descriptor)
                receipts = _receipt_id_list(wire.get(7), self._descriptor.receipt_count)
            except (TypeError, ValueError):
                pass
            outcome = await self._recover_within_deadline(
                request_id,
                operation,
                recovery,
                receipts,
                recovery_deadline,
            )
        else:
            outcome = self._project(wire)
            projected_here = True
        if isinstance(
            outcome,
            (Completed, Partial, Conflict, RecoveryRequired, ReceiptIntegrityFailed),
        ):
            if projected_here:
                self._retain_projected_result(outcome, wire)
            return outcome
        if not isinstance(cancellation, asyncio.CancelledError):
            if projected_here:
                self._retain_projected_result(outcome, wire)
            return outcome
        _QUALIFICATION_RESULT.set(None)
        _QUALIFICATION_CANCELLATION.set((cancellation, request_id))
        raise cancellation

    async def _acquire_preparation_evidence(
        self,
        request_id: bytes,
        idempotency_key: Optional[str],
        encoded_input: bytes,
        advancement_deadline: float,
        deadline: float,
        coordination: Optional[_ProfileInvocationTicket] = None,
    ) -> Tuple[Optional[bytearray], Optional[bytes], Optional[BaseException]]:
        if self._descriptor.preparation_evidence is None:
            return None, None, None
        body = _encode({
            1: 1,
            2: request_id,
            3: idempotency_key,
            4: self._descriptor.runtime_contract_digest,
            5: encoded_input,
            6: self._connection,
        })
        route = self._descriptor.collection_route.removesuffix("/operations") + "/preparation-evidence"
        cancellation: Optional[BaseException] = None
        try:
            raw = await _profile_request(
                self._client, "POST", route, body, _remaining_timeout(advancement_deadline), coordination,
            )
            handle, outcome = self._decode_preparation_evidence_response(raw, request_id)
        except BaseException as error:
            if not _is_post_write_request_error(error) and not isinstance(error, ValueError):
                raise
            if isinstance(error, _PostWriteRequestError) and isinstance(
                error.cause, (asyncio.CancelledError, asyncio.TimeoutError),
            ):
                cancellation = error.cause
            raw = await _profile_request(
                self._client, "POST", route, body, _remaining_timeout(deadline), coordination,
            )
            handle, outcome = self._decode_preparation_evidence_response(raw, request_id)
        return handle, outcome, cancellation

    def _decode_preparation_evidence_response(
        self, raw: bytes, request_id: bytes,
    ) -> Tuple[Optional[bytearray], Optional[bytes]]:
        if not 1 <= len(raw) <= self._descriptor.response_bytes + 256:
            raise ValueError("preparation evidence response exceeds bound")
        wire = _decode(raw)
        if (
            not isinstance(wire, dict)
            or wire.get(1) != 1
            or wire.get(2) != request_id
        ):
            raise ValueError("invalid preparation evidence response")
        if wire.get(3) == "lease":
            if (
                set(wire) != {1, 2, 3, 4, 5, 6}
                or not isinstance(wire.get(4), bytes)
                or len(wire[4]) != 32
                or not isinstance(wire.get(5), bytes)
                or len(wire[5]) != 32
                or not isinstance(wire.get(6), int)
                or isinstance(wire.get(6), bool)
                or wire[6] < 1
            ):
                raise ValueError("invalid preparation evidence lease")
            return bytearray(wire[4]), None
        if wire.get(3) == "outcome":
            outcome = wire.get(4)
            if (
                set(wire) != {1, 2, 3, 4}
                or not isinstance(outcome, bytes)
                or not 1 <= len(outcome) <= self._descriptor.response_bytes
            ):
                raise ValueError("invalid preparation evidence outcome")
            return None, outcome
        raise ValueError("unknown preparation evidence response")

    async def _wait_for_accepted_execute(
        self,
        request_id: bytes,
        operation: str,
        initial: Dict[int, Any],
        prepared_recovery: bytes,
        prepared_receipts: Tuple[str, ...],
        deadline: float,
    ) -> ProfileOutcome[_T, _P, _G]:
        wire = initial
        recovery = prepared_recovery
        receipts = prepared_receipts
        while wire.get(2) == "in-progress":
            try:
                candidate = _bytes(wire.get(8))
                _assert_recovery_identity(
                    candidate, (operation, self._descriptor.profile_id, self._descriptor.version),
                )
                _validate_in_progress(wire, self._descriptor)
                recovery = candidate
                receipts = _receipt_id_list(wire.get(7), self._descriptor.receipt_count)
            except (TypeError, ValueError):
                return await self._recover_within_deadline(
                    request_id, operation, recovery, receipts, deadline,
                )
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            if wire.get(6) != "not-applied":
                return await self._recover_within_deadline(
                    request_id, operation, recovery, receipts, deadline,
                )
            if remaining <= 0:
                return _recovery_required(
                    operation, RecoveryHandle.from_bytes(recovery), receipts,
                )
            try:
                await asyncio.sleep(min(0.025, remaining))
                raw = await self._client._request(
                    "GET", f"{self._descriptor.collection_route}/{operation}",
                    b"", _remaining_timeout(deadline),
                )
                wire = _profile_outcome(raw, request_id, self._descriptor)
            except BaseException:
                return await self._recover_within_deadline(
                    request_id, operation, recovery, receipts, deadline,
                )
        try:
            projected = self._project(wire)
        except (TypeError, ValueError):
            return await self._recover_within_deadline(
                request_id, operation, recovery, receipts, deadline,
            )
        self._retain_projected_result(projected, wire)
        return projected

    async def _recover_within_deadline(
        self,
        request_id: bytes,
        operation: str,
        recovery: bytes,
        receipts: Tuple[str, ...],
        deadline: float,
    ) -> ProfileOutcome[_T, _P, _G]:
        expected = (
            operation, self._descriptor.profile_id, self._descriptor.version,
        )
        _assert_recovery_identity(recovery, expected)
        remaining = max(0.0, deadline - asyncio.get_running_loop().time())
        sealed = RecoveryHandle.from_bytes(recovery)
        if remaining <= 0:
            return _recovery_required(operation, sealed, receipts)
        # Execute was already accepted. Shield recovery from caller
        # cancellation so a durable pre-entry reservation cannot leak, but
        # never exceed the one monotonic recovery deadline.
        task = asyncio.create_task(self._recover_ambiguous(
            request_id, operation, recovery, receipts,
            timedelta(seconds=remaining), expected,
        ))
        try:
            return await asyncio.wait_for(asyncio.shield(task), remaining)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            if remaining > 0:
                try:
                    return await asyncio.wait_for(asyncio.shield(task), remaining)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
            return _recovery_required(operation, sealed, receipts)

    async def recover(
        self,
        recovery: RecoveryHandle,
        options: Optional[RecoveryOptions] = None,
    ) -> _T:
        outcome = await self.recover_outcome(recovery, options)
        if isinstance(outcome, Completed):
            return outcome.value
        _raise_outcome(outcome)
        raise AssertionError("unreachable")

    async def recover_outcome(
        self,
        recovery: RecoveryHandle,
        options: Optional[RecoveryOptions] = None,
    ) -> ProfileOutcome[_T, _P, _G]:
        result_token = _QUALIFICATION_RESULT.set(None)
        cancellation_token = _QUALIFICATION_CANCELLATION.set(None)
        try:
            outcome = await self._recover_outcome_inner(recovery, options)
            retained = _QUALIFICATION_RESULT.get()
            if retained is not None and retained[0] is outcome:
                await _complete_qualification_handoff(_report_qualification_result(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1], retained[2],
                ))
            return outcome
        except BaseException as error:
            retained = _QUALIFICATION_CANCELLATION.get()
            if retained is not None and retained[0] is error:
                await _complete_qualification_handoff(_report_qualification_cancellation(
                    self._client, self._descriptor.profile_id, self._descriptor.version,
                    retained[1],
                ))
            raise
        finally:
            _QUALIFICATION_RESULT.reset(result_token)
            _QUALIFICATION_CANCELLATION.reset(cancellation_token)

    async def _recover_outcome_inner(
        self,
        recovery: RecoveryHandle,
        options: Optional[RecoveryOptions],
    ) -> ProfileOutcome[_T, _P, _G]:
        descriptor = self._descriptor
        selected = _profile_recovery_options(options, descriptor.execution_milliseconds)
        recovery_only = self._client._recovery_only()
        capability = self._client._profile_capability_for_recovery(
            descriptor.profile_id, descriptor.version,
        )
        compatible = capability is not None and (
            capability.runtime_digest == descriptor.runtime_contract_digest
            and capability.error_digest == descriptor.error_projection_digest
            and capability.operation_protocol == "auths.profile-operation/1"
        )
        if not compatible and not recovery_only:
            raise _unavailable_error(
                _local_issue("client.profile-contract-mismatch", "profile contract digest mismatch"),
                None, (),
            )
        identity = _recovery_identity(recovery.to_bytes())
        if (
            identity[1] != descriptor.profile_id
            or identity[2] != descriptor.version
        ):
            raise ValueError("recovery handle belongs to another profile")
        request_id = os.urandom(16)
        body = _encode({1: 1, 2: request_id, 3: recovery.to_bytes()})
        # The sealed handle determines the operation and profile. Recovery uses
        # the common route so a restarted caller need not retain domain state.
        terminal: Optional[Dict[int, Any]] = None
        try:
            raw = await self._client._request(
                "POST", "/v1/operations/recover", body, selected.timeout
            )
            if not compatible:
                return _recovery_unavailable(identity[0], recovery, ())
            wire = _profile_outcome(raw, request_id, descriptor)
            _bind_recovery_response(wire, identity, descriptor)
            if wire.get(2) == "in-progress":
                _validate_in_progress(wire, descriptor)
                return _recovery_required(
                    identity[0], _recovery(wire.get(8)),
                    _receipt_id_list(wire.get(7), descriptor.receipt_count),
                )
            if wire.get(2) == "ready":
                _optional_text(wire.get(8))
                return _recovery_required(
                    identity[0], _recovery(wire.get(7)),
                    _receipt_ids([wire.get(6)], descriptor),
                )
            terminal = wire
        except (
            OSError, asyncio.TimeoutError, asyncio.CancelledError, TypeError, ValueError,
            _PostWriteRequestError,
        ):
            return (
                _recovery_unavailable(identity[0], recovery, ())
                if recovery_only else _recovery_required(identity[0], recovery, ())
            )
        if terminal is None:
            raise AssertionError("terminal recovery outcome was not retained")
        return self._project_and_retain(terminal)

    async def _recover_ambiguous(
        self,
        request_id: bytes,
        operation: str,
        recovery_bytes: bytes,
        receipt_ids: Tuple[str, ...],
        timeout: timedelta,
        expected: Tuple[str, str, int],
    ) -> ProfileOutcome[_T, _P, _G]:
        recovery = RecoveryHandle.from_bytes(recovery_bytes)
        body = _encode({1: 1, 2: request_id, 3: recovery_bytes})
        terminal: Optional[Dict[int, Any]] = None
        try:
            raw = await self._client._request(
                "POST",
                f"{self._descriptor.collection_route}/{operation}/recover",
                body,
                timeout,
            )
            wire = _profile_outcome(raw, request_id, self._descriptor)
            _bind_recovery_response(wire, expected, self._descriptor)
            if wire.get(2) == "in-progress":
                _validate_in_progress(wire, self._descriptor)
                return _recovery_required(
                    operation, _recovery(wire.get(8)),
                    _receipt_id_list(wire.get(7), self._descriptor.receipt_count),
                )
            if wire.get(2) == "ready":
                _optional_text(wire.get(8))
                return _recovery_required(
                    operation, _recovery(wire.get(7)),
                    _receipt_ids([wire.get(6)], self._descriptor),
                )
            terminal = wire
        except (
            OSError, asyncio.TimeoutError, asyncio.CancelledError, ValueError,
            _PostWriteRequestError,
        ):
            return _recovery_required(operation, recovery, receipt_ids)

        if terminal is None:
            raise AssertionError("terminal recovery outcome was not retained")
        return self._project_and_retain(terminal)

    def _project_and_retain(
        self, wire: Dict[int, Any],
    ) -> ProfileOutcome[_T, _P, _G]:
        projected = self._project(wire)
        self._retain_projected_result(projected, wire)
        return projected

    def _retain_projected_result(
        self, projected: object, wire: Dict[int, Any],
    ) -> None:
        request_id = wire.get(3)
        result = wire.get(5)
        if not isinstance(request_id, bytes) or len(request_id) != 16:
            raise ValueError("invalid terminal profile request ID")
        if not isinstance(result, bytes) or not 1 <= len(result) <= 16_777_216:
            raise ValueError("invalid terminal profile result")
        if wire.get(2) not in {
            "completed", "denied", "unavailable", "conflict", "not-applied",
            "partial", "recovery-required", "receipt-integrity-failed",
        }:
            raise ValueError("profile outcome has no terminal projection")
        _QUALIFICATION_RESULT.set((projected, request_id, result))

    def _project(self, wire: Dict[int, Any]) -> ProfileOutcome[_T, _P, _G]:
        kind = wire.get(2)
        if kind == "completed":
            operation = _operation_id(wire.get(4))
            completion = _completion(wire.get(7))
            receipts = _receipt_ids(wire.get(6), self._descriptor)
            metadata = OperationMetadata(
                operation, f"{self._descriptor.profile_id}/{self._descriptor.version}",
                _optional_text(wire.get(8)), completion, receipts,
            )
            value = _decode_profile_result(
                self._descriptor.profile_api, self._descriptor.success_type,
                wire.get(5), self._success_class, metadata,
            )
            return Completed(_OUTCOME_TOKEN, "completed", value)
        if kind == "denied":
            _optional_text(wire.get(7))
            return Denied(_OUTCOME_TOKEN, "denied", _operation_id(wire.get(4)), _issue_for_effect(wire.get(5), EffectState.NOT_APPLIED), _receipt_ids([wire.get(6)], self._descriptor))
        if kind == "unavailable":
            _optional_text(wire.get(7))
            raw_operation = wire.get(4)
            unavailable_operation = (
                None if raw_operation is None else _operation_id(raw_operation)
            )
            return Unavailable(_OUTCOME_TOKEN, "unavailable", unavailable_operation, _issue_for_effect(wire.get(5), EffectState.NOT_APPLIED), _receipt_ids(wire.get(6), self._descriptor))
        if kind == "conflict":
            _optional_text(wire.get(8))
            return Conflict(_OUTCOME_TOKEN, "conflict", _operation_id(wire.get(4)), _issue_for_effect(wire.get(5), EffectState.POSSIBLE), _recovery(wire.get(6)), _receipt_ids(wire.get(7), self._descriptor))
        if kind == "not-applied":
            _optional_text(wire.get(8))
            return NotApplied(_OUTCOME_TOKEN, "not-applied", _operation_id(wire.get(4)), _issue_for_effect(wire.get(5), EffectState.NOT_APPLIED), _receipt_ids(wire.get(6), self._descriptor), _completion(wire.get(7)))
        if kind == "partial":
            _optional_text(wire.get(9))
            if self._partial_class is None or self._descriptor.partial_type is None:
                raise ValueError("profile returned an undeclared partial result")
            details = _decode_profile_result(self._descriptor.profile_api, self._descriptor.partial_type, wire.get(5), self._partial_class, None)
            return Partial(_OUTCOME_TOKEN, "partial", _operation_id(wire.get(4)), _issue_for_effect(wire.get(6), EffectState.APPLIED), details, _receipt_ids(wire.get(7), self._descriptor), _completion(wire.get(8)))
        if kind == "recovery-required":
            _optional_text(wire.get(9))
            progress = None
            if wire.get(8) is not None:
                if self._progress_class is None or self._descriptor.progress_type is None:
                    raise ValueError("profile returned undeclared recovery progress")
                progress = _decode_profile_result(self._descriptor.profile_api, self._descriptor.progress_type, wire.get(8), self._progress_class, None)
            return RecoveryRequired(_OUTCOME_TOKEN, "recovery-required", _operation_id(wire.get(4)), _issue_for_effect(wire.get(5), EffectState.POSSIBLE), _recovery(wire.get(6)), _receipt_ids(wire.get(7), self._descriptor), progress)
        if kind == "receipt-integrity-failed":
            _optional_text(wire.get(9))
            operation = _operation_id(wire.get(4))
            state = _integrity_state(wire.get(6))
            effect = _integrity_effect(wire.get(7))
            terminal = wire.get(8)
            if type(terminal) is not bool or not _valid_integrity_truth(state, effect, terminal):
                raise ValueError("receipt integrity outcome contradicts durable truth")
            parsed = _issue_for_effect(wire.get(5), effect)
            if (
                parsed.code != "core.terminal-receipt-integrity-failed"
                or parsed.correlation_id != operation
                or parsed.execution_reference != operation
                or not _integrity_provider_boundary(
                    state, effect, parsed.entered_boundaries.provider,
                )
            ):
                raise ValueError("unexpected receipt integrity issue")
            return ReceiptIntegrityFailed(
                _OUTCOME_TOKEN, "receipt-integrity-failed", operation,
                parsed, state, effect, terminal, (),
            )
        raise ValueError("unknown or impossible profile outcome")


def bind_profile(
    session: Client,
    *,
    profile_id: str,
    version: int,
    collection_route: str,
    profile_client_runtime: str,
    runtime_contract_digest: str,
    error_projection_digest: str,
    request_bytes: int,
    response_bytes: int,
    execution_milliseconds: int,
    receipt_count: int,
    receipt_bytes: int,
    profile_api: Mapping[str, object],
    input_type: str,
    success_type: str,
    input_class: Type[object],
    success_class: Type[_T],
    connection: Optional[str],
    preparation_evidence: Optional[str] = None,
    partial_type: Optional[str] = None,
    progress_type: Optional[str] = None,
    partial_class: Optional[Type[_P]] = None,
    progress_class: Optional[Type[_G]] = None,
) -> BoundProfile[_T, _P, _G]:
    if not re.fullmatch(r"auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*", profile_id):
        raise ValueError("invalid generated profile identity")
    if collection_route != _route(profile_id, version):
        raise ValueError("generated profile route does not match its identity")
    descriptor = ProfileDescriptor(
        profile_id, version, collection_route, profile_client_runtime,
        _digest(runtime_contract_digest), _digest(error_projection_digest), preparation_evidence,
        request_bytes, response_bytes, execution_milliseconds, receipt_count,
        receipt_bytes, profile_api, input_type, success_type,
        partial_type, progress_type,
    )
    return BoundProfile(
        session, descriptor, connection, input_class, success_class,
        partial_class, progress_class,
    )


def _raise_outcome(outcome: object) -> None:
    if isinstance(outcome, Denied):
        raise _denied_error(outcome.issue, outcome.operation_id, outcome.receipt_ids)
    if isinstance(outcome, Unavailable):
        raise _unavailable_error(outcome.issue, outcome.operation_id, outcome.receipt_ids)
    if isinstance(outcome, Conflict):
        raise _conflict_error(outcome.issue, outcome.operation_id, outcome.receipt_ids, outcome.recovery)
    if isinstance(outcome, NotApplied):
        raise _not_applied_error(outcome.issue, outcome.operation_id, outcome.receipt_ids)
    if isinstance(outcome, Partial):
        raise _partial_error(outcome.issue, outcome.operation_id, outcome.receipt_ids, outcome.details)
    if isinstance(outcome, RecoveryRequired):
        raise _recovery_required_error(outcome.issue, outcome.operation_id, outcome.receipt_ids, outcome.recovery, outcome.progress)
    if isinstance(outcome, ReceiptIntegrityFailed):
        raise _receipt_integrity_error(
            outcome.issue, outcome.operation_id, outcome.state, outcome.terminal,
        )
    raise TypeError("unsupported profile outcome")


def _encode_profile_input(api: Mapping[str, object], type_name: str, value: object, expected: Type[object]) -> bytes:
    if type(value) is not expected:
        raise TypeError(f"expected generated {type_name}")
    types = api.get("types")
    if not isinstance(types, dict) or type_name not in types:
        raise ValueError("generated profile API is inconsistent")
    canonical = _validate_value(types[type_name], value, types, encode=True)
    return _encode(canonical)


def _decode_profile_result(api: Mapping[str, object], type_name: str, value: object, cls: Type[_T], metadata: Optional[OperationMetadata]) -> _T:
    if not isinstance(value, bytes):
        raise ValueError("profile result is not canonical bytes")
    types = api.get("types")
    if not isinstance(types, dict) or type_name not in types:
        raise ValueError("generated profile API is inconsistent")
    canonical = _decode(value)
    normalized = _validate_value(types[type_name], canonical, types, encode=False)
    if not isinstance(normalized, dict):
        raise ValueError("top-level profile result must be a record")
    kwargs = {_snake(key): item for key, item in normalized.items()}
    if metadata is not None:
        kwargs["auths"] = metadata
    return cls(**kwargs)


def _validate_value(node: object, value: object, types: Mapping[str, object], *, encode: bool) -> object:
    if not isinstance(node, dict) or not isinstance(node.get("kind"), str):
        raise ValueError("invalid generated profile schema")
    kind = node["kind"]
    if kind == "ref":
        name = node.get("name")
        if not isinstance(name, str) or name not in types:
            raise ValueError("invalid generated profile reference")
        return _validate_value(types[name], value, types, encode=encode)
    if kind == "boolean":
        if type(value) is not bool:
            raise TypeError("expected boolean")
        return value
    if kind in ("uint", "int"):
        if type(value) is not int:
            raise TypeError("expected integer")
        minimum, maximum = int(node["minimum"]), int(node["maximum"])
        if not minimum <= value <= maximum or (kind == "uint" and value < 0):
            raise ValueError("integer is outside profile bounds")
        return value
    if kind in ("string", "enum"):
        if not isinstance(value, str):
            raise TypeError("expected string")
        if kind == "enum":
            if value not in node.get("values", []):
                raise ValueError("unknown enum value")
            return value
        raw = value.encode("utf-8")
        if not int(node["minimumBytes"]) <= len(raw) <= int(node["maximumBytes"]):
            raise ValueError("string is outside profile bounds")
        _alphabet(value, str(node["alphabet"]))
        return value
    if kind == "bytes":
        convenience = node.get("sourceConvenience")
        if convenience not in (None, "file"):
            raise ValueError("invalid generated byte source convenience")
        if encode and convenience == "file" and type(value) is ProfileFile:
            value = _read_profile_file(value, int(node["maximumBytes"]))
        if not isinstance(value, bytes):
            raise TypeError("expected bytes")
        if not int(node["minimumBytes"]) <= len(value) <= int(node["maximumBytes"]):
            raise ValueError("bytes are outside profile bounds")
        return bytes(value)
    if kind == "option":
        return None if value is None else _validate_value(node["value"], value, types, encode=encode)
    if kind == "list":
        if not isinstance(value, (tuple, list)):
            raise TypeError("expected bounded sequence")
        if not int(node["minimumItems"]) <= len(value) <= int(node["maximumItems"]):
            raise ValueError("sequence is outside profile bounds")
        return [_validate_value(node["value"], item, types, encode=encode) for item in value]
    if kind == "record":
        fields = node.get("fields")
        if not isinstance(fields, list):
            raise ValueError("invalid generated record")
        if encode:
            if not dataclasses.is_dataclass(value):
                raise TypeError("expected generated dataclass")
            source = {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
            expected = {_snake(str(field["name"])) for field in fields}
            if set(source) - {"auths"} != expected:
                raise TypeError("generated dataclass fields do not match schema")
            return {str(field["name"]): _validate_value(field["value"], source[_snake(str(field["name"]))], types, encode=True) for field in fields}
        if not isinstance(value, dict) or set(value) != {field["name"] for field in fields}:
            raise ValueError("profile result record is not closed")
        return {str(field["name"]): _validate_value(field["value"], value[field["name"]], types, encode=False) for field in fields}
    raise ValueError("unsupported generated profile type")


def _issue(value: object) -> ErrorInfo:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 65_536:
        raise ValueError("invalid Auths issue envelope")
    raw = _decode(value)
    return parse_error_info(raw)


def _issue_for_effect(value: object, expected: EffectState) -> ErrorInfo:
    issue = _issue(value)
    if issue.effect is not expected:
        raise ValueError("profile outcome contradicts its Auths issue effect")
    return issue


def _integrity_effect(value: object) -> EffectState:
    if value not in ("not-applied", "possible", "applied"):
        raise ValueError("invalid receipt integrity effect")
    return EffectState(value)


def _integrity_state(value: object) -> OperationState:
    if value not in (
        "preparing", "denied", "unavailable", "ready", "executing",
        "recovery-required", "completed", "partial", "not-applied",
    ):
        raise ValueError("invalid receipt integrity state")
    return value  # type: ignore[return-value]


def _valid_integrity_truth(
    state: OperationState, effect: EffectState, terminal: bool,
) -> bool:
    if state in ("preparing", "ready"):
        return effect is EffectState.NOT_APPLIED and not terminal
    if state == "executing":
        return effect in (EffectState.NOT_APPLIED, EffectState.POSSIBLE) and not terminal
    if state in ("denied", "unavailable", "not-applied"):
        return effect is EffectState.NOT_APPLIED and terminal
    if state == "recovery-required":
        return effect is EffectState.POSSIBLE and not terminal
    return state in ("completed", "partial") and effect is EffectState.APPLIED and terminal


def _integrity_provider_boundary(
    state: OperationState, effect: EffectState, entered: bool,
) -> bool:
    if state in ("preparing", "ready", "denied", "unavailable"):
        return not entered
    if effect in (EffectState.POSSIBLE, EffectState.APPLIED):
        return entered
    return True


def _local_issue(code: str, summary: str) -> ErrorInfo:
    return ErrorInfo(
        "auths.error/1", code, "configuration", "connect", "negotiation", summary,
        "auths-python", EffectState.NOT_APPLIED, RetryClass.NEVER,
        RecommendedAction.INSTALL_COMPATIBLE_RUNTIME,
        EnteredBoundaries(False, False, False, False, False),
        None, None, None, (),
    )


def _outcome(value: bytes, expected_request: bytes) -> Dict[int, Any]:
    raw = _decode(value)
    sizes = {
        "ready": 8, "in-progress": 9, "denied": 7, "unavailable": 7,
        "conflict": 8, "completed": 8, "partial": 9, "not-applied": 8,
        "recovery-required": 9, "receipt-integrity-failed": 9,
    }
    if not isinstance(raw, dict) or raw.get(1) != 1 or not isinstance(raw.get(2), str):
        raise ValueError("invalid Auths profile outcome")
    maximum = sizes.get(raw[2])
    if (
        maximum is None or set(raw) != set(range(1, maximum + 1))
        or raw.get(3) != expected_request
    ):
        raise ValueError("Auths profile outcome has unknown, missing, or mismatched fields")
    return raw


def _profile_outcome(
    value: bytes, expected_request: bytes, descriptor: ProfileDescriptor,
) -> Dict[int, Any]:
    if not 1 <= len(value) <= descriptor.response_bytes:
        raise ValueError("profile response exceeds the declared bound")
    return _outcome(value, expected_request)


def _recovery_required(
    operation_id: str,
    recovery: RecoveryHandle,
    receipt_ids: Tuple[str, ...],
) -> RecoveryRequired[Any]:
    return RecoveryRequired(
        _OUTCOME_TOKEN, "recovery-required", operation_id,
        _outcome_unknown_issue(operation_id), recovery, receipt_ids, None,
    )


def _coordinated_replay_wire(wire: Mapping[int, object]) -> Dict[int, object]:
    replay = dict(wire)
    kind = replay.get(2)
    if kind in ("completed", "not-applied"):
        _completion(replay.get(7))
        replay[7] = "replayed"
    elif kind == "partial":
        _completion(replay.get(8))
        replay[8] = "replayed"
    return replay


def _recovery_unavailable(
    operation_id: str,
    recovery: RecoveryHandle,
    receipt_ids: Tuple[str, ...],
) -> RecoveryRequired[Any]:
    return RecoveryRequired(
        _OUTCOME_TOKEN, "recovery-required", operation_id,
        _recovery_unavailable_issue(operation_id), recovery, receipt_ids, None,
    )


def _outcome_unknown_issue(operation_id: str) -> ErrorInfo:
    return ErrorInfo(
        "auths.error/1", "operation.outcome-unknown", "state", "execute",
        "provider", "the provider outcome remains unknown; recover this operation",
        operation_id, EffectState.POSSIBLE, RetryClass.UNKNOWN,
        RecommendedAction.RESUME_AND_RECONCILE,
        EnteredBoundaries(False, False, True, True, True),
        operation_id, None, None, ("unknown",),
    )


def _recovery_unavailable_issue(operation_id: str) -> ErrorInfo:
    return ErrorInfo(
        "auths.error/1", "operation.recovery-unavailable", "state", "recover",
        "reconciliation", "recovery could not safely decode the installed operation outcome",
        operation_id, EffectState.POSSIBLE, RetryClass.UNKNOWN,
        RecommendedAction.RESUME_AND_RECONCILE,
        EnteredBoundaries(False, False, False, False, True),
        operation_id, None, None, ("unknown",),
    )


def _recovery_identity(value: bytes) -> Tuple[str, str, int]:
    raw = _decode(value)
    if not isinstance(raw, dict) or set(raw) != set(range(1, 12)) or raw.get(1) != 1:
        raise ValueError("invalid recovery handle")
    operation = _operation_id(raw.get(2))
    profile_id, version = raw.get(3), raw.get(4)
    if (
        not isinstance(profile_id, str)
        or re.fullmatch(r"auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*", profile_id) is None
        or type(version) is not int or not 1 <= version <= 65_535
        or not isinstance(raw.get(5), bytes) or len(raw[5]) != 32
        or type(raw.get(6)) is not int
        or (raw.get(7) is not None and type(raw.get(7)) is not int)
        or not isinstance(raw.get(8), bytes) or len(raw[8]) != 32
        or raw.get(9) != "Ed25519"
        or not isinstance(raw.get(10), str)
        or not isinstance(raw.get(11), bytes) or len(raw[11]) != 64
    ):
        raise ValueError("invalid recovery handle")
    return operation, profile_id, version


def _bind_recovery_response(
    wire: Mapping[int, object],
    expected: Tuple[str, str, int],
    descriptor: ProfileDescriptor,
) -> None:
    if (
        _operation_id(wire.get(4)) != expected[0]
        or expected[1] != descriptor.profile_id
        or expected[2] != descriptor.version
    ):
        raise ValueError("recovery response changed operation identity")
    kind = wire.get(2)
    raw_handle = (
        wire.get(7) if kind == "ready" else
        wire.get(8) if kind == "in-progress" else
        wire.get(6) if kind in ("conflict", "recovery-required") else
        None
    )
    if raw_handle is not None:
        if not isinstance(raw_handle, bytes):
            raise ValueError("invalid recovery response handle")
        actual = _recovery_identity(raw_handle)
        if actual != expected:
            raise ValueError("recovery response returned a foreign handle")


def _assert_recovery_identity(
    value: bytes,
    expected: Tuple[str, str, int],
) -> None:
    if _recovery_identity(value) != expected:
        raise ValueError("recovery handle changed operation identity")


def _receipt_ids(value: object, descriptor: ProfileDescriptor) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) > descriptor.receipt_count:
        raise ValueError("invalid receipt list")
    receipts = tuple(
        _receipt_bytes(item, min(1_048_576, descriptor.receipt_bytes))
        for item in value
    )
    if sum(len(item) for item in receipts) > descriptor.receipt_bytes:
        raise ValueError("profile receipt bytes exceed the declared bound")
    return tuple(parse_portable_receipt(item)[1] for item in receipts)


def _receipt_id_list(value: object, maximum: int) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("invalid receipt ID list")
    if any(
        not isinstance(item, str)
        or re.fullmatch(r"rcpt_[A-Za-z0-9_-]{43}", item) is None
        for item in value
    ):
        raise ValueError("invalid receipt ID")
    return tuple(value)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError("expected Auths bytes")
    return value


def _receipt_bytes(value: object, maximum: int = 1_048_576) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= maximum:
        raise ValueError("invalid portable receipt")
    return value


def _recovery(value: object) -> RecoveryHandle:
    if not isinstance(value, bytes):
        raise ValueError("invalid recovery handle")
    return RecoveryHandle.from_bytes(value)


def _operation_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"op_[A-Za-z0-9_-]{22}", value):
        raise ValueError("invalid operation id")
    return value


def _completion(value: object) -> Literal["fresh", "replayed", "reconciled"]:
    if value not in ("fresh", "replayed", "reconciled"):
        raise ValueError("invalid completion kind")
    if value == "fresh":
        return "fresh"
    if value == "replayed":
        return "replayed"
    return "reconciled"


def _optional_text(value: object) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not _lower_token(value, 64):
        raise ValueError("invalid connection alias")
    return value


def _validate_in_progress(
    value: Mapping[int, object], descriptor: ProfileDescriptor,
) -> None:
    _operation_id(value.get(4))
    if value.get(5) not in ("preparing", "executing"):
        raise ValueError("invalid in-progress state")
    if value.get(6) not in ("not-applied", "possible"):
        raise ValueError("invalid in-progress effect")
    _receipt_id_list(value.get(7), descriptor.receipt_count)
    _recovery(value.get(8))
    _optional_text(value.get(9))


async def _wait_coordinated_identity(
    ticket: _ProfileInvocationTicket, deadline: float,
) -> Tuple[Optional[Tuple[bytes, str, bytes]], bool]:
    # A cancelled follower cannot classify the independently advancing leader
    # as pre-entry. Consume cancellation and keep the shared identity future
    # shielded until the leader publishes durable truth or a null prewrite proof.
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise asyncio.TimeoutError("profile operation deadline exceeded")
    resolution = asyncio.create_task(asyncio.wait_for(asyncio.shield(ticket.entry.identity), remaining))
    cancellation_observed = False
    while True:
        try:
            return await asyncio.shield(resolution), cancellation_observed
        except asyncio.CancelledError:
            cancellation_observed = True
            _consume_current_cancellation()


def _consume_current_cancellation() -> None:
    """Clear 3.11+ cancellation state; pre-3.11 needs no explicit reset."""
    task = asyncio.current_task()
    uncancel = None if task is None else getattr(task, "uncancel", None)
    if uncancel is not None:
        uncancel()


async def _complete_qualification_handoff(report: Awaitable[None]) -> None:
    """Delay host cancellation until the one already-chosen result is durable."""
    task = asyncio.ensure_future(report)
    while True:
        try:
            await asyncio.shield(task)
            return
        except asyncio.CancelledError:
            if task.done():
                task.result()
                return
            _consume_current_cancellation()


async def _profile_request(
    client: object, method: str, path: str, body: bytes, timeout: timedelta,
    coordination: Optional[_ProfileInvocationTicket],
) -> bytes:
    request = getattr(client, "_request")
    if coordination is None:
        return await request(method, path, body, timeout)
    return await request(method, path, body, timeout, coordination)


def _remaining_timeout(deadline: float) -> timedelta:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise asyncio.TimeoutError("profile operation deadline exceeded")
    return timedelta(seconds=remaining)


def _digest(value: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid generated contract digest")
    return bytes.fromhex(value)


def _route(profile_id: str, version: int) -> str:
    parts = profile_id.split(".")
    if len(parts) != 3 or parts[0] != "auths" or version < 1:
        raise ValueError("invalid profile route identity")
    return f"/v1/profiles/{parts[1]}/{parts[2]}/{version}/operations"


def _lower_token(value: str, maximum: int) -> bool:
    return len(value.encode("utf-8")) <= maximum and re.fullmatch(r"[a-z][a-z0-9-]*", value) is not None


def _snake(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def _alphabet(value: str, alphabet: str) -> None:
    patterns = {
        "ascii-graphic": r"[!-~]*", "registered-token": r"[A-Za-z0-9][A-Za-z0-9._:-]*",
        "lower-token": r"[a-z][a-z0-9-]*", "lower-hex": r"[0-9a-f]+",
        "base64url": r"[A-Za-z0-9_-]+",
    }
    if alphabet == "utf8":
        if any(ord(char) == 0 or ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value):
            raise ValueError("string contains a forbidden control character")
    elif alphabet not in patterns or re.fullmatch(patterns[alphabet], value) is None:
        raise ValueError("string violates the profile alphabet")


def _validate_options(value: OperationOptions) -> None:
    if value.idempotency_key is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value.idempotency_key) is None:
        raise ValueError("invalid idempotency key")
    _validate_recovery_options(RecoveryOptions(value.timeout, value.recovery_wait))


def _validate_recovery_options(value: RecoveryOptions) -> None:
    timeout = value.timeout.total_seconds() * 1000
    wait = value.recovery_wait.total_seconds() * 1000
    if timeout != int(timeout) or wait != int(wait) or not 1 <= timeout <= 300_000 or not 1 <= wait <= timeout:
        raise ValueError("invalid operation duration")


def _profile_operation_options(
    value: Optional[OperationOptions], maximum: int,
) -> OperationOptions:
    selected = value or OperationOptions(
        timeout=timedelta(milliseconds=min(30_000, maximum)),
        recovery_wait=timedelta(milliseconds=min(5_000, maximum)),
    )
    _validate_options(selected)
    if selected.timeout > timedelta(milliseconds=maximum):
        raise ValueError("timeout exceeds the generated profile execution bound")
    return selected


def _profile_recovery_options(
    value: Optional[RecoveryOptions], maximum: int,
) -> RecoveryOptions:
    selected = value or RecoveryOptions(
        timeout=timedelta(milliseconds=min(30_000, maximum)),
        recovery_wait=timedelta(milliseconds=min(5_000, maximum)),
    )
    _validate_recovery_options(selected)
    if selected.timeout > timedelta(milliseconds=maximum):
        raise ValueError("timeout exceeds the generated profile execution bound")
    return selected


def _bounded_integer(value: int, minimum: int, maximum: int, name: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside bounds")


def _read_profile_file(value: ProfileFile, maximum: int) -> bytes:
    _bounded_integer(maximum, 0, 64 * 1024 * 1024, "profile file maximum")
    path = value._path
    try:
        path_before = os.lstat(path)
    except OSError:
        raise ValueError("profile file is unavailable") from None
    _require_regular_profile_file(path_before)

    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flag = getattr(os, name, 0)
        if type(flag) is int:
            flags |= flag
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("profile file could not be opened safely") from None

    try:
        opened = os.fstat(descriptor)
        _require_regular_profile_file(opened)
        if not _same_profile_file_snapshot(path_before, opened):
            raise ValueError("profile file changed during bounded read")
        if opened.st_size > maximum:
            raise ValueError("profile file exceeds its generated bound")

        try:
            result = os.read(descriptor, maximum + 1)
            descriptor_after = os.fstat(descriptor)
        except OSError:
            raise ValueError("profile file could not be read safely") from None
    finally:
        os.close(descriptor)

    try:
        path_after = os.lstat(path)
    except OSError:
        raise ValueError("profile file changed during bounded read") from None
    _require_regular_profile_file(path_after)
    if (
        not _same_profile_file_snapshot(opened, descriptor_after)
        or not _same_profile_file_snapshot(descriptor_after, path_after)
    ):
        raise ValueError("profile file changed during bounded read")

    if len(result) > maximum:
        raise ValueError("profile file exceeds its generated bound")
    if len(result) != descriptor_after.st_size:
        raise ValueError("profile file changed during bounded read")
    return result


def _require_regular_profile_file(value: os.stat_result) -> None:
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise TypeError("profile file must be a regular non-symlink file")


def _same_profile_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )
