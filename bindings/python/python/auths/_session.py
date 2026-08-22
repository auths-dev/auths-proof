from __future__ import annotations

import asyncio
import base64
import os
import re
import stat
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Deque, Dict, Literal, Optional, Tuple, Union, cast

from ._cbor import decode as _decode_cbor
from ._cbor import encode as _encode_cbor
from ._public import (
    AuthsError, EffectState, EnteredBoundaries, ErrorInfo, Receipt,
    RecommendedAction, RetryClass, mint_receipt, parse_error_info,
    parse_portable_receipt, runtime_info,
)
from ._native import (
    encode_qualification_client_result_frame_v1,
    qualification_client_cancellation_result_v1,
)

_MEDIA_TYPE = "application/auths+cbor;version=1"
_MAX_HEADERS = 16_384
_MAX_RESPONSE = 16_777_216
_RECOVERY_TOKEN = object()
_OPERATION_ERROR_TOKEN = object()
_MAX_QUEUED_CALLS = 256
_QUALIFICATION_RESULT_SOCKET_ENV = "AUTHS_QUALIFICATION_CLIENT_RESULT_SOCKET"

OperationState = Literal[
    "preparing", "denied", "unavailable", "ready", "executing",
    "recovery-required", "completed", "partial", "not-applied",
]


class _ProfileInvocationEntry:
    def __init__(self, fingerprint: bytes, request_id: bytes) -> None:
        self.fingerprint = fingerprint
        self.request_id = request_id
        self.identity: asyncio.Future[Optional[Tuple[bytes, str, bytes]]] = (
            asyncio.get_running_loop().create_future()
        )
        self.waiters = 0
        self.published = False
        self.has_operation = False
        self.settled = False
        self.status: Optional[asyncio.Task[bytes]] = None


class _ProfileInvocationTicket:
    def __init__(
        self, client: "Client", scope: str, entry: _ProfileInvocationEntry,
        role: Literal["leader", "follower", "observer", "conflict-probe"],
        attached: bool,
    ) -> None:
        self.client = client
        self.scope = scope
        self.entry = entry
        self.role = role
        self.attached = attached
        self.request_id = entry.request_id
        self.finished = False


class _AdmissionGate:
    """Bounded FIFO admission for one authenticated SDK session."""

    def __init__(self, maximum: int) -> None:
        if type(maximum) is not int or not 1 <= maximum <= 32:
            raise ValueError("invalid SDK admission limit")
        self._maximum = maximum
        self._active = 0
        self._waiters: Deque[asyncio.Future[None]] = deque()
        self._closed = False

    async def acquire(self) -> None:
        if self._closed:
            raise ClientStateError("auths client is closed")
        if self._active < self._maximum:
            self._active += 1
            return
        if len(self._waiters) >= _MAX_QUEUED_CALLS:
            raise _unavailable_error(_admission_issue(), None, ())
        waiter = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        try:
            await waiter
        except BaseException:
            try:
                self._waiters.remove(waiter)
            except ValueError:
                if waiter.done() and not waiter.cancelled() and waiter.exception() is None:
                    self.release()
            raise

    def release(self) -> None:
        while self._waiters:
            waiter = self._waiters.popleft()
            if waiter.cancelled():
                continue
            waiter.set_result(None)
            return
        self._active -= 1

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_exception(ClientStateError("auths client is closed"))


def _is_reserved_sdk_request(method: str, path: str) -> bool:
    """Safe status and recovery calls do not consume ordinary effect capacity."""
    return (
        method == "GET" or method == "POST" and path == "/v1/operations/recover"
        or method == "POST" and re.fullmatch(
            r"/v1/profiles/[a-z][a-z0-9-]*/[a-z][a-z0-9-]*/[1-9][0-9]{0,4}"
            r"/operations/op_[A-Za-z0-9_-]{22}/recover",
            path,
        ) is not None
    )


@dataclass(frozen=True)
class ClientOptions:
    agent_socket: Optional[Union[str, os.PathLike[str]]] = None
    connect_timeout: timedelta = timedelta(seconds=5)


@dataclass(frozen=True)
class OperationOptions:
    idempotency_key: Optional[str] = None
    timeout: timedelta = timedelta(seconds=30)
    recovery_wait: timedelta = timedelta(seconds=5)


@dataclass(frozen=True)
class RecoveryOptions:
    timeout: timedelta = timedelta(seconds=30)
    recovery_wait: timedelta = timedelta(seconds=5)


@dataclass(frozen=True)
class OperationMetadata:
    operation_id: str
    profile: str
    connection: Optional[str]
    completion: Literal["fresh", "replayed", "reconciled"]
    receipt_ids: Tuple[str, ...]


@dataclass(frozen=True)
class OperationStatus:
    operation_id: str
    profile: str
    connection: Optional[str]
    state: OperationState
    effect: Literal["not-applied", "possible", "applied"]
    terminal: bool
    receipt_ids: Tuple[str, ...]
    recovery: Optional["RecoveryHandle"]


class RecoveryHandle:
    __slots__ = ("_bytes",)

    def __new__(cls, token: object, value: bytes) -> "RecoveryHandle":
        if token is not _RECOVERY_TOKEN:
            raise TypeError("RecoveryHandle is sealed")
        return super().__new__(cls)

    def __init__(self, token: object, value: bytes) -> None:
        if token is not _RECOVERY_TOKEN or not 1 <= len(value) <= 16_384:
            raise ValueError("recovery handle is outside bounds")
        self._bytes = bytes(value)

    def to_bytes(self) -> bytes:
        return self._bytes

    @classmethod
    def from_bytes(cls, value: bytes, /) -> "RecoveryHandle":
        return cls(_RECOVERY_TOKEN, bytes(value))

    def __repr__(self) -> str:
        return "RecoveryHandle(<redacted>)"


PortableReceipt = Receipt


class ClientStateError(RuntimeError):
    pass


class _PostWriteRequestError(Exception):
    """A local request failed after its bytes may have entered the agent."""

    def __init__(self, cause: BaseException) -> None:
        super().__init__("local Auths request failed after write")
        self.cause = cause


def _is_post_write_request_error(value: BaseException) -> bool:
    return isinstance(value, _PostWriteRequestError)


class _OperationError(AuthsError):
    def __new__(cls, token: object, *args: object, **kwargs: object) -> "_OperationError":
        if token is not _OPERATION_ERROR_TOKEN:
            raise TypeError("Auths operation errors are SDK-constructible only")
        return Exception.__new__(cls)

    def __init__(
        self,
        token: object,
        issue: ErrorInfo,
        operation_id: Optional[str],
        receipt_ids: Tuple[str, ...],
        *,
        recovery: Optional[RecoveryHandle] = None,
        details: object = None,
        progress: object = None,
    ) -> None:
        if token is not _OPERATION_ERROR_TOKEN:
            raise TypeError("Auths operation errors are SDK-constructible only")
        Exception.__init__(self, issue.summary)
        self.info = issue
        self.issue = issue
        self.operation_id = operation_id
        self.receipt_ids = receipt_ids
        self.recovery = recovery
        self.details = details
        self.progress = progress

    @property
    def recommended_action(self) -> object:
        return self.issue.recommended_action


class DeniedError(_OperationError):
    pass


class UnavailableError(_OperationError):
    pass


class ConflictError(_OperationError):
    pass


class NotAppliedError(_OperationError):
    pass


class PartialError(_OperationError):
    pass


class RecoveryRequired(_OperationError):
    pass


class ReceiptIntegrityError(_OperationError):
    def __init__(
        self,
        token: object,
        issue: ErrorInfo,
        operation_id: str,
        state: OperationState,
        terminal: bool,
    ) -> None:
        super().__init__(token, issue, operation_id, ())
        self.state = state
        self.terminal = terminal


def _denied_error(issue: ErrorInfo, operation_id: str, receipt_ids: Tuple[str, ...]) -> DeniedError:
    return DeniedError(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids)


def _unavailable_error(issue: ErrorInfo, operation_id: Optional[str], receipt_ids: Tuple[str, ...]) -> UnavailableError:
    return UnavailableError(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids)


def _conflict_error(issue: ErrorInfo, operation_id: str, receipt_ids: Tuple[str, ...], recovery: RecoveryHandle) -> ConflictError:
    return ConflictError(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids, recovery=recovery)


def _not_applied_error(issue: ErrorInfo, operation_id: str, receipt_ids: Tuple[str, ...]) -> NotAppliedError:
    return NotAppliedError(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids)


def _partial_error(issue: ErrorInfo, operation_id: str, receipt_ids: Tuple[str, ...], details: object) -> PartialError:
    return PartialError(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids, details=details)


def _recovery_required_error(issue: ErrorInfo, operation_id: str, receipt_ids: Tuple[str, ...], recovery: RecoveryHandle, progress: object) -> RecoveryRequired:
    return RecoveryRequired(_OPERATION_ERROR_TOKEN, issue, operation_id, receipt_ids, recovery=recovery, progress=progress)


def _receipt_integrity_error(
    issue: ErrorInfo,
    operation_id: str,
    state: OperationState,
    terminal: bool,
) -> ReceiptIntegrityError:
    return ReceiptIntegrityError(
        _OPERATION_ERROR_TOKEN, issue, operation_id, state, terminal,
    )


@dataclass(frozen=True)
class _ProfileCapability:
    profile_id: str
    version: int
    runtime_digest: bytes
    operation_protocol: str
    error_digest: bytes
    connection: Optional[Tuple[str, str, str]]
    qualification: Optional[Tuple[str, str, bytes]]


class Operations:
    def __init__(self, client: "Client") -> None:
        self._client = client

    async def recover(
        self,
        recovery: RecoveryHandle,
        /,
        *,
        options: Optional[RecoveryOptions] = None,
    ) -> OperationStatus:
        selected = _validate_recovery_options(options)
        request_id = os.urandom(16)
        identity = _recovery_identity(recovery.to_bytes())
        body = _encode_cbor({1: 1, 2: request_id, 3: recovery.to_bytes()})
        response_received = False
        try:
            raw = await self._client._request(
                "POST", "/v1/operations/recover", body, selected.timeout
            )
            response_received = True
            return _status_from_outcome(_wire_map(raw), identity, request_id)
        except _OperationError:
            raise
        except (
            asyncio.CancelledError, OSError, asyncio.TimeoutError, TypeError,
            ValueError, _PostWriteRequestError,
        ) as error:
            if (
                self._client._mode != "recovery-only"
                and not response_received
                and not isinstance(error, _PostWriteRequestError)
            ):
                raise
            raise _recovery_required_error(
                _recovery_unavailable_issue(identity[0]), identity[0], (), recovery, {},
            ) from error

    async def pending(self) -> Tuple[OperationStatus, ...]:
        raw = await self._client._request(
            "GET", "/v1/operations/pending", b"", timedelta(seconds=30)
        )
        wire = _wire_map(raw)
        if set(wire) != {1, 2} or wire[1] != 1 or not isinstance(wire[2], list):
            raise ValueError("invalid pending-operation response")
        if len(wire[2]) > 256:
            raise ValueError("pending-operation response exceeds bound")
        decoded = tuple(_pending_row(item) for item in wire[2])
        for previous, current in zip(decoded, decoded[1:]):
            if (previous[1], previous[0].operation_id) >= (current[1], current[0].operation_id):
                raise ValueError("pending operations are not strictly ordered")
        return tuple(item[0] for item in decoded)

    async def receipts(self, operation_id: str, /) -> Tuple[PortableReceipt, ...]:
        _validate_operation_id(operation_id)
        raw = await self._client._request(
            "GET", f"/v1/operations/{operation_id}/receipts", b"", timedelta(seconds=30)
        )
        wire = _wire_map(raw)
        if wire.get(2) == "receipt-integrity-failed":
            if (
                set(wire) != set(range(1, 10)) or wire.get(1) != 1
                or not isinstance(wire.get(3), bytes) or len(wire[3]) != 16
                or wire.get(4) != operation_id
            ):
                raise ValueError("invalid receipt integrity outcome")
            raise _receipt_integrity_failure(wire, operation_id)
        if set(wire) != {1, 2, 3} or wire[1] != 1 or wire[2] != operation_id:
            raise ValueError("invalid receipt response")
        rows = wire[3]
        if not isinstance(rows, list) or len(rows) > 64:
            raise ValueError("invalid receipt response")
        receipts = []
        total = 0
        for row in rows:
            item = _map(row)
            if set(item) != {1, 2} or not isinstance(item[1], str) or not isinstance(item[2], bytes):
                raise ValueError("invalid receipt entry")
            total += len(item[2])
            if total > 16 * 1024 * 1024:
                raise ValueError("receipt response exceeds bound")
            expected_id = parse_portable_receipt(item[2])[1]
            if item[1] != expected_id:
                raise ValueError("portable receipt ID mismatch")
            receipts.append(mint_receipt(item[1], item[2]))
        return tuple(receipts)


class Client:
    def __init__(self, options: Optional[ClientOptions] = None) -> None:
        self._options = options or ClientOptions()
        _duration_ms(self._options.connect_timeout, 1, 30_000, "connect_timeout")
        self._state = "new"
        self._socket: Optional[str] = None
        self._session_id: Optional[str] = None
        self._principal: Optional[str] = None
        self._profiles: Dict[Tuple[str, int], _ProfileCapability] = {}
        self._mode: Literal["full", "recovery-only"] = "full"
        self._operations = Operations(self)
        self._admission = _AdmissionGate(32)
        self._active_requests: set[asyncio.Task[object]] = set()
        self._profile_invocations: Dict[str, _ProfileInvocationEntry] = {}
        self._qualification_result_socket: Optional[str] = None

    async def __aenter__(self) -> "Client":
        if self._state != "new":
            raise ClientStateError("auths client cannot be entered twice")
        self._state = "opening"
        try:
            self._socket = _discover_socket(self._options.agent_socket)
            qualification_result_socket = _discover_qualification_result_socket()
            if qualification_result_socket is None:
                _validate_posix_socket(self._socket)
            else:
                _validate_qualification_socket_pair(
                    self._socket, qualification_result_socket,
                )
            request_id = os.urandom(16)
            info = runtime_info()
            digest = bytes.fromhex(info.error_registry_digest)
            body = _encode_cbor({
                1: 1, 2: request_id, 3: "python", 4: info.sdk_version,
                5: digest, 6: "full",
            })
            raw = await self._request_raw(
                "POST", "/v1/session", body, self._options.connect_timeout, None
            )
            wire = _wire_map(raw)
            self._install_session(wire, request_id, digest)
            if qualification_result_socket is not None:
                if self._mode != "full":
                    raise ValueError("qualification result handoff requires a full local session")
                self._qualification_result_socket = qualification_result_socket
            self._state = "open"
            return self
        except (
            OSError, asyncio.TimeoutError, ClientStateError, ValueError,
            _PostWriteRequestError,
        ) as error:
            self._state = "closed"
            self._session_id = None
            self._profiles.clear()
            self._qualification_result_socket = None
            raise _unavailable_error(
                _client_issue(
                    "client.agent-unavailable",
                    "the local Auths agent session could not be established",
                ),
                None,
                (),
            ) from error
        except BaseException:
            self._state = "closed"
            self._session_id = None
            self._profiles.clear()
            raise

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._state == "closed":
            return
        if self._state == "new":
            self._state = "closed"
            return
        session = self._session_id
        self._state = "closing"
        self._admission.close()
        for entry in self._profile_invocations.values():
            if not entry.identity.done():
                entry.identity.set_result(None)
            entry.published = True
        self._profile_invocations.clear()
        current = asyncio.current_task()
        active = tuple(task for task in self._active_requests if task is not current)
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        try:
            if session is not None and self._socket is not None:
                try:
                    await self._request_raw(
                        "DELETE", f"/v1/session/{session}", b"",
                        timedelta(seconds=5), session,
                    )
                except Exception:
                    pass
        finally:
            self._session_id = None
            self._profiles.clear()
            self._qualification_result_socket = None
            self._state = "closed"

    @property
    def operations(self) -> Operations:
        return self._operations

    def _profile_capability(
        self, profile_id: str, version: int, *, for_recovery: bool = False,
    ) -> _ProfileCapability:
        self._ensure_open()
        if self._mode == "recovery-only" and not for_recovery:
            raise _unavailable_error(
                _client_issue(
                    "client.profile-unavailable",
                    "the local Auths session permits recovery only",
                ),
                None,
                (),
            )
        try:
            capability = self._profiles[(profile_id, version)]
        except KeyError as error:
            raise _unavailable_error(
                _client_issue(
                    "client.profile-unavailable",
                    "the local Auths agent did not advertise this profile",
                ),
                None,
                (),
            ) from error
        self._require_qualification_profile(capability)
        return capability

    def _qualification_socket_for(self, profile_id: str, version: int) -> Optional[str]:
        self._ensure_open()
        if self._qualification_result_socket is None:
            return None
        capability = self._profiles.get((profile_id, version))
        if self._mode != "full" or capability is None or capability.qualification is not None:
            raise ValueError(
                "qualification result handoff is outside the exercised unqualified profile",
            )
        return self._qualification_result_socket

    def _require_qualification_profile(self, capability: _ProfileCapability) -> None:
        if (
            self._qualification_result_socket is not None
            and (self._mode != "full" or capability.qualification is not None)
        ):
            raise ValueError(
                "qualification result handoff is outside the exercised unqualified profile",
            )

    async def _request(
        self, method: str, path: str, body: bytes, timeout: timedelta,
        coordination: Optional[_ProfileInvocationTicket] = None,
    ) -> bytes:
        self._ensure_open()
        if self._session_id is None:
            raise ClientStateError("auths client is not open")
        if _is_reserved_sdk_request(method, path):
            return await self._tracked_request(method, path, body, timeout)
        await self._admission.acquire()
        try:
            self._ensure_open()
            return await self._tracked_request(method, path, body, timeout)
        finally:
            self._admission.release()

    def _begin_profile_invocation(
        self, scope: str, fingerprint: bytes, request_id: bytes,
    ) -> _ProfileInvocationTicket:
        self._ensure_open()
        entry = self._profile_invocations.get(scope)
        if entry is not None and entry.fingerprint != fingerprint:
            if entry.waiters >= 256:
                raise _unavailable_error(_admission_issue(), None, ())
            entry.waiters += 1
            ticket = _ProfileInvocationTicket(self, scope, entry, "conflict-probe", True)
            ticket.request_id = bytes(request_id)
            return ticket
        if entry is not None:
            attached = entry.waiters < 256
            if attached:
                entry.waiters += 1
            return _ProfileInvocationTicket(
                self, scope, entry, "follower" if attached else "observer", attached,
            )
        entry = _ProfileInvocationEntry(bytes(fingerprint), bytes(request_id))
        self._profile_invocations[scope] = entry
        return _ProfileInvocationTicket(self, scope, entry, "leader", False)

    def _publish_profile_invocation(
        self, ticket: _ProfileInvocationTicket, operation_id: Optional[str],
        initial: bytes = b"",
    ) -> None:
        if (
            ticket.client is not self or ticket.role != "leader"
            or ticket.finished or ticket.entry.published
        ):
            return
        ticket.entry.published = True
        ticket.entry.has_operation = operation_id is not None
        ticket.entry.identity.set_result(
            None if operation_id is None else (ticket.entry.request_id, operation_id, bytes(initial))
        )

    def _finish_profile_invocation(self, ticket: _ProfileInvocationTicket) -> None:
        if ticket.client is not self or ticket.finished:
            return
        ticket.finished = True
        entry = ticket.entry
        if ticket.role == "leader":
            if not entry.published:
                entry.published = True
                if not entry.identity.done():
                    entry.identity.set_result(None)
            entry.settled = True
        elif ticket.attached:
            entry.waiters -= 1
        if (
            entry.settled and (not entry.has_operation or entry.waiters == 0)
            and self._profile_invocations.get(ticket.scope) is entry
        ):
            del self._profile_invocations[ticket.scope]

    async def _profile_invocation_status(
        self, ticket: _ProfileInvocationTicket, path: str, timeout: timedelta,
    ) -> bytes:
        if (
            ticket.client is not self or ticket.finished
            or ticket.role not in ("follower", "observer")
        ):
            raise ClientStateError("invalid coordinated profile status request")
        entry = ticket.entry
        if entry.status is None:
            task = asyncio.create_task(self._request("GET", path, b"", timeout))
            entry.status = task
            def clear(completed: asyncio.Task[bytes]) -> None:
                if entry.status is completed:
                    entry.status = None
            task.add_done_callback(clear)
        return await asyncio.shield(entry.status)

    async def _tracked_request(
        self, method: str, path: str, body: bytes, timeout: timedelta,
    ) -> bytes:
        self._ensure_open()
        session = self._session_id
        if session is None:
            raise ClientStateError("auths client is not open")
        task = asyncio.current_task()
        if task is None:
            raise ClientStateError("Auths request has no owning task")
        tracked = cast(asyncio.Task[object], task)
        self._active_requests.add(tracked)
        try:
            return await self._request_raw(method, path, body, timeout, session)
        finally:
            self._active_requests.discard(tracked)

    def _recovery_only(self) -> bool:
        self._ensure_open()
        return self._mode == "recovery-only"

    def _profile_capability_for_recovery(
        self, profile_id: str, version: int,
    ) -> Optional[_ProfileCapability]:
        self._ensure_open()
        capability = self._profiles.get((profile_id, version))
        if capability is not None:
            self._require_qualification_profile(capability)
        return capability

    async def _request_raw(
        self,
        method: str,
        path: str,
        body: bytes,
        timeout: timedelta,
        session: Optional[str],
    ) -> bytes:
        if self._socket is None:
            raise ClientStateError("auths client is not open")
        timeout_seconds = _duration_ms(timeout, 1, 300_000, "timeout") / 1000
        written = [False]
        try:
            return await asyncio.wait_for(
                _unix_http_request(
                    self._socket, method, path, body, session, written,
                ),
                timeout_seconds,
            )
        except (asyncio.CancelledError, asyncio.TimeoutError, OSError, ClientStateError, ValueError) as error:
            if written[0]:
                raise _PostWriteRequestError(error) from error
            raise

    def _install_session(self, wire: Dict[int, Any], request_id: bytes, digest: bytes) -> None:
        if set(wire) != set(range(1, 9)) or wire[1] != 1 or wire[2] != request_id:
            raise ValueError("invalid Auths session response")
        if not _valid_session_id(wire[3]) or not _valid_principal(wire[4]):
            raise ValueError("invalid Auths session binding")
        mode = wire[8]
        if (
            mode not in ("full", "recovery-only")
            or not isinstance(wire[5], bytes) or len(wire[5]) != 32
            or (mode == "full") != (wire[5] == digest)
            or type(wire[7]) is not int or not 1 <= wire[7] <= 32
        ):
            raise ValueError("invalid Auths session mode")
        profiles = wire[6]
        if not isinstance(profiles, list) or len(profiles) > 256:
            raise ValueError("invalid Auths profile advertisement")
        parsed: Dict[Tuple[str, int], _ProfileCapability] = {}
        previous_key: Optional[Tuple[str, int]] = None
        for raw in profiles:
            item = _map(raw)
            if set(item) != set(range(1, 8)):
                raise ValueError("invalid Auths profile advertisement")
            connection = item[6]
            projection: Optional[Tuple[str, str, str]]
            if connection is None:
                projection = None
            else:
                connection_map = _map(connection)
                if set(connection_map) != {1, 2, 3}:
                    raise ValueError("invalid Auths connection advertisement")
                projection = (connection_map[1], connection_map[2], connection_map[3])
                if (
                    not _valid_lower_token(projection[0])
                    or not _valid_semantic_id(projection[1])
                    or not _valid_semantic_id(projection[2])
                ):
                    raise ValueError("invalid Auths connection advertisement")
            if (
                not _valid_profile_id(item[1])
                or type(item[2]) is not int or not 1 <= item[2] <= 65_535
                or not isinstance(item[3], bytes) or len(item[3]) != 32
                or item[4] != "auths.profile-operation/1"
                or not isinstance(item[5], bytes) or len(item[5]) != 32
            ):
                raise ValueError("invalid Auths profile advertisement")
            raw_qualification = item[7]
            qualification: Optional[Tuple[str, str, bytes]]
            if raw_qualification is None:
                qualification = None
            else:
                qualified = _map(raw_qualification)
                qualification_id = qualified.get(1)
                target = qualified.get(2)
                closure = qualified.get(3)
                if (
                    set(qualified) != {1, 2, 3}
                    or not isinstance(qualification_id, str)
                    or re.fullmatch(r"qlf_[A-Za-z0-9_-]{43}", qualification_id) is None
                    or target not in {"linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64"}
                    or not isinstance(closure, bytes)
                    or len(closure) != 32
                ):
                    raise ValueError("invalid Auths qualification advertisement")
                qualification = (qualification_id, target, bytes(closure))
            key = (item[1], item[2])
            if key in parsed or previous_key is not None and previous_key >= key:
                raise ValueError("duplicate or unordered Auths profile advertisement")
            previous_key = key
            parsed[key] = _ProfileCapability(
                item[1], item[2], bytes(item[3]), item[4], bytes(item[5]), projection,
                qualification,
            )
        self._session_id = wire[3]
        self._principal = wire[4]
        self._mode = cast(Literal["full", "recovery-only"], mode)
        self._profiles = parsed
        self._admission = _AdmissionGate(wire[7])

    def _ensure_open(self) -> None:
        if self._state != "open":
            raise ClientStateError("auths client is not open")


def connect(*, options: Optional[ClientOptions] = None) -> Client:
    return Client(options)


def _valid_session_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"ses_([A-Za-z0-9_-]{22})", value)
    if match is None:
        return False
    encoded = match.group(1)
    try:
        decoded = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, TypeError):
        return False
    return (
        len(decoded) == 16 and any(decoded)
        and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == encoded
    )


def _valid_principal(value: object) -> bool:
    if not isinstance(value, str) or not 3 <= len(value.encode("utf-8")) <= 512:
        return False
    scheme, separator, remainder = value.partition(":")
    return (
        separator == ":" and bool(remainder)
        and re.fullmatch(r"[a-z][a-z0-9+.-]*", scheme) is not None
        and all(0x21 <= ord(character) <= 0x7e for character in value)
    )


def _valid_profile_id(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 128
        and re.fullmatch(r"auths\.[a-z][a-z0-9-]{0,63}\.[a-z][a-z0-9-]{0,63}", value) is not None
    )


def _valid_lower_token(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 64
        and re.fullmatch(r"[a-z][a-z0-9-]*", value) is not None
    )


def _valid_semantic_id(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 128
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value) is not None
    )


def _discover_socket(explicit: Optional[Union[str, os.PathLike[str]]]) -> str:
    candidate: Optional[str]
    if explicit is not None:
        candidate = os.fspath(explicit)
    else:
        candidate = os.environ.get("AUTHS_AGENT_SOCKET")
        if candidate is None and os.name == "posix":
            runtime = os.environ.get("XDG_RUNTIME_DIR")
            if runtime and os.path.isabs(runtime):
                candidate = os.path.join(runtime, "auths", "agent.sock")
        if candidate is None and os.name == "nt":
            candidate = r"\\.\pipe\auths-agent"
    if candidate is None:
        raise _unavailable_error(
            _client_issue(
                "client.agent-unavailable",
                "no safe local Auths agent socket is configured",
            ),
            None,
            (),
        )
    encoded = candidate.encode("utf-8")
    if not 1 <= len(encoded) <= 1024 or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError("invalid local Auths agent socket")
    if os.name == "posix" and not os.path.isabs(candidate):
        raise ValueError("local Auths agent socket must be absolute")
    if os.name == "nt" and not candidate.startswith("\\\\.\\pipe\\"):
        raise ValueError("local Auths agent pipe must be host-local")
    return candidate


def _discover_qualification_result_socket() -> Optional[str]:
    candidate = os.environ.get(_QUALIFICATION_RESULT_SOCKET_ENV)
    if candidate is None:
        return None
    encoded = candidate.encode("utf-8")
    if (
        os.name != "posix"
        or os.uname().sysname != "Linux"
        or not os.path.isabs(candidate)
        or not 1 <= len(encoded) <= 1024
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise ValueError("invalid qualification result socket")
    return candidate


def _validate_posix_socket(path: str) -> None:
    if os.name != "posix":
        raise _unavailable_error(
            _client_issue("client.agent-unavailable", "local named-pipe transport is unavailable"),
            None,
            (),
        )
    try:
        item = os.lstat(path)
    except OSError as error:
        raise _unavailable_error(
            _client_issue("client.agent-unavailable", "local Auths agent socket is unavailable"),
            None,
            (),
        ) from error
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISSOCK(item.st_mode):
        raise _unavailable_error(
            _client_issue("client.agent-unavailable", "Auths agent address is not a safe socket"),
            None,
            (),
        )
    if item.st_uid not in (0, os.geteuid()) or item.st_mode & stat.S_IWOTH:
        raise _unavailable_error(
            _client_issue("client.agent-unavailable", "Auths agent socket permissions are unsafe"),
            None,
            (),
        )


def _validate_qualification_socket_pair(agent_socket: str, result_socket: str) -> None:
    if (
        os.name != "posix"
        or os.uname().sysname != "Linux"
        or agent_socket == result_socket
        or os.path.normpath(agent_socket) != agent_socket
        or os.path.normpath(result_socket) != result_socket
        or os.path.dirname(agent_socket) != os.path.dirname(result_socket)
    ):
        raise ValueError("qualification sockets are not one normalized protected pair")
    parent_path = Path(agent_socket).parent
    current = Path("/")
    for component in parent_path.parts[1:]:
        current /= component
        item = os.lstat(current)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise ValueError("qualification socket parent is not a no-symlink directory")
    parent = os.lstat(parent_path)
    agent = os.lstat(agent_socket)
    result = os.lstat(result_socket)
    owner = parent.st_uid
    gid = os.getegid()
    if (
        owner in (0, os.geteuid())
        or parent.st_gid != gid or stat.S_IMODE(parent.st_mode) != 0o710
        or not stat.S_ISDIR(parent.st_mode)
        or agent.st_uid != owner or result.st_uid != owner
        or agent.st_gid != gid or result.st_gid != gid
        or stat.S_IMODE(agent.st_mode) != 0o660
        or stat.S_IMODE(result.st_mode) != 0o660
        or not stat.S_ISSOCK(agent.st_mode) or not stat.S_ISSOCK(result.st_mode)
    ):
        raise ValueError("qualification sockets are not exact protected shared state")


async def _report_qualification_result(
    client: Client,
    profile_id: str,
    version: int,
    request_id: bytes,
    result: bytes,
    *,
    cancellation: bool = False,
) -> None:
    socket_path = client._qualification_socket_for(profile_id, version)
    if socket_path is None:
        return
    if len(request_id) != 16 or not 1 <= len(result) <= _MAX_RESPONSE:
        raise ValueError("invalid qualification result handoff")
    deadline = asyncio.get_running_loop().time() + 30.0
    new_mode = 1 if cancellation else 0
    mode = new_mode
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("qualification result acknowledgement timed out")
        sent = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(socket_path), remaining,
            )
            try:
                writer.write(encode_qualification_client_result_frame_v1(
                    mode, request_id, result,
                ))
                await asyncio.wait_for(writer.drain(), _qualification_remaining(deadline))
                writer.write_eof()
                sent = True
                acknowledgement = await asyncio.wait_for(
                    reader.readexactly(32), _qualification_remaining(deadline),
                )
                trailing = await asyncio.wait_for(
                    reader.read(1), _qualification_remaining(deadline),
                )
                if len(acknowledgement) == 32 and trailing == b"":
                    return
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        if sent:
            mode = new_mode + 2
        await asyncio.sleep(min(0.01, max(0.0, deadline - asyncio.get_running_loop().time())))


async def _report_qualification_cancellation(
    client: Client, profile_id: str, version: int, request_id: bytes,
) -> None:
    result = qualification_client_cancellation_result_v1(request_id)
    await _report_qualification_result(
        client, profile_id, version, request_id, result, cancellation=True,
    )


def _qualification_remaining(deadline: float) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("qualification result acknowledgement timed out")
    return remaining


def _client_issue(code: str, summary: str) -> ErrorInfo:
    if code == "client.profile-unavailable":
        return ErrorInfo(
            "auths.error/1", code, "configuration", "connect", "negotiation",
            summary, "auths-python", EffectState.NOT_APPLIED, RetryClass.NEVER,
            RecommendedAction.INSTALL_COMPATIBLE_RUNTIME,
            EnteredBoundaries(False, False, False, False, False),
            None, None, None, (),
        )
    return ErrorInfo(
        "auths.error/1", "client.agent-unavailable", "runtime", "connect",
        "local-agent", summary, "auths-python", EffectState.NOT_APPLIED,
        RetryClass.CONDITIONAL, RecommendedAction.CORRECT_CONFIGURATION,
        EnteredBoundaries(False, False, False, False, False),
        None, None, None, (),
    )


def _admission_issue() -> ErrorInfo:
    return ErrorInfo(
        "auths.error/1", "operation.admission-exhausted", "state", "execute",
        "admission", "Operation admission exhausted", "auths-python-admission",
        EffectState.NOT_APPLIED, RetryClass.CONDITIONAL,
        RecommendedAction.RETRY_EXECUTION,
        EnteredBoundaries(False, False, False, False, False),
        None, None, None, ("unknown",),
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


async def _unix_http_request(
    socket_path: str,
    method: str,
    path: str,
    body: bytes,
    session: Optional[str],
    written: Optional[list[bool]] = None,
) -> bytes:
    if not path.startswith("/") or any(char in path for char in ("?", "%", "\r", "\n")):
        raise ValueError("invalid Auths agent route")
    if len(body) > 33_554_432:
        raise ValueError("Auths request exceeds the absolute frame bound")
    reader, writer = await asyncio.open_unix_connection(socket_path)
    try:
        headers = [
            f"{method} {path} HTTP/1.1", "Host: localhost",
            f"Content-Type: {_MEDIA_TYPE}", f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if session is not None:
            headers.append(f"Auths-Session: {session}")
        wire = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        if written is not None:
            written[0] = True
        writer.write(wire)
        await writer.drain()
        header = await reader.readuntil(b"\r\n\r\n")
        if len(header) > _MAX_HEADERS:
            raise ValueError("Auths response headers exceed bound")
        lines = header[:-4].split(b"\r\n")
        if not lines or not lines[0].startswith(b"HTTP/1.1 "):
            raise ValueError("invalid Auths HTTP response")
        try:
            status = int(lines[0].split(b" ", 2)[1])
        except (ValueError, IndexError) as error:
            raise ValueError("invalid Auths HTTP response") from error
        parsed: Dict[bytes, bytes] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            key = name.strip().lower()
            if not separator or key in parsed:
                raise ValueError("invalid Auths HTTP response headers")
            parsed[key] = value.strip()
        if status != 200:
            raise ClientStateError(f"local Auths agent refused request ({status})")
        if parsed.get(b"content-type") != _MEDIA_TYPE.encode("ascii"):
            raise ValueError("invalid Auths response media type")
        try:
            length = int(parsed[b"content-length"])
        except (KeyError, ValueError) as error:
            raise ValueError("invalid Auths response length") from error
        if not 0 <= length <= _MAX_RESPONSE:
            raise ValueError("Auths response exceeds bound")
        response = await reader.readexactly(length)
        if await reader.read(1):
            raise ValueError("trailing bytes after Auths response")
        return response
    finally:
        writer.close()
        await writer.wait_closed()


def _wire_map(raw: bytes) -> Dict[int, Any]:
    return _map(_decode_cbor(raw))


def _map(value: Any) -> Dict[int, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, int) for key in value):
        raise ValueError("expected integer-keyed Auths map")
    return value


def _duration_ms(value: timedelta, minimum: int, maximum: int, name: str) -> int:
    microseconds = value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds
    if microseconds % 1000 != 0:
        raise ValueError(f"{name} must use whole milliseconds")
    milliseconds = microseconds // 1000
    if not minimum <= milliseconds <= maximum:
        raise ValueError(f"{name} is outside bounds")
    return milliseconds


def _validate_recovery_options(options: Optional[RecoveryOptions]) -> RecoveryOptions:
    selected = options or RecoveryOptions()
    timeout = _duration_ms(selected.timeout, 1, 300_000, "timeout")
    wait = _duration_ms(selected.recovery_wait, 1, timeout, "recovery_wait")
    if wait > timeout:
        raise ValueError("recovery_wait exceeds timeout")
    return selected


def _validate_operation_id(value: str) -> None:
    if re.fullmatch(r"op_[A-Za-z0-9_-]{22}", value) is None:
        raise ValueError("invalid operation id")


def _recovery_identity(value: bytes) -> Tuple[str, str, int]:
    raw = _wire_map(value)
    if set(raw) != set(range(1, 12)) or raw.get(1) != 1:
        raise ValueError("invalid recovery handle")
    operation, profile_id, version = raw.get(2), raw.get(3), raw.get(4)
    if not isinstance(operation, str):
        raise ValueError("invalid recovery operation")
    _validate_operation_id(operation)
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


def _receipt_id_list(value: object) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 64 or any(
        not isinstance(item, str)
        or re.fullmatch(r"rcpt_[A-Za-z0-9_-]{43}", item) is None
        for item in value
    ):
        raise ValueError("invalid receipt ID list")
    return tuple(value)


def _receipt_ids_from_portable(value: object) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid portable receipt list")
    output = []
    for item in value:
        if not isinstance(item, bytes) or not 1 <= len(item) <= 1_048_576:
            raise ValueError("invalid portable receipt")
        output.append(parse_portable_receipt(item)[1])
    return tuple(output)


def _status_from_outcome(
    wire: Dict[int, Any],
    identity: Tuple[str, str, int],
    request_id: bytes,
) -> OperationStatus:
    kind = wire.get(2)
    sizes = {
        "ready": 8, "in-progress": 9, "denied": 7, "unavailable": 7,
        "conflict": 8, "completed": 8, "partial": 9, "not-applied": 8,
        "recovery-required": 9, "receipt-integrity-failed": 9,
    }
    maximum = sizes.get(kind) if isinstance(kind, str) else None
    if (
        maximum is None or set(wire) != set(range(1, maximum + 1))
        or wire.get(1) != 1 or wire.get(3) != request_id
    ):
        raise ValueError("invalid recovery outcome")
    operation = wire.get(4)
    if not isinstance(operation, str) or operation != identity[0]:
        raise ValueError("recovery outcome changed operation identity")
    _validate_operation_id(operation)
    if kind == "receipt-integrity-failed":
        raise _receipt_integrity_failure(wire, operation)
    recovery: Optional[RecoveryHandle] = None
    if kind == "ready":
        if not isinstance(wire.get(5), bytes) or len(wire[5]) != 32:
            raise ValueError("invalid preparation commitment")
        receipt_ids = _receipt_ids_from_portable([wire.get(6)])
        recovery = _status_recovery(wire.get(7), identity)
        connection = wire.get(8)
        state: OperationState = "ready"
        effect: Literal["not-applied", "possible", "applied"] = "not-applied"
        terminal = False
    elif kind == "in-progress":
        state_value, effect_value = wire.get(5), wire.get(6)
        if (
            state_value not in ("preparing", "executing")
            or effect_value not in ("not-applied", "possible")
            or (state_value == "preparing" and effect_value != "not-applied")
        ):
            raise ValueError("invalid in-progress truth")
        state = cast(OperationState, state_value)
        effect = cast(Literal["not-applied", "possible", "applied"], effect_value)
        receipt_ids = _receipt_id_list(wire.get(7))
        recovery = _status_recovery(wire.get(8), identity)
        connection = wire.get(9)
        terminal = False
    elif kind == "denied":
        _status_issue(wire.get(5), "not-applied", operation)
        receipt_ids = _receipt_ids_from_portable([wire.get(6)])
        connection = wire.get(7); state = "denied"; effect = "not-applied"; terminal = True
    elif kind == "unavailable":
        _status_issue(wire.get(5), "not-applied", operation)
        receipts = wire.get(6)
        if not isinstance(receipts, list) or len(receipts) > 1:
            raise ValueError("invalid unavailable receipt list")
        receipt_ids = _receipt_ids_from_portable(receipts)
        connection = wire.get(7); state = "unavailable"; effect = "not-applied"; terminal = True
    elif kind == "conflict":
        _status_issue(wire.get(5), "possible", operation)
        recovery = _status_recovery(wire.get(6), identity)
        receipt_ids = _receipt_ids_from_portable(wire.get(7))
        connection = wire.get(8); state = "recovery-required"; effect = "possible"; terminal = False
    elif kind == "completed":
        _bounded_result(wire.get(5)); receipt_ids = _receipt_ids_from_portable(wire.get(6)); _completion(wire.get(7))
        connection = wire.get(8); state = "completed"; effect = "applied"; terminal = True
    elif kind == "partial":
        _bounded_result(wire.get(5)); _status_issue(wire.get(6), "applied", operation); receipt_ids = _receipt_ids_from_portable(wire.get(7)); _completion(wire.get(8))
        connection = wire.get(9); state = "partial"; effect = "applied"; terminal = True
    elif kind == "not-applied":
        _status_issue(wire.get(5), "not-applied", operation); receipt_ids = _receipt_ids_from_portable(wire.get(6)); _completion(wire.get(7))
        connection = wire.get(8); state = "not-applied"; effect = "not-applied"; terminal = True
    else:
        _status_issue(wire.get(5), "possible", operation)
        recovery = _status_recovery(wire.get(6), identity)
        receipt_ids = _receipt_ids_from_portable(wire.get(7))
        if wire.get(8) is not None:
            _bounded_result(wire.get(8))
        connection = wire.get(9); state = "recovery-required"; effect = "possible"; terminal = False
    if connection is not None and (
        not isinstance(connection, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", connection) is None
    ):
        raise ValueError("invalid connection alias")
    return OperationStatus(
        operation, f"{identity[1]}/{identity[2]}", connection, state,
        effect, terminal,
        receipt_ids, recovery,
    )


def _status_issue(
    value: object,
    expected_effect: Literal["not-applied", "possible", "applied"],
    operation_id: str,
) -> ErrorInfo:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 65_536:
        raise ValueError("invalid recovery outcome issue")
    parsed = parse_error_info(_decode_cbor(value))
    if (
        parsed.effect is not EffectState(expected_effect)
        or parsed.correlation_id != operation_id
        or parsed.execution_reference not in (None, operation_id)
    ):
        raise ValueError("recovery outcome issue changed operation truth")
    return parsed


def _status_recovery(
    value: object,
    expected: Tuple[str, str, int],
) -> RecoveryHandle:
    if not isinstance(value, bytes) or _recovery_identity(value) != expected:
        raise ValueError("recovery outcome returned a foreign handle")
    return RecoveryHandle.from_bytes(value)


def _bounded_result(value: object) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= _MAX_RESPONSE:
        raise ValueError("operation result is outside bounds")
    return value


def _completion(value: object) -> Literal["fresh", "replayed", "reconciled"]:
    if value not in ("fresh", "replayed", "reconciled"):
        raise ValueError("invalid operation completion")
    return cast(Literal["fresh", "replayed", "reconciled"], value)


def _receipt_integrity_failure(
    wire: Dict[int, Any], operation_id: str,
) -> ReceiptIntegrityError:
    raw_state = wire.get(6)
    if raw_state not in (
        "preparing", "denied", "unavailable", "ready", "executing",
        "recovery-required", "completed", "partial", "not-applied",
    ):
        raise ValueError("invalid receipt integrity state")
    raw_effect = wire.get(7)
    if raw_effect not in ("not-applied", "possible", "applied"):
        raise ValueError("invalid receipt integrity effect")
    terminal = wire.get(8)
    state = cast(OperationState, raw_state)
    if type(terminal) is not bool or not _valid_integrity_truth(
        state, cast(Literal["not-applied", "possible", "applied"], raw_effect), terminal,
    ):
        raise ValueError("receipt integrity outcome contradicts durable truth")
    connection = wire.get(9)
    if connection is not None and (
        not isinstance(connection, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", connection) is None
    ):
        raise ValueError("invalid receipt integrity connection")
    issue_bytes = wire.get(5)
    if not isinstance(issue_bytes, bytes) or not 1 <= len(issue_bytes) <= 65_536:
        raise ValueError("invalid receipt integrity issue")
    issue = parse_error_info(_decode_cbor(issue_bytes))
    if (
        issue.code != "core.terminal-receipt-integrity-failed"
        or issue.effect is not EffectState(raw_effect)
        or issue.correlation_id != operation_id
        or issue.execution_reference != operation_id
        or not _integrity_provider_boundary(
            state, cast(Literal["not-applied", "possible", "applied"], raw_effect),
            issue.entered_boundaries.provider,
        )
    ):
        raise ValueError("invalid receipt integrity issue")
    return _receipt_integrity_error(issue, operation_id, state, terminal)


def _valid_integrity_truth(
    state: OperationState,
    effect: Literal["not-applied", "possible", "applied"],
    terminal: bool,
) -> bool:
    if state in ("preparing", "ready"):
        return effect == "not-applied" and not terminal
    if state == "executing":
        return effect in ("not-applied", "possible") and not terminal
    if state in ("denied", "unavailable", "not-applied"):
        return effect == "not-applied" and terminal
    if state == "recovery-required":
        return effect == "possible" and not terminal
    return state in ("completed", "partial") and effect == "applied" and terminal


def _integrity_provider_boundary(
    state: OperationState,
    effect: Literal["not-applied", "possible", "applied"],
    entered: bool,
) -> bool:
    if state in ("preparing", "ready", "denied", "unavailable"):
        return not entered
    if effect in ("possible", "applied"):
        return entered
    return True


def _pending_row(value: Any) -> Tuple[OperationStatus, int]:
    wire = _map(value)
    if set(wire) != set(range(1, 11)):
        raise ValueError("invalid pending operation")
    operation = wire[1]
    profile_id = wire[2]
    version = wire[3]
    if not isinstance(operation, str):
        raise ValueError("invalid pending-operation identity")
    _validate_operation_id(operation)
    if (
        not isinstance(profile_id, str)
        or re.fullmatch(r"auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*", profile_id) is None
        or not isinstance(version, int) or isinstance(version, bool)
        or not 1 <= version <= 65_535
    ):
        raise ValueError("invalid pending-operation profile")
    state = wire[4]
    effect = wire[5]
    if (
        not isinstance(state, str) or not isinstance(effect, str)
        or (state, effect) not in {
            ("preparing", "not-applied"), ("ready", "not-applied"),
            ("executing", "not-applied"), ("executing", "possible"),
            ("recovery-required", "possible"),
        }
        or wire[6] is not False
    ):
        raise ValueError("invalid pending-operation truth")
    updated_at = wire[7]
    if not isinstance(updated_at, int) or isinstance(updated_at, bool) or updated_at < 1:
        raise ValueError("invalid pending-operation timestamp")
    receipt_ids = _receipt_id_list(wire[8])
    if not isinstance(wire[9], bytes):
        raise ValueError("invalid pending-operation recovery handle")
    identity = _recovery_identity(wire[9])
    if identity != (operation, profile_id, version):
        raise ValueError("pending recovery handle changed operation identity")
    recovery = RecoveryHandle.from_bytes(wire[9])
    connection = wire[10]
    if connection is not None and (
        not isinstance(connection, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", connection) is None
    ):
        raise ValueError("invalid pending-operation connection")
    return (
        OperationStatus(
            operation, f"{profile_id}/{version}", connection, cast(OperationState, state),
            cast(Literal["not-applied", "possible", "applied"], effect), False,
            receipt_ids, recovery,
        ),
        updated_at,
    )


def _status_from_pending(value: Any) -> OperationStatus:
    return _pending_row(value)[0]
