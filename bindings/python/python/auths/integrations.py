"""Transport and framework adapter boundaries without Auths semantics."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Generic,
    Generator,
    Literal,
    Optional,
    Protocol,
    Type,
    TypeVar,
    cast,
    runtime_checkable,
)

from ._development import DevelopmentEd25519Signer, DevelopmentReceiptAttestor
from ._product import (
    Auths,
    AuthsConfiguration,
    _AuthsResources,
    _create_auths_configuration,
    create_auths,
)
from ._bootstrap import prepare_raw_key_authority
from .profiles._mcp import (
    McpExecutionStore,
    McpExecutionObserver,
    McpRecoveryCheckpoint,
    McpReceiptSink,
    McpToolAuthority,
    resources_for_mcp_authority,
)
from ._workflow import Approval, ApprovalConfiguration, AuthsClient, Validity

InputT = TypeVar("InputT", contravariant=True)
OutputT = TypeVar("OutputT", covariant=True)


@runtime_checkable
class IdentityTransport(Protocol):
    contract_version: int

    async def exchange(self, packet: bytes, *, maximum_bytes: int) -> bytes: ...


@runtime_checkable
class FrameworkAdapter(Protocol, Generic[InputT, OutputT]):
    contract_version: int

    async def handle(self, value: InputT) -> OutputT: ...


async def exchange_identity(
    transport: IdentityTransport,
    packet: bytes,
    *,
    maximum_bytes: int = 128 * 1024,
    timeout: float = 10.0,
) -> bytes:
    value = bytes(packet)
    if not value or maximum_bytes < 1 or maximum_bytes > 16 * 1024 * 1024:
        raise ValueError("identity exchange input is outside supported bounds")
    if len(value) > maximum_bytes or timeout <= 0 or timeout > 300:
        raise ValueError("identity exchange input is outside supported bounds")
    result = await asyncio.wait_for(
        transport.exchange(value, maximum_bytes=maximum_bytes), timeout
    )
    if type(result) is not bytes or not result or len(result) > maximum_bytes:
        raise ValueError("identity transport returned an invalid packet")
    return result


_DEVELOPMENT_DIAGNOSTICS = (
    "mode=development",
    "signer=ephemeral-ed25519",
    "trust=local-raw-key",
    "approval=none",
    "state=in-memory-not-production-durable",
    "receipts=memory-not-production-durable",
)


class _MemoryMcpResources(McpExecutionStore, McpReceiptSink):
    def __init__(self) -> None:
        self._executions: dict[
            str,
            tuple[
                Literal["reserved", "provider", "completed"],
                Optional[McpRecoveryCheckpoint],
            ],
        ] = {}
        self._receipts: dict[str, bytes] = {}

    async def reserve(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        if execution_id in self._executions:
            return "exact-replay"
        self._executions[execution_id] = ("reserved", _copy_recovery(recovery))
        return "acquired"

    async def mark_provider_entry(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> None:
        existing = self._executions.get(execution_id)
        if existing is None or existing[0] != "reserved":
            raise ValueError("invalid development provider-entry transition")
        self._executions[execution_id] = ("provider", _copy_recovery(recovery))

    async def save_recovery(self, recovery: McpRecoveryCheckpoint) -> None:
        existing = self._executions.get(recovery.execution_id)
        if existing is None or existing[0] == "completed":
            raise ValueError("invalid development recovery transition")
        self._executions[recovery.execution_id] = (
            existing[0],
            _copy_recovery(recovery),
        )

    async def load_recovery(self, reference: str) -> Optional[bytes]:
        for stage, recovery in self._executions.values():
            if (
                stage != "completed"
                and recovery is not None
                and recovery.reference == reference
            ):
                return bytes(recovery.record_json)
        return None

    async def clear_pending(self, execution_id: str) -> None:
        if execution_id not in self._executions:
            raise ValueError("invalid development completion transition")
        self._executions[execution_id] = ("completed", None)

    async def persist(self, execution_id: str, receipt_json: bytes) -> None:
        existing = self._executions.get(execution_id)
        if existing is None or existing[0] != "provider":
            raise ValueError("invalid development receipt transition")
        persisted = self._receipts.get(execution_id)
        if persisted is not None:
            if persisted != bytes(receipt_json):
                raise ValueError("development receipt conflicts with persisted bytes")
            return
        self._receipts[execution_id] = bytes(receipt_json)


class _FileMcpResources(McpExecutionStore, McpReceiptSink):
    def __init__(self, root: Path) -> None:
        self._root = root

    async def reserve(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        _assert_recovery(execution_id, recovery)
        await self._write_recovery(recovery)
        path = self._path("execution", execution_id)
        try:
            await asyncio.to_thread(
                _exclusive_write,
                path,
                _execution_record("reserved", recovery.reference),
            )
            await asyncio.to_thread(_sync_directory, self._root)
            return "acquired"
        except FileExistsError:
            _parse_execution_record(await asyncio.to_thread(path.read_bytes))
            return "exact-replay"

    async def mark_provider_entry(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> None:
        _assert_recovery(execution_id, recovery)
        path = self._path("execution", execution_id)
        try:
            stage, _ = _parse_execution_record(await asyncio.to_thread(path.read_bytes))
        except FileNotFoundError:
            raise ValueError("recoverable development execution is missing") from None
        if stage != "reserved":
            raise ValueError(
                "invalid recoverable development provider-entry transition"
            )
        await self._write_recovery(recovery)
        await asyncio.to_thread(
            _atomic_write,
            path,
            _execution_record("provider", recovery.reference),
        )

    async def save_recovery(self, recovery: McpRecoveryCheckpoint) -> None:
        _assert_recovery(recovery.execution_id, recovery)
        path = self._path("execution", recovery.execution_id)
        stage, _ = _parse_execution_record(await asyncio.to_thread(path.read_bytes))
        if stage == "completed":
            raise ValueError("invalid recoverable development recovery transition")
        await self._write_recovery(recovery)
        await asyncio.to_thread(
            _atomic_write,
            path,
            _execution_record(stage, recovery.reference),
        )

    async def load_recovery(self, reference: str) -> Optional[bytes]:
        execution_id = _execution_id_for_reference(reference)
        try:
            stage, current_reference = _parse_execution_record(
                await asyncio.to_thread(
                    self._path("execution", execution_id).read_bytes
                )
            )
            if stage == "completed" or current_reference != reference:
                return None
            return await asyncio.to_thread(
                self._path(
                    "recovery", hashlib.sha256(reference.encode()).hexdigest()
                ).read_bytes
            )
        except FileNotFoundError:
            return None

    async def clear_pending(self, execution_id: str) -> None:
        path = self._path("execution", execution_id)
        stage, reference = _parse_execution_record(
            await asyncio.to_thread(path.read_bytes)
        )
        if stage == "completed":
            return
        await asyncio.to_thread(_atomic_write, path, _execution_record("completed"))
        if reference is not None:
            recovery_path = self._path(
                "recovery", hashlib.sha256(reference.encode()).hexdigest()
            )
            try:
                await asyncio.to_thread(recovery_path.unlink)
            except FileNotFoundError:
                pass
            await asyncio.to_thread(_sync_directory, self._root)

    async def persist(self, execution_id: str, receipt_json: bytes) -> None:
        path = self._path("receipt", execution_id)
        try:
            await asyncio.to_thread(_exclusive_write, path, bytes(receipt_json))
            await asyncio.to_thread(_sync_directory, self._root)
        except FileExistsError:
            if await asyncio.to_thread(path.read_bytes) != bytes(receipt_json):
                raise ValueError(
                    "development receipt conflicts with persisted bytes"
                ) from None

    async def _write_recovery(self, recovery: McpRecoveryCheckpoint) -> None:
        await asyncio.to_thread(
            _atomic_write,
            self._path(
                "recovery", hashlib.sha256(recovery.reference.encode()).hexdigest()
            ),
            bytes(recovery.record_json),
        )

    def _path(self, kind: str, identifier: str) -> Path:
        if (
            kind not in ("execution", "receipt", "recovery")
            or len(identifier) != 64
            or any(value not in "0123456789abcdef" for value in identifier)
        ):
            raise ValueError("invalid recoverable development record identity")
        return self._root / f"{kind}-{identifier}.json"


class _PendingAuths(Awaitable[Auths]):
    def __init__(self, configuration: AuthsConfiguration) -> None:
        self._configuration = configuration
        self._auths: Optional[Auths] = None

    def __await__(self) -> Generator[Any, None, Auths]:
        return self._open().__await__()

    async def _open(self) -> Auths:
        if self._auths is None:
            self._auths = await create_auths(self._configuration)
        return self._auths

    async def __aenter__(self) -> Auths:
        return await self._open()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        if self._auths is not None:
            await self._auths.aclose()


class _Development:
    def create_auths(
        self,
        *,
        authority: McpToolAuthority,
        approval: Optional[ApprovalConfiguration] = None,
        observer: Optional[McpExecutionObserver] = None,
    ) -> _PendingAuths:
        resources = _MemoryMcpResources()
        return _PendingAuths(
            _development_configuration(
                authority,
                resources,
                resources,
                secrets.token_bytes(32),
                _DEVELOPMENT_DIAGNOSTICS,
                approval,
                observer,
            )
        )

    def create_recoverable_auths(
        self,
        *,
        directory: Path,
        authority: McpToolAuthority,
        approval: Optional[ApprovalConfiguration] = None,
        observer: Optional[McpExecutionObserver] = None,
    ) -> _PendingAuths:
        root = Path(directory)
        if not root.is_absolute():
            raise ValueError("recoverable development directory must be absolute")
        root.mkdir(parents=True, exist_ok=True)
        key, authority_not_before = _development_session(root)
        resources = _FileMcpResources(root)
        diagnostics = tuple(
            "state=file-backed-single-machine-not-production-durable"
            if value.startswith("state=")
            else "receipts=file-backed-single-machine-not-production-durable"
            if value.startswith("receipts=")
            else value
            for value in _DEVELOPMENT_DIAGNOSTICS
        )
        return _PendingAuths(
            _development_configuration(
                authority,
                resources,
                resources,
                key,
                diagnostics,
                approval,
                observer,
                authority_not_before,
            )
        )


class _Production:
    def create_auths(self, configuration: AuthsConfiguration) -> _PendingAuths:
        if configuration.mode != "production":
            raise TypeError("production composition rejects development capabilities")
        return _PendingAuths(configuration)


development = _Development()
production = _Production()


def _development_configuration(
    authority: McpToolAuthority,
    state: McpExecutionStore,
    receipts: McpReceiptSink,
    session_key: bytes,
    diagnostics: tuple[str, ...],
    configured_approval: Optional[ApprovalConfiguration],
    observer: Optional[McpExecutionObserver],
    authority_not_before: Optional[int] = None,
) -> AuthsConfiguration:
    profile, permissions, namespaces, audiences = resources_for_mcp_authority(authority)
    observer = _development_observer(observer)
    opened = False
    child_index = 0

    async def open_resources() -> _AuthsResources:
        nonlocal opened, child_index
        if opened:
            raise TypeError("development Auths configuration is single-use")
        opened = True
        root_signer = DevelopmentEd25519Signer(_development_seed(session_key, "root"))
        actor_signer = DevelopmentEd25519Signer(_development_seed(session_key, "actor"))
        receipt_attestor = DevelopmentReceiptAttestor(
            _development_seed(session_key, "receipts")
        )
        client: Optional[AuthsClient] = None
        try:
            approval = (
                Approval.none("approval.development.none")
                if configured_approval is None
                else configured_approval
            )
            actor = await actor_signer.public_identity()
            now = (
                int(time.time())
                if authority_not_before is None
                else authority_not_before
            )
            prepared = await prepare_raw_key_authority(
                authority_id="development.local",
                root_signer=root_signer,
                subject=actor,
                profile=profile,
                permissions=permissions,
                resource_namespaces=namespaces,
                validity=Validity(now, now + 86_400),
                audiences=audiences,
                remaining_depth=4,
                approval=approval,
            )
            client = AuthsClient(
                signer=actor_signer,
                trusted_authority=prepared.trusted_authority,
            )
            await client.open()
            agent = await client.attach_agent(
                name="development-agent",
                profile=profile,
                authority=prepared.authority,
                approval=approval,
            )
            await root_signer.aclose()

            async def dispose() -> None:
                await receipt_attestor.aclose()
                await client.aclose()

            async def child_signer() -> DevelopmentEd25519Signer:
                nonlocal child_index
                signer = DevelopmentEd25519Signer(
                    _development_seed(session_key, f"child:{child_index}")
                )
                child_index += 1
                return signer

            return _AuthsResources(
                agent,
                authority,
                state,
                receipts,
                receipt_attestor,
                bytes(session_key),
                child_signer,
                dispose,
                observer,
            )
        except BaseException:
            await root_signer.aclose()
            if client is not None:
                await client.aclose()
            else:
                await actor_signer.aclose()
            await receipt_attestor.aclose()
            raise

    return _create_auths_configuration("development", diagnostics, open_resources)


def _development_observer(
    value: Optional[McpExecutionObserver],
) -> Optional[McpExecutionObserver]:
    if value is None:
        return None
    if not callable(getattr(value, "checkpoint", None)):
        raise TypeError("invalid MCP execution observer")
    return value


def _development_seed(session_key: bytes, role: str) -> bytes:
    encoded = role.encode()
    return hashlib.sha256(
        bytes(session_key) + len(encoded).to_bytes(8, "big") + encoded
    ).digest()


def _development_session(root: Path) -> tuple[bytes, int]:
    path = root / "auths-development-v2.json"
    key = secrets.token_bytes(32)
    authority_not_before = int(time.time())
    record = json.dumps(
        {
            "schema": "auths.recoverable-development/2",
            "authorityNotBefore": authority_not_before,
            "sessionKey": key.hex(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if _publish_new_file(path, record):
        return key, authority_not_before
    try:
        parsed: object = json.loads(path.read_bytes())
        if type(parsed) is not dict:
            raise ValueError
        item = cast(dict[str, object], parsed)
        session_key = item.get("sessionKey")
        existing_not_before = item.get("authorityNotBefore")
        if (
            set(item) != {"schema", "authorityNotBefore", "sessionKey"}
            or item.get("schema") != "auths.recoverable-development/2"
            or type(session_key) is not str
            or type(existing_not_before) is not int
            or existing_not_before < 0
        ):
            raise ValueError
        existing = bytes.fromhex(session_key)
        if len(existing) != 32:
            raise ValueError
        return existing, existing_not_before
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("recoverable development manifest is corrupt") from None


def _publish_new_file(path: Path, value: bytes) -> bool:
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(16)}.tmp")
    try:
        _exclusive_write(temporary, value)
        try:
            os.link(temporary, path)
        except FileExistsError:
            return False
        _sync_directory(path.parent)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _exclusive_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, value: bytes) -> None:
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(16)}.tmp")
    try:
        _exclusive_write(temporary, value)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _copy_recovery(recovery: McpRecoveryCheckpoint) -> McpRecoveryCheckpoint:
    return McpRecoveryCheckpoint(
        recovery.execution_id, recovery.reference, bytes(recovery.record_json)
    )


def _execution_record(
    stage: Literal["reserved", "provider", "completed"],
    recovery_reference: Optional[str] = None,
) -> bytes:
    return json.dumps(
        {
            "schema": "auths.development-execution/2",
            "stage": stage,
            **(
                {}
                if recovery_reference is None
                else {"recoveryReference": recovery_reference}
            ),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _parse_execution_record(
    value: bytes,
) -> tuple[Literal["reserved", "provider", "completed"], Optional[str]]:
    try:
        parsed: object = json.loads(value)
        if type(parsed) is not dict:
            raise ValueError
        record = cast(dict[str, object], parsed)
        if record.get("schema") != "auths.development-execution/2":
            raise ValueError
        stage = record.get("stage")
        reference = record.get("recoveryReference")
        if stage == "completed" and set(record) == {"schema", "stage"}:
            return "completed", None
        if (
            stage not in ("reserved", "provider")
            or set(record) != {"schema", "stage", "recoveryReference"}
            or type(reference) is not str
        ):
            raise ValueError
        _execution_id_for_reference(reference)
        return cast(Literal["reserved", "provider"], stage), reference
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("recoverable development execution is corrupt") from None


def _assert_recovery(execution_id: str, recovery: McpRecoveryCheckpoint) -> None:
    if (
        recovery.execution_id != execution_id
        or _execution_id_for_reference(recovery.reference) != execution_id
        or not recovery.record_json
    ):
        raise ValueError("recovery checkpoint does not match execution")


def _execution_id_for_reference(reference: str) -> str:
    if (
        type(reference) is not str
        or len(reference) != 134
        or not reference.startswith("mcp1.")
        or reference[69] != "."
        or any(value not in "0123456789abcdef" for value in reference[5:69])
        or any(value not in "0123456789abcdef" for value in reference[70:])
    ):
        raise ValueError("invalid recoverable development reference")
    return reference[5:69]


__all__ = [
    "FrameworkAdapter",
    "IdentityTransport",
    "development",
    "exchange_identity",
    "production",
]
