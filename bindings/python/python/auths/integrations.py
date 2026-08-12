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
    Awaitable,
    Generic,
    Literal,
    Optional,
    Protocol,
    Type,
    TypeVar,
    runtime_checkable,
)

from ._development import DevelopmentEd25519Signer, DevelopmentReceiptAttestor
from ._product import (
    Auths,
    AuthsConfiguration,
    _AuthsResources,
    _create_auths,
    _create_auths_configuration,
)
from ._bootstrap import prepare_raw_key_authority
from .profiles._mcp import (
    McpExecutionStore,
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
        self._executions: set[str] = set()
        self._entered: set[str] = set()
        self._recovery: dict[str, bytes] = {}
        self._receipts: dict[str, bytes] = {}

    async def reserve(
        self, execution_id: str
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        if execution_id in self._executions:
            return "exact-replay"
        self._executions.add(execution_id)
        return "acquired"

    async def mark_provider_entry(self, execution_id: str) -> None:
        if execution_id not in self._executions or execution_id in self._entered:
            raise ValueError("invalid development provider-entry transition")
        self._entered.add(execution_id)

    async def save_recovery(self, reference: str, record_json: bytes) -> None:
        self._recovery[reference] = bytes(record_json)

    async def load_recovery(self, reference: str) -> Optional[bytes]:
        return self._recovery.get(reference)

    async def persist(self, execution_id: str, receipt_json: bytes) -> None:
        if execution_id not in self._entered or execution_id in self._receipts:
            raise ValueError("invalid development receipt transition")
        self._receipts[execution_id] = bytes(receipt_json)


class _FileMcpResources(McpExecutionStore, McpReceiptSink):
    def __init__(self, root: Path) -> None:
        self._root = root

    async def reserve(
        self, execution_id: str
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        path = self._path("execution", execution_id)
        record = _RESERVED_EXECUTION_RECORD
        try:
            await asyncio.to_thread(_exclusive_write, path, record)
            await asyncio.to_thread(_sync_directory, self._root)
            return "acquired"
        except FileExistsError:
            if await asyncio.to_thread(path.read_bytes) not in (
                _RESERVED_EXECUTION_RECORD,
                _PROVIDER_EXECUTION_RECORD,
            ):
                raise ValueError("recoverable development execution is corrupt")
            return "exact-replay"

    async def mark_provider_entry(self, execution_id: str) -> None:
        path = self._path("execution", execution_id)
        try:
            existing = await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError:
            raise ValueError("recoverable development execution is missing") from None
        if existing != _RESERVED_EXECUTION_RECORD:
            raise ValueError(
                "invalid recoverable development provider-entry transition"
            )
        await asyncio.to_thread(
            _atomic_write,
            path,
            _PROVIDER_EXECUTION_RECORD,
        )

    async def save_recovery(self, reference: str, record_json: bytes) -> None:
        await asyncio.to_thread(
            _atomic_write,
            self._path("recovery", hashlib.sha256(reference.encode()).hexdigest()),
            bytes(record_json),
        )

    async def load_recovery(self, reference: str) -> Optional[bytes]:
        path = self._path("recovery", hashlib.sha256(reference.encode()).hexdigest())
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError:
            return None

    async def persist(self, execution_id: str, receipt_json: bytes) -> None:
        await asyncio.to_thread(
            _exclusive_write,
            self._path("receipt", execution_id),
            bytes(receipt_json),
        )
        await asyncio.to_thread(_sync_directory, self._root)

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

    def __await__(self):
        return self._open().__await__()

    async def _open(self) -> Auths:
        if self._auths is None:
            self._auths = await _create_auths(self._configuration)
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
            )
        )

    def create_recoverable_auths(
        self,
        *,
        directory: Path,
        authority: McpToolAuthority,
        approval: Optional[ApprovalConfiguration] = None,
    ) -> _PendingAuths:
        root = Path(directory)
        if not root.is_absolute():
            raise ValueError("recoverable development directory must be absolute")
        root.mkdir(parents=True, exist_ok=True)
        key = _development_session_key(root)
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
) -> AuthsConfiguration:
    profile, permissions, namespaces, audiences = resources_for_mcp_authority(authority)
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
            now = int(time.time())
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


def _development_seed(session_key: bytes, role: str) -> bytes:
    encoded = role.encode()
    return hashlib.sha256(
        bytes(session_key) + len(encoded).to_bytes(8, "big") + encoded
    ).digest()


def _development_session_key(root: Path) -> bytes:
    path = root / "auths-development-v1.json"
    key = secrets.token_bytes(32)
    record = json.dumps(
        {
            "schema": "auths.recoverable-development/1",
            "sessionKey": key.hex(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    try:
        _exclusive_write(path, record)
        _sync_directory(root)
        return key
    except FileExistsError:
        try:
            parsed = json.loads(path.read_bytes())
            if (
                type(parsed) is not dict
                or parsed.get("schema") != "auths.recoverable-development/1"
                or type(parsed.get("sessionKey")) is not str
            ):
                raise ValueError
            existing = bytes.fromhex(parsed["sessionKey"])
            if len(existing) != 32:
                raise ValueError
            return existing
        except (OSError, ValueError, json.JSONDecodeError):
            raise ValueError("recoverable development manifest is corrupt") from None


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


_RESERVED_EXECUTION_RECORD = (
    b'{"schema":"auths.development-execution/1","stage":"reserved"}'
)
_PROVIDER_EXECUTION_RECORD = (
    b'{"schema":"auths.development-execution/1","stage":"provider"}'
)


__all__ = [
    "FrameworkAdapter",
    "IdentityTransport",
    "development",
    "exchange_identity",
    "production",
]
