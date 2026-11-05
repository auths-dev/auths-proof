"""Closed Google Drive v3 GET adapter for the verified document-read command."""

from __future__ import annotations

import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

import certifi

from .contracts import MAX_METADATA_BYTES, ReadCommand, TaskDescriptor
from .token_store import TokenVault
from .google_metadata import (
    DriveRepresentation, GoogleDenied, GoogleUnavailable, validate_metadata,
)

HOST = "www.googleapis.com"
METADATA_LIMIT = MAX_METADATA_BYTES
REQUEST_DEADLINE_SECONDS = 15
_DNS_SLOTS = threading.BoundedSemaphore(4)


@dataclass
class ProviderTrace:
    """Observed Drive GETs and body bytes; capacity is reserved separately."""

    requests_started: int = 0
    response_bytes: int = 0
    observer: ProviderAttemptObserver | None = None
    task_expires_at: int | None = None

    def begin(self, phase: str) -> int:
        ordinal = self.requests_started + 1
        if self.observer is not None:
            self.observer.begin(ordinal, phase)
        self.requests_started = ordinal
        return ordinal

    def observed(self, ordinal: int, count: int) -> None:
        if self.observer is not None:
            self.observer.observed(ordinal, count)
        self.response_bytes += count

    def finish(self, ordinal: int, status: str) -> None:
        if self.observer is not None:
            self.observer.finish(ordinal, status)


class ProviderAttemptObserver(Protocol):
    def begin(self, ordinal: int, phase: str) -> None: ...
    def observed(self, ordinal: int, count: int) -> None: ...
    def finish(self, ordinal: int, status: str) -> None: ...


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("Google request deadline exceeded")
    return left


def _resolve_google(deadline: float) -> list[tuple]:
    """Bound DNS wait without leaving a token-bearing request in a worker."""
    if not _DNS_SLOTS.acquire(blocking=False):
        raise GoogleUnavailable("Google DNS capacity is unavailable")
    result: queue.Queue[tuple[list[tuple] | None, OSError | None]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put((socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM), None))
        except OSError as error:
            result.put((None, error))
        finally:
            _DNS_SLOTS.release()

    try:
        threading.Thread(target=resolve, name="google-read-dns", daemon=True).start()
    except RuntimeError as error:
        _DNS_SLOTS.release()
        raise GoogleUnavailable("Google DNS worker is unavailable") from error
    try:
        addresses, error = result.get(timeout=_remaining(deadline))
    except queue.Empty as error:
        raise TimeoutError("Google DNS deadline exceeded") from error
    if error is not None:
        raise GoogleUnavailable("Google DNS resolution failed") from error
    return addresses or []


def _abort_connection(connection: http.client.HTTPSConnection) -> None:
    """Interrupt a header/body parser even if a peer trickles bytes forever."""
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass


class _PinnedGoogleConnection(http.client.HTTPSConnection):
    def __init__(self, *args, deadline: float, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.deadline = deadline

    def connect(self) -> None:
        addresses = _resolve_google(self.deadline)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise GoogleUnavailable("Google DNS returned a non-public destination")
        last_error: OSError | None = None
        for family, socktype, proto, _, address in addresses:
            raw = socket.socket(family, socktype, proto)
            try:
                raw.settimeout(_remaining(self.deadline))
                raw.connect(address)
                raw.settimeout(_remaining(self.deadline))
                self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
                return
            except OSError as error:
                last_error = error
                raw.close()
        raise GoogleUnavailable("Google TLS connection failed") from last_error


def _get(path: str, token: str, limit: int, trace: ProviderTrace,
         phase: str) -> tuple[int, bytes, str]:
    budget = REQUEST_DEADLINE_SECONDS
    if trace.task_expires_at is not None:
        budget = min(budget, trace.task_expires_at - time.time())
    deadline = time.monotonic() + max(0, budget)
    connection = _PinnedGoogleConnection(HOST, timeout=max(0, budget),
                                         context=ssl.create_default_context(cafile=certifi.where()),
                                         deadline=deadline)
    ordinal = trace.begin(phase)
    watchdog = threading.Timer(max(0, budget), _abort_connection, args=(connection,))
    watchdog.daemon = True
    watchdog.start()
    finished = False

    def finish(status: str) -> None:
        nonlocal finished
        trace.finish(ordinal, status)
        finished = True

    try:
        connection.timeout = _remaining(deadline)
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {token}",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        if getattr(connection, "sock", None) is not None:
            connection.sock.settimeout(_remaining(deadline))
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            finish("redirect_refused")
            raise GoogleUnavailable("Google returned a redirect")
        if response.getheader("Content-Encoding", "identity") != "identity":
            finish("encoding_refused")
            raise GoogleUnavailable("Google returned encoded content")
        declared = response.getheader("Content-Length")
        if declared is not None and (not declared.isascii() or not declared.isdecimal() or int(declared) > limit):
            finish("limit_refused")
            raise GoogleUnavailable("Google response exceeds byte limit")
        body = bytearray()
        while len(body) <= limit:
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(_remaining(deadline))
            else:
                _remaining(deadline)
            part = response.read(min(16_384, limit + 1 - len(body)))
            if part:
                trace.observed(ordinal, len(part))
            body.extend(part)
            if not part:
                break
        if len(body) > limit:
            finish("limit_refused")
            raise GoogleUnavailable("Google response exceeds byte limit")
        _remaining(deadline)
        finish(f"http_{response.status}")
        return response.status, bytes(body), response.getheader("Content-Type", "")
    except (OSError, http.client.HTTPException) as error:
        if not finished:
            finish("transport_unknown")
        raise GoogleUnavailable("Google request failed") from error
    except GoogleUnavailable:
        if not finished:
            finish("transport_unknown")
        raise
    finally:
        watchdog.cancel()
        connection.close()


class GoogleDriveReader:
    def __init__(self, task: TaskDescriptor, tokens: TokenVault) -> None:
        task.validate()
        self.task = task
        self.tokens = tokens
        self.trace = ProviderTrace(task_expires_at=task.expires_at)

    def set_attempt_observer(self, observer: ProviderAttemptObserver) -> None:
        self.trace.observer = observer

    def _metadata(self, command: ReadCommand) -> tuple[DriveRepresentation, str]:
        if command not in self.task.calls():
            raise GoogleDenied("document is outside approved task")
        if int(time.time()) >= self.task.expires_at:
            raise GoogleDenied("task expired")
        lease = self.tokens.lease(self.task)
        file_id = quote(command.file_id, safe="")
        metadata_path = (f"/drive/v3/files/{file_id}?fields=id,mimeType,size,trashed,"
                         "capabilities(canDownload)&supportsAllDrives=true")
        status, body, content_type = _get(metadata_path, lease.access_token, METADATA_LIMIT,
                                          self.trace, "metadata")
        if status in {401, 403, 404}:
            raise GoogleDenied("Google refused document metadata")
        if status != 200 or "application/json" not in content_type:
            raise GoogleUnavailable("Google metadata request was unsuccessful")
        return validate_metadata(body, command), lease.access_token

    def inspect_exact(self, command: ReadCommand) -> None:
        """Check employee-readable metadata without fetching document content."""
        self.trace = ProviderTrace(observer=self.trace.observer,
                                   task_expires_at=self.task.expires_at)
        self._metadata(command)

    def read_exact(self, command: ReadCommand) -> bytes:
        self.trace = ProviderTrace(observer=self.trace.observer,
                                   task_expires_at=self.task.expires_at)
        representation, access_token = self._metadata(command)
        file_id = quote(command.file_id, safe="")
        if representation is DriveRepresentation.GOOGLE_DOCUMENT:
            path = f"/drive/v3/files/{file_id}/export?mimeType=text%2Fplain"
        else:
            path = f"/drive/v3/files/{file_id}?alt=media"
        status, content, content_type = _get(path, access_token, command.max_bytes,
                                              self.trace, "content")
        if status in {401, 403, 404}:
            raise GoogleDenied("Google refused document content")
        if status != 200 or "text/plain" not in content_type:
            raise GoogleUnavailable("Google content request was unsuccessful")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GoogleUnavailable("Google returned invalid UTF-8 text") from error
        return content
