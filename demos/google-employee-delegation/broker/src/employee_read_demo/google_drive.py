"""Closed Google Drive v3 GET adapter for the verified document-read command."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

from .contracts import MAX_METADATA_BYTES, ReadCommand, TaskDescriptor
from .token_store import TokenVault

HOST = "www.googleapis.com"
DOC_MIME = "application/vnd.google-apps.document"
TEXT_MIME = "text/plain"
METADATA_LIMIT = MAX_METADATA_BYTES


class GoogleDenied(PermissionError):
    """Provider refusal; no private file detail is included."""


class GoogleUnavailable(RuntimeError):
    """Transport or malformed provider result; retry needs fresh admission."""


@dataclass
class ProviderTrace:
    """Observed Drive GETs and body bytes; capacity is reserved separately."""

    requests_started: int = 0
    response_bytes: int = 0
    observer: ProviderAttemptObserver | None = None

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


class _PinnedGoogleConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        try:
            addresses = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
        except OSError as error:
            raise GoogleUnavailable("Google DNS resolution failed") from error
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise GoogleUnavailable("Google DNS returned a non-public destination")
        last_error: OSError | None = None
        for family, socktype, proto, _, address in addresses:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(self.timeout)
            try:
                raw.connect(address)
                self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
                return
            except OSError as error:
                last_error = error
                raw.close()
        raise GoogleUnavailable("Google TLS connection failed") from last_error


def _get(path: str, token: str, limit: int, trace: ProviderTrace,
         phase: str) -> tuple[int, bytes, str]:
    connection = _PinnedGoogleConnection(HOST, timeout=15, context=ssl.create_default_context())
    ordinal = trace.begin(phase)
    try:
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {token}",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            trace.finish(ordinal, "redirect_refused")
            raise GoogleUnavailable("Google returned a redirect")
        if response.getheader("Content-Encoding", "identity") != "identity":
            trace.finish(ordinal, "encoding_refused")
            raise GoogleUnavailable("Google returned encoded content")
        declared = response.getheader("Content-Length")
        if declared is not None and (not declared.isascii() or not declared.isdecimal() or int(declared) > limit):
            trace.finish(ordinal, "limit_refused")
            raise GoogleUnavailable("Google response exceeds byte limit")
        body = bytearray()
        while len(body) <= limit:
            part = response.read(min(16_384, limit + 1 - len(body)))
            if part:
                trace.observed(ordinal, len(part))
            body.extend(part)
            if not part:
                break
        if len(body) > limit:
            trace.finish(ordinal, "limit_refused")
            raise GoogleUnavailable("Google response exceeds byte limit")
        trace.finish(ordinal, f"http_{response.status}")
        return response.status, bytes(body), response.getheader("Content-Type", "")
    except (OSError, http.client.HTTPException) as error:
        trace.finish(ordinal, "transport_unknown")
        raise GoogleUnavailable("Google request failed") from error
    finally:
        connection.close()


class GoogleDriveReader:
    def __init__(self, task: TaskDescriptor, tokens: TokenVault) -> None:
        task.validate()
        self.task = task
        self.tokens = tokens
        self.trace = ProviderTrace()

    def set_attempt_observer(self, observer: ProviderAttemptObserver) -> None:
        self.trace.observer = observer

    def _metadata(self, command: ReadCommand) -> tuple[dict, str]:
        if command not in self.task.calls():
            raise GoogleDenied("document is outside approved task")
        if int(time.time()) >= self.task.expires_at:
            raise GoogleDenied("task expired")
        lease = self.tokens.lease(self.task)
        file_id = quote(command.file_id, safe="")
        metadata_path = f"/drive/v3/files/{file_id}?fields=id,mimeType,size,trashed,capabilities(canDownload)"
        status, body, content_type = _get(metadata_path, lease.access_token, METADATA_LIMIT,
                                          self.trace, "metadata")
        if status in {401, 403, 404}:
            raise GoogleDenied("Google refused document metadata")
        if status != 200 or "application/json" not in content_type:
            raise GoogleUnavailable("Google metadata request was unsuccessful")
        try:
            metadata = json.loads(body)
        except (ValueError, UnicodeDecodeError) as error:
            raise GoogleUnavailable("Google metadata is malformed") from error
        if not isinstance(metadata, dict) or metadata.get("id") != command.file_id or metadata.get("trashed") is True:
            raise GoogleDenied("Google document metadata did not match")
        capabilities = metadata.get("capabilities")
        if not isinstance(capabilities, dict) or capabilities.get("canDownload") is not True:
            raise GoogleDenied("Google does not permit download")
        mime = metadata.get("mimeType")
        if mime not in {DOC_MIME, TEXT_MIME}:
            raise GoogleDenied("unsupported Google document type")
        if mime == TEXT_MIME:
            size = metadata.get("size")
            if size is not None and (not str(size).isdecimal() or int(size) > command.max_bytes):
                raise GoogleDenied("document exceeds approved byte limit")
        return metadata, lease.access_token

    def inspect_exact(self, command: ReadCommand) -> None:
        """Check employee-readable metadata without fetching document content."""
        self.trace = ProviderTrace(observer=self.trace.observer)
        self._metadata(command)

    def read_exact(self, command: ReadCommand) -> bytes:
        self.trace = ProviderTrace(observer=self.trace.observer)
        metadata, access_token = self._metadata(command)
        file_id = quote(command.file_id, safe="")
        mime = metadata["mimeType"]
        if mime == DOC_MIME:
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
