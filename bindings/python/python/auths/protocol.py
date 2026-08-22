from __future__ import annotations

import asyncio as _asyncio
import ssl as _ssl
import struct as _struct
import time as _time
import urllib.error as _urlerror
import urllib.parse as _urlparse
import urllib.request as _urlrequest
from dataclasses import dataclass as _dataclass
from datetime import timedelta as _timedelta
from typing import Any as _Any, Literal as _Literal, Optional as _Optional, Protocol as _Protocol, cast as _cast

from ._public import auths_error as _auths_error, error_info as _error_info, runtime_info as _runtime_info
from .verify import AuthorizedVerification, UnsuccessfulVerification, VerificationInput, VerificationMetrics, VerificationResult

_MEDIA: _Literal["application/vnd.auths.remote-verification.v1+cbor"] = "application/vnd.auths.remote-verification.v1+cbor"
_TOKEN = object()


def _head(major: int, value: int) -> bytes:
    if value < 24: return bytes([(major << 5) | value])
    if value <= 0xFF: return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF: return bytes([(major << 5) | 25]) + _struct.pack(">H", value)
    if value <= 0xFFFFFFFF: return bytes([(major << 5) | 26]) + _struct.pack(">I", value)
    return bytes([(major << 5) | 27]) + _struct.pack(">Q", value)


def _encode(value: _Any) -> bytes:
    if value is None: return b"\xf6"
    if isinstance(value, bool): return b"\xf5" if value else b"\xf4"
    if isinstance(value, int) and value >= 0: return _head(0, value)
    if isinstance(value, bytes): return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode(); return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)): return _head(4, len(value)) + b"".join(_encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: _encode(item[0]))
        return _head(5, len(items)) + b"".join(_encode(k) + _encode(v) for k, v in items)
    raise TypeError("unsupported CBOR value")


def _decode(data: bytes) -> _Any:
    view = memoryview(data)
    def take(offset: int) -> tuple[_Any, int]:
        if offset >= len(view): raise ValueError
        initial = view[offset]; offset += 1; major, additional = initial >> 5, initial & 31
        if additional < 24: length = additional
        elif additional == 24: length = view[offset]; offset += 1
        elif additional == 25: length = _struct.unpack_from(">H", view, offset)[0]; offset += 2
        elif additional == 26: length = _struct.unpack_from(">I", view, offset)[0]; offset += 4
        elif additional == 27: length = _struct.unpack_from(">Q", view, offset)[0]; offset += 8
        elif major == 7 and additional in (20, 21, 22): return ({20: False, 21: True, 22: None}[additional], offset)
        else: raise ValueError
        if major == 0: return length, offset
        if major in (2, 3):
            end = offset + length
            if end > len(view): raise ValueError
            raw = bytes(view[offset:end]); return (raw if major == 2 else raw.decode("utf-8"), end)
        if major == 4:
            values: _Any = []
            for _ in range(length): value, offset = take(offset); values.append(value)
            return values, offset
        if major == 5:
            values = {}
            for _ in range(length):
                key, offset = take(offset); value, offset = take(offset)
                if key in values: raise ValueError
                values[key] = value
            return values, offset
        raise ValueError
    value, end = take(0)
    if end != len(view): raise ValueError
    return value


@_dataclass(frozen=True)
class TransportRequest:
    url: str
    method: _Literal["POST"]
    media_type: _Literal["application/vnd.auths.remote-verification.v1+cbor"]
    accept: _Literal["application/vnd.auths.remote-verification.v1+cbor"]
    body: bytes
    deadline_unix_ms: int
    maximum_response_bytes: int


@_dataclass(frozen=True)
class TransportResponse:
    status: int
    media_type: str
    body: bytes


class BoundedTransport(_Protocol):
    @property
    def contract(self) -> _Literal["bounded-byte-transport/2"]: ...
    async def send(self, request: TransportRequest) -> TransportResponse: ...
    async def aclose(self) -> None: ...


class _HttpTransport:
    contract: _Literal["bounded-byte-transport/2"] = "bounded-byte-transport/2"
    def __init__(self, token: str) -> None: self._token = token
    async def send(self, request: TransportRequest) -> TransportResponse:
        remaining = max(0.001, (request.deadline_unix_ms - int(_time.time() * 1000)) / 1000)
        value = _urlrequest.Request(request.url, data=request.body, method="POST", headers={"Authorization": "Bearer " + self._token, "Content-Type": request.media_type, "Accept": request.accept, "Auths-Error-Registry-SHA256": _runtime_info().error_registry_digest})
        def send() -> TransportResponse:
            opener = _urlrequest.build_opener(_urlrequest.HTTPSHandler(context=_ssl.create_default_context()), _NoRedirect())
            with opener.open(value, timeout=remaining) as response:
                body = response.read(request.maximum_response_bytes + 1)
                if len(body) > request.maximum_response_bytes: raise ValueError("response over limit")
                return TransportResponse(response.status, response.headers.get_content_type(), body)
        return await _asyncio.to_thread(send)
    async def aclose(self) -> None: return None


class _NoRedirect(_urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req: _Any, fp: _Any, code: int, msg: str, headers: _Any, newurl: str) -> None:
        raise _urlerror.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class RemoteVerifier:
    def __init__(self, token: object, endpoint: str, transport: BoundedTransport, owns: bool, timeout: _timedelta, maximum: int, insecure: bool) -> None:
        if token is not _TOKEN: raise TypeError("RemoteVerifier is sealed")
        parsed = _urlparse.urlsplit(endpoint)
        loopback = parsed.hostname in ("127.0.0.1", "::1")
        if (parsed.scheme != "https" and not (insecure and parsed.scheme == "http" and loopback)) or not parsed.netloc or parsed.username or parsed.path not in ("", "/") or parsed.query or parsed.fragment: raise ValueError("endpoint must be an HTTPS origin")
        seconds = timeout.total_seconds()
        if not 0.001 <= seconds <= 300 or seconds * 1000 != int(seconds * 1000): raise ValueError("timeout outside bounds")
        if not 1024 <= maximum <= 16 * 1024 * 1024: raise ValueError("maximum response outside bounds")
        self._url, self._transport, self._owns, self._timeout, self._maximum = parsed.scheme + "://" + parsed.netloc + "/v2/verification/authorize", transport, owns, seconds, maximum
        self._state = "new"
    async def __aenter__(self) -> "RemoteVerifier":
        if self._state != "new": raise RuntimeError("auths client is not open")
        self._state = "open"; return self
    async def __aexit__(self, *exc: object) -> None: await self.aclose()
    async def aclose(self) -> None:
        if self._state == "closed": return
        self._state = "closed"
        if self._owns: await self._transport.aclose()
    async def verify(self, input: VerificationInput, /) -> VerificationResult:
        if self._state != "open": raise RuntimeError("auths client is not open")
        correlation = f"auths-{_time.time_ns():x}"
        digest = bytes.fromhex(_runtime_info().error_registry_digest)
        body = _encode({0: 1, 1: input.proof, 2: input.action, 3: input.trusted_context, 4: correlation, 5: digest})
        request = TransportRequest(self._url, "POST", _MEDIA, _MEDIA, body, int((_time.time() + self._timeout) * 1000), self._maximum)
        try: response = await _asyncio.wait_for(self._transport.send(request), self._timeout)
        except _asyncio.TimeoutError: raise _auths_error("remote.timeout")
        except Exception as exc: raise _auths_error("remote.transport-unavailable", summary=str(exc)[:256])
        if response.status != 200 or response.media_type.split(";", 1)[0].strip() != _MEDIA: raise _auths_error("remote.response-malformed")
        try:
            raw = _decode(response.body)
            if raw[0] != 1 or raw[4] != correlation or raw[10] != digest: raise ValueError
            kinds, stages = ("authorized", "denied", "indeterminate"), ("decode", "resolve", "principal-control", "authority", "complete")
            kind = kinds[raw[1]]
            stage = _cast(_Literal["decode", "resolve", "principal-control", "authority", "complete"], stages[raw[3]])
            metrics_raw = raw[5]
            metrics = VerificationMetrics(*(int(metrics_raw[index]) for index in range(7)))
            code = str(raw[2])
            required = None if raw[6] is None else bytes(raw[6])
            executed = bytes(raw[7])
            decision = bytes(raw[8])
            if kind == "authorized":
                return AuthorizedVerification("authorized", code, stage, correlation, metrics, required, executed, decision)
            negative_kind: _Literal["denied", "indeterminate"] = "denied" if kind == "denied" else "indeterminate"
            return UnsuccessfulVerification(negative_kind, code, stage, correlation, metrics, required, executed, decision, _error_info(raw[9].get("code", "core.authorization-indeterminate")))
        except Exception: raise _auths_error("remote.response-malformed")


def connect_remote_verifier(*, endpoint: str, access_token: str, timeout: _timedelta = _timedelta(seconds=30), maximum_response_bytes: int = 8 * 1024 * 1024, allow_insecure_loopback: bool = False) -> RemoteVerifier:
    if not access_token or len(access_token.encode()) > 8192: raise ValueError("invalid access token")
    return RemoteVerifier(_TOKEN, endpoint, _HttpTransport(access_token), True, timeout, maximum_response_bytes, allow_insecure_loopback)


def remote_verifier_from_transport(endpoint: str, transport: BoundedTransport, /, *, owns_transport: bool = False, timeout: _timedelta = _timedelta(seconds=30), maximum_response_bytes: int = 8 * 1024 * 1024, allow_insecure_loopback: bool = False) -> RemoteVerifier:
    if transport.contract != "bounded-byte-transport/2": raise ValueError("unsupported bounded transport contract")
    return RemoteVerifier(_TOKEN, endpoint, transport, owns_transport, timeout, maximum_response_bytes, allow_insecure_loopback)


__all__ = ["TransportRequest", "TransportResponse", "BoundedTransport", "RemoteVerifier", "connect_remote_verifier", "remote_verifier_from_transport"]
