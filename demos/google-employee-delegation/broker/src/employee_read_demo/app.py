"""Loopback-only employee workbench for Google login, consent and enrollment."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import json
import stat
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_sessions import BrowserSession, BrowserSessionStore, SessionDenied
from .admission import AdmissionDenied
from .demo_co_contract import (
    CompanyImport, OperatorPins, ImportStatus,
    import_company, inspect_exports,
)
from .enrollment import EnrollmentDenied, EnrollmentStore, VerifiedGoogleSubject
from .google_oauth import GoogleOAuth, GoogleOAuthConfig, OAuthRejected, OAuthStateStore
from .token_store import TokenVault

COOKIE = "ap070_session"
MAX_JSON = 16_384


def _b64(value: str, *, max_bytes: int) -> bytes:
    if not isinstance(value, str) or len(value) > max_bytes * 2 or not value.isascii():
        raise ValueError("encoded value is outside bounds")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not 1 <= len(raw) <= max_bytes:
        raise ValueError("decoded value is outside bounds")
    return raw


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


@dataclass(frozen=True)
class Workbench:
    sessions: BrowserSessionStore
    oauth: GoogleOAuth | None
    enrollment: EnrollmentStore
    vault: TokenVault | None
    company: CompanyImport | None
    status: ImportStatus
    origin: str


class Handler(BaseHTTPRequestHandler):
    server: "WorkbenchServer"

    def log_message(self, format: str, *args: object) -> None:
        # Request paths can contain OAuth authorization codes; never log them.
        pass

    @property
    def workbench(self) -> Workbench:
        return self.server.workbench

    def _headers(self, content_type: str, length: int, *, cookie: str | None = None) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if cookie is not None:
            age = 0 if cookie == "" else 3600
            self.send_header("Set-Cookie", f"{COOKIE}={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}")

    def _json(self, status: HTTPStatus, value: object, *, cookie: str | None = None) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8", len(body), cookie=cookie)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, *, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self._headers("text/plain; charset=utf-8", 0, cookie=cookie)
        self.end_headers()

    def _cookie(self) -> str | None:
        try:
            parsed = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = parsed.get(COOKIE)
            return None if morsel is None else morsel.value
        except Exception:
            return None

    def _session(self, *, create: bool = False) -> tuple[BrowserSession, bool]:
        cookie = self._cookie()
        if cookie:
            try:
                return self.workbench.sessions.get(cookie), False
            except SessionDenied:
                pass
        if not create:
            raise SessionDenied("browser session is unavailable")
        return self.workbench.sessions.create(), True

    def _json_body(self, session: BrowserSession) -> dict:
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.workbench.origin:
            raise SessionDenied("request origin is unavailable")
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            raise ValueError("JSON content type is required")
        self.workbench.sessions.check_csrf(session, self.headers.get("X-CSRF-Token", ""))
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValueError("content length is required") from error
        if not 1 <= size <= MAX_JSON:
            raise ValueError("JSON body is outside bounds")
        document = json.loads(self.rfile.read(size), object_pairs_hook=_unique_pairs)
        if type(document) is not dict:
            raise ValueError("JSON object is required")
        return document

    def _check_host(self) -> None:
        if self.headers.get("Host") != urlsplit(self.workbench.origin).netloc:
            raise SessionDenied("request host is unavailable")

    def do_GET(self) -> None:
        try:
            self._check_host()
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                body = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
                        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<title>Auths employee delegation</title><body>"
                        "<h1>Employee to agent Google read delegation</h1>"
                        "<p id='status'>Checking company prerequisites…</p>"
                        "<p id='employee'></p><p id='drive'></p>"
                        "<a href='/api/v1/google/authorize?kind=login'>Sign in with Google</a> "
                        "<a href='/api/v1/google/authorize?kind=connect'>Connect Drive</a>"
                        "<button id='disconnect' hidden>Disconnect Drive</button>"
                        "<script src='/workbench.js'></script></body></html>").encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self._headers("text/html; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/workbench.js":
                body = ("fetch('/api/v1/session').then(r=>r.json()).then(s=>{"
                        "document.getElementById('status').textContent='Google: '+s.google_status;"
                        "document.getElementById('employee').textContent="
                        "s.subject?'Signed in as Google subject '+s.subject:'No employee signed in';"
                        "document.getElementById('drive').textContent="
                        "s.drive_connected?'Drive connected':'Drive not connected';"
                        "let d=document.getElementById('disconnect');d.hidden=!s.drive_connected;"
                        "d.onclick=()=>fetch('/api/v1/google/disconnect',{method:'POST',"
                        "headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf},"
                        "body:'{}'}).then(()=>location.reload());"
                        "});").encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self._headers("application/javascript; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/v1/session":
                session, created = self._session(create=True)
                drive_connected = bool(
                    session.connection_id and session.issuer and session.subject
                    and self.workbench.vault is not None
                    and self.workbench.vault.active_connection(
                        session.connection_id, session.issuer, session.subject,
                    )
                )
                if session.connection_id and not drive_connected:
                    self.workbench.sessions.clear_connection(session)
                self._json(HTTPStatus.OK, {
                    "contract": "auths.employee-session/v1",
                    "google_status": self.workbench.status.google,
                    "company_id": None if self.workbench.company is None else self.workbench.company.bundle["company_id"],
                    "subject": session.subject,
                    "drive_connected": drive_connected,
                    "csrf": session.csrf,
                }, cookie=session.cookie if created else None)
                return
            if parsed.path == "/api/v1/google/authorize":
                if self.workbench.company is None or self.workbench.oauth is None:
                    self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Google is not configured"})
                    return
                kind = parse_qs(parsed.query).get("kind", ["login"])
                if kind not in (["login"], ["connect"]):
                    raise ValueError("unsupported Google authorization kind")
                session, created = self._session(create=kind == ["login"])
                uri, _ = self.workbench.oauth.begin(kind[0], browser_cookie=session.cookie,
                                                     expected_subject=session.subject if kind == ["connect"] else None)
                self._redirect(uri, cookie=session.cookie if created else None)
                return
            if parsed.path == "/api/v1/google/callback":
                if self.workbench.company is None or self.workbench.oauth is None:
                    raise OAuthRejected("Google is unavailable")
                query = parse_qs(parsed.query)
                state = query.get("state", [None])
                code = query.get("code", [None])
                if len(state) != 1 or len(code) != 1 or not state[0] or not code[0]:
                    raise OAuthRejected("Google callback is incomplete")
                session, _ = self._session()
                result = self.workbench.oauth.complete(
                    state=state[0], code=code[0], browser_cookie=session.cookie,
                )
                if result.kind == "login":
                    rotated = self.workbench.sessions.login(
                        session, issuer=result.issuer, subject=result.subject,
                    )
                    self._redirect("/", cookie=rotated.cookie)
                    return
                if (session.issuer, session.subject) != (result.issuer, result.subject):
                    raise OAuthRejected("Drive consent account changed")
                if self.workbench.vault is None:
                    raise OAuthRejected("Drive credential store is unavailable")
                binding = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("connect", result.issuer, result.subject),
                )
                connection_id = self.workbench.vault.link(
                    company=binding.company_id, employee_principal=binding.principal,
                    binding_ref=binding.binding_ref, identity=result,
                )
                self.workbench.sessions.set_connection(session, connection_id)
                self._redirect("/")
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (ValueError, SessionDenied, OAuthRejected, EnrollmentDenied, AdmissionDenied) as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})

    def do_POST(self) -> None:
        try:
            self._check_host()
            session, _ = self._session()
            body = self._json_body(session)
            path = urlsplit(self.path).path
            if path == "/api/v1/session/logout":
                self.workbench.sessions.logout(session)
                self._json(HTTPStatus.OK, {"status": "signed_out"}, cookie="")
                return
            if path == "/api/v1/google/disconnect":
                if not session.connection_id or self.workbench.vault is None:
                    raise SessionDenied("Drive connection is unavailable")
                self.workbench.vault.disconnect(session.connection_id)
                self.workbench.sessions.clear_connection(session)
                self._json(HTTPStatus.OK, {"status": "disconnected"})
                return
            if path in {"/api/v1/employees/enroll/prepare", "/api/v1/employees/enroll"}:
                if self.workbench.company is None or not session.issuer or not session.subject:
                    raise EnrollmentDenied("employee enrollment is unavailable")
                identity = VerifiedGoogleSubject("login", session.issuer, session.subject)
                packet = _b64(body.get("identity_packet", ""), max_bytes=4096)
                if path.endswith("/prepare"):
                    nonce, message = self.workbench.enrollment.prepare(
                        self.workbench.company, identity, packet,
                    )
                    self._json(HTTPStatus.OK, {"nonce": nonce, "message": base64.urlsafe_b64encode(message).decode("ascii")})
                    return
                signature = _b64(body.get("signature", ""), max_bytes=256)
                nonce = body.get("nonce")
                if not isinstance(nonce, str) or len(nonce) > 128:
                    raise ValueError("enrollment nonce is invalid")
                binding = asyncio.run(self.workbench.enrollment.complete(
                    self.workbench.company, identity, nonce, packet, signature,
                ))
                self._json(HTTPStatus.OK, {"principal": binding.principal,
                                           "binding_ref": binding.binding_ref})
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (ValueError, binascii.Error, SessionDenied, EnrollmentDenied) as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})


class WorkbenchServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], workbench: Workbench) -> None:
        super().__init__(address, Handler)
        self.workbench = workbench


def _private_file(path: Path, max_bytes: int) -> bytes:
    if (not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("operator secret file must be private and bounded")
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AP-SPEC-070 loopback workbench")
    parser.add_argument("--state-db", required=True, type=Path)
    parser.add_argument("--connections", type=Path)
    parser.add_argument("--access-expectations", type=Path)
    parser.add_argument("--scenario-result", type=Path, action="append", default=[])
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--oauth-config", type=Path)
    parser.add_argument("--fernet-key", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    origin = f"http://127.0.0.1:{args.port}"
    pins = None
    if args.pins is not None:
        pins = OperatorPins(**json.loads(_private_file(args.pins, 4096)))
    status = inspect_exports(args.connections, args.access_expectations, pins,
                             tuple(args.scenario_result))
    company = None
    if status.google == "ready" and pins and args.connections and args.access_expectations:
        company = import_company(args.connections, args.access_expectations, pins,
                                 scenario_results=tuple(args.scenario_result))
    sessions = BrowserSessionStore(args.state_db)
    oauth = None
    if args.oauth_config is not None:
        config = GoogleOAuthConfig(**json.loads(_private_file(args.oauth_config, 4096)))
        config.validate()
        if config.redirect_uri != origin + "/api/v1/google/callback":
            parser.error("Google redirect URI must match this loopback workbench")
        oauth = GoogleOAuth(config, OAuthStateStore(args.state_db))
    vault = None
    if args.fernet_key is not None:
        if oauth is None:
            parser.error("credential key requires Google OAuth configuration")
        vault = TokenVault(args.state_db, encryption_key=_private_file(args.fernet_key, 128).strip(),
                           client_id=oauth.config.client_id,
                           refresh_client_secret=oauth.config.client_secret)
    workbench = Workbench(sessions, oauth, EnrollmentStore(args.state_db), vault,
                          company, status, origin)
    with WorkbenchServer(("127.0.0.1", args.port), workbench) as server:
        print(f"Auths workbench: {origin} (Google: {status.google})", flush=True)
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
