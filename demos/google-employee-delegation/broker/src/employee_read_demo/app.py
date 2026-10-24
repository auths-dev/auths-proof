"""Loopback-only employee workbench for Google login, consent and enrollment."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import json
import stat
from dataclasses import dataclass
from dataclasses import asdict
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .browser_sessions import BrowserSession, BrowserSessionStore, SessionDenied
from .admission import AdmissionDenied
from .agent_registry import AgentDenied, AgentRegistry
from .demo_co_contract import (
    CompanyImport, OperatorPins, ImportStatus,
    import_company, inspect_exports,
)
from .enrollment import EnrollmentDenied, EnrollmentStore, VerifiedGoogleSubject
from .google_oauth import GoogleOAuth, GoogleOAuthConfig, OAuthRejected, OAuthStateStore
from .token_store import TokenVault
from .task_proposals import TaskDenied, TaskProposalStore
from .task_approval import ApprovalDenied, TaskApprovalStore
from .task_activation import ActivationDenied, TaskActivationStore
from .operator_authority import OperatorDenied
from .google_drive import GoogleDenied, GoogleUnavailable, GoogleDriveReader
from .agent_transport import AgentTransport, AgentTransportDenied
from .receipts import ReceiptStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

COOKIE = "ap070_session"
MAX_JSON = 16_384
MAX_AGENT_JSON = 800_000


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
    agents: AgentRegistry
    proposals: TaskProposalStore
    approvals: TaskApprovalStore
    activations: TaskActivationStore
    vault: TokenVault | None
    company: CompanyImport | None
    status: ImportStatus
    origin: str
    trusted_template: bytes | None = None
    expected_root: str | None = None
    agent_transport: AgentTransport | None = None


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

    def _agent_json_body(self, expected_fields: set[str]) -> dict:
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.workbench.origin:
            raise SessionDenied("request origin is unavailable")
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            raise ValueError("JSON content type is required")
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValueError("content length is required") from error
        if not 1 <= size <= MAX_AGENT_JSON:
            raise ValueError("agent JSON body is outside bounds")
        document = json.loads(self.rfile.read(size), object_pairs_hook=_unique_pairs)
        if type(document) is not dict or set(document) != expected_fields:
            raise ValueError("agent request fields are invalid")
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
            if parsed.path.startswith("/api/v1/tasks/") and parsed.path.endswith("/package"):
                if self.workbench.company is None or self.workbench.agent_transport is None:
                    raise AgentTransportDenied("task package is unavailable")
                parts = parsed.path.split("/")
                if len(parts) != 6 or not parts[4] or parts[5] != "package":
                    raise ValueError("task package path is invalid")
                session, _ = self._session()
                if not session.issuer or not session.subject:
                    raise SessionDenied("employee session is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                package = self.workbench.agent_transport.export_package(parts[4], employee)
                self._json(HTTPStatus.OK, package)
                return
            if parsed.path.startswith("/api/v1/receipts/"):
                receipt_id = parsed.path.removeprefix("/api/v1/receipts/")
                if not receipt_id or len(receipt_id) > 128 or "/" in receipt_id:
                    raise ValueError("receipt ID is invalid")
                if self.workbench.agent_transport is None or self.workbench.company is None:
                    raise AgentTransportDenied("receipt is unavailable")
                session, _ = self._session()
                if not session.issuer or not session.subject:
                    raise SessionDenied("employee session is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                receipts = self.workbench.agent_transport.receipts
                receipt = receipts.load(receipt_id)
                if receipt is None or (receipt.payload.get("company_id"),
                                       receipt.payload.get("identity_binding_ref"),
                                       receipt.payload.get("employee_principal")) != (
                                           employee.company_id, employee.binding_ref,
                                           employee.principal):
                    raise AgentTransportDenied("receipt is unavailable")
                from .receipts import verify_receipt
                if not verify_receipt(receipt, receipts.public_key):
                    raise AgentTransportDenied("receipt signature is invalid")
                self._json(HTTPStatus.OK, {"verified": True,
                                           "payload": receipt.payload,
                                           "signature": receipt.signature})
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
        except (ValueError, SessionDenied, OAuthRejected, EnrollmentDenied,
                AdmissionDenied, AgentTransportDenied) as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})

    def do_POST(self) -> None:
        try:
            self._check_host()
            path = urlsplit(self.path).path
            if path in {"/api/v1/tasks/challenge", "/api/v1/tools/call"}:
                if self.workbench.agent_transport is None:
                    raise AgentTransportDenied("agent transport is unavailable")
                fields = ({"task_id", "body_digest"} if path.endswith("/challenge")
                          else {"task_id", "challenge", "proof", "action"})
                body = self._agent_json_body(fields)
                task_id = body["task_id"]
                if not isinstance(task_id, str) or not 1 <= len(task_id) <= 256:
                    raise ValueError("task ID is invalid")
                if path.endswith("/challenge"):
                    digest = _b64(body["body_digest"], max_bytes=32)
                    challenge = self.workbench.agent_transport.issue_challenge(task_id, digest)
                    self._json(HTTPStatus.OK, {
                        "challenge": base64.urlsafe_b64encode(challenge.challenge).decode("ascii"),
                        "issued_at": challenge.issued_at,
                        "expires_at": challenge.expires_at,
                    })
                    return
                challenge = _b64(body["challenge"], max_bytes=32)
                proof = _b64(body["proof"], max_bytes=262_144)
                action = _b64(body["action"], max_bytes=262_144)
                outcome = self.workbench.agent_transport.execute(
                    task_id, challenge, proof, action,
                )
                self._json(HTTPStatus.OK, {
                    "status": "release_committed",
                    "content": base64.urlsafe_b64encode(outcome.content).decode("ascii"),
                    "native_code": outcome.native_code,
                    "receipt_id": outcome.receipt_id,
                    "transport_delivery": "unknown",
                })
                return
            session, _ = self._session()
            body = self._json_body(session)
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
            if path.startswith("/api/v1/tasks/") and path.endswith("/revoke"):
                parts = path.split("/")
                if len(parts) != 6 or not parts[4] or parts[5] != "revoke":
                    raise ValueError("task revoke path is invalid")
                if self.workbench.company is None or not session.issuer or not session.subject:
                    raise SessionDenied("employee session is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                if body:
                    raise ValueError("revoke body must be empty")
                self.workbench.approvals.revoke(parts[4], employee)
                self._json(HTTPStatus.OK, {"status": "revoked", "task_id": parts[4]})
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
            if path in {"/api/v1/agents/register/prepare", "/api/v1/agents/register"}:
                if self.workbench.company is None or not session.issuer or not session.subject:
                    raise AgentDenied("agent registration is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                packet = _b64(body.get("identity_packet", ""), max_bytes=4096)
                if path.endswith("/prepare"):
                    nonce, message, principal = self.workbench.agents.prepare(employee, packet)
                    self._json(HTTPStatus.OK, {
                        "nonce": nonce, "agent_principal": principal,
                        "message": base64.urlsafe_b64encode(message).decode("ascii"),
                    })
                    return
                nonce = body.get("nonce")
                if not isinstance(nonce, str) or len(nonce) > 128:
                    raise ValueError("agent registration nonce is invalid")
                signature = _b64(body.get("signature", ""), max_bytes=256)
                agent = asyncio.run(self.workbench.agents.complete(
                    employee, nonce, packet, signature,
                ))
                self._json(HTTPStatus.OK, {"agent_principal": agent.agent_principal})
                return
            if path == "/api/v1/tasks/prepare":
                if (self.workbench.company is None or self.workbench.vault is None
                        or not session.issuer or not session.subject
                        or not session.connection_id):
                    raise TaskDenied("task preparation is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                agent_principal = body.get("agent_principal")
                resources = body.get("logical_resource_ids")
                purpose = body.get("purpose")
                if (not isinstance(agent_principal, str)
                        or not isinstance(resources, list)
                        or any(not isinstance(item, str) for item in resources)
                        or not isinstance(purpose, str)):
                    raise ValueError("task selection is invalid")
                agent = self.workbench.agents.lookup(employee, agent_principal)
                task = self.workbench.proposals.prepare(
                    company=self.workbench.company, employee=employee,
                    agent=agent, connection_id=session.connection_id,
                    logical_resource_ids=tuple(resources), purpose=purpose,
                    vault=self.workbench.vault,
                    inspector_factory=lambda descriptor: GoogleDriveReader(
                        descriptor, self.workbench.vault,
                    ),
                )
                self._json(HTTPStatus.OK, {
                    "status": "prepared_only", "task": asdict(task),
                    "task_commitment": task.digest,
                    "approved_calls": [asdict(call) for call in task.calls()],
                })
                return
            if path in {"/api/v1/tasks/authorize/prepare", "/api/v1/tasks/authorize"}:
                if (self.workbench.company is None or self.workbench.vault is None
                        or not session.issuer or not session.subject):
                    raise ApprovalDenied("task authorization is unavailable")
                task_id = body.get("task_id")
                if not isinstance(task_id, str) or not 1 <= len(task_id) <= 256:
                    raise ValueError("task ID is invalid")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                if path.endswith("/prepare"):
                    task = self.workbench.proposals.get(task_id, employee)
                    pending = self.workbench.approvals.prepare(
                        task_id, employee, self.workbench.vault,
                    )
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_employee_signature",
                        "task": asdict(task),
                        "task_commitment": pending.task_commitment,
                        "approved_calls": [asdict(call) for call in task.calls()],
                        "signing_preimage": base64.urlsafe_b64encode(
                            pending.signing_preimage).decode("ascii"),
                    })
                    return
                signature = _b64(body.get("signature", ""), max_bytes=64)
                signed = self.workbench.approvals.complete(
                    task_id, employee, signature, self.workbench.vault,
                )
                self._json(HTTPStatus.OK, {
                    "status": "approved_pending_native_activation",
                    "task_id": signed.task_id,
                })
                return
            if path in {"/api/v1/tasks/activate/prepare", "/api/v1/tasks/activate"}:
                if (self.workbench.company is None or self.workbench.vault is None
                        or self.workbench.trusted_template is None
                        or self.workbench.expected_root is None
                        or not session.issuer or not session.subject):
                    raise ActivationDenied("native task activation is unavailable")
                task_id = body.get("task_id")
                if not isinstance(task_id, str) or not 1 <= len(task_id) <= 256:
                    raise ValueError("task ID is invalid")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                if path.endswith("/prepare"):
                    call_index = body.get("call_index")
                    if type(call_index) is not int:
                        raise ValueError("call index is invalid")
                    challenge = self.workbench.activations.begin(
                        task_id, employee, self.workbench.vault, call_index,
                    )
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_agent_signature",
                        "task_id": task_id,
                        "agent_principal": challenge.agent_principal,
                        "call": challenge.call,
                        "challenge": base64.urlsafe_b64encode(challenge.challenge).decode("ascii"),
                        "signing_preimage": base64.urlsafe_b64encode(
                            challenge.signing_preimage).decode("ascii"),
                        "expires_at": challenge.expires_at,
                    })
                    return
                challenge = _b64(body.get("challenge", ""), max_bytes=32)
                signature = _b64(body.get("signature", ""), max_bytes=64)
                task = self.workbench.activations.complete(
                    task_id, employee, self.workbench.vault, challenge, signature,
                    self.workbench.trusted_template, self.workbench.expected_root,
                )
                self._json(HTTPStatus.OK, {
                    "status": "active", "task_id": task.task_id,
                    "task_commitment": task.digest,
                })
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (ValueError, binascii.Error, SessionDenied, EnrollmentDenied,
                AgentDenied, TaskDenied, ApprovalDenied, ActivationDenied, OperatorDenied,
                AgentTransportDenied, AdmissionDenied, GoogleDenied,
                PermissionError) as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})
        except GoogleUnavailable:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE,
                       {"error": "Google document check is unavailable"})


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
    parser.add_argument("--trust-file", type=Path)
    parser.add_argument("--receipt-key", type=Path)
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
    trusted_template = None
    expected_root = None
    if args.trust_file is not None:
        from auths import _native

        manifest = json.loads(_private_file(args.trust_file, 262_144))
        if (manifest.get("contract") != "auths.google-read-root/v1"
                or manifest.get("service") != "atlas-drive"
                or manifest.get("configuration_id") != bytes(
                    _native.self_contained_configuration()).hex()
                or company is None or manifest.get("company_id") != company.bundle["company_id"]):
            parser.error("operator trust file does not match accepted company and SDK")
        expected_root = manifest.get("root_principal")
        trusted_template = base64.urlsafe_b64decode(manifest["trusted_template"])
        _native.parse_trusted_context(trusted_template)
    agent_transport = None
    if company is not None and vault is not None and trusted_template is not None:
        if args.receipt_key is None:
            parser.error("live agent transport requires a private receipt signing key")
        receipts = ReceiptStore(args.state_db, Ed25519PrivateKey.from_private_bytes(
            _private_file(args.receipt_key, 32),
        ))
        agent_transport = AgentTransport(
            args.state_db, vault=vault, trusted_template=trusted_template,
            expected_root=expected_root, receipts=receipts,
        )
    workbench = Workbench(sessions, oauth, EnrollmentStore(args.state_db),
                          AgentRegistry(args.state_db), TaskProposalStore(args.state_db),
                          TaskApprovalStore(args.state_db), TaskActivationStore(args.state_db),
                          vault, company, status, origin, trusted_template, expected_root,
                          agent_transport)
    with WorkbenchServer(("127.0.0.1", args.port), workbench) as server:
        print(f"Auths workbench: {origin} (Google: {status.google})", flush=True)
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
