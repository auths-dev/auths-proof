"""Loopback-only employee workbench for Google login, consent and enrollment."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import json
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from dataclasses import asdict
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .browser_sessions import BrowserSession, BrowserSessionStore, SessionDenied
from .admission import AdmissionDenied, AdmissionStore
from .agent_registry import AgentDenied, AgentRegistry
from .demo_co_contract import (
    CompanyImport, ContractRejected, OperatorPins, ImportStatus,
    import_company, inspect_exports,
)
from .enrollment import EnrollmentDenied, EnrollmentStore, VerifiedGoogleSubject
from .google_oauth import GoogleOAuth, GoogleOAuthConfig, OAuthRejected, OAuthStateStore
from .token_store import TokenVault
from .task_proposals import TaskDenied, TaskProposalStore
from .contracts import valid_service
from .task_approval import ApprovalDenied, TaskApprovalStore
from .task_activation import ActivationDenied, TaskActivationStore
from .operator_authority import OperatorDenied
from .task_write_browser import TaskWriteBrowserFlow
from .task_write_confirmation import TaskWriteConfirmationFlow
from .task_write_card import _installation
from .task_write_package import load_task_write_package
from .google_create_handoff import (
    CreatedChildContinuationTarget, prepare_create_inputs,
)
from .google_create_preflight import preflight_jules_created_child
from .google_create_negative_handoff import (
    NegativeCreateTarget, load_v4_final_pins, validate_negative_create_setup,
)
from .google_populate_failure_handoff import (
    PopulateFailureTarget, validate_populate_failure_setup,
)
from .write_handoff import (
    WriteHandoffPins, validate_current_write_observation, validate_write_handoff,
)
from .jules_write_context import JulesWriteContext
from .finance_denial_handoff import FinanceDenialPins, validate_finance_denial
from .finance_write_grant_handoff import (
    FinanceWriteGrantPins, validate_finance_write_grant,
)
from .project_b_grants_handoff import ProjectBGrantPins, validate_project_b_grants
from .edit_rerun_handoff import (
    EditRerunPins, EditRerunTarget, LOGICAL_ID, validate_edit_rerun,
)
from .bounded_negative_handoff import (
    BoundedNegativePins, validate_bounded_negative,
)
from .google_write_credential import WriteCredentialPins
from .google_write_preflight import (
    BOUNDED_NEGATIVE_LOGICAL_ID, EditTarget, preflight_jules_edit,
)
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
    company: CompanyImport | JulesWriteContext | None
    status: ImportStatus
    origin: str
    trusted_template: bytes | None = None
    expected_root: str | None = None
    agent_transport: AgentTransport | None = None
    service: str | None = None
    write_browser: TaskWriteBrowserFlow | None = None
    write_evidence: Path | None = None
    write_pins: WriteHandoffPins | None = None
    write_confirmation: TaskWriteConfirmationFlow | None = None
    write_target: CreatedChildContinuationTarget | None = None
    finance_read_target: str | None = None
    edit_rerun_target: EditRerunTarget | None = None
    negative_create_target: NegativeCreateTarget | None = None
    populate_failure_target: PopulateFailureTarget | None = None
    project_b_exclusion_target: str | None = None


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
                session = self.workbench.sessions.get(cookie)
                if session.company is not None and (self.workbench.company is None or
                        session.company != self.workbench.company.bundle["company_id"]):
                    raise SessionDenied("browser session belongs to another company")
                return session, False
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

    def _write_bindings(self, session: BrowserSession):
        """Re-read Jules login, enrollment, agent and producer pins each step."""
        workbench = self.workbench
        if (workbench.company is None or workbench.write_browser is None
                or workbench.write_evidence is None or workbench.write_pins is None
                or not session.issuer or not session.subject
                or session.subject != workbench.write_pins.jules_subject
                or workbench.company.bundle["company_id"] != workbench.write_pins.company):
            raise OperatorDenied("Jules write task is unavailable")
        evidence = validate_write_handoff(workbench.write_evidence, workbench.write_pins)
        employee = workbench.enrollment.lookup(
            workbench.company,
            VerifiedGoogleSubject("login", session.issuer, session.subject),
        )
        installed = _installation(workbench.write_browser.installation_path)
        if installed["pins"]["connection_subject"] != session.subject:
            raise OperatorDenied("installed write account differs from Google login")
        agent = workbench.agents.lookup(employee, installed["pins"]["agent_principal"])
        with sqlite3.connect(workbench.sessions.path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            human_row = db.execute("""SELECT identity_packet FROM employee_bindings
                WHERE binding_ref=? AND principal=? AND status='active'""", (
                    employee.binding_ref, employee.principal,
                )).fetchone()
            agent_row = db.execute("""SELECT identity_packet FROM registered_agents
                WHERE company=? AND employee_binding=? AND agent_principal=?
                AND packet_digest=? AND status='active'""", (
                    agent.company_id, agent.employee_binding_ref,
                    agent.agent_principal, agent.identity_packet_sha256,
                )).fetchone()
        if human_row is None or agent_row is None:
            raise OperatorDenied("Jules or registered agent identity changed")
        return employee, agent, human_row[0], agent_row[0], evidence

    def do_GET(self) -> None:
        try:
            self._check_host()
            parsed = urlsplit(self.path)
            if parsed.path == "/" and not any(key in parse_qs(parsed.query, keep_blank_values=True)
                                               for key in ("state", "code", "error")):
                body = files("employee_read_demo").joinpath("web", "index.html").read_bytes()
                self.send_response(HTTPStatus.OK)
                self._headers("text/html; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path in {"/workbench.js", "/style.css"}:
                name = "workbench.js" if parsed.path.endswith(".js") else "style.css"
                body = files("employee_read_demo").joinpath("web", name).read_bytes()
                self.send_response(HTTPStatus.OK)
                self._headers("application/javascript; charset=utf-8" if name.endswith(".js")
                              else "text/css; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/v1/session":
                session, created = self._session(create=True)
                employee_principal = None
                if (self.workbench.company is not None
                        and session.issuer and session.subject):
                    try:
                        employee_principal = self.workbench.enrollment.lookup(
                            self.workbench.company,
                            VerifiedGoogleSubject(
                                "login", session.issuer, session.subject,
                            ),
                        ).principal
                    except EnrollmentDenied:
                        pass
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
                    "employee_principal": employee_principal,
                    "drive_connected": drive_connected,
                    "task_write_available": bool(
                        self.workbench.write_browser is not None
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
                    "task_write_confirmation_available": bool(
                        self.workbench.write_confirmation is not None
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
                    "task_read_only_available": bool(
                        self.workbench.write_browser is not None
                        and self.workbench.write_browser.read_only
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
                    "task_read_only_kind": (
                        "finance_denial" if self.workbench.finance_read_target is not None
                        else "project_b_exclusion"
                        if self.workbench.project_b_exclusion_target is not None
                        else None
                    ),
                    "task_write_paired_available": bool(
                        self.workbench.write_confirmation is not None
                        and self.workbench.write_confirmation.companion_recipe_path is not None
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
                    "task_write_upfront_available": bool(
                        self.workbench.write_browser is not None
                        and self.workbench.write_browser.upfront_allowed_arguments is not None
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
                    "task_write_execution_available": bool(
                        self.workbench.write_confirmation is not None
                        and self.workbench.write_browser is not None
                        and not self.workbench.write_browser.read_only
                        and self.workbench.write_confirmation.gateway_state_dir is not None
                        and self.workbench.write_pins is not None
                        and session.subject == self.workbench.write_pins.jules_subject
                    ),
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
            if parsed.path.startswith("/api/v1/tasks/"):
                parts = parsed.path.split("/")
                if len(parts) != 5 or not parts[4]:
                    raise ValueError("task path is invalid")
                if self.workbench.company is None:
                    raise TaskDenied("task is unavailable")
                session, _ = self._session()
                if not session.issuer or not session.subject:
                    raise SessionDenied("employee session is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                self._json(HTTPStatus.OK, self.workbench.proposals.describe(parts[4], employee))
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
                if isinstance(self.workbench.company, JulesWriteContext) and kind == ["connect"]:
                    raise OAuthRejected("Jules task uses the existing checked Drive grant")
                session, created = self._session(create=kind == ["login"])
                uri, _ = self.workbench.oauth.begin(kind[0], browser_cookie=session.cookie,
                                                     expected_subject=session.subject if kind == ["connect"] else None)
                self._redirect(uri, cookie=session.cookie if created else None)
                return
            if parsed.path == "/":
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
                if (isinstance(self.workbench.company, JulesWriteContext)
                        and result.kind == "connect"):
                    raise OAuthRejected("Jules task uses the existing checked Drive grant")
                if result.kind == "login":
                    if (isinstance(self.workbench.company, JulesWriteContext)
                            and result.subject != self.workbench.company.jules_subject):
                        raise OAuthRejected("Google login is not pinned Jules")
                    rotated = self.workbench.sessions.login(
                        session, issuer=result.issuer, subject=result.subject,
                        company=self.workbench.company.bundle["company_id"],
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
                AdmissionDenied, AgentTransportDenied, TaskDenied) as error:
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
            if path in {"/api/v1/write/tasks/prepare", "/api/v1/write/tasks/authorize"}:
                if self.workbench.write_browser is None:
                    raise OperatorDenied("task write browser is unavailable")
                employee, agent, human_packet, agent_packet, evidence = self._write_bindings(session)
                if path.endswith("/prepare"):
                    if set(body) != {"purpose"} or type(body["purpose"]) is not str:
                        raise ValueError("task purpose is invalid")
                    package = load_task_write_package(
                        self.workbench.write_browser.authority_path)
                    paired = self.workbench.write_browser.companion_recipe_path is not None
                    pending_child = None
                    if paired:
                        scratch = (self.workbench.negative_create_target
                                   or self.workbench.populate_failure_target)
                        parent_id = (scratch.parent_id if scratch is not None
                                     else evidence["folder_id"])
                        create_inputs = prepare_create_inputs(
                            parent_id, pinned_folder_id=parent_id)
                        pending_child = {
                            "create_operation_id": secrets.token_urlsafe(18),
                            "create_recipe_digest": package.recipe_digest,
                            "populate_recipe_digest":
                                package.companion_write.recipe_digest,
                            "parent_handle": create_inputs["parent_id"],
                            "title": create_inputs["title"],
                            "marker": (scratch.marker if scratch is not None
                                       else create_inputs["recovery_marker"]),
                        }
                    prepared = self.workbench.write_browser.prepare(
                        employee=employee, agent=agent,
                        employee_identity_packet=human_packet,
                        agent_identity_packet=agent_packet,
                        resource_handle=(
                            self.workbench.finance_read_target
                            if self.workbench.finance_read_target is not None else
                            evidence["probe_document_id"]
                            if self.workbench.project_b_exclusion_target is not None else
                            parent_id if paired else
                            self.workbench.write_target.child.candidate_id
                            if self.workbench.write_target is not None else
                            self.workbench.edit_rerun_target.document_id
                            if self.workbench.edit_rerun_target is not None else
                            evidence["document_id"]),
                        resource_label=(
                            "No write destination (read-only task)"
                            if (self.workbench.finance_read_target is not None
                                or self.workbench.project_b_exclusion_target is not None) else
                            (f"Project A scratch run {scratch.run_id}"
                             if scratch is not None else
                             "Project A destination folder") if paired else
                            self.workbench.write_target.child.title
                            if self.workbench.write_target is not None else
                            self.workbench.edit_rerun_target.document_title
                            if self.workbench.edit_rerun_target is not None else
                            evidence["document_title"]),
                        pending_child=pending_child,
                        read_resource_handle=((self.workbench.finance_read_target
                                              or evidence["probe_document_id"])
                                              if self.workbench.write_browser.read_recipe_path
                                              is not None else None),
                        read_resource_label=(("Finance budget document; Google access unverified"
                                              if self.workbench.finance_read_target is not None
                                              else "Project A source document")
                                             if self.workbench.write_browser.read_recipe_path
                                             is not None else None),
                        account_label=evidence["jules_email"],
                        purpose=body["purpose"],
                    )
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_jules_signatures",
                        "nonce": prepared.nonce, "card": prepared.card,
                        "account_label": prepared.account_label,
                        "resource_label": prepared.resource_label,
                        "read_resource_label": prepared.read_resource_label,
                        "write_tool": prepared.write_tool,
                        "companion_write_tool": prepared.companion_write_tool,
                        "grant_preimage": (
                            None if prepared.grant_preimage is None else
                            base64.urlsafe_b64encode(prepared.grant_preimage).decode("ascii")),
                        "read_grant_preimage": (
                            None if prepared.read_grant_preimage is None else
                            base64.urlsafe_b64encode(
                                prepared.read_grant_preimage).decode("ascii")),
                        "companion_grant_preimage": (
                            None if prepared.companion_grant_preimage is None else
                            base64.urlsafe_b64encode(
                                prepared.companion_grant_preimage).decode("ascii")),
                        "task_preimage": base64.urlsafe_b64encode(
                            prepared.task_preimage).decode("ascii"),
                        "expires_at": prepared.expires_at,
                    })
                    return
                expected = {"nonce", "task_signature"}
                if not self.workbench.write_browser.read_only:
                    expected.add("grant_signature")
                if self.workbench.write_browser.read_recipe_path is not None:
                    expected.add("read_grant_signature")
                if self.workbench.write_browser.companion_recipe_path is not None:
                    expected.add("companion_grant_signature")
                if set(body) != expected:
                    raise ValueError("task signatures are incomplete")
                nonce = body["nonce"]
                if type(nonce) is not str or not 1 <= len(nonce) <= 128:
                    raise ValueError("task signing nonce is invalid")
                completed = self.workbench.write_browser.complete(
                    nonce=nonce, employee=employee, agent=agent,
                    grant_signature=(_b64(body["grant_signature"], max_bytes=64)
                                     if "grant_signature" in body else None),
                    read_grant_signature=(
                        _b64(body["read_grant_signature"], max_bytes=64)
                        if "read_grant_signature" in body else None),
                    companion_grant_signature=(
                        _b64(body["companion_grant_signature"], max_bytes=64)
                        if "companion_grant_signature" in body else None),
                    task_signature=_b64(body["task_signature"], max_bytes=64),
                )
                activation_status = _activate_signed_write_task(
                    completed.task_id, self.workbench.write_confirmation,
                )
                self._json(HTTPStatus.OK, {
                    "status": activation_status,
                    "task_id": completed.task_id,
                    "agent_principal": completed.agent_principal,
                    "expires_at": completed.expires_at,
                    "agent_package": completed.agent_package,
                    "read_agent_package": completed.read_agent_package,
                    "companion_agent_package": completed.companion_agent_package,
                })
                return
            if path in {"/api/v1/write/confirmations/prepare",
                        "/api/v1/write/confirmations/authorize"}:
                if (self.workbench.write_browser is not None
                        and self.workbench.write_browser.read_only):
                    raise OperatorDenied("read-only task has no write confirmation")
                flow = self.workbench.write_confirmation
                if flow is None:
                    raise OperatorDenied("exact write review is unavailable")
                employee, agent, _, _, _ = self._write_bindings(session)
                if path.endswith("/prepare"):
                    if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                        raise ValueError("write task ID is invalid")
                    prepared = flow.prepare(
                        task_id=body["task_id"], employee=employee, agent=agent,
                    )
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_exact_confirmation",
                        "nonce": prepared.nonce,
                        "task_id": prepared.task_id,
                        "agent_principal": prepared.card["agent_principal"],
                        "account_subject": prepared.card["connection_subject"],
                        "destination_handle": prepared.intent["resource_handle"],
                        "method": prepared.review.method,
                        "url": prepared.review.url,
                        "content_type": prepared.review.content_type,
                        "body": prepared.review.body,
                        "intent": prepared.intent,
                        "signing_preimage": base64.urlsafe_b64encode(
                            prepared.signing_preimage).decode("ascii"),
                        "expires_at": prepared.expires_at,
                    })
                    return
                if set(body) != {"nonce", "signature"}:
                    raise ValueError("exact confirmation is incomplete")
                nonce = body["nonce"]
                if type(nonce) is not str or not 1 <= len(nonce) <= 128:
                    raise ValueError("exact confirmation nonce is invalid")
                directory = flow.complete(
                    nonce=nonce, employee=employee, agent=agent,
                    signature=_b64(body["signature"], max_bytes=64),
                )
                self._json(HTTPStatus.OK, {
                    "status": "confirmed_pending_gateway_submission",
                    "task_id": directory.name,
                })
                return
            if path in {"/api/v1/write/effect-plans/prepare",
                        "/api/v1/write/effect-plans/authorize"}:
                if (self.workbench.write_browser is not None
                        and self.workbench.write_browser.read_only):
                    raise OperatorDenied("read-only task has no write effect plan")
                flow = self.workbench.write_confirmation
                if flow is None or flow.companion_recipe_path is None:
                    raise OperatorDenied("paired effect-plan review is unavailable")
                employee, agent, _, agent_packet, _ = self._write_bindings(session)
                if path.endswith("/prepare"):
                    if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                        raise ValueError("write task ID is invalid")
                    prepared = flow.prepare_effect_plan(
                        task_id=body["task_id"], employee=employee, agent=agent,
                        agent_identity_packet=agent_packet,
                    )
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_exact_effect_plan",
                        "nonce": prepared.nonce,
                        "task_id": prepared.task_id,
                        "agent_principal": prepared.card["agent_principal"],
                        "account_subject": prepared.card["connection_subject"],
                        "destination_handle": prepared.plan["create"]["resource_handle"],
                        "method": prepared.review.method,
                        "url": prepared.review.url,
                        "content_type": prepared.review.content_type,
                        "body": prepared.review.body,
                        "plan": prepared.plan,
                        "signing_preimage": base64.urlsafe_b64encode(
                            prepared.signing_preimage).decode("ascii"),
                        "expires_at": prepared.expires_at,
                    })
                    return
                if set(body) != {"nonce", "signature"}:
                    raise ValueError("effect-plan signature is incomplete")
                nonce = body["nonce"]
                if type(nonce) is not str or not 1 <= len(nonce) <= 128:
                    raise ValueError("effect-plan nonce is invalid")
                directory = flow.complete_effect_plan(
                    nonce=nonce, employee=employee, agent=agent,
                    agent_identity_packet=agent_packet,
                    signature=_b64(body["signature"], max_bytes=64),
                )
                self._json(HTTPStatus.OK, {
                    "status": "effect_plan_recorded",
                    "task_id": directory.name,
                })
                return
            if path == "/api/v1/write/submissions/execute":
                if (self.workbench.write_browser is not None
                        and self.workbench.write_browser.read_only):
                    raise OperatorDenied("read-only task cannot submit a write")
                flow = self.workbench.write_confirmation
                if flow is None or flow.gateway_state_dir is None:
                    raise OperatorDenied("gateway task execution is unavailable")
                if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                    raise ValueError("write task ID is invalid")
                employee, agent, _, _, _ = self._write_bindings(session)
                outcome = flow.submit(
                    task_id=body["task_id"], employee=employee, agent=agent,
                )
                self._json(HTTPStatus.OK, {"task_id": body["task_id"],
                                            "gateway": outcome})
                return
            if path in {"/api/v1/write/recovered-child/prepare",
                        "/api/v1/write/recovered-child/authorize",
                        "/api/v1/write/recovered-child/execute"}:
                flow = self.workbench.write_confirmation
                if ((self.workbench.write_browser is not None
                     and self.workbench.write_browser.read_only) or flow is None
                        or flow.companion_recipe_path is None):
                    raise OperatorDenied("paired recovered-child review is unavailable")
                employee, agent, _, _, _ = self._write_bindings(session)
                if path.endswith("/prepare"):
                    if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                        raise ValueError("recovery task ID is invalid")
                    prepared = flow.prepare_recovered_child(
                        task_id=body["task_id"], employee=employee, agent=agent)
                    self._json(HTTPStatus.OK, {
                        "status": "awaiting_recovered_child_confirmation",
                        "nonce": prepared.nonce,
                        "task_id": prepared.task_id,
                        "review": prepared.review,
                        "signing_preimage": base64.urlsafe_b64encode(
                            prepared.signing_preimage).decode("ascii"),
                        "expires_at": prepared.expires_at,
                    })
                    return
                if path.endswith("/authorize"):
                    if set(body) != {"nonce", "signature"}:
                        raise ValueError("recovery signature is incomplete")
                    if type(body["nonce"]) is not str or not 1 <= len(body["nonce"]) <= 128:
                        raise ValueError("recovery nonce is invalid")
                    directory = flow.complete_recovered_child(
                        nonce=body["nonce"], employee=employee, agent=agent,
                        signature=_b64(body["signature"], max_bytes=64))
                    self._json(HTTPStatus.OK, {
                        "status": "confirmed_pending_child_metadata_check",
                        "task_id": directory.name,
                    })
                    return
                if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                    raise ValueError("recovery task ID is invalid")
                result = flow.submit_recovered_child(
                    task_id=body["task_id"], employee=employee, agent=agent)
                self._json(HTTPStatus.OK, result)
                return
            if path in {"/api/v1/write/tasks/revoke", "/api/v1/write/tasks/status",
                        "/api/v1/write/tasks/activity"}:
                flow = self.workbench.write_confirmation
                if flow is None or flow.gateway_state_dir is None:
                    raise OperatorDenied("gateway task status is unavailable")
                if set(body) != {"task_id"} or type(body["task_id"]) is not str:
                    raise ValueError("write task ID is invalid")
                if self.workbench.company is None or not session.issuer or not session.subject:
                    raise SessionDenied("employee session is unavailable")
                employee = self.workbench.enrollment.lookup(
                    self.workbench.company,
                    VerifiedGoogleSubject("login", session.issuer, session.subject),
                )
                if path.endswith("/revoke"):
                    flow.revoke(task_id=body["task_id"], employee=employee)
                    self._json(HTTPStatus.OK, {"status": "revoked", "task_id": body["task_id"]})
                elif path.endswith("/activity"):
                    self._json(HTTPStatus.OK, flow.activity(
                        task_id=body["task_id"], employee=employee,
                    ))
                else:
                    self._json(HTTPStatus.OK, flow.status(
                        task_id=body["task_id"], employee=employee,
                    ))
                return
            if path == "/api/v1/identity/packet":
                from auths.identity.authoring import (
                    create_raw_key_ed25519_identity,
                    derive_raw_key_ed25519_authority_v1,
                )
                public_key = _b64(body.get("public_key", ""), max_bytes=32)
                if len(public_key) != 32:
                    raise ValueError("Ed25519 public key is invalid")
                identity = create_raw_key_ed25519_identity(public_key)
                self._json(HTTPStatus.OK, {
                    "identity_packet": base64.urlsafe_b64encode(identity.to_bytes()).decode("ascii"),
                    "principal": derive_raw_key_ed25519_authority_v1(public_key).principal,
                })
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
                    from .authority_identity import authority_for_identity_packet
                    authority_for_identity_packet(packet)
                    nonce, message = self.workbench.enrollment.prepare(
                        self.workbench.company, identity, packet,
                    )
                    from auths import _native
                    preimage = _native.identity_descriptor_signing_preimage_v1(
                        packet, "default-signing", message,
                    )
                    self._json(HTTPStatus.OK, {
                        "nonce": nonce,
                        "message": base64.urlsafe_b64encode(message).decode("ascii"),
                        "signing_preimage": base64.urlsafe_b64encode(preimage).decode("ascii"),
                    })
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
                    from auths import _native
                    preimage = _native.identity_descriptor_signing_preimage_v1(
                        packet, "default-signing", message,
                    )
                    self._json(HTTPStatus.OK, {
                        "nonce": nonce, "agent_principal": principal,
                        "message": base64.urlsafe_b64encode(message).decode("ascii"),
                        "signing_preimage": base64.urlsafe_b64encode(preimage).decode("ascii"),
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
                        or self.workbench.service is None
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
                    service=self.workbench.service,
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
        except (ValueError, binascii.Error, SessionDenied, EnrollmentDenied, ContractRejected,
                AgentDenied, TaskDenied, ApprovalDenied, ActivationDenied, OperatorDenied,
                AgentTransportDenied, AdmissionDenied, GoogleDenied,
                PermissionError) as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})
        except GoogleUnavailable:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE,
                       {"error": "Google document check is unavailable"})


class WorkbenchServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], workbench: Workbench) -> None:
        self.runtime = AdmissionStore(workbench.sessions.path).open_runtime()
        try:
            super().__init__(address, Handler)
        except BaseException:
            self.runtime.close()
            raise
        self.workbench = workbench

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.runtime.close()


def _private_file(path: Path, max_bytes: int) -> bytes:
    if (not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("operator secret file must be private and bounded")
    return path.read_bytes()


def _activate_signed_write_task(task_id: str,
                                flow: TaskWriteConfirmationFlow | None) -> str:
    """Preserve a signed task's ID when gateway activation is uncertain."""
    if flow is None or flow.gateway_state_dir is None:
        return "approved_pending_gateway_activation"
    try:
        flow.activate(task_id)
    except OperatorDenied:
        return "signed_activation_unconfirmed"
    return "activated_awaiting_agent_proposal"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AP-SPEC-070 loopback workbench")
    parser.add_argument("--state-db", required=True, type=Path)
    parser.add_argument("--connections", type=Path)
    parser.add_argument("--access-expectations", type=Path)
    parser.add_argument("--google-verification", type=Path)
    parser.add_argument("--scenario-result", type=Path, action="append", default=[])
    parser.add_argument("--scenario-dir", type=Path,
                        help="directory of operator-pinned scenario-result-*.json exports")
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--jules-only-evidence", type=Path,
                        help="private pinned AP-071 producer write evidence")
    parser.add_argument("--jules-only-pins", type=Path,
                        help="private Jules-only write handoff pins")
    parser.add_argument("--oauth-config", type=Path)
    parser.add_argument("--fernet-key", type=Path)
    parser.add_argument("--trust-file", type=Path)
    parser.add_argument("--receipt-key", type=Path)
    parser.add_argument("--task-write-authority", type=Path)
    parser.add_argument("--task-write-installation", type=Path)
    parser.add_argument("--task-write-recipe", type=Path)
    parser.add_argument("--task-write-profile-lock", type=Path)
    parser.add_argument("--task-read-recipe", type=Path)
    parser.add_argument("--task-read-profile-lock", type=Path)
    parser.add_argument("--task-companion-write-recipe", type=Path)
    parser.add_argument("--task-companion-write-profile-lock", type=Path)
    parser.add_argument("--task-write-output-dir", type=Path)
    parser.add_argument("--task-write-evidence", type=Path)
    parser.add_argument("--task-write-current-baseline", type=Path,
                        help="private immutable current working Doc observation")
    parser.add_argument("--task-write-current-baseline-sha256",
                        help="operator-reviewed digest of the current observation")
    parser.add_argument("--task-write-pins", type=Path)
    parser.add_argument("--task-write-gateway-bin", type=Path)
    parser.add_argument("--task-write-gateway-sha256")
    parser.add_argument("--task-write-gateway-state-dir", type=Path,
                        help="opt in to task activation and reviewed write submission")
    parser.add_argument("--task-write-credential-pins", type=Path)
    parser.add_argument("--task-write-grant", type=Path)
    parser.add_argument("--task-write-created-child", type=Path,
                        help="private pin for an existing blank child in a new edit task")
    parser.add_argument("--task-upfront-choices", type=Path,
                        help="owner-private exact argument choices for one upfront write")
    parser.add_argument("--task-edit-rerun-baseline", type=Path)
    parser.add_argument("--task-edit-rerun-baseline-sha256")
    parser.add_argument("--task-edit-rerun-choices", type=Path)
    parser.add_argument("--task-edit-rerun-choices-sha256")
    parser.add_argument("--task-edit-rerun-previous-observation-sha256")
    parser.add_argument("--task-bounded-negative-baseline", type=Path)
    parser.add_argument("--task-bounded-negative-choices", type=Path)
    parser.add_argument("--task-bounded-negative-pins", type=Path)
    parser.add_argument("--task-finance-denial-evidence", type=Path,
                        help="private demo_co provider-denial observation for a read-only task")
    parser.add_argument("--task-finance-denial-sha256",
                        help="operator-reviewed digest of the finance denial observation")
    parser.add_argument("--task-finance-document-id",
                        help="operator-pinned finance document for a read-only task")
    parser.add_argument("--task-finance-write-grant-evidence", type=Path,
                        help="private same-grant Jules finance denial observation")
    parser.add_argument("--task-finance-write-grant-sha256",
                        help="operator-reviewed digest of the same-grant observation")
    parser.add_argument("--task-project-b-grants-evidence", type=Path,
                        help="fresh private proof that Jules's read-only grant can read excluded Project B")
    parser.add_argument("--task-project-b-grants-sha256")
    parser.add_argument("--task-project-b-document-id")
    parser.add_argument("--task-create-negative-setup", type=Path)
    parser.add_argument("--task-create-negative-setup-sha256")
    parser.add_argument("--task-create-negative-v4-pins", type=Path)
    parser.add_argument("--task-create-negative-v4-baseline", type=Path)
    parser.add_argument("--task-create-negative-v4-candidate", type=Path)
    parser.add_argument("--task-create-negative-v4-final", type=Path)
    parser.add_argument("--task-populate-failure-setup", type=Path)
    parser.add_argument("--task-populate-failure-setup-sha256")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--container-bind", action="store_true",
                        help="bind all container interfaces; use only behind the compose relays")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    if args.container_bind and not Path("/.dockerenv").exists():
        parser.error("container bind requires Docker isolation")
    origin = f"http://127.0.0.1:{args.port}"
    scenario_results = tuple(args.scenario_result)
    if args.scenario_dir is not None:
        if args.scenario_dir.is_symlink() or not args.scenario_dir.is_dir():
            parser.error("scenario directory is unavailable")
        scenario_results += tuple(sorted(args.scenario_dir.glob("scenario-result-*.json")))
    if len(scenario_results) > 4096:
        parser.error("too many scenario results")
    pins = None
    if args.pins is not None:
        pins = OperatorPins(**json.loads(_private_file(args.pins, 4096)))
    status = inspect_exports(args.connections, args.access_expectations, pins,
                             scenario_results, args.google_verification)
    company = None
    if status.google == "ready" and pins and args.connections and args.access_expectations:
        company = import_company(args.connections, args.access_expectations, pins,
                                 scenario_results=scenario_results,
                                 google_verification=args.google_verification)
    jules_only = (args.jules_only_evidence is not None
                  or args.jules_only_pins is not None)
    if jules_only:
        if (company is not None or args.jules_only_evidence is None
                or args.jules_only_pins is None or args.oauth_config is None
                or args.fernet_key is not None):
            parser.error("Jules-only mode needs pinned evidence, pins and Google login only")
        try:
            snapshot_dir = args.jules_only_evidence.resolve().parent
            if (snapshot_dir != args.jules_only_pins.resolve().parent
                    or stat.S_IMODE(snapshot_dir.stat().st_mode) & 0o077):
                raise ValueError("Jules-only snapshots need one private directory")
            _private_file(args.jules_only_evidence, 65_536)
            jules_pins = WriteHandoffPins(**json.loads(
                _private_file(args.jules_only_pins, 4096),
                object_pairs_hook=_unique_pairs,
            ))
            company = JulesWriteContext.from_pinned_evidence(
                args.jules_only_evidence, jules_pins,
            )
        except (OSError, PermissionError, ValueError, TypeError) as error:
            parser.error(f"Jules-only producer handoff is unavailable: {error}")
        status = ImportStatus(
            "jules_write_only", "not_imported", "not_imported",
            "pinned Jules write evidence; full company import remains incomplete",
        )
    sessions = BrowserSessionStore(args.state_db)
    oauth = None
    if args.oauth_config is not None:
        config = GoogleOAuthConfig(**json.loads(_private_file(args.oauth_config, 4096)))
        config.validate()
        if config.redirect_uri != origin:
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
    service = None
    if args.trust_file is not None:
        from auths import _native

        manifest = json.loads(_private_file(args.trust_file, 262_144))
        if (manifest.get("contract") != "auths.google-read-root/v1"
                or not valid_service(manifest.get("service"))
                or manifest.get("configuration_id") != bytes(
                    _native.self_contained_configuration()).hex()
                or company is None or manifest.get("company_id") != company.bundle["company_id"]):
            parser.error("operator trust file does not match accepted company and SDK")
        expected_root = manifest.get("root_principal")
        service = manifest["service"]
        trusted_template = base64.urlsafe_b64decode(manifest["trusted_template"])
        _native.parse_trusted_context(trusted_template)
    agent_transport = None
    if (isinstance(company, CompanyImport) and vault is not None
            and trusted_template is not None):
        if args.receipt_key is None:
            parser.error("live agent transport requires a private receipt signing key")
        receipts = ReceiptStore(args.state_db, Ed25519PrivateKey.from_private_bytes(
            _private_file(args.receipt_key, 32),
        ))
        agent_transport = AgentTransport(
            args.state_db, vault=vault, trusted_template=trusted_template,
            expected_root=expected_root, receipts=receipts,
        )
    write_options = (
        args.task_write_authority, args.task_write_installation,
        args.task_write_recipe, args.task_write_profile_lock,
        args.task_write_output_dir, args.task_write_evidence, args.task_write_pins,
    )
    if any(option is not None for option in write_options) and not all(
            option is not None for option in write_options):
        parser.error("all task-write inputs must be supplied together")
    if (any(option is not None for option in (
            args.task_project_b_grants_evidence,
            args.task_project_b_grants_sha256,
            args.task_project_b_document_id))
            and not all(option is not None for option in write_options)):
        parser.error("Project B exclusion requires a complete task installation")
    negative_setup_options = (
        args.task_create_negative_setup,
        args.task_create_negative_setup_sha256,
    )
    scratch_v4_options = (
        args.task_create_negative_v4_pins,
        args.task_create_negative_v4_baseline,
        args.task_create_negative_v4_candidate,
        args.task_create_negative_v4_final,
    )
    populate_failure_options = (
        args.task_populate_failure_setup,
        args.task_populate_failure_setup_sha256,
    )
    if any(option is not None for option in (*negative_setup_options,
                                              *scratch_v4_options,
                                              *populate_failure_options)) and (
            not all(option is not None for option in scratch_v4_options)
            or not all(option is not None for option in write_options)
            or args.task_companion_write_recipe is None
            or args.task_write_created_child is not None
            or args.task_finance_denial_evidence is not None):
        parser.error("scratch create requires complete paired task and v4 pins")
    if (any(option is not None for option in negative_setup_options)
            == any(option is not None for option in populate_failure_options)):
        if any(option is not None for option in scratch_v4_options):
            parser.error("scratch create requires exactly one setup kind")
    if (any(option is not None for option in negative_setup_options)
            and not all(option is not None for option in negative_setup_options)):
        parser.error("negative create setup and digest must be supplied together")
    if (any(option is not None for option in populate_failure_options)
            and not all(option is not None for option in populate_failure_options)):
        parser.error("populate failure setup and digest must be supplied together")
    if (args.task_write_current_baseline is None) != (
            args.task_write_current_baseline_sha256 is None):
        parser.error("current working Doc baseline and digest must be supplied together")
    if args.task_write_current_baseline is not None and not all(
            option is not None for option in write_options):
        parser.error("current working Doc baseline requires task-write inputs")
    if (args.task_companion_write_recipe is None) != (
            args.task_companion_write_profile_lock is None):
        parser.error("companion write recipe and profile lock must be supplied together")
    if args.task_companion_write_recipe is not None and not all(
            option is not None for option in write_options):
        parser.error("companion write requires the task-write installation")
    if args.task_write_created_child is not None and not all(
            option is not None for option in write_options):
        parser.error("created-child continuation requires task-write inputs")
    if args.task_upfront_choices is not None and (not all(
            option is not None for option in write_options)
            or args.task_write_created_child is not None
            or args.task_companion_write_recipe is not None
            or args.task_write_gateway_state_dir is None):
        parser.error("bounded upfront requires an installed single-write task")
    rerun_options = (args.task_edit_rerun_baseline,
                     args.task_edit_rerun_baseline_sha256,
                     args.task_edit_rerun_choices,
                     args.task_edit_rerun_choices_sha256,
                     args.task_edit_rerun_previous_observation_sha256)
    if any(option is not None for option in rerun_options) and (
            not all(option is not None for option in rerun_options)
            or args.task_upfront_choices is None
            or args.task_write_current_baseline is not None
            or args.task_write_created_child is not None):
        parser.error("clean edit rerun requires a pinned upfront task")
    bounded_options = (args.task_bounded_negative_baseline,
                       args.task_bounded_negative_choices,
                       args.task_bounded_negative_pins)
    if any(option is not None for option in bounded_options) and (
            not all(option is not None for option in bounded_options)
            or any(option is not None for option in rerun_options)
            or args.task_upfront_choices is None
            or args.task_write_current_baseline is not None
            or args.task_write_created_child is not None):
        parser.error("bounded negative run requires one pinned upfront task")
    finance_options = (args.task_finance_denial_evidence,
                       args.task_finance_denial_sha256,
                       args.task_finance_document_id,
                       args.task_finance_write_grant_evidence,
                       args.task_finance_write_grant_sha256)
    if any(option is not None for option in finance_options) and (
            not all(option is not None for option in finance_options)
            or not all(option is not None for option in write_options)
            or args.task_upfront_choices is not None
            or args.task_write_created_child is not None
            or args.task_companion_write_recipe is not None
            or args.task_read_recipe is None
            or args.task_write_gateway_state_dir is None):
        parser.error("finance denial needs pinned evidence and an installed read task")
    write_browser = None
    write_pins = None
    write_confirmation = None
    write_target = None
    upfront_choices = None
    finance_read_target = None
    project_b_exclusion_target = None
    edit_rerun_target = None
    bounded_negative_mode = False
    negative_create_target = None
    populate_failure_target = None
    if all(option is not None for option in write_options):
        if company is None:
            parser.error("task write requires an accepted company import")
        output_dir = args.task_write_output_dir.resolve()
        if (args.task_write_evidence.resolve().parent != output_dir
                or args.task_write_pins.resolve().parent != output_dir):
            parser.error("task write evidence and pins must be private local snapshots")
        write_pins = WriteHandoffPins(**json.loads(
            _private_file(args.task_write_pins, 4096), object_pairs_hook=_unique_pairs,
        ))
        if write_pins.company != company.bundle["company_id"]:
            parser.error("task write producer company does not match import")
        if (isinstance(company, JulesWriteContext)
                and (write_pins.evidence_sha256 != company.bundle_sha256
                     or write_pins.jules_subject != company.jules_subject)):
            parser.error("task write pins differ from Jules-only enrollment generation")
        write_evidence = validate_write_handoff(args.task_write_evidence, write_pins)
        if args.task_finance_denial_evidence is not None:
            try:
                finance_pins = FinanceDenialPins(
                    company=write_pins.company,
                    instance=write_pins.instance,
                    definition_hash=write_pins.definition_hash,
                    customer_id=write_pins.customer_id,
                    jules_subject=write_pins.jules_subject,
                    document_id=args.task_finance_document_id,
                    evidence_sha256=args.task_finance_denial_sha256,
                )
                current_time = int(time.time())
                validate_finance_denial(
                    args.task_finance_denial_evidence, finance_pins,
                    now=current_time,
                )
                source_generation = int(
                    args.task_finance_denial_evidence.parent.name.split("-")[-1])
                finance_read_target = validate_finance_write_grant(
                    args.task_finance_write_grant_evidence,
                    FinanceWriteGrantPins(
                        finance_pins, source_generation,
                        args.task_finance_write_grant_sha256,
                    ), now=current_time,
                )["document_id"]
            except (ContractRejected, OSError, PermissionError) as error:
                parser.error(f"finance denial observation refused: {error}")
        project_b_options = (
            args.task_project_b_grants_evidence,
            args.task_project_b_grants_sha256,
            args.task_project_b_document_id,
        )
        if any(option is not None for option in project_b_options):
            if not all(option is not None for option in project_b_options):
                parser.error("Project B exclusion pins must be complete")
            if finance_read_target is not None:
                parser.error("read-only probe modes cannot be combined")
            try:
                project_b_exclusion_target = validate_project_b_grants(
                    args.task_project_b_grants_evidence,
                    ProjectBGrantPins(
                        company=write_pins.company,
                        instance=write_pins.instance,
                        definition_hash=write_pins.definition_hash,
                        jules_subject=write_pins.jules_subject,
                        document_id=args.task_project_b_document_id,
                        drive_id=write_evidence["drive_id"],
                        evidence_sha256=args.task_project_b_grants_sha256,
                    ), now=int(time.time()),
                ).document_id
            except (ContractRejected, OSError, PermissionError) as error:
                parser.error(f"Project B grant observation refused: {error}")
        if args.task_write_current_baseline is not None:
            try:
                validate_current_write_observation(
                    args.task_write_current_baseline,
                    args.task_write_current_baseline_sha256,
                    evidence=write_evidence, now=int(time.time()),
                )
            except (ContractRejected, OSError, PermissionError) as error:
                parser.error(f"current working Doc observation refused: {error}")
        if args.task_upfront_choices is not None:
            upfront_document = json.loads(
                _private_file(args.task_upfront_choices, 16_384),
                object_pairs_hook=_unique_pairs,
            )
            if (type(upfront_document) is not dict
                    or set(upfront_document) != {"schema", "choices"}
                    or upfront_document["schema"] != "auths.ap071-upfront-choices/1"
                    or type(upfront_document["choices"]) is not list):
                parser.error("bounded upfront choices are malformed")
            upfront_choices = upfront_document["choices"]
        if args.task_edit_rerun_baseline is not None:
            try:
                edit_rerun_target = validate_edit_rerun(
                    args.task_edit_rerun_baseline,
                    args.task_edit_rerun_choices,
                    EditRerunPins(
                        write_pins,
                        args.task_edit_rerun_previous_observation_sha256,
                        args.task_edit_rerun_baseline_sha256,
                        args.task_edit_rerun_choices_sha256,
                    ), source_evidence=write_evidence, now=int(time.time()),
                )
            except (ContractRejected, OSError, PermissionError, ValueError) as error:
                parser.error(f"clean edit rerun producer handoff refused: {error}")
            if upfront_choices != edit_rerun_target.allowed_arguments():
                parser.error("upfront choices disagree with producer commitments")
        if args.task_bounded_negative_baseline is not None:
            try:
                raw = json.loads(_private_file(
                    args.task_bounded_negative_pins, 4096),
                    object_pairs_hook=_unique_pairs)
                fields = {"baseline_sha256", "choices_sha256",
                          "scratch_root_id", "scratch_plan_sha256",
                          "v4_baseline_sha256", "v4_final_sha256"}
                if type(raw) is not dict or set(raw) != fields:
                    raise ContractRejected("bounded negative pins are malformed")
                edit_rerun_target = validate_bounded_negative(
                    args.task_bounded_negative_baseline,
                    args.task_bounded_negative_choices,
                    BoundedNegativePins(write_pins, **raw),
                    source_evidence=write_evidence, now=int(time.time()),
                )
            except (ContractRejected, OSError, PermissionError, ValueError) as error:
                parser.error(f"bounded negative producer handoff refused: {error}")
            if upfront_choices != edit_rerun_target.allowed_arguments():
                parser.error("upfront choices disagree with bounded negative pins")
            bounded_negative_mode = True
        if args.task_write_created_child is not None:
            if args.task_companion_write_recipe is not None:
                parser.error("created-child continuation cannot issue another create")
            write_target = CreatedChildContinuationTarget.from_document(json.loads(
                _private_file(args.task_write_created_child, 4096),
                object_pairs_hook=_unique_pairs,
            ))
            if (write_target.child.parent_id != write_evidence["folder_id"]
                    or write_target.child.drive_id != write_evidence["drive_id"]):
                parser.error("created-child continuation differs from pinned Project A")
        if all(option is not None for option in negative_setup_options):
            try:
                negative_create_target = validate_negative_create_setup(
                    args.task_create_negative_v4_baseline,
                    args.task_create_negative_v4_candidate,
                    args.task_create_negative_v4_final,
                    args.task_create_negative_setup,
                    args.task_create_negative_setup_sha256,
                    load_v4_final_pins(args.task_create_negative_v4_pins),
                )
            except (ContractRejected, OSError, PermissionError) as error:
                parser.error(f"negative create setup refused: {error}")
        if any(option is not None for option in populate_failure_options):
            try:
                populate_failure_target = validate_populate_failure_setup(
                    args.task_create_negative_v4_baseline,
                    args.task_create_negative_v4_candidate,
                    args.task_create_negative_v4_final,
                    args.task_populate_failure_setup,
                    args.task_populate_failure_setup_sha256,
                    load_v4_final_pins(args.task_create_negative_v4_pins),
                )
            except (ContractRejected, OSError, PermissionError) as error:
                parser.error(f"populate failure setup refused: {error}")
        loaded = load_task_write_package(args.task_write_authority)
        if loaded.company_id != write_pins.company:
            parser.error("task authority company disagrees with producer")
        if (args.task_write_created_child is not None
                and (loaded.read is not None
                     or loaded.companion_write is not None
                     or (loaded.authority.provider_service,
                         loaded.authority.provider_tool) != (
                             "google-docs-delegation-demo",
                             "populate_created_project_a_document_v1"))):
            parser.error("created-child continuation requires the populate-only recipe")
        read_paths = (args.task_read_recipe, args.task_read_profile_lock)
        if (loaded.read is None and any(path is not None for path in read_paths)) or (
                loaded.read is not None and not all(path is not None for path in read_paths)):
            parser.error("task read recipe inputs must match issued authority")
        companion_paths = (args.task_companion_write_recipe,
                           args.task_companion_write_profile_lock)
        if (loaded.companion_write is None and
                any(path is not None for path in companion_paths)) or (
                loaded.companion_write is not None and
                not all(path is not None for path in companion_paths)):
            parser.error("companion write recipe inputs must match issued authority")
        _installation(args.task_write_installation)
        write_browser = TaskWriteBrowserFlow(
            authority_path=args.task_write_authority,
            installation_path=args.task_write_installation,
            recipe_path=args.task_write_recipe,
            profile_lock_path=args.task_write_profile_lock,
            read_recipe_path=args.task_read_recipe,
            read_profile_lock_path=args.task_read_profile_lock,
            companion_recipe_path=args.task_companion_write_recipe,
            companion_profile_lock_path=args.task_companion_write_profile_lock,
            upfront_allowed_arguments=upfront_choices,
            read_only=(finance_read_target is not None
                       or project_b_exclusion_target is not None),
            private_output_dir=args.task_write_output_dir,
        )
    confirmation_options = (
        args.task_write_gateway_bin, args.task_write_gateway_sha256,
        args.task_write_credential_pins, args.task_write_grant,
    )
    if any(option is not None for option in confirmation_options) and not all(
            option is not None for option in confirmation_options):
        parser.error("gateway review and Jules preflight inputs must be supplied together")
    if (args.task_write_gateway_state_dir is not None
            and args.task_write_gateway_bin is None):
        parser.error("gateway execution requires review and Jules preflight inputs")
    if (args.task_write_created_child is not None
            and (not all(option is not None for option in confirmation_options)
                 or args.task_write_gateway_state_dir is None)):
        parser.error("created-child continuation requires Jules preflight and gateway execution")
    if args.task_write_gateway_bin is not None:
        if write_browser is None:
            parser.error("gateway review requires the task write installation")
        if args.task_write_gateway_state_dir is not None:
            installed_trust = _private_file(
                args.task_write_gateway_state_dir / "trusted.context.cbor", 262_144,
            )
            if installed_trust != loaded.authority.trusted_template:
                parser.error("gateway trust differs from issued task authority")
        raw_pins = json.loads(_private_file(args.task_write_credential_pins, 4096),
                              object_pairs_hook=_unique_pairs)
        if (type(raw_pins) is not dict
                or set(raw_pins) != {"producer", "client_id", "primary_domain",
                                     "connection_id", "connection_generation"}
                or type(raw_pins["producer"]) is not dict
                or set(raw_pins["producer"]) != {"company", "instance",
                    "definition_hash", "customer_id", "jules_subject",
                    "jules_email", "evidence_sha256"}):
            parser.error("Jules write credential pins are malformed")
        credential_pins = WriteCredentialPins(
            producer=WriteHandoffPins(**raw_pins["producer"]),
            client_id=raw_pins["client_id"],
            primary_domain=raw_pins["primary_domain"],
            connection_id=raw_pins["connection_id"],
            connection_generation=raw_pins["connection_generation"],
        )
        credential_pins.validate()
        installed_pins = _installation(args.task_write_installation)["pins"]
        if (credential_pins.producer != write_pins
                or credential_pins.connection_id != installed_pins["connection_id"]
                or credential_pins.connection_generation
                != installed_pins["connection_generation"]
                or credential_pins.producer.jules_subject
                != installed_pins["connection_subject"]):
            parser.error("Jules preflight pins disagree with gateway installation")

        def google_edit_preflight(card, reviewed):
            if write_target is not None:
                observed_child = preflight_jules_created_child(
                    args.task_write_evidence, args.task_write_grant,
                    credential_pins, write_target.child,
                    connection_id=card["connection_id"],
                    connection_generation=card["connection_generation"],
                )
                write_target.require_exact_action(
                    reviewed.arguments, child_id=observed_child.child_id,
                    tab_id=observed_child.tab_id,
                    revision_id=observed_child.revision_id,
                )
                return
            observed = preflight_jules_edit(
                args.task_write_evidence, args.task_write_grant,
                credential_pins, connection_id=card["connection_id"],
                connection_generation=card["connection_generation"],
                current_observation_path=args.task_write_current_baseline,
                current_observation_sha256=args.task_write_current_baseline_sha256,
                target=(None if edit_rerun_target is None else EditTarget(
                    edit_rerun_target.document_id,
                    edit_rerun_target.document_title,
                    (BOUNDED_NEGATIVE_LOGICAL_ID
                     if bounded_negative_mode else LOGICAL_ID),
                    edit_rerun_target.folder_id,
                    edit_rerun_target.drive_id,
                    edit_rerun_target.tab_id,
                    edit_rerun_target.marker,
                    edit_rerun_target.baseline_sha256,
                    edit_rerun_target.baseline_byte_count,
                )),
            )
            evidence = validate_write_handoff(args.task_write_evidence, write_pins)
            arguments = reviewed.arguments
            if (arguments.get("document_id") != observed.document_id
                    or arguments.get("tab_id") != observed.tab_id
                    or arguments.get("marker") != (
                        evidence["marker"] if edit_rerun_target is None
                        else edit_rerun_target.marker)
                    or arguments.get("required_revision_id") != observed.revision_id):
                raise OperatorDenied("agent proposal disagrees with fresh Jules preflight")

        write_confirmation = TaskWriteConfirmationFlow(
            authority_path=args.task_write_authority,
            installation_path=args.task_write_installation,
            recipe_path=args.task_write_recipe,
            profile_lock_path=args.task_write_profile_lock,
            read_recipe_path=args.task_read_recipe,
            read_profile_lock_path=args.task_read_profile_lock,
            companion_recipe_path=args.task_companion_write_recipe,
            companion_profile_lock_path=args.task_companion_write_profile_lock,
            upfront_allowed_arguments=upfront_choices,
            private_output_dir=args.task_write_output_dir,
            gateway_binary=args.task_write_gateway_bin,
            gateway_sha256=args.task_write_gateway_sha256,
            preflight=(None if write_browser.companion_recipe_path is not None
                       else google_edit_preflight),
            gateway_state_dir=args.task_write_gateway_state_dir,
        )
        try:
            write_confirmation._binary()
        except OperatorDenied as error:
            parser.error(str(error))
    workbench = Workbench(sessions, oauth, EnrollmentStore(args.state_db),
                          AgentRegistry(args.state_db), TaskProposalStore(args.state_db),
                          TaskApprovalStore(args.state_db), TaskActivationStore(args.state_db),
                          vault, company, status, origin, trusted_template, expected_root,
                          agent_transport, service, write_browser,
                          args.task_write_evidence, write_pins, write_confirmation,
                          write_target, finance_read_target, edit_rerun_target,
                          negative_create_target, populate_failure_target,
                          project_b_exclusion_target)
    bind_address = "0.0.0.0" if args.container_bind else "127.0.0.1"
    with WorkbenchServer((bind_address, args.port), workbench) as server:
        print(f"Auths workbench: {origin} (Google: {status.google})", flush=True)
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
