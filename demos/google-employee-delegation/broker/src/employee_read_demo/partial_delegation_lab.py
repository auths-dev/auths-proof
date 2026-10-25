"""Diagnostic human signature over Jules's existing Google grant.

This bypasses only the missing demo_co export in a separate process. Google
login binds the browser signer to Jules, while the existing Drive credential
remains unchanged. It is not full AP-SPEC-070 acceptance: the agent key and
broker still share a process. The production importer and vault stay closed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import stat
import tempfile
import time
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .admission import AdmissionDenied, AdmissionStore
from .authority import native_body_digest
from .browser_sessions import SessionDenied
from .contracts import TaskDescriptor, canonical_json
from .demo_co_contract import _unique_pairs
from .existing_consent_smoke import ExistingConsentPins, ExistingDemoCoConsentLease
from .google_drive import GoogleDriveReader
from .google_oauth import GoogleOAuth, GoogleOAuthConfig, OAuthStateStore, TOKEN_URL
from .operator_cli import _private_read, _private_write
from .read_executor import execute_read
from .receipts import ReceiptStore, verify_receipt
from .task_authority import plan_agent_grant

HEX64 = re.compile(r"^[0-9a-f]{64}$")
QUALIFICATION = "operator_assisted_partial_delegation_not_employee_onboarding"
_EVIDENCE_TYPE = "raw-key-v1"
_EVIDENCE_MEDIA = "application/vnd.auths.raw-key.v1"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str, length: int) -> bytes:
    if type(value) is not str or len(value) > length * 2 or not value.isascii():
        raise ValueError("encoded field is invalid")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as error:
        raise ValueError("encoded field is invalid") from error
    if len(raw) != length:
        raise ValueError("encoded field has wrong length")
    return raw


def _callback_state_and_code(raw_query: str) -> tuple[str, str]:
    """Accept Google's extra callback metadata, never ambiguous code/state."""
    query = parse_qs(raw_query, strict_parsing=True)
    if (len(query.get("state", [])) != 1 or len(query.get("code", [])) != 1
            or any(len(values) != 1 for values in query.values())):
        raise ValueError("OAuth callback is invalid")
    return query["state"][0], query["code"][0]


@dataclass(frozen=True)
class PartialInputs:
    report_sha256: str
    definition_hash: str
    customer_id: str
    domain: str
    subject: str
    email: str
    client_id: str
    project_a_id: str
    project_a_sha256: str
    project_b_id: str


def load_inputs(report_path: Path, report_sha256: str, oauth_client_path: Path) -> PartialInputs:
    if not HEX64.fullmatch(report_sha256):
        raise ValueError("report digest pin is invalid")
    raw = _private_read(report_path, 65_536)
    if hashlib.sha256(raw).hexdigest() != report_sha256:
        raise ValueError("producer partial report digest changed")
    report = json.loads(raw, object_pairs_hook=_unique_pairs)
    if (type(report) is not dict or report.get("schema_version") != "demo-co/google-partial-probe/v1"
            or report.get("qualification") != "partial_only_not_full_google_verification"
            or report.get("full_google_ready") is not False or report.get("passed") is not True
            or report.get("company") != "atlas-studio"
            or report.get("instance") != "live-test-atlas-20261025"
            or report.get("customer_id") != "C0218tf2n"
            or report.get("primary_domain") != "auths.dev"
            or report.get("dataset_version") != "atlas-v1"
            or not isinstance(report.get("definition_hash"), str)
            or not HEX64.fullmatch(report["definition_hash"])):
        raise ValueError("report is not the pinned partial Atlas generation")
    identity = report.get("identities", {}).get("person-jules", {})
    if (type(identity) is not dict or identity.get("email") != "jules@auths.dev"
            or not isinstance(identity.get("google_subject"), str)
            or not identity["google_subject"] or identity.get("suspended") is not False):
        raise ValueError("Jules identity is unavailable in producer report")
    def probe(resource: str) -> dict:
        matches = [item for item in report.get("probes", []) if type(item) is dict
                   and item.get("person") == "person-jules" and item.get("resource") == resource]
        if (len(matches) != 1 or matches[0].get("expected") != "allow"
                or matches[0].get("observed") != "allow" or matches[0].get("passed") is not True
                or not isinstance(matches[0].get("file_id"), str)
                or not isinstance(matches[0].get("content_sha256"), str)
                or not HEX64.fullmatch(matches[0]["content_sha256"])):
            raise ValueError("independent allowed control probe is missing")
        return matches[0]
    project_a, project_b = probe("doc-project-a-status"), probe("doc-project-b-plan")
    if project_a["file_id"] == project_b["file_id"]:
        raise ValueError("project controls overlap")
    oauth = json.loads(_private_read(oauth_client_path, 4096), object_pairs_hook=_unique_pairs)
    client = oauth.get("installed") if type(oauth) is dict else None
    if (type(client) is not dict or not isinstance(client.get("client_id"), str)
            or not client["client_id"] or client.get("token_uri") != TOKEN_URL):
        raise ValueError("reviewed OAuth client configuration is invalid")
    return PartialInputs(report_sha256, report["definition_hash"], report["customer_id"],
                         report["primary_domain"], identity["google_subject"],
                         identity["email"], client["client_id"], project_a["file_id"],
                         project_a["content_sha256"], project_b["file_id"])


class PartialDelegationLab:
    """One task, one browser signature, one real read, then revocation."""

    def __init__(self, inputs: PartialInputs, grant_path: Path) -> None:
        self.inputs = inputs
        self.grant_path = grant_path
        self.root_key = Ed25519PrivateKey.generate()
        self.agent_key = Ed25519PrivateKey.generate()
        from auths import _native
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.root_principal, self.root_evidence = _native.raw_key_ed25519_authority_v1(
            self.root_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.agent_principal, self.agent_evidence = _native.raw_key_ed25519_authority_v1(
            self.agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self._directory = tempfile.TemporaryDirectory(prefix="ap070-partial-human-")
        self.db = Path(self._directory.name) / "broker.sqlite3"
        self.task: TaskDescriptor | None = None
        self.employee_public_key: bytes | None = None
        self.employee_evidence: bytes | None = None
        self.root_grant = None
        self.prepared = None
        self.prepared_at: int | None = None
        self.used = False
        self.preparing_session_hash: str | None = None

    def close(self) -> None:
        self._directory.cleanup()

    def prepare(self, public_key: bytes, *, google_subject: str,
                browser_cookie: str) -> dict:
        if google_subject != self.inputs.subject or not browser_cookie:
            raise ValueError("Jules Google login is required")
        if self.task is not None or len(public_key) != 32:
            raise ValueError("one valid browser key may prepare this lab")
        from auths import _native
        employee_principal, evidence = _native.raw_key_ed25519_authority_v1(public_key)
        now = int(time.time())
        task = TaskDescriptor(
            "auths.google-read-task/v1", "atlas-studio", "live-test-atlas-20261025",
            self.inputs.definition_hash, employee_principal, "partial-jules-binding",
            self.agent_principal, "atlas-drive", "partial-demo-co-jules", 1,
            (self.inputs.project_a_id,), "text", 262_144, 1, 262_144,
            now - 1, now + 600, "partial-human-" + secrets.token_hex(12),
            "Operator-assisted partial Jules read delegation",
        )
        task.validate()
        pins = ExistingConsentPins(
            task.company_id, task.instance_id, "person-jules", self.inputs.customer_id,
            self.inputs.domain, self.inputs.email, self.inputs.subject, self.inputs.client_id,
            task.employee_principal, task.identity_binding_ref, task.connection_id,
            task.connection_generation, task.task_id, task.file_ids,
        )
        lease = ExistingDemoCoConsentLease(self.grant_path, pins)
        # Fixed Google UserInfo verifies the existing grant before the human is
        # asked to sign. It does not authenticate the browser operator as Jules.
        lease.lease(task, now=now)
        audience = "mcp://atlas-drive"
        resource = audience + "/tools/google_drive_document_read"
        request = _native.GrantRequest(
            _native.Principal(employee_principal), "auths.mcp", 2,
            [("tools/call", resource)], now - 60, now + 660,
            [audience], None, None, 1, None, "raw-key-baseline", [],
        )
        unsigned_root = _native.root_grant(_native.Principal(self.root_principal), request)
        root_prepared = _native.prepare_signing(unsigned_root, "raw-key-v1",
                                                self.root_principal, "ed25519-v1")
        self.root_grant = root_prepared.complete(self.root_key.sign(bytes(root_prepared.signing_preimage)))
        plan = plan_agent_grant(task, _native.inspect_signed(self.root_grant),
                                assurance_floor="raw-key-baseline")
        self.prepared = _native.prepare_signing(plan.unsigned, "raw-key-v1",
                                                 employee_principal, "ed25519-v1")
        self.prepared_at = now
        self.task = task
        self.employee_public_key = public_key
        self.employee_evidence = evidence
        self.preparing_session_hash = hashlib.sha256(browser_cookie.encode("ascii")).hexdigest()
        return {
            "qualification": QUALIFICATION,
            "review": {
                "company": task.company_id, "google_account": self.inputs.email,
                "google_subject_reference": hashlib.sha256(self.inputs.subject.encode()).hexdigest(),
                "employee_auths_principal": employee_principal,
                "agent_auths_principal": self.agent_principal,
                "approved_document": "doc-project-a-status", "file_id": self.inputs.project_a_id,
                "excluded_document": "doc-project-b-plan", "excluded_file_id": self.inputs.project_b_id,
                "output": task.output, "max_calls": task.max_calls,
                "max_total_bytes": task.max_total_bytes, "expires_at": task.expires_at,
                "task_id": task.task_id, "task_commitment": task.digest,
            },
            "signing_preimage": _b64(bytes(self.prepared.signing_preimage)),
            "browser_google_identity_verified": True,
        }

    def approve_and_run(self, signature: bytes, *, google_subject: str,
                        browser_cookie: str) -> dict:
        if (google_subject != self.inputs.subject or not self.preparing_session_hash
                or hashlib.sha256(browser_cookie.encode("ascii")).hexdigest()
                != self.preparing_session_hash):
            raise ValueError("Jules Google browser session changed")
        if (self.used or self.task is None or self.prepared is None
                or self.employee_public_key is None or self.employee_evidence is None
                or self.prepared_at is None):
            raise ValueError("delegation preparation is unavailable")
        self.used = True
        Ed25519PublicKey.from_public_bytes(self.employee_public_key).verify(
            signature, bytes(self.prepared.signing_preimage))
        from auths import _native
        from dataclasses import replace
        task = self.task
        child_grant = self.prepared.complete(signature)
        command = task.calls()[0]
        store = AdmissionStore(self.db)
        store.register_connection(connection_id=task.connection_id, company=task.company_id,
                                  employee=task.employee_principal,
                                  binding_ref=task.identity_binding_ref, generation=1)
        store.enroll(task)
        excluded = replace(command, file_id=self.inputs.project_b_id)
        try:
            store.issue_challenge(task, native_body_digest(excluded, task.service), now=int(time.time()))
        except AdmissionDenied:
            pass
        else:
            raise RuntimeError("excluded Project B received a challenge")
        challenge = store.issue_challenge(task, native_body_digest(command, task.service), now=int(time.time()))
        arguments = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(command)))
        call = _native.mcp_call(task.service, "google_drive_document_read", arguments)
        prepared_action = _native.prepare_mcp_call_action(
            call, _native.Principal(self.agent_principal), child_grant,
            challenge, int(time.time()), 30,
        )
        agent_signing = _native.prepare_signing(prepared_action.unsigned, "raw-key-v1",
                                                 self.agent_principal, "ed25519-v1")
        signed_action = agent_signing.complete(self.agent_key.sign(bytes(agent_signing.signing_preimage)))
        assurance = _native.AssurancePolicy("raw-key-baseline", [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ])
        audience = f"mcp://{task.service}"
        resource = f"{audience}/tools/google_drive_document_read"
        now = int(time.time())
        anchor = _native.TrustAnchor(
            self.root_principal, _native.Principal(self.root_principal),
            ["raw-key-v1"], [("auths.mcp", 2)], [("tools/call", resource)],
            [audience], [audience], self.prepared_at - 60,
            self.prepared_at + 660, None, 2,
            "raw-key-baseline", None,
        )
        template = _native.compile_trusted_context(
            _native.self_contained_configuration(), None, 1, 1, 1,
            [anchor], assurance, None, None, "none-v1", [_EVIDENCE_TYPE], [],
        )
        context = template.bind_request(audience, challenge, now)
        def evidence(raw: bytes) -> tuple[str, str, bytes]:
            return _EVIDENCE_TYPE, _EVIDENCE_MEDIA, bytes(raw)
        proof, action, _ = _native.assemble_mcp_proof(
            prepared_action, signed_action, [self.root_grant, child_grant],
            [[evidence(self.root_evidence)], [evidence(self.employee_evidence)]],
            [evidence(self.agent_evidence)], context,
        )
        pins = ExistingConsentPins(
            task.company_id, task.instance_id, "person-jules", self.inputs.customer_id,
            self.inputs.domain, self.inputs.email, self.inputs.subject, self.inputs.client_id,
            task.employee_principal, task.identity_binding_ref, task.connection_id,
            task.connection_generation, task.task_id, task.file_ids,
        )
        provider = GoogleDriveReader(task, ExistingDemoCoConsentLease(self.grant_path, pins))
        receipts = ReceiptStore(self.db, Ed25519PrivateKey.generate())
        outcome = execute_read(
            task=task, challenge=challenge, proof=proof, action=action,
            trusted_template=bytes(_native.inspect_trusted_context(template)),
            store=store, provider=provider, receipts=receipts,
        )
        digest = hashlib.sha256(outcome.content).hexdigest()
        if digest != self.inputs.project_a_sha256:
            raise RuntimeError("live Auths read differs from independent producer hash")
        receipt = receipts.load(outcome.receipt_id)
        if receipt is None or not verify_receipt(receipt, receipts.public_key):
            raise RuntimeError("signed read receipt did not verify")
        store.revoke(task.task_id)
        try:
            store.issue_challenge(task, native_body_digest(command, task.service), now=int(time.time()))
        except AdmissionDenied:
            revoked = True
        else:
            revoked = False
        if not revoked:
            raise RuntimeError("revoked task received a new challenge")
        return {
            "qualification": QUALIFICATION,
            "producer_report_sha256": self.inputs.report_sha256,
            "task_id": task.task_id,
            "employee_key_signature_verified": True,
            "browser_google_identity_verified": True,
            "agent_distinct_principal": self.agent_principal != task.employee_principal,
            "agent_process_isolated": False,
            "native_code": outcome.native_code,
            "project_a": {"observed": "released", "hash_matches_producer": True,
                          "content_bytes": len(outcome.content),
                          "provider_requests": provider.trace.requests_started},
            "project_b": {"observed": "denied_before_provider", "provider_requests": 0},
            "receipt_signature_verified": True,
            "receipt_id": outcome.receipt_id,
            "revoked_new_challenge_denied": True,
            "full_google_export_ready": False,
            "full_ap_spec_070_acceptance": False,
        }


_PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="csrf-token" content="__CSRF__">
<title>Atlas Jules delegation lab</title>
<h1>Atlas · Jules human-to-agent delegation lab</h1>
<p>This uses Jules's existing Google Drive grant. Sign in with Google as Jules
to bind this browser to that employee subject before preparing a task. This
login requests only OpenID and email; it does not replace the Drive grant.</p>
<p id="identity">__IDENTITY__</p>
<button id="login" __LOGIN_DISABLED__>Sign in with Google as Jules</button>
<p>The browser creates a non-exportable Auths signing key for this task. The
agent has a distinct Auths key, but this diagnostic runs both roles in one
broker process.</p>
<p>The production importer remains closed. This is not full AP-SPEC-070 acceptance.</p>
<button id="prepare" __PREPARE_DISABLED__>Prepare exact delegation</button>
<h2>Scope to review</h2><pre id="review">No task prepared.</pre>
<button id="approve" disabled>Sign this exact delegation and run one read</button>
<h2>Redacted result</h2><pre id="result">No read attempted.</pre>
<script src="/lab.js"></script></html>
"""

_SCRIPT = """'use strict';
let keyPair = null;
let prepared = null;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const review = document.getElementById('review');
const result = document.getElementById('result');
const prepareButton = document.getElementById('prepare');
const approveButton = document.getElementById('approve');
document.getElementById('login').onclick = async () => {
  try {
    const data = await post('/oauth/start', {});
    window.location.assign(data.authorization_url);
  } catch (error) { review.textContent = String(error); }
};
function b64(bytes) {
  let s = ''; for (const byte of new Uint8Array(bytes)) s += String.fromCharCode(byte);
  return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function unb64(value) {
  const s = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
async function post(path, value) {
  const response = await fetch(path, {method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json', 'X-CSRF-Token':csrf},
    body:JSON.stringify(value)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Lab request failed');
  return data;
}
prepareButton.onclick = async () => {
  prepareButton.disabled = true;
  try {
    keyPair = await crypto.subtle.generateKey({name:'Ed25519'}, false, ['sign','verify']);
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    prepared = await post('/prepare', {public_key:b64(publicKey)});
    review.textContent = JSON.stringify(prepared.review, null, 2);
    approveButton.disabled = false;
  } catch (error) { review.textContent = String(error); }
};
approveButton.onclick = async () => {
  approveButton.disabled = true;
  try {
    const preimage = unb64(prepared.signing_preimage);
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, preimage);
    const data = await post('/approve', {signature:b64(signature)});
    result.textContent = JSON.stringify(data, null, 2);
  } catch (error) { result.textContent = String(error); }
};
"""


class LabServer(HTTPServer):
    def __init__(self, port: int, lab: PartialDelegationLab, output: Path,
                 oauth_config: GoogleOAuthConfig) -> None:
        self.lab = lab
        self.output = output
        self.oauth = GoogleOAuth(oauth_config, OAuthStateStore(lab.db))
        super().__init__(("127.0.0.1", port), LabHandler)


class LabHandler(BaseHTTPRequestHandler):
    server: LabServer

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str,
              *, cookie: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        if cookie is not None:
            self.send_header("Set-Cookie", f"ap070_lab={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, value: dict) -> None:
        self._send(status, canonical_json(value), "application/json; charset=utf-8")

    def _session(self):
        fields = [part.strip() for part in self.headers.get("Cookie", "").split(";")]
        candidates = [part[10:] for part in fields if part.startswith("ap070_lab=")]
        if len(candidates) != 1:
            raise SessionDenied("browser session is unavailable")
        return self.server.oauth.states.sessions.get(candidates[0])

    def _redirect_home(self, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", f"ap070_lab={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            try:
                session = self._session()
                cookie = None
            except SessionDenied:
                session = self.server.oauth.states.sessions.create()
                cookie = session.cookie
            logged_in = session.subject == self.server.lab.inputs.subject
            page = (_PAGE.replace("__CSRF__", session.csrf)
                    .replace("__IDENTITY__", "Google authenticated: jules@auths.dev" if logged_in
                             else "Google authentication required")
                    .replace("__LOGIN_DISABLED__", "disabled" if logged_in else "")
                    .replace("__PREPARE_DISABLED__", "" if logged_in else "disabled"))
            self._send(HTTPStatus.OK, page.encode(), "text/html; charset=utf-8", cookie=cookie)
        elif path == "/lab.js":
            self._send(HTTPStatus.OK, _SCRIPT.encode(), "text/javascript; charset=utf-8")
        elif path == "/oauth/callback":
            try:
                session = self._session()
                # Google can append issuer, scope, account and prompt metadata.
                # Only state and code are consumed; both must be unambiguous.
                state, code = _callback_state_and_code(urlsplit(self.path).query)
                result = self.server.oauth.complete(state=state, code=code,
                                                    browser_cookie=session.cookie)
                if result.subject != self.server.lab.inputs.subject or result.email != self.server.lab.inputs.email:
                    raise ValueError("Google subject is not Jules")
                session = self.server.oauth.states.sessions.login(
                    session, issuer=result.issuer, subject=result.subject)
            except Exception as error:
                print(f"Partial lab Google login failed: {type(error).__name__}", flush=True)
                self._json(HTTPStatus.FORBIDDEN, {"error": "Jules Google login failed"})
                return
            self._redirect_home(session.cookie)
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "unavailable"})

    def do_POST(self) -> None:
        origin = f"http://127.0.0.1:{self.server.server_port}"
        try:
            session = self._session()
            self.server.oauth.states.sessions.check_csrf(session, self.headers.get("X-CSRF-Token", ""))
        except SessionDenied:
            self._json(HTTPStatus.FORBIDDEN, {"error": "browser session is unavailable"})
            return
        if (self.headers.get("Origin") != origin
                or self.headers.get("Content-Type") != "application/json"):
            self._json(HTTPStatus.FORBIDDEN, {"error": "request origin is unavailable"})
            return
        try:
            size = int(self.headers.get("Content-Length", ""))
            if not 1 <= size <= 4096:
                raise ValueError("request size is invalid")
            body = json.loads(self.rfile.read(size), object_pairs_hook=_unique_pairs)
            path = urlsplit(self.path).path
            if path == "/oauth/start" and body == {}:
                url, _ = self.server.oauth.begin("login", browser_cookie=session.cookie)
                response = {"authorization_url": url + "&login_hint=jules%40auths.dev&prompt=select_account"}
            elif path == "/prepare" and type(body) is dict and set(body) == {"public_key"}:
                response = self.server.lab.prepare(_unb64(body["public_key"], 32),
                                                   google_subject=session.subject or "",
                                                   browser_cookie=session.cookie)
            elif path == "/approve" and type(body) is dict and set(body) == {"signature"}:
                response = self.server.lab.approve_and_run(_unb64(body["signature"], 64),
                                                           google_subject=session.subject or "",
                                                           browser_cookie=session.cookie)
                _private_write(self.server.output, canonical_json(response) + b"\n")
            else:
                raise ValueError("lab action is unavailable")
        except Exception as error:
            # Never echo a provider exception, credential, or private path into
            # the browser. The terminal gets only the exception class.
            print(f"Partial lab failed: {type(error).__name__}", flush=True)
            self._json(HTTPStatus.FORBIDDEN, {"error": "partial lab action failed"})
            return
        self._json(HTTPStatus.OK, response)


def main() -> int:
    parser = argparse.ArgumentParser(description="Operator-assisted partial Atlas/Jules delegation lab")
    parser.add_argument("--producer-report", required=True, type=Path)
    parser.add_argument("--producer-report-sha256", required=True)
    parser.add_argument("--oauth-client", required=True, type=Path)
    parser.add_argument("--employee-grant", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8870)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or args.out.exists():
        parser.error("port or private output path is unavailable")
    if (args.out.parent.is_symlink() or not args.out.parent.is_dir()
            or stat.S_IMODE(args.out.parent.stat().st_mode) & 0o077):
        parser.error("output directory must exist and be owner-only")
    inputs = load_inputs(args.producer_report, args.producer_report_sha256, args.oauth_client)
    oauth = json.loads(_private_read(args.oauth_client, 4096), object_pairs_hook=_unique_pairs)["installed"]
    oauth_config = GoogleOAuthConfig(inputs.client_id, oauth["client_secret"],
                                    f"http://127.0.0.1:{args.port}/oauth/callback", inputs.domain)
    lab = PartialDelegationLab(inputs, args.employee_grant)
    try:
        with LabServer(args.port, lab, args.out, oauth_config) as server:
            print(f"Partial delegation lab: http://127.0.0.1:{args.port}/", flush=True)
            server.serve_forever(poll_interval=0.5)
    finally:
        lab.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
