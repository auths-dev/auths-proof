from __future__ import annotations

import http.client
import json
import base64
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from employee_read_demo.app import Workbench, WorkbenchServer
from employee_read_demo.agent_registry import AgentRegistry
from employee_read_demo.browser_sessions import BrowserSessionStore
from employee_read_demo.demo_co_contract import ImportStatus
from employee_read_demo.enrollment import EnrollmentStore
from employee_read_demo.google_oauth import OAuthResult
from employee_read_demo.jules_write_context import JulesWriteContext
from employee_read_demo.task_proposals import TaskProposalStore
from employee_read_demo.task_approval import TaskApprovalStore
from employee_read_demo.task_activation import TaskActivationStore


class WorkbenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "broker.sqlite3"
        state = Workbench(
            BrowserSessionStore(path), None, EnrollmentStore(path), AgentRegistry(path),
            TaskProposalStore(path), TaskApprovalStore(path), TaskActivationStore(path), None, None,
            ImportStatus("not_configured", "validated", "validated", "Google is absent"),
            "http://127.0.0.1:0",
        )
        self.server = WorkbenchServer(("127.0.0.1", 0), state)
        self.server.workbench = Workbench(
            state.sessions, None, state.enrollment, state.agents, state.proposals,
            state.approvals,
            state.activations,
            None, None, state.status,
            f"http://127.0.0.1:{self.server.server_port}",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._close)

    def _close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, method: str, path: str, *, cookie: str | None = None,
                csrf: str | None = None, payload: dict | None = None) -> tuple[int, dict, str | None]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        body = None
        if method == "POST":
            body = json.dumps(payload if payload is not None else {}).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read())
        set_cookie = response.getheader("Set-Cookie")
        status = response.status
        connection.close()
        return status, data, set_cookie

    def test_local_workbench_keeps_google_closed_and_requires_csrf(self) -> None:
        status, data, cookie = self.request("GET", "/api/v1/session")
        self.assertEqual(status, 200)
        self.assertEqual(data["google_status"], "not_configured")
        self.assertFalse(data["drive_connected"])
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        session_cookie = cookie.split(";", 1)[0]
        status, _, _ = self.request("GET", "/api/v1/google/authorize?kind=login",
                                    cookie=session_cookie)
        self.assertEqual(status, 503)
        status, _, _ = self.request("POST", "/api/v1/session/logout",
                                    cookie=session_cookie, csrf="wrong")
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/v1/tasks/prepare",
                                    cookie=session_cookie, csrf=data["csrf"])
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/v1/session/logout",
                                    cookie=session_cookie, csrf=data["csrf"])
        self.assertEqual(status, 200)

    def test_public_identity_packet_requires_employee_browser_csrf(self) -> None:
        status, session, cookie = self.request("GET", "/api/v1/session")
        self.assertEqual(status, 200)
        public = base64.urlsafe_b64encode(b"\x42" * 32).decode()
        path = "/api/v1/identity/packet"
        status, _, _ = self.request("POST", path, payload={"public_key": public})
        self.assertEqual(status, 403)
        status, packet, _ = self.request(
            "POST", path, cookie=cookie.split(";", 1)[0], csrf=session["csrf"],
            payload={"public_key": public},
        )
        self.assertEqual(status, 200)
        self.assertTrue(packet["identity_packet"])
        self.assertTrue(packet["principal"])

    def test_workbench_assets_are_served_with_no_store(self) -> None:
        for path, marker in (("/", b"Review and authorize one task"),
                             ("/workbench.js", b"signEmployee"),
                             ("/style.css", b"#message")):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
            connection.request("GET", path)
            response = connection.getresponse()
            content = response.read()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            self.assertIn(marker, content)
            connection.close()

    def test_desktop_oauth_callback_uses_root_and_rotates_session(self) -> None:
        session = self.server.workbench.sessions.create()
        self.server.workbench = replace(
            self.server.workbench,
            company=SimpleNamespace(bundle={"company_id": "atlas-studio"}),
            oauth=SimpleNamespace(complete=lambda **kwargs: OAuthResult(
                "login", "https://accounts.google.com", "google-subject-a",
                "employee@example.invalid", frozenset(), "access-token", None, 3600,
            )),
        )
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request("GET", "/?state=state-a&code=code-a",
                           headers={"Cookie": f"ap070_session={session.cookie}"})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/")
        rotated_cookie = response.getheader("Set-Cookie")
        self.assertIsNotNone(rotated_cookie)
        self.assertNotIn(session.cookie, rotated_cookie)
        connection.close()

        status, data, _ = self.request("GET", "/?state=&code=code-a")
        self.assertEqual(status, 403)
        self.assertEqual(data["error"], "Google callback is incomplete")

    def test_other_company_browser_cookie_cannot_authorize_this_workbench(self) -> None:
        sessions = self.server.workbench.sessions
        other = sessions.login(sessions.create(), issuer="https://accounts.google.com",
                               subject="shared-subject", company="other-company")
        self.server.workbench = replace(
            self.server.workbench,
            company=SimpleNamespace(bundle={"company_id": "atlas-studio"}),
        )
        status, data, new_cookie = self.request(
            "GET", "/api/v1/session", cookie=f"ap070_session={other.cookie}",
        )
        self.assertEqual(status, 200)
        self.assertIsNone(data["subject"])
        self.assertIsNotNone(new_cookie)
        status, _, _ = self.request(
            "POST", "/api/v1/tasks/prepare", cookie=f"ap070_session={other.cookie}",
            csrf=other.csrf,
        )
        self.assertEqual(status, 403)

    def test_jules_only_login_refuses_other_subject_and_drive_reconsent(self) -> None:
        context = JulesWriteContext(
            {"company_id": "atlas-studio", "people": []},
            "c" * 64, "jules-subject",
        )
        self.server.workbench = replace(
            self.server.workbench, company=context,
            status=ImportStatus("jules_write_only", "not_imported", "not_imported",
                                "pinned Jules evidence"),
            oauth=SimpleNamespace(complete=lambda **kwargs: OAuthResult(
                "login", "https://accounts.google.com", "other-subject",
                None, frozenset(), "access-token", None, 3600,
            )),
        )
        status, session, cookie = self.request("GET", "/api/v1/session")
        self.assertEqual(status, 200)
        self.assertEqual(session["google_status"], "jules_write_only")
        self.assertFalse(session["task_write_available"])
        session_cookie = cookie.split(";", 1)[0]
        status, denied, _ = self.request(
            "GET", "/api/v1/google/authorize?kind=connect", cookie=session_cookie,
        )
        self.assertEqual(status, 403)
        self.assertIn("existing checked Drive grant", denied["error"])
        status, denied, _ = self.request(
            "GET", "/?state=state-a&code=code-a", cookie=session_cookie,
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "Google login is not pinned Jules")
        self.server.workbench = replace(
            self.server.workbench,
            oauth=SimpleNamespace(complete=lambda **kwargs: OAuthResult(
                "connect", "https://accounts.google.com", "jules-subject",
                None, frozenset(), "access-token", None, 3600,
            )),
        )
        status, denied, _ = self.request(
            "GET", "/?state=state-b&code=code-b", cookie=session_cookie,
        )
        self.assertEqual(status, 403)
        self.assertIn("existing checked Drive grant", denied["error"])


if __name__ == "__main__":
    unittest.main()
