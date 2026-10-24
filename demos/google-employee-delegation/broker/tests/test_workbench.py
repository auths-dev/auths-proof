from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from employee_read_demo.app import Workbench, WorkbenchServer
from employee_read_demo.browser_sessions import BrowserSessionStore
from employee_read_demo.demo_co_contract import ImportStatus
from employee_read_demo.enrollment import EnrollmentStore


class WorkbenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "broker.sqlite3"
        state = Workbench(
            BrowserSessionStore(path), None, EnrollmentStore(path), None, None,
            ImportStatus("not_configured", "validated", "validated", "Google is absent"),
            "http://127.0.0.1:0",
        )
        self.server = WorkbenchServer(("127.0.0.1", 0), state)
        self.server.workbench = Workbench(
            state.sessions, None, state.enrollment, None, None, state.status,
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
                csrf: str | None = None) -> tuple[int, dict, str | None]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        body = None
        if method == "POST":
            body = b"{}"
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
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        session_cookie = cookie.split(";", 1)[0]
        status, _, _ = self.request("GET", "/api/v1/google/authorize?kind=login",
                                    cookie=session_cookie)
        self.assertEqual(status, 503)
        status, _, _ = self.request("POST", "/api/v1/session/logout",
                                    cookie=session_cookie, csrf="wrong")
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/v1/session/logout",
                                    cookie=session_cookie, csrf=data["csrf"])
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
