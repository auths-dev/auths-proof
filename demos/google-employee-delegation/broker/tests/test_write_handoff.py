from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from employee_read_demo.write_handoff import WriteHandoffPending, inspect_write_handoff


class WriteHandoffTests(unittest.TestCase):
    def test_missing_producer_contract_cannot_activate_write(self) -> None:
        status = inspect_write_handoff()
        self.assertEqual(status.status, "write_not_configured")
        self.assertFalse(status.ready)
        with self.assertRaises(WriteHandoffPending):
            status.require_ready()

    def test_unreviewed_file_cannot_activate_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claimed-ready.json"
            path.write_text(json.dumps({"status": "ready", "token": "do-not-read"}))
            status = inspect_write_handoff(path)
            self.assertEqual(status.status, "write_not_configured")
            self.assertNotIn("do-not-read", repr(status))
            with self.assertRaises(WriteHandoffPending):
                status.require_ready()
