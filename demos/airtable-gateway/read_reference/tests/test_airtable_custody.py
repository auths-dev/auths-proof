"""The demo custody sidecar refuses changed pins before returning a PAT."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "airtable_custody.py"


class AirtableCustodyTests(unittest.TestCase):
    def test_exact_context_and_private_pat_file_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pat = root / "airtable.env"
            pat.write_text("PERSONAL_ACCESS_TOKEN=patSyntheticOnly\n")
            pat.chmod(0o600)
            source = "auths.materializer-source/1:airtable-operator-pat://test"
            pins = {
                "schema": "auths.airtable-custody-pins/1",
                "connection_id": "conn_AAAAAAAAAAAAAAAAAAAAAA",
                "connection_generation": 1, "source_generation": 1,
                "source_ref": source, "account_subject": "operator-test",
                "recipe_digest": "a" * 64, "kind": "read-release",
                "pat_file": str(pat),
                "pat_file_sha256": hashlib.sha256(pat.read_bytes()).hexdigest(),
            }
            pins_path = root / "pins.json"
            pins_path.write_text(json.dumps(pins, sort_keys=True, separators=(",", ":")))
            pins_path.chmod(0o600)
            request = {
                "schema": "auths.custody-process-request/1",
                "task_id": "task", "operation_id": "read",
                "connection_id": pins["connection_id"],
                "connection_generation": 1, "source_generation": 1,
                "account_subject": "operator-test", "recipe_digest": "a" * 64,
                "task_expires_at": int(time.time()) + 60, "kind": "read-release",
                "source_base64": base64.urlsafe_b64encode(source.encode()).decode().rstrip("="),
            }

            def invoke(candidate: dict) -> subprocess.CompletedProcess:
                return subprocess.run(
                    [sys.executable, str(SCRIPT), "--materialize", "--pins", str(pins_path)],
                    input=json.dumps(candidate).encode(), capture_output=True, timeout=5,
                    env={"PYTHONPATH": str(SCRIPT.parent.parent),
                         "PYTHONNOUSERSITE": "1"},
                )

            accepted = invoke(request)
            self.assertEqual(accepted.returncode, 0)
            output = json.loads(accepted.stdout)
            self.assertEqual(base64.urlsafe_b64decode(
                output["bearer_base64"] + "=" * (-len(output["bearer_base64"]) % 4)
            ), b"patSyntheticOnly")
            for changed in (
                {**request, "recipe_digest": "b" * 64},
                {**request, "connection_generation": 2},
                {**request, "source_base64": base64.urlsafe_b64encode(b"other").decode()},
            ):
                self.assertEqual(invoke(changed).returncode, 2)
            pat.write_text("PERSONAL_ACCESS_TOKEN=patChanged\n")
            self.assertEqual(invoke(request).returncode, 2)


if __name__ == "__main__":
    unittest.main()
