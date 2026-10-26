from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.finance_denial_handoff import (
    FinanceDenialPins, validate_finance_denial,
)


class FinanceDenialHandoffTests(unittest.TestCase):
    def test_direct_jules_denial_needs_exact_private_producer_evidence(self) -> None:
        now = int(datetime(2026, 10, 25, 19, 51, tzinfo=timezone.utc).timestamp())
        observed = {
            "schema_version": "demo-co/google-finance-denial/v1",
            "status": "passed", "attribution": "provider_state_only",
            "company": "atlas-studio", "instance": "live-test-atlas",
            "definition_hash": "a" * 64, "customer_id": "customer-1",
            "jules_subject": "jules-subject", "resource_id": "doc-finance-budget",
            "document_id": "finance-document-id",
            "observed_at": "2026-10-25T19:50:09Z",
            "admin_file_observed": True,
            "admin_content_matches_fixture": True,
            "jules_metadata_http_status": 404,
            "jules_export_http_status": 404,
            "metadata_response_leaked_fixture": False,
            "export_response_leaked_fixture": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            generation = Path(directory) / "generation-0009"
            generation.mkdir(mode=0o700)
            path = generation / "google-finance-denial.json"

            def write() -> FinanceDenialPins:
                path.write_text(json.dumps(observed, sort_keys=True))
                os.chmod(path, 0o600)
                return FinanceDenialPins(
                    observed["company"], observed["instance"],
                    observed["definition_hash"], observed["customer_id"],
                    observed["jules_subject"], observed["document_id"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

            pins = write()
            self.assertEqual(validate_finance_denial(path, pins, now=now), observed)
            observed["jules_export_http_status"] = 200
            write()
            with self.assertRaisesRegex(ContractRejected, "digest"):
                validate_finance_denial(path, pins, now=now)
            forged = write()
            with self.assertRaisesRegex(ContractRejected, "probe"):
                validate_finance_denial(path, forged, now=now)
            observed["jules_export_http_status"] = 404
            observed["admin_content_matches_fixture"] = False
            with self.assertRaisesRegex(ContractRejected, "schema|probe"):
                validate_finance_denial(path, write(), now=now)
            observed["admin_content_matches_fixture"] = True
            self.assertEqual(validate_finance_denial(path, write(), now=now)[
                "document_id"], "finance-document-id")
            with self.assertRaisesRegex(ContractRejected, "stale"):
                validate_finance_denial(path, write(), now=now + 3601)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ContractRejected, "unavailable"):
                validate_finance_denial(path, pins, now=now)


if __name__ == "__main__":
    unittest.main()
