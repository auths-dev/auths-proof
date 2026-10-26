from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.finance_denial_handoff import FinanceDenialPins
from employee_read_demo.finance_write_grant_handoff import (
    FinanceWriteGrantPins, validate_finance_write_grant,
)


class FinanceWriteGrantHandoffTests(unittest.TestCase):
    def test_same_grant_denial_is_private_fresh_and_source_bound(self) -> None:
        now = int(datetime(2026, 10, 25, 20, 5, tzinfo=timezone.utc).timestamp())
        source = FinanceDenialPins(
            "atlas-studio", "live-test-atlas", "a" * 64, "customer-1",
            "jules-subject", "finance-document-id", "b" * 64,
        )
        observed = {
            "schema_version": "demo-co/google-finance-write-grant-denial/v1",
            "status": "passed", "attribution": "provider_state_only",
            "company": source.company, "instance": source.instance,
            "definition_hash": source.definition_hash,
            "observed_at": "2026-10-25T20:04:09Z",
            "jules_subject": source.jules_subject,
            "resource_id": "doc-finance-budget",
            "document_id": source.document_id,
            "grant_kind": "existing_google_write_person_jules_drive_file",
            "granted_scopes": [
                "openid", "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/drive.file",
            ],
            "source_admin_finance_denial_generation": 9,
            "source_admin_finance_denial_sha256": source.evidence_sha256,
            "metadata_http_status": 404, "export_http_status": 404,
            "metadata_response_leaked_fixture": False,
            "export_response_leaked_fixture": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            generation = Path(directory) / "generation-0012"
            generation.mkdir(mode=0o700)
            path = generation / "google-finance-write-grant-denial.json"

            def write() -> FinanceWriteGrantPins:
                path.write_text(json.dumps(observed, sort_keys=True))
                os.chmod(path, 0o600)
                return FinanceWriteGrantPins(
                    source, 9, hashlib.sha256(path.read_bytes()).hexdigest(),
                )

            pins = write()
            self.assertEqual(validate_finance_write_grant(path, pins, now=now),
                             observed)
            observed["export_http_status"] = 200
            with self.assertRaisesRegex(ContractRejected, "digest"):
                write()
                validate_finance_write_grant(path, pins, now=now)
            with self.assertRaisesRegex(ContractRejected, "schema|probe"):
                validate_finance_write_grant(path, write(), now=now)
            observed["export_http_status"] = 404
            observed["source_admin_finance_denial_sha256"] = "c" * 64
            with self.assertRaisesRegex(ContractRejected, "probe"):
                validate_finance_write_grant(path, write(), now=now)
            observed["source_admin_finance_denial_sha256"] = source.evidence_sha256
            self.assertEqual(validate_finance_write_grant(path, write(), now=now)[
                "document_id"], source.document_id)
            with self.assertRaisesRegex(ContractRejected, "stale"):
                validate_finance_write_grant(path, write(), now=now + 3601)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ContractRejected, "unavailable"):
                validate_finance_write_grant(path, pins, now=now)


if __name__ == "__main__":
    unittest.main()
