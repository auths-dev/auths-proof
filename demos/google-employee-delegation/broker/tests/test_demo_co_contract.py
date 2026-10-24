from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from employee_read_demo.demo_co_contract import (
    ContractPending, ContractRejected, OperatorPins, import_company,
    validate_artifacts,
)


EXAMPLES = Path(__file__).parents[2] / "contracts" / "examples"


class DemoCoContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.connections = self.root / "connections.json"
        self.access = self.root / "access-expectations.json"
        self.connections.write_bytes((EXAMPLES / "connections-local-not-ready.json").read_bytes())
        self.access.write_bytes((EXAMPLES / "access-expectations.json").read_bytes())
        data = json.loads(self.connections.read_bytes())
        expected = json.loads(self.access.read_bytes())
        self.pins = OperatorPins(
            data["company_id"], data["instance_id"], data["definition_hash"],
            data["dataset_version"], hashlib.sha256(self.connections.read_bytes()).hexdigest(),
            expected["expectation_hash"], "operator-customer", "example.invalid",
        )

    def test_local_fixture_is_valid_but_never_imported_as_live(self) -> None:
        accepted = validate_artifacts(self.connections, self.access, self.pins)
        self.assertFalse(accepted.google_ready)
        self.assertEqual(accepted.status.google, "not_configured")
        with self.assertRaises(ContractPending):
            import_company(self.connections, self.access, self.pins)

    def test_unknown_field_is_rejected_even_with_new_digest(self) -> None:
        data = json.loads(self.connections.read_bytes())
        data["trusted_issuer"] = "https://attacker.invalid"
        self.connections.write_text(json.dumps(data))
        pins = OperatorPins(**{**self.pins.__dict__, "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        with self.assertRaises(ContractRejected):
            validate_artifacts(self.connections, self.access, pins)

    def test_tampered_expectations_are_rejected(self) -> None:
        data = json.loads(self.access.read_bytes())
        data["cases"][0]["expected"] = "deny"
        self.access.write_text(json.dumps(data))
        with self.assertRaises(ContractRejected):
            validate_artifacts(self.connections, self.access, self.pins)


if __name__ == "__main__":
    unittest.main()
