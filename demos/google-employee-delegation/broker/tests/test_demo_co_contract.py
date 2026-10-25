from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from employee_read_demo.demo_co_contract import (
    CompanyImport, ContractPending, ContractRejected, OperatorPins, import_company,
    prepare_operator_pins, validate_artifacts, validate_google_verification,
    validate_scenario_result,
)


EXAMPLES = Path(__file__).parents[2] / "contracts" / "examples"
SCHEMAS = Path(__file__).parents[1] / "src" / "employee_read_demo" / "schemas"


class DemoCoContractTests(unittest.TestCase):
    def test_copied_contract_schemas_match_lock(self) -> None:
        lock = json.loads((Path(__file__).parents[2] / "versions.lock.json").read_text())
        for name, filename in (
            ("connections", "connections-v1.schema.json"),
            ("access_expectations", "access-expectations-v1.schema.json"),
            ("scenario_result", "scenario-result-v1.schema.json"),
            ("google_verification", "google-verification-v1.schema.json"),
        ):
            expected = lock["demo_co_contracts"][name]["schema_sha256"]
            self.assertEqual(hashlib.sha256((SCHEMAS / filename).read_bytes()).hexdigest(), expected)

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

    def test_pin_candidate_uses_independent_operator_identity_inputs(self) -> None:
        values = dict(
            company_id=self.pins.company_id, instance_id=self.pins.instance_id,
            definition_hash=self.pins.definition_hash,
            dataset_version=self.pins.dataset_version,
            google_customer_id=self.pins.google_customer_id,
            google_primary_domain=self.pins.google_primary_domain,
        )
        candidate, accepted = prepare_operator_pins(self.connections, self.access, **values)
        self.assertEqual(candidate, self.pins)
        self.assertFalse(accepted.google_ready)
        with self.assertRaises(ContractRejected):
            prepare_operator_pins(self.connections, self.access,
                                  **{**values, "company_id": "wrong-company"})

    def test_installed_operator_command_writes_private_review_candidate_once(self) -> None:
        output = self.root / "pins.json"
        command = [
            sys.executable, "-m", "employee_read_demo.operator_cli", "propose-pins",
            "--connections", str(self.connections),
            "--access-expectations", str(self.access),
            "--company", self.pins.company_id,
            "--instance", self.pins.instance_id,
            "--definition-hash", self.pins.definition_hash,
            "--dataset-version", self.pins.dataset_version,
            "--google-customer-id", self.pins.google_customer_id,
            "--google-primary-domain", self.pins.google_primary_domain,
            "--out", str(output),
        ]
        first = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["status"], "review_required")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text())["bundle_sha256"], self.pins.bundle_sha256)
        second = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(json.loads(output.read_text())["bundle_sha256"], self.pins.bundle_sha256)

    def test_optional_oidc_client_metadata_does_not_activate_google(self) -> None:
        bundle = json.loads(self.connections.read_bytes())
        bundle["oidc_clients"] = [{
            "issuer": "http://127.0.0.1:58080/realms/demo",
            "client_id": "local-reader", "audience": "local-reader",
            "pkce": "S256", "redirect_uris": ["http://127.0.0.1:18080/callback"],
        }]
        self.connections.write_text(json.dumps(bundle))
        pins = OperatorPins(**{**self.pins.__dict__,
                               "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        accepted = validate_artifacts(self.connections, self.access, pins)
        self.assertFalse(accepted.google_ready)
        bundle["oidc_clients"][0]["private_secret"] = "forbidden"
        self.connections.write_text(json.dumps(bundle))
        pins = OperatorPins(**{**pins.__dict__,
                               "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        with self.assertRaises(ContractRejected):
            validate_artifacts(self.connections, self.access, pins)

    def test_non_google_person_mapping_may_share_logical_person_id(self) -> None:
        bundle = json.loads(self.connections.read_bytes())
        bundle["people"].append({
            "logical_person_id": "person-morgan", "provider": "oidc",
            "issuer": "http://127.0.0.1:58080/realms/demo",
            "provider_subject": "separate-oidc-subject",
            "provider_directory_id": None, "status": "prerequisite_missing",
        })
        self.connections.write_text(json.dumps(bundle))
        pins = OperatorPins(**{**self.pins.__dict__,
                               "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        self.assertFalse(validate_artifacts(self.connections, self.access, pins).google_ready)
        bundle["people"].append(dict(bundle["people"][0]))
        self.connections.write_text(json.dumps(bundle))
        pins = OperatorPins(**{**pins.__dict__,
                               "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        with self.assertRaises(ContractRejected):
            validate_artifacts(self.connections, self.access, pins)

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
        bundle = json.loads(self.connections.read_bytes())
        bundle["access_expectations"]["sha256"] = hashlib.sha256(self.access.read_bytes()).hexdigest()
        self.connections.write_text(json.dumps(bundle))
        pins = OperatorPins(**{**self.pins.__dict__,
                               "bundle_sha256": hashlib.sha256(self.connections.read_bytes()).hexdigest()})
        with self.assertRaises(ContractRejected):
            validate_artifacts(self.connections, self.access, pins)

    def test_local_scenario_cannot_be_called_live(self) -> None:
        scenario = EXAMPLES / "scenario-result-local-not-ready.json"
        observed = validate_scenario_result(scenario, self.pins)
        self.assertEqual(observed["status"], "not_configured")

    def test_agent_scenario_cannot_pass_with_mismatched_outcome(self) -> None:
        scenario = json.loads((EXAMPLES / "scenario-result-local-not-ready.json").read_text())
        scenario.update({
            "mode": "google", "status": "pass", "person_id": "person-morgan",
            "agent_id": "agent-01", "delegation_id": "task-01",
            "delegated_resources": ["project-a-brief"],
            "resource_id": "project-a-brief", "action": "read",
            "boundary": "provider-and-delegation", "expected": "allow",
            "observed": "deny", "evidence_refs": ["independent-probe.json"],
            "failure_reason": None,
        })
        path = self.root / "scenario-result.json"
        path.write_text(json.dumps(scenario))
        with self.assertRaises(ContractRejected):
            validate_scenario_result(path, self.pins)

    def test_google_verification_requires_pinned_matching_independent_probes(self) -> None:
        accepted = CompanyImport(
            {"people": [
                {"provider": "google", "logical_person_id": "person-a",
                 "provider_directory_id": "directory-a", "provider_subject": "subject-a"},
                {"provider": "google", "logical_person_id": "person-b",
                 "provider_directory_id": "directory-b", "provider_subject": "subject-b"},
            ]},
            {"cases": [
                {"logical_person_id": "person-a", "logical_resource_id": "document-a",
                 "status": "pass", "expected": "allow"},
                {"logical_person_id": "person-b", "logical_resource_id": "document-a",
                 "status": "pass", "expected": "deny"},
            ]},
            "bundle-digest", True,
        )
        verification = {
            "schema_version": "demo-co/google-verification/v1",
            "company": self.pins.company_id, "instance": self.pins.instance_id,
            "definition_hash": self.pins.definition_hash,
            "customer_id": self.pins.google_customer_id,
            "checked_at": "2026-10-25T00:00:00Z", "passed": True,
            "people": [
                {"person": "person-a", "directory_id": "directory-a",
                 "subject": "subject-a", "suspended": False},
                {"person": "person-b", "directory_id": "directory-b",
                 "subject": "subject-b", "suspended": False},
            ],
            "probes": [
                {"person": "person-a", "resource": "document-a", "expected": "allow",
                 "observed": "allow", "passed": True, "http_status": 200,
                 "content_sha256": "a" * 64},
                {"person": "person-b", "resource": "document-a", "expected": "deny",
                 "observed": "deny", "passed": True, "http_status": 404},
            ],
        }
        path = self.root / "google-verification.json"

        def pinned() -> OperatorPins:
            path.write_text(json.dumps(verification))
            return OperatorPins(**{**self.pins.__dict__,
                                   "google_verification_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})

        pins = pinned()
        self.assertTrue(validate_google_verification(path, pins, accepted)["passed"])
        verification["probes"][1]["observed"] = "allow"
        path.write_text(json.dumps(verification))
        with self.assertRaises(ContractRejected):
            validate_google_verification(path, pins, accepted)
        with self.assertRaises(ContractRejected):
            validate_google_verification(path, pinned(), accepted)
        verification["probes"][1]["observed"] = "deny"
        verification["people"][1]["subject"] = "wrong-subject"
        with self.assertRaises(ContractRejected):
            validate_google_verification(path, pinned(), accepted)
        verification["people"][1]["subject"] = "subject-b"
        verification["probes"].pop()
        with self.assertRaises(ContractRejected):
            validate_google_verification(path, pinned(), accepted)


if __name__ == "__main__":
    unittest.main()
