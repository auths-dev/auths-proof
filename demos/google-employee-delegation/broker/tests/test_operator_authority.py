from __future__ import annotations

import tempfile
import unittest
import json
import base64
from pathlib import Path

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding, EnrollmentStore
from employee_read_demo.operator_authority import EmployeeAuthorityStore, OperatorDenied, OperatorRoot
from employee_read_demo.operator_cli import init_root, issue_employee


class OperatorAuthorityTests(unittest.TestCase):
    def test_root_issues_bounded_employee_grant_from_enrolled_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sqlite3"
            EnrollmentStore(path)
            employee_key = Ed25519PrivateKey.generate()
            public = employee_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            identity = create_raw_key_ed25519_identity(public)
            principal, evidence = authority_for_identity_packet(identity.to_bytes())
            binding = EmployeeBinding("atlas-studio", "person-morgan",
                                      "https://accounts.google.com", "subject-a",
                                      principal, "binding-a")
            with EmployeeAuthorityStore(path)._connect() as db:
                db.execute("""INSERT INTO employee_bindings
                    (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                    VALUES(?,?,?,?,?,?,?,?)""", (
                        binding.binding_ref, binding.company_id,
                        binding.logical_person_id, binding.issuer, binding.subject,
                        binding.principal, identity.to_bytes(), "a" * 64,
                    ))
            root = OperatorRoot(b"\x21" * 32)
            grant = root.issue_employee(binding=binding,
                                        identity_packet=identity.to_bytes(),
                                        service="atlas-drive", now=1000)
            self.assertEqual(grant.employee_evidence, evidence)
            self.assertEqual(grant.root_principal, root.principal)
            parsed = _native.parse_signed("grant", grant.signed_grant)
            self.assertEqual(bytes(_native.inspect_signed(parsed)), grant.signed_grant)
            store = EmployeeAuthorityStore(path)
            store.save(grant, binding)
            self.assertEqual(store.load(binding, now=1200), grant)
            with self.assertRaises(OperatorDenied):
                store.load(binding, now=4600)
            other = create_raw_key_ed25519_identity(bytes(
                _native.DevelopmentEd25519Key.generate().public_key))
            with self.assertRaises(OperatorDenied):
                root.issue_employee(binding=binding,
                                    identity_packet=other.to_bytes(),
                                    service="atlas-drive", now=1000)

            with store._connect() as db:
                db.execute("DELETE FROM employee_authorities WHERE employee_binding=?",
                           (binding.binding_ref,))

            private = Path(directory) / "operator"
            private.mkdir(mode=0o700)
            seed_file = private / "root.seed"
            trust_file = private / "trust.json"
            initialized = init_root(seed_file, trust_file,
                                    company="atlas-studio", service="atlas-drive", now=1000)
            self.assertEqual(seed_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(trust_file.stat().st_mode & 0o777, 0o600)
            manifest = json.loads(trust_file.read_bytes())
            self.assertEqual(initialized["root_principal"], manifest["root_principal"])
            _native.parse_trusted_context(base64.urlsafe_b64decode(manifest["trusted_template"]))
            issued = issue_employee(seed_file, trust_file, path,
                                    binding.binding_ref, now=1000)
            self.assertEqual(issued["employee_principal"], principal)


if __name__ == "__main__":
    unittest.main()
