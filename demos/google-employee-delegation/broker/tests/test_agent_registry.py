from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from auths.identity.authoring import create_raw_key_ed25519_identity, prepare_identity_message

from employee_read_demo.agent_registry import AgentDenied, AgentRegistry
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding


def identity_for(key: Ed25519PrivateKey):
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return create_raw_key_ed25519_identity(public)


class AgentRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = AgentRegistry(Path(self.temp.name) / "broker.sqlite3")
        employee = identity_for(Ed25519PrivateKey.generate())
        self.employee = EmployeeBinding(
            "atlas-studio", "person-morgan", "https://accounts.google.com",
            "google-subject-a", authority_for_identity_packet(employee.to_bytes())[0], "binding-a",
        )
        with self.registry._connect() as db:
            db.execute("""INSERT INTO employee_bindings
                (binding_ref,company,person,issuer,subject,principal,identity_packet,bundle_digest)
                VALUES(?,?,?,?,?,?,?,?)""", (
                    self.employee.binding_ref, self.employee.company_id,
                    self.employee.logical_person_id, self.employee.issuer,
                    self.employee.subject, self.employee.principal,
                    employee.to_bytes(), "a" * 64,
                ))

    def test_distinct_agent_proves_key_and_cannot_replay(self) -> None:
        key = Ed25519PrivateKey.generate()
        identity = identity_for(key)
        nonce, message, principal = self.registry.prepare(self.employee, identity.to_bytes())
        self.assertEqual(principal, authority_for_identity_packet(identity.to_bytes())[0])
        signature = key.sign(prepare_identity_message(identity, message=message).signing_preimage)
        bound = asyncio.run(self.registry.complete(
            self.employee, nonce, identity.to_bytes(), signature,
        ))
        self.assertEqual(bound.agent_principal, principal)
        self.assertEqual(self.registry.lookup(self.employee, principal), bound)
        with self.assertRaises(AgentDenied):
            asyncio.run(self.registry.complete(
                self.employee, nonce, identity.to_bytes(), signature,
            ))

    def test_employee_key_cannot_be_registered_as_agent(self) -> None:
        key = Ed25519PrivateKey.generate()
        identity = identity_for(key)
        same = EmployeeBinding(**{**self.employee.__dict__, "principal": authority_for_identity_packet(identity.to_bytes())[0]})
        with self.assertRaises(AgentDenied):
            self.registry.prepare(same, identity.to_bytes())

    def test_offboarded_employee_cannot_register_agent(self) -> None:
        with self.registry._connect() as db:
            db.execute("UPDATE employee_bindings SET status='disabled'")
        with self.assertRaises(AgentDenied):
            self.registry.prepare(self.employee,
                                  identity_for(Ed25519PrivateKey.generate()).to_bytes())


if __name__ == "__main__":
    unittest.main()
