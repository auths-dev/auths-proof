"""The AP-071 human/agent ceremony accepts a second reviewed provider shape.

The provider-specific Airtable request is compiled and exercised by gateway
tests. This test covers the shared operator, human and agent authority path;
it sends no Airtable request and makes no employee-identity claim for a PAT.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from employee_read_agent.run import AgentKey
from employee_read_agent.write import sign_read, sign_write
from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding, EnrollmentStore
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.operator_cli import init_root
from employee_read_demo.task_write_browser import TaskWriteBrowserFlow
from employee_read_demo.task_write_card import build_exact_write_card
from employee_read_demo.task_write_operator_cli import issue_task_package
from employee_read_demo.task_write_package import load_task_write_package
from employee_read_demo.task_write_proofs import task_commitment


AIRTABLE = Path(__file__).resolve().parents[3] / "airtable-gateway"
WRITE = AIRTABLE / "write_reference"
READ = AIRTABLE / "read_reference"


class CrossProviderTaskCardTests(unittest.TestCase):
    def test_airtable_read_and_write_use_the_shared_signed_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "operator"
            private.mkdir(mode=0o700)
            root_seed = private / "root.seed"
            root_trust = private / "root-trust.json"
            init_root(root_seed, root_trust, company="example-company",
                      service="operator", now=1000)
            state = private / "broker.sqlite3"
            EnrollmentStore(state)
            os.chmod(state, 0o600)
            human_key = Ed25519PrivateKey.generate()
            human_packet = create_raw_key_ed25519_identity(
                human_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).to_bytes()
            human_principal, _ = authority_for_identity_packet(human_packet)
            with sqlite3.connect(state) as db:
                db.execute("""INSERT INTO employee_bindings
                    (binding_ref,company,person,issuer,subject,principal,
                     identity_packet,bundle_digest)
                    VALUES(?,?,?,?,?,?,?,?)""", (
                        "employee-binding", "example-company", "person-operator",
                        "https://id.example", "operator-subject", human_principal,
                        human_packet, "a" * 64,
                    ))
            agent_key = Ed25519PrivateKey.generate()
            agent_seed = agent_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
            )
            agent_packet = create_raw_key_ed25519_identity(
                agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).to_bytes()
            agent_principal, _ = authority_for_identity_packet(agent_packet)
            agent_digest = hashlib.sha256(agent_packet).hexdigest()
            # Digests are the exact outputs of gateway `review` and
            # `review-release` for the checked-in Airtable sources.
            write_digest = "2766350e0222f0d427b41bf3dc241c948aa6812e32893d983ddc208e09cbb73f"
            read_digest = "bc0335d9ab4fb4bb381834bef8aa5e6e6df58686f0920db460a109efa272fec7"
            authority = private / "airtable-task-authority.json"
            issue_task_package(
                root_seed=root_seed, root_trust=root_trust, state_db=state,
                binding_ref="employee-binding", company="example-company",
                recipe_path=WRITE / "recipe.json",
                profile_lock_path=WRITE / "profile.lock.json",
                provider_service="airtable-gateway-demo",
                provider_tool="set_demo_status_v2",
                recipe_digest=write_digest,
                read_recipe_path=READ / "recipe.json",
                read_profile_lock_path=READ / "profile.lock.json",
                read_service="airtable-delegation-demo",
                read_tool="release_demo_status_v2",
                read_recipe_digest=read_digest,
                output=authority, now=1000,
            )
            record = "recTEST0000000001"
            installed = private / "task-installation.json"
            installed.write_text(json.dumps({
                "schema": "auths.gateway-task-installation/3",
                "recipe_digests": [write_digest],
                "pins": {
                    "company_id": "example-company",
                    "human_principal": human_principal,
                    "agent_principal": agent_principal,
                    "agent_key_fingerprint": agent_digest,
                    "connection_id": "operator-airtable-write",
                    "connection_generation": 1,
                    "connection_subject": "operator-account",
                    "permitted_read_scopes": [{
                        "handle": record, "recipe_digest": read_digest,
                        "connection_id": "operator-airtable-read",
                        "connection_generation": 1,
                        "connection_subject": "operator-account",
                    }],
                    "delivery_channel": "agent-channel",
                    "operator_policy_digest": "d" * 64,
                    "allow_bounded_writes": False,
                },
            }, sort_keys=True, separators=(",", ":")))
            os.chmod(installed, 0o600)
            employee = EmployeeBinding(
                "example-company", "person-operator", "https://id.example",
                "operator-subject", human_principal, "employee-binding",
            )
            agent = AgentBinding(
                "example-company", "employee-binding", agent_principal, agent_digest,
            )
            package = load_task_write_package(authority, now=1010)
            card = build_exact_write_card(
                package, employee, agent, installation_path=installed,
                recipe_path=WRITE / "recipe.json",
                profile_lock_path=WRITE / "profile.lock.json",
                resource_handle=record, purpose="Read status, then set Approved",
                read_recipe_path=READ / "recipe.json",
                read_profile_lock_path=READ / "profile.lock.json",
                read_resource_handle=record, now=1010,
            )
            self.assertEqual(card["read_scopes"][0]["handle"], record)
            self.assertEqual(card["write_scopes"][0]["handle"], record)
            self.assertEqual(card["max_release_bytes"], 64)
            self.assertEqual(card["write_approval_mode"], "exact")
            flow = TaskWriteBrowserFlow(
                authority_path=authority, installation_path=installed,
                recipe_path=WRITE / "recipe.json",
                profile_lock_path=WRITE / "profile.lock.json",
                read_recipe_path=READ / "recipe.json",
                read_profile_lock_path=READ / "profile.lock.json",
                private_output_dir=private,
            )
            prepared = flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=human_packet,
                agent_identity_packet=agent_packet,
                resource_handle=record, resource_label="Disposable Airtable record",
                read_resource_handle=record,
                read_resource_label="Current DemoStatus",
                account_label="Operator Airtable connection",
                purpose="Read status, then set Approved", now=1010,
            )
            completed = flow.complete(
                nonce=prepared.nonce, employee=employee, agent=agent,
                grant_signature=human_key.sign(prepared.grant_preimage),
                read_grant_signature=human_key.sign(prepared.read_grant_preimage),
                task_signature=human_key.sign(prepared.task_preimage), now=1011,
            )
            self.assertEqual(completed.read_agent_package["task_commitment"],
                             completed.agent_package["task_commitment"])
            self.assertEqual(completed.agent_package["recipe_digest"], write_digest)
            self.assertEqual(completed.read_agent_package["recipe_digest"], read_digest)
            common = {
                "task_id": completed.task_id,
                "task_commitment": task_commitment(prepared.card),
            }
            read_proof, read_action = sign_read(
                completed.read_agent_package, {
                    **common, "operator_namespace": "airtable-read-demo",
                    "operation_id": "read-one", "recipe_digest": read_digest,
                    "resource_id": record, "agent_principal": agent_principal,
                }, AgentKey(agent_seed), now=1012,
            )
            write_proof, write_action = sign_write(
                completed.agent_package, {
                    **common, "operator_namespace": "airtable-demo",
                    "operation_id": "write-one", "recipe_digest": write_digest,
                    "record_id": record, "replacement": "Approved",
                }, AgentKey(agent_seed), now=1012,
            )
            self.assertTrue(read_proof and read_action and write_proof and write_action)
            with self.assertRaises(OperatorDenied):
                build_exact_write_card(
                    package, employee, agent, installation_path=installed,
                    recipe_path=WRITE / "recipe.json",
                    profile_lock_path=WRITE / "profile.lock.json",
                    resource_handle=record, purpose="Read another record",
                    read_recipe_path=READ / "recipe.json",
                    read_profile_lock_path=READ / "profile.lock.json",
                    read_resource_handle="recTEST0000000002", now=1010,
                )


if __name__ == "__main__":
    unittest.main()
