"""Private operator issuance of task profiles for an enrolled employee."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EnrollmentStore
from employee_read_demo.enrollment import EmployeeBinding
from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.operator_cli import init_root
from employee_read_demo.task_write_operator_cli import issue_task_package
from employee_read_demo.task_write_package import load_task_write_package
from employee_read_demo.task_write_card import build_exact_write_card
from employee_read_demo.task_write_browser import TaskWriteBrowserFlow
from employee_read_demo.task_write_delegation import prepare_agent_read_delegation
from employee_read_demo.task_write_proofs import task_commitment
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_agent.run import AgentKey
from employee_read_agent.write import sign_read


REFERENCE = Path(__file__).resolve().parents[2] / "write_reference"


class TaskOperatorCliTests(unittest.TestCase):
    def test_issues_private_bound_authority_from_current_company_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "operator"
            private.mkdir(mode=0o700)
            seed, trust, output = (
                private / "root.seed", private / "trust.json",
                private / "task-authority.json",
            )
            init_root(seed, trust, company="atlas-studio",
                      service="atlas-drive", now=1000)
            state = private / "broker.sqlite3"
            EnrollmentStore(state)
            os.chmod(state, 0o600)
            human_key = Ed25519PrivateKey.generate()
            public = human_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            identity = create_raw_key_ed25519_identity(public)
            human, _ = authority_for_identity_packet(identity.to_bytes())
            import sqlite3
            with sqlite3.connect(state) as db:
                db.execute("""INSERT INTO employee_bindings
                    (binding_ref,company,person,issuer,subject,principal,
                     identity_packet,bundle_digest)
                    VALUES(?,?,?,?,?,?,?,?)""", (
                        "binding-jules", "atlas-studio", "person-jules",
                        "https://accounts.google.com", "synthetic-subject",
                        human, identity.to_bytes(), "a" * 64,
                    ))
            digest = "deec68be1e8fc256b2aa09cf100f6a6cc9481578d0faa19a633a7400b50945fe"
            summary = issue_task_package(
                root_seed=seed, root_trust=trust, state_db=state,
                binding_ref="binding-jules", company="atlas-studio",
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                provider_service="google-docs-delegation-demo",
                provider_tool="replace_project_a_marker_v2",
                recipe_digest=digest, output=output, now=1000,
            )
            self.assertEqual(summary["status"], "authority_issued")
            self.assertEqual(summary["human_principal"], human)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            package = json.loads(output.read_bytes())
            self.assertEqual(package["schema"], "auths.ap071-task-authority/2")
            self.assertIsNone(package["read"])
            self.assertEqual(package["recipe_digest"], digest)
            self.assertEqual(len(package["recipe_source_sha256"]), 64)
            self.assertEqual(len(package["profile_lock_sha256"]), 64)
            self.assertEqual(len(base64.urlsafe_b64decode(package["challenge_b64"])), 32)
            loaded = load_task_write_package(output, now=1000)
            self.assertEqual(loaded.authority.human_principal, human)
            self.assertEqual(loaded.recipe_digest, digest)
            read_reference = Path(__file__).resolve().parents[2] / "read_reference"
            mixed_output = private / "mixed-task-authority.json"
            read_digest = "57673e6adc5b7b000fe65a6441279fc03e019b887d66c488a2978fccb4d6e97c"
            issue_task_package(
                root_seed=seed, root_trust=trust, state_db=state,
                binding_ref="binding-jules", company="atlas-studio",
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                provider_service="google-docs-delegation-demo",
                provider_tool="replace_project_a_marker_v2",
                recipe_digest=digest,
                read_recipe_path=read_reference / "recipe.json",
                read_profile_lock_path=read_reference / "profile.lock.json",
                read_service="google-drive-delegation-demo",
                read_tool="release_project_a_text_v2",
                read_recipe_digest=read_digest,
                output=mixed_output, now=1000,
            )
            mixed = load_task_write_package(mixed_output, now=1000)
            self.assertEqual(mixed.read.recipe_digest, read_digest)
            self.assertEqual(mixed.authority.read_service,
                             "google-drive-delegation-demo")
            self.assertIsNotNone(mixed.authority.read_parent_grant)
            changed_read = json.loads(mixed_output.read_text())
            changed_read["read"]["parent_grant_b64"] = "invalid"
            tampered_read = private / "tampered-read.json"
            tampered_read.write_text(json.dumps(changed_read))
            os.chmod(tampered_read, 0o600)
            with self.assertRaises(OperatorDenied):
                load_task_write_package(tampered_read, now=1000)
            agent_key = Ed25519PrivateKey.generate()
            agent_public = agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            agent_packet = create_raw_key_ed25519_identity(agent_public).to_bytes()
            agent_principal, _ = authority_for_identity_packet(agent_packet)
            agent_digest = hashlib.sha256(agent_packet).hexdigest()
            installed = private / "task-write-installation.json"
            installed.write_text(json.dumps({
                "schema": "auths.gateway-task-installation/2",
                "recipe_digest": digest,
                "pins": {
                    "company_id": "atlas-studio", "human_principal": human,
                    "agent_principal": agent_principal,
                    "agent_key_fingerprint": agent_digest,
                    "connection_id": "jules-google",
                    "connection_generation": 1,
                    "connection_subject": "synthetic-subject",
                    "permitted_read_scopes": [],
                    "delivery_channel": "agent-channel",
                    "operator_policy_digest": "c" * 64,
                    "allow_bounded_writes": False,
                },
            }, sort_keys=True, separators=(",", ":")))
            os.chmod(installed, 0o600)
            employee = EmployeeBinding(
                "atlas-studio", "person-jules", "https://accounts.google.com",
                "synthetic-subject", human, "binding-jules",
            )
            agent = AgentBinding("atlas-studio", "binding-jules",
                                 agent_principal, agent_digest)
            mixed_installed = private / "mixed-task-installation.json"
            mixed_pins = json.loads(installed.read_text())
            mixed_pins["pins"]["permitted_read_scopes"] = [{
                "handle": "source-doc", "recipe_digest": read_digest,
                "connection_id": "jules-google-read", "connection_generation": 1,
                "connection_subject": "synthetic-subject",
            }]
            mixed_installed.write_text(json.dumps(
                mixed_pins, sort_keys=True, separators=(",", ":")))
            os.chmod(mixed_installed, 0o600)
            mixed_card = build_exact_write_card(
                mixed, employee, agent, installation_path=mixed_installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                resource_handle="working-doc", purpose="Read then update Project A",
                read_recipe_path=read_reference / "recipe.json",
                read_profile_lock_path=read_reference / "profile.lock.json",
                read_resource_handle="source-doc", now=1010,
            )
            self.assertEqual(mixed_card["read_scopes"],
                             mixed_pins["pins"]["permitted_read_scopes"])
            self.assertEqual(mixed_card["max_provider_calls"], 1)
            self.assertEqual(mixed_card["max_releases"], 1)
            self.assertEqual(mixed_card["max_release_bytes"], 16384)
            read_delegation = prepare_agent_read_delegation(
                mixed.authority, identity.to_bytes(), agent_packet,
                mixed_card, read_digest,
            )
            read_agent_package = read_delegation.complete(
                human_key.sign(read_delegation.signing_preimage), now=1011,
            )
            self.assertEqual(read_agent_package["schema"],
                             "auths.ap071-agent-read-package/1")
            self.assertEqual(read_agent_package["task_commitment"],
                             task_commitment(mixed_card))
            self.assertEqual(read_agent_package["recipe_digest"], read_digest)
            mixed_flow = TaskWriteBrowserFlow(
                authority_path=mixed_output, installation_path=mixed_installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                read_recipe_path=read_reference / "recipe.json",
                read_profile_lock_path=read_reference / "profile.lock.json",
                private_output_dir=private,
            )
            mixed_prepared = mixed_flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="working-doc",
                resource_label="Project A working Doc",
                read_resource_handle="source-doc",
                read_resource_label="Project A source Doc",
                account_label="Jules Google account",
                purpose="Read then update Project A", now=1010,
            )
            mixed_completed = mixed_flow.complete(
                nonce=mixed_prepared.nonce, employee=employee, agent=agent,
                grant_signature=human_key.sign(mixed_prepared.grant_preimage),
                read_grant_signature=human_key.sign(
                    mixed_prepared.read_grant_preimage),
                task_signature=human_key.sign(mixed_prepared.task_preimage),
                now=1011,
            )
            self.assertEqual(mixed_completed.read_agent_package["task_commitment"],
                             mixed_completed.agent_package["task_commitment"])
            self.assertTrue((mixed_completed.private_task_dir /
                             "agent-read-package.json").is_file())
            self.assertEqual(mixed_prepared.card["read_scopes"][0]["handle"],
                             "source-doc")
            agent_seed = agent_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            read_arguments = {
                "operator_namespace": "google-read-demo",
                "operation_id": "read-1", "recipe_digest": read_digest,
                "task_id": mixed_completed.task_id,
                "task_commitment": mixed_completed.read_agent_package[
                    "task_commitment"],
                "resource_id": "source-doc",
                "agent_principal": agent_principal,
            }
            read_proof, read_action = sign_read(
                mixed_completed.read_agent_package, read_arguments,
                AgentKey(agent_seed), now=1012,
            )
            self.assertTrue(read_proof and read_action)
            with self.assertRaises(ValueError):
                sign_read(mixed_completed.read_agent_package,
                          {**read_arguments, "agent_principal": human},
                          AgentKey(agent_seed), now=1012)
            with self.assertRaises(OperatorDenied):
                build_exact_write_card(
                    mixed, employee, agent, installation_path=mixed_installed,
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    resource_handle="working-doc", purpose="Read then update Project A",
                    read_recipe_path=read_reference / "recipe.json",
                    read_profile_lock_path=read_reference / "profile.lock.json",
                    read_resource_handle="other-doc", now=1010,
                )
            card = build_exact_write_card(
                loaded, employee, agent, installation_path=installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                resource_handle="working-doc", purpose="Update Project A", now=1010,
            )
            self.assertEqual(card["write_approval_mode"], "exact")
            self.assertEqual(card["write_scopes"][0]["handle"], "working-doc")
            self.assertEqual(card["expires_at"], 2810)
            flow = TaskWriteBrowserFlow(
                authority_path=output, installation_path=installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                private_output_dir=private,
            )
            prepared = flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="working-doc", resource_label="Project A working Doc",
                account_label="Jules Google account", purpose="Update Project A", now=1010,
            )
            completed = flow.complete(
                nonce=prepared.nonce, employee=employee, agent=agent,
                grant_signature=human_key.sign(prepared.grant_preimage),
                task_signature=human_key.sign(prepared.task_preimage), now=1011,
            )
            self.assertEqual(completed.task_id, prepared.card["task_id"])
            self.assertTrue((completed.private_task_dir / "task.proof").is_file())
            self.assertTrue((completed.private_task_dir / "task.action").is_file())
            self.assertEqual(json.loads((completed.private_task_dir / "task-card.json").read_text()),
                             prepared.card)
            self.assertEqual((completed.private_task_dir / "trusted-context.cbor").read_bytes(),
                             loaded.authority.trusted_template)
            self.assertEqual((completed.private_task_dir / "agent-package.json").stat().st_mode & 0o777, 0o600)
            gateway_binary = os.environ.get("AUTHS_GATEWAY_BIN")
            if gateway_binary:
                import sys
                sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent" / "src"))
                from employee_read_agent.write import sign_write

                agent_seed = agent_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                arguments = {
                    "operator_namespace": "google-docs-demo",
                    "operation_id": "write-1",
                    "recipe_digest": digest,
                    "task_id": prepared.card["task_id"],
                    "task_commitment": completed.agent_package["task_commitment"],
                    "document_id": "working-doc",
                    "tab_id": "t.0",
                    "marker": "PLACEHOLDER",
                    "replacement": "Updated Project A",
                    "required_revision_id": "rev-1",
                }
                agent_proof, agent_action = sign_write(
                    completed.agent_package, arguments, AgentKey(agent_seed), now=1012,
                )
                (completed.private_task_dir / "agent.proof").write_bytes(agent_proof)
                (completed.private_task_dir / "agent.action").write_bytes(agent_action)
                os.chmod(completed.private_task_dir / "agent.proof", 0o600)
                os.chmod(completed.private_task_dir / "agent.action", 0o600)
                binary = Path(gateway_binary).resolve()
                preflight_checks = []
                confirmation = TaskWriteConfirmationFlow(
                    authority_path=output, installation_path=installed,
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    private_output_dir=private, gateway_binary=binary,
                    gateway_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    preflight=lambda card, reviewed: preflight_checks.append(
                        (card["task_id"], reviewed.arguments["required_revision_id"])),
                )
                proposal = confirmation.prepare(
                    task_id=prepared.card["task_id"], employee=employee,
                    agent=agent, now=1013,
                )
                self.assertEqual(proposal.intent["resource_handle"], "working-doc")
                self.assertIn("Updated Project A", proposal.review.body)
                (completed.private_task_dir / "agent.action").write_bytes(b"changed")
                with self.assertRaises(OperatorDenied):
                    confirmation.complete(
                        nonce=proposal.nonce, employee=employee, agent=agent,
                        signature=human_key.sign(proposal.signing_preimage), now=1014,
                    )
                (completed.private_task_dir / "agent.action").write_bytes(agent_action)
                proposal = confirmation.prepare(
                    task_id=prepared.card["task_id"], employee=employee,
                    agent=agent, now=1014,
                )
                confirmation.complete(
                    nonce=proposal.nonce, employee=employee, agent=agent,
                    signature=human_key.sign(proposal.signing_preimage), now=1015,
                )
                self.assertTrue((completed.private_task_dir / "confirmation.proof").is_file())
                self.assertTrue((completed.private_task_dir / "confirmation.action").is_file())
                self.assertEqual(preflight_checks, [
                    (prepared.card["task_id"], "rev-1"),
                    (prepared.card["task_id"], "rev-1"),
                    (prepared.card["task_id"], "rev-1"),
                ])
            with self.assertRaises(OperatorDenied):
                flow.complete(
                    nonce=prepared.nonce, employee=employee, agent=agent,
                    grant_signature=human_key.sign(prepared.grant_preimage),
                    task_signature=human_key.sign(prepared.task_preimage), now=1011,
                )
            drifted = flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="working-doc", resource_label="Project A working Doc",
                account_label="Jules Google account", purpose="Update Project A", now=1012,
            )
            changed_installation = json.loads(installed.read_text())
            changed_installation["pins"]["connection_generation"] = 2
            installed.write_text(json.dumps(changed_installation))
            with self.assertRaises(OperatorDenied):
                flow.complete(
                    nonce=drifted.nonce, employee=employee, agent=agent,
                    grant_signature=human_key.sign(drifted.grant_preimage),
                    task_signature=human_key.sign(drifted.task_preimage), now=1013,
                )
            with self.assertRaises(OperatorDenied):
                build_exact_write_card(
                    loaded, employee, agent, installation_path=installed,
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    resource_handle="other-doc", purpose="Bad\nPurpose", now=1010,
                )
            tampered = private / "tampered.json"
            changed = dict(package)
            changed["challenge_b64"] = base64.urlsafe_b64encode(bytes(32)).decode()
            tampered.write_text(json.dumps(changed))
            os.chmod(tampered, 0o600)
            with self.assertRaises(OperatorDenied):
                load_task_write_package(tampered, now=1000)
            self.assertEqual(package["expires_at"], 4600)
            self.assertNotIn("token", output.read_text().lower())
            _native.parse_trusted_context(base64.urlsafe_b64decode(
                package["trusted_template_b64"],
            ))
            for name in ("approval_grant_b64", "confirmation_grant_b64",
                         "write_parent_grant_b64"):
                _native.parse_signed("grant", base64.urlsafe_b64decode(package[name]))
            with self.assertRaises(FileExistsError):
                issue_task_package(
                    root_seed=seed, root_trust=trust, state_db=state,
                    binding_ref="binding-jules", company="atlas-studio",
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    provider_service="google-docs-delegation-demo",
                    provider_tool="replace_project_a_marker_v2",
                    recipe_digest=digest, output=output, now=1000,
                )
            with self.assertRaises(ValueError):
                issue_task_package(
                    root_seed=seed, root_trust=trust, state_db=state,
                    binding_ref="binding-jules", company="other-company",
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    provider_service="google-docs-delegation-demo",
                    provider_tool="replace_project_a_marker_v2",
                    recipe_digest=digest, output=private / "wrong.json", now=1000,
                )
            with self.assertRaises(ValueError):
                issue_task_package(
                    root_seed=seed, root_trust=trust, state_db=state,
                    binding_ref="binding-jules", company="atlas-studio",
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    provider_service="airtable-gateway-demo",
                    provider_tool="set_demo_status_v2",
                    recipe_digest=digest, output=private / "wrong-profile.json",
                    now=1000,
                )


if __name__ == "__main__":
    unittest.main()
