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
from employee_read_demo.task_write_delegation import (
    prepare_agent_companion_write_delegation, prepare_agent_read_delegation,
)
from employee_read_demo.task_write_proofs import task_commitment
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.operator_authority import OperatorDenied
from employee_read_agent.run import AgentKey
from employee_read_agent.write import sign_read, sign_write


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
            self.assertEqual(package["schema"], "auths.ap071-task-authority/4")
            self.assertIsNone(package["read"])
            self.assertEqual(package["recipe_digest"], digest)
            self.assertEqual(len(package["recipe_source_sha256"]), 64)
            self.assertEqual(len(package["profile_lock_sha256"]), 64)
            self.assertEqual(len(base64.urlsafe_b64decode(package["challenge_b64"])), 32)
            loaded = load_task_write_package(output, now=1000)
            self.assertEqual(loaded.authority.human_principal, human)
            self.assertIsNotNone(loaded.authority.effect_plan_grant)
            self.assertEqual(loaded.recipe_digest, digest)
            create_reference = Path(__file__).resolve().parents[2] / "create_reference"
            populate_reference = Path(__file__).resolve().parents[2] / "populate_reference"
            create_digest, populate_digest = "a" * 64, "b" * 64
            paired_output = private / "paired-task-authority.json"
            issue_task_package(
                root_seed=seed, root_trust=trust, state_db=state,
                binding_ref="binding-jules", company="atlas-studio",
                recipe_path=create_reference / "recipe.json",
                profile_lock_path=create_reference / "profile.lock.json",
                provider_service="google-drive-delegation-demo",
                provider_tool="create_project_a_document_v1",
                recipe_digest=create_digest,
                companion_write_recipe_path=populate_reference / "recipe.json",
                companion_write_profile_lock_path=populate_reference / "profile.lock.json",
                companion_write_service="google-docs-delegation-demo",
                companion_write_tool="populate_created_project_a_document_v1",
                companion_write_recipe_digest=populate_digest,
                output=paired_output, now=1000,
            )
            paired_raw = json.loads(paired_output.read_bytes())
            self.assertEqual(paired_raw["schema"], "auths.ap071-task-authority/5")
            paired = load_task_write_package(paired_output, now=1000)
            self.assertEqual(paired.companion_write.recipe_digest, populate_digest)
            self.assertIsNotNone(paired.authority.recovery_grant)
            self.assertNotEqual(
                paired.authority.recovery_grant.signed_grant,
                paired.authority.effect_plan_grant.signed_grant,
            )
            self.assertEqual(paired.authority.companion_write_service,
                             "google-docs-delegation-demo")
            bad_recovery = paired_raw | {"recovery_grant_b64": "invalid"}
            bad_recovery_path = private / "bad-recovery.json"
            bad_recovery_path.write_text(json.dumps(bad_recovery))
            os.chmod(bad_recovery_path, 0o600)
            with self.assertRaises(OperatorDenied):
                load_task_write_package(bad_recovery_path, now=1000)
            tampered_pair = private / "tampered-pair.json"
            paired_raw["companion_write"]["parent_grant_b64"] = "invalid"
            tampered_pair.write_text(json.dumps(paired_raw))
            os.chmod(tampered_pair, 0o600)
            with self.assertRaises(OperatorDenied):
                load_task_write_package(tampered_pair, now=1000)
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
                "schema": "auths.gateway-task-installation/5",
                "recipe_digests": [digest],
                "pins": {
                    "company_id": "atlas-studio", "initiator_principal": human, "approver_principal": human,
                    "agent_principal": agent_principal,
                    "agent_key_fingerprint": agent_digest,
                    "connection_id": "jules-google",
                    "connection_generation": 1,
                    "connection_subject": "synthetic-subject",
                    "permitted_read_scopes": [],
                    "delivery_channel": "agent-channel",
                    "delegation": {"partition_generation": 1, "root_instance_generation": 1,
                                   "max_depth": 0, "permitted_channels": {
                                       "agent-channel": {"principal": agent_principal, "instance_generation": 1}}},
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
            paired_card = {
                "schema": "auths.agent-task/4", "task_id": "paired-task",
                "initiator_principal": human, "approver_principal": human, "agent_principal": agent_principal,
                "not_before": 1010, "expires_at": 1300,
                "write_scopes": [{"handle": "project-a-folder",
                                  "recipe_digest": create_digest, "verb": "create"}],
                "pending_child": {"create_operation_id": "create-1",
                                  "create_recipe_digest": create_digest,
                                  "populate_recipe_digest": populate_digest,
                                  "parent_handle": "project-a-folder",
                                  "title": "Auths AP-071 Project A handoff",
                                  "marker": "ap071_" + "d" * 32},
            }
            companion = prepare_agent_companion_write_delegation(
                paired.authority, identity.to_bytes(), agent_packet,
                paired_card, populate_digest,
            )
            companion_package = companion.complete(
                human_key.sign(companion.signing_preimage), now=1011,
            )
            self.assertEqual(companion_package["recipe_digest"], populate_digest)
            self.assertEqual(companion_package["service"],
                             "google-docs-delegation-demo")
            companion_seed = agent_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            companion_proof, companion_action = sign_write(
                companion_package, {
                    "operator_namespace": "google-docs-populate-demo",
                    "operation_id": "populate-1",
                    "recipe_digest": populate_digest,
                    "task_id": paired_card["task_id"],
                    "task_commitment": task_commitment(paired_card),
                    "document_id": "child_ABC-123", "tab_id": "t.0",
                    "required_revision_id": "revision-1",
                    "text": "Project A handoff",
                }, AgentKey(companion_seed), now=1012,
            )
            self.assertTrue(companion_proof and companion_action)
            paired_installed = private / "paired-task-installation.json"
            paired_pins = json.loads(installed.read_text())
            paired_pins["recipe_digests"] = sorted([create_digest, populate_digest])
            paired_installed.write_text(json.dumps(
                paired_pins, sort_keys=True, separators=(",", ":")))
            os.chmod(paired_installed, 0o600)
            with self.assertRaisesRegex(
                    OperatorDenied, "populate preflight signer is not installed"):
                build_exact_write_card(
                    paired, employee, agent,
                    installation_path=paired_installed,
                    recipe_path=create_reference / "recipe.json",
                    profile_lock_path=create_reference / "profile.lock.json",
                    resource_handle="project-a-folder",
                    purpose="Create and populate one Project A handoff",
                    companion_recipe_path=populate_reference / "recipe.json",
                    companion_profile_lock_path=populate_reference / "profile.lock.json",
                    pending_child=paired_card["pending_child"], now=1010,
                )
            paired_pins["populate_preflight"] = {
                "public_key_hex": "1" * 64, "rule_digest": "2" * 64,
            }
            paired_installed.write_text(json.dumps(
                paired_pins, sort_keys=True, separators=(",", ":")))
            paired_flow = TaskWriteBrowserFlow(
                authority_path=paired_output, installation_path=paired_installed,
                recipe_path=create_reference / "recipe.json",
                profile_lock_path=create_reference / "profile.lock.json",
                companion_recipe_path=populate_reference / "recipe.json",
                companion_profile_lock_path=populate_reference / "profile.lock.json",
                private_output_dir=private,
            )
            paired_prepared = paired_flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="project-a-folder",
                resource_label="Project A destination folder",
                account_label="Jules Google account",
                pending_child=paired_card["pending_child"],
                purpose="Create and populate one Project A handoff", now=1010,
            )
            self.assertEqual(paired_prepared.card["max_writes"], 2)
            self.assertEqual(paired_prepared.card["pending_child"],
                             paired_card["pending_child"])
            paired_completed = paired_flow.complete(
                nonce=paired_prepared.nonce, employee=employee, agent=agent,
                grant_signature=human_key.sign(paired_prepared.grant_preimage),
                companion_grant_signature=human_key.sign(
                    paired_prepared.companion_grant_preimage),
                task_signature=human_key.sign(paired_prepared.task_preimage),
                now=1011,
            )
            self.assertEqual(paired_completed.companion_agent_package[
                "task_commitment"], paired_completed.agent_package["task_commitment"])
            self.assertTrue((paired_completed.private_task_dir /
                             "agent-companion-write-package.json").is_file())
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
            read_only_flow = TaskWriteBrowserFlow(
                authority_path=mixed_output, installation_path=mixed_installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                read_recipe_path=read_reference / "recipe.json",
                read_profile_lock_path=read_reference / "profile.lock.json",
                read_only=True, private_output_dir=private,
            )
            read_only_prepared = read_only_flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="source-doc", resource_label="No write destination",
                read_resource_handle="source-doc",
                read_resource_label="Pinned finance document",
                account_label="Jules Google account",
                purpose="Try the provider-denied finance read", now=1010,
            )
            self.assertEqual(read_only_prepared.card["write_scopes"], [])
            self.assertEqual(read_only_prepared.card["max_writes"], 0)
            self.assertEqual(read_only_prepared.card["max_provider_calls"], 1)
            self.assertIsNone(read_only_prepared.grant_preimage)
            read_only_completed = read_only_flow.complete(
                nonce=read_only_prepared.nonce, employee=employee, agent=agent,
                grant_signature=None,
                read_grant_signature=human_key.sign(
                    read_only_prepared.read_grant_preimage),
                task_signature=human_key.sign(read_only_prepared.task_preimage),
                now=1011,
            )
            self.assertIsNone(read_only_completed.agent_package)
            self.assertIsNotNone(read_only_completed.read_agent_package)
            self.assertFalse((read_only_completed.private_task_dir /
                              "agent-package.json").exists())
            self.assertTrue((read_only_completed.private_task_dir /
                             "agent-read-package.json").is_file())
            forged_write = read_only_flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="source-doc", resource_label="No write destination",
                read_resource_handle="source-doc",
                read_resource_label="Pinned finance document",
                account_label="Jules Google account",
                purpose="Try the provider-denied finance read", now=1012,
            )
            with self.assertRaisesRegex(OperatorDenied, "no write grant"):
                read_only_flow.complete(
                    nonce=forged_write.nonce, employee=employee, agent=agent,
                    grant_signature=human_key.sign(b"forged-write"),
                    read_grant_signature=human_key.sign(
                        forged_write.read_grant_preimage),
                    task_signature=human_key.sign(forged_write.task_preimage),
                    now=1013,
                )
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
            upfront_pins = json.loads(installed.read_text())
            upfront_pins["pins"]["allow_bounded_writes"] = True
            upfront_installed = private / "upfront-task-installation.json"
            upfront_installed.write_text(json.dumps(
                upfront_pins, sort_keys=True, separators=(",", ":")))
            os.chmod(upfront_installed, 0o600)
            choice = {"document_id": "working-doc", "tab_id": "t.0",
                      "required_revision_id": "revision-1", "marker": "AP071-test-marker",
                      "replacement": "Approved"}
            choices = [choice, {**choice, "replacement": "Pending"}]
            upfront_card = build_exact_write_card(
                loaded, employee, agent, installation_path=upfront_installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                resource_handle="working-doc", purpose="Choose one fixed update",
                upfront_allowed_arguments=choices, now=1010,
            )
            self.assertEqual(upfront_card["write_approval_mode"], "bounded-upfront")
            self.assertEqual(upfront_card["upfront_allowed_arguments"], choices)
            upfront_flow = TaskWriteBrowserFlow(
                authority_path=output, installation_path=upfront_installed,
                recipe_path=REFERENCE / "recipe.json",
                profile_lock_path=REFERENCE / "profile.lock.json",
                upfront_allowed_arguments=choices, private_output_dir=private,
            )
            upfront_prepared = upfront_flow.prepare(
                employee=employee, agent=agent,
                employee_identity_packet=identity.to_bytes(),
                agent_identity_packet=agent_packet,
                resource_handle="working-doc", resource_label="Project A working Doc",
                account_label="Jules Google account",
                purpose="Choose one fixed update", now=1010,
            )
            self.assertEqual(upfront_prepared.card["write_approval_mode"],
                             "bounded-upfront")
            upfront_completed = upfront_flow.complete(
                nonce=upfront_prepared.nonce, employee=employee, agent=agent,
                grant_signature=human_key.sign(upfront_prepared.grant_preimage),
                task_signature=human_key.sign(upfront_prepared.task_preimage), now=1011,
            )
            self.assertEqual(json.loads((upfront_completed.private_task_dir /
                                         "task-card.json").read_text())["upfront_allowed_arguments"],
                             choices)
            with self.assertRaises(OperatorDenied):
                build_exact_write_card(
                    loaded, employee, agent, installation_path=installed,
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    resource_handle="working-doc", purpose="Unapproved upfront",
                    upfront_allowed_arguments=choices, now=1010,
                )
            for rejected in ([choice, choice], [{**choice, "document_id": "other-doc"}],
                             [{**choice, "extra": "unexpected"}]):
                with self.assertRaises(OperatorDenied):
                    build_exact_write_card(
                        loaded, employee, agent,
                        installation_path=upfront_installed,
                        recipe_path=REFERENCE / "recipe.json",
                        profile_lock_path=REFERENCE / "profile.lock.json",
                        resource_handle="working-doc", purpose="Invalid upfront",
                        upfront_allowed_arguments=rejected, now=1010,
                    )
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
                upfront_arguments = {
                    "operator_namespace": "google-docs-demo",
                    "operation_id": "upfront-1", "recipe_digest": digest,
                    "task_id": upfront_prepared.card["task_id"],
                    "task_commitment": upfront_completed.agent_package["task_commitment"],
                    **choice,
                }
                upfront_proof, upfront_action = sign_write(
                    upfront_completed.agent_package, upfront_arguments,
                    AgentKey(agent_seed), now=1012,
                )
                upfront_dir = upfront_completed.private_task_dir
                (upfront_dir / "agent.proof").write_bytes(upfront_proof)
                (upfront_dir / "agent.action").write_bytes(upfront_action)
                os.chmod(upfront_dir / "agent.proof", 0o600)
                os.chmod(upfront_dir / "agent.action", 0o600)
                upfront_confirmation = TaskWriteConfirmationFlow(
                    authority_path=output, installation_path=upfront_installed,
                    recipe_path=REFERENCE / "recipe.json",
                    profile_lock_path=REFERENCE / "profile.lock.json",
                    upfront_allowed_arguments=choices,
                    private_output_dir=private, gateway_binary=binary,
                    gateway_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    gateway_state_dir=private,
                    preflight=lambda card, reviewed: None,
                )
                with self.assertRaisesRegex(OperatorDenied, "no exact confirmation"):
                    upfront_confirmation.prepare(
                        task_id=upfront_prepared.card["task_id"],
                        employee=employee, agent=agent, now=1013,
                    )
                import subprocess
                from unittest.mock import patch
                actual_run = subprocess.run
                submissions = []

                def submit_once(command, **kwargs):
                    if command[1] == "task-submit":
                        submissions.append(command)
                        return subprocess.CompletedProcess(command, 0,
                            b'{"outcome":"response-recorded","status":200}', b'')
                    return actual_run(command, **kwargs)

                with patch("employee_read_demo.task_write_confirmation.subprocess.run",
                           side_effect=submit_once):
                    upfront_confirmation.submit(
                        task_id=upfront_prepared.card["task_id"],
                        employee=employee, agent=agent, now=1013,
                    )
                self.assertEqual(len(submissions), 1)
                self.assertNotIn("--confirmation-proof", submissions[0])
                self.assertNotIn("--confirmation-action", submissions[0])
                unapproved_proof, unapproved_action = sign_write(
                    upfront_completed.agent_package,
                    {**upfront_arguments, "operation_id": "upfront-2",
                     "replacement": "Unapproved"},
                    AgentKey(agent_seed), now=1013,
                )
                (upfront_dir / "agent.proof").write_bytes(unapproved_proof)
                (upfront_dir / "agent.action").write_bytes(unapproved_action)
                with self.assertRaisesRegex(OperatorDenied, "outside upfront allowance"):
                    upfront_confirmation.submit(
                        task_id=upfront_prepared.card["task_id"],
                        employee=employee, agent=agent, now=1014,
                    )
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
                         "effect_plan_grant_b64",
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
