"""Private operator issuance of task profiles for an enrolled employee."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from auths import _native
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EnrollmentStore
from employee_read_demo.operator_cli import init_root
from employee_read_demo.task_write_operator_cli import issue_task_package


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
            digest = "b" * 64
            summary = issue_task_package(
                root_seed=seed, root_trust=trust, state_db=state,
                binding_ref="binding-jules", company="atlas-studio",
                provider_service="google-docs-delegation-demo",
                provider_tool="replace_project_a_marker_v2",
                recipe_digest=digest, output=output, now=1000,
            )
            self.assertEqual(summary["status"], "authority_issued")
            self.assertEqual(summary["human_principal"], human)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            package = json.loads(output.read_bytes())
            self.assertEqual(package["schema"], "auths.ap071-task-authority/1")
            self.assertEqual(package["recipe_digest"], digest)
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
                    provider_service="google-docs-delegation-demo",
                    provider_tool="replace_project_a_marker_v2",
                    recipe_digest=digest, output=output, now=1000,
                )
            with self.assertRaises(ValueError):
                issue_task_package(
                    root_seed=seed, root_trust=trust, state_db=state,
                    binding_ref="binding-jules", company="other-company",
                    provider_service="google-docs-delegation-demo",
                    provider_tool="replace_project_a_marker_v2",
                    recipe_digest=digest, output=private / "wrong.json", now=1000,
                )


if __name__ == "__main__":
    unittest.main()
