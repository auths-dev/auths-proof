"""The isolated agent signs a real two-hop native write proof."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from auths import _native
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from employee_read_agent.run import AgentKey
from employee_read_agent.write import sign_write


class WriteProofTests(unittest.TestCase):
    def test_distinct_agent_signs_under_human_child_grant(self) -> None:
        root_key = Ed25519PrivateKey.generate()
        human_key = Ed25519PrivateKey.generate()
        agent_seed = Ed25519PrivateKey.generate().private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
        )
        agent = AgentKey(agent_seed)
        recipe_digest = "2766350e0222f0d427b41bf3dc241c948aa6812e32893d983ddc208e09cbb73f"
        def authority(key):
            public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return _native.raw_key_ed25519_authority_v1(public)
        root, root_evidence = authority(root_key)
        human, human_evidence = authority(human_key)
        service, tool = "airtable-gateway-demo", "set_demo_status_v2"
        audience = f"mcp://{service}"
        permission = ("tools/call", f"{audience}/tools/{tool}")
        root_request = _native.GrantRequest(
            _native.Principal(human), "auths.mcp", 2, [permission],
            1000, 1600, [audience], None, None, 1, None,
            "raw-key-baseline", [],
        )
        unsigned_root = _native.root_grant(_native.Principal(root), root_request)
        root_signing = _native.prepare_signing(
            unsigned_root, "raw-key-v1", root, "ed25519-v1",
        )
        parent = root_signing.complete(
            root_key.sign(bytes(root_signing.signing_preimage)),
        )
        child_request = _native.GrantRequest(
            _native.Principal(agent.principal), "auths.mcp", 2, [permission],
            1000, 1500, [audience], None, None, 0, None,
            "raw-key-baseline", [],
        )
        plan = _native.plan_child(parent, child_request)
        human_signing = _native.prepare_signing(
            plan.unsigned, "raw-key-v1", human, "ed25519-v1",
        )
        child = human_signing.complete(
            human_key.sign(bytes(human_signing.signing_preimage)),
        )
        assurance = _native.AssurancePolicy("raw-key-baseline", [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ])
        anchor = _native.TrustAnchor(
            root, _native.Principal(root), ["raw-key-v1"], [("auths.mcp", 2)],
            [permission], [audience], [audience], 1000, 1600,
            None, 2, "raw-key-baseline", None,
        )
        compiled = _native.compile_trusted_context(
            _native.mcp_gateway_configuration(), None, 1, 1, 1,
            [anchor], assurance, None, None, "none-v1", ["raw-key-v1"], [],
        )
        challenge = bytes([0x37]) * 32
        context = compiled.bind_request(audience, challenge, 1100)
        encode = lambda raw: base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        package = {
            "schema": "auths.ap071-agent-write-package/1",
            "agent_principal": agent.principal,
            "service": service, "tool": tool,
            "task_id": "task-1", "task_commitment": "a" * 64,
            "expires_at": 1500,
            "recipe_digest": recipe_digest,
            "challenge_b64": encode(challenge),
            "write_parent_grant_b64": encode(_native.inspect_signed(parent)),
            "signed_child_grant_b64": encode(_native.inspect_signed(child)),
            "root_evidence_b64": encode(root_evidence),
            "human_evidence_b64": encode(human_evidence),
            "trusted_template_b64": encode(_native.inspect_trusted_context(context)),
        }
        arguments = {
            "task_id": "task-1", "task_commitment": "a" * 64,
            "recipe_digest": recipe_digest, "record_id": "recTEST0000000001",
            "replacement": "Approved", "operation_id": "write-1",
            "operator_namespace": "airtable-demo",
        }
        proof, action = sign_write(package, arguments, agent, now=1100)
        self.assertGreater(len(proof), 0)
        self.assertGreater(len(action), 0)
        binary = os.environ.get("AUTHS_GATEWAY_BIN")
        if binary:
            repository = Path(__file__).resolve().parents[4]
            with tempfile.TemporaryDirectory() as directory:
                root_path = Path(directory)
                (root_path / "proof.cbor").write_bytes(proof)
                (root_path / "action.cbor").write_bytes(action)
                (root_path / "trust.cbor").write_bytes(
                    _native.inspect_trusted_context(context),
                )
                reference = repository / "demos/airtable-gateway/write_reference"
                result = subprocess.run([
                    binary, "review-submission",
                    "--recipe", str(reference / "recipe.json"),
                    "--profile-lock", str(reference / "profile.lock.json"),
                    "--trusted-context", str(root_path / "trust.cbor"),
                    "--proof", str(root_path / "proof.cbor"),
                    "--action", str(root_path / "action.cbor"),
                    "--evaluated-at", "1100",
                ], capture_output=True, text=True, check=True, timeout=30)
                review = json.loads(result.stdout)
                self.assertIn("actors", review, review)
                self.assertEqual(review["actors"], [agent.principal])
                self.assertEqual(review["request"]["method"], "PATCH")
        with self.assertRaises(ValueError):
            sign_write(package, {**arguments, "task_commitment": "c" * 64},
                       agent, now=1100)
        with self.assertRaises(ValueError):
            sign_write({**package, "agent_principal": human}, arguments,
                       agent, now=1100)
        self.assertTrue(sign_write(package, arguments, agent, now=1499)[0])
        with self.assertRaises(ValueError):
            sign_write(package, arguments, agent, now=1500)


if __name__ == "__main__":
    unittest.main()
