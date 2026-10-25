from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from employee_read_demo.operator_authority import OperatorDenied
from employee_read_demo.task_agent_draft import DRAFT_DOMAIN, verify_agent_draft


class AgentDraftVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.card = {
            "task_id": "task-1",
            "read_scopes": [{"handle": "source-1"}],
        }
        self.statement = {
            "schema": "auths.agent-draft/1", "task_id": "task-1",
            "task_commitment": "a" * 64, "agent_principal": "agent-1",
            "source_resource_handle": "source-1", "read_operation_id": "read-1",
            "source_sha256": "b" * 64, "source_bytes": 30,
            "content": "Project A is ready for review. [source-1]",
        }

    def envelope(self, statement: dict) -> bytes:
        canonical = lambda value: json.dumps(value, sort_keys=True,
                                             separators=(",", ":"),
                                             ensure_ascii=False).encode()
        signature = self.key.sign(DRAFT_DOMAIN + canonical(statement))
        return canonical({
            "statement": statement,
            "signature_b64": base64.b64encode(signature).decode().rstrip("="),
        })

    def verify(self, raw: bytes, reads: dict[str, int] | None = None) -> str:
        with patch("employee_read_demo.task_agent_draft.task_commitment",
                   return_value="a" * 64):
            return verify_agent_draft(
                raw, card=self.card, agent_principal="agent-1",
                public_key=self.public,
                acknowledged_reads={"read-1": 30} if reads is None else reads,
            )

    def test_signed_draft_requires_registered_key_and_acknowledged_read(self) -> None:
        raw = self.envelope(self.statement)
        self.assertEqual(self.verify(raw).content, self.statement["content"])
        extra = dict(self.statement, content="Ready [source-1] [outside]")
        with self.assertRaisesRegex(OperatorDenied, "acknowledged task read"):
            self.verify(self.envelope(extra))
        with self.assertRaisesRegex(OperatorDenied, "acknowledged task read"):
            self.verify(raw, {})
        altered = json.loads(raw)
        altered["statement"]["content"] = "Fabricated [source-1]"
        with self.assertRaisesRegex(OperatorDenied, "signature"):
            self.verify(json.dumps(altered, sort_keys=True,
                                   separators=(",", ":")).encode())
        other_key = Ed25519PrivateKey.from_private_bytes(b"\x66" * 32)
        with patch("employee_read_demo.task_agent_draft.task_commitment",
                   return_value="a" * 64):
            with self.assertRaisesRegex(OperatorDenied, "signature"):
                verify_agent_draft(
                    raw, card=self.card, agent_principal="agent-1",
                    public_key=other_key.public_key().public_bytes(
                        Encoding.Raw, PublicFormat.Raw),
                    acknowledged_reads={"read-1": 30},
                )


if __name__ == "__main__":
    unittest.main()
