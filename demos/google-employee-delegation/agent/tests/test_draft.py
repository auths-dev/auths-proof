from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from employee_read_agent.draft import DRAFT_DOMAIN, author_signed_draft
from employee_read_agent.cli import _private_source


class _Model:
    def draft(self, purpose: str, sources: dict[str, str]) -> str:
        assert purpose == "Prepare a Project A handoff"
        assert sources == {"source-1": "Project A is ready for review."}
        return "Project A is ready for review. [source-1]"


class SignedDraftTests(unittest.TestCase):
    def test_short_cited_draft_signs_exact_received_source_facts(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
        raw = author_signed_draft(
            source=b"Project A is ready for review.",
            source_resource_handle="source-1", read_operation_id="read-1",
            task_id="task-1", task_commitment="a" * 64,
            agent_principal="agent-1", purpose="Prepare a Project A handoff",
            model=_Model(), key=key,
        )
        envelope = json.loads(raw)
        statement = envelope["statement"]
        self.assertEqual(statement["source_bytes"], 30)
        self.assertEqual(statement["content"],
                         "Project A is ready for review. [source-1]")
        key.public_key().verify(
            base64.b64decode(envelope["signature_b64"] + "=="),
            DRAFT_DOMAIN + json.dumps(statement, sort_keys=True,
                                      separators=(",", ":"),
                                      ensure_ascii=False).encode(),
        )

    def test_uncited_or_oversized_model_output_is_refused(self) -> None:
        key = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
        class BadModel:
            def draft(self, purpose: str, sources: dict[str, str]) -> str:
                return "uncited" * 40
        with self.assertRaisesRegex(ValueError, "source citation"):
            author_signed_draft(
                source=b"Project A", source_resource_handle="source-1",
                read_operation_id="read-1", task_id="task-1",
                task_commitment="a" * 64, agent_principal="agent-1",
                purpose="Prepare a Project A handoff", model=BadModel(), key=key,
            )
        class ExtraCitationModel:
            def draft(self, purpose: str, sources: dict[str, str]) -> str:
                return "Ready [source-1] [outside]"
        with self.assertRaisesRegex(ValueError, "source citation"):
            author_signed_draft(
                source=b"Project A", source_resource_handle="source-1",
                read_operation_id="read-1", task_id="task-1",
                task_commitment="a" * 64, agent_principal="agent-1",
                purpose="Prepare a Project A handoff", model=ExtraCitationModel(), key=key,
            )

    def test_draft_source_must_be_owner_private_and_not_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "released-source"
            source.write_bytes(b"Project A")
            source.chmod(0o600)
            self.assertEqual(_private_source(source, 16_384), b"Project A")
            linked = Path(directory).resolve() / "linked-source"
            linked.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "private and bounded"):
                _private_source(linked, 16_384)
            source.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private and bounded"):
                _private_source(source, 16_384)


if __name__ == "__main__":
    unittest.main()
