"""Sign an agent-authored short draft against one received task read.

This is an owner-private handoff to the exact human review. It binds the
agent's text to the bytes in its own release file, but the gateway receipt and
private verifier must still establish that those bytes came from the provider.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


DRAFT_SCHEMA = "auths.agent-draft/1"
DRAFT_DOMAIN = b"auths.agent-draft/1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


class DraftModel(Protocol):
    def draft(self, purpose: str, sources: dict[str, str]) -> str: ...


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def author_signed_draft(*, source: bytes, source_resource_handle: str,
                        read_operation_id: str, task_id: str,
                        task_commitment: str, agent_principal: str,
                        purpose: str, model: DraftModel,
                        key: Ed25519PrivateKey) -> bytes:
    """Return a bounded canonical envelope; no provider credential is used."""
    if (not 1 <= len(source) <= 16_384
            or type(source_resource_handle) is not str
            or _ID.fullmatch(source_resource_handle) is None
            or type(task_id) is not str or _ID.fullmatch(task_id) is None
            or type(read_operation_id) is not str
            or _ID.fullmatch(read_operation_id) is None
            or type(task_commitment) is not str
            or _DIGEST.fullmatch(task_commitment) is None
            or type(agent_principal) is not str or not agent_principal
            or type(purpose) is not str or not 1 <= len(purpose) <= 512):
        raise ValueError("agent draft inputs are outside bounds")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("released source is not UTF-8 text") from error
    draft = model.draft(purpose, {source_resource_handle: text})
    try:
        draft_bytes = draft.encode("utf-8") if type(draft) is str else b""
    except UnicodeEncodeError as error:
        raise ValueError("agent draft is not UTF-8 text") from error
    citations = re.findall(r"\[([^\[\]\n]{1,128})\]", draft) if type(draft) is str else []
    if (type(draft) is not str
            or not 1 <= len(draft_bytes) <= 192
            or not citations
            or any(citation != source_resource_handle for citation in citations)
            or "\x00" in draft):
        raise ValueError("agent draft lacks a bounded source citation")
    statement = {
        "schema": DRAFT_SCHEMA,
        "task_id": task_id,
        "task_commitment": task_commitment,
        "agent_principal": agent_principal,
        "source_resource_handle": source_resource_handle,
        "read_operation_id": read_operation_id,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "source_bytes": len(source),
        "content": draft,
    }
    signature = key.sign(DRAFT_DOMAIN + _canonical(statement))
    return _canonical({
        "statement": statement,
        "signature_b64": base64.b64encode(signature).decode("ascii").rstrip("="),
    })
