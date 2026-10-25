"""Verify the separate agent's private draft before Jules reviews its text."""

from __future__ import annotations

import base64
import binascii
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .demo_co_contract import _unique_pairs
from .operator_authority import OperatorDenied
from .task_write_proofs import task_commitment


DRAFT_SCHEMA = "auths.agent-draft/1"
DRAFT_DOMAIN = b"auths.agent-draft/1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_STATEMENT = {
    "schema", "task_id", "task_commitment", "agent_principal",
    "source_resource_handle", "read_operation_id", "source_sha256",
    "source_bytes", "content",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def verify_agent_draft(raw: bytes, *, card: dict, agent_principal: str,
                       public_key: bytes, acknowledged_reads: dict[str, int]) -> str:
    """Return the exact signed text only for the task's acknowledged read."""
    if (not 1 <= len(raw) <= 4096 or type(card) is not dict
            or type(public_key) is not bytes or len(public_key) != 32):
        raise OperatorDenied("agent draft is unavailable")
    try:
        envelope = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError) as error:
        raise OperatorDenied("agent draft is malformed") from error
    if (type(envelope) is not dict
            or set(envelope) != {"statement", "signature_b64"}
            or type(envelope["statement"]) is not dict
            or set(envelope["statement"]) != _STATEMENT
            or type(envelope["signature_b64"]) is not str):
        raise OperatorDenied("agent draft is malformed")
    statement = envelope["statement"]
    scopes = card.get("read_scopes")
    content = statement["content"]
    operation_id = statement["read_operation_id"]
    try:
        content_bytes = content.encode("utf-8") if type(content) is str else b""
    except UnicodeEncodeError as error:
        raise OperatorDenied("agent draft is not UTF-8 text") from error
    citations = re.findall(r"\[([^\[\]\n]{1,128})\]", content) if type(content) is str else []
    if (statement["schema"] != DRAFT_SCHEMA
            or statement["task_id"] != card.get("task_id")
            or statement["task_commitment"] != task_commitment(card)
            or statement["agent_principal"] != agent_principal
            or type(scopes) is not list or len(scopes) != 1
            or type(scopes[0]) is not dict
            or type(statement["source_resource_handle"]) is not str
            or _ID.fullmatch(statement["source_resource_handle"]) is None
            or statement["source_resource_handle"] != scopes[0].get("handle")
            or type(operation_id) is not str or _ID.fullmatch(operation_id) is None
            or type(statement["source_sha256"]) is not str
            or _DIGEST.fullmatch(statement["source_sha256"]) is None
            or type(statement["source_bytes"]) is not int
            or not 1 <= statement["source_bytes"] <= 16_384
            or acknowledged_reads.get(operation_id) != statement["source_bytes"]
            or type(content) is not str
            or not 1 <= len(content_bytes) <= 192
            or not citations
            or any(citation != statement["source_resource_handle"] for citation in citations)
            or "\x00" in content):
        raise OperatorDenied("agent draft disagrees with acknowledged task read")
    try:
        signature = base64.b64decode(envelope["signature_b64"] + "==", validate=True)
        if len(signature) != 64:
            raise ValueError("signature length")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, DRAFT_DOMAIN + _canonical(statement),
        )
    except (ValueError, binascii.Error, InvalidSignature) as error:
        raise OperatorDenied("agent draft signature is invalid") from error
    if raw != _canonical(envelope):
        raise OperatorDenied("agent draft is not canonical")
    return content
