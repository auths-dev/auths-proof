"""Author one provider-neutral write proof inside the isolated agent process.

The package contains public native grants and operator pins only. The agent
keeps its own seed and never receives the human key or provider credential.
The gateway remains the final authority for recipe, task, confirmation and
provider entry.
"""

from __future__ import annotations

import base64
import json
import re
import time

from auths import _native

from .run import AgentKey


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PROFILE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _decode(value: object, maximum: int) -> bytes:
    if type(value) is not str or len(value) > maximum * 2:
        raise ValueError("agent write package field exceeds bounds")
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("agent write package field is malformed") from error
    if not 1 <= len(raw) <= maximum:
        raise ValueError("agent write package field exceeds bounds")
    return raw


def sign_write(package: dict, arguments: dict, key: AgentKey,
               *, now: int | None = None) -> tuple[bytes, bytes]:
    """Sign the agent's selected action; never submit or claim provider effect."""
    if (type(package) is not dict
            or package.get("schema") != "auths.ap071-agent-write-package/1"
            or type(arguments) is not dict
            or package.get("agent_principal") != key.principal
            or not isinstance(package.get("service"), str)
            or _PROFILE.fullmatch(package["service"]) is None
            or not isinstance(package.get("tool"), str)
            or _TOOL.fullmatch(package["tool"]) is None
            or type(package.get("task_id")) is not str
            or not isinstance(package.get("task_commitment"), str)
            or _DIGEST.fullmatch(package["task_commitment"]) is None
            or not isinstance(package.get("recipe_digest"), str)
            or _DIGEST.fullmatch(package["recipe_digest"]) is None
            or arguments.get("task_id") != package["task_id"]
            or arguments.get("task_commitment") != package["task_commitment"]
            or arguments.get("recipe_digest") != package["recipe_digest"]):
        raise ValueError("agent write is outside its task package")
    now = int(time.time()) if now is None else now
    challenge = _decode(package.get("challenge_b64"), 32)
    if len(challenge) != 32:
        raise ValueError("installed challenge is invalid")
    parent = _native.parse_signed(
        "grant", _decode(package.get("write_parent_grant_b64"), 262_144),
    )
    child = _native.parse_signed(
        "grant", _decode(package.get("signed_child_grant_b64"), 262_144),
    )
    root_evidence = _decode(package.get("root_evidence_b64"), 4096)
    human_evidence = _decode(package.get("human_evidence_b64"), 4096)
    template = _native.parse_trusted_context(
        _decode(package.get("trusted_template_b64"), 262_144),
    )
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    canonical = _native.canonicalize_mcp_arguments_json(encoded)
    call = _native.mcp_call(package["service"], package["tool"], canonical)
    prepared = _native.prepare_mcp_call_action(
        call, _native.Principal(key.principal), child, challenge, now, 30,
    )
    signing = _native.prepare_signing(
        prepared.unsigned, "raw-key-v1", key.principal, "ed25519-v1",
    )
    signed = signing.complete(key.private.sign(bytes(signing.signing_preimage)))
    context = template.bind_request(f"mcp://{package['service']}", challenge, now)
    evidence = lambda raw: ("raw-key-v1", "application/vnd.auths.raw-key.v1", raw)
    proof, action, _ = _native.assemble_mcp_proof(
        prepared, signed, [parent, child],
        [[evidence(root_evidence)], [evidence(human_evidence)]],
        [evidence(key.evidence)], context,
    )
    verdict, command = _native.verify_exact_mcp_command(
        proof, action, bytes(_native.inspect_trusted_context(context)),
        package["service"], package["tool"],
    )
    if verdict.kind != "authorized" or command is None:
        raise ValueError("native agent write proof was refused")
    return bytes(proof), bytes(action)
