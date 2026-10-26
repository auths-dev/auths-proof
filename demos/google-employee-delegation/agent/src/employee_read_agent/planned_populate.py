"""Form the agent's Google population action from one approved effect plan.

The agent receives no Google credential. These local checks keep the agent's
own signed draft, the Jules plan and the reported child aligned; the gateway
independently verifies the human plan, Jules preflight, task and actual action
before any provider request.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .draft import DRAFT_DOMAIN, DRAFT_SCHEMA
from .run import AgentKey


_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DRAFT_FIELDS = {
    "schema", "task_id", "task_commitment", "agent_principal",
    "source_resource_handle", "read_operation_id", "source_sha256",
    "source_bytes", "content",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def planned_populate_arguments(*, package: dict, plan: dict, preflight: dict,
                               draft: dict, recipe: dict, key: AgentKey,
                               now: int | None = None) -> dict:
    """Build exact profile arguments; the generic native signer signs them."""
    now = int(time.time()) if now is None else now
    if (type(package) is not dict
            or package.get("schema") != "auths.ap071-agent-write-package/1"
            or package.get("agent_principal") != key.principal
            or type(plan) is not dict
            or set(plan) != {"schema", "task_id", "task_commitment", "create",
                             "populate_recipe_digest", "populate_operation_id",
                             "initial_text", "expires_at"}
            or plan["schema"] != "auths.agent-effect-plan/1"
            or type(plan["create"]) is not dict
            or type(preflight) is not dict
            or set(preflight) != {"statement", "signature_b64"}
            or type(preflight["statement"]) is not dict
            or type(preflight["signature_b64"]) is not str
            or type(draft) is not dict
            or set(draft) != {"statement", "signature_b64"}
            or type(draft["statement"]) is not dict
            or type(draft["signature_b64"]) is not str
            or set(draft["statement"]) != _DRAFT_FIELDS
            or type(recipe) is not dict
            or recipe.get("schema") != "auths.gateway-recipe-source/2"
            or recipe.get("service") != package.get("service")
            or recipe.get("tool") != package.get("tool")
            or type(recipe.get("task_binding")) is not dict
            or recipe.get("task_binding", {}).get("verb") != "edit"):
        raise ValueError("planned populate handoff is malformed")
    statement = preflight["statement"]
    own_draft = draft["statement"]
    create = plan["create"]
    fields = recipe.get("task_populate")
    resource_field = recipe["task_binding"].get("resource_field")
    values = statement.get("provider_values")
    if (type(fields) is not dict
            or set(fields) != {"text_field", "preflight_fields"}
            or (fields["text_field"], fields["preflight_fields"], resource_field)
            != ("text", ["required_revision_id", "tab_id"], "document_id")
            or recipe.get("operator_namespace") != "google-docs-populate-demo"
            or statement.get("schema") != "auths.gateway-task-populate-preflight/2"
            or statement.get("task_id") != package.get("task_id")
            or statement.get("task_commitment") != package.get("task_commitment")
            or statement.get("create_operation_id") != create.get("operation_id")
            or statement.get("populate_recipe_digest") != package.get("recipe_digest")
            or plan["populate_recipe_digest"] != package.get("recipe_digest")
            or plan["task_id"] != package.get("task_id")
            or plan["task_commitment"] != package.get("task_commitment")
            or create.get("verb") != "create"
            or create.get("task_id") != package.get("task_id")
            or create.get("task_commitment") != package.get("task_commitment")
            or statement.get("connection_subject") != create.get("connection_subject")
            or statement.get("connection_generation") != create.get("connection_generation")
            or own_draft.get("schema") != DRAFT_SCHEMA
            or own_draft.get("task_id") != package.get("task_id")
            or own_draft.get("task_commitment") != package.get("task_commitment")
            or own_draft.get("agent_principal") != key.principal
            or own_draft.get("content") != plan["initial_text"]
            or type(plan["initial_text"]) is not str
            or not 1 <= len(plan["initial_text"].encode("utf-8")) <= 192
            or type(plan["populate_operation_id"]) is not str
            or _ID.fullmatch(plan["populate_operation_id"]) is None
            or type(statement.get("child_id")) is not str
            or _ID.fullmatch(statement["child_id"]) is None
            or type(values) is not dict
            or set(values) != {"tab_id", "required_revision_id"}
            or type(values["tab_id"]) is not str
            or not 1 <= len(values["tab_id"].encode()) <= 64
            or type(values["required_revision_id"]) is not str
            or not 1 <= len(values["required_revision_id"].encode()) <= 128
            or type(plan["expires_at"]) is not int
            or type(statement.get("valid_until")) is not int
            or type(statement.get("checked_at")) is not int
            or type(package.get("expires_at")) is not int
            or not statement["checked_at"] <= now < statement["valid_until"]
            or statement["valid_until"] > plan["expires_at"]
            or now >= min(plan["expires_at"], statement["valid_until"],
                          package["expires_at"])):
        raise ValueError("planned populate differs from agent draft or task")
    try:
        signature = base64.b64decode(draft["signature_b64"] + "==", validate=True)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        public = key.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, DRAFT_DOMAIN + _canonical(own_draft),
        )
    except (InvalidSignature, ValueError, binascii.Error) as error:
        raise ValueError("agent draft signature changed") from error
    return {
        "operator_namespace": recipe["operator_namespace"],
        "operation_id": plan["populate_operation_id"],
        "recipe_digest": package["recipe_digest"],
        "task_id": package["task_id"],
        "task_commitment": package["task_commitment"],
        resource_field: statement["child_id"],
        fields["text_field"]: plan["initial_text"],
        **values,
    }
