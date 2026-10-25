"""Build a human-readable task card from installed, owner-controlled facts.

The browser may provide only a bounded purpose. It cannot choose an agent,
connection, recipe, destination or policy limit. Provider-specific pickers
resolve a resource handle before calling this provider-neutral builder.
"""

from __future__ import annotations

import json
import re
import secrets
import time
import unicodedata
from pathlib import Path

from .agent_registry import AgentBinding
from .demo_co_contract import _unique_pairs
from .enrollment import EmployeeBinding
from .operator_authority import OperatorDenied
from .operator_cli import _private_read
from .task_write_operator_cli import _reviewed_profile
from .task_write_package import LoadedTaskWritePackage


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PINS = {
    "company_id", "human_principal", "agent_principal",
    "agent_key_fingerprint", "connection_id", "connection_generation",
    "connection_subject", "delivery_channel", "operator_policy_digest",
    "allow_bounded_writes", "permitted_read_scopes",
}


def _installation(path: Path) -> dict:
    try:
        document = json.loads(_private_read(path, 16_384), object_pairs_hook=_unique_pairs)
    except (PermissionError, UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("installed gateway task pins are unavailable") from error
    if (type(document) is not dict or set(document) != {"schema", "recipe_digest", "pins"}
            or document["schema"] != "auths.gateway-task-installation/2"
            or type(document["recipe_digest"]) is not str
            or _DIGEST.fullmatch(document["recipe_digest"]) is None
            or type(document["pins"]) is not dict
            or set(document["pins"]) != _PINS):
        raise OperatorDenied("installed gateway task pins are malformed")
    return document


def build_exact_write_card(
    package: LoadedTaskWritePackage,
    employee: EmployeeBinding,
    agent: AgentBinding,
    *,
    installation_path: Path,
    recipe_path: Path,
    profile_lock_path: Path,
    resource_handle: str,
    purpose: str,
    now: int | None = None,
) -> dict:
    """Create one short task tied to the installed gateway and reviewed recipe."""
    now = int(time.time()) if now is None else now
    authority = package.authority
    installation = _installation(installation_path)
    pins = installation["pins"]
    try:
        service, tool, recipe_sha, lock_sha = _reviewed_profile(
            recipe_path, profile_lock_path,
        )
        recipe = json.loads(recipe_path.read_bytes(), object_pairs_hook=_unique_pairs)
    except (OSError, ValueError) as error:
        raise OperatorDenied("reviewed write recipe is unavailable") from error
    binding = recipe.get("task_binding") if type(recipe) is dict else None
    verb = binding.get("verb") if type(binding) is dict else None
    if (installation["recipe_digest"] != package.recipe_digest
            or recipe_sha != package.recipe_source_sha256
            or lock_sha != package.profile_lock_sha256
            or service != authority.provider_service
            or tool != authority.provider_tool
            or verb not in ("edit", "create")
            or package.company_id != employee.company_id
            or package.binding_ref != employee.binding_ref
            or employee.principal != authority.human_principal
            or agent.company_id != employee.company_id
            or agent.employee_binding_ref != employee.binding_ref
            or agent.agent_principal == employee.principal
            or pins["company_id"] != employee.company_id
            or pins["human_principal"] != employee.principal
            or pins["agent_principal"] != agent.agent_principal
            or pins["agent_key_fingerprint"] != agent.identity_packet_sha256
            or pins["allow_bounded_writes"] is not False
            or type(pins["connection_id"]) is not str
            or not 1 <= len(pins["connection_id"]) <= 128
            or type(pins["connection_generation"]) is not int
            or pins["connection_generation"] < 1
            or type(pins["connection_subject"]) is not str
            or not 1 <= len(pins["connection_subject"]) <= 256
            or pins["permitted_read_scopes"] != []
            or type(pins["delivery_channel"]) is not str
            or not 1 <= len(pins["delivery_channel"]) <= 256
            or type(pins["operator_policy_digest"]) is not str
            or _DIGEST.fullmatch(pins["operator_policy_digest"]) is None
            or type(resource_handle) is not str
            or not 1 <= len(resource_handle) <= 256
            or any(unicodedata.category(character) == "Cc" for character in resource_handle)
            or type(purpose) is not str or not 1 <= len(purpose) <= 512
            or any(unicodedata.category(character) == "Cc" for character in purpose)
            or not authority.not_before <= now < authority.expires_at - 60):
        raise OperatorDenied("task card disagrees with installed authority")
    return {
        "schema": "auths.agent-task/2",
        "task_id": secrets.token_urlsafe(18),
        "company_id": employee.company_id,
        "human_principal": employee.principal,
        "agent_principal": agent.agent_principal,
        "agent_key_fingerprint": agent.identity_packet_sha256,
        "connection_id": pins["connection_id"],
        "connection_generation": pins["connection_generation"],
        "connection_subject": pins["connection_subject"],
        "read_scopes": [],
        "write_scopes": [{"handle": resource_handle,
                          "recipe_digest": package.recipe_digest, "verb": verb,
                          "connection_id": pins["connection_id"],
                          "connection_generation": pins["connection_generation"],
                          "connection_subject": pins["connection_subject"]}],
        "delivery_channel": pins["delivery_channel"],
        "not_before": now,
        "expires_at": min(now + 1800, authority.expires_at),
        "max_provider_calls": 0,
        "max_releases": 0,
        "max_release_bytes": 0,
        "max_writes": 1,
        "write_approval_mode": "exact",
        "operator_policy_digest": pins["operator_policy_digest"],
        "purpose": purpose,
    }
