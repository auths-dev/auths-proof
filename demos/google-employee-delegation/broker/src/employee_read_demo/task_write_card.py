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
from .task_write_operator_cli import _reviewed_profile, _reviewed_release_profile
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
    optional = {"populate_preflight", "recovery_attestation"}
    if (type(document) is not dict
            or not {"schema", "recipe_digests", "pins"} <= set(document)
            or not set(document) <= {"schema", "recipe_digests", "pins"} | optional
            or document["schema"] != "auths.gateway-task-installation/3"
            or type(document["recipe_digests"]) is not list
            or not 1 <= len(document["recipe_digests"]) <= 4
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                   for value in document["recipe_digests"])
            or document["recipe_digests"] != sorted(set(document["recipe_digests"]))
            or type(document["pins"]) is not dict
            or set(document["pins"]) != _PINS):
        raise OperatorDenied("installed gateway task pins are malformed")
    preflight = document.get("populate_preflight")
    if ("populate_preflight" in document
            and (type(preflight) is not dict
                 or set(preflight) != {"public_key_hex", "rule_digest"}
                 or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                        for value in preflight.values()))):
        raise OperatorDenied("installed gateway preflight pin is malformed")
    recovery = document.get("recovery_attestation")
    if ("recovery_attestation" in document
            and (type(recovery) is not dict
                 or set(recovery) != {"public_key_hex", "rule_digest"}
                 or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                        for value in recovery.values()))):
        raise OperatorDenied("installed gateway recovery pin is malformed")
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
    read_recipe_path: Path | None = None,
    read_profile_lock_path: Path | None = None,
    read_resource_handle: str | None = None,
    companion_recipe_path: Path | None = None,
    companion_profile_lock_path: Path | None = None,
    pending_child: dict | None = None,
    upfront_allowed_arguments: list[dict] | None = None,
    read_only: bool = False,
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
    if (package.recipe_digest not in installation["recipe_digests"]
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
            or type(pins["allow_bounded_writes"]) is not bool
            or type(pins["connection_id"]) is not str
            or not 1 <= len(pins["connection_id"]) <= 128
            or type(pins["connection_generation"]) is not int
            or pins["connection_generation"] < 1
            or type(pins["connection_subject"]) is not str
            or not 1 <= len(pins["connection_subject"]) <= 256
            or type(pins["permitted_read_scopes"]) is not list
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
    read_scopes = []
    release_bytes = 0
    if package.read is None:
        if any(value is not None for value in (
                read_recipe_path, read_profile_lock_path, read_resource_handle)):
            raise OperatorDenied("read source is not installed for this task")
    else:
        if (read_recipe_path is None or read_profile_lock_path is None
                or type(read_resource_handle) is not str
                or not 1 <= len(read_resource_handle) <= 256
                or any(unicodedata.category(character) == "Cc"
                       for character in read_resource_handle)):
            raise OperatorDenied("reviewed task source is unavailable")
        try:
            read_service, read_tool, read_sha, read_lock_sha = _reviewed_release_profile(
                read_recipe_path, read_profile_lock_path,
            )
            read_recipe = json.loads(read_recipe_path.read_bytes(),
                                     object_pairs_hook=_unique_pairs)
        except (OSError, ValueError) as error:
            raise OperatorDenied("reviewed read recipe is unavailable") from error
        if (read_service != package.read.service or read_tool != package.read.tool
                or read_sha != package.read.recipe_source_sha256
                or read_lock_sha != package.read.profile_lock_sha256):
            raise OperatorDenied("reviewed read recipe changed")
        matches = [scope for scope in pins["permitted_read_scopes"]
                   if type(scope) is dict
                   and scope.get("handle") == read_resource_handle
                   and scope.get("recipe_digest") == package.read.recipe_digest]
        if len(matches) != 1 or set(matches[0]) != {
                "handle", "recipe_digest", "connection_id",
                "connection_generation", "connection_subject"}:
            raise OperatorDenied("task source is outside operator read pins")
        scope = matches[0]
        if (type(scope["connection_id"]) is not str
                or not 1 <= len(scope["connection_id"]) <= 128
                or type(scope["connection_generation"]) is not int
                or scope["connection_generation"] < 1
                or type(scope["connection_subject"]) is not str
                or not 1 <= len(scope["connection_subject"]) <= 256):
            raise OperatorDenied("task read connection pin is invalid")
        read_scopes = [scope]
        release_bytes = min(16_384,
                            read_recipe["response"]["maximum_release_bytes"])
    if package.companion_write is None:
        if any(value is not None for value in (
                companion_recipe_path, companion_profile_lock_path, pending_child)):
            raise OperatorDenied("task has no reviewed companion write")
    else:
        companion = package.companion_write
        if installation.get("populate_preflight") is None:
            raise OperatorDenied("populate preflight signer is not installed")
        if (verb != "create" or companion_recipe_path is None
                or companion_profile_lock_path is None
                or type(pending_child) is not dict
                or set(pending_child) != {
                    "create_operation_id", "create_recipe_digest",
                    "populate_recipe_digest", "parent_handle", "title", "marker"}
                or pending_child["create_recipe_digest"] != package.recipe_digest
                or pending_child["populate_recipe_digest"] != companion.recipe_digest
                or pending_child["parent_handle"] != resource_handle
                or companion.recipe_digest not in installation["recipe_digests"]
                or not all(type(pending_child[key]) is str
                           and 1 <= len(pending_child[key].encode()) <= maximum
                           and not any(unicodedata.category(char) == "Cc"
                                       for char in pending_child[key])
                           for key, maximum in (("create_operation_id", 32),
                                                ("title", 256), ("marker", 256)))):
            raise OperatorDenied("pending child differs from installed task write")
        try:
            second_service, second_tool, second_sha, second_lock_sha = _reviewed_profile(
                companion_recipe_path, companion_profile_lock_path)
            second_recipe = json.loads(companion_recipe_path.read_bytes(),
                                       object_pairs_hook=_unique_pairs)
        except (OSError, ValueError) as error:
            raise OperatorDenied("reviewed companion write is unavailable") from error
        if (second_service != companion.service or second_tool != companion.tool
                or second_sha != companion.recipe_source_sha256
                or second_lock_sha != companion.profile_lock_sha256
                or second_recipe["task_binding"]["verb"] != "edit"):
            raise OperatorDenied("reviewed companion write changed")
    if (type(read_only) is not bool
            or (read_only and (len(read_scopes) != 1
                               or pending_child is not None
                               or package.companion_write is not None
                               or upfront_allowed_arguments is not None))):
        raise OperatorDenied("read-only task needs one selected source and no write options")
    card = {
        "schema": "auths.agent-task/2",
        "task_id": secrets.token_urlsafe(18),
        "company_id": employee.company_id,
        "human_principal": employee.principal,
        "agent_principal": agent.agent_principal,
        "agent_key_fingerprint": agent.identity_packet_sha256,
        "connection_id": pins["connection_id"],
        "connection_generation": pins["connection_generation"],
        "connection_subject": pins["connection_subject"],
        "read_scopes": read_scopes,
        "write_scopes": [] if read_only else [{"handle": resource_handle,
                                                "recipe_digest": package.recipe_digest,
                                                "verb": verb,
                                                "connection_id": pins["connection_id"],
                                                "connection_generation": pins["connection_generation"],
                                                "connection_subject": pins["connection_subject"]}],
        "delivery_channel": pins["delivery_channel"],
        "not_before": now,
        "expires_at": min(now + 1800, authority.expires_at),
        "max_provider_calls": len(read_scopes),
        "max_releases": len(read_scopes),
        "max_release_bytes": release_bytes,
        "max_writes": 0 if read_only else 2 if package.companion_write is not None else 1,
        "write_approval_mode": "exact",
        "operator_policy_digest": pins["operator_policy_digest"],
        "purpose": purpose,
    }
    if pending_child is not None:
        card["pending_child"] = pending_child.copy()
    if upfront_allowed_arguments is not None:
        binding_fields = {"operator_namespace", "operation_id", "recipe_digest",
                          "task_id", "task_commitment"}
        try:
            profile = json.loads(profile_lock_path.read_bytes(),
                                 object_pairs_hook=_unique_pairs)
            expected_fields = set(profile["command_schema"]["fields"]) - binding_fields
            serialized = [json.dumps(choice, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False)
                          for choice in upfront_allowed_arguments]
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise OperatorDenied("bounded upfront choices are malformed") from error
        resource_field = binding["resource_field"]
        if (type(upfront_allowed_arguments) is not list
                or not pins["allow_bounded_writes"] or verb != "edit"
                or pending_child is not None or package.companion_write is not None
                or not 1 <= len(upfront_allowed_arguments) <= 4
                or any(type(choice) is not dict or set(choice) != expected_fields
                       or choice.get(resource_field) != resource_handle
                       or len(encoded.encode()) > 4096
                       for choice, encoded in zip(upfront_allowed_arguments, serialized))
                or len(set(serialized)) != len(serialized)):
            raise OperatorDenied("bounded upfront choices disagree with installed task")
        card["write_approval_mode"] = "bounded-upfront"
        card["upfront_allowed_arguments"] = upfront_allowed_arguments
    return card
