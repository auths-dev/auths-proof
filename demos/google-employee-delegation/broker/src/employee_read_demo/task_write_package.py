"""Load one operator-owned AP-071 task authority package for browser signing.

The package contains public grants and trust, not a human key or provider
credential. Its private file protects operator selection and prevents a
browser or agent from replacing the profiles, account or challenge.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .contracts import valid_service
from .demo_co_contract import _unique_pairs
from .operator_authority import EmployeeAuthority, OperatorDenied
from .operator_cli import _private_read
from .task_write_authority import TaskWriteAuthority


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_FIELDS = {
    "schema", "company_id", "binding_ref", "root_principal", "human_principal",
    "provider_service", "provider_tool", "recipe_digest",
    "recipe_source_sha256", "profile_lock_sha256", "not_before", "expires_at",
    "trusted_template_b64", "challenge_b64", "approval_grant_b64",
    "confirmation_grant_b64", "write_parent_grant_b64", "root_evidence_b64",
    "human_evidence_b64", "read",
}
_FIELDS_V3 = _FIELDS | {"companion_write"}
_FIELDS_V4 = _FIELDS | {"effect_plan_grant_b64"}
_FIELDS_V4_COMPANION = _FIELDS_V3 | {"effect_plan_grant_b64"}
_READ_FIELDS = {
    "service", "tool", "recipe_digest", "recipe_source_sha256",
    "profile_lock_sha256", "parent_grant_b64",
}
_COMPANION_FIELDS = _READ_FIELDS


@dataclass(frozen=True)
class ReadProfile:
    service: str
    tool: str
    recipe_digest: str
    recipe_source_sha256: str
    profile_lock_sha256: str


@dataclass(frozen=True)
class CompanionWriteProfile:
    service: str
    tool: str
    recipe_digest: str
    recipe_source_sha256: str
    profile_lock_sha256: str


@dataclass(frozen=True)
class LoadedTaskWritePackage:
    company_id: str
    binding_ref: str
    recipe_digest: str
    recipe_source_sha256: str
    profile_lock_sha256: str
    read: ReadProfile | None
    authority: TaskWriteAuthority
    companion_write: CompanionWriteProfile | None = None


def _decode(value: object, maximum: int) -> bytes:
    if type(value) is not str or len(value) > maximum * 2:
        raise OperatorDenied("task authority package field is outside bounds")
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise OperatorDenied("task authority package field is malformed") from error
    if not 1 <= len(raw) <= maximum:
        raise OperatorDenied("task authority package field is outside bounds")
    return raw


def load_task_write_package(path: Path, *, now: int | None = None) -> LoadedTaskWritePackage:
    """Read a private issuance file and refuse drift from its installed trust."""
    from auths import _native

    try:
        package = json.loads(_private_read(path, 262_144), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError, PermissionError) as error:
        raise OperatorDenied("task authority package is unavailable") from error
    if (type(package) is not dict
            or (package.get("schema"), set(package)) not in (
                ("auths.ap071-task-authority/2", _FIELDS),
                ("auths.ap071-task-authority/3", _FIELDS_V3),
                ("auths.ap071-task-authority/4", _FIELDS_V4),
                ("auths.ap071-task-authority/4", _FIELDS_V4_COMPANION))
            or type(package.get("company_id")) is not str
            or not 1 <= len(package["company_id"]) <= 128
            or type(package.get("binding_ref")) is not str
            or not 1 <= len(package["binding_ref"]) <= 256
            or type(package.get("root_principal")) is not str
            or type(package.get("human_principal")) is not str
            or not valid_service(package.get("provider_service"))
            or package["provider_service"] == "auths-agent-task"
            or type(package.get("provider_tool")) is not str
            or _TOOL.fullmatch(package["provider_tool"]) is None
            or any(type(package.get(field)) is not str
                   or _DIGEST.fullmatch(package[field]) is None
                   for field in ("recipe_digest", "recipe_source_sha256",
                                 "profile_lock_sha256"))
            or type(package.get("not_before")) is not int
            or type(package.get("expires_at")) is not int):
        raise OperatorDenied("task authority package is malformed")
    read = package["read"]
    if read is not None and (
            type(read) is not dict or set(read) != _READ_FIELDS
            or not valid_service(read.get("service"))
            or read["service"] == "auths-agent-task"
            or type(read.get("tool")) is not str
            or _TOOL.fullmatch(read["tool"]) is None
            or (read["service"], read["tool"]) ==
            (package["provider_service"], package["provider_tool"])
            or any(type(read.get(field)) is not str
                   or _DIGEST.fullmatch(read[field]) is None
                   for field in ("recipe_digest", "recipe_source_sha256",
                                 "profile_lock_sha256"))):
        raise OperatorDenied("task read authority package is malformed")
    companion = package.get("companion_write")
    if companion is not None and (
            type(companion) is not dict or set(companion) != _COMPANION_FIELDS
            or not valid_service(companion.get("service"))
            or companion["service"] == "auths-agent-task"
            or type(companion.get("tool")) is not str
            or _TOOL.fullmatch(companion["tool"]) is None
            or (companion["service"], companion["tool"]) in (
                (package["provider_service"], package["provider_tool"]),
                (read["service"], read["tool"]) if read is not None else (None, None))
            or any(type(companion.get(field)) is not str
                   or _DIGEST.fullmatch(companion[field]) is None
                   for field in ("recipe_digest", "recipe_source_sha256",
                                 "profile_lock_sha256"))
            or companion["recipe_digest"] == package["recipe_digest"]):
        raise OperatorDenied("task companion write authority package is malformed")
    now = int(time.time()) if now is None else now
    if not package["not_before"] <= now < package["expires_at"]:
        raise OperatorDenied("task authority package expired")
    try:
        trusted = _decode(package["trusted_template_b64"], 262_144)
        challenge = _decode(package["challenge_b64"], 32)
        root_evidence = _decode(package["root_evidence_b64"], 4096)
        human_evidence = _decode(package["human_evidence_b64"], 4096)
        grants = {
            name: _decode(package[f"{name}_b64"], 262_144)
            for name in ("approval_grant", "confirmation_grant", "write_parent_grant")
        }
        if package["schema"] == "auths.ap071-task-authority/4":
            grants["effect_plan_grant"] = _decode(
                package["effect_plan_grant_b64"], 262_144)
        if read is not None:
            grants["read_parent_grant"] = _decode(read["parent_grant_b64"], 262_144)
        if companion is not None:
            grants["companion_write_parent_grant"] = _decode(
                companion["parent_grant_b64"], 262_144)
        context = _native.parse_trusted_context(trusted)
        for raw in grants.values():
            _native.parse_signed("grant", raw)
        _native.Principal(package["root_principal"])
        _native.Principal(package["human_principal"])
    except Exception as error:
        raise OperatorDenied("task authority native material is invalid") from error
    if (len(challenge) != 32
            or bytes(context.configuration) != bytes(_native.mcp_gateway_configuration())
            or bytes(context.expected_challenge) != challenge
            or context.expected_audience != f"mcp://{package['provider_service']}"):
        raise OperatorDenied("task authority trust does not match its profile")
    def employee_grant(name: str) -> EmployeeAuthority:
        return EmployeeAuthority(
            package["binding_ref"], package["human_principal"],
            package["root_principal"], grants[name], root_evidence,
            human_evidence, package["not_before"], package["expires_at"],
        )
    authority = TaskWriteAuthority(
        package["provider_service"], package["provider_tool"],
        package["root_principal"], package["human_principal"], trusted,
        employee_grant("approval_grant"), employee_grant("confirmation_grant"),
        employee_grant("write_parent_grant"), challenge,
        package["not_before"], package["expires_at"],
        None if read is None else read["service"],
        None if read is None else read["tool"],
        None if read is None else employee_grant("read_parent_grant"),
        None if companion is None else companion["service"],
        None if companion is None else companion["tool"],
        None if companion is None else employee_grant("companion_write_parent_grant"),
        (employee_grant("effect_plan_grant")
         if "effect_plan_grant" in grants else None),
    )
    read_profile = None if read is None else ReadProfile(
        read["service"], read["tool"], read["recipe_digest"],
        read["recipe_source_sha256"], read["profile_lock_sha256"],
    )
    companion_profile = None if companion is None else CompanionWriteProfile(
        companion["service"], companion["tool"], companion["recipe_digest"],
        companion["recipe_source_sha256"], companion["profile_lock_sha256"],
    )
    return LoadedTaskWritePackage(
        package["company_id"], package["binding_ref"], package["recipe_digest"],
        package["recipe_source_sha256"], package["profile_lock_sha256"],
        read_profile, authority, companion_profile,
    )
