"""Operator-owned native authority for AP-071 task and write actions.

This module issues three distinct root-to-employee grants under one
provider-neutral trust context. The employee may delegate only the provider
write grant to a separately registered agent. The approval and confirmation
grants remain on the employee key. No provider credential enters this module.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass

from .contracts import valid_service
from .enrollment import EmployeeBinding
from .operator_authority import EmployeeAuthority, OperatorDenied, OperatorRoot


TASK_SERVICE = "auths-agent-task"
APPROVAL_TOOL = "approve_agent_task_v1"
CONFIRMATION_TOOL = "confirm_agent_write_v1"
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class TaskWriteAuthority:
    """Private operator handoff; only its trust template is installed."""

    provider_service: str
    provider_tool: str
    root_principal: str
    human_principal: str
    trusted_template: bytes
    approval_grant: EmployeeAuthority
    confirmation_grant: EmployeeAuthority
    write_parent_grant: EmployeeAuthority
    challenge: bytes
    not_before: int
    expires_at: int


def _permission(service: str, tool: str) -> tuple[str, str]:
    return "tools/call", f"mcp://{service}/tools/{tool}"


def issue_task_write_authority(
    root: OperatorRoot,
    binding: EmployeeBinding,
    identity_packet: bytes,
    *,
    provider_service: str,
    provider_tool: str,
    now: int | None = None,
    lifetime: int = 3600,
) -> TaskWriteAuthority:
    """Issue exact task profiles and one delegable provider tool to a human.

    The operator selects ``provider_service`` and ``provider_tool`` from its
    reviewed recipe, never from an agent action. The returned template defaults
    to the provider audience; the gateway rebinds only its fixed task actions
    to ``mcp://auths-agent-task`` during verification.
    """
    from auths import _native

    if (not valid_service(provider_service) or provider_service == TASK_SERVICE
            or not isinstance(provider_tool, str)
            or _TOOL.fullmatch(provider_tool) is None
            or not 60 <= lifetime <= 3600):
        raise OperatorDenied("task write profile or lifetime is invalid")
    now = int(time.time()) if now is None else now
    approval = root.issue_employee_for_tool(
        binding=binding, identity_packet=identity_packet,
        service=TASK_SERVICE, tool=APPROVAL_TOOL, now=now,
        lifetime=lifetime, remaining_depth=0,
    )
    confirmation = root.issue_employee_for_tool(
        binding=binding, identity_packet=identity_packet,
        service=TASK_SERVICE, tool=CONFIRMATION_TOOL, now=now,
        lifetime=lifetime, remaining_depth=0,
    )
    write_parent = root.issue_employee_for_tool(
        binding=binding, identity_packet=identity_packet,
        service=provider_service, tool=provider_tool, now=now,
        lifetime=lifetime, remaining_depth=1,
    )
    task_audience = f"mcp://{TASK_SERVICE}"
    provider_audience = f"mcp://{provider_service}"
    assurance = _native.AssurancePolicy("raw-key-baseline", [
        ("root", "every", "self-certifying-identifier", None),
        ("actor", "every", "self-certifying-identifier", None),
        ("actor", "every", "offline-verifiable", None),
    ])
    anchor = _native.TrustAnchor(
        root.principal, _native.Principal(root.principal),
        ["raw-key-v1"], [("auths.mcp", 2)],
        [_permission(TASK_SERVICE, APPROVAL_TOOL),
         _permission(TASK_SERVICE, CONFIRMATION_TOOL),
         _permission(provider_service, provider_tool)],
        [task_audience, provider_audience],
        [task_audience, provider_audience],
        now, now + lifetime, None, 2, "raw-key-baseline", None,
    )
    compiled = _native.compile_trusted_context(
        _native.self_contained_configuration(), None, 1, 1, 1,
        [anchor], assurance, None, None, "none-v1", ["raw-key-v1"], [],
    )
    challenge = secrets.token_bytes(32)
    provider_context = compiled.bind_request(provider_audience, challenge, now)
    return TaskWriteAuthority(
        provider_service, provider_tool, root.principal, binding.principal,
        bytes(_native.inspect_trusted_context(provider_context)),
        approval, confirmation, write_parent, challenge, now, now + lifetime,
    )


def plan_agent_write_grant(
    authority: TaskWriteAuthority,
    agent_principal: str,
    *,
    not_before: int,
    expires_at: int,
):
    """Prepare the employee-signed child grant for the exact write profile.

    The caller must verify that ``agent_principal`` belongs to the registered
    agent selected on the reviewed task card. This plan is not a grant until
    the human signs its preimage in browser custody.
    """
    from auths import _native

    if (not authority.not_before <= not_before < expires_at <= authority.expires_at
            or agent_principal == authority.human_principal):
        raise OperatorDenied("agent grant is outside human authority")
    parent = _native.parse_signed("grant", authority.write_parent_grant.signed_grant)
    audience = f"mcp://{authority.provider_service}"
    request = _native.GrantRequest(
        _native.Principal(agent_principal), "auths.mcp", 2,
        [_permission(authority.provider_service, authority.provider_tool)],
        not_before, expires_at, [audience], None, None, 0, None,
        "raw-key-baseline", [],
    )
    return _native.plan_child(parent, request)
