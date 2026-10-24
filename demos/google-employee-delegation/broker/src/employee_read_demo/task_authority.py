"""Native planning for the reviewed employee-to-agent grant."""

from __future__ import annotations

from .authority import native_body_digest
from .contracts import TaskDescriptor


def plan_agent_grant(task: TaskDescriptor, signed_employee_grant: bytes, *, assurance_floor: str):
    """Return a native child plan, never an automatically accepted grant.

    The employee custody signer signs ``plan.unsigned`` after review. The
    broker must verify that signed grant in the complete company-rooted proof
    under operator-pinned trust before enrolling the task.
    """
    task.validate()
    if not signed_employee_grant or len(signed_employee_grant) > 262_144:
        raise ValueError("invalid employee grant")
    from auths import _native

    parent = _native.parse_signed("grant", signed_employee_grant)
    audience = f"mcp://{task.service}"
    request = _native.GrantRequest(
        _native.Principal(task.agent_principal), "auths.mcp", 2,
        [("tools/call", f"{audience}/tools/google_drive_document_read")],
        task.not_before, task.expires_at, [audience],
        [native_body_digest(call, task.service) for call in task.calls()],
        None, 0, None, assurance_floor, [],
    )
    return _native.plan_child(parent, request)
