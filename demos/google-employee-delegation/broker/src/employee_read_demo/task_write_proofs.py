"""Prepare native AP-071 human actions without custody of the human key.

The browser signs the returned Ed25519 preimage. A caller must render and
review the exact card or closed write intent before requesting that signature.
The gateway subsequently checks operator pins, task admission and the closed
provider request; a proof from this module does not authorize provider I/O.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .contracts import canonical_json, commitment
from .operator_authority import OperatorDenied
from .task_write_authority import (
    APPROVAL_TOOL, CONFIRMATION_TOOL, EFFECT_PLAN_TOOL, RECOVERY_TOOL,
    TASK_SERVICE,
    TaskWriteAuthority,
)


_ROOT_EVIDENCE = "raw-key-v1", "application/vnd.auths.raw-key.v1"


@dataclass(frozen=True)
class CompletedHumanAction:
    proof: bytes
    action: bytes


@dataclass(frozen=True)
class PreparedHumanAction:
    """One short-lived signature request for an exact reviewed payload."""

    tool: str
    payload_canonical: bytes
    signing_preimage: bytes
    challenge: bytes
    prepared_at: int
    expires_at: int
    authority: TaskWriteAuthority
    _prepared: object
    _signing: object
    _grant: object

    def complete(self, signature: bytes, *, now: int | None = None) -> CompletedHumanAction:
        from auths import _native

        now = int(time.time()) if now is None else now
        if (type(signature) is not bytes or len(signature) != 64
                or now < self.prepared_at or now >= self.expires_at):
            raise OperatorDenied("human signature is unavailable")
        signed = self._signing.complete(signature)
        template = _native.parse_trusted_context(self.authority.trusted_template)
        context = template.bind_request(
            f"mcp://{TASK_SERVICE}", self.challenge, self.prepared_at,
        )
        evidence = lambda raw: (*_ROOT_EVIDENCE, raw)
        proof, action, _ = _native.assemble_mcp_proof(
            self._prepared, signed, [self._grant],
            [[evidence(self.authority.approval_grant.root_evidence)]],
            [evidence(self.authority.approval_grant.employee_evidence)], context,
        )
        verdict, command = _native.verify_exact_mcp_command(
            proof, action, bytes(_native.inspect_trusted_context(context)),
            TASK_SERVICE, self.tool,
        )
        if verdict.kind != "authorized" or command is None:
            raise OperatorDenied("human native action was refused")
        return CompletedHumanAction(bytes(proof), bytes(action))


def _prepare(authority: TaskWriteAuthority, *, tool: str,
             payload: dict, now: int | None) -> PreparedHumanAction:
    from auths import _native

    now = int(time.time()) if now is None else now
    if (tool not in (APPROVAL_TOOL, CONFIRMATION_TOOL, EFFECT_PLAN_TOOL,
                    RECOVERY_TOOL)
            or not authority.not_before <= now < authority.expires_at - 1):
        raise OperatorDenied("human task authority expired")
    grant = {
        APPROVAL_TOOL: authority.approval_grant,
        CONFIRMATION_TOOL: authority.confirmation_grant,
        EFFECT_PLAN_TOOL: authority.effect_plan_grant,
        RECOVERY_TOOL: authority.recovery_grant,
    }[tool]
    if grant is None:
        raise OperatorDenied("human task tool authority is unavailable")
    terminal = _native.parse_signed("grant", grant.signed_grant)
    challenge = authority.challenge
    arguments = bytes(_native.canonicalize_mcp_arguments_json(canonical_json(payload)))
    call = _native.mcp_call(TASK_SERVICE, tool, arguments)
    prepared = _native.prepare_mcp_call_action(
        call, _native.Principal(authority.human_principal), terminal,
        challenge, now, min(300, authority.expires_at - now),
    )
    signing = _native.prepare_signing(
        prepared.unsigned, "raw-key-v1", authority.human_principal, "ed25519-v1",
    )
    return PreparedHumanAction(
        tool, arguments, bytes(signing.signing_preimage), challenge, now,
        min(now + 300, authority.expires_at), authority, prepared, signing,
        terminal,
    )


def prepare_task_approval(authority: TaskWriteAuthority, card: dict,
                          *, now: int | None = None) -> PreparedHumanAction:
    if (type(card) is not dict or card.get("schema") != "auths.agent-task/2"
            or card.get("human_principal") != authority.human_principal):
        raise OperatorDenied("reviewed task card does not name the human")
    return _prepare(authority, tool=APPROVAL_TOOL, payload={"task": card}, now=now)


def prepare_exact_confirmation(authority: TaskWriteAuthority, intent: dict,
                               *, now: int | None = None) -> PreparedHumanAction:
    if type(intent) is not dict or not intent.get("task_id"):
        raise OperatorDenied("closed write intent is unavailable")
    return _prepare(authority, tool=CONFIRMATION_TOOL,
                    payload={"write": intent}, now=now)


def prepare_effect_plan_confirmation(authority: TaskWriteAuthority, plan: dict,
                                     *, now: int | None = None) -> PreparedHumanAction:
    if (type(plan) is not dict
            or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") is None
            or type(plan.get("initial_text")) is not str
            or not 1 <= len(plan["initial_text"].encode("utf-8")) <= 192):
        raise OperatorDenied("reviewed effect plan is invalid")
    return _prepare(authority, tool=EFFECT_PLAN_TOOL,
                    payload={"plan": plan}, now=now)


def prepare_recovered_child_confirmation(
    authority: TaskWriteAuthority, recovery: dict,
    *, now: int | None = None,
) -> PreparedHumanAction:
    if (type(recovery) is not dict
            or recovery.get("schema") != "auths.agent-recovered-child/1"
            or type(recovery.get("task_id")) is not str
            or type(recovery.get("candidate_id")) is not str
            or type(recovery.get("attestation_commitment")) is not str):
        raise OperatorDenied("reviewed recovered child is invalid")
    return _prepare(authority, tool=RECOVERY_TOOL,
                    payload={"recovery": recovery}, now=now)


def task_commitment(card: dict) -> str:
    """Match the gateway's domain-separated commitment for a reviewed card."""
    if type(card) is not dict or card.get("schema") != "auths.agent-task/2":
        raise OperatorDenied("task card is invalid")
    return commitment("auths.agent-task.v2", card)
