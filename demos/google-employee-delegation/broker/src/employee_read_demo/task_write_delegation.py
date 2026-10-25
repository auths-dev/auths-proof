"""Complete a human-signed child write grant for one registered agent.

The caller must obtain the employee and agent identity packets from its active
enrollment/registry, and compare the card with current operator pins before
rendering it. This module holds no private key or provider credential.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass

from .authority_identity import authority_for_identity_packet
from .operator_authority import OperatorDenied
from .task_write_authority import (
    TaskWriteAuthority, plan_agent_read_grant, plan_agent_write_grant,
)
from .task_write_proofs import task_commitment


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class PreparedAgentDelegation:
    signing_preimage: bytes
    human_principal: str
    agent_principal: str
    task_id: str
    task_commitment: str
    recipe_digest: str
    expires_at: int
    authority: TaskWriteAuthority
    human_public_key: bytes
    kind: str
    _signing: object

    def complete(self, signature: bytes, *, now: int | None = None) -> dict:
        """Return public proof material only after the enrolled human signs."""
        from auths import _native

        now = int(time.time()) if now is None else now
        if (type(signature) is not bytes or len(signature) != 64
                or not self.authority.not_before <= now < self.expires_at):
            raise OperatorDenied("human child grant signature is invalid")
        try:
            _native.verify_ed25519_preimage_v1(
                self.human_public_key, self.signing_preimage, signature,
            )
        except Exception as error:
            raise OperatorDenied("human child grant signature is invalid") from error
        child = self._signing.complete(signature)
        encode = lambda raw: base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        read = self.kind == "read"
        parent = (self.authority.read_parent_grant if read else
                  self.authority.write_parent_grant)
        return {
            "schema": ("auths.ap071-agent-read-package/1" if read else
                       "auths.ap071-agent-write-package/1"),
            "agent_principal": self.agent_principal,
            "service": (self.authority.read_service if read else
                        self.authority.provider_service),
            "tool": (self.authority.read_tool if read else
                     self.authority.provider_tool),
            "task_id": self.task_id,
            "expires_at": self.expires_at,
            "task_commitment": self.task_commitment,
            "recipe_digest": self.recipe_digest,
            "challenge_b64": encode(self.authority.challenge),
            ("read_parent_grant_b64" if read else
             "write_parent_grant_b64"): encode(parent.signed_grant),
            "signed_child_grant_b64": encode(_native.inspect_signed(child)),
            "root_evidence_b64": encode(
                parent.root_evidence,
            ),
            "human_evidence_b64": encode(
                parent.employee_evidence,
            ),
            "trusted_template_b64": encode(self.authority.trusted_template),
        }


def prepare_agent_delegation(
    authority: TaskWriteAuthority, human_identity_packet: bytes,
    registered_agent_packet: bytes, card: dict, recipe_digest: str,
) -> PreparedAgentDelegation:
    """Prepare a child grant after the caller's active-registry lookup."""
    return _prepare_provider_delegation(
        authority, human_identity_packet, registered_agent_packet,
        card, recipe_digest, "write",
    )


def prepare_agent_read_delegation(
    authority: TaskWriteAuthority, human_identity_packet: bytes,
    registered_agent_packet: bytes, card: dict, recipe_digest: str,
) -> PreparedAgentDelegation:
    """Prepare the card's one read grant for the same registered agent."""
    return _prepare_provider_delegation(
        authority, human_identity_packet, registered_agent_packet,
        card, recipe_digest, "read",
    )


def _prepare_provider_delegation(
    authority: TaskWriteAuthority, human_identity_packet: bytes,
    registered_agent_packet: bytes, card: dict, recipe_digest: str,
    kind: str,
) -> PreparedAgentDelegation:
    from auths import _native

    human, evidence = authority_for_identity_packet(human_identity_packet)
    agent, _ = authority_for_identity_packet(registered_agent_packet)
    scopes = card.get(f"{kind}_scopes") if type(card) is dict else None
    parent = (authority.read_parent_grant if kind == "read" else
              authority.write_parent_grant)
    if (human != authority.human_principal
            or parent is None or evidence != parent.employee_evidence
            or agent == human or type(card) is not dict
            or card.get("human_principal") != human
            or card.get("agent_principal") != agent
            or type(card.get("task_id")) is not str
            or not 1 <= len(card["task_id"]) <= 128
            or type(scopes) is not list or len(scopes) != 1
            or type(scopes[0]) is not dict
            or (kind == "write" and scopes[0].get("verb") not in ("edit", "create"))
            or (kind == "read" and "verb" in scopes[0])
            or scopes[0].get("recipe_digest") != recipe_digest
            or type(recipe_digest) is not str
            or _DIGEST.fullmatch(recipe_digest) is None
            or type(card.get("not_before")) is not int
            or type(card.get("expires_at")) is not int):
        raise OperatorDenied("reviewed agent delegation does not match authority")
    projection = _native.decode_identity_descriptor_v1(human_identity_packet)
    public_key = projection.relationships[0][3][0][1]
    plan = (plan_agent_read_grant if kind == "read" else
            plan_agent_write_grant)(authority, agent,
                                    not_before=card["not_before"],
                                    expires_at=card["expires_at"])
    signing = _native.prepare_signing(
        plan.unsigned, "raw-key-v1", human, "ed25519-v1",
    )
    return PreparedAgentDelegation(
        bytes(signing.signing_preimage), human, agent, card["task_id"],
        task_commitment(card), recipe_digest, card["expires_at"], authority,
        public_key, kind, signing,
    )
