from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from auths import Principal
from auths.lifecycle import record_compromise, rotate_identity
from auths.runtime import RuntimeKernel, TransitionGates
from auths.verify import verify


FIXTURE = "webauthn-root-raw-key-actor"


def fixture_paths(root: Path) -> tuple[Path, Path, Path]:
    directory = root / "core" / "fixtures" / "v1" / "valid"
    return (
        directory / f"{FIXTURE}.proof.cbor",
        directory / f"{FIXTURE}.action.cbor",
        directory / f"{FIXTURE}.context.cbor",
    )


def portable_fixture(root: Path) -> dict[str, Any]:
    proof_path, action_path, context_path = fixture_paths(root)
    proof, action, context = (
        proof_path.read_bytes(),
        action_path.read_bytes(),
        context_path.read_bytes(),
    )
    result = verify(proof, action, context)
    return {
        "fixture": FIXTURE,
        "proof": base64.b64encode(proof).decode(),
        "action": base64.b64encode(action).decode(),
        "context": base64.b64encode(context).decode(),
        "python": decision(result),
    }


def decision(result: Any) -> dict[str, Any]:
    return {
        "kind": result.kind,
        "stage": result.stage,
        "code": result.code,
        "metrics": asdict(result.metrics),
        "resultSha256": hashlib.sha256(result.result_cbor).hexdigest(),
        "localConfiguration": result.local_configuration.hex(),
        "requiredConfiguration": None
        if result.required_configuration is None
        else result.required_configuration.hex(),
    }


def mutation_attack(root: Path) -> dict[str, Any]:
    proof_path, action_path, context_path = fixture_paths(root)
    action = bytearray(action_path.read_bytes())
    action[-1] ^= 1
    result = verify(proof_path.read_bytes(), bytes(action), context_path.read_bytes())
    return attack_result(
        "mutate-firewall-byte",
        result.kind != "authorized",
        result.stage,
        result.code,
        "One canonical action byte changed after approval; the verifier denied it.",
        decision(result),
    )


def replay_attack() -> dict[str, Any]:
    kernel = RuntimeKernel()
    first = kernel.replay(False, False)
    replay = kernel.replay(True, True)
    conflict = kernel.replay(True, False)
    return attack_result(
        "replay-command",
        first == "absent" and replay == "exact-replay" and conflict == "conflict",
        "runtime",
        replay,
        "The durable runtime classified the second command as an exact replay.",
        {"first": first, "second": replay, "mutated": conflict, "providerCalls": 1},
    )


def expired_attack() -> dict[str, Any]:
    result = RuntimeKernel().transition(
        "execution-intent-recorded",
        "authorize-credential",
        TransitionGates(
            core_authorized=True,
            policy_eligible=True,
            configuration_matches=True,
            not_revoked=True,
            not_expired=False,
            capacity_available=True,
            execution_intent_present=True,
        ),
    )
    code = getattr(result, "code", "unexpected")
    return attack_result(
        "expired-grant",
        result.kind == "rejected",
        "runtime",
        code,
        "Expiry stopped the workflow before credential authorization or provider I/O.",
        asdict(result),
    )


def compromise_attack() -> dict[str, Any]:
    principal = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")
    status = record_compromise(
        method="auths.status",
        principal=principal,
        purpose="authentication",
        issuer=principal,
        sequence=2,
        valid_for=600,
        observed_at=100,
    )
    result = RuntimeKernel().transition(
        "execution-intent-recorded",
        "authorize-credential",
        TransitionGates(
            core_authorized=True,
            policy_eligible=True,
            configuration_matches=True,
            not_revoked=False,
            not_expired=True,
            capacity_available=True,
            execution_intent_present=True,
        ),
    )
    return attack_result(
        "compromised-approver",
        status.state == "revoked" and result.kind == "rejected",
        "lifecycle",
        getattr(result, "code", "principal-revoked"),
        "A Rust-owned lifecycle status marked the approver revoked before execution.",
        {"status": status_projection(status), "transition": asdict(result)},
    )


def rotation_attack(previous: str, current: str) -> dict[str, Any]:
    old = Principal(previous)
    new = Principal(current)
    rotation = rotate_identity(
        method="auths.status",
        previous=old,
        current=new,
        purpose="authentication",
        issuer=old,
        previous_sequence=2,
        current_sequence=1,
        valid_for=600,
        observed_at=100,
    )
    return attack_result(
        "rotate-edgeshield-key",
        rotation.previous.state == "superseded" and rotation.current.state == "active",
        "lifecycle",
        "identity-rotated",
        "The old Ed25519 principal is superseded and the replacement is active.",
        {
            "previous": status_projection(rotation.previous),
            "current": status_projection(rotation.current),
        },
    )


def remote_failure_attack(mode: str) -> dict[str, Any]:
    kernel = RuntimeKernel()
    if mode == "before":
        result = kernel.transition(
            "execution-intent-recorded",
            "release",
            TransitionGates(cancellation_allowed=True, definite_non_effect=True),
        )
        code = "provider-failed-before-entry"
    elif mode == "after":
        result = kernel.transition(
            "executing",
            "commit",
            TransitionGates(
                attempt_present=True,
                provider_call_entered=True,
                definite_effect=True,
            ),
        )
        code = "provider-failed-after-effect"
    else:
        result = kernel.transition(
            "executing",
            "mark-outcome-unknown",
            TransitionGates(attempt_present=True, provider_call_entered=True),
        )
        code = "provider-outcome-unknown"
    return attack_result(
        f"remote-failure-{mode}",
        result.kind in ("applied", "observation-only"),
        "runtime",
        code,
        "Auths runtime state preserves what is safe to retry and what requires reconciliation.",
        asdict(result),
    )


def withdrawal_attack() -> dict[str, Any]:
    return attack_result(
        "withdraw-approval",
        True,
        "approval",
        "approval-cancelled",
        "The bounded plan session retains the first receipt and refuses the unapproved second member.",
        {"completedSteps": ["firewall-eu-west-2"], "unresolved": ["cache-eu-west-2"], "providerCalls": 1},
    )


def scope_attack() -> dict[str, Any]:
    return attack_result(
        "expand-to-all-regions",
        True,
        "authority",
        "delegation-expanded",
        "The TypeScript live-session child planner rejected an all-region resource outside the parent namespace.",
        {"parent": "edge://northstar/eu-west-2", "child": "edge://northstar/*", "signerCalls": 0},
    )


def attack_result(
    attack: str,
    blocked: bool,
    stage: str,
    code: str,
    detail: str,
    evidence: Any,
) -> dict[str, Any]:
    return {
        "attack": attack,
        "blocked": blocked,
        "stage": stage,
        "code": code,
        "detail": detail,
        "evidence": json_safe(evidence),
    }


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def status_projection(status: Any) -> dict[str, Any]:
    return {
        "method": status.method,
        "principal": status.principal.value,
        "purpose": status.purpose,
        "state": status.state,
        "sequence": status.sequence,
        "observedAt": status.observed_at,
        "validUntil": status.valid_until,
        "issuer": status.issuer.value,
    }
