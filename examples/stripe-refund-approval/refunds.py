"""Stripe refunds an AI agent may request only with two of three manager
approvals and inside a per-agent limit, submitted through the Auths gateway.

Commands, in the order the README runs them:

    python refunds.py setup   --state DIR --gateway auths-gateway
    python refunds.py refund  --state DIR --socket SOCK --operation-id ID \\
                              --payment-intent PI --amount CENTS --approvers a,b
    python refunds.py export  --state DIR --out audit-bundle.json

Everything here uses development keys stored under ``DIR/keys`` so one person
can play every role. In production the root and each manager sign through
their own custody adapters, and the agent never holds the managers' keys.
The Stripe secret key never enters this program: only the gateway holds it.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import (
    AuthoringUnsuccessful,
    GrantEvidence,
    QuorumApprover,
    author_mcp_quorum_proof,
)
from auths.gateway import GatewayClient, GatewayEndpoint, GatewaySignedObservation

from generated import CONTRACT, CreateRefund

HERE = Path(__file__).resolve().parent
RECIPE = HERE / "recipe.json"
PROFILE_LOCK = HERE / "profile.lock.json"
MANAGERS = ("manager-a", "manager-b", "manager-c")
ROLES = ("root", "agent") + MANAGERS
ASSURANCE = "raw-key-baseline"
DAY = 86_400


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _gateway_json(gateway: str, *arguments: str) -> Dict[str, Any]:
    output = subprocess.run([gateway, *arguments], check=True, capture_output=True, text=True)
    return json.loads(output.stdout)


class DevelopmentSigner:
    """A custody signer over a development key. Managers see the review
    display before signing; a production signer shows it on their device."""

    def __init__(self, name: str, seed: bytes) -> None:
        self.name = name
        self.key = _native.DevelopmentEd25519Key.from_seed(seed)
        self.evidence = PublicControlEvidence(
            self.key.evidence_type, self.key.media_type, self.key.evidence
        )
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "example.development-key",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite
            ),
            "development-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        shown = ", ".join(f"{field.label}={field.value}" for field in request.display)
        print(f"  {self.name} signs: {shown[:200]}", file=sys.stderr)
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.descriptor.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                self.key.sign(request.signing_preimage),
                (self.evidence,),
            ),
        )

    async def aclose(self) -> None:
        return None


def _signer(state: Path, name: str) -> DevelopmentSigner:
    return DevelopmentSigner(name, (state / "keys" / f"{name}.seed").read_bytes())


def _trusted_context(
    configuration: bytes,
    anchors: List[Any],
    audience: str,
    challenge: bytes,
    now: int,
    required: int,
    extension: str,
) -> bytes:
    """``required`` authorized approvals from as many distinct actors and
    distinct roots, under the anchors given."""
    assurance = _native.AssurancePolicy(
        ASSURANCE,
        [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ],
    )
    template = _native.compile_trusted_context(
        configuration,
        None,
        required,
        required,
        required,
        anchors,
        assurance,
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        [extension],
    )
    return bytes(_native.inspect_trusted_context(template.bind_request(audience, challenge, now)))


def setup(args: argparse.Namespace) -> None:
    state: Path = args.state
    if (state / "setup.json").exists():
        raise SystemExit(f"{state} is already set up; use a fresh directory")
    review = _gateway_json(
        args.gateway, "review", "--recipe", str(RECIPE), "--profile-lock", str(PROFILE_LOCK)
    )
    bound = _gateway_json(
        args.gateway,
        "bound-extension",
        "--argument",
        "amount",
        "--ceiling",
        str(args.ceiling),
        "--window-seconds",
        str(args.window_seconds),
        "--max-count",
        str(args.max_count),
    )
    for name in ROLES:
        _private_write(state / "keys" / f"{name}.seed", os.urandom(32))
    signers = {name: _signer(state, name) for name in ROLES}
    principals = {name: signer.key.principal for name, signer in signers.items()}

    now = int(time.time())
    not_before, expires_at = now - 300, now + args.days * DAY
    service, tool = review["service"], review["tool"]
    audience = f"mcp://{service}"
    permission = ("tools/call", f"{audience}/tools/{tool}")
    challenge = bytes(_native.generate_challenge_v1())

    def anchor(name: str, depth: int) -> Any:
        return _native.TrustAnchor(
            name,
            _native.Principal(principals[name]),
            ["raw-key-v1"],
            [("auths.mcp", 2)],
            [permission],
            [audience],
            [audience],
            not_before,
            expires_at,
            None,
            depth,
            ASSURANCE,
            None,
        )

    # The root may delegate once (to the agent); managers approve directly.
    anchors = [anchor("root", 1)] + [anchor(name, 0) for name in MANAGERS]
    extension = bound["extension_id"]
    gateway_context = _trusted_context(
        bytes.fromhex(review["verifier_configuration"]),
        anchors,
        audience,
        challenge,
        now,
        3,
        extension,
    )
    sdk_context = _trusted_context(
        bytes(_native.self_contained_configuration()),
        anchors,
        audience,
        challenge,
        now,
        3,
        extension,
    )

    root = signers["root"].key
    grant_request = _native.GrantRequest(
        _native.Principal(principals["agent"]),
        "auths.mcp",
        2,
        [permission],
        not_before,
        expires_at,
        [audience],
        None,
        None,
        0,
        None,
        ASSURANCE,
        [(extension, bytes.fromhex(bound["extension_body_hex"]))],
    )
    signing = _native.prepare_signing(
        _native.root_grant(_native.Principal(principals["root"]), grant_request),
        root.principal_method,
        root.verification_method,
        root.suite,
    )
    grant = signing.complete(root.sign(signing.signing_preimage))

    _private_write(state / "trust" / "gateway.context.cbor", gateway_context)
    _private_write(state / "trust" / "sdk.context.cbor", sdk_context)
    _private_write(state / "agent.grant.cbor", bytes(_native.inspect_signed(grant)))
    summary = {
        "recipe_digest": review["recipe_digest"],
        "operator_namespace": review["operator_namespace"],
        "audience": audience,
        "challenge_hex": challenge.hex(),
        "trusted_context_sha256": hashlib.sha256(gateway_context).hexdigest(),
        "principals": principals,
        "bound": {
            key: bound[key] for key in ("argument", "ceiling", "window_seconds", "max_count")
        },
    }
    _private_write(state / "setup.json", json.dumps(summary, indent=2).encode())
    print(json.dumps(summary, indent=2))


async def _refund(args: argparse.Namespace) -> Dict[str, Any]:
    state: Path = args.state
    setup_facts = json.loads((state / "setup.json").read_text())
    managers = [name for name in args.approvers.split(",") if name]
    if not set(managers) <= set(MANAGERS) or len(set(managers)) != len(managers):
        raise SystemExit(f"approvers must be distinct names from {', '.join(MANAGERS)}")
    command = CreateRefund(
        operator_namespace="stripe-refunds",
        operation_id=args.operation_id,
        recipe_digest=setup_facts["recipe_digest"],
        payment_intent=args.payment_intent,
        amount=args.amount,
    )
    root = _signer(state, "root")
    agent = QuorumApprover(
        _signer(state, "agent"),
        (GrantEvidence((state / "agent.grant.cbor").read_bytes(), (root.evidence,)),),
    )
    approvers = [agent] + [QuorumApprover(_signer(state, name)) for name in managers]
    local_trust = args.local_trust or state / "trust" / "sdk.context.cbor"
    now = int(time.time())
    record: Dict[str, Any] = {"operation_id": args.operation_id, "amount": args.amount}
    try:
        # The agent and every listed manager sign the same exact refund.
        authored = await author_mcp_quorum_proof(
            contract=CONTRACT,
            command=command,
            required=len(approvers),
            approvers=approvers,
            trusted_context_template=local_trust.read_bytes(),
            challenge=bytes.fromhex(setup_facts["challenge_hex"]),
            evaluation_time=now,
            expires_at=now + 900,
        )
    except AuthoringUnsuccessful as refused:
        record.update(stage="authoring", outcome="refused-locally", code=refused.code)
        return record
    gateway = GatewayClient(GatewayEndpoint(args.socket.resolve()))
    result = await gateway.submit(proof=authored.proof, action=authored.action)
    record.update(dataclasses.asdict(result))
    observation = await gateway.observe_outcome(args.operation_id)
    outcome = observation.observation if isinstance(observation, GatewaySignedObservation) else None
    entry = {
        "operation_id": args.operation_id,
        "proof_b64": _b64(authored.proof),
        "action_b64": _b64(authored.action),
        "outcome_b64": _b64(outcome) if outcome is not None else None,
    }
    log = state / "audit" / "entries.jsonl"
    log.parent.mkdir(mode=0o700, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return record


def export(args: argparse.Namespace) -> None:
    state: Path = args.state
    log = state / "audit" / "entries.jsonl"
    entries = [json.loads(line) for line in log.read_text().splitlines() if line]
    bundle = {
        "schema": "auths.gateway-audit-bundle/1",
        "recipe_b64": _b64(RECIPE.read_bytes()),
        "profile_lock_b64": _b64(PROFILE_LOCK.read_bytes()),
        "trusted_context_b64": _b64((state / "trust" / "gateway.context.cbor").read_bytes()),
        "entries": entries,
    }
    args.out.write_text(json.dumps(bundle, indent=1) + "\n")
    print(f"wrote {args.out} with {len(entries)} submissions")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="refunds.py")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("setup", help="create principals, trust, and the agent grant")
    prepare.add_argument("--state", type=Path, required=True)
    prepare.add_argument("--gateway", default="auths-gateway")
    prepare.add_argument("--ceiling", type=int, default=5_000, help="largest refund, in cents")
    prepare.add_argument("--max-count", type=int, default=2, help="refunds per agent per window")
    prepare.add_argument("--window-seconds", type=int, default=DAY)
    prepare.add_argument("--days", type=int, default=30, help="trust and grant validity")
    refund = commands.add_parser("refund", help="author, approve, and submit one refund")
    refund.add_argument("--state", type=Path, required=True)
    refund.add_argument("--socket", type=Path, required=True)
    refund.add_argument("--operation-id", required=True)
    refund.add_argument("--payment-intent", required=True)
    refund.add_argument("--amount", type=int, required=True, help="cents")
    refund.add_argument("--approvers", required=True, help="comma-separated manager names")
    refund.add_argument(
        "--local-trust",
        type=Path,
        help="the agent's own pre-submit check; the gateway's installed trust decides",
    )
    bundle = commands.add_parser("export", help="write the audit bundle")
    bundle.add_argument("--state", type=Path, required=True)
    bundle.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "setup":
        setup(args)
    elif args.command == "refund":
        print(json.dumps(asyncio.run(_refund(args))))
    else:
        export(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
