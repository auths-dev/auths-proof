"""Stripe refunds an AI agent may request only with two of three manager
approvals and inside a per-agent limit, submitted through the Auths gateway.

Commands, in the order the README runs them:

    python refunds.py setup   --state DIR --gateway auths-gateway
    python refunds.py request --state DIR --operation-id ID --payment-intent PI \\
                              --amount CENTS --approvers a,b --out REQUESTS \\
                              [--currency usd] [--connect-account acct_...] [--precheck]
    auths approve REQUESTS/manager-a.request \\
                              --signer DIR/signers/manager-a.json --out REQUESTS/manager-a.response
    python refunds.py submit  --state DIR --socket SOCK --operation-id ID --responses REQUESTS
    python refunds.py export  --state DIR --out audit-bundle.json

``submit`` sends every assembled proof to the gateway: only the gateway
decides the approval threshold, the ceiling, the per-window count, and
whether an operation ID may run again. ``request --precheck`` is an opt-in,
client-side pre-check and not an enforcement boundary. Every outcome record
says who decided it in ``decided_by``: ``gateway``, ``approver``, or
``client``.

``python refunds.py grant --state DIR --agent NAME --max-count N`` issues one
more agent its own grant with the same limits and another count; the journey
uses it for the refusals that consume a count slot.

The agent writes one approval request per manager; each manager answers with
``auths approve`` on their own machine, and the agent collects the
response files. Everything here uses development keys stored under
``DIR/keys`` so one person can play every role; they are development custody.
In production the root and each manager sign through their own custody
adapters, and the agent never holds the managers' keys. The Stripe secret key
never enters this program: only the gateway holds it.
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
    ApprovalMember,
    ApprovalProposal,
    GrantEvidence,
    approval_requests,
    approve,
    collect_approvals,
    open_approval_request,
    propose_mcp_approval,
)
from auths.gateway import GatewayClient, GatewayEndpoint, GatewaySignedObservation

from generated import CONTRACT, CreateRefund

HERE = Path(__file__).resolve().parent
RECIPE = HERE / "recipe.json"
PROFILE_LOCK = HERE / "profile.lock.json"
MANAGERS = ("manager-a", "manager-b", "manager-c")
# The gateway's trusted context requires this many authorized approvals from
# as many distinct actors and roots: the agent and two managers.
APPROVALS_REQUIRED = 3
ROLES = ("root", "agent") + MANAGERS
ASSURANCE = "raw-key-baseline"
DAY = 86_400
# The test connected account the grant's scope lists; the gateway sends it as
# `Stripe-Account` on the refund and on every read of the refund's records.
CONNECT_ACCOUNT = "acct_1AuthsConnected"
# The recipe declares a derived Idempotency-Key with 86 400 seconds of
# provider retention. The gateway refuses an action whose approval window plus
# its 60-second entry deadline exceeds that retention, so every entry of one
# approved refund falls within one retention period of the first.
APPROVAL_WINDOW = DAY - 60


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


def _principals(state: Path) -> Dict[str, str]:
    """Every principal by name: the roles setup created and each agent
    ``grant`` added."""
    facts = json.loads((state / "setup.json").read_text())
    principals: Dict[str, str] = dict(facts["principals"])
    for path in sorted((state / "agents").glob("*.json")):
        principals[path.stem] = json.loads(path.read_text())["principal"]
    return principals


def _bound(gateway: str, bound: Dict[str, Any], max_count: int) -> Dict[str, Any]:
    """The grant extension for ``bound`` with ``max_count`` refunds per
    window, as the gateway's registered evaluator enforces it."""
    return _gateway_json(
        gateway,
        "bound-extension",
        "--argument",
        "amount",
        "--ceiling",
        str(bound["ceiling"]),
        "--window-seconds",
        str(bound["window_seconds"]),
        "--max-count",
        str(max_count),
        "--sum-limit",
        str(bound["sum_limit"]),
        "--partition",
        "currency=" + ",".join(bound["currencies"]),
        "--scope",
        "connect_account=" + bound["connect_account"],
    )


def _root_grant(
    state: Path, facts: Dict[str, Any], subject: str, extension: Dict[str, Any]
) -> bytes:
    """A grant from the root to ``subject`` carrying ``extension``, valid for
    the trust's lifetime."""
    root = _signer(state, "root").key
    audience = facts["audience"]
    grant_request = _native.GrantRequest(
        _native.Principal(subject),
        "auths.mcp",
        2,
        [("tools/call", f"{audience}/tools/{facts['tool']}")],
        facts["not_before"],
        facts["expires_at"],
        [audience],
        None,
        None,
        0,
        None,
        ASSURANCE,
        [(extension["extension_id"], bytes.fromhex(extension["extension_body_hex"]))],
    )
    signing = _native.prepare_signing(
        _native.root_grant(_native.Principal(facts["principals"]["root"]), grant_request),
        root.principal_method,
        root.verification_method,
        root.suite,
    )
    return bytes(_native.inspect_signed(signing.complete(root.sign(signing.signing_preimage))))


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
    limits = {
        "ceiling": args.ceiling,
        "window_seconds": args.window_seconds,
        "sum_limit": args.sum_limit,
        "currencies": sorted(set(args.currencies.split(","))),
        "connect_account": args.connect_account,
    }
    bound = _bound(args.gateway, limits, args.max_count)
    for name in ROLES:
        _private_write(state / "keys" / f"{name}.seed", os.urandom(32))
    # What each manager passes to `auths approve --signer`.
    for name in MANAGERS:
        signer = {
            "schema": "auths.approval-signer/1",
            "custody": "development-ed25519",
            "seed_file": f"../keys/{name}.seed",
        }
        _private_write(state / "signers" / f"{name}.json", json.dumps(signer, indent=2).encode())
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
        APPROVALS_REQUIRED,
        extension,
    )
    sdk_context = _trusted_context(
        bytes(_native.self_contained_configuration()),
        anchors,
        audience,
        challenge,
        now,
        APPROVALS_REQUIRED,
        extension,
    )

    facts = {
        "audience": audience,
        "tool": tool,
        "not_before": not_before,
        "expires_at": expires_at,
        "principals": principals,
    }
    agent_grant = _root_grant(state, facts, principals["agent"], bound)

    _private_write(state / "trust" / "gateway.context.cbor", gateway_context)
    _private_write(state / "trust" / "sdk.context.cbor", sdk_context)
    _private_write(state / "agent.grant.cbor", agent_grant)
    summary = {
        "recipe_digest": review["recipe_digest"],
        "operator_namespace": review["operator_namespace"],
        "audience": audience,
        "tool": tool,
        "not_before": not_before,
        "expires_at": expires_at,
        "challenge_hex": challenge.hex(),
        "trusted_context_sha256": hashlib.sha256(gateway_context).hexdigest(),
        "principals": principals,
        "approvals_required": APPROVALS_REQUIRED,
        "connect_account": args.connect_account,
        "limits": limits,
        "bound": {
            key: bound[key]
            for key in (
                "argument",
                "ceiling",
                "window_seconds",
                "max_count",
                "sum_limit",
                "partition",
                "scope",
            )
        },
    }
    _private_write(state / "setup.json", json.dumps(summary, indent=2).encode())
    print(json.dumps(summary, indent=2))


def grant(args: argparse.Namespace) -> None:
    """Issues one more agent its own grant: the setup's limits with
    ``--max-count`` refunds per window, counted apart from every other
    agent's."""
    state: Path = args.state
    facts = json.loads((state / "setup.json").read_text())
    name: str = args.agent
    if name in facts["principals"] or (state / "agents" / f"{name}.json").exists():
        raise SystemExit(f"{name} already exists")
    bound = _bound(args.gateway, facts["limits"], args.max_count)
    _private_write(state / "keys" / f"{name}.seed", os.urandom(32))
    principal = _signer(state, name).key.principal
    _private_write(state / f"{name}.grant.cbor", _root_grant(state, facts, principal, bound))
    record = {"principal": principal, "max_count": bound["max_count"]}
    _private_write(state / "agents" / f"{name}.json", json.dumps(record).encode())
    print(json.dumps({"agent": name, **record}))


def _proposal(state: Path, operation: str) -> ApprovalProposal[CreateRefund]:
    """Rebuilds the agent's proposal for ``operation`` from its saved inputs;
    the same inputs always give the same envelopes and requests."""
    facts = json.loads((state / "setup.json").read_text())
    principals = _principals(state)
    pending = json.loads((state / "pending" / f"{operation}.json").read_text())
    managers = pending["managers"]
    requester = principals[pending["agent"]]
    agent = ApprovalMember(requester, (state / f"{pending['agent']}.grant.cbor").read_bytes())
    return propose_mcp_approval(
        contract=CONTRACT,
        command=CreateRefund(
            operator_namespace="stripe-refunds",
            operation_id=operation,
            recipe_digest=facts["recipe_digest"],
            payment_intent=pending["payment_intent"],
            amount=pending["amount"],
            connect_account=pending["connect_account"],
            currency=pending["currency"],
        ),
        # The agent and every listed manager approve the same exact refund.
        required=1 + len(managers),
        approvers=[agent] + [ApprovalMember(principals[name]) for name in managers],
        requester=requester,
        challenge=bytes.fromhex(facts["challenge_hex"]),
        evaluation_time=pending["evaluation_time"],
        validity_seconds=APPROVAL_WINDOW,
    )


def _agent_grants(state: Path, agent: str) -> tuple[GrantEvidence, ...]:
    root = _signer(state, "root")
    return (GrantEvidence((state / f"{agent}.grant.cbor").read_bytes(), (root.evidence,)),)


PRECHECK_NOTE = (
    "client-side pre-check; not an enforcement boundary. "
    "The gateway enforces this rule whether or not the pre-check runs."
)


def _precheck(facts: Dict[str, Any], listed: List[str], amount: int) -> Optional[str]:
    """The rule a request breaks by what ``setup.json`` states, if any. It
    checks no signature, window count, or operation ID: only the gateway
    decides those."""
    if len(set(listed)) != len(listed):
        return "repeated-approver"
    if 1 + len(set(listed)) < facts["approvals_required"]:
        return "approvals-below-threshold"
    if amount > facts["bound"]["ceiling"]:
        return "above-ceiling"
    return None


def _write_pending(state: Path, operation: str, data: bytes) -> None:
    """Writes the request's inputs. An earlier request for the same operation
    ID is kept under the first free ``<id>.json.N``: whether the ID may run
    again is the gateway's decision, not this program's."""
    path = state / "pending" / f"{operation}.json"
    if path.exists():
        number = 1
        while path.with_name(f"{path.name}.{number}").exists():
            number += 1
        path.rename(path.with_name(f"{path.name}.{number}"))
        print(
            f"{operation} was requested before; the earlier request is kept as "
            f"{path.name}.{number}. The gateway's attempt store decides whether "
            "this operation ID may run again.",
            file=sys.stderr,
        )
    _private_write(path, data)


async def _request(args: argparse.Namespace) -> Dict[str, Any]:
    state: Path = args.state
    facts = json.loads((state / "setup.json").read_text())
    principals = _principals(state)
    listed = [name for name in args.approvers.split(",") if name]
    unknown = sorted(set(listed) - set(MANAGERS))
    if unknown:
        raise SystemExit(f"approvers must be names from {', '.join(MANAGERS)}; got {', '.join(unknown)}")
    if args.agent in MANAGERS or args.agent == "root" or args.agent not in principals:
        raise SystemExit(f"{args.agent} is not an agent of {state}")
    if args.precheck:
        rule = _precheck(facts, listed, args.amount)
        if rule is not None:
            return {
                "operation_id": args.operation_id,
                "outcome": "not-submitted",
                "decided_by": "client",
                "reason": "precheck",
                "precheck": rule,
                "note": PRECHECK_NOTE,
            }
    managers: List[str] = []
    for name in listed:
        if name in managers:
            print(
                f"dropped the repeated approver {name}: a proposal cannot name one "
                "approver twice; the gateway decides the threshold for the approvers "
                "that remain",
                file=sys.stderr,
            )
            continue
        managers.append(name)
    pending = {
        "agent": args.agent,
        "managers": managers,
        "payment_intent": args.payment_intent,
        "amount": args.amount,
        "currency": args.currency,
        "connect_account": args.connect_account or facts["connect_account"],
        "evaluation_time": int(time.time()),
    }
    _write_pending(state, args.operation_id, json.dumps(pending).encode())
    proposal = _proposal(state, args.operation_id)
    names = {principal: name for name, principal in principals.items()}
    out: Path = args.out
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    written: Dict[str, str] = {}
    for request in approval_requests(proposal):
        name = names[request.approver]
        if name == args.agent:
            # The agent approves its own request like any other approver.
            reviewed = open_approval_request(request.data)
            response = await approve(
                reviewed, _signer(state, name), grants=_agent_grants(state, name)
            )
            (out / "agent.response").write_text(response.text + "\n")
            continue
        path = out / f"{name}.request"
        path.write_text(request.text + "\n")
        written[name] = str(path)
    return {
        "operation_id": args.operation_id,
        "requests": written,
        "action_b64": _b64(proposal.action),
    }


def _record_entry(audit: Path, entry: Dict[str, Any]) -> str:
    """Keeps at most one bundle entry per operation ID: the first submission,
    or a later one that the gateway recorded in place of one it did not."""
    log = audit / "entries.jsonl"
    entries = (
        [json.loads(line) for line in log.read_text().splitlines() if line] if log.exists() else []
    )
    for index, existing in enumerate(entries):
        if existing["operation_id"] != entry["operation_id"]:
            continue
        if existing["outcome_b64"] is None and entry["outcome_b64"] is not None:
            entries[index] = entry
            replacement = log.with_name(log.name + ".new")
            replacement.write_text(
                "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in entries),
                encoding="utf-8",
            )
            replacement.replace(log)
            return "replaced"
        return "unchanged"
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return "appended"


async def _submit(args: argparse.Namespace) -> Dict[str, Any]:
    state: Path = args.state
    names = {principal: name for name, principal in _principals(state).items()}
    proposal = _proposal(state, args.operation_id)
    responses = sorted(args.responses.glob("*.response"))
    texts = [path.read_text().strip() for path in responses]
    record: Dict[str, Any] = {"operation_id": args.operation_id, "amount": proposal.command.amount}
    audit = state / "audit"
    audit.mkdir(mode=0o700, exist_ok=True)
    with (audit / "approvals.jsonl").open("a", encoding="utf-8") as handle:
        for text in texts:
            line = {"operation_id": args.operation_id, "response": text}
            handle.write(json.dumps(line, separators=(",", ":")) + "\n")
    collection = collect_approvals(proposal, texts)
    statuses = {names.get(item.approver, item.approver): item for item in collection.statuses}
    declined = sorted(name for name, item in statuses.items() if item.status == "declined")
    if declined:
        record.update(
            outcome="not-submitted",
            decided_by="approver",
            reason="approver-declined",
            declined=declined,
        )
        return record
    waiting = {
        name: item.code or item.status
        for name, item in statuses.items()
        if item.status != "approved"
    }
    if waiting:
        # No proof exists until every listed approver approved this exact
        # request, so nothing can be sent; this is not a policy refusal.
        record.update(
            outcome="not-submitted",
            decided_by="client",
            reason="approvals-incomplete",
            waiting=waiting,
            unattributed=[[index, code] for index, code in collection.unattributed],
        )
        return record
    # Every assembled proof goes to the gateway. Collection checks every
    # envelope byte for byte; only the gateway decides the threshold, the
    # ceiling, the count, and whether the operation ID may run.
    proof = collection.assemble()
    gateway = GatewayClient(GatewayEndpoint(args.socket.resolve()))
    result = await gateway.submit(proof=proof, action=proposal.action)
    record.update(dataclasses.asdict(result))
    record["decided_by"] = "gateway"
    observation = await gateway.observe_outcome(args.operation_id)
    outcome = observation.observation if isinstance(observation, GatewaySignedObservation) else None
    entry = {
        "operation_id": args.operation_id,
        "proof_b64": _b64(proof),
        "action_b64": _b64(proposal.action),
        "outcome_b64": _b64(outcome) if outcome is not None else None,
    }
    record["bundle"] = _record_entry(audit, entry)
    return record


def export(args: argparse.Namespace) -> None:
    state: Path = args.state
    log = state / "audit" / "entries.jsonl"
    entries = [json.loads(line) for line in log.read_text().splitlines() if line]
    approvals = state / "audit" / "approvals.jsonl"
    responses = [
        json.loads(line) for line in approvals.read_text().splitlines() if line
    ] if approvals.exists() else []
    bundle = {
        "schema": "auths.gateway-audit-bundle/2",
        "recipe_b64": _b64(RECIPE.read_bytes()),
        "profile_lock_b64": _b64(PROFILE_LOCK.read_bytes()),
        "trusted_context_b64": _b64((state / "trust" / "gateway.context.cbor").read_bytes()),
        "entries": entries,
        "approval_responses": responses,
    }
    args.out.write_text(json.dumps(bundle, indent=1) + "\n")
    print(f"wrote {args.out} with {len(entries)} submissions and {len(responses)} approval responses")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="refunds.py")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("setup", help="create principals, trust, and the agent grant")
    prepare.add_argument("--state", type=Path, required=True)
    prepare.add_argument("--gateway", default="auths-gateway")
    prepare.add_argument("--ceiling", type=int, default=5_000, help="largest refund, in cents")
    prepare.add_argument("--max-count", type=int, default=2, help="refunds per agent per window")
    prepare.add_argument("--window-seconds", type=int, default=DAY)
    prepare.add_argument(
        "--sum-limit", type=int, default=6_000, help="refund sum per currency per window, in cents"
    )
    prepare.add_argument("--currencies", default="eur,usd", help="comma-separated currencies")
    prepare.add_argument("--connect-account", default=CONNECT_ACCOUNT, help="the account in scope")
    prepare.add_argument("--days", type=int, default=30, help="trust and grant validity")
    another = commands.add_parser("grant", help="issue one more agent its own grant")
    another.add_argument("--state", type=Path, required=True)
    another.add_argument("--gateway", default="auths-gateway")
    another.add_argument("--agent", required=True)
    another.add_argument("--max-count", type=int, required=True, help="refunds per window")
    request = commands.add_parser("request", help="write one approval request per manager")
    request.add_argument("--state", type=Path, required=True)
    request.add_argument("--operation-id", required=True)
    request.add_argument("--payment-intent", required=True)
    request.add_argument("--amount", type=int, required=True, help="cents")
    request.add_argument("--approvers", required=True, help="comma-separated manager names")
    request.add_argument("--currency", default="usd")
    request.add_argument("--connect-account", help="defaults to the account in the grant's scope")
    request.add_argument("--agent", default="agent", help="the requesting agent")
    request.add_argument("--out", type=Path, required=True, help="directory for requests and responses")
    request.add_argument(
        "--precheck",
        action="store_true",
        help="client-side pre-check, not an enforcement boundary: refuse before writing any "
        "request when the approvers are fewer than the threshold, one repeats, or the amount "
        "is above the ceiling that setup.json records. The gateway enforces these rules "
        "whether or not the pre-check runs.",
    )
    submit = commands.add_parser("submit", help="collect the responses and submit through the gateway")
    submit.add_argument("--state", type=Path, required=True)
    submit.add_argument("--socket", type=Path, required=True)
    submit.add_argument("--operation-id", required=True)
    submit.add_argument("--responses", type=Path, required=True, help="directory of *.response files")
    bundle = commands.add_parser("export", help="write the audit bundle")
    bundle.add_argument("--state", type=Path, required=True)
    bundle.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "setup":
        setup(args)
    elif args.command == "grant":
        grant(args)
    elif args.command == "request":
        print(json.dumps(asyncio.run(_request(args))))
    elif args.command == "submit":
        print(json.dumps(asyncio.run(_submit(args))))
    else:
        export(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
