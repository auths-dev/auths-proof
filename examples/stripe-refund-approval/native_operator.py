"""Development operator tooling for the refund examples and generated scaffold.

The native gateway authors and reviews every effect. This helper transports
SDK-authored read proofs and external signatures; it decides no gateway verdict.
Simulation is an explicitly finite scripted reviewer. Interactive runs require
consent to each complete native literal review before the exact signature.
Root, read-actor, manager and reviewer keys belong in an operator-private directory.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
from dataclasses import dataclass
import json
import os
import re
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import time
from typing import Optional

from auths.adapters.custody import PublicControlEvidence
from auths.authoring import (GrantEvidence, approval_requests, approve, collect_approvals,
                            open_approval_request, propose_mcp_approval, sign_approval_action)
from auths.self_hosted import (ExactMcpTool, StringField, IntegerField, OptionalField,
                              Permission, Profile, author_root_grant, load_signer_file)

READ_TOOLS = ("auths_gateway_candidate_check_v1", "auths_gateway_recovery_read_v1")
MAX_FRAME = 8 * 1024 * 1024
MAX_REVIEWS = 128
MAX_PROOF_BYTES = 4 * 1024 * 1024
MAX_ACTION_BYTES = 64 * 1024
PEER_TIMEOUT = 5
NATIVE_COMMAND_TIMEOUT = 60
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


class OperatorRefusal(ValueError):
    """A closed local refusal code, safe to return without peer data or paths."""


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OperatorRefusal("operator.duplicate-field")
        result[key] = value
    return result


def reject_constant(_):
    raise OperatorRefusal("operator.invalid-json")


def validate_request(value):
    if not isinstance(value, dict):
        raise OperatorRefusal("operator.invalid-request")
    if value.get("kind") == "approve" and set(value) == {"kind", "proof", "action"}:
        unb64(value["proof"], MAX_PROOF_BYTES)
        unb64(value["action"], MAX_ACTION_BYTES)
        return value
    if value.get("kind") == "recover" and set(value) == {"kind", "source"}:
        if not isinstance(value["source"], str) or TOKEN.fullmatch(value["source"]) is None:
            raise OperatorRefusal("operator.invalid-source")
        return value
    raise OperatorRefusal("operator.invalid-request")


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unb64(value, maximum=MAX_PROOF_BYTES):
    if (not isinstance(value, str) or not 0 < len(value) <= (maximum * 4 + 2) // 3
            or BASE64URL.fullmatch(value) is None):
        raise OperatorRefusal("operator.invalid-base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise OperatorRefusal("operator.invalid-base64url") from None
    if not 0 < len(decoded) <= maximum or b64(decoded) != value:
        raise OperatorRefusal("operator.invalid-base64url")
    return decoded


def write(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(value)


def run(binary, *arguments, check=True):
    try:
        result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                                timeout=NATIVE_COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise OperatorRefusal("operator.native-command-timeout") from None
    except OSError:
        raise OperatorRefusal("operator.native-command-unavailable") from None
    if check and result.returncode:
        raise OperatorRefusal("operator.native-command-refused")
    return result


@dataclass(frozen=True)
class CandidateCheck:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    candidate_connection: str
    expected_previous: Optional[str]
    read_contract: str
    maximum_response_bytes: int


@dataclass(frozen=True)
class RecoveryRead:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    source_effect: str
    source_operation: str
    read_contract: str
    maximum_response_bytes: int


def read_contract(call):
    if call["name"] not in READ_TOOLS:
        raise OperatorRefusal("operator.unlisted-read-tool")
    command_type = CandidateCheck if call["name"] == READ_TOOLS[0] else RecoveryRead
    fields = {key: StringField(min_length=1, max_length=128)
              for key in command_type.__annotations__}
    fields["maximum_response_bytes"] = IntegerField(1, 1048576)
    if command_type is CandidateCheck:
        fields["expected_previous"] = OptionalField(StringField(min_length=64, max_length=64))
    contract = ExactMcpTool(service=call["service"], name=call["name"],
                            command_type=command_type, fields=fields)
    return contract, contract.validate_arguments(call["arguments"])


def signer_file(directory, name, seed):
    path = directory / (name + ".json")
    write(path, json.dumps({"schema": "auths.approval-signer/1", "custody": "development-ed25519",
                           "seed_file": str(Path(seed).resolve())}).encode())
    return path


async def provision(directory, facts, key_paths, gateway, simulation):
    """Called by operator setup before install; grants only the two native read tools."""
    directory.mkdir(mode=0o700, parents=True)
    signers = {name: signer_file(directory, name, seed) for name, seed in key_paths.items()}
    root = load_signer_file(signers["root"]).signer
    reader = load_signer_file(signers["reader"]).signer
    now = int(time.time())
    try:
        grant = await author_root_grant(signer=root, subject=reader.descriptor.principal,
            profile=Profile("auths.mcp", 2),
            permissions=[Permission("tools/call", facts["audience"] + "/tools/" + name)
                         for name in READ_TOOLS], audiences=[facts["audience"]],
            not_before=facts["not_before"], expires_at=facts["expires_at"],
            remaining_depth=0, assurance_floor="raw-key-baseline", requested_at=now)
    finally:
        await root.aclose()
        await reader.aclose()
    write(directory / "read-grant.json", json.dumps({"bytes": b64(grant.signed_grant),
        "evidence": [{"type": item.evidence_type, "media_type": item.media_type,
                      "bytes": b64(item.bytes)} for item in grant.evidence]}).encode())
    seed = secrets.token_bytes(32)
    write(directory / "reviewer.seed", seed)
    from auths import _native
    reviewer = _native.DevelopmentEd25519Key.from_seed(seed)
    policy = run(gateway, "effect-policy", "--partition", "refund-development",
                 "--epoch", "1", "--approver-public-key", bytes(reviewer.public_key).hex()).stdout
    write(directory / "effect-policy.json", policy)
    write(directory / "configuration.json", json.dumps({"gateway": str(Path(gateway).resolve()),
        "facts": facts, "signers": {name: str(path.resolve()) for name, path in signers.items()},
        "simulation": simulation, "maximum_reviews": MAX_REVIEWS}).encode())


def consent(directory, name):
    """Exact bounded response through a private operator FIFO, never application input."""
    fifo = directory / "consent"
    os.mkfifo(fifo, 0o600)
    descriptor = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        print(f"Read the full text {directory / 'literal-review.txt'} and canonical signing request "
              f"{directory / 'signing-request.json'} in your trusted operator shell, "
              f"then write 'approve {name}' followed by a newline to {fifo}", file=sys.stderr, flush=True)
        deadline, response = time.monotonic() + 600, b""
        while time.monotonic() < deadline and len(response) < 256:
            try:
                response += os.read(descriptor, 256 - len(response))
            except BlockingIOError:
                pass
            if b"\n" in response:
                if response != ("approve " + name + "\n").encode():
                    raise OperatorRefusal("operator.review-declined")
                return
            time.sleep(0.05)
        raise OperatorRefusal("operator.review-expired")
    finally:
        os.close(descriptor)
        fifo.unlink(missing_ok=True)


class Operator:
    def __init__(self, directory, state):
        self.directory, self.state = Path(directory), Path(state)
        self.config = json.loads((self.directory / "configuration.json").read_text())
        self.facts = self.config["facts"]
        self.binary = self.config["gateway"]
        from auths import _native
        self.reviewer = _native.DevelopmentEd25519Key.from_seed((self.directory / "reviewer.seed").read_bytes())
        self.sequence = len(list(self.directory.glob("review-*")))

    async def read_packet(self, call):
        contract, command = read_contract(call)
        grant = json.loads((self.directory / "read-grant.json").read_text())
        names = self.facts.get("approvers", self.facts.get("managers"))
        reader = load_signer_file(self.config["signers"]["reader"]).signer
        managers = [load_signer_file(self.config["signers"][name]).signer for name in names]
        try:
            proposal = propose_mcp_approval(contract=contract, command=command,
                required=self.facts["approvals_required"],
                approvers=[self.facts["principals"][name] for name in names],
                actor=reader.descriptor.principal, actor_grant=unb64(grant["bytes"]),
                challenge=bytes.fromhex(self.facts["challenge_hex"]),
                evaluation_time=int(time.time()), validity_seconds=1800)
            responses = []
            for signer in managers[:self.facts["approvals_required"]]:
                request = next(item for item in approval_requests(proposal)
                               if item.approver == signer.descriptor.principal)
                responses.append((await approve(open_approval_request(request.text,
                    now=int(time.time())), signer)).text)
            signed = await sign_approval_action(proposal, reader, grants=[GrantEvidence(
                unb64(grant["bytes"]), tuple(PublicControlEvidence(item["type"],
                item["media_type"], unb64(item["bytes"])) for item in grant["evidence"]))])
            return collect_approvals(proposal, responses).assemble(signed), proposal.action
        finally:
            await reader.aclose()
            for signer in managers:
                await signer.aclose()

    def exact_approval(self, proof, action, *mode):
        self.sequence += 1
        if self.sequence > self.config["maximum_reviews"]:
            raise OperatorRefusal("operator.review-budget-exhausted")
        name = f"review-{self.sequence}"
        directory = self.directory / name
        directory.mkdir(mode=0o700)
        write(directory / "proof", proof)
        write(directory / "action", action)
        now = int(time.time())
        result = run(self.binary, "effect-review", "--state-dir", self.state,
            "--proof", directory / "proof", "--action", directory / "action",
            "--not-before", now - 1, "--expires-at", now + 1800,
            "--request-out", directory / "request", *mode, check=False)
        if result.returncode:
            return None
        review = json.loads(result.stdout)
        if (review.get("schema") != "auths.private-effect-signing/2"
            or review.get("renderer") != "auths.literal-complete-review/1"
            or not isinstance(review.get("literal_review"), str) or not review["literal_review"]):
            raise OperatorRefusal("operator.complete-native-review-required")
        write(directory / "literal-review.json", result.stdout)
        write(directory / "literal-review.txt", review["literal_review"].encode("utf-8"))
        write(directory / "signing-request.json", result.stdout)
        if not self.config["simulation"]:
            consent(directory, name)
        signature = self.reviewer.sign(bytes.fromhex(review["signing_message_hex"]))
        approval = run(self.binary, "effect-approval", "--request", directory / "request",
                       "--signature-hex", bytes(signature).hex()).stdout
        write(directory / "approval", approval)
        return directory

    def publish(self, loopback=None):
        candidate = self.state / "candidate-installation.json"
        call = self.directory / "candidate-call.json"
        run(self.binary, "effect-candidate-call", "--state-dir", self.state,
            "--candidate", candidate, "--operation", "install-check", "--call-out", call)
        proof, action = asyncio.run(self.read_packet(json.loads(call.read_text())))
        approved = self.exact_approval(proof, action, "--candidate", candidate)
        if approved is None:
            raise OperatorRefusal("operator.candidate-review-refused")
        arguments = ["--state-dir", self.state, "--candidate", candidate,
                     "--proof", approved / "proof", "--action", approved / "action",
                     "--approval", approved / "approval"]
        run(self.binary, "candidate-acquire", *arguments,
            *(["--loopback-provider", loopback] if loopback else []))
        run(self.binary, "candidate-publish", *arguments)
        write(self.directory / "adversarial-substitution.approval", (approved / "approval").read_bytes())

    def activate_configuration(self):
        review = run(self.binary, "effect-configuration-review", "--state-dir", self.state).stdout
        write(self.directory / "configuration-review.json", review)
        exact = json.loads(review)
        run(self.binary, "effect-configuration-activate", "--state-dir", self.state,
            "--expected-revision", exact["previous_revision_hex"], "--expected-candidate", exact["candidate_hex"])

    def request(self, request):
        request = validate_request(request)
        if request.get("kind") == "approve" and set(request) == {"kind", "proof", "action"}:
            directory = self.exact_approval(unb64(request["proof"]), unb64(request["action"]))
            if directory is not None:
                return {"approval": b64((directory / "approval").read_bytes()),
                        "literal_review": json.loads((directory / "literal-review.json").read_text())["literal_review"]}
            if self.config["simulation"]:
                # Deliberately mismatched, genuine candidate approval for hostile
                # proof tests. Never manufactures valid authority for their effect.
                return {"approval": b64((self.directory / "adversarial-substitution.approval").read_bytes()),
                        "adversarial_substitution": True}
            raise OperatorRefusal("operator.mutation-review-refused")
        if request.get("kind") == "recover" and set(request) == {"kind", "source"}:
            source = request["source"]
            call = json.loads(run(self.binary, "effect-recovery-call", "--state-dir", self.state,
                "--source-operation", source, "--recovery-operation", f"read-{self.sequence + 1}").stdout)
            proof, action = asyncio.run(self.read_packet(call))
            directory = self.exact_approval(proof, action, "--recovery-of", source)
            if directory is None:
                raise OperatorRefusal("operator.recovery-review-refused")
            return {"proof": b64(proof), "action": b64(action),
                    "approval": b64((directory / "approval").read_bytes())}
        raise OperatorRefusal("operator.invalid-request")


def exact(connection, count, deadline):
    value = b""
    while len(value) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OperatorRefusal("operator.peer-timeout")
        connection.settimeout(remaining)
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise OperatorRefusal("operator.truncated-frame")
        value += chunk
    return value


def receive(connection, timeout=PEER_TIMEOUT):
    deadline = time.monotonic() + timeout
    length = struct.unpack(">I", exact(connection, 4, deadline))[0]
    if not 0 < length <= MAX_FRAME:
        raise OperatorRefusal("operator.frame-bound")
    try:
        value = json.loads(exact(connection, length, deadline).decode("utf-8"),
                           object_pairs_hook=strict_object, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise OperatorRefusal("operator.invalid-json") from None
    if not isinstance(value, dict):
        raise OperatorRefusal("operator.invalid-request")
    return value


def send(connection, value):
    encoded = json.dumps(value, separators=(",", ":")).encode()
    if not 0 < len(encoded) <= MAX_FRAME:
        raise OperatorRefusal("operator.frame-bound")
    connection.sendall(struct.pack(">I", len(encoded)) + encoded)


def request(socket_path, value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(620)
        connection.connect(str(socket_path))
        send(connection, value)
        result = receive(connection, timeout=620)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result


def serve_peer(operator, connection):
    """One bounded exchange; malformed or disconnected peers never kill the listener."""
    accepted = False
    with connection:
        connection.settimeout(PEER_TIMEOUT)
        try:
            request = validate_request(receive(connection))
            accepted = True
            result = operator.request(request)
        except OperatorRefusal as error:
            result = {"error": str(error)}
        except (socket.timeout, TimeoutError):
            result = {"error": "operator.peer-timeout"}
        except OSError:
            result = {"error": "operator.peer-unavailable"}
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            # Native response/signing adapters can also refuse. No diagnostic
            # text, submitted content or private filesystem path crosses back.
            result = {"error": "operator.request-refused"}
        try:
            send(connection, result)
        except (OSError, OperatorRefusal):
            pass  # A disconnected peer has no new authority or retry entitlement.
    return accepted


def serve(operator, socket_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        old = os.umask(0o177)
        try:
            server.bind(str(socket_path))
        finally:
            os.umask(old)
        server.listen(8)
        print("ready", flush=True)
        accepted = 0
        while accepted < MAX_REVIEWS:
            connection, _ = server.accept()
            # Malformed peers do not spend the finite valid-request allowance.
            accepted += int(serve_peer(operator, connection))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup")
    setup.add_argument("--facts", type=Path, required=True)
    setup.add_argument("--key-directory", type=Path, required=True)
    setup.add_argument("--gateway", required=True)
    setup.add_argument("--simulation", action="store_true")
    publish = commands.add_parser("publish")
    publish.add_argument("--state", type=Path, required=True)
    publish.add_argument("--loopback-provider")
    activate = commands.add_parser("activate-configuration")
    activate.add_argument("--state", type=Path, required=True)
    listener = commands.add_parser("serve")
    listener.add_argument("--state", type=Path, required=True)
    listener.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "setup":
        facts = json.loads(args.facts.read_text())
        names = ["root", "reader", *facts.get("approvers", facts.get("managers"))]
        asyncio.run(provision(args.directory, facts,
            {name: args.key_directory / (name + ".seed") for name in names}, args.gateway, args.simulation))
    elif args.command == "publish":
        Operator(args.directory, args.state).publish(args.loopback_provider)
    elif args.command == "activate-configuration":
        Operator(args.directory, args.state).activate_configuration()
    else:
        serve(Operator(args.directory, args.state), args.socket)


if __name__ == "__main__":
    main()
