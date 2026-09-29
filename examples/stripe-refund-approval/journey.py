"""Run the whole README journey unattended and check every claim it makes.

    python journey.py --gateway PATH/TO/auths-gateway [--summary out.json]

By default the gateway sends every request to ``mock_stripe.py``, a counting
Stripe double on 127.0.0.1; that needs a gateway built with
``--features loopback-provider``. With ``--stripe-test-mode`` the same
journey calls Stripe's test mode instead, using the developer's own
restricted key ``STRIPE_TEST_RESTRICTED_KEY`` (``rk_test_`` only), their
platform and connected account IDs, a refundable ``--payment-intent`` of at
least 30.00 USD in the connected account, and a ``--rejected-payment-intent``
of at least 80.00 USD whose charge is already fully refunded. The key is
piped to the gateway install and nowhere else.

Refund 1 is read back: the gateway finds its echo token in the refund's
metadata and records ``observed-by-provider``. Refund 4 names a
PaymentIntent whose charge is already refunded, so the provider rejects it
with 400 after the gateway entered it. The offline audit reports it
``verified`` (authorized and entered) with its ``http_status`` of 400 beside
the verdict, and it still consumes the agent's second refund of the window.

Each of the recipe's provider checks refuses one hostile refund with zero
writes: a key without the declared test prefix at install; a
``connect_account`` the grant does not list, and a refund above the
currency's remaining sum, both before any credential lease; and, after the
lease, a refund above half of ``/amount_received``, a currency the
PaymentIntent does not have, the double reporting another account, and the
double answering a denied read with 200. The four refusals after the lease
consume a count slot each, so a second agent with its own grant makes them.

Every refund is submitted through ``gateway_witness.py``, a relay on the
application socket that runs as its own process and records each exchange.
A hostile case passes only if it was decided by the gateway: the command's
record says ``decided_by: "gateway"`` with the expected outcome and code, and
the witness saw exactly one submit frame during the case, whose response
carries the same. A negative control refused by ``request --precheck`` must
fail that guard.

Against the double it also checks the ``Idempotency-Key`` the gateway derives
for each refund, then restores the gateway's store from a backup taken
before the first refund, which forgets every claim but keeps the shared
connection record, and resubmits an approved refund: the double, like
Stripe, must return the first refund rather than create a second.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
PYTHON = sys.executable
# The double's accounts and its already-refunded PaymentIntent.
PLATFORM_ACCOUNT = "acct_1AuthsPlatform0"
CONNECTED_ACCOUNT = "acct_1AuthsConnected"
OTHER_ACCOUNT = "acct_1AuthsOtherAcct"
REFUNDED_PAYMENT_INTENT = "pi_mock_refunded"
STRIPE_VERSION = "2025-03-31.basil"
# The second agent, whose refunds the checks after the credential lease refuse.
CHECKS_AGENT = "agent-checks"
# A clearly fake key without the recipe's `rk_test_` prefix.
NON_TEST_KEY = "rk_live_not-a-real-key"
KEY_VARIABLES = ("STRIPE_TEST_RESTRICTED_KEY", "STRIPE_TEST_SECRET_KEY")
# The packaged approval CLI installed beside this interpreter with the wheel.
APPROVE_CLI = str(Path(sys.executable).parent / "auths")
IDEMPOTENCY_DOMAIN = b"auths.gateway-idempotency-key/1\0"


def idempotency_key(namespace: str, operation: str) -> str:
    """The ``Idempotency-Key`` the gateway derives for one logical operation."""
    preimage = IDEMPOTENCY_DOMAIN + namespace.encode() + b"\0" + operation.encode()
    return "auths-i1-" + hashlib.sha256(preimage).hexdigest()


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Journey:
    def __init__(self, gateway: str, workdir: Path) -> None:
        self.gateway = gateway
        self.work = workdir
        self.state = workdir / "state"
        self.gateway_state = workdir / "gateway"
        self.socket = workdir / "app.sock"
        # Every submission goes through the witness, which relays it to the
        # gateway and records the exchange from its own process.
        self.witness_socket = workdir / "witness.sock"
        self.witness_log = workdir / "witness.jsonl"
        self.ledger = workdir / "ledger.jsonl"
        self.control = workdir / "control.json"
        self.processes: List[subprocess.Popen[str]] = []
        # No child process inherits a Stripe key; the install reads it on stdin.
        self.env = {key: value for key, value in os.environ.items() if key not in KEY_VARIABLES}
        self.steps: List[Dict[str, Any]] = []
        self.started = time.monotonic()
        self.last_warnings = ""

    def step(self, name: str, action: Callable[[], Any]) -> Any:
        begun = time.monotonic()
        result = action()
        self.steps.append({"step": name, "seconds": round(time.monotonic() - begun, 3)})
        print(f"[{len(self.steps):2}] {name} ({self.steps[-1]['seconds']}s)", file=sys.stderr)
        return result

    def run(
        self, *command: str, stdin: Optional[str] = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command, input=stdin, capture_output=True, text=True, cwd=HERE, env=self.env
        )
        if check and result.returncode != 0:
            raise SystemExit(f"{' '.join(command[:3])} failed: {result.stderr.strip()}")
        return result

    def background(self, *command: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=HERE,
            env=self.env,
        )
        self.processes.append(process)
        return process

    def terminate(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self.processes.remove(process)

    def stop(self) -> None:
        for process in list(self.processes):
            self.terminate(process)

    def provider_entries(self) -> List[Dict[str, Any]]:
        if not self.ledger.exists():
            return []
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line]

    def witness_lines(self) -> List[Dict[str, Any]]:
        if not self.witness_log.exists():
            return []
        return [json.loads(line) for line in self.witness_log.read_text().splitlines() if line]

    def request(
        self,
        operation: str,
        amount: int,
        approvers: str,
        payment_intent: str,
        *,
        out: Optional[str] = None,
        precheck: bool = False,
        **extra: str,
    ) -> tuple[Path, Dict[str, Any]]:
        """The agent writes one request per manager (and its own response),
        into ``approvals/<out or operation>``, and prints its record; its
        warnings are kept in ``last_warnings``. ``extra`` passes
        ``currency``, ``connect_account``, or ``agent``."""
        folder = self.work / "approvals" / (out or operation)
        options = [
            item
            for name, value in extra.items()
            for item in ("--" + name.replace("_", "-"), value)
        ]
        requested = self.run(
            PYTHON,
            "refunds.py",
            "request",
            "--state",
            str(self.state),
            "--operation-id",
            operation,
            "--payment-intent",
            payment_intent,
            "--amount",
            str(amount),
            "--approvers",
            approvers,
            "--out",
            str(folder),
            *options,
            *(["--precheck"] if precheck else []),
        )
        self.last_warnings = requested.stderr
        return folder, json.loads(requested.stdout)

    def answer(
        self, folder: Path, manager: str, *, decline: bool = False, request: Optional[Path] = None
    ) -> subprocess.CompletedProcess[str]:
        """One manager answers on their own machine with the packaged CLI."""
        command = [
            APPROVE_CLI,
            "approve",
            str(request or folder / f"{manager}.request"),
            "--signer",
            str(self.state / "signers" / f"{manager}.json"),
            "--yes",
            "--out",
            str(folder / f"{manager}.response"),
        ]
        if decline:
            command.append("--decline")
        return self.run(*command, check=False)

    def submit(self, operation: str, folder: Path) -> Dict[str, Any]:
        command = [
            PYTHON,
            "refunds.py",
            "submit",
            "--state",
            str(self.state),
            "--socket",
            str(self.witness_socket),
            "--operation-id",
            operation,
            "--responses",
            str(folder),
        ]
        return json.loads(self.run(*command).stdout)

    def refund(
        self,
        operation: str,
        amount: int,
        approvers: str,
        payment_intent: str,
        declines: tuple[str, ...] = (),
        *,
        out: Optional[str] = None,
        precheck: bool = False,
        **extra: str,
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Requests, has each distinct listed manager answer once, and
        submits. Returns the request's record and the outcome record; a
        pre-check refusal is the outcome, and nothing is asked or sent."""
        folder, requested = self.request(
            operation, amount, approvers, payment_intent, out=out, precheck=precheck, **extra
        )
        if requested.get("outcome") == "not-submitted":
            return requested, requested
        for manager in dict.fromkeys(name for name in approvers.split(",") if name):
            answered = self.answer(folder, manager, decline=manager in declines)
            if answered.returncode != 0:
                raise SystemExit(f"{manager} could not answer: {answered.stderr.strip()}")
        return requested, self.submit(operation, folder)

    def audit(
        self, bundle: Path, trust: str, observer: str, *options: str
    ) -> subprocess.CompletedProcess[str]:
        command = [
            self.gateway,
            "audit",
            "--bundle",
            str(bundle),
            "--trusted-context-sha256",
            trust,
            "--observer",
            observer,
            *options,
        ]
        # Prove the audit needs no network where the platform allows it.
        if platform.system() == "Linux" and shutil.which("unshare"):
            probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
            if probe.returncode == 0:
                command = ["unshare", "-rn", *command]
        return subprocess.run(command, capture_output=True, text=True, cwd=HERE, env=self.env)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"journey check failed: {message}")


SUBMIT_SCHEMA = "auths.gateway-submit/1"
# Words only the gateway's submit result may carry.
GATEWAY_OUTCOMES = {
    "denied",
    "not-entered",
    "indeterminate",
    "unknown",
    "response-recorded",
    "observed",
    "observed-by-provider",
}


def submit_frames(frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The witness's submit exchanges; observe frames are recorded but not
    counted."""
    return [frame for frame in frames if frame.get("schema") == SUBMIT_SCHEMA]


def expect_gateway_decided(
    case: str,
    record: Dict[str, Any],
    frames: List[Dict[str, Any]],
    outcome: str,
    code: Optional[str] = None,
    status: Optional[int] = None,
    action_b64: Optional[str] = None,
) -> None:
    """The case was decided by the gateway: the command's record says so,
    with the expected result, and the witness process saw exactly one submit
    frame during the case, whose response from the gateway is that result."""
    seen = submit_frames(frames)
    expect(
        record.get("decided_by") == "gateway",
        f"{case}: the record says decided_by={record.get('decided_by')!r}, not the gateway: {record}",
    )
    expect(seen, f"{case}: the record says the gateway decided, but the witness saw no submit frame")
    expect(len(seen) == 1, f"{case}: the witness saw {len(seen)} submit frames, not one")
    response = seen[0].get("response") or {}
    for key in ("outcome", "code", "status"):
        expect(
            response.get(key) == record.get(key),
            f"{case}: the gateway answered {key}={response.get(key)!r} on the socket, "
            f"the record says {record.get(key)!r}",
        )
    expect(record.get("outcome") == outcome, f"{case}: outcome {record.get('outcome')!r}, expected {outcome!r}")
    if code is not None:
        expect(record.get("code") == code, f"{case}: code {record.get('code')!r}, expected {code!r}")
    if status is not None:
        expect(record.get("status") == status, f"{case}: status {record.get('status')!r}, expected {status}")
    if action_b64 is not None:
        expect(
            seen[0].get("action_sha256") == hashlib.sha256(unb64(action_b64)).hexdigest(),
            f"{case}: the submit frame the witness saw carried another action",
        )


def expect_not_submitted(
    case: str, record: Dict[str, Any], frames: List[Dict[str, Any]], decided_by: str, reason: str
) -> None:
    """Nothing reached the gateway, and the record says who stopped it
    without presenting the stop as a gateway refusal."""
    expect(
        record.get("decided_by") == decided_by
        and record.get("outcome") == "not-submitted"
        and record.get("reason") == reason,
        f"{case}: {record}",
    )
    expect("code" not in record, f"{case}: a record not decided by the gateway carries a code: {record}")
    expect(record.get("outcome") not in GATEWAY_OUTCOMES, f"{case}: {record}")
    expect(not submit_frames(frames), f"{case}: the witness saw a submit frame: {frames}")


def resubmit(journey: Journey, operation: str) -> Dict[str, Any]:
    """Submits the recorded proof and action of ``operation`` again,
    unchanged, as a client retrying after the gateway lost its state would."""
    from auths.gateway import GatewayClient, GatewayEndpoint

    log = journey.state / "audit" / "entries.jsonl"
    entry = next(
        item
        for item in (json.loads(line) for line in log.read_text().splitlines() if line)
        if item["operation_id"] == operation
    )

    async def submit() -> Any:
        gateway = GatewayClient(GatewayEndpoint(journey.socket.resolve()))
        return await gateway.submit(
            proof=unb64(entry["proof_b64"]), action=unb64(entry["action_b64"])
        )

    return dataclasses.asdict(asyncio.run(submit()))


def tamper(
    bundle: Dict[str, Any], operation: str, change: Callable[[Dict[str, Any]], None]
) -> Dict[str, Any]:
    copy = json.loads(json.dumps(bundle))
    change(next(entry for entry in copy["entries"] if entry["operation_id"] == operation))
    return copy


def flip_proof_byte(entry: Dict[str, Any]) -> None:
    raw = bytearray(
        base64.urlsafe_b64decode(entry["proof_b64"] + "=" * (-len(entry["proof_b64"]) % 4))
    )
    raw[len(raw) // 2] ^= 0x01
    entry["proof_b64"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", required=True, help="auths-gateway binary")
    parser.add_argument("--summary", type=Path, help="write the timing and result summary here")
    parser.add_argument("--stripe-test-mode", action="store_true")
    parser.add_argument("--payment-intent", default="pi_mock_journey")
    parser.add_argument("--rejected-payment-intent", default=REFUNDED_PAYMENT_INTENT)
    parser.add_argument("--platform-account", default=PLATFORM_ACCOUNT)
    parser.add_argument("--connect-account", default=CONNECTED_ACCOUNT)
    args = parser.parse_args()

    live = args.stripe_test_mode
    if live:
        secret = os.environ.get("STRIPE_TEST_RESTRICTED_KEY", "")
        if not secret.startswith("rk_test_"):
            raise SystemExit(
                "--stripe-test-mode needs STRIPE_TEST_RESTRICTED_KEY=rk_test_...; other keys are refused"
            )
        for option, value, default, prefix in (
            ("--payment-intent", args.payment_intent, "pi_mock_journey", "pi_"),
            ("--rejected-payment-intent", args.rejected_payment_intent, REFUNDED_PAYMENT_INTENT, "pi_"),
            ("--platform-account", args.platform_account, PLATFORM_ACCOUNT, "acct_"),
            ("--connect-account", args.connect_account, CONNECTED_ACCOUNT, "acct_"),
        ):
            if not value.startswith(prefix) or value == default:
                raise SystemExit(f"--stripe-test-mode needs {option} {prefix}... from your test account")
    else:
        secret = "rk_test_mock_" + os.urandom(12).hex()

    workdir = Path(tempfile.mkdtemp(prefix="auths-refunds-", dir="/tmp")).resolve()
    journey = Journey(args.gateway, workdir)
    try:
        # README step 3: principals, trust, and the agent's bounded grant.
        facts = journey.step(
            "setup: root, three managers, agent, trust, bounded grant",
            lambda: json.loads(
                journey.run(
                    PYTHON,
                    "refunds.py",
                    "setup",
                    "--state",
                    str(journey.state),
                    "--gateway",
                    args.gateway,
                    "--connect-account",
                    args.connect_account,
                ).stdout
            ),
        )
        journey.step(
            f"second agent '{CHECKS_AGENT}' with its own grant (4 per window)",
            lambda: journey.run(
                PYTHON,
                "refunds.py",
                "grant",
                "--state",
                str(journey.state),
                "--gateway",
                args.gateway,
                "--agent",
                CHECKS_AGENT,
                "--max-count",
                "4",
            ),
        )
        # The double checks the bearer token by digest; the key itself stays
        # only in the gateway's credential store.
        mock_token_sha256 = hashlib.sha256(secret.encode()).hexdigest()
        loopback: List[str] = []

        # README step 4: Stripe, here its local double.
        def start_double() -> None:
            mock = journey.background(
                PYTHON,
                "mock_stripe.py",
                "--ledger",
                str(journey.ledger),
                "--token-sha256",
                mock_token_sha256,
                "--control",
                str(journey.control),
                "--payment-intent",
                args.payment_intent,
            )
            port = mock.stdout.readline().strip() if mock.stdout else ""
            expect(port.isdigit(), "mock Stripe did not start")
            loopback.extend(["--loopback-provider", port])

        if not live:
            journey.step("start the counting Stripe double", start_double)

        def install(state_dir: Path, key: str) -> subprocess.CompletedProcess[str]:
            state_dir.mkdir(mode=0o700)
            return journey.run(
                args.gateway,
                "install",
                "--state-dir",
                str(state_dir),
                "--recipe",
                "recipe.json",
                "--profile-lock",
                "profile.lock.json",
                "--trusted-context",
                str(journey.state / "trust" / "gateway.context.cbor"),
                "--approve-digest",
                facts["recipe_digest"],
                "--provider",
                "stripe",
                "--alias",
                "refunds",
                "--account-label",
                args.platform_account,
                "--credential-stdin",
                *loopback,
                stdin=key + "\n",
                check=False,
            )

        # Hostile: the credential guard refuses a key without the declared
        # test prefix before any provider read, and stores nothing.
        def non_test_key() -> Dict[str, Any]:
            before = len(journey.provider_entries())
            refused = install(journey.work / "gateway-non-test-key", NON_TEST_KEY)
            return {
                "exit": refused.returncode,
                "code": refused.stderr.strip().split()[-1] if refused.stderr.strip() else None,
                "provider_requests": len(journey.provider_entries()) - before,
            }

        guard = journey.step("hostile: the guard refuses a key without rk_test_", non_test_key)
        expect(
            guard["exit"] != 0
            and guard["code"] == "gateway.install.credential-guard"
            and guard["provider_requests"] == 0,
            f"non-test key: {guard}",
        )

        # README step 5: the gateway takes the key on stdin, checks it with
        # the provider, and starts.
        def install_key() -> None:
            installed = install(journey.gateway_state, secret)
            expect(installed.returncode == 0, f"install failed: {installed.stderr.strip()}")

        onboarding_from = len(journey.provider_entries())
        journey.step("gateway install with the key on stdin", install_key)
        onboarding = journey.provider_entries()[onboarding_from:]
        # The store as a backup taken now would hold it: the shared connection
        # record and no claim. The state-loss check restores it.
        attempts_backup = journey.work / "attempts-backup"
        shutil.copytree(journey.gateway_state / "attempts", attempts_backup)
        observer = journey.step(
            "gateway observer key",
            lambda: json.loads(
                journey.run(
                    args.gateway, "observer-init", "--state-dir", str(journey.gateway_state)
                ).stdout
            )["observer_anchor"]["principal"],
        )

        serve = [
            args.gateway,
            "serve",
            "--state-dir",
            str(journey.gateway_state),
            "--app-socket",
            str(journey.socket),
            *loopback,
        ]
        running: Dict[str, subprocess.Popen[str]] = {}

        def start_gateway() -> None:
            # A stopped gateway leaves its socket file behind; wait for a new one.
            journey.socket.unlink(missing_ok=True)
            running["gateway"] = journey.background(*serve)
            deadline = time.monotonic() + 10
            while not journey.socket.exists():
                expect(time.monotonic() < deadline, "gateway did not open its app socket")
                time.sleep(0.05)

        journey.step("gateway serve" + ("" if live else " (to the counting Stripe double)"), start_gateway)

        # The witness relays the application socket from its own process and
        # records every exchange; every `submit` below goes through it.
        def start_witness() -> None:
            witness = journey.background(
                PYTHON,
                "gateway_witness.py",
                "--listen",
                str(journey.witness_socket),
                "--upstream",
                str(journey.socket),
                "--log",
                str(journey.witness_log),
            )
            ready = witness.stdout.readline().strip() if witness.stdout else ""
            expect(ready == "ready", "the gateway witness did not start")

        journey.step("gateway witness on the application socket", start_witness)

        pi = args.payment_intent
        results: Dict[str, Dict[str, Any]] = {}
        requests: Dict[str, Dict[str, Any]] = {}
        frames: Dict[str, List[Dict[str, Any]]] = {}
        warnings: Dict[str, str] = {}

        def watched(case: str, action: Callable[[], Dict[str, Any]]) -> None:
            """Runs one case and keeps its record, the provider requests it
            caused, and the witness's frames during it."""
            before = len(journey.provider_entries())
            seen = len(journey.witness_lines())
            results[case] = action()
            made = journey.provider_entries()[before:]
            frames[case] = journey.witness_lines()[seen:]
            results[case]["provider_requests"] = len(made)
            results[case]["provider_writes"] = sum(entry["kind"] == "write" for entry in made)

        def submit(
            case: str,
            amount: int,
            approvers: str,
            declines: tuple[str, ...] = (),
            payment_intent: Optional[str] = None,
            operation: Optional[str] = None,
            **extra: Any,
        ) -> None:
            def run() -> Dict[str, Any]:
                requested, record = journey.refund(
                    operation or case, amount, approvers, payment_intent or pi, declines, **extra
                )
                requests[case] = requested
                warnings[case] = journey.last_warnings
                return record

            watched(case, run)

        def reused_approvals() -> Dict[str, Any]:
            """refund-1's approved proof, sent with another refund's action."""
            _, requested = journey.request("refund-8-reuse", 1_000, "manager-a,manager-b", pi)
            requests["refund-8-reuse"] = requested
            log = journey.state / "audit" / "entries.jsonl"
            first = next(
                item
                for item in (json.loads(line) for line in log.read_text().splitlines() if line)
                if item["operation_id"] == "refund-1"
            )
            proof, action = journey.work / "reuse.proof", journey.work / "reuse.action"
            proof.write_bytes(unb64(first["proof_b64"]))
            action.write_bytes(unb64(requested["action_b64"]))
            sent = journey.run(
                args.gateway,
                "submit",
                "--app-socket",
                str(journey.witness_socket),
                "--proof",
                str(proof),
                "--action",
                str(action),
            )
            # The CLI prints the gateway's submit result unchanged.
            return {"decided_by": "gateway", **json.loads(sent.stdout)}

        # The hostile table: every case the gateway must decide, in order.
        # Each is checked by the guard: the record says the gateway decided,
        # and the witness saw exactly one submit frame with that answer.
        # Refused before any credential lease: no provider request at all.
        before_lease = {
            "refund-2-one-approval": ("denied", "composition-requirement-not-met"),
            "refund-6-no-manager": ("denied", "composition-requirement-not-met"),
            "refund-7-repeated": ("denied", "composition-requirement-not-met"),
            "refund-3-over-ceiling": ("not-entered", "gateway.policy.above-ceiling"),
            "refund-other-account": ("not-entered", "gateway.policy.scope-denied"),
            "refund-over-sum": ("not-entered", "gateway.policy.sum-exhausted"),
            "refund-5-window": ("not-entered", "gateway.policy.window-exhausted"),
            "refund-1-replay": ("not-entered", "gateway.attempt.replay"),
            "refund-8-reuse": ("denied", "action-body-mismatch"),
            "refund-7-retry": ("not-entered", "gateway.policy.window-exhausted"),
        }
        # Refused after the lease by a provider check: reads, never a write.
        after_lease = {
            "refund-above-ratio": ("not-entered", "gateway.relative-ceiling.above"),
            "refund-currency-mismatch": (
                "not-entered",
                "gateway.relative-ceiling.binding-mismatch",
            ),
        }
        if not live:
            after_lease.update(
                {
                    "refund-account-substituted": (
                        "not-entered",
                        "gateway.credential.account-mismatch",
                    ),
                    "refund-denied-read-answered": (
                        "not-entered",
                        "gateway.credential.capability-excess",
                    ),
                }
            )
        expected_refusals = {**before_lease, **after_lease}

        # README step 6: the agent writes a request per manager, each manager
        # answers with `auths approve`, and the gateway submits.
        journey.step(
            "refund 1: 15.00, agent + manager-a + manager-b (remote approvals)",
            lambda: submit("refund-1", 1_500, "manager-a,manager-b"),
        )
        journey.step(
            "declined: manager-b declines, nothing is submitted",
            lambda: submit("refund-declined", 2_000, "manager-a,manager-b", declines=("manager-b",)),
        )

        def tampered_request() -> Dict[str, Any]:
            folder, _ = journey.request("refund-tampered", 1_500, "manager-a,manager-b", pi)
            original = (folder / "manager-a.request").read_text().strip()
            raw = bytearray(unb64(original[len("auths-ar1-"):]))
            at = bytes(raw).index(b'"amount":1500')
            raw[at : at + len(b'"amount":1500')] = b'"amount":9500'
            edited = folder / "manager-a.edited"
            edited.write_text("auths-ar1-" + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode())
            answered = journey.answer(folder, "manager-a", request=edited)
            return {
                "exit": answered.returncode,
                "refused": "approval.action-mismatch" in answered.stderr,
                "signed": (folder / "manager-a.response").exists(),
            }

        tampered_run: Dict[str, Any] = {}

        def tampered_case() -> Dict[str, Any]:
            tampered_run.update(tampered_request())
            return dict(tampered_run)

        journey.step(
            "tampered request: the manager's CLI refuses and signs nothing",
            lambda: watched("refund-tampered", tampered_case),
        )
        journey.step(
            "hostile: 1 of 3 approvals",
            lambda: submit("refund-2-one-approval", 1_200, "manager-a"),
        )
        journey.step(
            "hostile: no manager, only the agent",
            lambda: submit("refund-6-no-manager", 1_100, ""),
        )
        journey.step(
            "hostile: manager-a listed twice (request drops the repeat)",
            lambda: submit("refund-7-repeated", 1_300, "manager-a,manager-a"),
        )
        journey.step(
            "hostile: over the 50.00 ceiling",
            lambda: submit("refund-3-over-ceiling", 9_000, "manager-a,manager-b"),
        )
        journey.step(
            "hostile: a connected account the grant does not list",
            lambda: submit(
                "refund-other-account", 1_000, "manager-a,manager-c", connect_account=OTHER_ACCOUNT
            ),
        )
        journey.step(
            "hostile: 50.00 with 45.00 left of the day's 60.00 USD",
            lambda: submit("refund-over-sum", 5_000, "manager-a,manager-b"),
        )
        journey.step(
            "refund 4: 40.00 of a PaymentIntent already refunded (rejected)",
            lambda: submit(
                "refund-4",
                4_000,
                "manager-b,manager-c",
                payment_intent=args.rejected_payment_intent,
            ),
        )
        journey.step(
            "hostile: third refund in the window",
            lambda: submit("refund-5-window", 1_000, "manager-a,manager-c"),
        )
        journey.step(
            "hostile: refund-1 requested again, with fresh approvals",
            lambda: submit(
                "refund-1-replay",
                1_500,
                "manager-b,manager-c",
                operation="refund-1",
                out="refund-1-replay",
            ),
        )
        journey.step(
            "hostile: refund-1's proof sent for another refund",
            lambda: watched("refund-8-reuse", reused_approvals),
        )
        journey.step(
            "retry after denial: refund-7-repeated again, with managers B and C",
            lambda: submit(
                "refund-7-retry",
                1_300,
                "manager-b,manager-c",
                operation="refund-7-repeated",
                out="refund-7-retry",
            ),
        )

        # The negative control: a client-side pre-check refuses locally, and
        # the guard must reject it as not decided by the gateway.
        journey.step(
            "negative control: an under-approved request refused by --precheck",
            lambda: submit("refund-9-precheck", 1_200, "manager-a", precheck=True),
        )

        # The recipe's checks after the credential lease, each refusing one
        # refund of the second agent before any write.
        def checked(operation: str, amount: int, control: Dict[str, Any], **extra: str) -> None:
            journey.control.write_text(json.dumps(control))
            try:
                submit(operation, amount, "manager-b,manager-c", agent=CHECKS_AGENT, **extra)
            finally:
                journey.control.unlink(missing_ok=True)

        journey.step(
            "hostile: 30.01, above half of the payment's 60.00",
            lambda: checked("refund-above-ratio", 3_001, {}),
        )
        journey.step(
            "hostile: EUR against a USD PaymentIntent",
            lambda: checked("refund-currency-mismatch", 1_000, {}, currency="eur"),
        )
        if not live:
            journey.step(
                "hostile: the provider reports another account at the lease",
                lambda: checked("refund-account-substituted", 1_000, {"account": OTHER_ACCOUNT}),
            )
            journey.step(
                "hostile: the provider answers a denied read with 200",
                lambda: checked("refund-denied-read-answered", 1_000, {"denied_status": 200}),
            )

        observed = results["refund-1"]
        expect_gateway_decided(
            "refund-1",
            observed,
            frames["refund-1"],
            "observed-by-provider",
            status=200,
            action_b64=requests["refund-1"]["action_b64"],
        )
        expect(observed["evidence"]["channel"] == "read-back", f"refund-1: {observed}")
        expect(observed["bundle"] == "appended", f"refund-1: {observed}")
        expect_gateway_decided(
            "refund-4",
            results["refund-4"],
            frames["refund-4"],
            "response-recorded",
            status=400,
            action_b64=requests["refund-4"]["action_b64"],
        )
        declined = results["refund-declined"]
        expect_not_submitted("refund-declined", declined, frames["refund-declined"], "approver", "approver-declined")
        expect(
            declined.get("declined") == ["manager-b"] and declined["provider_requests"] == 0,
            f"refund-declined: {declined}",
        )
        expect(
            tampered_run == {"exit": 1, "refused": True, "signed": False},
            f"tampered request: {tampered_run}",
        )
        expect(
            not submit_frames(frames["refund-tampered"])
            and results["refund-tampered"]["provider_requests"] == 0,
            f"tampered request reached the gateway: {frames['refund-tampered']}",
        )
        hostile: Dict[str, Dict[str, Any]] = {}
        for case, (outcome, code) in expected_refusals.items():
            expect_gateway_decided(
                case,
                results[case],
                frames[case],
                outcome,
                code,
                action_b64=requests[case]["action_b64"],
            )
            hostile[case] = {
                "decided_by": results[case]["decided_by"],
                "outcome": outcome,
                "code": code,
                "submit_frames": len(submit_frames(frames[case])),
            }
        # Only the reused-approvals case is sent by the journey itself, which
        # asks for no signed outcome.
        expect(
            len(frames["refund-8-reuse"]) == 1,
            f"refund-8-reuse: the witness saw {frames['refund-8-reuse']}",
        )
        expect(
            "dropped the repeated approver manager-a" in warnings["refund-7-repeated"],
            f"refund-7-repeated: request did not name the dropped repeat: {warnings['refund-7-repeated']}",
        )
        for case in ("refund-1-replay", "refund-7-retry"):
            expect(
                "attempt store decides" in warnings[case],
                f"{case}: request did not warn that the operation ID was requested before",
            )
        expect(results["refund-1-replay"]["bundle"] == "unchanged", f"replay: {results['refund-1-replay']}")
        expect(results["refund-7-retry"]["bundle"] == "replaced", f"retry: {results['refund-7-retry']}")

        control = results["refund-9-precheck"]
        expect_not_submitted("refund-9-precheck", control, frames["refund-9-precheck"], "client", "precheck")
        expect(control.get("precheck") == "approvals-below-threshold", f"negative control: {control}")
        try:
            expect_gateway_decided(
                "refund-9-precheck",
                control,
                frames["refund-9-precheck"],
                "denied",
                "composition-requirement-not-met",
            )
        except SystemExit as rejected:
            negative_control = {"guard_rejected": True, "reason": str(rejected)}
        else:
            raise SystemExit("journey check failed: the guard accepted a request refused only locally")
        hostile["refund-9-precheck"] = {
            "decided_by": control["decided_by"],
            "outcome": control["outcome"],
            "precheck": control["precheck"],
            "submit_frames": len(submit_frames(frames["refund-9-precheck"])),
            "guard_rejected": True,
        }
        for case in ("refund-1-replay", "refund-8-reuse", "refund-7-retry", "refund-9-precheck"):
            expect(results[case]["provider_requests"] == 0, f"{case} reached the provider")

        state_loss: Optional[Dict[str, Any]] = None
        if not live:
            for operation in before_lease:
                expect(
                    results[operation]["provider_requests"] == 0,
                    f"{operation} reached the provider",
                )
            for operation in after_lease:
                expect(
                    results[operation]["provider_writes"] == 0
                    and results[operation]["provider_requests"] > 0,
                    f"{operation}: {results[operation]}",
                )
            entries = journey.provider_entries()
            expect(
                all(entry["authorized"] and entry["stripe_version"] == STRIPE_VERSION for entry in entries),
                "provider saw an unauthenticated or unversioned request",
            )
            credential_reads = {"/v1/balance", "/v1/account", "/v1/customers", "/v1/payouts"}
            expect(
                all(
                    entry["stripe_account"] is None
                    if entry["path"] in credential_reads
                    else entry["stripe_account"] == args.connect_account
                    for entry in entries
                ),
                "Stripe-Account went on a credential read or missed an action request",
            )
            expect(
                [(entry["method"], entry["path"], entry["status"]) for entry in onboarding]
                == [
                    ("GET", "/v1/balance", 200),
                    ("GET", "/v1/account", 200),
                    ("GET", "/v1/customers", 403),
                    ("GET", "/v1/payouts", 403),
                ],
                f"install onboarding reads {onboarding}",
            )
            writes = [entry for entry in entries if entry["kind"] == "write"]
            expect(len(writes) == 2, f"expected exactly 2 provider writes, saw {len(writes)}")
            expect(all(entry["well_formed"] for entry in writes), "provider saw a malformed refund")
            expect([entry["amount"] for entry in writes] == [1_500, 4_000], f"provider writes {writes}")
            expect(
                writes[0]["echo"] == observed["evidence"]["echo"],
                f"refund-1 echo {writes[0]['echo']} != {observed['evidence']['echo']}",
            )
            read_back = f"/v1/refunds/{writes[0]['refund']}"
            expect(
                any(entry["path"] == read_back and entry["status"] == 200 for entry in entries),
                f"refund-1 was not read back at {read_back}",
            )
            keys = {
                operation: idempotency_key(facts["operator_namespace"], operation)
                for operation in ("refund-1", "refund-4")
            }
            sent = [entry["idempotency_key"] for entry in writes]
            expect(sent == [keys["refund-1"], keys["refund-4"]], f"Idempotency-Key values {sent}")
            expect(not any(entry["replayed"] for entry in writes), f"provider replays {writes}")

            # State loss: the gateway's store is restored from the backup
            # taken before the first refund, which still holds the shared
            # connection record but no claim, and a client resubmits
            # refund-1's approved proof and action. No claim stops it now;
            # only the repeated Idempotency-Key keeps the double, like Stripe,
            # from making a second refund. A wiped store would lose the
            # connection record too, and the gateway would refuse every entry.
            def lose_attempts_and_resubmit() -> Dict[str, Any]:
                journey.terminate(running["gateway"])
                shutil.rmtree(journey.gateway_state / "attempts")
                shutil.copytree(attempts_backup, journey.gateway_state / "attempts")
                start_gateway()
                return resubmit(journey, "refund-1")

            state_loss = journey.step(
                "state loss: store restored from an older backup, refund-1 resubmitted",
                lose_attempts_and_resubmit,
            )
            expect(
                state_loss["outcome"] == "observed-by-provider" and state_loss["status"] == 200,
                f"resubmitted refund-1: {state_loss}",
            )
            writes = [entry for entry in journey.provider_entries() if entry["kind"] == "write"]
            expect(len(writes) == 3, f"expected 3 provider writes, saw {len(writes)}")
            expect(
                writes[2]["idempotency_key"] == keys["refund-1"]
                and writes[2]["replayed"]
                and writes[2]["refund"] == writes[0]["refund"],
                f"resubmitted refund-1 was not de-duplicated: {writes[2]}",
            )
            refunds_created = {entry["refund"] for entry in writes if entry["refund"]}
            expect(len(refunds_created) == 1, f"expected 1 refund, saw {sorted(refunds_created)}")

        # README step 8: the audit bundle.
        bundle_path = journey.work / "audit-bundle.json"
        journey.step(
            "export audit bundle",
            lambda: journey.run(
                PYTHON,
                "refunds.py",
                "export",
                "--state",
                str(journey.state),
                "--out",
                str(bundle_path),
            ),
        )
        journey.stop()

        # README step 9: the offline audit, with the gateway stopped. The
        # gateway recorded nothing for the refusals it made before the claim,
        # so their entries carry no outcome and the audit reports them
        # unverified: the default policy fails the bundle, and
        # --allow-unverified-refusals passes it because the audit itself
        # refuses each of those proofs.
        exported = json.loads(bundle_path.read_text())
        unrecorded = {
            entry["operation_id"]
            for entry in exported["entries"]
            if entry.get("outcome_b64") is None
        }
        # refund-7-repeated's unsigned entry was replaced by its signed retry.
        expect(
            unrecorded
            == {
                "refund-2-one-approval",
                "refund-6-no-manager",
                "refund-3-over-ceiling",
                "refund-other-account",
            },
            f"entries without a signed outcome: {sorted(unrecorded)}",
        )
        strict = journey.step(
            "offline audit (gateway stopped)",
            lambda: journey.audit(bundle_path, facts["trusted_context_sha256"], observer),
        )
        expect(
            strict.returncode != 0 and strict.stderr.strip() == "audit.unverified",
            f"audit without --allow-unverified-refusals: {strict.returncode} {strict.stderr}",
        )
        audited = journey.step(
            "offline audit accepting unverified refusals",
            lambda: journey.audit(
                bundle_path,
                facts["trusted_context_sha256"],
                observer,
                "--allow-unverified-refusals",
            ),
        )
        expect(audited.returncode == 0, f"audit failed: {audited.stderr}")
        report = json.loads(audited.stdout)
        expect(report == json.loads(strict.stdout), "the option changed the audit report")
        verdicts = {
            entry["operation_id"]: (entry["status"], entry["code"], entry["admitted"])
            for entry in report["entries"]
        }
        # One bundle entry per operation ID: the replay left refund-1's
        # alone, the retry replaced refund-7-repeated's unsigned one, and the
        # journey's own reused-approvals submission has none.
        bundled = [entry["operation_id"] for entry in exported["entries"]]
        audited_refusals = {
            operation: code
            for operation, (_, code) in expected_refusals.items()
            if operation not in ("refund-1-replay", "refund-8-reuse", "refund-7-retry")
        }
        audited_refusals["refund-7-repeated"] = expected_refusals["refund-7-retry"][1]
        expect(len(bundled) == len(set(bundled)), f"bundle repeats an operation ID: {bundled}")
        expect(
            set(bundled) == {"refund-1", "refund-4", *audited_refusals},
            f"bundle entries {sorted(bundled)}",
        )
        for operation in ("refund-1", "refund-4"):
            expect(
                verdicts[operation] == ("verified", "audit.verified", True),
                f"audit {operation}: {verdicts[operation]}",
            )
        for operation, code in audited_refusals.items():
            expected = (
                ("unverified", code, False) if operation in unrecorded else ("refused", code, True)
            )
            expect(verdicts[operation] == expected, f"audit {operation}: {verdicts[operation]}")
        # Every entered refund shows the provider's result beside its verdict,
        # the one the provider rejected included.
        provider_results = {
            entry["operation_id"]: entry["provider_result"] for entry in report["entries"]
        }
        entered = [
            entry["operation_id"] for entry in report["entries"] if entry["status"] == "verified"
        ]
        expect(entered == ["refund-1", "refund-4"], f"audit entered {entered}")
        for operation, stage, status in (
            ("refund-1", "observed-by-provider", 200),
            ("refund-4", "response-recorded", 400),
        ):
            result = provider_results[operation]
            expect(
                result is not None
                and result["stage"] == stage
                and result["http_status"] == status
                and result["response_digest"] is not None,
                f"audit provider result {operation}: {result}",
            )
        exhausted = provider_results["refund-5-window"]
        expect(
            exhausted is not None
            and exhausted["refusal"] == "gateway.policy.window-exhausted"
            and exhausted["recount"] is None,
            f"audit provider result refund-5-window: {exhausted}",
        )
        for operation in after_lease:
            result = provider_results[operation]
            expect(
                result is not None
                and result["stage"] == "not-entered"
                and result["refusal"] == expected_refusals[operation][1]
                and result["http_status"] is None,
                f"audit provider result {operation}: {result}",
            )
        expect(
            report["recovery"]["class"] == "linked-after-response",
            f"audit recovery {report['recovery']}",
        )
        verified = next(entry for entry in report["entries"] if entry["operation_id"] == "refund-1")
        expect(len(verified["approvals"]) == 3, "refund-1 should carry the agent and two managers")
        expect(
            set(verified["approvals"])
            == {facts["principals"][name] for name in ("agent", "manager-a", "manager-b")},
            "refund-1 approvers",
        )
        recorded = {
            (item["operation_id"], item["approver"], item["decision"])
            for item in report["approval_responses"]
        }
        principals = facts["principals"]
        expect(
            {
                ("refund-declined", principals["manager-a"], "approve"),
                ("refund-declined", principals["manager-b"], "decline"),
                ("refund-1", principals["manager-a"], "approve"),
                ("refund-1", principals["manager-b"], "approve"),
            }
            <= recorded,
            f"audit approval responses {sorted(recorded)}",
        )

        # Hostile: a tampered bundle is detected. Each case runs with
        # --allow-unverified-refusals, so that only the tampering can fail it.
        bundle = json.loads(bundle_path.read_text())

        def audit_tampered(value: Dict[str, Any]) -> subprocess.CompletedProcess[str]:
            path = journey.work / "tampered.json"
            path.write_text(json.dumps(value))
            return journey.audit(
                path, facts["trusted_context_sha256"], observer, "--allow-unverified-refusals"
            )

        def refund_1(result: subprocess.CompletedProcess[str]) -> Dict[str, Any]:
            return next(
                entry
                for entry in json.loads(result.stdout)["entries"]
                if entry["operation_id"] == "refund-1"
            )

        def drop_outcome(entry: Dict[str, Any]) -> None:
            entry.pop("outcome_b64", None)

        outcome_of_4 = next(
            entry for entry in bundle["entries"] if entry["operation_id"] == "refund-4"
        )["outcome_b64"]
        tampered = {
            "proof byte flipped": (
                tamper(bundle, "refund-1", flip_proof_byte),
                "audit.entered-without-authority",
            ),
            "action swapped": (
                tamper(
                    bundle,
                    "refund-1",
                    lambda entry: entry.update(
                        action_b64=next(
                            item for item in bundle["entries"] if item["operation_id"] == "refund-4"
                        )["action_b64"]
                    ),
                ),
                "audit.outcome-commitment-mismatch",
            ),
            "outcome replayed": (
                tamper(bundle, "refund-1", lambda entry: entry.update(outcome_b64=outcome_of_4)),
                "audit.outcome-invalid",
            ),
        }
        detections: Dict[str, str] = {}
        for label, (value, code) in tampered.items():
            result = audit_tampered(value)
            findings = [
                entry["code"]
                for entry in json.loads(result.stdout)["entries"]
                if entry["status"] == "inconsistent"
            ]
            expect(
                result.returncode != 0 and findings == [code],
                f"tamper '{label}' not detected: {findings} {result.stderr}",
            )
            detections[label] = code
        # An entered refund whose outcome was left out verifies, so it stays
        # unverified and fails the audit even with the option.
        removed = audit_tampered(tamper(bundle, "refund-1", drop_outcome))
        removed_entry = refund_1(removed)
        expect(
            removed.returncode != 0
            and removed.stderr.strip() == "audit.unverified"
            and json.loads(removed.stdout)["inconsistent"] == 0
            and (removed_entry["status"], removed_entry["code"], removed_entry["admitted"])
            == ("unverified", "audit.outcome-missing", True),
            f"tamper 'outcome removed' not detected: {removed_entry} {removed.stderr}",
        )
        detections["outcome removed"] = "audit.unverified"
        swapped_trust = dict(
            bundle,
            trusted_context_b64=base64.urlsafe_b64encode(
                (journey.state / "trust" / "sdk.context.cbor").read_bytes()
            )
            .rstrip(b"=")
            .decode(),
        )
        result = audit_tampered(swapped_trust)
        expect(
            result.returncode != 0 and "audit.trust-pin-mismatch" in result.stderr,
            "replaced trust not detected",
        )
        detections["trust replaced"] = "audit.trust-pin-mismatch"
        # The documented limit of --allow-unverified-refusals: with its outcome
        # removed, an altered proof is refused by the audit and so accepted by
        # the option. It is reported unverified, never refused, and the
        # default policy still fails it. This is not a detection.
        def remove_and_flip(entry: Dict[str, Any]) -> None:
            drop_outcome(entry)
            flip_proof_byte(entry)

        limited = audit_tampered(tamper(bundle, "refund-1", remove_and_flip))
        limited_entry = refund_1(limited)
        expect(
            limited.returncode == 0
            and json.loads(limited.stdout)["inconsistent"] == 0
            and limited_entry["status"] == "unverified"
            and not limited_entry["admitted"],
            f"known limit changed: {limited_entry} {limited.returncode} {limited.stderr}",
        )
        known_limits = {
            "outcome removed and proof byte flipped": {
                "exit": limited.returncode,
                "refund-1": limited_entry["status"],
            }
        }
        journey.steps.append({"step": "tampered bundles detected", "seconds": 0})

        writes = [entry for entry in journey.provider_entries() if entry["kind"] == "write"]
        summary = {
            "journey": "stripe-refund-approval",
            "provider": "stripe-test-mode" if live else "counting-mock",
            "wall_seconds": round(time.monotonic() - journey.started, 2),
            "steps": journey.steps,
            "refunds": results,
            "tampered_request": tampered_run,
            "non_test_key": guard,
            "provider_checks": {
                operation: {
                    "code": results[operation]["code"],
                    "provider_writes": None if live else results[operation]["provider_writes"],
                }
                for operation in expected_refusals
            },
            "provider_requests": None if live else len(journey.provider_entries()),
            "provider_writes": None if live else len(writes),
            "provider_refunds": None
            if live
            else len({entry["refund"] for entry in writes if entry["refund"]}),
            "state_loss_resubmission": state_loss,
            "audit": {
                "verified": report["verified"],
                "refused": report["refused"],
                "unverified": report["unverified"],
                "inconsistent": report["inconsistent"],
                "http_status": {
                    operation: provider_results[operation]["http_status"]
                    for operation in entered
                },
            },
            "tamper_detected": detections,
            "known_limits": known_limits,
            "hostile": hostile,
            "negative_control": negative_control,
            "gateway_witness": journey.witness_lines(),
        }
        text = json.dumps(summary, indent=2)
        print(text)
        if args.summary:
            args.summary.write_text(text + "\n")
        return 0
    finally:
        journey.stop()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
