#!/usr/bin/env python3
"""Run AP-071's installed Airtable mechanism case on one disposable record.

This is an operator-only development tool. Its human key is synthetic and the
PAT has no employee subject; a successful run proves the shared task/release/
exact-write mechanism on a second HTTPS provider, not cross-provider human
identity. The named resource journal permits separate cleanup after a failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
for source in (
    ROOT / "bindings/python/src",
    ROOT / "demos/google-employee-delegation/broker/src",
    ROOT / "demos/google-employee-delegation/agent/src",
    ROOT / "demos/airtable-gateway",
    ROOT / "qualification/reference",
):
    sys.path.insert(0, str(source))

from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from airtable_resources import Resources
from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding, EnrollmentStore
from employee_read_demo.operator_cli import _private_write, init_root
from employee_read_demo.task_write_browser import TaskWriteBrowserFlow
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.task_write_operator_cli import issue_task_package
from employee_read_demo.task_write_proofs import task_commitment
from launch import credentials as read_env_credentials


WRITE = HERE.parent / "write_reference"
WRITE_DIGEST = "2766350e0222f0d427b41bf3dc241c948aa6812e32893d983ddc208e09cbb73f"
READ_DIGEST = "bc0335d9ab4fb4bb381834bef8aa5e6e6df58686f0920db460a109efa272fec7"
BASE = "appQD3Qf0YFBCW9bV"
TABLE = "tblBx2jwe0IsPYRKT"
ACCOUNT = "operator-airtable-pat"


def _private_dir(path: Path, *, create: bool = False) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("operator directory is not an absolute private path")
    if create:
        path.mkdir(mode=0o700)
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("operator directory is not owner-private")
    return path


def _token(env_file: Path) -> str:
    decoded = json.loads(read_env_credentials(env_file))
    token = decoded.get("token")
    if type(token) is not str or not token.startswith("pat"):
        raise ValueError("Airtable development PAT is unavailable")
    return token


class Airtable:
    def __init__(self, token: str) -> None:
        self.session = requests.Session()
        self.session.trust_env = False
        self.token = token

    def request(self, method: str, path: str, fields: dict | None = None) -> dict:
        if (method not in {"GET", "POST", "DELETE"} or not path.startswith("/v0/")
                or path.startswith("//") or any(char in path for char in "\r\n")):
            raise ValueError("Airtable operator request is outside the fixture")
        response = self.session.request(
            method, "https://api.airtable.com" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/json"},
            json=fields, timeout=25, allow_redirects=False,
        )
        try:
            if (not 200 <= response.status_code <= 299
                    or len(response.content) > 65_536
                    or "application/json" not in response.headers.get("Content-Type", "")):
                raise ValueError("Airtable operator request was refused")
            value = response.json()
            if type(value) is not dict:
                raise ValueError("Airtable operator response is malformed")
            return value
        finally:
            response.close()

    def close(self) -> None:
        self.session.close()


def _gateway(binary: Path, command: str, *args: str,
             secret: bytes | None = None) -> dict:
    argv = list(map(str, args))
    # A generated task ID may begin with '-'; pass it as one option value so
    # clap cannot mistake it for a new flag.
    if "--task-id" in argv:
        index = argv.index("--task-id")
        if index + 1 >= len(argv):
            raise ValueError("task ID option has no value")
        argv[index:index + 2] = ["--task-id=" + argv[index + 1]]
    completed = subprocess.run(
        [str(binary), command, *argv], input=secret,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env={"PATH": os.environ.get("PATH", "")}, check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > 131_072:
        # The child output may contain provider data on an unexpected failure.
        raise RuntimeError("gateway " + command + " refused; inspect private state")
    result = json.loads(completed.stdout)
    if type(result) is not dict:
        raise RuntimeError("gateway " + command + " returned malformed status")
    return result


def _agent(command: str, *args: str, wait: bool = True) -> subprocess.CompletedProcess | subprocess.Popen:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1",
           "PYTHONPATH": os.pathsep.join((
               str(ROOT / "bindings/python/src"),
               str(ROOT / "demos/google-employee-delegation/agent/src"),
           ))}
    invocation = ([sys.executable, str(HERE / "lost_ack_agent.py"),
                   *map(str, args)] if command == "serve-release-lossy" else
                  [sys.executable, "-m", "employee_read_agent.cli", command,
                   *map(str, args)])
    if not wait:
        return subprocess.Popen(invocation, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env)
    completed = subprocess.run(invocation, capture_output=True, env=env,
                               check=False, timeout=45)
    if completed.returncode != 0:
        raise RuntimeError("separate agent " + command + " refused")
    return completed


def _write_json(path: Path, value: dict) -> None:
    _private_write(path, json.dumps(value, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8"))


def _wait_for(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError("agent channel stopped before accepting release")
        time.sleep(0.05)
    raise RuntimeError("agent channel did not become available")


def run(env_file: Path, root: Path, binary: Path,
        *, drop_ack: bool = False, fail_before_content: bool = False,
        revoke_before_actions: bool = False) -> None:
    root = _private_dir(root, create=True)
    if sum((drop_ack, fail_before_content, revoke_before_actions)) > 1:
        raise ValueError("choose only one release or revocation fault")
    operator = _private_dir(root / "operator", create=True)
    agent_dir = _private_dir(root / "agent", create=True)
    state = _private_dir(root / "gateway", create=True)
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise ValueError("gateway binary is unavailable")
    if fail_before_content:
        help_result = subprocess.run(
            [str(binary), "task-read-submit", "--help"],
            capture_output=True, timeout=15, check=True,
        )
        if b"--fail-before-content" not in help_result.stdout:
            raise ValueError("development no-content fault is unavailable")
    write_review = _gateway(
        binary, "review", "--recipe", WRITE / "recipe.json",
        "--profile-lock", WRITE / "profile.lock.json",
    )
    read_review = _gateway(
        binary, "review-release", "--recipe", HERE / "recipe.json",
        "--profile-lock", HERE / "profile.lock.json",
    )
    if (write_review.get("digest") != WRITE_DIGEST
            or write_review.get("origin") != "https://api.airtable.com"
            or write_review.get("method") != "PATCH"
            or read_review.get("digest") != READ_DIGEST
            or read_review.get("origin") != "https://api.airtable.com"
            or read_review.get("method") != "GET"):
        raise ValueError("reviewed Airtable recipes changed")
    token = _token(env_file)
    airtable = Airtable(token)
    resources = Resources(token, api=airtable.request)
    journal, pool = root / "resources.json", root / "record-pool.json"
    run_id = f"ap071/{int(time.time())}/{secrets.randbelow(10**12 - 1) + 1}"
    # This durable ownership predicate is written before the provider POST.
    resources.prepare(run_id, 1, journal, pool)
    record = json.loads(pool.read_bytes())["records"][0]["id"]
    row_path = f"/v0/{BASE}/{TABLE}/{record}"
    before = airtable.request("GET", row_path)
    if before.get("id") != record or before.get("fields", {}).get("DemoStatus") != "Pending":
        raise RuntimeError("disposable Airtable baseline changed")

    root_seed, root_trust = operator / "root.seed", operator / "root-trust.json"
    init_root(root_seed, root_trust, company="ap071-conformance",
              service="operator", now=int(time.time()))
    broker_db = operator / "broker.sqlite3"
    EnrollmentStore(broker_db)
    os.chmod(broker_db, 0o600)
    human_key = Ed25519PrivateKey.generate()
    human_packet = create_raw_key_ed25519_identity(
        human_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).to_bytes()
    human_principal, _ = authority_for_identity_packet(human_packet)
    with sqlite3.connect(broker_db) as db:
        db.execute("""INSERT INTO employee_bindings
            (binding_ref,company,person,issuer,subject,principal,
             identity_packet,bundle_digest) VALUES(?,?,?,?,?,?,?,?)""", (
                "operator-binding", "ap071-conformance", "operator-person",
                "https://synthetic.local", ACCOUNT, human_principal,
                human_packet, "a" * 64,
            ))
    agent_key = Ed25519PrivateKey.generate()
    agent_seed = agent_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    _private_write(agent_dir / "agent.seed", agent_seed)
    agent_packet = create_raw_key_ed25519_identity(
        agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).to_bytes()
    agent_principal, _ = authority_for_identity_packet(agent_packet)
    _private_write(operator / "agent.identity.cbor", agent_packet)
    agent_digest = hashlib.sha256(agent_packet).hexdigest()
    authority = operator / "task-authority.json"
    issue_task_package(
        root_seed=root_seed, root_trust=root_trust, state_db=broker_db,
        binding_ref="operator-binding", company="ap071-conformance",
        recipe_path=WRITE / "recipe.json",
        profile_lock_path=WRITE / "profile.lock.json",
        provider_service="airtable-gateway-demo", provider_tool="set_demo_status_v2",
        recipe_digest=WRITE_DIGEST,
        read_recipe_path=HERE / "recipe.json",
        read_profile_lock_path=HERE / "profile.lock.json",
        read_service="airtable-delegation-demo", read_tool="release_demo_status_v2",
        read_recipe_digest=READ_DIGEST, output=authority,
    )
    issued = json.loads(authority.read_bytes())
    _private_write(operator / "trusted-context.cbor",
                   base64.urlsafe_b64decode(issued["trusted_template_b64"]))
    write_connection = _gateway(
        binary, "install", "--state-dir", state,
        "--recipe", WRITE / "recipe.json",
        "--profile-lock", WRITE / "profile.lock.json",
        "--trusted-context", operator / "trusted-context.cbor",
        "--approve-digest", WRITE_DIGEST, "--provider", "airtable",
        "--alias", "ap071-write", "--account-label", ACCOUNT,
        "--credential-stdin", "--connection-json", "--deployment", "development",
        secret=token.encode("ascii"),
    )
    read_connection = _gateway(
        binary, "task-read-connect", "--state-dir", state,
        "--recipe", HERE / "recipe.json",
        "--profile-lock", HERE / "profile.lock.json",
        "--approve-digest", READ_DIGEST, "--provider", "airtable",
        "--alias", "ap071-read", "--account-subject", ACCOUNT,
        "--credential-stdin", secret=token.encode("ascii"),
    )
    read_scope = {
        "handle": record, "recipe_digest": READ_DIGEST,
        "connection_id": read_connection["connection_id"],
        "connection_generation": read_connection["connection_generation"],
        "connection_subject": ACCOUNT,
    }
    installation = operator / "task-installation.json"
    _write_json(installation, {
        "schema": "auths.gateway-task-installation/3",
        "recipe_digests": [WRITE_DIGEST], "pins": {
            "company_id": "ap071-conformance", "human_principal": human_principal,
            "agent_principal": agent_principal,
            "agent_key_fingerprint": agent_digest,
            "connection_id": write_connection["connection_id"],
            "connection_generation": write_connection["credential_generation"],
            "connection_subject": ACCOUNT,
            "permitted_read_scopes": [read_scope],
            "delivery_channel": "airtable-agent-local",
            "operator_policy_digest": "d" * 64,
            "allow_bounded_writes": False,
        },
    })
    _gateway(binary, "task-configure", "--state-dir", state,
             "--from", installation)
    employee = EmployeeBinding(
        "ap071-conformance", "operator-person", "https://synthetic.local",
        ACCOUNT, human_principal, "operator-binding",
    )
    agent = AgentBinding("ap071-conformance", "operator-binding",
                         agent_principal, agent_digest)
    browser = TaskWriteBrowserFlow(
        authority_path=authority, installation_path=installation,
        recipe_path=WRITE / "recipe.json",
        profile_lock_path=WRITE / "profile.lock.json",
        read_recipe_path=HERE / "recipe.json",
        read_profile_lock_path=HERE / "profile.lock.json",
        private_output_dir=operator,
    )
    prepared = browser.prepare(
        employee=employee, agent=agent, employee_identity_packet=human_packet,
        agent_identity_packet=agent_packet, resource_handle=record,
        resource_label="Disposable Airtable record",
        read_resource_handle=record, read_resource_label="Current DemoStatus",
        account_label="Operator Airtable PAT", purpose="Read status, set Approved",
    )
    signed = browser.complete(
        nonce=prepared.nonce, employee=employee, agent=agent,
        grant_signature=human_key.sign(prepared.grant_preimage),
        read_grant_signature=human_key.sign(prepared.read_grant_preimage),
        task_signature=human_key.sign(prepared.task_preimage),
    )
    _gateway(binary, "task-activate", "--state-dir", state,
             "--proof", signed.private_task_dir / "task.proof",
             "--action", signed.private_task_dir / "task.action")
    channel = agent_dir / "release.sock"
    _gateway(binary, "task-read-configure", "--state-dir", state,
             "--agent-identity", operator / "agent.identity.cbor",
             "--channel-socket", channel,
             "--channel-name", "airtable-agent-local")
    _write_json(agent_dir / "read-package.json", signed.read_agent_package)
    _write_json(agent_dir / "write-package.json", signed.agent_package)
    common = {"task_id": signed.task_id,
              "task_commitment": task_commitment(prepared.card)}
    _write_json(agent_dir / "wrong-recipient-read-arguments.json", {
        **common, "operator_namespace": "airtable-read-demo",
        "operation_id": "airtable-read-wrong-recipient",
        "recipe_digest": READ_DIGEST,
        "resource_id": record,
        "agent_principal": "key:sha256:wrong-recipient",
    })
    wrong_recipient_output = _private_dir(
        agent_dir / "wrong-recipient-read-output", create=True)
    try:
        _agent("sign-read", "--key-file", agent_dir / "agent.seed",
               "--package-file", agent_dir / "read-package.json",
               "--arguments-file", agent_dir / "wrong-recipient-read-arguments.json",
               "--out-dir", wrong_recipient_output)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("agent signed a release to a different recipient")
    before_read = _gateway(binary, "task-status", "--state-dir", state,
                           "--task-id", signed.task_id)
    if ((wrong_recipient_output / "read.proof").exists()
            or (wrong_recipient_output / "read.action").exists()
            or before_read.get("provider_calls") != 0
            or before_read.get("releases") != 0):
        raise RuntimeError("wrong Airtable recipient entered provider or released content")
    wrong_recipe = "f" * 64
    wrong_recipe_package = dict(signed.read_agent_package)
    wrong_recipe_package["recipe_digest"] = wrong_recipe
    _write_json(agent_dir / "wrong-recipe-read-package.json", wrong_recipe_package)
    _write_json(agent_dir / "wrong-recipe-read-arguments.json", {
        **common, "operator_namespace": "airtable-read-demo",
        "operation_id": "airtable-read-wrong-recipe",
        "recipe_digest": wrong_recipe, "resource_id": record,
        "agent_principal": agent_principal,
    })
    wrong_recipe_output = _private_dir(
        agent_dir / "wrong-recipe-read-output", create=True)
    _agent("sign-read", "--key-file", agent_dir / "agent.seed",
           "--package-file", agent_dir / "wrong-recipe-read-package.json",
           "--arguments-file", agent_dir / "wrong-recipe-read-arguments.json",
           "--out-dir", wrong_recipe_output)
    wrong_recipe_result = _gateway(
        binary, "task-read-submit", "--state-dir", state,
        "--task-id", signed.task_id,
        "--agent-proof", wrong_recipe_output / "read.proof",
        "--agent-action", wrong_recipe_output / "read.action",
    )
    after_wrong_recipe = _gateway(binary, "task-status", "--state-dir", state,
                                  "--task-id", signed.task_id)
    if (wrong_recipe_result != {"outcome": "not-entered",
                                "code": "gateway.release.native-proof"}
            or after_wrong_recipe != before_read):
        raise RuntimeError("wrong Airtable recipe entered provider or spent task budget")
    excluded_record = record[:-1] + ("Z" if record[-1] != "Z" else "Y")
    _write_json(agent_dir / "excluded-read-arguments.json", {
        **common, "operator_namespace": "airtable-read-demo",
        "operation_id": "airtable-read-excluded", "recipe_digest": READ_DIGEST,
        "resource_id": excluded_record, "agent_principal": agent_principal,
    })
    excluded_output = _private_dir(agent_dir / "excluded-read-output", create=True)
    _agent("sign-read", "--key-file", agent_dir / "agent.seed",
           "--package-file", agent_dir / "read-package.json",
           "--arguments-file", agent_dir / "excluded-read-arguments.json",
           "--out-dir", excluded_output)
    excluded_receiver = _agent(
        "serve-release", "--key-file", agent_dir / "agent.seed",
        "--socket", channel, "--output", agent_dir / "excluded-source.bin",
        "--task-id", signed.task_id,
        "--task-commitment", common["task_commitment"],
        "--operation-id", "airtable-read-excluded",
        "--resource-handle", excluded_record,
        "--channel-name", "airtable-agent-local", wait=False,
    )
    try:
        _wait_for(channel, excluded_receiver)
        excluded = _gateway(
            binary, "task-read-submit", "--state-dir", state,
            "--task-id", signed.task_id,
            "--agent-proof", excluded_output / "read.proof",
            "--agent-action", excluded_output / "read.action",
        )
    finally:
        if excluded_receiver.poll() is None:
            excluded_receiver.terminate()
        excluded_receiver.communicate(timeout=5)
        if channel.is_socket():
            channel.unlink()
    zero = _gateway(binary, "task-status", "--state-dir", state,
                    "--task-id", signed.task_id)
    if (excluded != {"outcome": "not-entered", "code": "gateway.release.scope"}
            or zero.get("provider_calls") != 0
            or zero.get("releases") != 0):
        raise RuntimeError("excluded Airtable read entered provider or released content")
    read_operation = "airtable-read-one"
    _write_json(agent_dir / "read-arguments.json", {
        **common, "operator_namespace": "airtable-read-demo",
        "operation_id": read_operation, "recipe_digest": READ_DIGEST,
        "resource_id": record, "agent_principal": agent_principal,
    })
    read_output = _private_dir(agent_dir / "read-output", create=True)
    _agent("sign-read", "--key-file", agent_dir / "agent.seed",
           "--package-file", agent_dir / "read-package.json",
           "--arguments-file", agent_dir / "read-arguments.json",
           "--out-dir", read_output)
    if revoke_before_actions:
        write_operation = "airtable-write-after-revoke"
        _write_json(agent_dir / "revoked-write-arguments.json", {
            **common, "operator_namespace": "airtable-demo",
            "operation_id": write_operation, "recipe_digest": WRITE_DIGEST,
            "record_id": record, "replacement": "Approved",
        })
        write_output = _private_dir(agent_dir / "revoked-write-output", create=True)
        _agent("sign-write", "--key-file", agent_dir / "agent.seed",
               "--package-file", agent_dir / "write-package.json",
               "--arguments-file", agent_dir / "revoked-write-arguments.json",
               "--out-dir", write_output)
        _private_write(signed.private_task_dir / "agent.proof",
                       (write_output / "agent.proof").read_bytes())
        _private_write(signed.private_task_dir / "agent.action",
                       (write_output / "agent.action").read_bytes())

        def revocation_preflight(card: dict, review: object) -> None:
            current = airtable.request("GET", row_path)
            if (card["write_scopes"][0]["handle"] != record
                    or review.arguments.get("record_id") != record
                    or review.arguments.get("replacement") != "Approved"
                    or current != before):
                raise RuntimeError("Airtable revocation proposal baseline changed")

        flow = TaskWriteConfirmationFlow(
            authority_path=authority, installation_path=installation,
            recipe_path=WRITE / "recipe.json",
            profile_lock_path=WRITE / "profile.lock.json",
            read_recipe_path=HERE / "recipe.json",
            read_profile_lock_path=HERE / "profile.lock.json",
            private_output_dir=operator, gateway_binary=binary,
            gateway_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            preflight=revocation_preflight, gateway_state_dir=state,
        )
        exact = flow.prepare(task_id=signed.task_id, employee=employee, agent=agent)
        flow.complete(nonce=exact.nonce, employee=employee, agent=agent,
                      signature=human_key.sign(exact.signing_preimage))
        prior = _gateway(binary, "task-status", "--state-dir", state,
                         "--task-id", signed.task_id)
        if (prior.get("provider_calls") != 0 or prior.get("releases") != 0
                or prior.get("writes") != 0):
            raise RuntimeError("revocation task spent budget before revocation")
        _gateway(binary, "task-revoke", "--state-dir", state,
                 "--task-id", signed.task_id)
        revoked_read = _gateway(
            binary, "task-read-submit", "--state-dir", state,
            "--task-id", signed.task_id,
            "--agent-proof", read_output / "read.proof",
            "--agent-action", read_output / "read.action",
        )
        revoked_write = _gateway(
            binary, "task-submit", "--state-dir", state,
            "--task-id", signed.task_id,
            "--agent-proof", signed.private_task_dir / "agent.proof",
            "--agent-action", signed.private_task_dir / "agent.action",
            "--confirmation-proof", signed.private_task_dir / "confirmation.proof",
            "--confirmation-action", signed.private_task_dir / "confirmation.action",
        )
        after_revoke = _gateway(binary, "task-status", "--state-dir", state,
                                "--task-id", signed.task_id)
        after_provider = airtable.request("GET", row_path)
        if (revoked_read != {"outcome": "not-entered",
                             "code": "gateway.release.task-inactive"}
                or revoked_write != {"outcome": "not-entered",
                                    "code": "gateway.task.inactive"}
                or after_revoke.get("provider_calls") != 0
                or after_revoke.get("releases") != 0
                or after_revoke.get("writes") != 0
                or after_provider != before):
            raise RuntimeError("revoked Airtable task reached provider or changed record")
        _write_json(operator / "redacted-result.json", {
            "schema": "auths.ap071-airtable-revocation/1",
            "task_id": signed.task_id, "record_id": record,
            "read_operation_id": read_operation,
            "write_operation_id": write_operation,
            "read_outcome": revoked_read,
            "write_outcome": revoked_write,
            "gateway_status": after_revoke,
            "independent_readback": "unchanged-pending",
            "cleanup": "pending",
        })
        print(json.dumps({
            "status": "installed-airtable-revocation-observed",
            "task_id": signed.task_id, "record_id": record,
            "result": str(operator / "redacted-result.json"),
            "cleanup": "pending",
        }, sort_keys=True))
        airtable.close()
        return
    source = agent_dir / "released-status.txt"
    server = _agent("serve-release-lossy" if drop_ack else "serve-release",
                    "--key-file", agent_dir / "agent.seed",
                    "--socket", channel, "--output", source,
                    "--task-id", signed.task_id,
                    "--task-commitment", common["task_commitment"],
                    "--operation-id", read_operation,
                    "--resource-handle", record,
                    "--channel-name", "airtable-agent-local", wait=False)
    try:
        _wait_for(channel, server)
        release = _gateway(
            binary, "task-read-submit", "--state-dir", state,
            "--task-id", signed.task_id,
            "--agent-proof", read_output / "read.proof",
            "--agent-action", read_output / "read.action",
            *(("--fail-before-content",) if fail_before_content else ()),
        )
        server.communicate(timeout=15)
        if not fail_before_content and server.returncode != 0:
            raise RuntimeError("agent did not acknowledge the Airtable release")
        if fail_before_content and server.returncode == 0:
            raise RuntimeError("agent completed despite the no-send fault")
    finally:
        if server.poll() is None:
            server.terminate()
            server.communicate(timeout=5)
    if fail_before_content and source.exists():
        raise RuntimeError("agent received content after the no-send fault")
    if not fail_before_content and source.read_bytes() != b"Pending":
        raise RuntimeError("agent received unexpected Airtable content")
    if drop_ack or fail_before_content:
        status = _gateway(binary, "task-status", "--state-dir", state,
                          "--task-id", signed.task_id)
        expected_stage = "not-delivered" if fail_before_content else "delivery-unknown"
        if (release != {"outcome": expected_stage}
                or status.get("provider_calls") != 1
                or status.get("releases") != 1
                or status.get("released_bytes") != 7
                or status.get("reads") != [{
                    "operation_id": read_operation, "released_bytes": 7,
                    "stage": expected_stage,
                }]):
            raise RuntimeError("release fault was misaccounted")
        replay_receiver = _agent(
            "serve-release", "--key-file", agent_dir / "agent.seed",
            "--socket", channel, "--output", agent_dir / "replay-source.bin",
            "--task-id", signed.task_id,
            "--task-commitment", common["task_commitment"],
            "--operation-id", read_operation,
            "--resource-handle", record,
            "--channel-name", "airtable-agent-local", wait=False,
        )
        try:
            _wait_for(channel, replay_receiver)
            replay = _gateway(
                binary, "task-read-submit", "--state-dir", state,
                "--task-id", signed.task_id,
                "--agent-proof", read_output / "read.proof",
                "--agent-action", read_output / "read.action",
            )
        finally:
            if replay_receiver.poll() is None:
                replay_receiver.terminate()
            replay_receiver.communicate(timeout=5)
            if channel.is_socket():
                channel.unlink()
        after_replay = _gateway(binary, "task-status", "--state-dir", state,
                                "--task-id", signed.task_id)
        if (replay != {"outcome": "not-entered",
                       "code": "gateway.release.task-admission"}
                or after_replay != status
                or (agent_dir / "replay-source.bin").exists()):
            raise RuntimeError("faulted read was delivered a second time")
        _write_json(operator / "redacted-result.json", {
            "schema": ("auths.ap071-airtable-no-send/1" if fail_before_content
                       else "auths.ap071-airtable-lost-ack/1"),
            "task_id": signed.task_id, "record_id": record,
            "read_operation_id": read_operation,
            "read_outcome": release["outcome"],
            "agent_saved_exact_bytes": drop_ack,
            "replay_outcome": replay["outcome"],
            "replay_code": replay["code"],
            "gateway_status": status,
            "cleanup": "pending",
        })
        print(json.dumps({
            "status": ("installed-airtable-no-send-observed" if fail_before_content
                       else "installed-airtable-lost-ack-observed"),
            "task_id": signed.task_id, "record_id": record,
            "result": str(operator / "redacted-result.json"),
            "cleanup": "pending",
        }, sort_keys=True))
        airtable.close()
        return
    _gateway(binary, "task-release-compare", "--state-dir", state,
             "--task-id", signed.task_id, "--operation-id", read_operation,
             "--resource-handle", record, "--source-file", source,
             secret=hashlib.sha256(source.read_bytes()).hexdigest().encode("ascii"))
    write_operation = "airtable-write-one"
    _write_json(agent_dir / "write-arguments.json", {
        **common, "operator_namespace": "airtable-demo",
        "operation_id": write_operation, "recipe_digest": WRITE_DIGEST,
        "record_id": record, "replacement": "Approved",
    })
    write_output = _private_dir(agent_dir / "write-output", create=True)
    _agent("sign-write", "--key-file", agent_dir / "agent.seed",
           "--package-file", agent_dir / "write-package.json",
           "--arguments-file", agent_dir / "write-arguments.json",
           "--out-dir", write_output)
    _private_write(signed.private_task_dir / "agent.proof",
                   (write_output / "agent.proof").read_bytes())
    _private_write(signed.private_task_dir / "agent.action",
                   (write_output / "agent.action").read_bytes())

    def preflight(card: dict, review: object) -> None:
        current = airtable.request("GET", row_path)
        if (card["write_scopes"][0]["handle"] != record
                or review.arguments.get("record_id") != record
                or review.arguments.get("replacement") != "Approved"
                or current.get("id") != record
                or current.get("fields", {}).get("DemoStatus") != "Pending"):
            raise RuntimeError("Airtable exact write preflight changed")

    flow = TaskWriteConfirmationFlow(
        authority_path=authority, installation_path=installation,
        recipe_path=WRITE / "recipe.json",
        profile_lock_path=WRITE / "profile.lock.json",
        read_recipe_path=HERE / "recipe.json",
        read_profile_lock_path=HERE / "profile.lock.json",
        private_output_dir=operator, gateway_binary=binary,
        gateway_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        preflight=preflight, gateway_state_dir=state,
    )
    exact = flow.prepare(task_id=signed.task_id, employee=employee, agent=agent)
    flow.complete(nonce=exact.nonce, employee=employee, agent=agent,
                  signature=human_key.sign(exact.signing_preimage))
    outcome = flow.submit(task_id=signed.task_id, employee=employee, agent=agent)
    after = airtable.request("GET", row_path)
    if (after.get("id") != record
            or after.get("fields", {}).get("DemoStatus") != "Approved"
            or not after.get("fields", {}).get("auths_echo")):
        raise RuntimeError("independent Airtable effect readback disagrees")
    status = _gateway(binary, "task-status", "--state-dir", state,
                      "--task-id", signed.task_id)
    replay = _gateway(
        binary, "task-submit", "--state-dir", state,
        "--task-id", signed.task_id,
        "--agent-proof", signed.private_task_dir / "agent.proof",
        "--agent-action", signed.private_task_dir / "agent.action",
        "--confirmation-proof", signed.private_task_dir / "confirmation.proof",
        "--confirmation-action", signed.private_task_dir / "confirmation.action",
    )
    after_replay = _gateway(binary, "task-status", "--state-dir", state,
                            "--task-id", signed.task_id)
    replay_readback = airtable.request("GET", row_path)
    if (replay.get("outcome") != "not-entered"
            or after_replay != status or replay_readback != after):
        raise RuntimeError("Airtable write replay entered provider or changed effect")
    _write_json(operator / "redacted-result.json", {
        "schema": "auths.ap071-airtable-conformance/1",
        "task_id": signed.task_id, "record_id": record,
        "read_operation_id": read_operation, "write_operation_id": write_operation,
        "read_outcome": release.get("outcome"),
        "write_outcome": outcome.get("outcome"),
        "independent_readback": "approved-with-echo",
        "excluded_read_outcome": excluded.get("outcome"),
        "excluded_read_code": excluded.get("code"),
        "wrong_recipe_outcome": wrong_recipe_result.get("outcome"),
        "wrong_recipe_code": wrong_recipe_result.get("code"),
        "wrong_recipient_outcome": "agent-signing-refused",
        "write_replay_outcome": replay.get("outcome"),
        "write_replay_code": replay.get("code"),
        "gateway_status": status,
        "cleanup": "pending",
    })
    print(json.dumps({"status": "installed-airtable-conformance-observed",
                      "task_id": signed.task_id, "record_id": record,
                      "result": str(operator / "redacted-result.json"),
                      "cleanup": "pending"}, sort_keys=True))
    airtable.close()


def cleanup(env_file: Path, root: Path) -> None:
    root = _private_dir(root)
    token = _token(env_file)
    airtable = Airtable(token)
    try:
        Resources(token, api=airtable.request).cleanup(root / "resources.json")
    finally:
        airtable.close()
    report = root / "operator" / "redacted-result.json"
    if report.exists():
        document = json.loads(report.read_bytes())
        document["cleanup"] = "run-owned-record-retired"
        replacement = report.with_name("redacted-result.next")
        _write_json(replacement, document)
        os.replace(replacement, report)
    print(json.dumps({"status": "run-owned-record-retired", "root": str(root)},
                     sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "cleanup"))
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--gateway-bin", type=Path)
    parser.add_argument("--drop-ack", action="store_true",
                        help="receive bytes but deliberately lose agent ACK")
    parser.add_argument("--fail-before-content", action="store_true",
                        help="development gateway fault after release charge, before content")
    parser.add_argument("--revoke-before-actions", action="store_true",
                        help="revoke after both actions are signed but before provider entry")
    args = parser.parse_args()
    if args.command == "run":
        if args.gateway_bin is None:
            parser.error("run needs the reviewed gateway binary")
        run(args.env_file, args.root, args.gateway_bin,
            drop_ack=args.drop_ack,
            fail_before_content=args.fail_before_content,
            revoke_before_actions=args.revoke_before_actions)
    else:
        cleanup(args.env_file, args.root)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print provider responses or bearer material from an unexpected
        # exception. The private ownership journal remains for cleanup.
        print("ap071.airtable.conformance-refused: " + type(error).__name__,
              file=sys.stderr)
        raise SystemExit(1) from None
