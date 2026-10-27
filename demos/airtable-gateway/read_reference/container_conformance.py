#!/usr/bin/env python3
"""Run one source-free AP-071 Airtable read/write task across isolated containers.

The operator runs this driver outside both containers. Only the gateway mounts
its state and operator proofs; only the agent mounts its seed and release
output. The PAT enters the gateway's private development credential store via
stdin, and the operator retains a separate disposable-record cleanup journal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)
from auths.identity.authoring import create_raw_key_ed25519_identity

from employee_read_demo.agent_registry import AgentBinding
from employee_read_demo.authority_identity import authority_for_identity_packet
from employee_read_demo.enrollment import EmployeeBinding, EnrollmentStore
from employee_read_demo.operator_cli import _private_write, init_root
from employee_read_demo.task_write_browser import TaskWriteBrowserFlow
from employee_read_demo.task_write_confirmation import TaskWriteConfirmationFlow
from employee_read_demo.task_write_operator_cli import issue_task_package
from employee_read_demo.task_write_proofs import task_commitment

from airtable_resources import Resources
from installed_conformance import (
    ACCOUNT, BASE, READ_DIGEST, TABLE, WRITE_DIGEST, Airtable, _private_dir,
    _token, _write_json,
)


HERE = Path(__file__).resolve().parent
WRITE = HERE.parent / "write_reference"
GATEWAY_BIN = "/usr/local/bin/auths-gateway"


def _docker(container: str, *argv: str, secret: bytes | None = None,
            timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", "exec", "-i", container, *map(str, argv)],
        input=secret if secret is not None else b"", capture_output=True,
        timeout=timeout, check=False,
    )


def _gateway(container: str, command: str, *args: str,
             secret: bytes | None = None) -> dict:
    argv = list(map(str, args))
    if "--task-id" in argv:
        index = argv.index("--task-id")
        argv[index:index + 2] = ["--task-id=" + argv[index + 1]]
    result = _docker(container, GATEWAY_BIN, command, *argv, secret=secret)
    if result.returncode != 0 or len(result.stdout) > 131_072:
        raise RuntimeError("installed container gateway " + command + " refused")
    value = json.loads(result.stdout)
    if type(value) is not dict:
        raise RuntimeError("installed container gateway returned malformed status")
    return value


def _agent(container: str, command: str, *args: str) -> None:
    result = _docker(container, "python", "-m", "employee_read_agent.cli",
                     command, *args, timeout=45)
    if result.returncode != 0:
        raise RuntimeError("installed container agent " + command + " refused")


def _mounted(containers: tuple[str, str], root: Path) -> None:
    agent, gateway = containers
    result = subprocess.run(["docker", "inspect", agent, gateway],
                            capture_output=True, check=True, timeout=15)
    entries = {item["Name"].lstrip("/"): item for item in json.loads(result.stdout)}
    if set(entries) != {agent, gateway}:
        raise ValueError("container identity changed")
    a, g = entries[agent], entries[gateway]
    def mounts(item: dict) -> dict[str, dict]:
        return {m["Destination"]: m for m in item["Mounts"]}
    def host_source(mount: dict, path: Path) -> bool:
        # Docker Desktop may expose one bind through its Linux /host_mnt path.
        return mount.get("Source") in {str(path), "/host_mnt" + str(path)}
    am, gm = mounts(a), mounts(g)
    if (a["HostConfig"]["NetworkMode"] != "none"
            or not a["HostConfig"]["ReadonlyRootfs"]
            or not g["HostConfig"]["ReadonlyRootfs"]
            or a["Config"]["User"] != g["Config"]["User"]
            or not host_source(am.get("/agent", {}), root / "agent")
            or not host_source(gm.get("/gateway-state", {}), root / "gateway")
            or not host_source(gm.get("/operator", {}), root / "operator")
            or gm["/operator"]["RW"] is not False
            or am.get("/channel", {}).get("Type") != "volume"
            or gm.get("/channel", {}).get("Name") != am["/channel"]["Name"]
            or gm["/channel"]["RW"] is not False
            or "/operator" in am or "/gateway-state" in am
            or "/agent" in gm):
        raise ValueError("AP-071 container isolation mounts changed")
    probe = _docker(agent, "python", "-m", "employee_read_agent.isolation_probe")
    if probe.returncode != 0 or json.loads(probe.stdout).get("passed") is not True:
        raise ValueError("installed agent isolation probe refused")


def _socket_ready(gateway: str, receiver: subprocess.Popen[bytes]) -> None:
    for _ in range(150):
        if _docker(gateway, "test", "-S", "/channel/agent.sock", timeout=5).returncode == 0:
            return
        if receiver.poll() is not None:
            raise RuntimeError("isolated agent receiver exited before channel ready")
        time.sleep(0.1)
    raise RuntimeError("isolated agent channel did not become ready")


def run(env_file: Path, root: Path, agent_container: str,
        gateway_container: str, reviewed_gateway: Path) -> None:
    root = _private_dir(root)
    operator = _private_dir(root / "operator")
    agent_dir = _private_dir(root / "agent")
    state = _private_dir(root / "gateway")
    _mounted((agent_container, gateway_container), root)
    token = _token(env_file)
    airtable = Airtable(token)
    resources = Resources(token, api=airtable.request)
    journal, pool = root / "resources.json", root / "record-pool.json"
    run_id = f"ap071-container/{int(time.time())}/{secrets.randbelow(10**12 - 1) + 1}"
    resources.prepare(run_id, 1, journal, pool)
    record = json.loads(pool.read_bytes())["records"][0]["id"]
    row_path = f"/v0/{BASE}/{TABLE}/{record}"
    before = airtable.request("GET", row_path)
    if before.get("id") != record or before.get("fields", {}).get("DemoStatus") != "Pending":
        raise RuntimeError("disposable Airtable baseline changed")

    root_seed, root_trust = operator / "root.seed", operator / "root-trust.json"
    init_root(root_seed, root_trust, company="ap071-container",
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
                "operator-binding", "ap071-container", "operator-person",
                "https://synthetic.local", ACCOUNT, human_principal,
                human_packet, "a" * 64,
            ))
    agent_key = Ed25519PrivateKey.generate()
    _private_write(agent_dir / "agent.seed", agent_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    agent_packet = create_raw_key_ed25519_identity(
        agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).to_bytes()
    agent_principal, _ = authority_for_identity_packet(agent_packet)
    _private_write(operator / "agent.identity.cbor", agent_packet)
    agent_digest = hashlib.sha256(agent_packet).hexdigest()
    authority = operator / "task-authority.json"
    issue_task_package(
        root_seed=root_seed, root_trust=root_trust, state_db=broker_db,
        binding_ref="operator-binding", company="ap071-container",
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
    for name, source in (
        ("write-recipe.json", WRITE / "recipe.json"),
        ("write-lock.json", WRITE / "profile.lock.json"),
        ("read-recipe.json", HERE / "recipe.json"),
        ("read-lock.json", HERE / "profile.lock.json"),
    ):
        _private_write(operator / name, source.read_bytes())
    installed_write = _gateway(
        gateway_container, "install", "--state-dir", "/gateway-state",
        "--recipe", "/operator/write-recipe.json",
        "--profile-lock", "/operator/write-lock.json",
        "--trusted-context", "/operator/trusted-context.cbor",
        "--approve-digest", WRITE_DIGEST, "--provider", "airtable",
        "--alias", "ap071-container-write", "--account-label", ACCOUNT,
        "--credential-stdin", "--connection-json", "--deployment", "development",
        secret=token.encode("ascii"),
    )
    installed_read = _gateway(
        gateway_container, "task-read-connect", "--state-dir", "/gateway-state",
        "--recipe", "/operator/read-recipe.json",
        "--profile-lock", "/operator/read-lock.json",
        "--approve-digest", READ_DIGEST, "--provider", "airtable",
        "--alias", "ap071-container-read", "--account-subject", ACCOUNT,
        "--credential-stdin", secret=token.encode("ascii"),
    )
    read_scope = {
        "handle": record, "recipe_digest": READ_DIGEST,
        "connection_id": installed_read["connection_id"],
        "connection_generation": installed_read["connection_generation"],
        "connection_subject": ACCOUNT,
    }
    installation = operator / "task-installation.json"
    _write_json(installation, {
        "schema": "auths.gateway-task-installation/4",
        "recipe_digests": [WRITE_DIGEST], "pins": {
            "company_id": "ap071-container", "initiator_principal": human_principal, "approver_principal": human_principal,
            "agent_principal": agent_principal,
            "agent_key_fingerprint": agent_digest,
            "connection_id": installed_write["connection_id"],
            "connection_generation": installed_write["credential_generation"],
            "connection_subject": ACCOUNT,
            "permitted_read_scopes": [read_scope],
            "delivery_channel": "airtable-agent-container",
            "operator_policy_digest": "d" * 64,
            "allow_bounded_writes": False,
        },
    })
    _gateway(gateway_container, "task-configure", "--state-dir", "/gateway-state",
             "--from", "/operator/task-installation.json")
    employee = EmployeeBinding(
        "ap071-container", "operator-person", "https://synthetic.local",
        ACCOUNT, human_principal, "operator-binding",
    )
    agent = AgentBinding("ap071-container", "operator-binding",
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
    task_id = signed.task_id
    task_dir = signed.private_task_dir
    _gateway(gateway_container, "task-activate", "--state-dir", "/gateway-state",
             "--proof", f"/operator/{task_id}/task.proof",
             "--action", f"/operator/{task_id}/task.action")
    _gateway(gateway_container, "task-read-configure", "--state-dir", "/gateway-state",
             "--agent-identity", "/operator/agent.identity.cbor",
             "--channel-socket", "/channel/agent.sock",
             "--channel-name", "airtable-agent-container")
    _write_json(agent_dir / "read-package.json", signed.read_agent_package)
    _write_json(agent_dir / "write-package.json", signed.agent_package)
    common = {"task_id": task_id, "task_commitment": task_commitment(prepared.card)}
    read_operation = "airtable-container-read"
    _write_json(agent_dir / "read-arguments.json", {
        **common, "operator_namespace": "airtable-read-demo",
        "operation_id": read_operation, "recipe_digest": READ_DIGEST,
        "resource_id": record, "agent_principal": agent_principal,
    })
    _private_dir(agent_dir / "read-output", create=True)
    _agent(agent_container, "sign-read", "--key-file", "/agent/agent.seed",
           "--package-file", "/agent/read-package.json",
           "--arguments-file", "/agent/read-arguments.json",
           "--out-dir", "/agent/read-output")
    _private_write(operator / "read.proof", (agent_dir / "read-output/read.proof").read_bytes())
    _private_write(operator / "read.action", (agent_dir / "read-output/read.action").read_bytes())
    receiver = subprocess.Popen([
        "docker", "exec", agent_container, "python", "-m",
        "employee_read_agent.cli", "serve-release",
        "--key-file", "/agent/agent.seed", "--socket", "/channel/agent.sock",
        "--output", "/agent/released-status.txt", "--task-id", task_id,
        "--task-commitment", common["task_commitment"],
        "--operation-id", read_operation, "--resource-handle", record,
        "--channel-name", "airtable-agent-container",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _socket_ready(gateway_container, receiver)
        release = _gateway(gateway_container, "task-read-submit",
                           "--state-dir", "/gateway-state", "--task-id", task_id,
                           "--agent-proof", "/operator/read.proof",
                           "--agent-action", "/operator/read.action")
        receiver.communicate(timeout=20)
        if receiver.returncode != 0:
            raise RuntimeError("isolated agent did not acknowledge release")
    finally:
        if receiver.poll() is None:
            receiver.terminate()
            receiver.communicate(timeout=5)
    if release.get("outcome") != "agent-acknowledged":
        raise RuntimeError("isolated gateway release was not acknowledged")
    if (agent_dir / "released-status.txt").read_bytes() != b"Pending":
        raise RuntimeError("isolated agent received unexpected source")

    write_operation = "airtable-container-write"
    _write_json(agent_dir / "write-arguments.json", {
        **common, "operator_namespace": "airtable-demo",
        "operation_id": write_operation, "recipe_digest": WRITE_DIGEST,
        "record_id": record, "replacement": "Approved",
    })
    _private_dir(agent_dir / "write-output", create=True)
    _agent(agent_container, "sign-write", "--key-file", "/agent/agent.seed",
           "--package-file", "/agent/write-package.json",
           "--arguments-file", "/agent/write-arguments.json",
           "--out-dir", "/agent/write-output")
    _private_write(task_dir / "agent.proof",
                   (agent_dir / "write-output/agent.proof").read_bytes())
    _private_write(task_dir / "agent.action",
                   (agent_dir / "write-output/agent.action").read_bytes())

    def preflight(card: dict, review: object) -> None:
        current = airtable.request("GET", row_path)
        if (card["write_scopes"][0]["handle"] != record
                or review.arguments.get("record_id") != record
                or review.arguments.get("replacement") != "Approved"
                or current.get("id") != record
                or current.get("fields", {}).get("DemoStatus") != "Pending"):
            raise RuntimeError("isolated exact write preflight changed")

    flow = TaskWriteConfirmationFlow(
        authority_path=authority, installation_path=installation,
        recipe_path=WRITE / "recipe.json",
        profile_lock_path=WRITE / "profile.lock.json",
        read_recipe_path=HERE / "recipe.json",
        read_profile_lock_path=HERE / "profile.lock.json",
        private_output_dir=operator, gateway_binary=reviewed_gateway,
        gateway_sha256=hashlib.sha256(reviewed_gateway.read_bytes()).hexdigest(),
        preflight=preflight, gateway_state_dir=state,
    )
    exact = flow.prepare(task_id=task_id, employee=employee, agent=agent)
    flow.complete(nonce=exact.nonce, employee=employee, agent=agent,
                  signature=human_key.sign(exact.signing_preimage))
    outcome = _gateway(
        gateway_container, "task-submit", "--state-dir", "/gateway-state",
        "--task-id", task_id,
        "--agent-proof", f"/operator/{task_id}/agent.proof",
        "--agent-action", f"/operator/{task_id}/agent.action",
        "--confirmation-proof", f"/operator/{task_id}/confirmation.proof",
        "--confirmation-action", f"/operator/{task_id}/confirmation.action",
    )
    after = airtable.request("GET", row_path)
    if (outcome.get("outcome") not in {"observed-by-provider", "observed", "response-recorded"}
            or after.get("id") != record
            or after.get("fields", {}).get("DemoStatus") != "Approved"
            or not after.get("fields", {}).get("auths_echo")):
        raise RuntimeError("isolated provider write was not independently observed")
    status = _gateway(gateway_container, "task-status", "--state-dir",
                      "/gateway-state", "--task-id", task_id)
    if (status.get("provider_calls") != 1 or status.get("releases") != 1
            or status.get("released_bytes") != 7 or status.get("writes") != 1):
        raise RuntimeError("isolated task budgets disagreed with provider effects")
    _write_json(operator / "redacted-result.json", {
        "schema": "auths.ap071-container-read-write/1",
        "task_id": task_id, "record_id": record,
        "read_operation_id": read_operation, "write_operation_id": write_operation,
        "read_outcome": release["outcome"], "write_outcome": outcome["outcome"],
        "provider_calls": status["provider_calls"],
        "releases": status["releases"], "released_bytes": status["released_bytes"],
        "writes": status["writes"],
        "independent_readback": "approved-with-echo",
        "agent_isolation": "installed-probe-passed",
        "cleanup": "pending",
    })
    print(json.dumps({
        "status": "installed-container-read-write-observed",
        "task_id": task_id, "record_id": record,
        "result": str(operator / "redacted-result.json"), "cleanup": "pending",
    }, sort_keys=True))
    airtable.close()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--agent-container", required=True)
    parser.add_argument("--gateway-container", required=True)
    parser.add_argument("--reviewed-gateway", type=Path, required=True)
    args = parser.parse_args()
    run(args.env_file, args.root, args.agent_container,
        args.gateway_container, args.reviewed_gateway)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ap071.airtable.container-refused: " + type(error).__name__,
              file=__import__("sys").stderr)
        raise SystemExit(1) from None
