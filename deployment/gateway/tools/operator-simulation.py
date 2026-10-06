#!/usr/bin/env python3
"""A labeled operator rehearsal using downloaded binaries, never a source build."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time


class Refusal(Exception):
    """Only a bounded, non-secret diagnostic reaches the public report."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def private_tree(path, uid, gid):
    for item in [path, *path.rglob("*")]:
        require(not item.is_symlink(), "simulation.unexpected-symlink")
        os.chown(item, uid, gid)


class Operator:
    def __init__(self, package, inputs, work, sockets):
        self.binary = package / "bin/auths-gateway"
        self.qualification = package / "bin/auths-qualification"
        self.inputs, self.work, self.sockets = inputs, work, sockets
        self.steps, self.servers = [], {}
        self.uid, self.gid, self.app_uid = 62001, 62000, 62002
        fixture = json.loads((inputs / "custody-hostile.json").read_text())
        self.sources = [{"source": entry["source"],
                         "canary": "synthetic-simulation-" + os.urandom(16).hex()}
                        for entry in fixture["redaction"]["canaries"]["sources"]]
        require(len(self.sources) == 11, "simulation.canary-inventory")
        self.canaries = [entry["canary"].encode() for entry in self.sources]
        self.secret = next(e["canary"].encode() for e in self.sources if e["source"] == "credential")
        self.account = next(e["canary"] for e in self.sources if e["source"] == "provider-account-id")
        self.rotated = ("synthetic-simulation-rotation-" + os.urandom(16).hex()).encode()
        self.canaries.append(self.rotated)

    def scan(self, data):
        for canary in self.canaries:
            needles = [canary, canary.hex().encode(), canary.hex().upper().encode()]
            for padding in range(3):
                # Exclude sextets containing padding bytes or trailing partial bits.
                start = (padding * 8 + 5) // 6
                end = ((padding + len(canary)) * 8) // 6
                for encode in (base64.b64encode, base64.urlsafe_b64encode):
                    needles.append(encode(b"\0" * padding + canary)[start:end])
            require(not any(needle in data for needle in needles), "simulation.canary-exposure")

    def run(self, label, args, stdin=b"", success=True, code=None, root=False, env=None, binary=None):
        started = time.monotonic()
        record = {"step": label, "command": args[0], "seconds": None, "passed": False}
        self.steps.append(record)
        options = {} if root else {"user": self.uid, "group": self.gid, "extra_groups": []}
        result = subprocess.run(
            [str(binary or self.binary), *map(str, args)], input=stdin,
            capture_output=True, timeout=65, cwd=self.work,
            env={"PATH": "/usr/bin:/bin", **(env or {})}, **options,
        )
        record["seconds"] = round(time.monotonic() - started, 3)
        record["exit_code"] = result.returncode
        self.scan(result.stdout + result.stderr)
        require(len(result.stdout) + len(result.stderr) <= 1024 * 1024, "simulation.output-bound")
        require((result.returncode == 0) == success, "simulation.command-exit")
        if code:
            require(code.encode() in result.stderr or code.encode() in result.stdout, "simulation.expected-code")
            record["code"] = code
        record["passed"] = True
        return result.stdout

    def json(self, label, args, **kwargs):
        return json.loads(self.run(label, args, **kwargs))

    def install(self, state, store=None, join=False, secret=None, extra=(), label="install"):
        args = ["install", "--state-dir", state, "--recipe", self.inputs / "recipe.json",
                "--profile-lock", self.inputs / "profile.lock.json",
                "--trusted-context", self.inputs / "trusted.context.cbor",
                "--approve-digest", self.digest, "--provider", "airtable",
                "--alias", "simulation", "--credential-stdin",
                "--recipe-family", "operator-simulation-v1",
                "--provider-contract-id", "3" * 64]
        args += ["--join"] if join else ["--account-label", self.account]
        if store:
            args += ["--attempt-store", store]
        return self.run(label, [*args, *extra], stdin=(secret or self.secret) + b"\n")

    def start(self, state):
        started = time.monotonic()
        record = {"step": "start-" + state.name, "command": "serve", "passed": False}
        self.steps.append(record)
        app = self.sockets / (state.name + ".sock")
        log = tempfile.TemporaryFile()
        process = subprocess.Popen(
            [str(self.binary), "serve", "--state-dir", str(state), "--app-socket", str(app)],
            stdout=subprocess.PIPE, stderr=log, cwd=self.work,
            env={"PATH": "/usr/bin:/bin"}, user=self.uid, group=self.gid, extra_groups=[],
        )
        self.servers[state] = (process, log, app)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(15)), "simulation.start-timeout")
            ready = process.stdout.readline(65537)
        self.scan(ready)
        require(ready.startswith(b"app socket ready"), "simulation.start-refused")
        record.update(passed=True, seconds=round(time.monotonic() - started, 3))

    def stop(self, state):
        started = time.monotonic()
        record = {"step": "drain-" + state.name, "command": "SIGTERM", "passed": False}
        self.steps.append(record)
        process, log, app = self.servers.pop(state)
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise Refusal("simulation.shutdown-timeout")
        self.scan(process.stdout.read(65537))
        log.seek(0)
        self.scan(log.read(65537))
        log.close()
        process.stdout.close()
        require(process.returncode == 0, "simulation.shutdown-refused")
        require(not app.exists() and not (state / "admin.sock").exists(), "simulation.socket-not-removed")
        record.update(passed=True, seconds=round(time.monotonic() - started, 3))

    def admin(self, state, command, label=None, extra=(), stdin=b"", success=True, code=None):
        result = self.json(label or command + "-" + state.name,
                           [command, "--state-dir", state, *extra],
                           stdin=stdin, success=success, code=code)
        require(result["ok"] == success, "simulation.admin-verdict")
        return result

    def status(self, state):
        return self.admin(state, "status")["status"]

    def doctor(self, state):
        app = self.servers[state][2]
        report = self.json("diagnose-development-" + state.name,
                           ["doctor", "--state-dir", state, "--app-socket", app,
                            "--app-uid", str(self.app_uid), "--app-gid", str(self.gid)],
                           root=True, success=False, code="gateway.doctor.not-ready")
        require(report["schema"] == "auths.gateway-readiness/1" and not report["ready"],
                "simulation.false-production-readiness")
        checks = {row["check"]: row for row in report["checks"]}
        require(len(checks) == 10, "simulation.diagnostic-inventory")
        require(checks["operator-plane-isolation"]["ready"], "simulation.isolation-refused")
        require(not checks["provider-secret-custody"]["ready"], "simulation.plaintext-ready")
        require(checks["observer-custody"]["state"] == "not-configured", "simulation.optional-observer")
        return report

    def exercise(self):
        review = self.json("review-recipe", ["review", "--recipe", self.inputs / "recipe.json",
                                         "--profile-lock", self.inputs / "profile.lock.json"])
        self.digest = review["recipe_digest"]
        first, second, store = self.work / "first", self.work / "second", self.work / "store"
        self.install(first, store)
        self.install(second, store, join=True, label="join-second-host")
        for source in self.sources:
            (first / (source["source"] + ".captured")).write_text(source["canary"])
        private_tree(first, self.uid, self.gid)
        self.json("offline-support", ["support-bundle", "--state-dir", first])
        # These are shipped builds: neither test transport nor plaintext production is allowed.
        args = ["install", "--state-dir", self.work / "production", "--recipe",
                self.inputs / "recipe.json", "--profile-lock", self.inputs / "profile.lock.json",
                "--trusted-context", self.inputs / "trusted.context.cbor", "--approve-digest",
                self.digest, "--provider", "airtable", "--alias", "simulation",
                "--account-label", self.account, "--credential-stdin", "--deployment", "production"]
        self.run("refuse-production-plaintext", args, stdin=self.secret + b"\n", success=False,
                 code="gateway.credential.production-plaintext-refused")
        self.start(first)
        self.start(second)
        require(self.status(first)["credential_held"] and self.status(second)["credential_held"],
                "simulation.joined-custody")
        self.doctor(first)
        self.admin(first, "disable")
        require(self.status(second)["state"] == "disabled", "simulation.shared-disable")
        self.admin(second, "enable")
        require(self.status(first)["state"] == "active", "simulation.shared-enable")
        self.stop(first)
        self.stop(second)
        snapshot = self.work / "old-store"
        shutil.copytree(store, snapshot)
        self.start(first)
        self.start(second)
        self.admin(first, "disable")
        self.admin(second, "enable")
        self.status(first)
        self.status(second)
        self.stop(first)
        self.stop(second)
        current = self.work / "current-store"
        shutil.copytree(store, current)
        floor = (first / "connection-floor.json").read_bytes()
        shutil.rmtree(store)
        shutil.copytree(snapshot, store)
        private_tree(store, self.uid, self.gid)
        self.run("refuse-stale-restore",
                 ["rotate-prepare", "--state-dir", first, "--operator-process", "--credential-stdin"],
                 stdin=self.rotated + b"\n", success=False, code="gateway.admin.connection-unavailable")
        require((first / "connection-floor.json").read_bytes() == floor, "simulation.floor-replaced")
        shutil.rmtree(store)
        shutil.copytree(current, store)
        private_tree(store, self.uid, self.gid)
        # Development file custody is a process-local snapshot. Keep both hosts
        # drained while separate operator processes update those files;
        # production AWS readers resolve the published exact version instead.
        prepared = self.admin(first, "rotate-prepare", extra=["--operator-process", "--credential-stdin"],
                              stdin=self.rotated + b"\n")
        self.admin(first, "rotate-commit", extra=["--operator-process", "--commitment", prepared["commitment"]])
        # The development stores are host-local: the second host must adopt the same secret.
        self.admin(second, "rotate", extra=["--operator-process", "--credential-stdin"],
                   stdin=self.rotated + b"\n")
        self.start(first)
        self.start(second)
        one, two = self.status(first), self.status(second)
        require(one["credential_generation"] == two["credential_generation"]
                and one["credential_held"] and two["credential_held"], "simulation.rotation-diverged")
        self.json("redacted-support", ["support-bundle", "--state-dir", first],
                  env={"AUTHS_SIMULATION_CANARY": self.secret.decode()})
        self.admin(first, "reobserve", extra=["--operation-id", "simulation-no-such-operation"],
                   success=False, code="gateway.reobserve.not-observable")
        tuple_bytes = self.run("deployment-tuple", ["qualification-status", "--state-dir", first, "--tuple"])
        tuple_path = self.work / "tuple.json"
        tuple_path.write_bytes(tuple_bytes)
        os.chown(tuple_path, self.uid, self.gid)
        self.run("disposable-signer-rotation-and-freshness",
                 ["stage-trust", "--tuple", tuple_path, "--out", self.work / "trust-stage"],
                 binary=self.qualification)
        # Rolling restart retains the shared binding; there is no new candidate or live attestation.
        self.stop(first)
        self.start(first)
        require(self.status(first)["credential_generation"] == self.status(second)["credential_generation"],
                "simulation.restart-diverged")
        self.stop(first)
        self.stop(second)
        emergency = self.work / "emergency"
        self.install(emergency, label="install-outage-fixture")
        (emergency / "credentials.cbor").unlink()
        (emergency / "qualification-state.json").write_bytes(b"unavailable")
        for command, state in [("disable", "disabled"), ("disable", "disabled"),
                               ("revoke", "revoked"), ("disable", "revoked")]:
            result = self.json("outage-" + command,
                               [command, "--state-dir", emergency, "--store-only"])
            require(result["state"] == state and result["drainage"] == "not-checked"
                    and result["credential_deletion"] == "not-attempted", "simulation.false-outage-claim")

    def cleanup(self):
        for state in list(self.servers):
            process, log, _ = self.servers.pop(state)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            process.stdout.close()
            log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "auths.operator-simulation/1", "participant": "agent-simulation",
              "independent_human_trial": False, "production_qualification": False,
              "source_commit": args.expected_commit, "passed": False, "steps": [],
              "not_exercised": ["live AWS workload identity", "live provider writes and unknown recovery",
                                "production qualification import", "production PostgreSQL PITR",
                                "upgrade to a distinct attested candidate"],
              "friction": [{"code": "operator.platform-linux-only", "resolution": "rehearse on Ubuntu CI"},
                           {"code": "operator.development-custody-snapshot",
                            "resolution": "drain development hosts before separate-process file rotation; restart both afterward"},
                           {"code": "operator.production-inputs-unprovisioned",
                            "resolution": "owner supplies offline public root and protected live inputs"}]}
    started, operator = time.monotonic(), None
    try:
        require(os.geteuid() == 0, "simulation.root-required")
        expected = Path(str(args.archive) + ".sha256").read_text().split()
        require(len(expected) == 2 and expected[1] == args.archive.name, "simulation.checksum-format")
        with args.archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(digest == expected[0], "simulation.archive-digest")
        report["archive_sha256"] = digest
        with tempfile.TemporaryDirectory(prefix="auths-op-", dir="/var/tmp") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o755)
            with tarfile.open(args.archive, "r:gz") as archive:
                members = archive.getmembers()
                names = [member.name for member in members]
                require(len(names) == len(set(names)) <= 64, "simulation.archive-members")
                for member in members:
                    path = PurePosixPath(member.name)
                    require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                            and path.parts[0] == "auths-gateway-operator" and path.suffix != ".rs",
                            "simulation.archive-path")
                archive.extractall(root, filter="data")
            package = root / "auths-gateway-operator"
            manifest = json.loads((package / "manifest.json").read_text())
            require(manifest["schema"] == "auths.gateway-operator-package/1"
                    and manifest["source_commit"] == args.expected_commit, "simulation.package-identity")
            require(set(names) == {"auths-gateway-operator/" + item["path"] for item in manifest["files"]}
                    | {"auths-gateway-operator/manifest.json"}, "simulation.package-inventory")
            for item in manifest["files"]:
                require(hashlib.sha256((package / item["path"]).read_bytes()).hexdigest() == item["sha256"],
                        "simulation.payload-digest")
            work, sockets, inputs = root / "work", root / "sockets", root / "inputs"
            work.mkdir(mode=0o700)
            sockets.mkdir(mode=0o750)
            shutil.copytree(args.inputs, inputs)
            os.chmod(inputs, 0o700)
            os.chown(work, 62001, 62000)
            os.chown(sockets, 62001, 62000)
            private_tree(inputs, 62001, 62000)
            operator = Operator(package, inputs, work, sockets)
            operator.exercise()
            report["passed"] = True
    except Exception as error:
        report["failure_code"] = str(error) if isinstance(error, Refusal) else "simulation." + type(error).__name__
        if operator and operator.steps:
            operator.steps[-1].update(passed=False, failure_code=report["failure_code"])
    finally:
        if operator:
            try:
                operator.cleanup()
            except Exception:
                report.update(passed=False, failure_code="simulation.cleanup-failed")
            report["steps"] = operator.steps
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["command_count"] = len(report["steps"])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": report["passed"], "commands": report["command_count"],
                      "seconds": report["elapsed_seconds"], "failure_code": report.get("failure_code")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
