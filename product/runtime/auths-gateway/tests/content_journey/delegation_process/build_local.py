#!/usr/bin/env python3
"""Construct installed consumer inputs and the canonical AP073 process artifact.

This is an artifact constructor, not the repository CI/release gate. It never
uses live credentials or providers. A new output directory is mandatory.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[6]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    artifacts = output / "artifacts"
    artifacts.mkdir()

    def run(name, command, directory=repository, env=None):
        log = output / (name + ".log")
        with log.open("wb") as destination:
            result = subprocess.run(command, cwd=directory, env=env, stdout=destination,
                                    stderr=subprocess.STDOUT, timeout=1800)
        print(name, result.returncode, str(log), flush=True)
        return result.returncode

    def rust():
        result = run("native-build", ["cargo", "test", "--locked", "-p", "auths-gateway",
                     "--features", "loopback-provider,testkit-harness", "--test", "content_journey",
                     "--no-run", "--message-format=json"])
        if result:
            return result
        records = [json.loads(line) for line in (output / "native-build.log").read_text().splitlines()
                   if line.startswith('{')]
        for name, filename in [("content_journey", "auths-ap073-journey"),
                               ("auths-gateway", "auths-gateway-simulation")]:
            binaries = [item["executable"] for item in records
                        if item.get("reason") == "compiler-artifact"
                        and item.get("target", {}).get("name") == name and item.get("executable")]
            if len(set(binaries)) != 1:
                raise ValueError("constructor.native-artifact-missing")
            shutil.copyfile(binaries[0], artifacts / filename)
            (artifacts / filename).chmod(0o755)
        return 0

    def python():
        return run("wheel-build", ["maturin", "build", "--locked", "--profile", "python-extension",
                   "--interpreter", sys.executable, "--manifest-path", "bindings/python/Cargo.toml",
                   "--out", str(artifacts)])

    def node():
        sdk = repository / "bindings/typescript"
        for name, command in [("npm-inputs", ["npm", "ci", "--ignore-scripts"]),
                              ("wasm-build", ["npm", "run", "build:wasm"]),
                              ("declarations-build", ["npm", "run", "build"]),
                              ("npm-package", ["npm", "pack", "--pack-destination", str(artifacts)])]:
            result = run(name, command, sdk)
            if result:
                return result
        return 0

    # Independent builds expose their failures together. Cargo serializes shared
    # target access itself; no constructor proceeds with a missing package.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(build) for build in (rust, python, node)]
        results = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as error:
                print("constructor failed:", type(error).__name__, flush=True)
                results.append(1)
    if any(results):
        raise SystemExit(1)
    consumer = output / "consumer"
    consumer.mkdir()
    if run("consumer-venv", [sys.executable, "-m", "venv", str(consumer / "venv")]):
        raise SystemExit(1)
    wheels = list(artifacts.glob("auths-*.whl"))
    packages = list(artifacts.glob("auths-dev-sdk-*.tgz"))
    if len(wheels) != 1 or len(packages) != 1:
        raise ValueError("constructor.package-count")
    interpreter = consumer / "venv/bin/python"
    if run("consumer-wheel", [str(interpreter), "-I", "-m", "pip", "install", "--no-index", str(wheels[0])]):
        raise SystemExit(1)
    (consumer / "package.json").write_text('{"private":true,"type":"module"}\n')
    if run("consumer-npm", ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-save", str(packages[0])], consumer):
        raise SystemExit(1)
    environment = dict(os.environ, AUTHS_DELEGATION_CONSUMER_DIR=str(consumer),
                       AUTHS_DELEGATION_PYTHON=str(interpreter),
                       AUTHS_GATEWAY_OPERATOR_TEST_BINARY=str(artifacts / "auths-gateway-simulation"),
                       AUTHS_UPDATE_FIXTURES="1")
    environment.pop("AUTHS_DELEGATION_DISTINCT_UIDS", None)
    environment.pop("AUTHS_DELEGATION_EVIDENCE_OUT", None)
    selector = "delegation_process::native_installed_delegation_process_fixture_is_current"
    binary = str(artifacts / "auths-ap073-journey")
    registry = subprocess.check_output([binary, "--list"], text=True, timeout=30)
    if selector + ": test" not in registry.splitlines():
        raise ValueError("constructor.required-selector-missing")
    result = run("installed-journey", [binary, "--ignored", "--exact", selector,
                 "--nocapture"], consumer, environment)
    if result == 0 and "test result: ok. 1 passed; 0 failed; 0 ignored;" not in (output / "installed-journey.log").read_text():
        raise ValueError("constructor.required-selector-did-not-run-once")
    raise SystemExit(result)


if __name__ == "__main__":
    main()
