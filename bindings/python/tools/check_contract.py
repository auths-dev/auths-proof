from __future__ import annotations

import importlib.util
import json
from importlib.metadata import version
from pathlib import Path

from auths import _native


def main() -> None:
    root = Path(__file__).parents[1]
    runtime = json.loads((root / "sdk-runtime-contract.json").read_text())
    abi = json.loads((root / "native-abi-v2.json").read_text())
    capability = json.loads((root / "sdk-capability.json").read_text())
    adapters = json.loads((root / "adapter-contracts.json").read_text())
    matrix = json.loads((root.parent / "customer-journey-matrix-v1.json").read_text())
    identity = json.loads((root / "identity-conformance-v1.json").read_text())
    package = runtime["package"]
    if version("auths") != package["version"]:
        raise SystemExit("installed package version disagrees with runtime contract")
    if _native.native_abi_version() != package["nativeAbi"]:
        raise SystemExit("installed native ABI disagrees with runtime contract")
    if abi["abiVersion"] != package["nativeAbi"]:
        raise SystemExit("native ABI manifest disagrees with runtime contract")
    for native_type in abi["types"]:
        if not isinstance(getattr(_native, native_type, None), type):
            raise SystemExit(f"native ABI type is unavailable: {native_type}")
    for operation in (*abi["operations"], *abi["inspection"]):
        if not callable(getattr(_native, operation, None)):
            raise SystemExit(f"native ABI operation is unavailable: {operation}")
    if capability["implementationStatus"] != "elite-repository-implementation-complete":
        raise SystemExit("capability evidence does not describe the implemented SDK")
    for module in runtime["excludedModules"]:
        if importlib.util.find_spec(module) is not None:
            raise SystemExit(f"superseded public module remains importable: {module}")
    if runtime["compatibilityWindow"] is not False:
        raise SystemExit("prelaunch runtime contract must not declare a compatibility window")
    if runtime["distribution"] != {
        "wheels": "published",
        "sourceDistribution": "not-published",
        "localCompilerRequired": False,
    }:
        raise SystemExit("Python release distribution policy drifted")
    if adapters["schema"] != runtime["adapterContract"]:
        raise SystemExit("adapter contracts disagree with the runtime contract")
    if identity["descriptorProtocol"] != runtime["semanticSubjects"]["identity"]:
        raise SystemExit("identity conformance corpus disagrees with runtime semantics")
    repository = root.parents[1]
    if (repository / ".git").exists():
        for journey in matrix["journeys"]:
            for language in ("rust", "typescript", "python"):
                if not (repository / journey[language]).exists():
                    raise SystemExit(
                        f"customer journey evidence is missing: {journey['id']} {language}"
                    )
    print("Python package, native ABI, capability, and clean-break contracts agree")


if __name__ == "__main__":
    main()
