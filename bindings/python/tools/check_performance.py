from __future__ import annotations

import asyncio
import importlib
import json
import os
import platform
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Callable


def _p95(samples: list[float]) -> float:
    return sorted(samples)[max(0, int(len(samples) * 0.95) - 1)]


def _timings(operation: Callable[[], object], count: int) -> list[float]:
    samples: list[float] = []
    for _ in range(count):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def _native_boundary(module: object, size: int) -> float:
    commit = getattr(module, "commit_canonical_v1")
    value = bytes(size)
    return _p95(
        _timings(
            lambda: commit("auths.performance-boundary.v1", value),
            100,
        )
    )


async def _event_loop_yields() -> list[float]:
    samples: list[float] = []
    for _ in range(100):
        started = time.perf_counter()
        await asyncio.sleep(0)
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def main() -> None:
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--print"):
        raise SystemExit(
            "usage: check_performance.py <binding-vectors> <wheel> [--print]"
        )
    capture = len(sys.argv) == 4
    vectors = Path(sys.argv[1])
    wheel = Path(sys.argv[2])
    started = time.perf_counter()
    verify_module = importlib.import_module("auths.verify")
    profiles_module = importlib.import_module("auths.profiles")
    native_module = importlib.import_module("auths._native")
    cold_initialize_ms = (time.perf_counter() - started) * 1000

    item = (
        (vectors / "workflow.proof.cbor").read_bytes(),
        (vectors / "workflow.action.cbor").read_bytes(),
        (vectors / "workflow.context.cbor").read_bytes(),
    )
    verify = verify_module.verify
    verify_many = verify_module.verify_many
    verify(*item)
    verify_many((item,) * 32)
    single = _timings(lambda: verify(*item), 100)
    batch = _timings(lambda: verify_many((item,) * 32), 100)
    profile = profiles_module.mcp.profile(service="performance")
    actions = tuple(
        profile.call("read_record", {"index": index}) for index in range(64)
    )
    profile.plan(actions)
    plans = _timings(lambda: profile.plan(actions), 100)

    tracemalloc.start()
    verify_many((item,) * 32)
    _, verify_peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    measurement = {
        "coldInitializeMs": round(cold_initialize_ms, 3),
        "singleVerifyMsP95": round(_p95(single), 3),
        "pyO3BoundarySerializeSmallP95Ms": round(
            _native_boundary(native_module, 64), 3
        ),
        "pyO3BoundarySerializeMediumP95Ms": round(
            _native_boundary(native_module, 4096), 3
        ),
        "pyO3BoundarySerializeMaximumP95Ms": round(
            _native_boundary(native_module, 65536), 3
        ),
        "batch32MsP95": round(_p95(batch), 3),
        "plan64MsP95": round(_p95(plans), 3),
        "verifyPeakBytes": verify_peak_bytes,
        "eventLoopYieldMsP95": round(_p95(asyncio.run(_event_loop_yields())), 3),
        "wheelBytes": wheel.stat().st_size,
    }
    baseline = json.loads(
        (Path(__file__).parents[1] / "performance-baseline.json").read_text()
    )
    expected_keys = set(baseline["measurements"])
    if set(measurement) != expected_keys:
        raise SystemExit("Python performance measurement contract drifted")

    current_environment = {
        "implementation": platform.python_implementation(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "operatingSystem": sys.platform,
        "architecture": platform.machine().lower(),
        "build": "release abi3 wheel",
        "runner": "github-actions"
        if os.environ.get("GITHUB_ACTIONS") == "true"
        else "developer-reference",
    }
    matching_environment = current_environment == baseline["environment"]
    if not capture:
        for key, limit in baseline["hardLimits"].items():
            if measurement[key] > limit:
                raise SystemExit(f"{key} exceeded the cross-platform hard limit")
    if matching_environment and not capture:
        runtime_threshold = (
            1 + baseline["reviewThresholds"]["runtimeRegressionPercent"] / 100
        )
        wheel_threshold = (
            1 + baseline["reviewThresholds"]["wheelSizeRegressionPercent"] / 100
        )
        for key in (
            "coldInitializeMs",
            "singleVerifyMsP95",
            "pyO3BoundarySerializeSmallP95Ms",
            "pyO3BoundarySerializeMediumP95Ms",
            "pyO3BoundarySerializeMaximumP95Ms",
            "batch32MsP95",
            "plan64MsP95",
            "eventLoopYieldMsP95",
        ):
            budget = baseline["measurements"][key] * runtime_threshold
            if measurement[key] > budget:
                raise SystemExit(
                    f"{key} exceeded the matching-runner regression budget: "
                    f"observed {measurement[key]}, budget {budget:.3f}"
                )
        wheel_budget = baseline["measurements"]["wheelBytes"] * wheel_threshold
        if measurement["wheelBytes"] > wheel_budget:
            raise SystemExit(
                "wheelBytes exceeded the matching-runner regression budget: "
                f"observed {measurement['wheelBytes']}, budget {wheel_budget:.0f}"
            )

    print(
        json.dumps(
            {
                "environment": current_environment,
                "matchingEnvironment": matching_environment,
                "measurement": measurement,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
