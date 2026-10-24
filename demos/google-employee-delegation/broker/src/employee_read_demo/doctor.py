"""Honest prerequisite status for the unconfigured demo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .demo_co_contract import OperatorPins, inspect_exports


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect AP-SPEC-070 prerequisites")
    parser.add_argument("--connections", type=Path)
    parser.add_argument("--access-expectations", type=Path)
    parser.add_argument("--scenario-result", type=Path, action="append", default=[])
    parser.add_argument("--pins", type=Path, help="operator-reviewed JSON pin set")
    args = parser.parse_args()
    pins = None
    if args.pins is not None:
        if args.pins.stat().st_size > 4096:
            parser.error("pin file exceeds 4096 bytes")
        try:
            pins = OperatorPins(**json.loads(args.pins.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError) as error:
            parser.error(f"invalid pin file: {error}")
    status = inspect_exports(args.connections, args.access_expectations, pins,
                             tuple(args.scenario_result))
    print(json.dumps({"contract": "auths.google-read-doctor/v1", **status.__dict__}, sort_keys=True))
    return 0 if status.google == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
