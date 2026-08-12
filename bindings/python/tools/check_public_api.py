from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from types import ModuleType


def public_modules() -> tuple[ModuleType, ...]:
    topology_path = Path(__file__).parents[2] / "public-topology-v1.json"
    topology = json.loads(topology_path.read_text())
    names = tuple(
        name for layer in topology["layers"] for name in layer["python"]
    )
    return tuple(importlib.import_module(name) for name in names)


def projection() -> str:
    lines = []
    for module in public_modules():
        names = getattr(module, "__all__", None)
        if type(names) is not list or any(type(name) is not str for name in names):
            raise SystemExit(f"{module.__name__} must define an explicit string __all__")
        lines.append("[" + module.__name__ + "]")
        lines.extend(sorted(names))
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    snapshot = Path(__file__).parents[1] / "api" / "public-api.txt"
    actual = projection()
    if args.update:
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(actual)
        return
    if snapshot.read_text() != actual:
        raise SystemExit(
            "installed Python public API drifted; review exports and update api/public-api.txt"
        )
    print("Python public API snapshot passed")


if __name__ == "__main__":
    main()
