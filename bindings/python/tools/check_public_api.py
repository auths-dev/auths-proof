from __future__ import annotations

import argparse
from pathlib import Path

import auths
import auths.advanced
import auths.native


def projection() -> str:
    sections = {
        "auths": auths.__all__,
        "auths.advanced": auths.advanced.__all__,
        "auths.native": auths.native.__all__,
    }
    lines = []
    for module, names in sections.items():
        lines.append("[" + module + "]")
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
