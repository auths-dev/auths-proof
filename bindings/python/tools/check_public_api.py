from __future__ import annotations

import argparse
import importlib
from pathlib import Path

import auths
import auths.approvals
import auths.authority
import auths.custody
import auths.diagnostics
import auths.errors
import auths.identity
import auths.inspection
import auths.integrations
import auths.lifecycle
import auths.observability
import auths.profile_kit
import auths.profiles.http
import auths.profiles.mcp
import auths.runtime
import auths.testkit
import auths.trust
import auths.verify

auths_profiles_mcp = importlib.import_module("auths.profiles.mcp")


def projection() -> str:
    sections = {
        "auths": auths.__all__,
        "auths.approvals": auths.approvals.__all__,
        "auths.authority": auths.authority.__all__,
        "auths.custody": auths.custody.__all__,
        "auths.diagnostics": auths.diagnostics.__all__,
        "auths.errors": auths.errors.__all__,
        "auths.identity": auths.identity.__all__,
        "auths.inspection": auths.inspection.__all__,
        "auths.integrations": auths.integrations.__all__,
        "auths.lifecycle": auths.lifecycle.__all__,
        "auths.observability": auths.observability.__all__,
        "auths.profile_kit": auths.profile_kit.__all__,
        "auths.profiles.http": auths.profiles.http.__all__,
        "auths.profiles.mcp": auths_profiles_mcp.__all__,
        "auths.runtime": auths.runtime.__all__,
        "auths.testkit": auths.testkit.__all__,
        "auths.trust": auths.trust.__all__,
        "auths.verify": auths.verify.__all__,
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
