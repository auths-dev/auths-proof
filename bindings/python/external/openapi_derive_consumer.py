"""Installed-wheel, source-free derive consumer contract.

Runs the packaged ``auths-profile`` command against the committed derivation
corpus: derive one operation, generate its profile, check it, and prove a hand
edit is caught. The expected bytes, including the gateway recipe digest the
Rust compiler recorded for the same recipe, come from the corpus directory
passed as the only argument.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CASE = "minimal-create-note"


def run(command: list[str], *, expect: int = 0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != expect:
        raise SystemExit(
            f"{command[1:3]} exited {completed.returncode}, expected {expect}:\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return completed


def main() -> None:
    corpus = Path(sys.argv[1]).resolve()
    tool = shutil.which("auths-profile")
    if tool is None:
        raise SystemExit("the installed wheel did not provide auths-profile")
    case = next(
        entry for entry in json.loads((corpus / "cases.json").read_text(encoding="utf-8"))["cases"]
        if entry["id"] == CASE
    )
    expected = corpus / "expected" / CASE
    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "derived"
        derived = run([
            tool, "derive", "--openapi", str(corpus / case["document"]["file"]),
            "--directory", str(target), *case["arguments"],
        ])
        if "claim:      derived shape only; provider effect unqualified" not in derived.stdout:
            raise SystemExit("derive did not report its claim boundary")
        for name in ("profile.toml", "recipe.json", "derivation.json"):
            if (target / name).read_bytes() != (expected / name).read_bytes():
                raise SystemExit(f"installed derive wrote different {name} bytes")
        manifest = str(target / "profile.toml")
        run([tool, "generate", manifest])
        run([tool, "check", manifest])
        lock = json.loads((target / "profile.lock.json").read_text(encoding="utf-8"))
        if lock != json.loads((expected / "profile.lock.json").read_text(encoding="utf-8")):
            raise SystemExit("installed generator wrote a different lock")
        recipe = json.loads((target / "recipe.json").read_text(encoding="utf-8"))
        review = json.loads((expected / "review.json").read_text(encoding="utf-8"))
        if lock["schema_digest"] != recipe["profile_schema_digest"] or lock["tool"] != review["tool"]:
            raise SystemExit("derived recipe is not bound to the generated profile lock")
        profile = target / "profile.toml"
        profile.write_bytes(profile.read_bytes().replace(b"max_bytes = 100", b"max_bytes = 99"))
        edited = run([tool, "check", manifest], expect=1)
        if "derived file edited by hand" not in edited.stderr:
            raise SystemExit("check did not report the hand edit")
        rejected = run([
            tool, "derive", "--openapi", str(corpus / "documents/hostile.json"),
            "--directory", str(Path(temporary) / "hostile"),
            "--operation", "hObjectUnion", "--service", "hostile", "--name", "hostile",
            "--operator-namespace", "hostile",
        ], expect=1)
        if "contract.derive.unsupported-construct" not in rejected.stderr:
            raise SystemExit("installed derive did not reject a hostile construct")
    print(f"installed derive reproduced {CASE}; recipe digest {review['digest']} recorded by the Rust compiler")


if __name__ == "__main__":
    main()
