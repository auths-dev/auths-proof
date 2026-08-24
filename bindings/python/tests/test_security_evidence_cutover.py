from __future__ import annotations

import json
from pathlib import Path


def test_every_cutover_evidence_reference_is_live_and_unique() -> None:
    repository = Path(__file__).parents[3]
    manifest = json.loads(
        (repository / "bindings/security-evidence-cutover-v1.json").read_text()
    )
    removed = manifest["removedTests"]
    paths = [entry["path"] for entry in removed]
    assert len(paths) == len(set(paths)) == 32
    assert all(entry["evidence"] for entry in removed)
    referenced = {
        path
        for entry in (*manifest["currentClaims"], *removed)
        for path in entry["evidence"]
    }
    missing = sorted(path for path in referenced if not (repository / path).is_file())
    assert missing == []
