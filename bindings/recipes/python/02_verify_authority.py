from __future__ import annotations

import json
import os
from pathlib import Path

from auths.verify import VerificationInput, verify


fixture = os.environ.get("AUTHS_RECIPE_FIXTURE")
if not fixture:
    raise SystemExit(
        "Set AUTHS_RECIPE_FIXTURE to the directory containing workflow.proof.cbor, "
        "workflow.action.cbor and workflow.context.cbor; "
        "see docs/product/recipes/02_VERIFY_AUTHORITY.md for a disposable example."
    )
root = Path(fixture)
proof = (root / "workflow.proof.cbor").read_bytes()
action = (root / "workflow.action.cbor").read_bytes()
context = (root / "workflow.context.cbor").read_bytes()
verified = verify(
    VerificationInput(proof=proof, action=action, trusted_context=context)
)
if verified.kind != "authorized":
    raise RuntimeError(f"unexpected verdict: {verified.kind}")
changed = bytearray(action)
changed[-1] ^= 1
try:
    changed_rejected = verify(
        VerificationInput(
            proof=proof, action=bytes(changed), trusted_context=context
        )
    ).kind != "authorized"
except (TypeError, ValueError):
    changed_rejected = True
if not changed_rejected:
    raise RuntimeError("mutated action remained authorized")
print(
    json.dumps(
        {
            "recipe": "02-verify-authority",
            "outcome": verified.kind,
            "changedRejected": changed_rejected,
        }
    )
)
