from __future__ import annotations

import json
import os
from pathlib import Path

from auths.verify import verify


root = Path(os.environ["AUTHS_RECIPE_FIXTURE"])
proof = (root / "workflow.proof.cbor").read_bytes()
action = (root / "workflow.action.cbor").read_bytes()
context = (root / "workflow.context.cbor").read_bytes()
verified = verify(proof, action, context)
if verified.kind != "authorized":
    raise RuntimeError(f"unexpected verdict: {verified.kind}")
changed = bytearray(action)
changed[-1] ^= 1
try:
    changed_rejected = verify(proof, bytes(changed), context).kind != "authorized"
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
