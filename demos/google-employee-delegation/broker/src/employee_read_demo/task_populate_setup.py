"""Private development setup for a paired Google create/populate task.

Run before task-configure or human review. The signer seed stays in operator
custody; only its public key and the reviewed Google preflight code revision
enter the gateway task installation. An incomplete or existing setup is
refused rather than silently changing a live task's preflight policy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from .google_create_preflight import current_populate_preflight_rule_digest
from .operator_authority import OperatorDenied
from .operator_cli import _private_write
from .task_write_card import _installation


def prepare_populate_preflight_installation(
    base_installation: Path, *, seed_out: Path, installation_out: Path,
) -> dict[str, str]:
    """Create one signer and canonical pinned installation in a private dir."""
    if (not all(path.is_absolute() for path in (
            base_installation, seed_out, installation_out))
            or len({base_installation, seed_out, installation_out}) != 3
            or seed_out.parent != installation_out.parent
            or seed_out.parent.is_symlink()
            or not seed_out.parent.is_dir()
            or seed_out.exists() or installation_out.exists()):
        raise OperatorDenied("private populate preflight setup paths are unavailable")
    installation = _installation(base_installation)
    if ("populate_preflight" in installation
            or len(installation["recipe_digests"]) != 2):
        raise OperatorDenied("paired installation must have two recipes and no preflight pin")
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    rule_digest = current_populate_preflight_rule_digest()
    pinned = installation | {
        "populate_preflight": {
            "public_key_hex": public_hex,
            "rule_digest": rule_digest,
        },
    }
    _private_write(seed_out, seed)
    try:
        _private_write(installation_out, json.dumps(
            pinned, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
    except BaseException:
        seed_out.unlink(missing_ok=True)
        raise
    return {
        "installation": str(installation_out),
        "signing_seed": str(seed_out),
        "public_key_hex": public_hex,
        "rule_digest": rule_digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-installation", type=Path, required=True)
    parser.add_argument("--seed-out", type=Path, required=True)
    parser.add_argument("--installation-out", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_populate_preflight_installation(
        args.base_installation, seed_out=args.seed_out,
        installation_out=args.installation_out,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
