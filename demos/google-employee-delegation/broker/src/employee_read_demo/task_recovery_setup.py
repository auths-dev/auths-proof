"""Pin a separate operator signer before response-less create recovery.

The signer seed remains in private operator custody. The gateway installation
receives only its public key and the reviewed recovery join rule digest.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from .operator_authority import OperatorDenied
from .operator_cli import _private_write
from .task_recovery_operator import current_recovery_attestation_rule_digest
from .task_write_card import _installation


def prepare_recovery_attestation_installation(
    base_installation: Path, *, seed_out: Path, installation_out: Path,
) -> dict[str, str]:
    if (not all(path.is_absolute() for path in (
            base_installation, seed_out, installation_out))
            or len({base_installation, seed_out, installation_out}) != 3
            or seed_out.parent != installation_out.parent
            or seed_out.parent.is_symlink()
            or not seed_out.parent.is_dir()
            or seed_out.exists() or installation_out.exists()):
        raise OperatorDenied("private recovery signer setup paths are unavailable")
    installation = _installation(base_installation)
    if ("recovery_attestation" in installation
            or "populate_preflight" not in installation
            or len(installation["recipe_digests"]) != 2):
        raise OperatorDenied("paired installation needs preflight and no recovery pin")
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    rule_digest = current_recovery_attestation_rule_digest()
    pinned = installation | {"recovery_attestation": {
        "public_key_hex": public_hex, "rule_digest": rule_digest,
    }}
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
    result = prepare_recovery_attestation_installation(
        args.base_installation, seed_out=args.seed_out,
        installation_out=args.installation_out,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
