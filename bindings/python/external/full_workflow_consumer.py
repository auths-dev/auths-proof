from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import auths
from auths.identity.authoring import create_raw_key_ed25519_identity


async def run(_: Path) -> None:
    """Check the installed root wheel without inventing an in-process effect runtime."""

    runtime = auths.runtime_info()
    if not runtime.compatible:
        raise RuntimeError("installed wheel runtime contract is incompatible")
    if runtime.profiles:
        raise RuntimeError("the root wheel must not embed a provider profile roster")
    if "local-agent.session-v1" not in runtime.capabilities:
        raise RuntimeError("installed wheel omitted the local-agent session capability")

    identity = create_raw_key_ed25519_identity(b"\x01" * 32)
    if not identity.identity_id.startswith("raw:"):
        raise RuntimeError("installed identity authoring path is unavailable")

    # An effectful clean-consumer test needs an operator-provisioned local
    # agent and generated profile distribution. This root-wheel check must not
    # replace that boundary with application handlers or provider credentials.
    if not callable(auths.connect):
        raise RuntimeError("installed local-agent connector is unavailable")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: full_workflow_consumer.py <binding-vectors>")
    asyncio.run(run(Path(sys.argv[1]).resolve()))
