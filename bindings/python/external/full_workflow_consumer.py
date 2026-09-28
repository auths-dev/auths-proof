from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import auths
from auths.gateway import GatewayClient, GatewayEndpoint
from auths.identity.authoring import create_raw_key_ed25519_identity


async def run(_: Path) -> None:
    """Check the installed root wheel without inventing an in-process effect runtime."""

    runtime = auths.runtime_info()
    if not runtime.compatible:
        raise RuntimeError("installed wheel runtime contract is incompatible")
    if runtime.profiles:
        raise RuntimeError("the root wheel must not embed a provider profile roster")
    if "gateway.client-v1" not in runtime.capabilities:
        raise RuntimeError("installed wheel omitted the gateway client capability")

    identity = create_raw_key_ed25519_identity(b"\x01" * 32)
    if identity.method_id != "raw-key-v2" or not identity.identity_id.startswith(
        "key:sha256-v2:"
    ):
        raise RuntimeError("installed identity authoring path is unavailable")

    # Provider writes go only through an operator-run gateway. This root-wheel
    # check confirms the client surface is installed; the gateway journey runs
    # the installed wheel against a real gateway harness.
    if not callable(GatewayClient) or not callable(GatewayEndpoint):
        raise RuntimeError("installed gateway client is unavailable")
    if hasattr(auths, "connect"):
        raise RuntimeError("installed wheel still exposes a local-agent connector")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: full_workflow_consumer.py <binding-vectors>")
    asyncio.run(run(Path(sys.argv[1]).resolve()))
