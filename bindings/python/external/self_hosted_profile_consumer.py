"""Packed-wheel, source-free self-hosted profile consumer smoke contract."""

from __future__ import annotations

import asyncio
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

from auths.execution import Attempted, NotExecuted, ProviderAccepted, run_once
from auths.testkit import development_mcp_artifacts


class MemoryAttempts:
    def __init__(self) -> None:
        self.claimed = False

    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool:
        if self.claimed:
            return False
        self.claimed = True
        return True

    def read(self, action_commitment: bytes) -> None:
        return None

    def finish(self, action_commitment: bytes, state: str) -> None:
        return None


class Adapter:
    def __init__(self) -> None:
        self.credentials = 0
        self.calls = 0

    def credential(self) -> str:
        self.credentials += 1
        return "synthetic-token"

    async def invoke(self, command: object, credential: str) -> ProviderAccepted[str]:
        self.calls += 1
        return ProviderAccepted("accepted")

    async def observe(self, command: object) -> str:
        return "observed"


async def exercise(contract: object) -> None:
    good = development_mcp_artifacts(
        service="example-create", name="invoke_v1", arguments={"value": "open"},
    )
    other = development_mcp_artifacts(
        service="example-create", name="other_v1", arguments={"value": "open"},
    )
    attempts = MemoryAttempts()
    adapter = Adapter()
    base = {"contract": contract, "attempts": attempts, "operation_key": "one", "adapter": adapter}
    denied = await run_once(
        **base, proof=other.proof, action=other.action,
        trusted_context=other.trusted_context,
    )
    assert isinstance(denied, NotExecuted) and adapter.credentials == 0
    accepted = await run_once(
        **base, proof=good.proof, action=good.action,
        trusted_context=good.trusted_context,
    )
    assert isinstance(accepted, Attempted) and accepted.provider.kind == "accepted"
    replay = await run_once(
        **base, proof=good.proof, action=good.action,
        trusted_context=good.trusted_context,
    )
    assert isinstance(replay, NotExecuted) and replay.kind == "replay"
    assert adapter.credentials == adapter.calls == 1


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="auths-profile-consumer-") as temporary:
        root = Path(temporary)
        subprocess.run(
            [sys.executable, "-m", "auths._profile_cli", "init",
             "--language", "python", "--name", "example-create",
             "--directory", str(root)],
            check=True, cwd=root, stdout=subprocess.DEVNULL,
        )
        manifest = root / "profile.toml"
        source = manifest.read_text(encoding="utf-8")
        original = '[arguments.fields.value]\ntype = "string"\nmin_bytes = 1\nmax_bytes = 256\n'
        assert original in source
        manifest.write_text(source.replace(original,
            '[arguments.fields.value]\ntype = "enum"\nvariants = ["open", "closed"]\n'),
            encoding="utf-8")
        subprocess.run(
            [sys.executable, "-m", "auths._profile_cli", "generate", str(manifest)],
            check=True, cwd=root, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [sys.executable, "-m", "auths._profile_cli", "check",
             str(manifest)],
            check=True, cwd=root, stdout=subprocess.DEVNULL,
        )
        spec = importlib.util.spec_from_file_location("external_generated", root / "generated.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("generated command cannot be imported")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        asyncio.run(exercise(module.CONTRACT))


if __name__ == "__main__":
    main()
