"""Packed-wheel, source-free self-hosted profile consumer smoke contract."""

from __future__ import annotations

import asyncio
import importlib.util
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor, CustodyKeyState, CustodyKind, CustodyLifecycle,
    CustodySignatureDescriptor, CustodySigned, PublicControlEvidence,
    SigningRequest, SigningResponse,
)
from auths.attempts import FileAttemptStore
from auths.authoring import AuthoredMcpProof, GrantEvidence, author_mcp_proof
from auths.execution import (
    Attempted, NotExecuted, ProviderAccepted, reconcile_read_only, run_once,
)
from auths.self_hosted import AuthorizedCommand, ExactMcpTool, StringField, verify_command
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


@dataclass(frozen=True)
class Change:
    value: str


class FixtureCustodySigner:
    """CI-only external custody adapter; its seed is a public test vector."""

    def __init__(self, seed: bytes) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(seed)
        self.descriptor = CustodyDescriptor(
            "signer-custody/2", CustodyKind.WORKLOAD, "test.external-custody",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite,
            ),
            "fixture-key-1", CustodyKeyState.ACTIVE_CURRENT, CustodyLifecycle.EPHEMERAL,
        )
        self.calls = 0

    async def sign(self, request: SigningRequest) -> CustodySigned:
        self.calls += 1
        return CustodySigned("signed", SigningResponse(
            request.request_id, request.object_id, self.key.principal,
            self.descriptor.signature, self.descriptor.key_version,
            request.transaction_digest, self.key.sign(request.signing_preimage),
            (PublicControlEvidence(
                self.key.evidence_type, self.key.media_type, self.key.evidence,
            ),),
        ))

    async def aclose(self) -> None:
        return None


class AmbiguousAdapter(Adapter):
    async def invoke(self, command: object, credential: str) -> ProviderAccepted[str]:
        self.calls += 1
        raise TimeoutError("the synthetic provider may have applied the write")


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


async def exercise_signed_journey(vectors: Path, root: Path) -> None:
    """Packaged wheel, signed action, supplied trust, one write, unknown recovery."""
    signer = FixtureCustodySigner((vectors / "mcp.actor-seed.bin").read_bytes())
    contract = ExactMcpTool(
        service="reports", name="update_demo_record", command_type=Change,
        fields={"value": StringField(min_length=1, max_length=32)},
    )
    grants = (GrantEvidence(
        (vectors / "mcp.signed-root-grant.cbor").read_bytes(),
        (PublicControlEvidence(
            "raw-key-v1", "application/vnd.auths.raw-key.v1",
            (vectors / "mcp.root-evidence.bin").read_bytes(),
        ),),
    ),)
    context = (vectors / "mcp.context.cbor").read_bytes()
    async def author(value: str) -> AuthoredMcpProof[Change]:
        return await author_mcp_proof(
            contract=contract, command=Change(value), grants=grants,
            trusted_context_template=context, signer=signer,
            challenge=bytes([0x22]) * 32, evaluation_time=50,
        )

    first = await author("reviewed")
    attempts = FileAttemptStore(root / "attempts")
    adapter = Adapter()
    base = {
        "contract": contract, "proof": first.proof, "action": first.action,
        "trusted_context": first.trusted_context, "attempts": attempts,
        "operation_key": "signed-write-one", "adapter": adapter,
    }
    wrong = ExactMcpTool(
        service="reports", name="other_record", command_type=Change,
        fields={"value": StringField(min_length=1, max_length=32)},
    )
    denied = await run_once(**{**base, "contract": wrong})
    assert isinstance(denied, NotExecuted) and adapter.credentials == 0
    written = await run_once(**base)
    assert isinstance(written, Attempted) and written.provider.kind == "accepted"
    assert written.observation == "observed"
    replay = await run_once(**base)
    assert isinstance(replay, NotExecuted) and replay.kind == "replay"
    assert adapter.calls == adapter.credentials == 1

    second = await author("queued")
    ambiguous = AmbiguousAdapter()
    try:
        await run_once(
            contract=contract, proof=second.proof, action=second.action,
            trusted_context=second.trusted_context, attempts=attempts,
            operation_key="signed-write-two", adapter=ambiguous,
        )
    except TimeoutError:
        pass
    else:
        raise AssertionError("ambiguous provider entry was not surfaced")
    record = attempts.read(second.action_commitment)
    assert record is not None and record.state == "unknown"
    authorization = verify_command(
        contract=contract, proof=second.proof, action=second.action,
        trusted_context=second.trusted_context,
    )
    assert isinstance(authorization, AuthorizedCommand)
    observed = await reconcile_read_only(authorization=authorization, adapter=ambiguous)
    assert observed == "observed" and ambiguous.calls == 1
    assert signer.calls == 2


def main(vectors: Path) -> None:
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
        asyncio.run(exercise_signed_journey(vectors, root))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
