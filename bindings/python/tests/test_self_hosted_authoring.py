"""An external custody signer and operator context can author an exact action."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

import pytest

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import (
    GrantEvidence,
    ProductionAuthoringInputs,
    author_mcp_proof,
    author_production_mcp_proof,
)
from auths.self_hosted import (
    AuthorizedCommand,
    ExactMcpTool,
    PreparedMcpAction,
    StringField,
    attach_observations,
    verify_command,
)

OBSERVATION_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor"


@dataclass(frozen=True)
class Change:
    value: str


@dataclass(frozen=True)
class Observation:
    media_type: str
    observation: bytes


TOOL = ExactMcpTool(
    service="example-service",
    name="set_value",
    command_type=Change,
    fields={"value": StringField(min_length=1, max_length=32)},
)


class ExternalSigner:
    def __init__(self, key: _native.DevelopmentEd25519Key) -> None:
        self.key = key
        self.calls = 0
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "test.external-signer",
            key.principal,
            CustodySignatureDescriptor(
                key.principal_method, key.verification_method, key.suite
            ),
            "test-key-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        self.calls += 1
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.key.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                self.key.sign(request.signing_preimage),
                (
                    PublicControlEvidence(
                        self.key.evidence_type, self.key.media_type, self.key.evidence
                    ),
                ),
            ),
        )

    async def aclose(self) -> None:
        return None


def _authority(now: int) -> tuple[_native.DevelopmentEd25519Key, GrantEvidence, bytes]:
    key = _native.DevelopmentEd25519Key.generate()
    principal = _native.Principal(key.principal)
    audience = "mcp://example-service"
    resource = f"{audience}/tools/set_value"
    request = _native.GrantRequest(
        principal, "auths.mcp", 2, [("tools/call", resource)], now - 60, now + 600,
        [audience], None, None, 0, None, "raw-key-baseline", [],
    )
    unsigned = _native.root_grant(principal, request)
    signing = _native.prepare_signing(
        unsigned, key.principal_method, key.verification_method, key.suite
    )
    signed = signing.complete(key.sign(signing.signing_preimage))
    evidence = PublicControlEvidence(key.evidence_type, key.media_type, key.evidence)
    assurance = _native.AssurancePolicy(
        "raw-key-baseline",
        [("root", "every", "self-certifying-identifier", None),
         ("actor", "every", "self-certifying-identifier", None),
         ("actor", "every", "offline-verifiable", None)],
    )
    anchor = _native.TrustAnchor(
        principal.value, principal, [key.principal_method], [("auths.mcp", 2)],
        [("tools/call", resource)], [audience], [audience], now - 60,
        now + 600, None, 1, "raw-key-baseline", None,
    )
    context = _native.compile_trusted_context(
        _native.self_contained_configuration(), None, 1, 1, 1, [anchor], assurance,
        None, None, "none-v1", [key.evidence_type], [],
    )
    return key, GrantEvidence(_native.inspect_signed(signed), (evidence,)), (
        _native.inspect_trusted_context(context)
    )


@pytest.mark.asyncio
async def test_external_signer_authors_portable_exact_proof() -> None:
    now = int(time.time())
    key, grant, template = _authority(now)
    signer = ExternalSigner(key)
    artifacts = await author_mcp_proof(
        contract=TOOL,
        command=Change("approved"),
        grants=(grant,),
        trusted_context_template=template,
        signer=signer,
        challenge=_native.generate_challenge_v1(),
        evaluation_time=now,
    )
    result = verify_command(
        contract=TOOL, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert isinstance(result, AuthorizedCommand)
    assert result.command == Change("approved")
    assert signer.calls == 1


@pytest.mark.asyncio
async def test_production_bundle_requires_durable_active_custody() -> None:
    now = int(time.time())
    key, grant, template = _authority(now)
    signer = ExternalSigner(key)
    with pytest.raises(ValueError, match="durable"):
        ProductionAuthoringInputs(
            (grant,), template, signer, _native.generate_challenge_v1(), now
        )
    assert signer.calls == 0
    signer.descriptor = replace(signer.descriptor, lifecycle=CustodyLifecycle.DURABLE)
    inputs = ProductionAuthoringInputs(
        (grant,), template, signer, _native.generate_challenge_v1(), now
    )
    authored = await author_production_mcp_proof(
        contract=TOOL, command=Change("approved"), inputs=inputs
    )
    verdict = verify_command(
        contract=TOOL, proof=authored.proof, action=authored.action,
        trusted_context=authored.trusted_context,
    )
    assert isinstance(verdict, AuthorizedCommand)
    assert signer.calls == 1


def test_production_bundle_rejects_missing_or_invalid_trust_before_signing() -> None:
    now = int(time.time())
    key, grant, _ = _authority(now)
    signer = ExternalSigner(key)
    signer.descriptor = replace(signer.descriptor, lifecycle=CustodyLifecycle.DURABLE)
    with pytest.raises((ValueError, TypeError)):
        ProductionAuthoringInputs(
            (grant,), b"not-a-context", signer, _native.generate_challenge_v1(), now
        )
    assert signer.calls == 0


@pytest.mark.asyncio
async def test_missing_grant_rejects_before_signer_access() -> None:
    now = int(time.time())
    key, _, template = _authority(now)
    signer = ExternalSigner(key)
    with pytest.raises(ValueError, match="grant"):
        await author_mcp_proof(
            contract=TOOL, command=Change("approved"), grants=(),
            trusted_context_template=template, signer=signer,
            challenge=_native.generate_challenge_v1(), evaluation_time=now,
        )
    assert signer.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field_name", ["object_id", "transaction_digest"])
async def test_signer_response_must_bind_the_exact_request(field_name: str) -> None:
    now = int(time.time())
    key, grant, template = _authority(now)

    class MismatchedSigner(ExternalSigner):
        async def sign(self, request: SigningRequest) -> CustodySigned:
            signed = await super().sign(request)
            original = getattr(request, field_name)
            altered = bytes([original[0] ^ 1]) + original[1:]
            return CustodySigned(
                "signed", replace(signed.response, **{field_name: altered})
            )

    signer = MismatchedSigner(key)
    with pytest.raises(ValueError, match="exact signing request"):
        await author_mcp_proof(
            contract=TOOL, command=Change("approved"), grants=(grant,),
            trusted_context_template=template, signer=signer,
            challenge=_native.generate_challenge_v1(), evaluation_time=now,
        )
    assert signer.calls == 1



def _prepared(now: int) -> PreparedMcpAction[Change]:
    key, grant, _ = _authority(now)
    return TOOL.prepare(
        Change("approved"),
        actor=_native.Principal(key.principal),
        terminal_grant=_native.parse_signed("grant", grant.signed_grant),
        challenge=_native.generate_challenge_v1(),
        evaluation_time=now,
    )


def test_attached_observations_are_bound_before_signing() -> None:
    prepared = _prepared(int(time.time()))
    first = Observation(OBSERVATION_MEDIA_TYPE, b"\xa1" * 40)
    second = Observation(OBSERVATION_MEDIA_TYPE, b"\x07" * 12)
    attached = attach_observations(prepared, (first, second))
    assert attached.command == prepared.command
    assert attached.arguments_json == prepared.arguments_json
    assert attached.canonical_action != prepared.canonical_action
    assert attached.action_commitment != prepared.action_commitment
    assert (
        _native.inspect_unsigned(attached.action.unsigned)
        != _native.inspect_unsigned(prepared.action.unsigned)
    )
    for observation in (first, second):
        assert observation.observation in attached.canonical_action
    unchanged = attach_observations(prepared, ())
    assert unchanged.canonical_action == prepared.canonical_action


@pytest.mark.parametrize(
    "observations",
    [
        (Observation("application/cbor", b"\x01" * 8),),
        (Observation(OBSERVATION_MEDIA_TYPE, b""),),
        (Observation(OBSERVATION_MEDIA_TYPE, b"\x02" * 4_097),),
        (
            Observation(OBSERVATION_MEDIA_TYPE, b"\x03" * 8),
            Observation(OBSERVATION_MEDIA_TYPE, b"\x03" * 8),
        ),
        tuple(
            Observation(OBSERVATION_MEDIA_TYPE, bytes([0xEE, index])) for index in range(33)
        ),
    ],
    ids=["media-type", "empty", "oversized", "repeated", "too-many"],
)
def test_attachment_rejects_media_type_size_count_and_repeats(
    observations: tuple[Observation, ...],
) -> None:
    with pytest.raises(_native.NativeAuthsError):
        attach_observations(_prepared(int(time.time())), observations)


def test_attachment_happens_once_and_needs_the_observation_shape() -> None:
    prepared = _prepared(int(time.time()))
    once = attach_observations(prepared, (Observation(OBSERVATION_MEDIA_TYPE, b"\x04" * 8),))
    with pytest.raises(_native.NativeAuthsError):
        attach_observations(once, ())
    with pytest.raises(TypeError):
        attach_observations(prepared, (b"not an observation",))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_attachment_is_signed_and_judged_only_by_the_verifier() -> None:
    now = int(time.time())
    key, grant, template = _authority(now)
    signer = ExternalSigner(key)
    carried = Observation(OBSERVATION_MEDIA_TYPE, b"bytes the attacher never decodes")
    authored = await author_mcp_proof(
        contract=TOOL,
        command=Change("approved"),
        grants=(grant,),
        trusted_context_template=template,
        signer=signer,
        challenge=_native.generate_challenge_v1(),
        evaluation_time=now,
        observations=(carried,),
    )
    assert carried.observation in authored.action
    result = verify_command(
        contract=TOOL, proof=authored.proof, action=authored.action,
        trusted_context=authored.trusted_context,
    )
    assert isinstance(result, AuthorizedCommand), "no requirement reads it"
    stripped = _prepared(now)
    assert authored.action_commitment != stripped.action_commitment
