"""The operator steps a self-hosted deployment needs, without native types.

Public through :mod:`auths.self_hosted`: compile a trusted context, issue a
root grant through a custody signer, and load an ``auths.approval-signer/1``
file.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal, Optional, Sequence, Tuple, Union, cast

from . import _native
from ._trust import AssurancePolicy, compile_trust
from ._trust import TrustAnchor as _PrivateTrustAnchor
from ._workflow import Permission, Profile
from .adapters.custody import (
    CustodyDescriptor,
    CustodyIndeterminate,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodyRejected,
    CustodySignatureDescriptor,
    CustodySigned,
    CustodySigner,
    PublicControlEvidence,
    ReviewField,
    SigningObjectKind,
    SigningRequest,
    SigningResponse,
)

if TYPE_CHECKING:
    from .authoring import GrantEvidence

_SIGNER_SCHEMA = "auths.approval-signer/1"
_MAX_SIGNER_FILE_BYTES = 1_048_576
_MAX_EXTENSIONS = 8
_MAX_EXTENSION_BYTES = 16_384
_MAX_U64 = 2**64 - 1


@dataclass(frozen=True)
class TrustAnchor:
    """One root the operator trusts and the most authority it may exercise or
    delegate.

    ``max_delegation_depth`` counts the delegations allowed below the anchor:
    0 means the anchor may only act, 1 lets it grant once. Anchors use
    expiry-only status and carry no budget ceiling.
    """

    id: str
    principal: str
    accepted_methods: Tuple[str, ...]
    profiles: Tuple[Profile, ...]
    permissions: Tuple[Permission, ...]
    resource_namespaces: Tuple[str, ...]
    audiences: Tuple[str, ...]
    not_before: int
    expires_at: int
    max_delegation_depth: int
    assurance_policy: str

    def __post_init__(self) -> None:
        for name in (
            "accepted_methods",
            "profiles",
            "permissions",
            "resource_namespaces",
            "audiences",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if type(self.principal) is not str or not self.principal:
            raise TypeError("trust anchor principal must be a non-empty string")

    def _private(self) -> _PrivateTrustAnchor:
        return _PrivateTrustAnchor(
            self.id,
            _native.Principal(self.principal),
            self.accepted_methods,
            self.profiles,
            self.permissions,
            self.resource_namespaces,
            self.audiences,
            self.not_before,
            self.expires_at,
            self.max_delegation_depth,
            self.assurance_policy,
        )


@dataclass(frozen=True)
class ApproverAnchor:
    """One principal the operator accepts approvals from, and nothing else.

    An approver anchor lets the verifier check that approver's signatures
    from ``not_before`` through ``expires_at``; it is not a trust anchor and
    grants no authority. Approver anchors use expiry-only status.
    """

    principal: str
    accepted_methods: Tuple[str, ...]
    not_before: int
    expires_at: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted_methods", tuple(self.accepted_methods))
        if type(self.principal) is not str or not self.principal:
            raise TypeError("approver anchor principal must be a non-empty string")
        if not 1 <= len(self.accepted_methods) <= 32 or any(
            type(value) is not str or not value for value in self.accepted_methods
        ):
            raise ValueError("approver anchor needs 1 to 32 accepted methods")
        for value in (self.not_before, self.expires_at):
            if type(value) is not int or not 0 <= value <= _MAX_U64:
                raise ValueError("approver anchor validity is outside bounds")

    def _native(self) -> _native.ApproverAnchor:
        return _native.ApproverAnchor(
            _native.Principal(self.principal),
            list(self.accepted_methods),
            self.not_before,
            self.expires_at,
            None,
        )


@dataclass(frozen=True)
class ApprovalRequirement:
    """Any ``threshold`` distinct principals of ``approvers`` must approve
    every verified action. Each approver needs an :class:`ApproverAnchor`;
    an actor's own approval never counts."""

    approvers: Tuple[str, ...]
    threshold: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "approvers", tuple(self.approvers))
        if not 1 <= len(self.approvers) <= 16 or any(
            type(value) is not str or not value for value in self.approvers
        ):
            raise ValueError("approval requirement names 1 to 16 approvers")
        if type(self.threshold) is not int or not 1 <= self.threshold <= len(self.approvers):
            raise ValueError("approval threshold is outside 1 to the approver count")


@dataclass(frozen=True)
class TrustedContextRequest:
    """The one audience, challenge, and evaluation time a trusted context is
    bound to, as a gateway installation needs."""

    audience: str
    challenge: bytes
    evaluation_time: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "challenge", bytes(self.challenge))
        if len(self.challenge) != 32:
            raise ValueError("request challenge must contain 32 bytes")
        if type(self.evaluation_time) is not int or not 0 <= self.evaluation_time <= _MAX_U64:
            raise ValueError("request evaluation time is outside bounds")


def compile_trusted_context(
    *,
    anchors: Sequence[TrustAnchor],
    assurance: AssurancePolicy,
    configuration: Optional[bytes] = None,
    minimum_authorized_branches: int = 1,
    minimum_distinct_actors: int = 1,
    minimum_distinct_roots: int = 1,
    evidence_types: Sequence[str] = (),
    critical_extensions: Sequence[str] = (),
    channel_policy: str = "none-v1",
    request: Optional[TrustedContextRequest] = None,
    approver_anchors: Sequence[ApproverAnchor] = (),
    approval_requirements: Sequence[ApprovalRequirement] = (),
) -> bytes:
    """Compiles an operator's trusted context and returns its canonical bytes.

    ``configuration`` is the 32-byte verifier configuration the context pins:
    pass the one ``auths-gateway review`` prints to install trust in that
    gateway, or omit it to pin this package's own verifier. The composition
    minimums default to 1. With ``request`` the context is bound to one
    audience, challenge, and evaluation time, as a gateway installation
    needs; without it the unbound template is returned. The parameters are
    those of the TypeScript SDK's ``compileTrustedContext``.

    ``approver_anchors`` name who may approve and ``approval_requirements``
    the approvals every verified action needs; an approver is never a trust
    anchor.

    Raises ``TypeError`` or ``ValueError`` for malformed or unbounded input
    before native code runs, and the native error for input the Rust model
    rejects.
    """
    values = tuple(anchors)
    if not 1 <= len(values) <= 32:
        raise ValueError("trusted context needs 1 to 32 trust anchors")
    if any(type(value) is not TrustAnchor for value in values):
        raise TypeError("trusted context anchors must be TrustAnchor values")
    if type(assurance) is not AssurancePolicy or len(assurance.requirements) > 32:
        raise TypeError("assurance must be an AssurancePolicy of at most 32 requirements")
    if configuration is not None and len(bytes(configuration)) != 32:
        raise ValueError("verifier configuration must contain 32 bytes")
    if request is not None and type(request) is not TrustedContextRequest:
        raise TypeError("request must be a TrustedContextRequest")
    approver_values = tuple(approver_anchors)
    requirement_values = tuple(approval_requirements)
    if len(approver_values) > 32 or any(
        type(value) is not ApproverAnchor for value in approver_values
    ):
        raise TypeError("approver anchors must be at most 32 ApproverAnchor values")
    if len(requirement_values) > 4 or any(
        type(value) is not ApprovalRequirement for value in requirement_values
    ):
        raise TypeError("approval requirements must be at most 4 ApprovalRequirement values")
    compiled = compile_trust(
        anchors=[value._private() for value in values],
        assurance=assurance,
        minimum_authorized_branches=minimum_authorized_branches,
        minimum_distinct_actors=minimum_distinct_actors,
        minimum_distinct_roots=minimum_distinct_roots,
        channel_policy=channel_policy,
        evidence_types=evidence_types,
        critical_extensions=critical_extensions,
        configuration=None if configuration is None else bytes(configuration),
        approver_anchors=[value._native() for value in approver_values],
        approval_requirements=[
            (list(value.approvers), value.threshold) for value in requirement_values
        ],
    )
    context = compiled.context
    if request is not None:
        context = context.bind_request(
            request.audience, request.challenge, request.evaluation_time
        )
    return bytes(_native.inspect_trusted_context(context))


async def author_root_grant(
    *,
    signer: CustodySigner,
    subject: str,
    profile: Profile,
    permissions: Sequence[Permission],
    audiences: Sequence[str],
    not_before: int,
    expires_at: int,
    remaining_depth: int,
    assurance_floor: str,
    requested_at: int,
    critical_extensions: Sequence[Tuple[str, bytes]] = (),
) -> "GrantEvidence":
    """Asks a trust anchor's custody signer to issue one parentless grant to
    ``subject``, and returns it with the anchor's control evidence, ready to
    be the first :class:`auths.authoring.GrantEvidence` of the subject's
    chain.

    The grant permits any body of ``profile`` under ``permissions`` and
    ``audiences`` from ``not_before`` through ``expires_at``, carries no
    budget ceiling, uses expiry-only status, and carries each critical
    extension exactly as given, such as the bounded-policy commitment a
    gateway enforces. ``remaining_depth`` counts the delegations the subject
    may make. The custody request expires 300 seconds after ``requested_at``.

    A declining signer raises :class:`auths.authoring.AuthoringUnsuccessful`.
    Malformed input raises ``TypeError`` or ``ValueError`` before any
    signature is requested, and a custody response that does not bind the
    exact request raises ``ValueError``. The grant's signature is checked
    when a proof that carries it is verified.
    """
    from .authoring import AuthoringUnsuccessful, GrantEvidence

    descriptor = signer.descriptor
    if descriptor.contract != "signer-custody/2":
        raise TypeError("signer does not implement the custody contract")
    if type(subject) is not str or not subject:
        raise TypeError("grant subject must be a non-empty string")
    if type(profile) is not Profile:
        raise TypeError("grant profile must be a Profile")
    permission_values = tuple(permissions)
    if not permission_values or any(type(value) is not Permission for value in permission_values):
        raise TypeError("grant permissions must be a non-empty list of Permission values")
    audience_values = tuple(audiences)
    if not 1 <= len(audience_values) <= 32 or any(
        type(value) is not str or not value for value in audience_values
    ):
        raise ValueError("grant audiences must list 1 to 32 non-empty strings")
    extensions = tuple((str(name), bytes(body)) for name, body in critical_extensions)
    if len(extensions) > _MAX_EXTENSIONS or any(
        len(body) > _MAX_EXTENSION_BYTES for _, body in extensions
    ):
        raise ValueError("a grant carries at most 8 critical extensions of at most 16 KiB each")
    for label, value in (
        ("grant validity", not_before),
        ("grant validity", expires_at),
        ("request time", requested_at),
    ):
        if type(value) is not int or not 0 <= value <= _MAX_U64:
            raise ValueError(f"{label} is outside bounds")
    if requested_at > _MAX_U64 - 300:
        raise ValueError("request time is outside bounds")
    if type(remaining_depth) is not int or not 0 <= remaining_depth <= 0xFFFF:
        raise ValueError("delegation depth must be a whole number from 0 to 65535")
    unsigned = _native.root_grant(
        _native.Principal(descriptor.principal),
        _native.GrantRequest(
            _native.Principal(subject),
            profile.id,
            profile.version,
            [(value.capability, value.resource) for value in permission_values],
            not_before,
            expires_at,
            list(audience_values),
            None,
            None,
            remaining_depth,
            None,
            assurance_floor,
            list(extensions),
        ),
    )
    signature = descriptor.signature
    prepared = _native.prepare_signing(
        unsigned,
        signature.principal_method,
        signature.verification_method,
        signature.suite,
    )
    custody_request = SigningRequest(
        prepared.request_id,
        SigningObjectKind.GRANT,
        bytes(prepared.object_id),
        descriptor,
        bytes(prepared.transaction_digest),
        bytes(prepared.signing_preimage),
        requested_at + 300,
        (
            ReviewField("grant subject", subject),
            ReviewField("profile", f"{profile.id}/{profile.version}"),
            ReviewField(
                "permissions",
                ", ".join(f"{value.capability} {value.resource}" for value in permission_values),
            ),
            ReviewField("audiences", ", ".join(audience_values)),
            ReviewField("valid", f"{not_before} to {expires_at}"),
            ReviewField("further delegations", str(remaining_depth)),
            ReviewField(
                "critical extensions",
                ", ".join(f"{name} ({len(body)} bytes)" for name, body in extensions)
                or "none",
            ),
        ),
    )
    outcome = await signer.sign(custody_request)
    if isinstance(outcome, (CustodyRejected, CustodyIndeterminate)):
        kind: Literal["rejected", "indeterminate"] = (
            "rejected" if isinstance(outcome, CustodyRejected) else "indeterminate"
        )
        raise AuthoringUnsuccessful(kind=kind, code=str(outcome.failure))
    if not isinstance(outcome, CustodySigned):
        raise TypeError("custody signer returned an invalid result")
    response = outcome.response
    if (
        response.request_id != custody_request.request_id
        or response.object_id != custody_request.object_id
        or response.principal != descriptor.principal
        or response.descriptor != descriptor.signature
        or response.provider_key_version != descriptor.key_version
        or response.transaction_digest != custody_request.transaction_digest
        or not 1 <= len(response.evidence) <= 32
    ):
        raise ValueError("custody response does not bind the exact signing request")
    signed = bytes(_native.inspect_signed(prepared.complete(bytes(response.signature))))
    _native.parse_signed("grant", signed)
    return GrantEvidence(signed, tuple(response.evidence))


class _DevelopmentSigner:
    """Development custody over a local Ed25519 seed file."""

    def __init__(self, seed: bytes) -> None:
        self._key = _native.DevelopmentEd25519Key.from_seed(seed)
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "auths.development-ed25519",
            self._key.principal,
            CustodySignatureDescriptor(
                self._key.principal_method, self._key.verification_method, self._key.suite
            ),
            "development-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.descriptor.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                bytes(self._key.sign(request.signing_preimage)),
                (
                    PublicControlEvidence(
                        self._key.evidence_type, self._key.media_type, bytes(self._key.evidence)
                    ),
                ),
            ),
        )

    async def aclose(self) -> None:
        return None


@dataclass(frozen=True)
class SignerFile:
    """What an ``auths.approval-signer/1`` file describes: a custody signer
    and whether it is development custody over a local key file."""

    signer: CustodySigner
    development: bool


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("signer configuration entries must be objects")
    return cast(dict[str, object], value)


def load_signer_file(path: Union[str, Path]) -> SignerFile:
    """Loads the signer an ``auths.approval-signer/1`` file describes, the
    format ``auths approve --signer`` reads.

    ``development-ed25519`` custody reads a 32-byte seed from ``seed_file``,
    relative to the signer file. ``module`` custody calls the factory that
    ``python`` names, as ``package.module:factory``, with the parsed file.
    ``grants`` lists the signer's grant chain, root first, each as
    ``signed_grant_b64`` with its ``evidence``.

    Raises ``ValueError`` for a missing, symlinked, oversized, or malformed
    file, and the import error of an unavailable custody module. The caller
    closes the returned signer.
    """
    location = Path(path)
    if (
        location.is_symlink()
        or not location.is_file()
        or location.stat().st_size > _MAX_SIGNER_FILE_BYTES
    ):
        raise ValueError("signer configuration is unavailable or outside bounds")
    config = _mapping(json.loads(location.read_text(encoding="utf-8")))
    if config.get("schema") != _SIGNER_SCHEMA:
        raise ValueError(f"signer configuration must declare schema {_SIGNER_SCHEMA}")
    if "grants" in config:
        raise ValueError("an approval signer carries no grant chain; remove grants")
    custody = config.get("custody")
    if custody == "development-ed25519":
        seed_file = config.get("seed_file")
        if not isinstance(seed_file, str):
            raise ValueError("development custody needs seed_file")
        seed = (location.parent / seed_file).resolve().read_bytes()
        if len(seed) != 32:
            raise ValueError("development seed must contain 32 bytes")
        return SignerFile(_DevelopmentSigner(seed), True)
    if custody == "module":
        target = config.get("python")
        if not isinstance(target, str) or ":" not in target:
            raise ValueError("module custody needs python = 'package.module:factory'")
        module_name, _, factory_name = target.partition(":")
        factory: Callable[[dict[str, object]], CustodySigner] = getattr(
            importlib.import_module(module_name), factory_name
        )
        signer = factory(config)
        if signer.descriptor.contract != "signer-custody/2":
            raise ValueError("module custody factory did not return a custody signer")
        return SignerFile(signer, False)
    raise ValueError("signer custody must be development-ed25519 or module")


__all__ = [
    "ApprovalRequirement",
    "ApproverAnchor",
    "SignerFile",
    "TrustAnchor",
    "TrustedContextRequest",
    "author_root_grant",
    "compile_trusted_context",
    "load_signer_file",
]
