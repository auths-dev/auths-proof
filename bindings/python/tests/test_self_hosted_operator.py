"""The public operator steps give the bytes the native path gives: a
trusted context bound to one request, a root grant through a custody signer,
and the signer an `auths.approval-signer/1` file describes."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from auths import _native
from auths.adapters.custody import (
    CustodyFailure,
    CustodyRejected,
    CustodySigned,
    SigningObjectKind,
    SigningRequest,
)
from auths.authoring import AuthoringUnsuccessful
from auths.self_hosted import (
    AssurancePolicy,
    AssuranceRequirement,
    Permission,
    Profile,
    SignerFile,
    TrustAnchor,
    TrustedContextRequest,
    author_root_grant,
    compile_trusted_context,
    load_signer_file,
)

ASSURANCE = "raw-key-baseline"
AUDIENCE = "mcp://stripe-refunds"
PERMISSION = Permission("tools/call", f"{AUDIENCE}/tools/create_refund")
PROFILE = Profile("auths.mcp", 2)
NOW = 1_800_000_000
CHALLENGE = bytes(range(32))
EXTENSION = ("auths.bounded-policy/1", b"\x01\x02\x03")


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def signer_file(directory: Path, name: str, seed: bytes) -> Path:
    home = directory / name
    home.mkdir()
    (home / "signing.seed").write_bytes(seed)
    path = home / "signer.json"
    path.write_text(
        json.dumps(
            {
                "schema": "auths.approval-signer/1",
                "custody": "development-ed25519",
                "seed_file": "signing.seed",
            }
        )
    )
    return path


def policy() -> AssurancePolicy:
    return AssurancePolicy(
        ASSURANCE,
        (
            AssuranceRequirement("root", "every", "self-certifying-identifier"),
            AssuranceRequirement("actor", "every", "self-certifying-identifier"),
            AssuranceRequirement("actor", "every", "offline-verifiable"),
        ),
    )


def anchor(name: str, principal: str, depth: int) -> TrustAnchor:
    return TrustAnchor(
        name,
        principal,
        ("raw-key-v1",),
        (PROFILE,),
        (PERMISSION,),
        (AUDIENCE,),
        (AUDIENCE,),
        NOW - 300,
        NOW + 86_400,
        depth,
        ASSURANCE,
    )


def native_anchor(name: str, principal: str, depth: int) -> Any:
    return _native.TrustAnchor(
        name,
        _native.Principal(principal),
        ["raw-key-v1"],
        [("auths.mcp", 2)],
        [(PERMISSION.capability, PERMISSION.resource)],
        [AUDIENCE],
        [AUDIENCE],
        NOW - 300,
        NOW + 86_400,
        None,
        depth,
        ASSURANCE,
        None,
    )


def native_assurance() -> Any:
    return _native.AssurancePolicy(
        ASSURANCE,
        [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ],
    )


def principal_of(seed: bytes) -> str:
    return str(_native.DevelopmentEd25519Key.from_seed(seed).principal)


def test_trusted_context_is_the_native_compile_bound_to_one_request() -> None:
    root, manager = principal_of(b"\x01" * 32), principal_of(b"\x02" * 32)
    configuration = bytes(_native.self_contained_configuration())
    compiled = compile_trusted_context(
        anchors=[anchor("root", root, 1), anchor("manager", manager, 0)],
        assurance=policy(),
        configuration=configuration,
        minimum_authorized_branches=2,
        minimum_distinct_actors=2,
        minimum_distinct_roots=2,
        evidence_types=("raw-key-v1",),
        critical_extensions=(EXTENSION[0],),
        request=TrustedContextRequest(AUDIENCE, CHALLENGE, NOW),
    )
    template = _native.compile_trusted_context(
        configuration,
        None,
        2,
        2,
        2,
        [native_anchor("root", root, 1), native_anchor("manager", manager, 0)],
        native_assurance(),
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        [EXTENSION[0]],
    )
    assert compiled == bytes(_native.inspect_trusted_context(template.bind_request(AUDIENCE, CHALLENGE, NOW)))
    # Omitting the configuration pins this package's own verifier; omitting
    # the request returns the unbound template.
    assert compile_trusted_context(
        anchors=[anchor("root", root, 1), anchor("manager", manager, 0)],
        assurance=policy(),
        minimum_authorized_branches=2,
        minimum_distinct_actors=2,
        minimum_distinct_roots=2,
        evidence_types=("raw-key-v1",),
        critical_extensions=(EXTENSION[0],),
    ) == bytes(_native.inspect_trusted_context(template))


def test_trusted_context_input_is_checked_before_native_code() -> None:
    root = anchor("root", principal_of(b"\x01" * 32), 1)
    with pytest.raises(ValueError):
        compile_trusted_context(anchors=[], assurance=policy())
    with pytest.raises(ValueError):
        compile_trusted_context(anchors=[root] * 33, assurance=policy())
    with pytest.raises(TypeError):
        compile_trusted_context(anchors=["root"], assurance=policy())  # type: ignore[list-item]
    with pytest.raises(ValueError):
        compile_trusted_context(anchors=[root], assurance=policy(), configuration=bytes(31))
    with pytest.raises(ValueError):
        TrustedContextRequest(AUDIENCE, bytes(31), NOW)
    with pytest.raises(ValueError):
        TrustedContextRequest(AUDIENCE, CHALLENGE, -1)
    with pytest.raises(TypeError):
        anchor("root", "", 1)


def test_root_grant_equals_the_native_path_and_carries_the_signer_evidence(tmp_path: Path) -> None:
    seed = b"\x03" * 32
    root = load_signer_file(signer_file(tmp_path, "root", seed))
    agent = principal_of(b"\x04" * 32)
    evidence = asyncio.run(
        author_root_grant(
            signer=root.signer,
            subject=agent,
            profile=PROFILE,
            permissions=[PERMISSION],
            audiences=[AUDIENCE],
            not_before=NOW - 300,
            expires_at=NOW + 86_400,
            remaining_depth=0,
            assurance_floor=ASSURANCE,
            requested_at=NOW,
            critical_extensions=[EXTENSION],
        )
    )
    key = _native.DevelopmentEd25519Key.from_seed(seed)
    signing = _native.prepare_signing(
        _native.root_grant(
            _native.Principal(key.principal),
            _native.GrantRequest(
                _native.Principal(agent),
                "auths.mcp",
                2,
                [(PERMISSION.capability, PERMISSION.resource)],
                NOW - 300,
                NOW + 86_400,
                [AUDIENCE],
                None,
                None,
                0,
                None,
                ASSURANCE,
                [EXTENSION],
            ),
        ),
        key.principal_method,
        key.verification_method,
        key.suite,
    )
    expected = bytes(_native.inspect_signed(signing.complete(key.sign(signing.signing_preimage))))
    assert evidence.signed_grant == expected
    assert [(item.evidence_type, item.media_type, item.bytes) for item in evidence.evidence] == [
        (key.evidence_type, key.media_type, bytes(key.evidence))
    ]


class _Declining:
    def __init__(self, loaded: SignerFile) -> None:
        self.descriptor = loaded.signer.descriptor
        self.requests: List[SigningRequest] = []

    async def sign(self, request: SigningRequest) -> CustodyRejected:
        self.requests.append(request)
        return CustodyRejected("rejected", CustodyFailure.DENIED)

    async def aclose(self) -> None:
        return None


class _Mismatched:
    def __init__(self, loaded: SignerFile) -> None:
        self.inner = loaded.signer
        self.descriptor = loaded.signer.descriptor

    async def sign(self, request: SigningRequest) -> CustodySigned:
        signed = await self.inner.sign(request)
        assert isinstance(signed, CustodySigned)
        response = dataclasses.replace(signed.response, request_id="another-request")
        return CustodySigned("signed", response)

    async def aclose(self) -> None:
        return None


def grant_with(signer: Any, **changes: Any) -> Any:
    arguments: Dict[str, Any] = {
        "signer": signer,
        "subject": principal_of(b"\x04" * 32),
        "profile": PROFILE,
        "permissions": [PERMISSION],
        "audiences": [AUDIENCE],
        "not_before": NOW - 300,
        "expires_at": NOW + 86_400,
        "remaining_depth": 0,
        "assurance_floor": ASSURANCE,
        "requested_at": NOW,
    }
    arguments.update(changes)
    return asyncio.run(author_root_grant(**arguments))


def test_root_grant_refuses_a_decline_a_mismatched_response_and_bad_input(tmp_path: Path) -> None:
    loaded = load_signer_file(signer_file(tmp_path, "root", b"\x05" * 32))
    declining = _Declining(loaded)
    with pytest.raises(AuthoringUnsuccessful) as declined:
        grant_with(declining)
    assert (declined.value.kind, declined.value.code) == ("rejected", "denied")
    request = declining.requests[0]
    assert request.object_kind is SigningObjectKind.GRANT and request.expires_at_unix_seconds == NOW + 300
    assert [field.label for field in request.display][:2] == ["grant subject", "profile"]
    with pytest.raises(ValueError):
        grant_with(_Mismatched(loaded))
    for changes, error in (
        ({"permissions": []}, TypeError),
        ({"audiences": []}, ValueError),
        ({"subject": ""}, TypeError),
        ({"remaining_depth": 70_000}, ValueError),
        ({"requested_at": 2**64 - 1}, ValueError),
        ({"critical_extensions": [EXTENSION] * 9}, ValueError),
        ({"critical_extensions": [(EXTENSION[0], bytes(16_385))]}, ValueError),
    ):
        with pytest.raises(error):
            grant_with(loaded.signer, **changes)


def test_signer_file_loads_development_custody(tmp_path: Path) -> None:
    seed = b"\x06" * 32
    loaded = load_signer_file(signer_file(tmp_path, "manager", seed))
    assert loaded.development
    assert loaded.signer.descriptor.principal == principal_of(seed)
    assert loaded.signer.descriptor.contract == "signer-custody/2"
    asyncio.run(loaded.signer.aclose())


def test_signer_file_refuses_links_and_malformed_files(tmp_path: Path) -> None:
    path = signer_file(tmp_path, "agent", b"\x07" * 32)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        load_signer_file(link)
    for change in (
        {"schema": "auths.approval-signer/2"},
        {"seed_file": None},
        {"custody": "hardware"},
        {"custody": "module", "python": "no-factory"},
        {"grants": []},
    ):
        document = json.loads(path.read_text())
        document.update(change)
        broken = tmp_path / "broken.json"
        broken.write_text(json.dumps(document))
        with pytest.raises(ValueError):
            load_signer_file(broken)
    (path.parent / "signing.seed").write_bytes(b"\x07" * 31)
    with pytest.raises(ValueError):
        load_signer_file(path)
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (1_048_576 + 1))
    with pytest.raises(ValueError):
        load_signer_file(big)


def test_signer_file_calls_a_module_custody_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    development = load_signer_file(signer_file(tmp_path, "agent", b"\x08" * 32))
    module = tmp_path / "custody_for_test.py"
    module.write_text(
        "RECEIVED = []\n"
        "SIGNER = None\n"
        "def factory(config):\n"
        "    RECEIVED.append(config)\n"
        "    return SIGNER\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    import custody_for_test  # type: ignore[import-not-found]

    custody_for_test.SIGNER = development.signer
    path = tmp_path / "module.json"
    path.write_text(
        json.dumps({"schema": "auths.approval-signer/1", "custody": "module", "python": "custody_for_test:factory"})
    )
    loaded = load_signer_file(path)
    assert loaded.signer is development.signer and not loaded.development
    assert custody_for_test.RECEIVED == [json.loads(path.read_text())]
    monkeypatch.delitem(sys.modules, "custody_for_test")
