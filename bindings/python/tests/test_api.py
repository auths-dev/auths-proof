from __future__ import annotations

from pathlib import Path

import pytest

import auths_proof
from auths_proof import Authorized, Denied, VerifiedAction, verify


CORPUS = (
    Path(__file__).parents[3]
    / "core"
    / "fixtures"
    / "v1"
    / "valid"
)
BINDING_VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"


def test_native_api_returns_a_sealed_authorized_action() -> None:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (BINDING_VECTORS / "authorized.context.cbor").read_bytes(),
    )

    assert isinstance(result, Authorized)
    assert result.code == "authorized"
    assert result.required_configuration == result.local_configuration
    assert len(result.local_configuration) == 32
    assert result.action.canonical_bytes == (
        CORPUS / "raw-key-chain.action.cbor"
    ).read_bytes()
    assert result.result_cbor == (
        BINDING_VECTORS / "authorized.result.cbor"
    ).read_bytes()


def test_verified_action_cannot_be_constructed_by_application_code() -> None:
    with pytest.raises(TypeError, match="sealed"):
        VerifiedAction(object(), b"unverified")


def test_configuration_mismatch_reports_required_and_executed_commitments() -> None:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.context.cbor").read_bytes(),
    )

    assert isinstance(result, Denied)
    assert result.code == "verifier-configuration-mismatch"
    assert result.required_configuration is not None
    assert len(result.required_configuration) == 32
    assert len(result.local_configuration) == 32
    assert result.required_configuration != result.local_configuration


def test_portable_decoder_rejects_shape_version_and_trailing_data() -> None:
    canonical = (BINDING_VECTORS / "authorized.result.cbor").read_bytes()
    assert canonical[0] == 0xB0
    assert canonical[-2:] == b"\x0f\x02"

    with pytest.raises(ValueError, match="trailing"):
        auths_proof._decode_result(canonical + b"\x00")

    reordered_keys = bytes([0xB0, 0x01, 0x04, 0x00, 0x00]) + canonical[5:]
    with pytest.raises(ValueError, match="canonical"):
        auths_proof._decode_result(reordered_keys)

    unknown_field = bytes([0xB1]) + canonical[1:] + b"\x10\xf6"
    with pytest.raises(ValueError, match="shape"):
        auths_proof._decode_result(unknown_field)

    with pytest.raises(ValueError, match="ABI version"):
        auths_proof._decode_result(canonical[:-1] + b"\x03")
