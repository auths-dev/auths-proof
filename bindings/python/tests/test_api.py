from __future__ import annotations

from pathlib import Path

import pytest

from auths_proof import Authorized, VerifiedAction, verify


CORPUS = (
    Path(__file__).parents[3]
    / "core"
    / "fixtures"
    / "v1"
    / "valid"
)


def test_native_api_returns_a_sealed_authorized_action() -> None:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.context.cbor").read_bytes(),
    )

    assert isinstance(result, Authorized)
    assert result.code == "authorized"
    assert result.action.canonical_bytes == (
        CORPUS / "raw-key-chain.action.cbor"
    ).read_bytes()
    assert result.result_cbor == (CORPUS / "raw-key-chain.result.cbor").read_bytes()


def test_verified_action_cannot_be_constructed_by_application_code() -> None:
    with pytest.raises(TypeError, match="sealed"):
        VerifiedAction(object(), b"unverified")
