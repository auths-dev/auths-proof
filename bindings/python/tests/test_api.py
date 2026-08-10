from __future__ import annotations

import copy
import pickle
from pathlib import Path
from typing import Callable

import pytest

import auths
import auths._native as native_implementation
from auths import Authorized, Denied, VerifiedAction, verify
from auths.advanced import canonical_action_bytes


CORPUS = Path(__file__).parents[3] / "core" / "fixtures" / "v1" / "valid"
BINDING_VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"


def authorized_result() -> Authorized:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (BINDING_VECTORS / "authorized.context.cbor").read_bytes(),
    )
    assert isinstance(result, Authorized)
    return result


def test_native_api_returns_the_core_sealed_authorized_action() -> None:
    result = authorized_result()

    assert result.code == "authorized"
    assert result.required_configuration == result.local_configuration
    assert len(result.local_configuration) == 32
    assert canonical_action_bytes(result.action) == (
        CORPUS / "raw-key-chain.action.cbor"
    ).read_bytes()
    assert result.result_cbor == (
        BINDING_VECTORS / "authorized.result.cbor"
    ).read_bytes()


def test_verified_action_has_no_python_construction_path() -> None:
    operations: tuple[Callable[[], object], ...] = (
        lambda: VerifiedAction(),
        lambda: object.__new__(VerifiedAction),
        lambda: VerifiedAction.__new__(VerifiedAction),
    )
    for operation in operations:
        with pytest.raises(TypeError):
            operation()
    with pytest.raises(TypeError):
        type("ForgedAction", (VerifiedAction,), {})

    assert not hasattr(auths, "_AUTHORIZED_TOKEN")
    assert not any(
        isinstance(value, VerifiedAction)
        for value in vars(native_implementation).values()
    )
    assert not hasattr(authorized_result().action, "__dict__")


def test_verified_action_rejects_copy_pickle_reduce_and_mutation() -> None:
    action = authorized_result().action

    operations: tuple[Callable[[], object], ...] = (
        lambda: copy.copy(action),
        lambda: copy.deepcopy(action),
        lambda: pickle.dumps(action),
        lambda: action.__reduce__(),
        lambda: action.__reduce_ex__(5),
    )
    for operation in operations:
        with pytest.raises(TypeError, match="native capability"):
            operation()
    with pytest.raises(AttributeError):
        action.authorized = False  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        object.__setattr__(action, "authorized", False)
    with pytest.raises(TypeError):
        memoryview(action)  # type: ignore[arg-type]


def test_canonical_bytes_do_not_promote_to_a_capability() -> None:
    canonical = canonical_action_bytes(authorized_result().action)

    assert isinstance(canonical, bytes)
    with pytest.raises(TypeError):
        VerifiedAction(canonical)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        canonical_action_bytes(canonical)  # type: ignore[arg-type]


def test_configuration_mismatch_has_no_authorization_handle() -> None:
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
    assert not hasattr(result, "action")


def test_native_result_parser_preserves_decode_failure_codes() -> None:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        b"not-canonical-cbor",
        (BINDING_VECTORS / "authorized.context.cbor").read_bytes(),
    )

    assert isinstance(result, Denied)
    assert result.stage == "decode"
    assert result.code == "malformed-proof"
    assert not hasattr(result, "action")
