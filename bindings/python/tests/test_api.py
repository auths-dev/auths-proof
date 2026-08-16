from __future__ import annotations

import copy
import pickle
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest

import auths
import auths._native as native_implementation
from auths.verify import AuthorizedResult, DeniedResult, verify
from auths._inspection import canonical_action_bytes

VerifiedAction = native_implementation.VerifiedAction


CORPUS = Path(__file__).parents[3] / "core" / "fixtures" / "v1" / "valid"
BINDING_VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"


def test_doctor_reports_only_bounded_installed_runtime_facts() -> None:
    report = auths.doctor(mode="development", state="in-memory")
    assert report.status == "ready"
    assert report.native_abi_compatible
    assert report.profiles == ("mcp/1",)
    assert report.warnings == (
        "development custody and trust are not production",
        "in-memory state is not production durable",
    )
    command = subprocess.run(
        [sys.executable, "-m", "auths", "doctor"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert command.returncode == 0
    assert "Native ABI       compatible" in command.stdout
    assert "Profiles         mcp/1" in command.stdout
    assert not any(
        value in command.stdout.lower()
        for value in (
            "credential",
            "private key",
            "signature",
            "proof bytes",
            "command bytes",
        )
    )


def test_identity_and_verify_imports_do_not_load_effect_workflow() -> None:
    source = """
import sys
import auths.identity
import auths.verify
forbidden = [
    name for name in sys.modules
    if name.startswith(('auths._workflow', 'auths._approvals', 'auths._custody', 'auths.profiles'))
]
if forbidden:
    raise RuntimeError(','.join(forbidden))
"""
    result = subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def authorized_result() -> AuthorizedResult:
    result = verify(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (BINDING_VECTORS / "authorized.context.cbor").read_bytes(),
    )
    assert isinstance(result, AuthorizedResult)
    return result


def native_action() -> VerifiedAction:
    result = native_implementation.verify_v1(
        (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
        (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
        (BINDING_VECTORS / "authorized.context.cbor").read_bytes(),
    )
    assert result.action is not None
    return result.action


def test_public_verification_is_inert_and_native_api_seals_the_action() -> None:
    result = authorized_result()

    assert result.code == "authorized"
    assert result.required_configuration == result.local_configuration
    assert len(result.local_configuration) == 32
    assert not hasattr(result, "action")
    assert (
        canonical_action_bytes(native_action())
        == (CORPUS / "raw-key-chain.action.cbor").read_bytes()
    )
    assert (
        result.result_cbor == (BINDING_VECTORS / "authorized.result.cbor").read_bytes()
    )


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
    assert not hasattr(native_action(), "__dict__")


def test_verified_action_rejects_copy_pickle_reduce_and_mutation() -> None:
    action = native_action()

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
    canonical = canonical_action_bytes(native_action())

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

    assert isinstance(result, DeniedResult)
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

    assert isinstance(result, DeniedResult)
    assert result.stage == "decode"
    assert result.code == "malformed-proof"
    assert not hasattr(result, "action")
