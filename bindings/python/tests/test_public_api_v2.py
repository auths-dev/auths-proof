from __future__ import annotations

import importlib

import pytest

import auths
import auths.adapters
import auths.adapters.custody
import auths.adapters.reservations
import auths.identity
import auths.identity.adapters
import auths.identity.authoring
import auths.profile_runtime
import auths.protocol
import auths.testkit
import auths.verify


EXPECTED_EXPORTS = {
    "auths": 28,
    "auths.verify": 23,
    "auths.identity": 11,
    "auths.identity.adapters": 14,
    "auths.identity.authoring": 4,
    "auths.protocol": 6,
    "auths.profile_runtime": 14,
    "auths.adapters": 2,
    "auths.adapters.custody": 16,
    "auths.adapters.reservations": 2,
    "auths.testkit": 8,
}


def test_exact_public_inventory() -> None:
    for name, expected in EXPECTED_EXPORTS.items():
        module = importlib.import_module(name)
        exported = module.__all__
        assert isinstance(exported, list)
        assert len(exported) == expected
        assert len(set(exported)) == expected
        assert all(hasattr(module, value) for value in exported)
    assert sum(EXPECTED_EXPORTS.values()) == 128


def test_product_root_is_small_and_removed_names_are_absent() -> None:
    assert auths.__all__ == [
        "AuthsError", "EffectState", "EnteredBoundaries", "ErrorInfo",
        "KnownAuthsErrorCode", "Receipt", "RecommendedAction", "RetryClass",
        "RuntimeInfo", "runtime_info", "Client", "ClientOptions",
        "ClientStateError", "ConflictError", "DeniedError", "NotAppliedError",
        "OperationMetadata", "OperationOptions", "OperationState",
        "OperationStatus", "Operations", "PartialError",
        "RecoveryHandle", "RecoveryOptions", "RecoveryRequired",
        "ReceiptIntegrityError", "UnavailableError", "connect",
    ]
    for removed in ("Completed", "ExecutionReference", "create_auths", "doctor"):
        assert not hasattr(auths, removed)


def test_profile_runtime_is_a_public_sealed_generated_package_surface() -> None:
    runtime = auths.profile_runtime
    assert runtime.PROFILE_CLIENT_RUNTIME == "auths.profile-client-runtime/1"
    assert runtime.__all__ == [
        "PROFILE_CLIENT_RUNTIME", "BoundProfile", "Completed", "Conflict",
        "Denied", "NotApplied", "Partial", "ProfileDescriptor",
        "ProfileFile", "ProfileOutcome", "RecoveryRequired",
        "ReceiptIntegrityFailed", "Unavailable", "bind_profile",
    ]
    with pytest.raises(TypeError, match="sealed"):
        runtime.Completed(object(), "completed", object())


def test_receipts_reject_direct_construction() -> None:
    with pytest.raises(TypeError):
        auths.Receipt(object(), "forged", b"forged")
