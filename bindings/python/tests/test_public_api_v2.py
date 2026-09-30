from __future__ import annotations

import importlib

import pytest

import auths
import auths.adapters
import auths.adapters.custody
import auths.adapters.reservations
import auths.attempts
import auths.authoring
import auths.execution
import auths.gateway
import auths.identity
import auths.identity.adapters
import auths.identity.authoring
import auths.protocol
import auths.self_hosted
import auths.testkit
import auths.verify


EXPECTED_EXPORTS = {
    "auths": 10,
    "auths.verify": 23,
    "auths.authoring": 24,
    "auths.attempts": 5,
    "auths.execution": 11,
    "auths.gateway": 17,
    "auths.self_hosted": 28,
    "auths.identity": 11,
    "auths.identity.adapters": 14,
    "auths.identity.authoring": 4,
    "auths.protocol": 6,
    "auths.adapters": 2,
    "auths.adapters.custody": 16,
    "auths.adapters.reservations": 2,
    "auths.testkit": 14,
}


def test_exact_public_inventory() -> None:
    for name, expected in EXPECTED_EXPORTS.items():
        module = importlib.import_module(name)
        exported = module.__all__
        assert isinstance(exported, list)
        assert len(exported) == expected
        assert len(set(exported)) == expected
        assert all(hasattr(module, value) for value in exported)
    assert sum(EXPECTED_EXPORTS.values()) == 187


def test_product_root_is_small_and_removed_names_are_absent() -> None:
    assert auths.__all__ == [
        "AuthsError", "EffectState", "EnteredBoundaries", "ErrorInfo",
        "KnownAuthsErrorCode", "Receipt", "RecommendedAction", "RetryClass",
        "RuntimeInfo", "runtime_info",
    ]
    for removed in (
        "Client", "ClientOptions", "Completed", "ExecutionReference", "Operations",
        "RecoveryHandle", "connect", "create_auths", "doctor",
    ):
        assert not hasattr(auths, removed)


def test_local_agent_client_modules_are_not_importable() -> None:
    for removed in ("auths.profile_runtime", "auths._session"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(removed)


def test_receipts_reject_direct_construction() -> None:
    with pytest.raises(TypeError):
        auths.Receipt(object(), "forged", b"forged")
