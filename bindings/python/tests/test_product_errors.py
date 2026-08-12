from __future__ import annotations

import json
from pathlib import Path

import pytest

from auths._product_errors import (
    AuthsError,
    EffectState,
    RecommendedAction,
    RetryClass,
    CauseCategory,
    cause_category_from,
    create_support_bundle,
    format_auths_error,
)
from auths.profiles import mcp
from auths.verify import decode_receipt
from auths._workflow import AuthsWorkflowError

ROOT = Path(__file__).parents[3]
FIXTURES = json.loads((ROOT / "product/fixtures/v1/errors/manifest.json").read_text())[
    "fixtures"
]


def test_every_rust_owned_error_fixture_parses_to_the_same_recovery_contract() -> None:
    for fixture in FIXTURES:
        error = AuthsError.parse(fixture)
        assert error.code == fixture["code"]
        assert error.code in format_auths_error(error)
        if error.effect is EffectState.POSSIBLE:
            assert error.retry is RetryClass.UNKNOWN
            assert error.recommended_action is RecommendedAction.RESUME_AND_RECONCILE
            assert error.execution_reference is not None


def test_unsafe_retry_and_unbounded_causes_fail_closed() -> None:
    possible = next(fixture for fixture in FIXTURES if fixture["effect"] == "possible")
    with pytest.raises(ValueError, match="not registered"):
        AuthsError.parse({**possible, "retry": "safe"})
    with pytest.raises(ValueError, match="causes"):
        AuthsError.parse({**possible, "causes": ["unknown"] * 9})
    assert "provider_body" not in repr(dict(AuthsError.parse(possible).to_dict()))


def test_support_bundles_are_deterministic_and_bounded() -> None:
    error = AuthsError.parse(FIXTURES[0])
    inputs = {
        "sdk_version": "1.0.0-rc.1",
        "runtime_family": "python",
        "runtime_version": "3.13.14",
        "platform": "linux-x64",
        "abi_version": "native-2",
        "semantic_subject": "auths-v1",
        "profiles": ["mcp/1"],
        "capabilities": ["verify", "execute", "verify"],
        "errors": [error],
    }
    assert dict(create_support_bundle(**inputs)) == dict(
        create_support_bundle(**inputs)
    )


def test_provider_failures_collapse_to_bounded_cause_categories() -> None:
    failure = TimeoutError("credential=never-cross-this-boundary")
    assert cause_category_from(failure) is CauseCategory.TIMEOUT
    assert "credential" not in cause_category_from(failure).value


def test_future_error_codes_remain_bounded_without_inferred_recovery() -> None:
    future = {
        **FIXTURES[0],
        "code": "future.new-code",
        "retry": "safe",
        "effect": "applied",
        "executionReference": "secret-reference",
        "causes": ["future-cause"],
    }
    error = AuthsError.parse(future)
    assert error.code == "future.new-code"
    assert error.details.family == "unknown"
    assert error.retry is RetryClass.UNKNOWN
    assert error.effect is EffectState.UNKNOWN
    assert error.execution_reference is None
    assert error.recommended_action is RecommendedAction.CONTACT_SUPPORT


def test_future_profile_and_receipt_versions_fail_before_interpretation() -> None:
    with pytest.raises(AuthsWorkflowError, match="unsupported MCP profile version"):
        mcp.profile(service="future", version=2)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported portable Auths receipt"):
        decode_receipt(b'{"schema":"auths.portable-receipt/2"}')
