"""The pyo3 transport carries meaning; it does not define any.

Three properties, each of which was false before this suite existed:

1. A failure crossing the pyo3 boundary arrives with the Rust registry's own
   classification attached -- stable code, effect state, retry class,
   recommended action -- and an unrecognised code fails closed to ``possible``.
2. The boundary exports no generic reference vertical, so a Python caller
   cannot define a vertical whose canonical form lives in Python.
3. A panic in the native layer cannot take the host interpreter down.

Every expected value here is derived from ``product/errors/v1/registry.json``
or from ``auths._native`` itself. Nothing is hardcoded from memory.
"""

from __future__ import annotations

import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from auths import _native

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_REGISTRY = json.loads(
    (_REPO_ROOT / "product/errors/v1/registry.json").read_text(encoding="utf-8")
)
_ABI = json.loads(
    (_PACKAGE_ROOT / "native-abi-v2.json").read_text(encoding="utf-8")
)

BY_CODE = {definition["code"]: definition for definition in _REGISTRY["definitions"]}

# auths_errors::EffectState has exactly three members. There is no fourth.
EFFECT_STATES = ("not-applied", "possible", "applied")
RETRY_CLASSES = ("never", "safe", "conditional", "unknown")


def _exported() -> set[str]:
    return {name for name in dir(_native) if not name.startswith("__")}


# ---------------------------------------------------------------------------
# 1. Errors cross structured.
# ---------------------------------------------------------------------------


def test_the_boundary_exception_carries_the_registry_classification() -> None:
    with pytest.raises(_native.NativeAuthsError) as caught:
        _native.decode_identity_v1(b"\xff\xff\xff")
    error = caught.value
    assert error.code in BY_CODE, (
        f"the boundary reported code {error.code!r}, which exists in no registry. "
        "Bindings mint no error codes."
    )
    definition = BY_CODE[error.code]
    outcomes = definition["outcomes"]
    assert error.effect in EFFECT_STATES
    assert error.retry in RETRY_CLASSES
    assert error.effect == outcomes[0]["effect"], (
        "the boundary reported an effect the registry does not declare for this code"
    )
    assert error.retry == outcomes[0]["retry"]
    assert error.recommended_action == definition["recommendedAction"]
    assert error.registered is True
    assert error.summary


def test_a_decoder_failure_is_provably_not_applied() -> None:
    """A pure decoder performed no effect, so it may say so."""
    with pytest.raises(_native.NativeAuthsError) as caught:
        _native.decode_identity_v1(b"\xff\xff\xff")
    assert caught.value.effect == "not-applied"


def test_an_undecodable_service_response_fails_closed_to_possible() -> None:
    """The service may already have applied the effect (contract 5.3).

    Reading `not-applied` off a response we could not parse would tell a caller
    that a possibly-committed write is safe to retry blindly.
    """
    with pytest.raises(_native.NativeAuthsError) as caught:
        _native.decode_production_response_v1(b"\x01\x02\x03")
    error = caught.value
    assert error.effect == "possible", (
        "an unreadable service response was classified as 'nothing happened'"
    )
    assert error.retry == "unknown"
    assert error.recommended_action == "resume-and-reconcile"


def test_an_unregistered_code_fails_closed_to_possible() -> None:
    code, effect, retry, action, registered = _native.error_classification_v1(
        "not.a.registry.code"
    )
    assert code == "not.a.registry.code"
    assert registered is False
    assert effect == "possible", (
        "an unknown code was not failed closed to 'possible'. A newer Rust code "
        "must never be silently downgraded to 'nothing happened' by an older binding."
    )
    assert retry == "unknown"
    assert action == "resume-and-reconcile"


def test_every_registry_code_classifies_through_the_native_layer() -> None:
    """Differential: the native classifier and the registry agree on all 48."""
    disagreements = []
    for definition in _REGISTRY["definitions"]:
        code, effect, retry, action, registered = _native.error_classification_v1(
            definition["code"]
        )
        outcomes = definition["outcomes"]
        expected_effect = (
            outcomes[0]["effect"]
            if len({outcome["effect"] for outcome in outcomes}) == 1
            else "possible"
        )
        expected_retry = (
            outcomes[0]["retry"]
            if len({outcome["retry"] for outcome in outcomes}) == 1
            else "unknown"
        )
        actual = (registered, effect, retry, action)
        expected = (True, expected_effect, expected_retry, definition["recommendedAction"])
        if actual != expected:
            disagreements.append(f"{code}: {actual} != {expected}")
    assert not disagreements, "\n".join(disagreements)
    assert len(_REGISTRY["definitions"]) > 0


def test_the_native_layer_admits_no_effect_value_outside_the_three() -> None:
    observed = {
        _native.error_classification_v1(definition["code"])[1]
        for definition in _REGISTRY["definitions"]
    }
    observed.add(_native.error_classification_v1("not.a.registry.code")[1])
    assert observed <= set(EFFECT_STATES), (
        f"the native layer produced effect value(s) {sorted(observed - set(EFFECT_STATES))} "
        f"outside {list(EFFECT_STATES)}"
    )


def test_the_attenuation_refusal_is_a_structured_auths_error() -> None:
    assert issubclass(
        _native.NativeDelegationExpandedError, _native.NativeAuthsError
    ), "a delegation refusal must carry the effect axis like every other failure"
    assert issubclass(_native.NativeAuthsError, ValueError), (
        "the structured exception must stay catchable as ValueError; the boundary "
        "already raised ValueError everywhere and callers depend on it"
    )


def test_a_contract_violation_is_not_dressed_up_as_an_authorization_outcome() -> None:
    """Contract 5.7. Passing the wrong type is a programmer error, not a denial."""
    with pytest.raises(TypeError) as caught:
        _native.decode_identity_v1("not bytes")
    assert not isinstance(caught.value, _native.NativeAuthsError)


# ---------------------------------------------------------------------------
# 2. No generic reference vertical, and no Python-defined vertical.
# ---------------------------------------------------------------------------

# The generic reference machinery that used to reach Python. `HttpAction` and
# `EdgeAction` come from `auths-profile-domains`, which is tier-1 reference
# Rust: broad by design and never projected. The `Application*` family was the
# generic "bring your own vertical" constructor set.
WITHDRAWN = (
    # auths-profile-domains, HTTP
    "HttpCall",
    "HttpAction",
    "NativeHttpPlan",
    "HttpCommand",
    "HttpPlanCommand",
    "HttpGatewayRequest",
    "http_call",
    "review_http_call",
    "commit_http_plan",
    "prepare_http_action",
    "authorize_http",
    "inspect_http_action",
    "consume_http_command",
    "seal_http_plan_command",
    "consume_http_plan_command",
    # auths-profile-domains, edge
    "DomainActionProjection",
    "canonicalize_edge_action_v1",
    "parse_canonical_edge_action_v1",
    # the generic vertical constructor and everything only it could build
    "application_action",
    "application_action_commitment_v1",
    "commit_application_plan",
    "prepare_application_action",
    "authorize_application",
    "seal_application_plan_command",
    "consume_application_command",
    "consume_application_plan_command",
    "prepare_application_command_decision_receipt_v1",
    "prepare_application_plan_decision_receipts_v1",
    "ApplicationAction",
    "ApplicationActionPreparation",
    "ApplicationCommand",
    "ApplicationGatewayCall",
    "ApplicationPlanCommand",
    "NativeApplicationPlan",
)


def test_the_generic_reference_verticals_are_not_reachable_from_python() -> None:
    present = sorted(name for name in WITHDRAWN if hasattr(_native, name))
    assert not present, (
        "generic reference-vertical symbols are exported from the pyo3 layer again: "
        + ", ".join(present)
        + ". The pyo3 layer is a transport, not a tier: it may expose no symbol its "
        "host tier does not expose."
    )


def test_a_python_caller_cannot_mint_a_canonical_action_for_its_own_profile() -> None:
    """The inverted form of the capability this wave removed.

    Before: ``define_profile`` plus ``_native.application_action`` let a caller
    name any profile id and hand the native layer a body that a *Python*
    callback had canonicalised. That made Python a semantic owner.
    """
    generic = [
        name
        for name in _exported()
        if isinstance(getattr(_native, name), types.BuiltinFunctionType)
        and name.startswith("application_")
    ]
    assert not generic, (
        "the native layer exports a generic action constructor again: " + ", ".join(generic)
    )


def test_no_native_symbol_is_exported_without_being_declared() -> None:
    declared = {*_ABI["types"], *_ABI["operations"], *_ABI["inspection"]}
    undeclared = sorted(_exported() - declared)
    assert not undeclared, (
        "native symbols are exported but undeclared in native-abi-v2.json: "
        + ", ".join(undeclared)
    )


def test_every_declared_native_symbol_exists() -> None:
    declared = {*_ABI["types"], *_ABI["operations"], *_ABI["inspection"]}
    missing = sorted(declared - _exported())
    assert not missing, "declared but missing: " + ", ".join(missing)


# ---------------------------------------------------------------------------
# 3. Panic safety.
# ---------------------------------------------------------------------------

_ADVERSARIAL_DRIVER = r"""
import itertools, sys, types
from auths import _native

POOL = [
    b"", b"\xff" * 3, b"\x00" * 64, b"\x00" * 33, "", "\x00", "a" * 4096,
    "auths.mcp/1", "not-a-profile", 0, 1, -1, 2**31, 2**63, 2**64 - 1, None,
    [], {}, (), [b"\xff"], [("a", "b")], [None], "-", "/", "\x00\uffff",
]

targets = []
for name in sorted(dir(_native)):
    if name.startswith("__"):
        continue
    value = getattr(_native, name)
    if isinstance(value, (types.BuiltinFunctionType, type)):
        targets.append((name, value))

for name, target in targets:
    for arity in range(0, 4):
        for args in itertools.product(POOL, repeat=arity):
            try:
                target(*args)
            except BaseException as error:
                if type(error).__name__ == "PanicException":
                    print("PANIC", name, args, file=sys.stderr)
                    raise SystemExit(3)
print("SURVIVED")
"""


def test_no_native_entry_point_can_be_panicked_from_python_input() -> None:
    """Runs in a subprocess on purpose.

    Under ``panic = "abort"`` a panic is SIGABRT, not an exception: it would
    kill the test runner rather than fail a test. A subprocess turns either
    outcome -- abort or ``PanicException`` -- into a readable failure.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _ADVERSARIAL_DRIVER],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=str(_PACKAGE_ROOT),
    )
    assert completed.returncode == 0, (
        "driving every native entry point with adversarial input killed the "
        f"interpreter (returncode {completed.returncode}). "
        f"stderr tail: {completed.stderr[-2000:]}"
    )
    assert "SURVIVED" in completed.stdout


def test_the_extension_refuses_to_be_built_with_an_aborting_panic_strategy() -> None:
    """The guard that makes the property above enforceable rather than lucky.

    `bindings/python/src/lib.rs` fails to compile under `panic = "abort"`,
    because pyo3's catch_unwind cannot run when the process aborts first.
    """
    source = (_PACKAGE_ROOT / "src/lib.rs").read_text(encoding="utf-8")
    assert '#[cfg(panic = "abort")]' in source
    assert "compile_error!" in source
    workspace = (_REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    assert "[profile.python-extension]" in workspace
    assert 'panic = "unwind"' in workspace
