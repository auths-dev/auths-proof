"""WAVE ACCEPTANCE TEST -- the effect axis must survive every boundary.

This module is the specification for the Transport and Surface lanes. It is
EXPECTED TO BE RED until they land. Every failure here is a finding, not a
flake, and none of these assertions may be weakened to make the suite green.

Property under test (contract 4.1, 5.1, 5.2, 5.4, 5.5, 5.6):

    Rust classifies each of the 48 registry codes with an effect --
    not-applied | possible | applied. ``possible`` means WE DO NOT KNOW whether
    the real-world effect happened. A caller who reads ``not-applied`` when the
    truth is ``possible`` will blindly retry and may repeat a payment or a
    database write. That distinction must arrive intact at the public Python
    API, together with the stable code identity, the retry class, and the
    recommended action.

Every value read here is read the way a REAL CALLER reads it: through a module
declared in ``bindings/public-topology-v1.json``. No test in this module may
import a private ``auths._*`` module.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

RED = "EFFECT-AXIS ACCEPTANCE (expected red until the Transport and Surface lanes land)"

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REGISTRY_PATH = _REPO_ROOT / "product/errors/v1/registry.json"
_FIXTURES_PATH = _REPO_ROOT / "product/fixtures/v1/errors/manifest.json"
_TOPOLOGY_PATH = _REPO_ROOT / "bindings/public-topology-v1.json"


def _read(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# The Rust-owned registry. Nothing here hardcodes a count or a code.
REGISTRY = _read(_REGISTRY_PATH)
# Rust-minted `auths.error/1` envelopes, one per code, from `ErrorEnvelope::parse`.
FIXTURES = _read(_FIXTURES_PATH)
TOPOLOGY = _read(_TOPOLOGY_PATH)

DEFINITIONS = REGISTRY["definitions"]
BY_CODE = {definition["code"]: definition for definition in DEFINITIONS}
ENVELOPE_FOR = {fixture["code"]: fixture for fixture in FIXTURES["fixtures"]}

# Derived, never assumed.
RUST_EFFECT_STATES = ("not-applied", "possible", "applied")
RUST_RETRY_CLASSES = ("never", "safe", "conditional", "unknown")


def _codes_with_effect(effect: str) -> list[str]:
    return sorted(
        definition["code"]
        for definition in DEFINITIONS
        if any(outcome["effect"] == effect for outcome in definition["outcomes"])
    )


POSSIBLE_CODES = _codes_with_effect("possible")
APPLIED_CODES = _codes_with_effect("applied")

PUBLIC_MODULES = tuple(
    module for layer in TOPOLOGY["layers"] for module in layer["python"]
)


def _public(module: str) -> Any:
    """Imports a module a real consumer can import, refusing private paths."""
    assert module in PUBLIC_MODULES, (
        f"{module} is not declared in bindings/public-topology-v1.json"
    )
    return importlib.import_module(module)


def _effect_value(value: Any) -> Any:
    """Reads an effect the way a caller does, tolerating str or str-Enum."""
    return getattr(value, "value", value)


# ---------------------------------------------------------------------------
# EA-0  Anti-vacuity guards. A check that iterates an empty set cannot fail.
# ---------------------------------------------------------------------------


def test_ea0_registry_fixtures_and_topology_are_non_empty_and_aligned() -> None:
    assert REGISTRY["schema"] == "auths.error-registry/1"
    assert DEFINITIONS, "registry has no definitions; every per-code test would be vacuous"
    assert len(ENVELOPE_FOR) == len(DEFINITIONS), (
        "the Rust-minted fixture corpus does not cover every registry code"
    )
    assert POSSIBLE_CODES, (
        "no code carries effect 'possible'; the safety-critical case would be untested"
    )
    assert APPLIED_CODES, (
        "no code carries effect 'applied'; that arm of the axis would be untested"
    )
    for definition in DEFINITIONS:
        for outcome in definition["outcomes"]:
            assert outcome["effect"] in RUST_EFFECT_STATES, (
                f"{definition['code']} declares effect {outcome['effect']!r}, "
                f"outside the Rust-owned set"
            )
    assert PUBLIC_MODULES, "public topology declares no Python entry points"
    for module in PUBLIC_MODULES:
        importlib.import_module(module)


# ---------------------------------------------------------------------------
# EA-1  Surface: every registry code reaches a public caller with all four
#       fields of its recovery contract.
# ---------------------------------------------------------------------------


def test_ea1_every_registry_code_reaches_a_public_python_caller_with_the_full_axis() -> None:
    auths = _public("auths")
    assert hasattr(auths, "AuthsError"), f"{RED}: the product root publishes no AuthsError"
    lost: list[str] = []
    for definition in DEFINITIONS:
        code = definition["code"]
        outcome = definition["outcomes"][0]
        try:
            error = auths.AuthsError.parse(ENVELOPE_FOR[code])
        except Exception as cause:  # noqa: BLE001 - the failure is the finding
            lost.append(f"{code}: public root refused the Rust-minted envelope ({cause})")
            continue
        if error.code != code:
            lost.append(f"{code}: code identity became {error.code}")
        effect = _effect_value(error.effect)
        if effect != outcome["effect"]:
            lost.append(f"{code}: effect became {effect}, Rust says {outcome['effect']}")
        retry = _effect_value(error.retry)
        if retry != outcome["retry"]:
            lost.append(f"{code}: retry became {retry}, Rust says {outcome['retry']}")
        action = _effect_value(error.recommended_action)
        if action != definition["recommendedAction"]:
            lost.append(
                f"{code}: recommended_action became {action}, "
                f"Rust says {definition['recommendedAction']}"
            )
        if effect not in RUST_EFFECT_STATES:
            lost.append(f"{code}: effect {effect!r} is outside the three Rust-owned states")
    assert not lost, f"{RED}\n" + "\n".join(lost)


# ---------------------------------------------------------------------------
# EA-2  Fail-closed: an unrecognized code must become `possible`, never a
#       fourth value and never `not-applied` (contract 4.1).
# ---------------------------------------------------------------------------


def test_ea2_an_unregistered_code_fails_closed_to_possible() -> None:
    auths = _public("auths")
    template = dict(ENVELOPE_FOR[POSSIBLE_CODES[0]])
    future = "mcp.code-minted-by-a-newer-rust"
    assert future not in BY_CODE, "the unknown-code probe accidentally uses a registered code"
    template["code"] = future
    error = auths.AuthsError.parse(template)
    assert error.code == future, f"{RED}: an unknown code lost its identity at the public surface"
    effect = _effect_value(error.effect)
    assert effect == "possible", (
        f"{RED}: an unknown code mapped to effect {effect!r}. Contract 4.1 requires 'possible'. "
        f"A newer Rust code must never be silently swallowed or downgraded by an older binding."
    )


def test_ea2b_the_public_python_surface_admits_exactly_three_effect_states() -> None:
    auths = _public("auths")
    observed = {
        _effect_value(auths.AuthsError.parse(ENVELOPE_FOR[definition["code"]]).effect)
        for definition in DEFINITIONS
    }
    unknown_envelope = dict(ENVELOPE_FOR[POSSIBLE_CODES[0]])
    unknown_envelope["code"] = "plan.code-minted-by-a-newer-rust"
    observed.add(_effect_value(auths.AuthsError.parse(unknown_envelope).effect))
    extra = sorted(value for value in observed if value not in RUST_EFFECT_STATES)
    assert not extra, (
        f"{RED}: the public surface produced effect value(s) {extra} outside "
        f"{list(RUST_EFFECT_STATES)}. EffectState has exactly three members."
    )


def test_ea2c_the_public_root_publishes_the_effect_axis_vocabulary() -> None:
    auths = _public("auths")
    exported = set(auths.__all__)
    missing = sorted({"EffectState", "RetryClass", "RecommendedAction"} - exported)
    assert not missing, (
        f"{RED}: the public root does not export {missing}. A caller cannot name the type "
        f"of the value they must branch on."
    )
    effect_state = auths.EffectState
    members = sorted(member.value for member in effect_state)
    assert members == sorted(RUST_EFFECT_STATES), (
        f"{RED}: auths.EffectState has members {members}, not {sorted(RUST_EFFECT_STATES)}. "
        f"There are exactly three."
    )
    retry_class = auths.RetryClass
    retry_members = sorted(getattr(member, "value", member) for member in retry_class)
    assert retry_members == sorted(RUST_RETRY_CLASSES), (
        f"{RED}: auths.RetryClass has members {retry_members}, not {sorted(RUST_RETRY_CLASSES)}. "
        f"The root currently exports the NextCall set ('never'|'backoff'|'resume'|'reconcile') "
        f"under the RetryClass name; they answer different questions and must never share an "
        f"identifier."
    )


# ---------------------------------------------------------------------------
# EA-3  Transport: Rust -> pyo3 -> Python. An error crossing the pyo3 boundary
#       must arrive as a structured envelope, not a bare ValueError string
#       (contract 5.2).
# ---------------------------------------------------------------------------


def test_ea3_an_error_crossing_the_pyo3_boundary_arrives_structured() -> None:
    identity = _public("auths.identity")
    auths = _public("auths")
    with pytest.raises(BaseException) as caught:  # noqa: PT011 - the type is the finding
        identity.decode_identity(b"\xff\xff\xff")
    error = caught.value
    assert isinstance(error, auths.AuthsError), (
        f"{RED}: the pyo3 boundary raised {type(error).__name__}({error.args!r}), not the public "
        f"AuthsError. The bare exception carries no code identity, no effect state, no retry "
        f"class, and no recommended action."
    )
    assert error.code in BY_CODE, (
        f"{RED}: the pyo3 boundary reported code {error.code!r}, which is not in the registry"
    )
    assert _effect_value(error.effect) in RUST_EFFECT_STATES, (
        f"{RED}: the pyo3 boundary reported effect {_effect_value(error.effect)!r}"
    )
    assert error.retry is not None, f"{RED}: the pyo3 boundary reported no retry class"
    assert error.recommended_action is not None, (
        f"{RED}: the pyo3 boundary reported no recommended action"
    )


def test_ea3b_every_pyo3_boundary_failure_on_a_public_entry_point_is_structured() -> None:
    identity = _public("auths.identity")
    verify = _public("auths.verify")
    auths = _public("auths")
    probes = (
        ("auths.identity.decode_identity", lambda: identity.decode_identity(b"\xff\xff\xff")),
        (
            "auths.verify.decode_receipt",
            lambda: verify.decode_receipt(b"\x01\x02\x03"),
        ),
    )
    flattened: list[str] = []
    for name, probe in probes:
        try:
            probe()
        except BaseException as error:  # noqa: BLE001 - the type is the finding
            if not isinstance(error, auths.AuthsError):
                flattened.append(f"{name}: raised {type(error).__name__}({error.args!r})")
        else:
            flattened.append(f"{name}: adversarial input did not fail; the probe proves nothing")
    assert not flattened, (
        f"{RED}: the following published entry points lose the effect axis at the pyo3 "
        f"boundary\n" + "\n".join(flattened)
    )


# ---------------------------------------------------------------------------
# EA-4  The execution path. This is the safety-critical one: a real failed
#       execution, driven through published entry points, must tell the caller
#       whether the effect may have happened (contract 5.1).
# ---------------------------------------------------------------------------


async def _drive_execution(tool: str, tools: Mapping[str, Any], request_id: str) -> Any:
    development = _public("auths.integrations").development
    mcp = _public("auths.profiles").mcp
    provider = mcp.development_provider(tools=dict(tools))
    session = await development.create_auths(authority=mcp.allow_tools([tool]))
    try:
        return await session.execute(
            action=mcp.call_tool(name=tool, arguments={}),
            provider=provider,
            request_id=request_id,
        )
    finally:
        await session.aclose()


async def _drive_denial(request_id: str) -> Any:
    development = _public("auths.integrations").development
    mcp = _public("auths.profiles").mcp

    async def allowed(
        arguments: Mapping[str, Any], context: Any
    ) -> Mapping[str, Any]:
        return {"ok": True}

    provider = mcp.development_provider(tools={"allowed": allowed})
    session = await development.create_auths(authority=mcp.allow_tools(["allowed"]))
    try:
        return await session.execute(
            action=mcp.call_tool(name="forbidden", arguments={}),
            provider=provider,
            request_id=request_id,
        )
    finally:
        await session.aclose()


def _shape(result: Any) -> str:
    fields = sorted(
        name for name in dir(result) if not name.startswith("_") and not callable(getattr(result, name))
    )
    return f"{type(result).__name__} {{ {', '.join(fields)} }}"


@pytest.mark.asyncio
async def test_ea4_a_provider_failure_tells_the_public_caller_the_effect_is_possible() -> None:
    async def boom(arguments: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
        raise RuntimeError("provider exploded after entry")

    result = await _drive_execution("boom", {"boom": boom}, "effect-axis-boom-000001")
    shape = _shape(result)
    code = getattr(result, "code", None)
    assert isinstance(code, str), (
        f"{RED}: a provider failure surfaced as {shape} with no stable code identity. "
        f"Rust classifies this as mcp.handler-failed, effect 'possible'."
    )
    assert code in BY_CODE, (
        f"{RED}: a provider failure surfaced code {code!r}, which is not in the registry"
    )
    effect = _effect_value(getattr(result, "effect", None))
    assert effect == "possible", (
        f"{RED}: a provider failure surfaced as {shape} with effect {effect!r}. The caller cannot "
        f"tell that the real-world effect may have been applied, and may blindly retry."
    )
    assert _effect_value(getattr(result, "retry", None)) == "unknown", (
        f"{RED}: a possible-effect failure did not report retry 'unknown'"
    )
    assert _effect_value(getattr(result, "recommended_action", None)) == "resume-and-reconcile", (
        f"{RED}: a possible-effect failure did not recommend reconciliation"
    )


@pytest.mark.asyncio
async def test_ea4b_two_distinct_registry_codes_do_not_collapse_to_one_caller_shape() -> None:
    async def boom(arguments: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
        raise RuntimeError("provider exploded after entry")

    async def oversized(
        arguments: Mapping[str, Any], context: Any
    ) -> Mapping[str, Any]:
        return {"blob": "x" * (2 * 1024 * 1024)}

    failed = await _drive_execution("boom", {"boom": boom}, "effect-axis-boom-000002")
    invalid = await _drive_execution(
        "oversized", {"oversized": oversized}, "effect-axis-oversized-000001"
    )
    assert (failed.kind, getattr(failed, "code", None)) != (
        invalid.kind,
        getattr(invalid, "code", None),
    ), (
        f"{RED}: a handler that raised and a handler that produced invalid output both surfaced "
        f"as {failed.kind} with code {getattr(failed, 'code', None)!r}. Rust distinguishes "
        f"mcp.handler-failed from mcp.invalid-handler-output; the public path destroys that "
        f"identity."
    )


@pytest.mark.asyncio
async def test_ea4c_a_denial_tells_the_public_caller_the_effect_is_not_applied() -> None:
    denied = await _drive_denial("effect-axis-denied-000001")
    assert denied.kind == "denied"
    effect = _effect_value(getattr(denied, "effect", None))
    assert effect == "not-applied", (
        f"{RED}: a denial surfaced as {_shape(denied)} with effect {effect!r}. A caller cannot "
        f"prove from the public result that nothing happened."
    )


# ---------------------------------------------------------------------------
# EA-5  Inventory gate: bindings mint no error codes (contract 5.4). Rather
#       than listing the codes to check, fail when a code appears OUTSIDE the
#       registry, so the whole class cannot return.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ea5_every_code_the_public_execution_path_emits_is_in_the_rust_registry() -> None:
    async def boom(arguments: Mapping[str, Any], context: Any) -> Mapping[str, Any]:
        raise RuntimeError("provider exploded after entry")

    emitted: set[str] = set()
    for result in (
        await _drive_execution("boom", {"boom": boom}, "effect-axis-inventory-000001"),
        await _drive_denial("effect-axis-inventory-000002"),
    ):
        code = getattr(result, "code", None)
        if isinstance(code, str):
            emitted.add(code)
    assert emitted, "no code was observed; this inventory gate would be vacuous"
    unregistered = sorted(code for code in emitted if code not in BY_CODE)
    assert not unregistered, (
        f"{RED}: the public execution path emitted code(s) {unregistered} that exist in no "
        f"registry. All codes originate in product/errors/v1/registry.json "
        f"({len(DEFINITIONS)} today)."
    )


# ---------------------------------------------------------------------------
# EA-6  The reported inventory, so the transcript carries the derived sets.
# ---------------------------------------------------------------------------


def test_ea6_the_derived_effect_inventory_is_reported(capsys: Any) -> None:
    only_not_applied = [
        definition["code"]
        for definition in DEFINITIONS
        if all(outcome["effect"] == "not-applied" for outcome in definition["outcomes"])
    ]
    with capsys.disabled():
        print(f"\nregistry: {len(DEFINITIONS)} stable codes")
        print(f"effect 'possible' ({len(POSSIBLE_CODES)}): {', '.join(POSSIBLE_CODES)}")
        print(f"effect 'applied' ({len(APPLIED_CODES)}): {', '.join(APPLIED_CODES)}")
        print(f"effect 'not-applied' only ({len(only_not_applied)})")
    assert (
        len(POSSIBLE_CODES) + len(APPLIED_CODES) + len(only_not_applied) == len(DEFINITIONS)
    ), "the three effect partitions do not sum to the registry size"
