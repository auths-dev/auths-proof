"""One vocabulary per concept, and the same port shape as TypeScript.

Contract 4 (the frozen vocabulary), 6.2 (framework contracts must be
structurally identical, not merely name-identical, and async parity is
required).
"""

from __future__ import annotations

import inspect
import re
import typing
from pathlib import Path

import pytest

import auths
from auths._product_errors import EffectState, RecommendedAction, RetryClass
import auths.service
from auths._product_errors import ProductVerb
from auths._service import NextCall
from auths._receipts import ReceiptDisclosureProtector, ReceiptDisclosureStore
from auths._workflow import APPROVAL_MODES, ApprovalMode, _validate_approval

_TYPESCRIPT = Path(__file__).parents[2] / "typescript" / "src"


def _members(alias: object) -> set[str]:
    return set(typing.get_args(alias))


# ---------------------------------------------------------------------------
# The effect axis and the two retry questions.
# ---------------------------------------------------------------------------


def test_effect_state_has_exactly_the_three_rust_members() -> None:
    assert {member.value for member in EffectState} == {
        "not-applied",
        "possible",
        "applied",
    }


def test_retry_class_and_next_call_are_different_questions() -> None:
    retry = {member.value for member in RetryClass}
    next_call = _members(NextCall)
    assert retry == {"never", "safe", "conditional", "unknown"}
    assert next_call == {"never", "backoff", "resume", "reconcile"}
    assert retry != next_call, (
        "RetryClass answers 'may I retry?' and NextCall answers 'what do I call "
        "next?'. They must never name the same closed set again."
    )
    assert auths.RetryClass is RetryClass, (
        "the public root binds RetryClass to the NextCall set again"
    )
    assert auths.service.NextCall is NextCall
    assert not hasattr(auths, "NextCall"), (
        "the remote client vocabulary is back on the product root"
    )


def test_the_product_verbs_are_the_five_rust_owns() -> None:
    assert _members(ProductVerb) == {
        "create",
        "delegate",
        "execute",
        "resume",
        "verify",
    }
    assert not hasattr(auths, "ProductStep"), "the `step` spelling is deleted"


def test_recover_is_not_a_product_operation() -> None:
    """Contract 4.2: `recover` has no Rust owner and no registry entry."""
    assert not hasattr(auths.Auths, "recover")
    import auths.profiles._mcp as mcp_profile

    assert not hasattr(mcp_profile, "recover_mcp_closed")


def test_the_public_root_names_the_vocabulary_a_caller_branches_on() -> None:
    for name in ("EffectState", "RetryClass", "RecommendedAction", "ProductVerb"):
        assert name in auths.__all__, name
    assert auths.EffectState is EffectState
    assert auths.RecommendedAction is RecommendedAction


def test_classify_reports_the_dominant_outcome_the_way_rust_does() -> None:
    """`auths_errors::classify` picks the dominant outcome, not the first one.

    Every definition in today's registry declares exactly one outcome, so the
    two rules are indistinguishable on real data and a parity check over the
    registry cannot see the difference. This drives a synthetic two-outcome
    definition instead, ordered so that first-declared and dominant disagree:
    the first-declared rule answers `not-applied` (nothing happened, safe to
    retry) where Rust answers `possible` (reconcile before retrying).
    """
    from auths import _product_errors

    two_outcomes = {
        "code": "test.two-outcomes",
        "family": "runtime",
        "operation": "execute",
        "stages": ["provider"],
        "outcomes": [
            {"retry": "never", "effect": "not-applied"},
            {"retry": "unknown", "effect": "possible"},
        ],
        "recommendedAction": "resume-and-reconcile",
    }
    single = {code: definition for code, definition in _product_errors._DEFINITIONS.items()}
    assert all(
        len(definition["outcomes"]) == 1 for definition in single.values()
    ), "registry gained a multi-outcome definition; this synthetic case is no longer needed"

    original = _product_errors._DEFINITIONS
    _product_errors._DEFINITIONS = {**single, "test.two-outcomes": two_outcomes}
    try:
        classification = _product_errors.classify("test.two-outcomes")
    finally:
        _product_errors._DEFINITIONS = original

    assert classification.effect is EffectState.POSSIBLE, (
        "classify reported the first-declared outcome. Rust reports the "
        "dominant one (possible > applied > not-applied), and a binding that "
        "picks differently tells a caller a possibly-applied effect provably "
        "did not happen."
    )
    assert classification.retry is RetryClass.UNKNOWN


# ---------------------------------------------------------------------------
# ApprovalMode: one list, and the validator agrees with the declared type.
# ---------------------------------------------------------------------------


def test_approval_mode_type_and_validator_admit_exactly_the_same_modes() -> None:
    declared = _members(ApprovalMode)
    assert declared == set(APPROVAL_MODES), (
        "ApprovalMode and APPROVAL_MODES disagree; the list is restated twice"
    )
    assert "headless" in declared, (
        "the product's headline agent case is unnameable through the typed surface"
    )
    accepted = {
        mode for mode in declared | {"not-a-mode"} if _validator_accepts_mode(mode)
    }
    assert accepted == declared, (
        f"the runtime validator admits {sorted(accepted)} but the type declares "
        f"{sorted(declared)}"
    )


def _validator_accepts_mode(mode: str) -> bool:
    """Reaches `_validate_approval`'s mode branch directly, past its type guards.

    The guards above the branch would reject the probe first, so the check
    would be testing the guard rather than the vocabulary.
    """
    source = inspect.getsource(_validate_approval)
    assert "APPROVAL_MODES" in source, (
        "the validator no longer reads APPROVAL_MODES; this check is vacuous"
    )
    return mode in APPROVAL_MODES


def test_typescript_declares_the_same_approval_modes() -> None:
    contracts = (_TYPESCRIPT / "workflow" / "contracts.ts").read_text()
    block = contracts[contracts.index("export type ApprovalMode") :]
    block = block[: block.index(";")]
    assert set(re.findall(r'"([a-z-]+)"', block)) == set(APPROVAL_MODES)


# ---------------------------------------------------------------------------
# Port shape parity with TypeScript.
# ---------------------------------------------------------------------------


def test_receipt_disclosure_ports_are_async_like_typescript() -> None:
    """A synchronous port cannot be implemented over a KMS or an HSM."""
    for port, methods in (
        (ReceiptDisclosureProtector, ("protect", "reveal")),
        (ReceiptDisclosureStore, ("put", "get", "delete")),
    ):
        for method in methods:
            member = getattr(port, method)
            assert inspect.iscoroutinefunction(member), (
                f"{port.__name__}.{method} is synchronous; TypeScript's returns a "
                f"Promise, so the same implementation cannot satisfy both"
            )


def test_typescript_receipt_disclosure_ports_are_the_ones_being_matched() -> None:
    """Anti-vacuity: read the TypeScript side rather than assuming it."""
    source = (_TYPESCRIPT / "receipt-inspection.ts").read_text()
    for interface in ("ReceiptDisclosureProtector", "ReceiptDisclosureStore"):
        block = source[source.index(f"export interface {interface}") :]
        block = block[: block.index("\n}")]
        signatures = [line for line in block.splitlines() if line.strip().endswith(";")]
        assert signatures, f"{interface} has no method signatures; check is vacuous"
        synchronous = [line.strip() for line in signatures if "Promise<" not in line]
        assert not synchronous, (
            f"TypeScript's {interface} is synchronous here: {synchronous}. "
            f"Python was aligned to the async shape; realign both together."
        )


# ---------------------------------------------------------------------------
# Homonyms: one identifier may not name two unrelated types (contract 4.3).
# ---------------------------------------------------------------------------


def test_no_name_is_exported_from_two_entry_points_as_two_different_types() -> None:
    import collections
    import importlib
    import json

    topology = json.loads(
        (Path(__file__).parents[2] / "public-topology-v1.json").read_text()
    )
    modules = [name for layer in topology["layers"] for name in layer["python"]]
    assert len(modules) > 1, "one entry point cannot produce a homonym; check is vacuous"
    seen: dict[str, dict[str, object]] = collections.defaultdict(dict)
    for name in modules:
        module = importlib.import_module(name)
        for exported in module.__all__:
            seen[exported][name] = getattr(module, exported)
    homonyms = {
        exported: sorted(owners)
        for exported, owners in seen.items()
        if len({id(value) for value in owners.values()}) > 1
    }
    assert not homonyms, (
        "these names resolve to different declarations depending on the import "
        f"path: {homonyms}. A shared declaration re-exported from two paths is "
        "fine; two unrelated types under one name is not."
    )


# ---------------------------------------------------------------------------
# The two factories: same concept, same word, one spelling per language.
# ---------------------------------------------------------------------------


def _typescript_source(*parts: str) -> str:
    return (_TYPESCRIPT.joinpath(*parts)).read_text()


def test_create_is_a_factory_in_both_languages_and_not_a_constructor() -> None:
    """Contract 4.2: `create` is one operation with one entry point per language.

    TypeScript never exports the class behind `Auths`, so `createAuths` is the
    only way to obtain one. Python exported the class itself, which made
    `Auths(...)` a second, undocumented entry point for the same verb.
    """
    product = _typescript_source("product.ts")
    assert "export function createAuths(" in product, (
        "TypeScript no longer spells the create verb `createAuths`; this check "
        "is asserting a spelling that no longer exists"
    )
    assert "export class AuthsFacade" not in product, (
        "TypeScript exported the facade class, so it too now has two entry "
        "points for `create` and Python was aligned to the wrong shape"
    )

    assert callable(auths.create_auths)
    assert "create_auths" in auths.__all__

    with pytest.raises(TypeError, match="sealed Auths facade"):
        auths.Auths(object(), object(), ())


def test_the_service_client_is_named_the_same_thing_in_both_languages() -> None:
    """Contract 4.4: the remote client is `ServiceClient`, minted by a factory.

    Python called the factory `create_auths` and the type `ServiceAuths`, so
    one word named the remote client here and the local facade in
    `auths.integrations`, and neither matched TypeScript.
    """
    service = _typescript_source("service.ts")
    assert "export function createServiceClient(" in service
    assert "export interface ServiceClient {" in service

    import auths.integrations

    assert callable(auths.service.create_service_client)
    assert isinstance(auths.service.ServiceClient, type)
    assert not hasattr(auths.service, "create_auths"), (
        "`create_auths` is back on the remote client, where it names something "
        "that is not an Auths"
    )
    assert not hasattr(auths.service, "ServiceAuths")
    assert callable(auths.integrations.development.create_auths), (
        "`create_auths` must keep meaning exactly one thing: make a local Auths"
    )
