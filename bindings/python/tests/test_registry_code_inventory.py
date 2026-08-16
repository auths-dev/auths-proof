"""Inventory gates: Python names failures, Rust defines what they mean.

These are written as *inventory* checks -- they fail when something appears
OUTSIDE the checked set -- so the class of defect cannot come back by adding a
new call site. Listing the codes to check would only pin today's list.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Iterator

import pytest

from auths._error_registry import UNRECOGNIZED_CODE
from auths._product_errors import (
    WORKFLOW_REASON_CODES,
    AuthsError,
    AuthsWorkflowError,
    EffectState,
    ProviderOperationError,
    RecommendedAction,
    RetryClass,
    classify,
    registry_codes,
)

_PACKAGE = Path(__file__).parents[1] / "python" / "auths"
_REGISTRY = json.loads(
    (Path(__file__).parents[3] / "product/errors/v1/registry.json").read_text()
)
_RUST_CODES = {definition["code"] for definition in _REGISTRY["definitions"]}


def _sources() -> Iterator[Path]:
    yield from sorted(_PACKAGE.rglob("*.py"))


def _workflow_error_reasons() -> list[tuple[str, str]]:
    """Every literal first argument to `AuthsWorkflowError(...)`, with its site.

    Covers direct construction and `super().__init__(...)` inside a class that
    actually derives from `AuthsWorkflowError` -- a `super()` call in any other
    class is a different constructor and must not be counted.
    """
    found: list[tuple[str, str]] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        subclass_bodies = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and any(
                isinstance(base, ast.Name) and base.id == "AuthsWorkflowError"
                for base in node.bases
            )
        ]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            direct = isinstance(node.func, ast.Name) and node.func.id == (
                "AuthsWorkflowError"
            )
            if not direct and not _is_super_init(node.func):
                continue
            if not direct and not any(
                node in ast.walk(body) for body in subclass_bodies
            ):
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            if " " in first.value:
                continue
            found.append((first.value, f"{path.name}:{node.lineno}"))
    return found


def _is_super_init(target: ast.expr) -> bool:
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "__init__"
        and isinstance(target.value, ast.Call)
        and isinstance(target.value.func, ast.Name)
        and target.value.func.id == "super"
    )


def test_the_python_package_names_no_code_outside_the_rust_registry() -> None:
    """Contract 5.4: bindings mint no error codes."""
    assert _RUST_CODES, "the registry is empty; this gate would be vacuous"
    unregistered = sorted(
        {code for code in WORKFLOW_REASON_CODES.values() if code not in _RUST_CODES}
    )
    assert not unregistered, (
        "WORKFLOW_REASON_CODES points at codes that exist in no registry: "
        + ", ".join(unregistered)
    )
    assert set(registry_codes()) == _RUST_CODES, (
        "the generated _error_registry.py has drifted from "
        "product/errors/v1/registry.json; run `cargo xtask error-registry --update`"
    )


def test_every_workflow_failure_site_names_a_mapped_reason() -> None:
    """A new failure site cannot invent a code by accident."""
    reasons = _workflow_error_reasons()
    assert len(reasons) > 20, (
        f"only {len(reasons)} workflow failure sites were found by the AST scan; "
        "the scan is not reaching the package and would pass vacuously"
    )
    unmapped = sorted(
        {
            f"{reason} ({site})"
            for reason, site in reasons
            if reason not in WORKFLOW_REASON_CODES
        }
    )
    assert not unmapped, (
        "workflow failure sites use reasons that name no registry code: "
        + ", ".join(unmapped)
    )


def test_every_mapped_reason_is_reachable_from_a_call_site() -> None:
    """The inverse: the table may not accumulate entries nothing raises.

    `authority-source-*` and `*-timeout`/`*-unsupported` are built by string
    concatenation, so they are listed here as the composed forms the two
    helpers can produce rather than found by the literal scan.
    """
    composed = {
        f"{operation}-{suffix}"
        for operation in ("approval", "signer")
        for suffix in ("failed", "rejected", "cancelled", "timeout", "unsupported")
    } | {
        f"authority-source-{kind}"
        for kind in ("unavailable", "rejected", "cancelled", "timeout", "unsupported")
    }
    literal = {reason for reason, _ in _workflow_error_reasons()}
    orphaned = sorted(set(WORKFLOW_REASON_CODES) - literal - composed)
    assert not orphaned, (
        "WORKFLOW_REASON_CODES has entries no call site can produce: "
        + ", ".join(orphaned)
    )


def test_every_workflow_error_carries_the_full_recovery_contract() -> None:
    for reason in WORKFLOW_REASON_CODES:
        error = AuthsWorkflowError(reason, "inventory probe")
        classification = classify(error.code)
        assert classification.known, reason
        assert error.effect is classification.effect, reason
        assert error.retry is classification.retry, reason
        assert error.recommended_action is classification.recommended_action, reason
        assert error.reason == reason
        # The safety rule that makes the axis worth reading at all.
        if error.retry is RetryClass.SAFE:
            assert error.effect is EffectState.NOT_APPLIED, reason
        if error.effect is EffectState.POSSIBLE:
            assert error.recommended_action is RecommendedAction.RESUME_AND_RECONCILE


def test_an_unmapped_reason_cannot_be_raised() -> None:
    with pytest.raises(LookupError, match="names no registry code"):
        AuthsWorkflowError("reason-nobody-registered", "inventory probe")


def test_provider_failures_map_onto_the_registry_too() -> None:
    for kind in ("unavailable", "rejected", "cancelled", "timeout", "unsupported"):
        error = ProviderOperationError(kind)  # type: ignore[arg-type]
        assert error.code in _RUST_CODES, kind
        assert error.kind == kind
        assert isinstance(error, AuthsError)
    with pytest.raises(ValueError, match="unsupported provider failure kind"):
        ProviderOperationError("not-a-kind")  # type: ignore[arg-type]


def test_the_package_ships_exactly_one_exception_hierarchy() -> None:
    """Contract 4.3: two unrelated `AuthsError` classes are banned."""
    classes: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("Error"):
                bases = {
                    getattr(base, "id", None) or getattr(base, "attr", None)
                    for base in node.bases
                }
                classes.append(f"{path.name}:{node.name}:{sorted(map(str, bases))}")
    roots = [
        entry
        for entry in classes
        if entry.endswith("['Exception']") and ":AuthsError:" in entry
    ]
    assert len(roots) == 1, (
        "the wheel defines more than one root Auths exception: " + ", ".join(roots)
    )


def test_the_unknown_code_answer_comes_from_rust() -> None:
    """Contract 4.1's fail-closed rule, read from the generated projection."""
    assert UNRECOGNIZED_CODE["effect"] == EffectState.POSSIBLE.value
    unknown = classify("nothing.this-build-knows")
    assert not unknown.known
    assert unknown.effect is EffectState.POSSIBLE
    assert unknown.retry.value == UNRECOGNIZED_CODE["retry"]
    assert unknown.recommended_action.value == UNRECOGNIZED_CODE["recommendedAction"]
