from __future__ import annotations

from pathlib import Path

import pytest

from auths import native
from auths.advanced import (
    mcp_action_bytes,
    parse_signed_object,
    parse_unsigned_object,
    signed_object_bytes,
    trusted_context_bytes,
    unsigned_object_bytes,
)


VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"
ROOT = native.Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
ACTOR = native.Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")


def test_native_abi_is_explicitly_versioned() -> None:
    assert native.ABI_VERSION == 1
    assert len(native.self_contained_configuration()) == 32


def test_child_planning_matches_the_shared_rust_typescript_fixture() -> None:
    parent = parse_unsigned_object(
        "grant", (VECTORS / "authoring.parent-grant.cbor").read_bytes()
    )
    proposed = parse_unsigned_object(
        "grant", (VECTORS / "authoring.proposed-grant.cbor").read_bytes()
    )

    plan = native.plan_child_statement(
        parent, native.grant_request_from_statement(proposed)
    )

    assert unsigned_object_bytes(plan.unsigned) == (
        VECTORS / "authoring.planned-grant.cbor"
    ).read_bytes()
    assert plan.diff.delegation_depth == (1, 0)
    assert plan.diff.budget_narrowed


def test_exact_signing_request_is_native_owned_and_single_use() -> None:
    unsigned = parse_unsigned_object(
        "grant", (VECTORS / "authoring.proposed-grant.cbor").read_bytes()
    )
    request = native.prepare_signing(
        unsigned,
        "raw-key-v1",
        ROOT.value,
        "ed25519-v1",
    )

    assert request.object_kind == "grant"
    assert request.request_id.startswith("grant:")
    assert len(request.object_id) == 32
    assert len(request.transaction_digest) == 32
    assert request.signing_preimage

    signed = request.complete(bytes(64))
    assert signed.kind == "grant"
    with pytest.raises(RuntimeError, match="already completed"):
        request.complete(bytes(64))
    assert signed_object_bytes(
        parse_signed_object("grant", signed_object_bytes(signed))
    ) == signed_object_bytes(signed)


def test_mcp_profile_semantics_are_owned_by_rust() -> None:
    terminal = parse_signed_object(
        "grant", (VECTORS / "mcp.signed-root-grant.cbor").read_bytes()
    )

    action = native.prepare_mcp_action(
        "reports",
        "update_demo_record",
        b'{"value":"reviewed"}',
        ACTOR,
        terminal,
        bytes([0x22]) * 32,
        50,
    )
    canonical, arguments = mcp_action_bytes(action)

    assert action.audience == "mcp://reports"
    assert action.resource == "mcp://reports/tools/update_demo_record"
    assert len(action.display_digest_hex) == 64
    assert canonical
    assert arguments == b'{"value":"reviewed"}'
    assert action.unsigned.kind == "action"

    with pytest.raises(ValueError, match="canonical JSON"):
        native.prepare_mcp_action(
            "reports",
            "update_demo_record",
            b'{"value": "reviewed"}',
            ACTOR,
            terminal,
            bytes([0x22]) * 32,
            50,
        )


def test_trust_compilation_and_request_binding_stay_native() -> None:
    assurance = native.AssurancePolicy(
        "raw-key-baseline",
        [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
        ],
    )
    anchor = native.TrustAnchor(
        ROOT.value,
        ROOT,
        ["raw-key-v1"],
        [("auths.mcp", 1)],
        [("tools/call", "mcp://reports/tools/update_demo_record")],
        ["mcp://reports"],
        ["mcp://reports"],
        0,
        100,
        ("numeric-ceiling-v1", 20),
        1,
        "raw-key-baseline",
        None,
    )
    template = native.compile_trusted_context(
        native.self_contained_configuration(),
        None,
        1,
        1,
        1,
        [anchor],
        assurance,
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        [],
    )
    request = template.bind_request("mcp://reports", bytes([0x22]) * 32, 50)

    assert request.configuration == native.self_contained_configuration()
    assert trusted_context_bytes(request)


def test_authorization_plan_builder_is_typed_and_bounded() -> None:
    builder = native.AuthorizationPlanBuilder()
    first = builder.proof(bytes([1]) * 32)
    second = builder.proof(bytes([2]) * 32)
    plan = builder.threshold(1, [first, second])

    assert plan.shape == (2, 2)
    assert len(plan.plan_id) == 32
