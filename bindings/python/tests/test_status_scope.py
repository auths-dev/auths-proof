from __future__ import annotations

import pytest

from auths._lifecycle import StatusScope, StatusTrustRule


def test_a_status_scope_lists_anchor_ids_only_for_anchors() -> None:
    assert StatusScope.own().kind == "own"
    assert StatusScope.any().anchor_ids == ()
    assert StatusScope.anchors(["anchor-f", "anchor-v"]).anchor_ids == (
        "anchor-f",
        "anchor-v",
    )
    with pytest.raises(ValueError):
        StatusScope.anchors([])
    with pytest.raises(ValueError):
        StatusScope("own", ("anchor-v",))
    with pytest.raises(ValueError):
        StatusScope("everyone")


def test_a_status_trust_rule_has_no_default_scope() -> None:
    with pytest.raises(TypeError):
        StatusTrustRule("auths-principal-status-v1", object(), 1)  # type: ignore[arg-type, call-arg]
