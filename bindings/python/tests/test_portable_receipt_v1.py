from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

import auths._native as native
from auths._public import parse_portable_receipt
from auths.verify import ReceiptTrustPolicy, RejectedReceipt, verify_receipt


def test_portable_receipt_v1_projection_is_self_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    portable_id = "rcpt_" + "A" * 43
    projection = SimpleNamespace(
        portable_receipt_id=portable_id,
        kind="execution",
        decision_receipt_id=b"d" * 32,
        execution_receipt_id=b"e" * 32,
        attested_decision=b"decision",
        attested_execution=b"execution",
    )
    monkeypatch.setattr(
        native, "decode_portable_receipt_v1", lambda _: projection, raising=False,
    )
    assert parse_portable_receipt(b"container") == (
        "execution", portable_id, b"d" * 32, b"e" * 32,
        b"decision", b"execution",
    )
    assert "linked_decision_receipt" not in inspect.signature(verify_receipt).parameters


def test_portable_receipt_v1_rejects_contradictory_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = SimpleNamespace(
        portable_receipt_id="rcpt_" + "A" * 43,
        kind="decision",
        decision_receipt_id=b"d" * 32,
        execution_receipt_id=b"e" * 32,
        attested_decision=b"decision",
        attested_execution=b"execution",
    )
    monkeypatch.setattr(
        native, "decode_portable_receipt_v1", lambda _: projection, raising=False,
    )
    with pytest.raises(ValueError, match="malformed portable receipt projection"):
        parse_portable_receipt(b"container")


def test_native_decoder_rejects_noncanonical_portable_receipt() -> None:
    with pytest.raises(ValueError, match="malformed receipt"):
        native.decode_portable_receipt_v1(b"\xa0")


def test_portable_receipt_bound_is_enforced_before_every_native_crossing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def decode(_: bytes) -> object:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            portable_receipt_id="rcpt_" + "A" * 43,
            kind="decision",
            decision_receipt_id=b"d" * 32,
            execution_receipt_id=None,
            attested_decision=b"decision",
            attested_execution=None,
        )

    monkeypatch.setattr(native, "decode_portable_receipt_v1", decode, raising=False)
    maximum = b"x" * 1_048_576
    assert parse_portable_receipt(maximum)[0] == "decision"
    assert calls == 1
    oversized = maximum + b"x"
    with pytest.raises(ValueError, match="outside bounds"):
        parse_portable_receipt(oversized)
    assert calls == 1

    trust = object.__new__(ReceiptTrustPolicy)
    rejected = verify_receipt(oversized, trust=trust)
    assert isinstance(rejected, RejectedReceipt)
    assert calls == 1
