from __future__ import annotations

import json
from pathlib import Path

import pytest

from auths import Receipt
from auths._product_errors import AuthsError, EffectState, registry_codes
from auths._receipts import AttestedReceipt, ReceiptSigner
from auths.verify import (
    InvalidReceiptInspection,
    VerifiedDisclosedReceipt,
    VerifiedOpaqueReceipt,
    create_receipt_disclosure,
    inspect_receipt,
)


ROOT = Path(__file__).parents[3]
FIXTURE = json.loads(
    (ROOT / "product/fixtures/v1/receipt-disclosure/inspection-v1.json").read_text()
)


def test_rust_typescript_and_python_share_the_receipt_disclosure_contract() -> None:
    receipt = _fixture_receipt()
    command = bytes.fromhex(FIXTURE["commandHex"])
    result = bytes.fromhex(FIXTURE["resultHex"])
    disclosure = create_receipt_disclosure(
        receipt,
        profile_id=FIXTURE["profile"]["id"],
        profile_version=FIXTURE["profile"]["version"],
        command=command,
        result=result,
    )
    assert disclosure == bytes.fromhex(FIXTURE["disclosureHex"])

    for scenario in FIXTURE["cases"]:
        selected_receipt, selected_disclosure = _scenario(
            scenario, receipt, command, result, disclosure
        )
        inspected = inspect_receipt(
            selected_receipt,
            mode=scenario["mode"],
            disclosure=selected_disclosure,
        )
        assert inspected.kind == scenario["kind"], scenario["id"]
        if isinstance(inspected, InvalidReceiptInspection):
            assert inspected.code == scenario["code"], scenario["id"]

    opaque = inspect_receipt(receipt)
    assert isinstance(opaque, VerifiedOpaqueReceipt)
    assert not hasattr(opaque, "summary")
    assert not hasattr(opaque, "disclosure")

    summary = inspect_receipt(receipt, mode="summary", disclosure=disclosure)
    assert isinstance(summary, VerifiedDisclosedReceipt)
    assert tuple(field.label for field in summary.summary.fields[:4]) == (
        "Fleet",
        "Device",
        "Command",
        "Sequence",
    )
    assert summary.disclosure is None
    assert not hasattr(summary, "effect_capable")

    full = inspect_receipt(receipt, mode="full", disclosure=disclosure)
    assert isinstance(full, VerifiedDisclosedReceipt)
    assert full.disclosure is not None
    assert full.disclosure.command == command
    assert full.disclosure.result == result

    # The bound is still enforced; it now reports the registry code so the
    # caller can read the effect axis instead of matching a message.
    with pytest.raises(AuthsError) as oversized:
        create_receipt_disclosure(
            receipt,
            profile_id=FIXTURE["profile"]["id"],
            profile_version=FIXTURE["profile"]["version"],
            command=b"x" * (1024 * 1024 + 1),
        )
    assert oversized.value.code in registry_codes()
    assert oversized.value.effect is EffectState.NOT_APPLIED


def _scenario(
    scenario: dict[str, str],
    receipt: Receipt,
    command: bytes,
    result: bytes,
    disclosure: bytes,
) -> tuple[Receipt, bytes | None]:
    mutation = scenario["mutation"]
    selected_receipt = receipt
    selected_disclosure: bytes | None = disclosure
    if mutation == "missing":
        selected_disclosure = None
    elif mutation == "malformed":
        selected_disclosure = b"\xff"
    elif mutation == "receipt-id":
        changed = (
            bytes([receipt.execution.receipt_id[0] ^ 1])
            + receipt.execution.receipt_id[1:]
        )
        selected_disclosure = create_receipt_disclosure(
            Receipt(
                receipt.decision,
                _replace_receipt(receipt.execution, receipt_id=changed),
            ),
            profile_id=FIXTURE["profile"]["id"],
            profile_version=FIXTURE["profile"]["version"],
            command=command,
            result=result,
        )
    elif mutation == "profile":
        selected_disclosure = create_receipt_disclosure(
            receipt,
            profile_id="auths.http",
            profile_version=1,
            command=command,
            result=result,
        )
    elif mutation == "command":
        changed = command[:-2] + bytes([command[-2] ^ 1]) + command[-1:]
        selected_disclosure = create_receipt_disclosure(
            receipt,
            profile_id=FIXTURE["profile"]["id"],
            profile_version=FIXTURE["profile"]["version"],
            command=changed,
            result=result,
        )
    elif mutation == "result":
        changed = result[:-2] + bytes([result[-2] ^ 1]) + result[-1:]
        selected_disclosure = create_receipt_disclosure(
            receipt,
            profile_id=FIXTURE["profile"]["id"],
            profile_version=FIXTURE["profile"]["version"],
            command=command,
            result=changed,
        )
    elif mutation == "evidence":
        signer = receipt.execution.signer
        selected_receipt = Receipt(
            receipt.decision,
            _replace_receipt(
                receipt.execution,
                signer=ReceiptSigner(
                    signer.principal,
                    signer.verification_method,
                    signer.suite,
                    b"\xff",
                ),
            ),
        )
    elif mutation == "receipt":
        changed = receipt.execution.bytes[:-1] + bytes(
            [receipt.execution.bytes[-1] ^ 1]
        )
        selected_receipt = Receipt(
            receipt.decision,
            _replace_receipt(receipt.execution, encoded=changed),
        )
    return selected_receipt, selected_disclosure


def _fixture_receipt() -> Receipt:
    return Receipt(
        _fixture_member(FIXTURE["receipt"]["decision"]),
        _fixture_member(FIXTURE["receipt"]["execution"]),
    )


def _fixture_member(value: dict[str, object]) -> AttestedReceipt:
    signer = value["signer"]
    assert isinstance(signer, dict)
    return AttestedReceipt(
        str(value["kind"]),
        bytes.fromhex(str(value["receiptIdHex"])),
        bytes.fromhex(str(value["bytesHex"])),
        ReceiptSigner(
            str(signer["principal"]),
            str(signer["verificationMethod"]),
            str(signer["suite"]),
            bytes.fromhex(str(signer["evidenceHex"])),
        ),
    )


def _replace_receipt(
    value: AttestedReceipt,
    *,
    receipt_id: bytes | None = None,
    encoded: bytes | None = None,
    signer: ReceiptSigner | None = None,
) -> AttestedReceipt:
    return AttestedReceipt(
        value.kind,
        value.receipt_id if receipt_id is None else receipt_id,
        value.bytes if encoded is None else encoded,
        value.signer if signer is None else signer,
    )
