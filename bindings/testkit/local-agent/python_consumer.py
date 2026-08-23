"""Installed-package consumer for the disposable local-agent launch proof."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
from pathlib import Path
from typing import Any, Dict

import auths
from auths import ClientOptions, OperationOptions
from auths.profile_runtime import Completed
from auths.verify import (
    ReceiptProfile,
    ReceiptTrustAnchor,
    VerifiedReceipt,
    pinned_receipt_trust,
    verify_receipt,
)
from auths_profiles.stripe import Stripe


IDEMPOTENCY_KEY = "testkit.stripe-refund.v1"


def _read_object(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("expected a JSON object")
    return value


def _decode_key(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


async def run(ready_path: Path, expected_path: Path, mode: str) -> None:
    ready = _read_object(ready_path)
    anchors = tuple(
        ReceiptTrustAnchor(
            role=row["role"],
            principal=row["principal"],
            verification_method=row["verificationMethod"],
            suite=row["suite"],
            public_key=_decode_key(row["publicKeyBase64Url"]),
        )
        for row in ready["receiptTrustAnchors"]
    )
    trust = pinned_receipt_trust(
        anchors=anchors,
        allowed_profiles=(ReceiptProfile("auths.stripe.refund", 1),),
    )
    async with auths.connect(
        options=ClientOptions(agent_socket=ready["agentSocket"])
    ) as session:
        outcome = await Stripe(session, connection=ready["connection"]).refunds.create_outcome(
            payment_intent="pi_testkit_123",
            amount=2_000,
            currency="usd",
            options=OperationOptions(idempotency_key=IDEMPOTENCY_KEY),
        )
        if not isinstance(outcome, Completed):
            raise AssertionError(f"expected completed, got {outcome.kind}")
        refund = outcome.value
        expected_completion = "fresh" if mode == "fresh" else "replayed"
        if refund.auths.completion != expected_completion:
            raise AssertionError(
                f"expected {expected_completion}, got {refund.auths.completion}"
            )
        receipts = await session.operations.receipts(refund.auths.operation_id)
        if tuple(value.id for value in receipts) != refund.auths.receipt_ids:
            raise AssertionError("receipt IDs differ from generated success metadata")
        if len(receipts) != 2:
            raise AssertionError("a provider-entered operation needs a receipt pair")
        for receipt in receipts:
            if not isinstance(verify_receipt(receipt, trust=trust), VerifiedReceipt):
                raise AssertionError("portable receipt did not verify")

        projection = {
            "refundId": refund.id,
            "operationId": refund.auths.operation_id,
            "receiptIds": list(refund.auths.receipt_ids),
        }
        if mode == "fresh":
            expected_path.write_text(
                json.dumps(projection, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif projection != _read_object(expected_path):
            raise AssertionError("restart replay changed the terminal result")
        print(json.dumps({"language": "python", "mode": mode, **projection}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--mode", choices=("fresh", "replay"), required=True)
    arguments = parser.parse_args()
    asyncio.run(run(arguments.ready, arguments.expected, arguments.mode))


if __name__ == "__main__":
    main()
