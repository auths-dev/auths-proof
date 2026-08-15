"""Canonical native Auths decision and execution receipts."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Literal, Mapping, Optional, Protocol, Tuple, Union, cast

from . import _native as native


@dataclass(frozen=True)
class ReceiptSigner:
    principal: str
    verification_method: str
    suite: str
    evidence: bytes

    def __post_init__(self) -> None:
        evidence = bytes(self.evidence)
        if (
            not self.principal
            or not self.verification_method
            or not self.suite
            or not evidence
        ):
            raise ValueError("invalid receipt signer")
        object.__setattr__(self, "evidence", evidence)


class ReceiptAttestor(Protocol):
    signer: ReceiptSigner

    async def sign(self, preimage: bytes) -> bytes: ...


@dataclass(frozen=True)
class AttestedReceipt:
    kind: str
    receipt_id: bytes
    bytes: bytes
    signer: ReceiptSigner

    def __post_init__(self) -> None:
        if self.kind not in ("decision", "execution"):
            raise ValueError("unsupported receipt kind")
        if len(self.receipt_id) != 32 or not self.bytes:
            raise ValueError("invalid attested receipt")
        object.__setattr__(self, "receipt_id", bytes(self.receipt_id))
        object.__setattr__(self, "bytes", bytes(self.bytes))


@dataclass(frozen=True)
class Receipt:
    decision: AttestedReceipt
    execution: AttestedReceipt

    def __post_init__(self) -> None:
        if self.decision.kind != "decision" or self.execution.kind != "execution":
            raise ValueError("Auths receipt pair has invalid kinds")


ReceiptViewMode = Literal["opaque", "summary", "full"]


@dataclass(frozen=True)
class ReceiptInspectionSigner:
    principal: str
    verification_method: str
    suite: str


@dataclass(frozen=True)
class ReceiptInspectionProfile:
    id: str
    version: int


@dataclass(frozen=True)
class ReceiptInspectionCommitments:
    proof: str
    action: str
    context: str
    principal_status: str
    grant_status: str
    execution_lease: str
    command: str
    result: Optional[str]


@dataclass(frozen=True)
class ReceiptInspectionMetadata:
    decision_receipt_id: str
    execution_receipt_id: str
    profile: ReceiptInspectionProfile
    decision: Literal["authorized", "denied", "indeterminate"]
    reasons: Tuple[str, ...]
    outcome: Literal["succeeded", "failed", "indeterminate"]
    decided_at: int
    completed_at: int
    decision_signer: ReceiptInspectionSigner
    execution_signer: ReceiptInspectionSigner
    commitments: ReceiptInspectionCommitments


@dataclass(frozen=True)
class ReceiptSummaryField:
    label: str
    value: str


@dataclass(frozen=True)
class ReceiptSummary:
    title: str
    fields: Tuple[ReceiptSummaryField, ...]


@dataclass(frozen=True)
class ReceiptDisclosureMaterial:
    command: bytes
    result: Optional[bytes]


@dataclass(frozen=True)
class VerifiedOpaqueReceipt:
    kind: Literal["verified-opaque"]
    mode: Literal["opaque"]
    receipt: ReceiptInspectionMetadata


@dataclass(frozen=True)
class VerifiedDisclosedReceipt:
    kind: Literal["verified-disclosed"]
    mode: Literal["summary", "full"]
    receipt: ReceiptInspectionMetadata
    summary: ReceiptSummary
    disclosure: Optional[ReceiptDisclosureMaterial]


@dataclass(frozen=True)
class InvalidReceiptInspection:
    kind: Literal["invalid"]
    mode: str
    code: str


ReceiptInspectionResult = Union[
    VerifiedOpaqueReceipt,
    VerifiedDisclosedReceipt,
    InvalidReceiptInspection,
]


class ReceiptDisclosureProtector(Protocol):
    def protect(self, tenant: str, receipt_id: bytes, plaintext: bytes) -> bytes: ...

    def reveal(self, tenant: str, receipt_id: bytes, protected: bytes) -> bytes: ...


class ReceiptDisclosureStore(Protocol):
    def put(self, tenant: str, receipt_id: bytes, protected: bytes) -> None: ...

    def get(self, tenant: str, receipt_id: bytes) -> Optional[bytes]: ...

    def delete(self, tenant: str, receipt_id: bytes) -> None: ...


def verify_receipt(receipt: AttestedReceipt) -> None:
    if type(receipt) is not AttestedReceipt:
        raise TypeError("attested receipt is required")
    native.verify_raw_key_receipt_v1(
        receipt.kind,
        receipt.bytes,
        receipt.receipt_id,
        receipt.signer.principal,
        receipt.signer.verification_method,
        receipt.signer.suite,
        receipt.signer.evidence,
    )


def verify_linked_receipt(receipt: Receipt) -> None:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    verify_receipt(receipt.decision)
    verify_receipt(receipt.execution)
    native.verify_receipt_link_v1(
        receipt.decision.bytes,
        receipt.decision.receipt_id,
        receipt.execution.bytes,
        receipt.execution.receipt_id,
    )


def create_receipt_disclosure(
    receipt: Receipt,
    *,
    profile_id: str,
    profile_version: int,
    command: bytes,
    result: Optional[bytes] = None,
) -> bytes:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    return bytes(
        native.prepare_receipt_disclosure_v1(
            receipt.execution.receipt_id,
            profile_id,
            profile_version,
            command,
            result,
        )
    )


def inspect_receipt(
    receipt: Receipt,
    *,
    mode: ReceiptViewMode = "opaque",
    disclosure: Optional[bytes] = None,
) -> ReceiptInspectionResult:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    document = native.inspect_raw_key_receipt_v1(
        receipt.decision.receipt_id,
        receipt.decision.bytes,
        receipt.decision.signer.evidence,
        receipt.execution.receipt_id,
        receipt.execution.bytes,
        receipt.execution.signer.evidence,
        mode,
        disclosure,
    )
    return _parse_inspection(json.loads(bytes(document)))


def encode_linked_receipt(receipt: Receipt) -> bytes:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    return json.dumps(
        {
            "schema": "auths.portable-receipt/1",
            "decision": _receipt_projection(receipt.decision),
            "execution": _receipt_projection(receipt.execution),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def decode_linked_receipt(value: bytes) -> Receipt:
    encoded = bytes(value)
    if not encoded or len(encoded) > 1024 * 1024:
        raise ValueError("portable Auths receipt is outside bounds")
    try:
        parsed: object = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("portable Auths receipt is malformed") from None
    if type(parsed) is not dict:
        raise ValueError("unsupported portable Auths receipt")
    item = cast(Mapping[str, object], parsed)
    if item.get("schema") != "auths.portable-receipt/1":
        raise ValueError("unsupported portable Auths receipt")
    return Receipt(
        _parse_receipt_projection(item.get("decision"), "decision"),
        _parse_receipt_projection(item.get("execution"), "execution"),
    )


def _receipt_projection(receipt: AttestedReceipt) -> dict[str, object]:
    return {
        "receiptId": _base64url(receipt.receipt_id),
        "bytes": _base64url(receipt.bytes),
        "signer": {
            "principal": receipt.signer.principal,
            "verificationMethod": receipt.signer.verification_method,
            "suite": receipt.signer.suite,
            "evidence": _base64url(receipt.signer.evidence),
        },
    }


def _parse_receipt_projection(value: object, kind: str) -> AttestedReceipt:
    if type(value) is not dict:
        raise ValueError("portable Auths receipt member is malformed")
    item = cast(Mapping[str, object], value)
    signer_value = item.get("signer")
    if type(signer_value) is not dict:
        raise ValueError("portable Auths receipt member is malformed")
    signer = cast(Mapping[str, object], signer_value)
    return AttestedReceipt(
        kind,
        _decode_base64url(item.get("receiptId"), 32, 32),
        _decode_base64url(item.get("bytes"), 1, 768 * 1024),
        ReceiptSigner(
            _bounded_text(signer.get("principal")),
            _bounded_text(signer.get("verificationMethod")),
            _bounded_text(signer.get("suite")),
            _decode_base64url(signer.get("evidence"), 1, 128 * 1024),
        ),
    )


def _parse_inspection(value: object) -> ReceiptInspectionResult:
    item = cast(Mapping[str, object], value)
    kind = item["kind"]
    if kind == "invalid":
        return InvalidReceiptInspection("invalid", str(item["mode"]), str(item["code"]))
    metadata = _parse_inspection_metadata(cast(Mapping[str, object], item["receipt"]))
    if kind == "verified-opaque":
        return VerifiedOpaqueReceipt("verified-opaque", "opaque", metadata)
    summary_value = cast(Mapping[str, object], item["summary"])
    fields = tuple(
        ReceiptSummaryField(str(field["label"]), str(field["value"]))
        for field in cast(list[Mapping[str, object]], summary_value["fields"])
    )
    material_value = item.get("disclosure")
    material = (
        None
        if material_value is None
        else ReceiptDisclosureMaterial(
            bytes.fromhex(
                str(cast(Mapping[str, object], material_value)["commandHex"])
            ),
            None
            if cast(Mapping[str, object], material_value).get("resultHex") is None
            else bytes.fromhex(
                str(cast(Mapping[str, object], material_value)["resultHex"])
            ),
        )
    )
    return VerifiedDisclosedReceipt(
        "verified-disclosed",
        cast(Literal["summary", "full"], item["mode"]),
        metadata,
        ReceiptSummary(str(summary_value["title"]), fields),
        material,
    )


def _parse_inspection_metadata(
    value: Mapping[str, object],
) -> ReceiptInspectionMetadata:
    profile = cast(Mapping[str, object], value["profile"])
    commitments = cast(Mapping[str, object], value["commitments"])
    return ReceiptInspectionMetadata(
        str(value["decisionReceiptId"]),
        str(value["executionReceiptId"]),
        ReceiptInspectionProfile(
            str(profile["id"]), int(cast(int, profile["version"]))
        ),
        cast(Literal["authorized", "denied", "indeterminate"], value["decision"]),
        tuple(str(reason) for reason in cast(list[object], value["reasons"])),
        cast(Literal["succeeded", "failed", "indeterminate"], value["outcome"]),
        int(cast(int, value["decidedAt"])),
        int(cast(int, value["completedAt"])),
        _parse_inspection_signer(cast(Mapping[str, object], value["decisionSigner"])),
        _parse_inspection_signer(cast(Mapping[str, object], value["executionSigner"])),
        ReceiptInspectionCommitments(
            str(commitments["proof"]),
            str(commitments["action"]),
            str(commitments["context"]),
            str(commitments["principalStatus"]),
            str(commitments["grantStatus"]),
            str(commitments["executionLease"]),
            str(commitments["command"]),
            None if commitments.get("result") is None else str(commitments["result"]),
        ),
    )


def _parse_inspection_signer(value: Mapping[str, object]) -> ReceiptInspectionSigner:
    return ReceiptInspectionSigner(
        str(value["principal"]),
        str(value["verificationMethod"]),
        str(value["suite"]),
    )


def _bounded_text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 1024:
        raise ValueError("portable Auths receipt text is outside bounds")
    return value


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object, minimum: int, maximum: int) -> bytes:
    if type(value) is not str or not value or len(value) > maximum * 2:
        raise ValueError("portable Auths receipt bytes are outside bounds")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise ValueError("portable Auths receipt bytes are malformed") from None
    if not minimum <= len(decoded) <= maximum or _base64url(decoded) != value:
        raise ValueError("portable Auths receipt bytes are not canonical")
    return decoded


async def _attest_decision(
    preparation: native.ReceiptPreparation, attestor: ReceiptAttestor
) -> AttestedReceipt:
    signature = await attestor.sign(bytes(preparation.signing_preimage))
    signer = attestor.signer
    encoded = native.attest_decision_receipt_v1(
        preparation.canonical,
        signer.principal,
        signer.verification_method,
        signer.suite,
        signature,
    )
    return AttestedReceipt(
        "decision", bytes(preparation.receipt_id), bytes(encoded), signer
    )


async def _attest_execution(
    preparation: native.ReceiptPreparation, attestor: ReceiptAttestor
) -> AttestedReceipt:
    signature = await attestor.sign(bytes(preparation.signing_preimage))
    signer = attestor.signer
    encoded = native.attest_execution_receipt_v1(
        preparation.canonical,
        signer.principal,
        signer.verification_method,
        signer.suite,
        signature,
    )
    return AttestedReceipt(
        "execution", bytes(preparation.receipt_id), bytes(encoded), signer
    )


__all__ = [
    "AttestedReceipt",
    "InvalidReceiptInspection",
    "ReceiptAttestor",
    "ReceiptDisclosureMaterial",
    "ReceiptDisclosureProtector",
    "ReceiptDisclosureStore",
    "ReceiptInspectionCommitments",
    "ReceiptInspectionMetadata",
    "ReceiptInspectionProfile",
    "ReceiptInspectionResult",
    "ReceiptInspectionSigner",
    "ReceiptSigner",
    "ReceiptSummary",
    "ReceiptSummaryField",
    "ReceiptViewMode",
    "Receipt",
    "VerifiedDisclosedReceipt",
    "VerifiedOpaqueReceipt",
    "create_receipt_disclosure",
    "decode_linked_receipt",
    "encode_linked_receipt",
    "inspect_receipt",
    "verify_receipt",
    "verify_linked_receipt",
]
