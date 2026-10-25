"""Private, broker-signed observations about one admitted read attempt."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .admission import AdmissionStore
from .authority import VerifiedRead
from .contracts import MAX_METADATA_BYTES, TaskDescriptor, canonical_json
from .google_drive import ProviderTrace

CONTRACT = "auths.employee-read-receipt/v1"
PREFIX = b"auths.employee-read-receipt/v1\n"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SignedReadReceipt:
    payload: dict
    signature: str

    def json_bytes(self) -> bytes:
        return canonical_json({"payload": self.payload, "signature": self.signature})


def verify_receipt(receipt: SignedReadReceipt, expected_public_key: bytes) -> bool:
    """The verifier pins a broker key; the receipt cannot choose its own root."""
    if type(receipt.payload) is not dict or type(receipt.signature) is not str:
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(expected_public_key)
        if receipt.payload.get("contract") != CONTRACT:
            return False
        signature = base64.urlsafe_b64decode(receipt.signature + "=" * (-len(receipt.signature) % 4))
        public.verify(signature, PREFIX + canonical_json(receipt.payload))
        return True
    except (ValueError, TypeError, binascii.Error, InvalidSignature):
        return False


class ReceiptStore:
    def __init__(self, path: Path, signing_key: Ed25519PrivateKey) -> None:
        self.path = path
        self.signing_key = signing_key
        self.public_key = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.signer_id = hashlib.sha256(self.public_key).hexdigest()
        AdmissionStore(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS read_receipts (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, receipt BLOB NOT NULL,
                created_at INTEGER NOT NULL
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def prepare(self, *, task: TaskDescriptor, verified: VerifiedRead, challenge: bytes,
                provider_stage: str, release_stage: str, content: bytes | None,
                trace: ProviderTrace | None = None,
                now: int | None = None) -> SignedReadReceipt:
        """Sign a receipt without publishing it before the release transaction."""
        if provider_stage not in {"not_contacted", "requested", "provider_denied", "content_fetched"}:
            raise ValueError("invalid provider stage")
        if release_stage not in {"not_committed", "committed"}:
            raise ValueError("invalid release stage")
        if (release_stage == "committed") != (content is not None):
            raise ValueError("released content evidence is inconsistent")
        if len(challenge) != 32 or len(verified.action_commitment) != 32:
            raise ValueError("invalid native commitment")
        if trace is not None and (not 0 <= trace.requests_started <= 2
                                  or not 0 <= trace.response_bytes <= MAX_METADATA_BYTES + verified.command.max_bytes + 2):
            raise ValueError("provider trace exceeds reserved capacity")
        now = int(time.time()) if now is None else now
        receipt_id = secrets.token_urlsafe(24)
        payload = {
            "contract": CONTRACT,
            "receipt_id": receipt_id,
            "company_id": task.company_id,
            "instance_id": task.instance_id,
            "environment_commitment": task.environment_commitment,
            "employee_principal": task.employee_principal,
            "identity_binding_ref": task.identity_binding_ref,
            "agent_principal": task.agent_principal,
            "task_id": task.task_id,
            "task_commitment": task.digest,
            "action_commitment": verified.action_commitment.hex(),
            "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
            "native_code": verified.native_code,
            "resource_ref": hashlib.sha256(verified.command.file_id.encode()).hexdigest(),
            "connection_id": task.connection_id,
            "connection_generation": task.connection_generation,
            "requested_max_bytes": verified.command.max_bytes,
            "reserved_provider_requests": 2,
            "reserved_provider_response_bytes": MAX_METADATA_BYTES + verified.command.max_bytes + 2,
            "provider_requests_started": None if trace is None else trace.requests_started,
            "provider_response_bytes_observed": None if trace is None else trace.response_bytes,
            "charged_task_bytes": verified.command.max_bytes,
            "provider_stage": provider_stage,
            "release_stage": release_stage,
            "transport_delivery": "unknown",
            "released_bytes": len(content) if content is not None else 0,
            "content_sha256": hashlib.sha256(content).hexdigest() if content is not None else None,
            "observed_at": now,
            "signer_id": self.signer_id,
        }
        signature = _b64(self.signing_key.sign(PREFIX + canonical_json(payload)))
        return SignedReadReceipt(payload, signature)

    def persist(self, db: sqlite3.Connection, task_id: str,
                receipt: SignedReadReceipt) -> None:
        """Insert under the caller's transaction, including a release gate."""
        db.execute("INSERT INTO read_receipts(id,task_id,receipt,created_at) VALUES(?,?,?,?)",
                   (receipt.payload["receipt_id"], task_id, receipt.json_bytes(),
                    receipt.payload["observed_at"]))

    def record(self, *, task: TaskDescriptor, verified: VerifiedRead, challenge: bytes,
               provider_stage: str, release_stage: str, content: bytes | None,
               trace: ProviderTrace | None = None,
               now: int | None = None) -> SignedReadReceipt:
        receipt = self.prepare(task=task, verified=verified, challenge=challenge,
                               provider_stage=provider_stage, release_stage=release_stage,
                               content=content, trace=trace, now=now)
        with self._connect() as db:
            self.persist(db, task.task_id, receipt)
        return receipt

    def load(self, receipt_id: str) -> SignedReadReceipt | None:
        """Trusted caller must check task ownership before exposing this private record."""
        with self._connect() as db:
            row = db.execute("SELECT receipt FROM read_receipts WHERE id=?", (receipt_id,)).fetchone()
        if row is None:
            return None
        document = json.loads(row[0])
        return SignedReadReceipt(document["payload"], document["signature"])
