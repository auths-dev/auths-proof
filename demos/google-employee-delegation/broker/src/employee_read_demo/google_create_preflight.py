"""Read-only Jules preflight for one response-derived Project A child.

The caller supplies a child ID from the durable Auths attempt and task
journals after native task admission. This Google vertical checks account,
metadata, edit capability and blank Docs revision under Jules's existing
subject-bound credential. It never creates, populates or binds the child.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .demo_co_contract import ContractRejected
from .google_create_handoff import (
    CreateRecoverySearch, CreatedChildMetadataPins, CHILD_TITLE,
    created_child_docs_url,
    created_child_edit_access_url, created_child_metadata_url,
    validate_created_child_docs_read, validate_created_child_edit_access,
    validate_created_child_metadata,
)
from .google_write_credential import WriteCredentialPins, lease_jules_write_token
from .google_write_preflight import (
    MAX_DOCS_BYTES, MAX_METADATA_BYTES, _bounded_get, _json_object,
)
from .write_handoff import validate_write_handoff

MAX_RECOVERY_PAGE_BYTES = 131_072
POPULATE_PREFLIGHT_SCHEMA = "auths.gateway-task-populate-preflight/1"
POPULATE_PREFLIGHT_DOMAIN = b"auths.gateway-task-populate-preflight/1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RULE_MODULES = (
    "google_create_preflight.py", "google_create_handoff.py",
    "google_write_credential.py", "google_write_preflight.py",
    "write_handoff.py", "demo_co_contract.py",
    "task_populate_operator.py",
)


def current_populate_preflight_rule_digest() -> str:
    """Pin the reviewed Google preflight implementation before task admission.

    This source revision commitment detects a different installed signer
    implementation. It is not a claim that source hashes prove semantics;
    the Google vertical tests and live provider checks remain separate.
    """
    digest = hashlib.sha256(b"auths.ap071-google-populate-preflight-rule/1\0")
    for name in _RULE_MODULES:
        source = Path(__file__).with_name(name).read_bytes()
        if len(source) > 1_048_576:
            raise ContractRejected("Google preflight implementation exceeds review bounds")
        digest.update(name.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(source).digest())
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class JulesCreatedChildPreflight:
    child_id: str
    tab_id: str
    revision_id: str
    created_at: datetime
    checked_at: int
    connection_id: str
    connection_generation: int
    connection_subject: str
    metadata_sha256: str
    capability_sha256: str
    docs_sha256: str


@dataclass(frozen=True)
class JulesCreateRecoverySearchResult:
    """Private search evidence only; it cannot authorize population or retry."""

    candidate_id: str | None
    candidate_count: int
    parent_id: str
    drive_id: str
    marker_value: str
    page_sha256: tuple[str, ...]
    metadata_sha256: str | None
    checked_at: int
    connection_id: str
    connection_generation: int
    connection_subject: str

    @property
    def status(self) -> str:
        if self.candidate_count == 0:
            return "zero"
        return "single" if self.candidate_count == 1 else "multiple"


def preflight_jules_created_child(
    evidence_path: Path,
    grant_path: Path,
    credential_pins: WriteCredentialPins,
    child_pins: CreatedChildMetadataPins,
    *,
    connection_id: str,
    connection_generation: int,
    now: int | None = None,
) -> JulesCreatedChildPreflight:
    """Use Jules's pinned grant for three fixed, bounded provider GETs."""
    now = int(time.time()) if now is None else now
    evidence = validate_write_handoff(evidence_path, credential_pins.producer)
    child_pins.validate()
    if (child_pins.parent_id != evidence["folder_id"]
            or child_pins.drive_id != evidence["drive_id"]):
        raise ContractRejected("created child differs from pinned Project A")
    lease = lease_jules_write_token(
        evidence_path, grant_path, credential_pins,
        connection_id=connection_id,
        connection_generation=connection_generation, now=now,
    )
    if lease.expires_at <= now + 90:
        raise ContractRejected("Jules child preflight lease expires before entry")
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Authorization": f"Bearer {lease.access_token}",
        "Accept-Encoding": "identity",
    })
    try:
        metadata_raw = _bounded_get(
            session, created_child_metadata_url(child_pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        )
        metadata = _json_object(metadata_raw)
        created_at = validate_created_child_metadata(metadata, child_pins)
        access_raw = _bounded_get(
            session, created_child_edit_access_url(child_pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        )
        access = _json_object(access_raw)
        validate_created_child_edit_access(access, child_pins)
        document_raw = _bounded_get(
            session, created_child_docs_url(child_pins), params={},
            maximum=MAX_DOCS_BYTES, media_type="application/json",
        )
        document = _json_object(document_raw)
        revision = validate_created_child_docs_read(document, child_pins)
        return JulesCreatedChildPreflight(
            child_pins.candidate_id, revision.tab_id, revision.revision_id,
            created_at, now, connection_id, connection_generation,
            credential_pins.producer.jules_subject,
            hashlib.sha256(metadata_raw).hexdigest(),
            hashlib.sha256(access_raw).hexdigest(),
            hashlib.sha256(document_raw).hexdigest(),
        )
    finally:
        session.close()


def attest_jules_created_child(
    evidence_path: Path,
    grant_path: Path,
    credential_pins: WriteCredentialPins,
    child_pins: CreatedChildMetadataPins,
    *,
    connection_id: str,
    connection_generation: int,
    task_id: str,
    task_commitment: str,
    plan_commitment: str,
    create_operation_id: str,
    populate_recipe_digest: str,
    rule_digest: str,
    plan_expires_at: int,
    signing_key: Ed25519PrivateKey,
    now: int | None = None,
) -> bytes:
    """Run the Jules-only GET checks and sign their bounded facts for Auths.

    The operator keeps this key beside the credential-bearing vertical, never
    in an agent action or a public receipt. The gateway independently checks
    its pinned public key, plan, task and response-derived child binding.
    """
    if (type(task_id) is not str or not 1 <= len(task_id) <= 128
            or type(create_operation_id) is not str
            or not 1 <= len(create_operation_id) <= 128
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                   for value in (task_commitment, plan_commitment,
                                 populate_recipe_digest, rule_digest))
            or type(plan_expires_at) is not int):
        raise ContractRejected("populate preflight plan pins are invalid")
    now = int(time.time()) if now is None else now
    if plan_expires_at <= now:
        raise ContractRejected("populate preflight plan has expired")
    observed = preflight_jules_created_child(
        evidence_path, grant_path, credential_pins, child_pins,
        connection_id=connection_id,
        connection_generation=connection_generation, now=now,
    )
    valid_until = min(observed.checked_at + 60, plan_expires_at)
    if valid_until <= observed.checked_at:
        raise ContractRejected("populate preflight plan has expired")
    statement = {
        "schema": POPULATE_PREFLIGHT_SCHEMA,
        "task_id": task_id,
        "task_commitment": task_commitment,
        "plan_commitment": plan_commitment,
        "create_operation_id": create_operation_id,
        "child_id": observed.child_id,
        "populate_recipe_digest": populate_recipe_digest,
        "preflight_rule_digest": rule_digest,
        "connection_id": observed.connection_id,
        "connection_generation": observed.connection_generation,
        "connection_subject": observed.connection_subject,
        "tab_id": observed.tab_id,
        "revision_id": observed.revision_id,
        "metadata_sha256": observed.metadata_sha256,
        "capability_sha256": observed.capability_sha256,
        "docs_sha256": observed.docs_sha256,
        "checked_at": observed.checked_at,
        "valid_until": valid_until,
    }
    signature = signing_key.sign(POPULATE_PREFLIGHT_DOMAIN + _canonical_json(statement))
    return _canonical_json({
        "statement": statement,
        "signature_b64": base64.b64encode(signature).decode("ascii").rstrip("="),
    })


def search_jules_created_child(
    evidence_path: Path,
    grant_path: Path,
    credential_pins: WriteCredentialPins,
    marker_value: str,
    *,
    connection_id: str,
    connection_generation: int,
    pinned_parent_id: str | None = None,
    inject_incomplete_search_for_test: bool = False,
    now: int | None = None,
) -> JulesCreateRecoverySearchResult:
    """Collect bounded recovery evidence; never grant or retry create.

    The caller must take `marker_value` from the original signed task, not an
    agent message. A returned ID is only a proposal for demo_co inspection and
    fresh human-signed recovered-child binding in the Auths task journal.
    """
    now = int(time.time()) if now is None else now
    evidence = validate_write_handoff(evidence_path, credential_pins.producer)
    parent_id = (pinned_parent_id if pinned_parent_id is not None
                 else evidence["folder_id"])
    search = CreateRecoverySearch(
        parent_id=parent_id, drive_id=evidence["drive_id"],
        marker_value=marker_value,
    )
    lease = lease_jules_write_token(
        evidence_path, grant_path, credential_pins,
        connection_id=connection_id,
        connection_generation=connection_generation, now=now,
    )
    if lease.expires_at <= now + 90:
        raise ContractRejected("Jules recovery lease expires before search")
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Authorization": f"Bearer {lease.access_token}",
        "Accept-Encoding": "identity",
    })
    try:
        page_sha256 = []
        while not search.complete:
            raw = _bounded_get(
                session, search.next_url(), params={},
                maximum=MAX_RECOVERY_PAGE_BYTES, media_type="application/json",
            )
            page = _json_object(raw)
            if inject_incomplete_search_for_test:
                # An Auths-owned fault test exercises the same parser with a
                # deliberately incomplete page. The raw Google reply remains
                # separately hashed; this flag never grants a child scope.
                page = page | {"incompleteSearch": True}
            search.accept_page(page)
            page_sha256.append(hashlib.sha256(raw).hexdigest())
        candidate_id = search.single_candidate()
        if candidate_id is None:
            return JulesCreateRecoverySearchResult(
                None, search.candidate_count, parent_id,
                evidence["drive_id"], marker_value, tuple(page_sha256), None,
                now, connection_id, connection_generation,
                credential_pins.producer.jules_subject,
            )
        pins = CreatedChildMetadataPins(
            candidate_id=candidate_id, parent_id=parent_id,
            drive_id=evidence["drive_id"], title=CHILD_TITLE,
            marker_value=marker_value,
        )
        metadata_raw = _bounded_get(
            session, created_child_metadata_url(pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        )
        metadata = _json_object(metadata_raw)
        validate_created_child_metadata(metadata, pins)
        return JulesCreateRecoverySearchResult(
            candidate_id, search.candidate_count, parent_id,
            evidence["drive_id"], marker_value, tuple(page_sha256),
            hashlib.sha256(metadata_raw).hexdigest(), now,
            connection_id, connection_generation,
            credential_pins.producer.jules_subject,
        )
    finally:
        session.close()
