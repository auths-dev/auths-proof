"""Read-only Jules preflight for one response-derived Project A child.

The caller supplies a child ID from the durable Auths attempt and task
journals after native task admission. This Google vertical checks account,
metadata, edit capability and blank Docs revision under Jules's existing
subject-bound credential. It never creates, populates or binds the child.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests

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


@dataclass(frozen=True)
class JulesCreatedChildPreflight:
    child_id: str
    tab_id: str
    revision_id: str
    created_at: datetime
    checked_at: int


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
        metadata = _json_object(_bounded_get(
            session, created_child_metadata_url(child_pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        created_at = validate_created_child_metadata(metadata, child_pins)
        access = _json_object(_bounded_get(
            session, created_child_edit_access_url(child_pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        validate_created_child_edit_access(access, child_pins)
        document = _json_object(_bounded_get(
            session, created_child_docs_url(child_pins), params={},
            maximum=MAX_DOCS_BYTES, media_type="application/json",
        ))
        revision = validate_created_child_docs_read(document, child_pins)
        return JulesCreatedChildPreflight(
            child_pins.candidate_id, revision.tab_id, revision.revision_id,
            created_at, now,
        )
    finally:
        session.close()


def search_jules_created_child(
    evidence_path: Path,
    grant_path: Path,
    credential_pins: WriteCredentialPins,
    marker_value: str,
    *,
    connection_id: str,
    connection_generation: int,
    now: int | None = None,
) -> str | None:
    """Find a sole candidate after response loss; never grant or retry create.

    The caller must take `marker_value` from the original signed task, not an
    agent message. A returned ID is only a proposal for demo_co inspection and
    fresh human-signed recovered-child binding in the Auths task journal.
    """
    now = int(time.time()) if now is None else now
    evidence = validate_write_handoff(evidence_path, credential_pins.producer)
    search = CreateRecoverySearch(
        parent_id=evidence["folder_id"], drive_id=evidence["drive_id"],
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
        while not search.complete:
            page = _json_object(_bounded_get(
                session, search.next_url(), params={},
                maximum=MAX_RECOVERY_PAGE_BYTES, media_type="application/json",
            ))
            search.accept_page(page)
        candidate_id = search.single_candidate()
        if candidate_id is None:
            return None
        pins = CreatedChildMetadataPins(
            candidate_id=candidate_id, parent_id=evidence["folder_id"],
            drive_id=evidence["drive_id"], title=CHILD_TITLE,
            marker_value=marker_value,
        )
        metadata = _json_object(_bounded_get(
            session, created_child_metadata_url(pins), params={},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        validate_created_child_metadata(metadata, pins)
        return candidate_id
    finally:
        session.close()
