"""Read-only Jules preflight for the run-owned Google Docs edit vertical.

This checks the producer's pinned fixture immediately before proposing an
exact write. It returns no document body or OAuth material. A passed preflight
is not Auths write authority and must be rechecked at the gateway entry.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import requests

from .demo_co_contract import _unique_pairs
from .google_write_credential import WriteCredentialPins, lease_jules_write_token
from .write_handoff import validate_current_write_observation, validate_write_handoff


MAX_METADATA_BYTES = 32_768
MAX_DOCS_BYTES = 131_072
MAX_EXPORT_BYTES = 16_384
DRIVE_FILES = "https://www.googleapis.com/drive/v3/files"
DOCS_DOCUMENTS = "https://docs.googleapis.com/v1/documents"
FIELDS = "id,name,mimeType,parents,driveId,appProperties,capabilities(canAddChildren,canEdit)"
FOLDER_LOGICAL_ID = "ap071-project-a-folder"
DOCUMENT_LOGICAL_ID = "ap071-project-a-working-doc"
BOUNDED_NEGATIVE_LOGICAL_ID = "ap071-bounded-upfront-negative-doc"
SCRATCH_ROOT_LOGICAL_ID = "ap071-negative-root"
SCRATCH_ROOT_TITLE = "Demo Co AP-071 Recovery Negatives"


class WritePreflightDenied(PermissionError):
    """The pinned working Doc can no longer be edited as Jules."""


@dataclass(frozen=True)
class WritePreflight:
    document_id: str
    tab_id: str
    revision_id: str
    baseline_sha256: str
    byte_count: int
    marker_count: int
    checked_at: int


@dataclass(frozen=True)
class EditTarget:
    """A separately validated, operator-pinned edit destination and baseline."""

    document_id: str
    document_title: str
    logical_id: str
    folder_id: str
    drive_id: str
    tab_id: str
    marker: str
    baseline_sha256: str
    baseline_byte_count: int


def _bounded_get(session: requests.Session, url: str, *, params: dict[str, str],
                 maximum: int, media_type: str) -> bytes:
    try:
        with session.get(url, params=params, timeout=15, allow_redirects=False,
                         stream=True) as response:
            actual_media_type = (
                response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            if (response.status_code != 200
                    or actual_media_type != media_type
                    or response.headers.get("Content-Encoding", "identity") != "identity"):
                raise WritePreflightDenied("Jules preflight provider read was refused")
            declared = response.headers.get("Content-Length")
            if (declared is not None
                    and (not declared.isascii() or not declared.isdecimal()
                         or int(declared) > maximum)):
                raise WritePreflightDenied("Jules preflight response exceeds its byte limit")
            raw = response.raw.read(maximum + 1)
            if len(raw) > maximum:
                raise WritePreflightDenied("Jules preflight response exceeds its byte limit")
            return raw
    except requests.RequestException as error:
        raise WritePreflightDenied("Jules preflight provider read is unavailable") from error


def _json_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise WritePreflightDenied("Jules preflight response is malformed") from error
    if type(value) is not dict:
        raise WritePreflightDenied("Jules preflight response is not an object")
    return value


def _owned(item: dict, *, item_id: str, title: str, mime: str,
           drive_id: str, owner: str, logical_id: str,
           parent_id: str | None) -> bool:
    properties = item.get("appProperties")
    return (
        item.get("id") == item_id and item.get("name") == title
        and item.get("mimeType") == mime and item.get("driveId") == drive_id
        and (parent_id is None or
             (type(item.get("parents")) is list and parent_id in item["parents"]))
        and type(properties) is dict
        and properties.get("demo_co_owner") == owner
        and properties.get("demo_co_logical_id") == logical_id
    )


def preflight_jules_edit(evidence_path: Path, grant_path: Path,
                         pins: WriteCredentialPins, *, connection_id: str,
                         connection_generation: int,
                         current_observation_path: Path | None = None,
                         current_observation_sha256: str | None = None,
                         target: EditTarget | None = None,
                         now: int | None = None) -> WritePreflight:
    """Check exact run-owned IDs, Jules ACL, current revision and baseline."""
    now = int(time.time()) if now is None else now
    evidence = validate_write_handoff(evidence_path, pins.producer)
    if (current_observation_path is None) != (current_observation_sha256 is None):
        raise WritePreflightDenied("current working Doc observation is incomplete")
    if target is not None and current_observation_path is not None:
        raise WritePreflightDenied("edit target and working Doc snapshot cannot mix")
    baseline_sha256 = evidence["baseline_sha256"]
    baseline_byte_count = evidence["baseline_byte_count"]
    document_id = evidence["document_id"]
    document_title = evidence["document_title"]
    document_logical_id = DOCUMENT_LOGICAL_ID
    document_parent_id = evidence["folder_id"]
    document_owner = f"demo-co/v1:{pins.producer.instance}/{pins.producer.company}"
    tab_id = evidence["tab_id"]
    marker = evidence["marker"]
    if target is not None:
        nested_scratch = target.logical_id == BOUNDED_NEGATIVE_LOGICAL_ID
        if ((target.folder_id != evidence["folder_id"] and not nested_scratch)
                or (target.folder_id == evidence["folder_id"] and nested_scratch)
                or target.drive_id != evidence["drive_id"]
                or target.document_id == evidence["document_id"]
                or target.logical_id not in (
                    "ap071-project-a-clean-edit-rerun",
                    BOUNDED_NEGATIVE_LOGICAL_ID)
                or not target.document_id or len(target.document_id) > 64
                or not target.document_title or len(target.document_title) > 256
                or not target.tab_id or len(target.tab_id) > 16
                or not target.marker or len(target.marker) > 48
                or len(target.baseline_sha256) != 64
                or not 1 <= target.baseline_byte_count <= MAX_EXPORT_BYTES):
            raise WritePreflightDenied("separate edit target is outside pinned Project A")
        document_id = target.document_id
        document_title = target.document_title
        document_logical_id = target.logical_id
        document_parent_id = target.folder_id
        if nested_scratch:
            document_owner = (
                f"demo-co/v1:{pins.producer.instance}/"
                "atlas-studio-recovery-negative")
        tab_id = target.tab_id
        marker = target.marker
        baseline_sha256 = target.baseline_sha256
        baseline_byte_count = target.baseline_byte_count
    if current_observation_path is not None:
        try:
            _, current = validate_current_write_observation(
                current_observation_path, current_observation_sha256,
                evidence=evidence, now=now,
            )
        except (OSError, ValueError, PermissionError) as error:
            raise WritePreflightDenied(
                "current working Doc observation disagrees with pins",
            ) from error
        if current["original_marker_count"] != 1:
            raise WritePreflightDenied("current working Doc marker is unavailable")
        baseline_sha256 = current["content_sha256"]
        baseline_byte_count = current["content_byte_count"]
    lease = lease_jules_write_token(
        evidence_path, grant_path, pins, connection_id=connection_id,
        connection_generation=connection_generation, now=now,
    )
    if lease.expires_at <= now + 90:
        raise WritePreflightDenied("Jules write lease expires before entry")
    owner = f"demo-co/v1:{pins.producer.instance}/{pins.producer.company}"
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Authorization": f"Bearer {lease.access_token}",
        "Accept-Encoding": "identity",
    })
    try:
        folder_id = evidence["folder_id"]
        folder = _json_object(_bounded_get(
            session, f"{DRIVE_FILES}/{quote(folder_id, safe='')}",
            params={"supportsAllDrives": "true", "fields": FIELDS},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        folder_capabilities = folder.get("capabilities")
        if (not _owned(folder, item_id=folder_id, title=evidence["folder_title"],
                       mime="application/vnd.google-apps.folder",
                       drive_id=evidence["drive_id"], owner=owner,
                       # Jules's drive.file view may omit the shared-drive
                       # root parent. The producer pins this relation; the
                       # Jules check independently binds ID, drive, owner,
                       # title and add-children capability.
                       logical_id=FOLDER_LOGICAL_ID, parent_id=None)
                or type(folder_capabilities) is not dict
                or folder_capabilities.get("canAddChildren") is not True):
            raise WritePreflightDenied("Project A folder drifted or Jules cannot create")
        if (target is not None
                and target.logical_id == BOUNDED_NEGATIVE_LOGICAL_ID):
            scratch = _json_object(_bounded_get(
                session, f"{DRIVE_FILES}/{quote(target.folder_id, safe='')}",
                params={"supportsAllDrives": "true", "fields": FIELDS},
                maximum=MAX_METADATA_BYTES, media_type="application/json",
            ))
            capabilities = scratch.get("capabilities")
            if (not _owned(
                    scratch, item_id=target.folder_id,
                    title=SCRATCH_ROOT_TITLE,
                    mime="application/vnd.google-apps.folder",
                    drive_id=evidence["drive_id"], owner=document_owner,
                    logical_id=SCRATCH_ROOT_LOGICAL_ID,
                    parent_id=folder_id)
                    or type(capabilities) is not dict
                    or capabilities.get("canAddChildren") is not True):
                raise WritePreflightDenied("Project A scratch root drifted")
        document = _json_object(_bounded_get(
            session, f"{DRIVE_FILES}/{quote(document_id, safe='')}",
            params={"supportsAllDrives": "true", "fields": FIELDS},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        document_capabilities = document.get("capabilities")
        if (not _owned(document, item_id=document_id,
                       title=document_title,
                       mime="application/vnd.google-apps.document",
                       drive_id=evidence["drive_id"], owner=document_owner,
                       logical_id=document_logical_id,
                       parent_id=document_parent_id)
                or type(document_capabilities) is not dict
                or document_capabilities.get("canEdit") is not True):
            raise WritePreflightDenied("working Doc drifted or Jules cannot edit")
        docs = _json_object(_bounded_get(
            session, f"{DOCS_DOCUMENTS}/{quote(document_id, safe='')}",
            params={"includeTabsContent": "true"},
            maximum=MAX_DOCS_BYTES, media_type="application/json",
        ))
        tabs, revision = docs.get("tabs"), docs.get("revisionId")
        tab_properties = (
            tabs[0].get("tabProperties")
            if type(tabs) is list and len(tabs) == 1 and type(tabs[0]) is dict
            else None
        )
        if (docs.get("documentId") != document_id or type(tabs) is not list
                or len(tabs) != 1 or type(tabs[0]) is not dict
                or type(tab_properties) is not dict
                or tab_properties.get("tabId") != tab_id
                or type(revision) is not str or not 0 < len(revision) <= 128):
            raise WritePreflightDenied("working Doc tab or revision drifted")
        body = _bounded_get(
            session, f"{DRIVE_FILES}/{quote(document_id, safe='')}/export",
            params={"mimeType": "text/plain"},
            maximum=MAX_EXPORT_BYTES, media_type="text/plain",
        )
        if (len(body) != baseline_byte_count
                or hashlib.sha256(body).hexdigest() != baseline_sha256
                or body.count(marker.encode("utf-8")) != 1):
            raise WritePreflightDenied("working Doc baseline or marker drifted")
        return WritePreflight(
            document_id, tab_id, revision,
            baseline_sha256, len(body), 1, now,
        )
    finally:
        session.close()
