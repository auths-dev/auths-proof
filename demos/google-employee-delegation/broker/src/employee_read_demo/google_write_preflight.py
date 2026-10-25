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
from .write_handoff import validate_write_handoff


MAX_METADATA_BYTES = 32_768
MAX_DOCS_BYTES = 131_072
MAX_EXPORT_BYTES = 16_384
DRIVE_FILES = "https://www.googleapis.com/drive/v3/files"
DOCS_DOCUMENTS = "https://docs.googleapis.com/v1/documents"
FIELDS = "id,name,mimeType,parents,driveId,appProperties,capabilities(canAddChildren,canEdit)"
FOLDER_LOGICAL_ID = "ap071-project-a-folder"
DOCUMENT_LOGICAL_ID = "ap071-project-a-working-doc"


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
                         now: int | None = None) -> WritePreflight:
    """Check exact run-owned IDs, Jules ACL, current revision and baseline."""
    now = int(time.time()) if now is None else now
    evidence = validate_write_handoff(evidence_path, pins.producer)
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
        folder_id, document_id = evidence["folder_id"], evidence["document_id"]
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
        document = _json_object(_bounded_get(
            session, f"{DRIVE_FILES}/{quote(document_id, safe='')}",
            params={"supportsAllDrives": "true", "fields": FIELDS},
            maximum=MAX_METADATA_BYTES, media_type="application/json",
        ))
        document_capabilities = document.get("capabilities")
        if (not _owned(document, item_id=document_id,
                       title=evidence["document_title"],
                       mime="application/vnd.google-apps.document",
                       drive_id=evidence["drive_id"], owner=owner,
                       logical_id=DOCUMENT_LOGICAL_ID, parent_id=folder_id)
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
                or tab_properties.get("tabId") != evidence["tab_id"]
                or type(revision) is not str or not 0 < len(revision) <= 128):
            raise WritePreflightDenied("working Doc tab or revision drifted")
        body = _bounded_get(
            session, f"{DRIVE_FILES}/{quote(document_id, safe='')}/export",
            params={"mimeType": "text/plain"},
            maximum=MAX_EXPORT_BYTES, media_type="text/plain",
        )
        if (len(body) != evidence["baseline_byte_count"]
                or hashlib.sha256(body).hexdigest() != evidence["baseline_sha256"]
                or body.count(evidence["marker"].encode("utf-8")) != 1):
            raise WritePreflightDenied("working Doc baseline or marker drifted")
        return WritePreflight(
            document_id, evidence["tab_id"], revision,
            evidence["baseline_sha256"], len(body), 1, now,
        )
    finally:
        session.close()
