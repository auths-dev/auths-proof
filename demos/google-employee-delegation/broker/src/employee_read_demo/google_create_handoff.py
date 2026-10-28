"""Pinned, read-only consumer of demo_co's new-child observation.

The producer reports provider state only. This shim does not turn a public
marker or an operator-supplied child ID into Auths task authority, and it
never performs a create, populate or cleanup request.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Mapping
from urllib.parse import quote, urlencode

from .timestamps import parse_aware_timestamp
from .demo_co_contract import ContractRejected, _load

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MARKER = re.compile(r"ap071_[0-9a-f]{32}\Z")
DRIVE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
CHILD_TITLE = "Auths AP-071 Project A handoff"
CHILD_MIME_TYPE = "application/vnd.google-apps.document"
CHILD_FIELDS = "id,name,mimeType,parents,driveId,properties,trashed,createdTime"
RECOVERY_FIELDS = "nextPageToken,incompleteSearch,files(" + CHILD_FIELDS + ")"
MAX_RECOVERY_PAGES = 4
MAX_RECOVERY_RESULTS = 100


def prepare_create_inputs(parent_id: str, *, pinned_folder_id: str) -> dict[str, str]:
    """Choose the first-run title and fresh marker before human review.

    The caller must still put these values in the signed agent action and
    exact human confirmation. This function confers no provider authority.
    """
    if (type(parent_id) is not str or type(pinned_folder_id) is not str
            or not parent_id or parent_id != pinned_folder_id
            or len(parent_id) > 64 or any(character.isspace() for character in parent_id)):
        raise ContractRejected("create parent differs from the pinned Project A folder")
    return {
        "parent_id": parent_id,
        "title": CHILD_TITLE,
        "recovery_marker": "ap071_" + secrets.token_hex(16),
    }


@dataclass(frozen=True)
class CreatedChildMetadataPins:
    """Exact signed create fields and operator-pinned shared Drive context.

    The candidate ID must come from the durable Auths attempt journal. These
    pins alone cannot attribute creation to an agent or authorize population.
    """

    candidate_id: str
    parent_id: str
    drive_id: str
    title: str
    marker_value: str

    def validate(self) -> None:
        if (not all(type(value) is str and DRIVE_ID.fullmatch(value)
                    for value in (self.candidate_id, self.parent_id, self.drive_id))
                or type(self.title) is not str or self.title != CHILD_TITLE
                or type(self.marker_value) is not str
                or MARKER.fullmatch(self.marker_value) is None):
            raise ContractRejected("created-child metadata pins are invalid")


@dataclass(frozen=True)
class CreatedChildContinuationTarget:
    """Operator-pinned target for a new, exact-confirmation edit task.

    This pin does not extend an expired create plan. The new task and exact
    confirmation must be signed separately, and Jules must freshly observe
    the blank child before entry.
    """

    child: CreatedChildMetadataPins
    text_sha256: str
    text_bytes: int

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "CreatedChildContinuationTarget":
        if (type(document) is not dict
                or set(document) != {"schema", "child_id", "parent_id",
                                     "drive_id", "title", "marker_value",
                                     "text_sha256", "text_bytes"}
                or document["schema"] != "auths.ap071-created-child-continuation/1"
                or type(document["text_sha256"]) is not str
                or HEX64.fullmatch(document["text_sha256"]) is None
                or type(document["text_bytes"]) is not int
                or not 1 <= document["text_bytes"] <= 192):
            raise ContractRejected("created-child continuation pin is invalid")
        child = CreatedChildMetadataPins(
            candidate_id=document["child_id"],
            parent_id=document["parent_id"],
            drive_id=document["drive_id"],
            title=document["title"],
            marker_value=document["marker_value"],
        )
        child.validate()
        return cls(child, document["text_sha256"], document["text_bytes"])

    def require_exact_action(self, arguments: Mapping[str, object], *,
                             child_id: str, tab_id: str,
                             revision_id: str) -> None:
        """Match the staged agent action to the fresh Jules child read."""
        text = arguments.get("text")
        if (arguments.get("document_id") != self.child.candidate_id
                or arguments.get("document_id") != child_id
                or arguments.get("tab_id") != tab_id
                or arguments.get("required_revision_id") != revision_id
                or type(text) is not str
                or len(text.encode("utf-8")) != self.text_bytes
                or hashlib.sha256(text.encode("utf-8")).hexdigest()
                != self.text_sha256):
            raise ContractRejected("agent population differs from fresh Jules preflight")


def created_child_metadata_url(pins: CreatedChildMetadataPins) -> str:
    """Build the fixed Google metadata GET for the response-derived child."""
    pins.validate()
    return ("https://www.googleapis.com/drive/v3/files/"
            + quote(pins.candidate_id, safe="")
            + "?supportsAllDrives=true&fields=" + quote(CHILD_FIELDS, safe=","))


def validate_created_child_metadata(metadata: Mapping[str, object],
                                    pins: CreatedChildMetadataPins) -> datetime:
    """Check a bounded files.get result as a test-only Google vertical oracle.

    The caller must separately pin the OAuth UserInfo subject, task action,
    response journal, and connection generation. A matching public marker is
    never child permission. The returned aware timestamp is correlation only.
    """
    pins.validate()
    if (not isinstance(metadata, Mapping)
            or metadata.get("id") != pins.candidate_id
            or metadata.get("name") != pins.title
            or metadata.get("mimeType") != CHILD_MIME_TYPE
            or metadata.get("parents") != [pins.parent_id]
            or metadata.get("driveId") != pins.drive_id
            or metadata.get("trashed") is not False
            or not isinstance(metadata.get("properties"), dict)
            or metadata["properties"].get("auths_operation_marker") != pins.marker_value):
        raise ContractRejected("created-child metadata differs from signed and operator pins")
    try:
        timestamp = metadata["createdTime"]
        if type(timestamp) is not str or len(timestamp) > 40:
            raise ValueError("invalid timestamp shape")
        created = parse_aware_timestamp(timestamp)
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("created-child creation time is invalid") from error
    if created.tzinfo is None or created.utcoffset() is None:
        raise ContractRejected("created-child creation time has no timezone")
    return created


class CreateRecoverySearch:
    """Read-only, bounded marker search; a result is never child authority.

    The caller owns the Jules credential and must send each URL it receives
    through that same subject-bound broker. Only a separately signed Auths
    recovery action may promote a single candidate to a task binding.
    """

    def __init__(self, *, parent_id: str, drive_id: str, marker_value: str):
        pins = CreatedChildMetadataPins(
            candidate_id="placeholder", parent_id=parent_id, drive_id=drive_id,
            title=CHILD_TITLE, marker_value=marker_value,
        )
        pins.validate()
        self._pins = pins
        self._pages = 0
        self._results = 0
        self._seen_tokens: set[str] = set()
        self._next_token: str | None = None
        self._candidates: set[str] = set()
        self._complete = False

    def next_url(self) -> str:
        if self._complete or self._pages >= MAX_RECOVERY_PAGES:
            raise ContractRejected("recovery search is complete or exceeded its page cap")
        query = (f"'{self._pins.parent_id}' in parents and "
                 "properties has { key='auths_operation_marker' and "
                 f"value='{self._pins.marker_value}' }} and trashed = false")
        params = {
            "q": query, "corpora": "drive", "driveId": self._pins.drive_id,
            "includeItemsFromAllDrives": "true", "supportsAllDrives": "true",
            "pageSize": str(MAX_RECOVERY_RESULTS), "fields": RECOVERY_FIELDS,
        }
        if self._next_token is not None:
            params["pageToken"] = self._next_token
        return "https://www.googleapis.com/drive/v3/files?" + urlencode(params)

    @property
    def complete(self) -> bool:
        return self._complete

    @property
    def candidate_count(self) -> int:
        if not self._complete:
            raise ContractRejected("recovery search is incomplete")
        return len(self._candidates)

    @property
    def page_count(self) -> int:
        if not self._complete:
            raise ContractRejected("recovery search is incomplete")
        return self._pages

    def accept_page(self, document: Mapping[str, object]) -> None:
        if self._complete or self._pages >= MAX_RECOVERY_PAGES:
            raise ContractRejected("recovery search cannot accept another page")
        if (not isinstance(document, Mapping)
                or document.get("incompleteSearch") is not False
                or type(document.get("files")) is not list):
            raise ContractRejected("recovery search page is incomplete or malformed")
        files = document["files"]
        if len(files) > MAX_RECOVERY_RESULTS or self._results + len(files) > MAX_RECOVERY_RESULTS:
            raise ContractRejected("recovery search exceeded its result cap")
        candidates = set(self._candidates)
        for item in files:
            if type(item) is not dict:
                raise ContractRejected("recovery search item is malformed")
            candidate_id = item.get("id")
            pins = CreatedChildMetadataPins(
                candidate_id=candidate_id, parent_id=self._pins.parent_id,
                drive_id=self._pins.drive_id, title=CHILD_TITLE,
                marker_value=self._pins.marker_value,
            )
            validate_created_child_metadata(item, pins)
            if candidate_id in candidates:
                raise ContractRejected("recovery search repeated a child ID")
            candidates.add(candidate_id)
        token = document.get("nextPageToken")
        if token is not None and (type(token) is not str or not 1 <= len(token) <= 512
                                  or not token.isascii() or any(ord(c) < 33 for c in token)
                                  or token in self._seen_tokens):
            raise ContractRejected("recovery search continuation is invalid")
        if token is not None and self._pages + 1 >= MAX_RECOVERY_PAGES:
            raise ContractRejected("recovery search did not finish within the page cap")
        self._candidates = candidates
        self._results += len(files)
        self._pages += 1
        if token is None:
            self._complete = True
        else:
            self._seen_tokens.add(token)
            self._next_token = token

    def single_candidate(self) -> str | None:
        if not self._complete:
            raise ContractRejected("recovery search is incomplete")
        return next(iter(self._candidates)) if len(self._candidates) == 1 else None


@dataclass(frozen=True)
class JulesChildDocsRevision:
    """Opaque values from Jules's fresh Docs GET, never a producer-admin read."""

    revision_id: str
    tab_id: str


def created_child_docs_url(pins: CreatedChildMetadataPins) -> str:
    """Build the fixed Jules-subject Docs read before population."""
    pins.validate()
    return ("https://docs.googleapis.com/v1/documents/"
            + quote(pins.candidate_id, safe="") + "?includeTabsContent=true")


def created_child_edit_access_url(pins: CreatedChildMetadataPins) -> str:
    """Build a fresh Jules-subject Drive capability read for that child."""
    pins.validate()
    return ("https://www.googleapis.com/drive/v3/files/"
            + quote(pins.candidate_id, safe="")
            + "?supportsAllDrives=true&fields=id,parents,capabilities(canEdit)")


def validate_created_child_docs_read(document: Mapping[str, object],
                                     pins: CreatedChildMetadataPins) -> JulesChildDocsRevision:
    """Extract only one bounded revision and tab from Jules's fresh Docs GET.

    The caller must verify the leased OAuth subject separately and obtain the
    bytes through the credential-owning broker. This parser confers no write.
    """
    pins.validate()
    if (not isinstance(document, Mapping)
            or document.get("documentId") != pins.candidate_id
            or type(document.get("revisionId")) is not str
            or not 1 <= len(document["revisionId"].encode()) <= 128
            or any(ord(character) < 33 for character in document["revisionId"])):
        raise ContractRejected("created-child Docs revision differs from Jules read pins")
    tabs = document.get("tabs")
    if (type(tabs) is not list or len(tabs) != 1
            or type(tabs[0]) is not dict
            or tabs[0].get("childTabs", []) != []
            or type(tabs[0].get("tabProperties")) is not dict
            or type(tabs[0].get("documentTab")) is not dict):
        raise ContractRejected("created-child Docs tab structure is unsupported")
    tab_id = tabs[0]["tabProperties"].get("tabId")
    if (type(tab_id) is not str or not 1 <= len(tab_id.encode()) <= 64
            or any(ord(character) < 33 for character in tab_id)):
        raise ContractRejected("created-child Docs tab ID is invalid")
    _require_blank_single_tab(tabs[0]["documentTab"])
    return JulesChildDocsRevision(document["revisionId"], tab_id)


def _require_blank_single_tab(document_tab: Mapping[str, object]) -> None:
    """Fail closed unless the fresh body ends in one newline-only paragraph.

    The first live child showed a leading section break and a newline-only
    paragraph. Compare the response's own indexes and reject other layouts;
    no numeric insertion offset is assumed or sent by the recipe.
    """
    body = document_tab.get("body")
    if type(body) is not dict or type(body.get("content")) is not list:
        raise ContractRejected("created-child Docs body is unavailable")
    content = body["content"]
    if len(content) == 2:
        section = content[0]
        if (type(section) is not dict
                or set(section) != {"endIndex", "sectionBreak"}
                or section["endIndex"] != 1
                or type(section["sectionBreak"]) is not dict
                or set(section["sectionBreak"]) != {"sectionStyle"}
                or type(section["sectionBreak"]["sectionStyle"]) is not dict
                or set(section["sectionBreak"]["sectionStyle"]) != {
                    "columnSeparatorStyle", "contentDirection", "sectionType"
                }):
            raise ContractRejected("created-child Doc has unsupported section break")
        paragraph_element = content[1]
    elif len(content) == 1:
        paragraph_element = content[0]
    else:
        raise ContractRejected("created-child Doc is not a blank single paragraph")
    if type(paragraph_element) is not dict:
        raise ContractRejected("created-child Doc has unsupported body elements")
    paragraph = paragraph_element.get("paragraph")
    if (type(paragraph) is not dict
            or any(key not in {"startIndex", "endIndex", "paragraph"}
                   for key in paragraph_element)
            or any(key not in {"elements", "paragraphStyle"} for key in paragraph)
            or type(paragraph.get("elements")) is not list
            or len(paragraph["elements"]) != 1):
        raise ContractRejected("created-child Doc has unsupported body elements")
    run = paragraph["elements"][0]
    if (type(run) is not dict
            or any(key not in {"startIndex", "endIndex", "textRun"} for key in run)
            or type(run.get("textRun")) is not dict
            or run["textRun"].get("content") != "\n"):
        raise ContractRejected("created-child Doc already has content")
    start, end = paragraph_element.get("startIndex"), paragraph_element.get("endIndex")
    run_start, run_end = run.get("startIndex"), run.get("endIndex")
    if (type(start) is not int or type(end) is not int
            or type(run_start) is not int or type(run_end) is not int
            or start < 0 or end != start + 1
            or run_start != start or run_end != end):
        raise ContractRejected("created-child Docs indexes are inconsistent")


def validate_created_child_edit_access(metadata: Mapping[str, object],
                                       pins: CreatedChildMetadataPins) -> None:
    """Require a fresh exact-child `canEdit` observation under Jules's lease."""
    pins.validate()
    if (not isinstance(metadata, Mapping)
            or metadata.get("id") != pins.candidate_id
            or metadata.get("parents") != [pins.parent_id]
            or type(metadata.get("capabilities")) is not dict
            or metadata["capabilities"].get("canEdit") is not True):
        raise ContractRejected("Jules cannot edit the pinned created child")


@dataclass(frozen=True)
class CreateObservationPins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    source_verification_sha256: str
    working_baseline_generation: int
    working_baseline_sha256: str
    drive_id: str
    folder_id: str
    child_id: str
    marker_value: str
    expected_content_sha256: str
    expected_content_byte_count: int
    observation_sha256: str

    def validate(self) -> None:
        hashes = (self.definition_hash, self.source_verification_sha256,
                  self.working_baseline_sha256, self.expected_content_sha256,
                  self.observation_sha256)
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.drive_id, self.folder_id, self.child_id)
        if (not all(type(value) is str and HEX64.fullmatch(value) for value in hashes)
                or not all(type(value) is str and 1 <= len(value) <= 256
                           and not any(character.isspace() for character in value)
                           for value in labels)
                or type(self.working_baseline_generation) is not int
                or self.working_baseline_generation < 2
                or type(self.expected_content_byte_count) is not int
                or not 0 < self.expected_content_byte_count <= 100_000
                or type(self.marker_value) is not str
                or MARKER.fullmatch(self.marker_value) is None):
            raise ContractRejected("create observation operator pins are invalid")


@dataclass(frozen=True)
class CreateObservationStatus:
    contract: str
    status: str
    attribution: str
    observation_sha256: str | None = None
    reason: str | None = None


def validate_create_observation(export: Path, pins: CreateObservationPins) -> None:
    """Check one exact producer observation against private Auths run pins.

    This checks observed content and isolation. The separate Auths task
    journal may bind the response-derived child; this export does not verify
    that binding or infer agent attribution.
    """
    pins.validate()
    observation, raw = _load(export, "google-create-observation-v1.schema.json")
    if hashlib.sha256(raw).hexdigest() != pins.observation_sha256:
        raise ContractRejected("create observation digest disagrees with operator pin")
    if (observation["schema_version"] != "demo-co/google-create-observation/v1"
            or observation["status"] != "ready"
            or observation["attribution"] != "provider_state_only"):
        raise ContractRejected("create observation has unsupported provenance")
    expected = {
        "company": pins.company,
        "instance": pins.instance,
        "definition_hash": pins.definition_hash,
        "customer_id": pins.customer_id,
        "jules_subject": pins.jules_subject,
        "source_verification_sha256": pins.source_verification_sha256,
        "working_baseline_generation": pins.working_baseline_generation,
        "working_baseline_sha256": pins.working_baseline_sha256,
        "drive_id": pins.drive_id,
        "folder_id": pins.folder_id,
        "child_id": pins.child_id,
        "child_title": CHILD_TITLE,
        "marker_key": "auths_operation_marker",
        "marker_value": pins.marker_value,
        "content_sha256": pins.expected_content_sha256,
        "content_byte_count": pins.expected_content_byte_count,
    }
    if any(observation.get(name) != value for name, value in expected.items()):
        raise ContractRejected("create observation disagrees with Auths run pins")
    if not all(observation.get(name) is True for name in (
            "child_parent_exact", "canonical_project_a_unchanged",
            "canonical_project_b_unchanged", "working_document_matches_expected",
            "jules_project_b_write_denied")):
        raise ContractRejected("create observation lacks independent isolation checks")
    if observation.get("marker_match_count") != 1 or observation.get("direct_child_count") != 3:
        raise ContractRejected("create observation has ambiguous child inventory")
    try:
        baseline = parse_aware_timestamp(observation["working_baseline_observed_at"])
        created = parse_aware_timestamp(observation["child_created_at"])
        observed = parse_aware_timestamp(observation["observed_at"])
    except (TypeError, ValueError) as error:
        raise ContractRejected("create observation has invalid times") from error
    if (any(value.tzinfo is None for value in (baseline, created, observed))
            or not baseline <= created <= observed
            or created - baseline > timedelta(minutes=5)):
        raise ContractRejected("create observation is outside the pinned run window")


def inspect_create_observation(export: Path | None = None,
                               pins: CreateObservationPins | None = None,
                               ) -> CreateObservationStatus:
    """Expose a redacted handoff result without claiming Auths attribution."""
    if export is None or pins is None:
        return CreateObservationStatus(
            "auths.demo-co-google-create-handoff-status/v1", "not_configured",
            "unproven", reason="producer observation and run pins are both required",
        )
    try:
        validate_create_observation(export, pins)
    except (ContractRejected, OSError, ValueError) as error:
        return CreateObservationStatus(
            "auths.demo-co-google-create-handoff-status/v1", "producer_rejected",
            "unproven", reason=str(error),
        )
    return CreateObservationStatus(
        "auths.demo-co-google-create-handoff-status/v1", "provider_state_observed",
        "provider_state_only", observation_sha256=pins.observation_sha256,
        reason="Auths task and create-response child binding have not been proved",
    )
