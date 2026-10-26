"""Strict Auths consumer for demo_co's forward-only population observation.

The producer observes Google state. This module grants no task authority and
does not infer provider entry from the observed content. The gateway journal
and the signed Jules/agent actions must be joined separately.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from .demo_co_contract import ContractRejected, _load
from .google_create_handoff import CHILD_TITLE
from .google_create_v4_handoff import CreateV4FinalPins
from .google_populate_failure_handoff import (
    BLANK_SCHEMA, BLANK_SCHEMA_SHA256, BLANK_SHA256, HEX64,
    SETUP_SCHEMA, _identifier, _pinned_observation, _timestamp,
    validate_populate_precreate_baseline,
)


INVENTORY_SCHEMA = "google-populate-provider-inventory-v1.schema.json"
INVENTORY_SCHEMA_SHA256 = (
    "bf175a3779551d1855e83824794d3c41385c90ed3997e8ff1f0a5e2462169c81"
)
FINAL_SCHEMA = "google-populate-provider-final-v2.schema.json"
FINAL_SCHEMA_SHA256 = (
    "f739432461d11e0872222e837a2a62393595c193b7d4a4305559a3c2745eb237"
)
DOCUMENT_MIME = "application/vnd.google-apps.document"
FOLDER_MIME = "application/vnd.google-apps.folder"


@dataclass(frozen=True)
class ProviderV2SourcePins:
    document_id: str
    raw_sha256: str
    raw_byte_count: int

    def validate(self) -> None:
        if (not _identifier(self.document_id)
                or type(self.raw_sha256) is not str
                or HEX64.fullmatch(self.raw_sha256) is None
                or type(self.raw_byte_count) is not int
                or not 1 <= self.raw_byte_count <= 100_000):
            raise ContractRejected("provider v2 source pin is invalid")


def _checked_inventory(pins: list[dict], root: str, run_folder: str,
                       expected_count: int) -> None:
    if (type(pins) is not list or not 1 <= len(pins) <= 128
            or any(type(item) is not dict for item in pins)
            or len({item.get("file_id") for item in pins}) != len(pins)
            or pins != sorted(pins, key=lambda item: (
                item.get("parent_id", ""), item.get("file_id", "")))
            or sum(item.get("parent_id") == root for item in pins)
                != expected_count
            or any(item.get("parent_id") == run_folder for item in pins)):
        raise ContractRejected("provider v2 sibling inventory is invalid")
    found_run_folder = False
    for item in pins:
        if (not _identifier(item.get("file_id"))
                or not _identifier(item.get("parent_id"))
                or type(item.get("name")) is not str
                or not item["name"]
                or item.get("mime_type") not in (DOCUMENT_MIME, FOLDER_MIME)):
            raise ContractRejected("provider v2 sibling pin is invalid")
        if item["file_id"] == run_folder:
            found_run_folder = (
                item["parent_id"] == root
                and item["mime_type"] == FOLDER_MIME
            )
        values = (item.get("raw_sha256"), item.get("raw_byte_count"),
                  item.get("revision_id"))
        if item["mime_type"] == FOLDER_MIME:
            if any(value is not None for value in values):
                raise ContractRejected("folder pin carries document content")
        elif (type(values[0]) is not str
              or HEX64.fullmatch(values[0]) is None
              or type(values[1]) is not int
              or not 0 <= values[1] <= 100_000
              or not _identifier(values[2])):
            raise ContractRejected("document pin lacks complete content")
    if not found_run_folder:
        raise ContractRejected("provider v2 run folder is absent")
    root_folders = {
        item["file_id"] for item in pins
        if item["parent_id"] == root and item["mime_type"] == FOLDER_MIME
    }
    if any(item["parent_id"] != root
           and (item["parent_id"] not in root_folders
                or item["mime_type"] != DOCUMENT_MIME)
           for item in pins):
        raise ContractRejected("provider v2 nested sibling is outside inventory")


def validate_populate_provider_final_v2(
    source_v4_paths: tuple[Path, Path, Path],
    setup_path: Path, setup_sha256: str,
    inventory_path: Path, inventory_sha256: str,
    precreate_path: Path, precreate_sha256: str,
    blank_path: Path, blank_sha256: str,
    final_path: Path, final_sha256: str,
    v4: CreateV4FinalPins, *, expected_text: str,
    source: ProviderV2SourcePins,
) -> dict:
    """Accept one exact Google after-state tied to immutable producer pins.

    A `still_blank` or `unexpected_state` report is evidence of provider state,
    but cannot qualify the approved population and is rejected here. Neither
    report authorizes a retry after possible provider entry.
    """
    source.validate()
    if (type(expected_text) is not str
            or not 1 <= len(expected_text.encode("utf-8")) <= 16_384):
        raise ContractRejected("approved population text is unavailable")
    expected_raw = b"\xef\xbb\xbf" + expected_text.encode("utf-8")
    expected_sha256 = hashlib.sha256(expected_raw).hexdigest()
    inventory_generation, inventory = _pinned_observation(
        inventory_path, inventory_sha256,
        "google-populate-provider-inventory.json",
        INVENTORY_SCHEMA, INVENTORY_SCHEMA_SHA256,
    )
    blank_generation, blank = _pinned_observation(
        blank_path, blank_sha256, "google-populate-blank-baseline.json",
        BLANK_SCHEMA, BLANK_SCHEMA_SHA256,
    )
    target, precreate_generation, precreate = validate_populate_precreate_baseline(
        *source_v4_paths, setup_path, setup_sha256,
        precreate_path, precreate_sha256, v4,
        now=int(_timestamp(blank.get("observed_at")).timestamp()),
    )
    final_generation, final = _pinned_observation(
        final_path, final_sha256, "google-populate-provider-final-v2.json",
        FINAL_SCHEMA, FINAL_SCHEMA_SHA256,
    )
    setup, _ = _load(setup_path, SETUP_SCHEMA)
    v4_source = v4.candidate.baseline
    common = {
        "company": v4_source.company,
        "instance": v4_source.instance,
        "definition_hash": v4_source.definition_hash,
        "drive_id": v4_source.drive_id,
        "project_a_folder_id": v4_source.folder_id,
        "scratch_root_id": setup["scratch_root_id"],
        "run_folder_id": target.parent_id,
        "run_id": target.run_id,
        "marker": target.marker,
    }
    if (not target.setup_generation < inventory_generation
            < precreate_generation < blank_generation < final_generation
            or any(any(document.get(key) != value
                       for key, value in common.items())
                   for document in (inventory, final))
            or inventory.get("schema_version")
                != "demo-co/google-populate-provider-inventory/v1"
            or inventory.get("status") != "ready"
            or inventory.get("attribution") != "provider_state_only"
            or inventory.get("setup_generation") != target.setup_generation
            or inventory.get("setup_sha256") != target.setup_sha256
            or inventory.get("run_folder_empty") is not True
            or inventory.get("source_jules_export_matches_admin") is not True
            or inventory.get("source_document_id") != source.document_id
            or inventory.get("source_raw_sha256") != source.raw_sha256
            or inventory.get("source_raw_byte_count") != source.raw_byte_count
            or type(inventory.get("scratch_root_child_count")) is not int
            or not 1 <= inventory["scratch_root_child_count"] <= 64
            or any(inventory.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))):
        raise ContractRejected("provider v2 inventory differs from run pins")
    _checked_inventory(inventory.get("sibling_pins"),
                       common["scratch_root_id"], target.parent_id,
                       inventory["scratch_root_child_count"])
    child = blank.get("child_id")
    if (not _identifier(child)
            or blank.get("schema_version")
                != "demo-co/google-populate-blank-baseline/v1"
            or blank.get("status") != "ready"
            or blank.get("attribution") != "provider_state_only"
            or blank.get("company") != v4_source.company
            or blank.get("instance") != v4_source.instance
            or blank.get("definition_hash") != v4_source.definition_hash
            or blank.get("drive_id") != v4_source.drive_id
            or blank.get("run_id") != target.run_id
            or blank.get("run_folder_id") != target.parent_id
            or blank.get("marker") != target.marker
            or blank.get("setup_generation") != target.setup_generation
            or blank.get("setup_sha256") != target.setup_sha256
            or blank.get("child_title") != CHILD_TITLE
            or blank.get("project_a_direct_child_count") != 8
            or blank.get("marker_match_count") != 1
            or blank.get("run_child_count") != 1
            or blank.get("raw_byte_count") != 3
            or blank.get("raw_sha256") != BLANK_SHA256
            or not _identifier(blank.get("tab_id"))
            or not _identifier(blank.get("admin_revision_id"))
            or any(blank.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))):
        raise ContractRejected("provider v2 blank child differs from run pins")
    if (final.get("schema_version")
            != "demo-co/google-populate-provider-final/v2"
            or final.get("status") != "exact_populated"
            or final.get("attribution") != "provider_state_only"
            or final.get("inventory_generation") != inventory_generation
            or final.get("inventory_sha256") != inventory_sha256
            or final.get("blank_baseline_generation") != blank_generation
            or final.get("blank_baseline_sha256") != blank_sha256
            or final.get("child_id") != child
            or final.get("child_created_at") != blank.get("child_created_at")
            or final.get("tab_id") != blank.get("tab_id")
            or final.get("blank_admin_revision_id")
                != blank.get("admin_revision_id")
            or not _identifier(final.get("observed_admin_revision_id"))
            or final["observed_admin_revision_id"]
                == blank["admin_revision_id"]
            or final.get("revision_changed") is not True
            or final.get("blank_raw_sha256") != BLANK_SHA256
            or final.get("observed_raw_sha256") != expected_sha256
            or final.get("expected_raw_sha256") != expected_sha256
            or final.get("observed_raw_byte_count") != len(expected_raw)
            or final.get("expected_raw_byte_count") != len(expected_raw)
            or final.get("exact_expected_content") is not True
            or final.get("still_exactly_blank") is not False
            or final.get("run_marker_occurrences_in_content") != 0
            or final.get("provider_match_count") != 1
            or final.get("run_child_count") != 1
            or final.get("scratch_root_child_count")
                != inventory["scratch_root_child_count"]
            or final.get("exact_sibling_inventory_unchanged") is not True
            or final.get("source_document_id") != source.document_id
            or final.get("source_raw_sha256") != source.raw_sha256
            or final.get("source_raw_byte_count") != source.raw_byte_count
            or final.get("source_unchanged") is not True
            or any(final.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))
            or final.get("provider_entry_attested") is not False
            or final.get("retry_authorized") is not False):
        raise ContractRejected("provider v2 final differs from approved run")
    setup_time = _timestamp(setup.get("observed_at"))
    inventory_time = _timestamp(inventory.get("observed_at"))
    precreate_time = _timestamp(precreate.get("observed_at"))
    created_time = _timestamp(blank.get("child_created_at"))
    blank_time = _timestamp(blank.get("observed_at"))
    final_time = _timestamp(final.get("observed_at"))
    if (not setup_time <= inventory_time <= precreate_time <= created_time
            <= blank_time < final_time
            or created_time - precreate_time > timedelta(minutes=5)):
        raise ContractRejected("provider v2 observation order changed")
    return {
        "schema": "auths.ap071-populate-provider-final-join/1",
        "authority": "provider_state_only",
        "status": "exact_populated",
        "retry_authorized": False,
        "company_id": v4_source.company,
        "jules_subject": v4_source.jules_subject,
        "run_id": target.run_id,
        "run_folder_id": target.parent_id,
        "marker": target.marker,
        "child_id": child,
        "tab_id": blank["tab_id"],
        "source_document_id": source.document_id,
        "source_raw_byte_count": source.raw_byte_count,
        "setup_generation": target.setup_generation,
        "setup_sha256": target.setup_sha256,
        "inventory_generation": inventory_generation,
        "inventory_sha256": inventory_sha256,
        "precreate_generation": precreate_generation,
        "precreate_sha256": precreate_sha256,
        "precreate_observed_at": precreate["observed_at"],
        "blank_generation": blank_generation,
        "blank_sha256": blank_sha256,
        "final_generation": final_generation,
        "final_sha256": final_sha256,
        "content_matches": True,
        "expected_raw_sha256": expected_sha256,
        "expected_raw_byte_count": len(expected_raw),
    }
