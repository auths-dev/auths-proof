"""Pin demo_co's recovery-refusal provider observations without granting authority.

Auths must separately prove its gateway attempt, search fault, refusal, and
zero retry/populate counts. These producer artifacts describe Google state
only; even a single blank child here cannot authorize child binding.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib.resources import files
from pathlib import Path

from .timestamps import parse_aware_timestamp
from .demo_co_contract import ContractRejected, _load, _unique_pairs
from .google_create_handoff import CHILD_TITLE, MARKER
from .google_create_v4_handoff import (
    CreateV4BaselinePins, CreateV4CandidateBlankPins, CreateV4FinalPins,
    CreateV4NeighborPins, validate_create_v4_observation,
)


SCHEMAS = {
    "google-create-negative-setup-v1.schema.json":
        "a14239c644406c7f81abb22f73ef3122cc6549d1fdfb090932b3420d30c94989",
    "google-create-negative-baseline-v1.schema.json":
        "8686b9f1da161f044a47ac12a69bfc60f060226ffbc7ff0c0644a147936878e1",
    "google-create-recovery-negative-v1.schema.json":
        "51080b065d5b8b62b553d475cdf0322075a4bf55a7994ebed411c7c4cfca646c",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[a-z][a-z0-9-]{1,40}\Z")
GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
BLANK_SHA256 = "f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5"
COUNTS = {"zero": (0, 0), "multiple": (1, 2), "incomplete": (0, 1)}


@dataclass(frozen=True)
class NegativeCreateTarget:
    run_id: str
    case: str
    marker: str
    parent_id: str
    setup_generation: int
    setup_sha256: str


def load_v4_final_pins(path: Path) -> CreateV4FinalPins:
    if (path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or path.stat().st_size > 16_384):
        raise ContractRejected("private v4 final pins are unavailable")
    try:
        document = json.loads(path.read_bytes(), object_pairs_hook=_unique_pairs)
        candidate = document.pop("candidate")
        baseline = candidate.pop("baseline")
        neighbors = tuple(CreateV4NeighborPins(**item)
                          for item in baseline.pop("neighbors"))
        baseline["prior_markers"] = tuple(baseline["prior_markers"])
        result = CreateV4FinalPins(
            candidate=CreateV4CandidateBlankPins(
                baseline=CreateV4BaselinePins(neighbors=neighbors, **baseline),
                **candidate,
            ), **document,
        )
        result.validate()
        return result
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ContractRejected("private v4 final pins are invalid") from error


def validate_negative_create_setup(
    source_v4_baseline_path: Path,
    source_v4_candidate_path: Path,
    source_v4_final_path: Path,
    setup_path: Path,
    setup_sha256: str,
    v4: CreateV4FinalPins,
) -> NegativeCreateTarget:
    """Bind a test task to one versioned producer scratch folder and marker."""
    v4.validate()
    if type(setup_sha256) is not str or HEX64.fullmatch(setup_sha256) is None:
        raise ContractRejected("negative setup digest is invalid")
    validate_create_v4_observation(source_v4_baseline_path,
                                   source_v4_candidate_path,
                                   source_v4_final_path, v4)
    location = GENERATION.fullmatch(setup_path.parent.name)
    if location is None:
        raise ContractRejected("negative setup generation is invalid")
    setup = _checked(setup_path, "google-create-negative-setup.json",
                     int(location.group(1)), setup_sha256,
                     "google-create-negative-setup-v1.schema.json")
    source = v4.candidate.baseline
    if (setup.get("schema_version") != "demo-co/google-create-negative-setup/v1"
            or setup.get("status") != "ready"
            or setup.get("attribution") != "producer_setup_only"
            or setup.get("scratch_journal_company")
                != "atlas-studio-recovery-negative"
            or setup.get("company") != source.company
            or setup.get("instance") != source.instance
            or setup.get("definition_hash") != source.definition_hash
            or setup.get("drive_id") != source.drive_id
            or setup.get("project_a_folder_id") != source.folder_id
            or setup.get("jules_subject") != source.jules_subject
            or setup.get("source_v4_baseline_generation")
                != source.baseline_generation
            or setup.get("source_v4_baseline_sha256")
                != source.baseline_sha256
            or setup.get("source_v4_final_generation")
                != v4.observation_generation
            or setup.get("source_v4_final_sha256")
                != v4.observation_sha256
            or type(setup.get("run_id")) is not str
            or RUN_ID.fullmatch(setup["run_id"]) is None
            or setup.get("case") not in COUNTS
            or type(setup.get("marker")) is not str
            or MARKER.fullmatch(setup["marker"]) is None
            or type(setup.get("scratch_root_id")) is not str
            or type(setup.get("run_folder_id")) is not str
            or any(not 1 <= len(setup[key]) <= 256
                   or any(character.isspace() for character in setup[key])
                   for key in ("scratch_root_id", "run_folder_id"))
            or len({source.folder_id, setup["scratch_root_id"],
                    setup["run_folder_id"]}) != 3
            or (setup.get("seed_id") is None) != (setup["case"] != "multiple")
            or (setup.get("seed_id") is not None and (
                type(setup["seed_id"]) is not str
                or not 1 <= len(setup["seed_id"]) <= 256
                or any(character.isspace() for character in setup["seed_id"])))
            or setup["marker"] in (*source.prior_markers,
                                   v4.candidate.marker)):
        raise ContractRejected("negative setup differs from frozen v4 source")
    _timestamp(setup, "observed_at")
    return NegativeCreateTarget(setup["run_id"], setup["case"],
                                setup["marker"], setup["run_folder_id"],
                                int(location.group(1)), setup_sha256)


@dataclass(frozen=True)
class CreateNegativePins:
    v4: CreateV4FinalPins
    run_id: str
    case: str
    marker: str
    scratch_root_id: str
    run_folder_id: str
    seed_id: str | None
    setup_generation: int
    setup_sha256: str
    baseline_generation: int
    baseline_sha256: str
    observation_generation: int
    observation_sha256: str

    def validate(self) -> None:
        self.v4.validate()
        identifiers = (self.scratch_root_id, self.run_folder_id)
        if (type(self.run_id) is not str or RUN_ID.fullmatch(self.run_id) is None
                or type(self.case) is not str or self.case not in COUNTS
                or type(self.marker) is not str or MARKER.fullmatch(self.marker) is None
                or any(type(item) is not str or not 1 <= len(item) <= 256
                       or any(char.isspace() for char in item) for item in identifiers)
                or len(set(identifiers)) != 2
                or self.v4.candidate.baseline.folder_id in identifiers
                or (self.seed_id is None) != (self.case != "multiple")
                or (self.seed_id is not None and (
                    type(self.seed_id) is not str or not 1 <= len(self.seed_id) <= 256
                    or any(char.isspace() for char in self.seed_id)))
                or any(type(item) is not int for item in (
                    self.setup_generation, self.baseline_generation,
                    self.observation_generation))
                or not self.v4.observation_generation < self.setup_generation
                       < self.baseline_generation < self.observation_generation
                or any(type(item) is not str or HEX64.fullmatch(item) is None
                       for item in (self.setup_sha256, self.baseline_sha256,
                                    self.observation_sha256))):
            raise ContractRejected("negative recovery pins are invalid")


def validate_negative_precreate_baseline(
    source_v4_baseline_path: Path,
    source_v4_candidate_path: Path,
    source_v4_final_path: Path,
    setup_path: Path,
    setup_sha256: str,
    baseline_path: Path,
    baseline_sha256: str,
    v4: CreateV4FinalPins,
    *,
    now: int,
) -> tuple[NegativeCreateTarget, int, dict]:
    """Accept a recent producer baseline before the one signed create entry."""
    target = validate_negative_create_setup(
        source_v4_baseline_path, source_v4_candidate_path,
        source_v4_final_path, setup_path, setup_sha256, v4,
    )
    location = GENERATION.fullmatch(baseline_path.parent.name)
    if (location is None or type(baseline_sha256) is not str
            or HEX64.fullmatch(baseline_sha256) is None):
        raise ContractRejected("negative baseline pins are invalid")
    generation = int(location.group(1))
    if generation <= target.setup_generation:
        raise ContractRejected("negative baseline predates setup")
    baseline = _checked(
        baseline_path, "google-create-negative-baseline.json", generation,
        baseline_sha256, "google-create-negative-baseline-v1.schema.json",
    )
    source = v4.candidate.baseline
    if (baseline.get("schema_version")
            != "demo-co/google-create-negative-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("setup_generation") != target.setup_generation
            or baseline.get("setup_sha256") != target.setup_sha256
            or baseline.get("source_v4_baseline_generation")
                != source.baseline_generation
            or baseline.get("source_v4_baseline_sha256")
                != source.baseline_sha256
            or baseline.get("source_v4_final_generation")
                != v4.observation_generation
            or baseline.get("source_v4_final_sha256")
                != v4.observation_sha256
            or baseline.get("company") != source.company
            or baseline.get("instance") != source.instance
            or baseline.get("definition_hash") != source.definition_hash
            or baseline.get("drive_id") != source.drive_id
            or baseline.get("project_a_folder_id") != source.folder_id
            or baseline.get("run_id") != target.run_id
            or baseline.get("case") != target.case
            or baseline.get("marker") != target.marker
            or baseline.get("run_folder_id") != target.parent_id
            or baseline.get("project_a_direct_child_count") != 8
            or any(baseline.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))):
        raise ContractRejected("negative baseline differs from reviewed setup")
    setup = _checked(setup_path, "google-create-negative-setup.json",
                     target.setup_generation, setup_sha256,
                     "google-create-negative-setup-v1.schema.json")
    if (baseline.get("scratch_root_id") != setup["scratch_root_id"]
            or baseline.get("seed_id") != setup["seed_id"]):
        raise ContractRejected("negative baseline crossed setup inventory")
    baseline_time = _timestamp(baseline, "observed_at")
    if not _timestamp(setup, "observed_at") <= baseline_time:
        raise ContractRejected("negative baseline predates setup observation")
    age = datetime.fromtimestamp(now, tz=baseline_time.tzinfo) - baseline_time
    if not timedelta(0) <= age <= timedelta(minutes=5):
        raise ContractRejected("negative baseline is stale or future-dated")
    expected = COUNTS[target.case][0]
    matches = _matches(baseline, expected, seed=setup["seed_id"],
                       baseline_time=None, observed_time=baseline_time)
    if matches != ({setup["seed_id"]} if setup["seed_id"] else set()):
        raise ContractRejected("negative baseline marker inventory differs")
    return target, generation, baseline


def _timestamp(document: dict, field: str) -> datetime:
    try:
        result = parse_aware_timestamp(document[field])
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("negative producer time is invalid") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ContractRejected("negative producer time lacks timezone")
    return result


def _checked(path: Path, name: str, generation: int, digest: str,
             schema_name: str) -> dict:
    location = GENERATION.fullmatch(path.parent.name)
    if (path.name != name or location is None
            or int(location.group(1)) != generation
            or path.parent.is_symlink() or not path.parent.is_dir()
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
            or path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ContractRejected("negative artifact location differs from pins")
    schema = files("employee_read_demo").joinpath("schemas", schema_name).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMAS[schema_name]:
        raise ContractRejected("negative producer schema differs from reviewed bytes")
    document, raw = _load(path, schema_name)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractRejected("negative producer artifact differs from pin")
    return document


def _matches(document: dict, expected: int, *, seed: str | None,
             baseline_time: datetime | None, observed_time: datetime) -> set[str]:
    matches = document.get("matches")
    if (type(matches) is not list or len(matches) != expected
            or document.get("provider_match_count") != expected):
        raise ContractRejected("negative marker inventory differs from pins")
    identifiers: set[str] = set()
    for match in matches:
        if (type(match) is not dict or type(match.get("file_id")) is not str
                or not 1 <= len(match["file_id"]) <= 256
                or match["file_id"] in identifiers
                or match.get("title") != CHILD_TITLE
                or match.get("raw_byte_count") != 3
                or match.get("raw_sha256") != BLANK_SHA256):
            raise ContractRejected("negative marker match is not the blank Doc")
        created = _timestamp(match, "created_at")
        if created > observed_time:
            raise ContractRejected("negative marker match is future-dated")
        if baseline_time is not None:
            if match["file_id"] == seed:
                if created > baseline_time:
                    raise ContractRejected("negative setup seed postdates baseline")
            elif not baseline_time < created <= baseline_time + timedelta(minutes=5):
                raise ContractRejected("negative new child is outside attempt window")
        identifiers.add(match["file_id"])
    return identifiers


def validate_create_recovery_negative_observation(
    source_v4_baseline_path: Path,
    source_v4_candidate_path: Path,
    source_v4_final_path: Path,
    setup_path: Path,
    baseline_path: Path,
    observation_path: Path,
    pins: CreateNegativePins,
) -> dict:
    """Check all producer pins and return a provider-state-only verdict."""
    pins.validate()
    validate_create_v4_observation(source_v4_baseline_path,
                                   source_v4_candidate_path,
                                   source_v4_final_path, pins.v4)
    setup = _checked(setup_path, "google-create-negative-setup.json",
                     pins.setup_generation, pins.setup_sha256,
                     "google-create-negative-setup-v1.schema.json")
    baseline = _checked(baseline_path, "google-create-negative-baseline.json",
                        pins.baseline_generation, pins.baseline_sha256,
                        "google-create-negative-baseline-v1.schema.json")
    after = _checked(observation_path, "google-create-recovery-negative.json",
                     pins.observation_generation, pins.observation_sha256,
                     "google-create-recovery-negative-v1.schema.json")
    source = pins.v4.candidate.baseline
    common = {
        "company": source.company, "instance": source.instance,
        "definition_hash": source.definition_hash, "drive_id": source.drive_id,
        "project_a_folder_id": source.folder_id, "run_id": pins.run_id,
        "case": pins.case, "marker": pins.marker,
        "scratch_root_id": pins.scratch_root_id,
        "run_folder_id": pins.run_folder_id,
    }
    if any(any(doc.get(key) != value for key, value in common.items())
           for doc in (setup, baseline, after)):
        raise ContractRejected("negative artifacts crossed run identity")
    v4_common = {
        "source_v4_baseline_generation": source.baseline_generation,
        "source_v4_baseline_sha256": source.baseline_sha256,
        "source_v4_final_generation": pins.v4.observation_generation,
        "source_v4_final_sha256": pins.v4.observation_sha256,
    }
    if (setup.get("schema_version") != "demo-co/google-create-negative-setup/v1"
            or setup.get("status") != "ready"
            or setup.get("attribution") != "producer_setup_only"
            or setup.get("scratch_journal_company") != "atlas-studio-recovery-negative"
            or setup.get("jules_subject") != source.jules_subject
            or setup.get("seed_id") != pins.seed_id
            or any(setup.get(key) != value for key, value in v4_common.items())):
        raise ContractRejected("negative setup differs from frozen v4 source")
    before_count, after_count = COUNTS[pins.case]
    if (baseline.get("schema_version") != "demo-co/google-create-negative-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("setup_generation") != pins.setup_generation
            or baseline.get("setup_sha256") != pins.setup_sha256
            or baseline.get("seed_id") != pins.seed_id
            or any(baseline.get(key) != value for key, value in v4_common.items())
            or baseline.get("project_a_direct_child_count") != 8
            or any(baseline.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))):
        raise ContractRejected("negative baseline differs from setup")
    setup_time = _timestamp(setup, "observed_at")
    baseline_time = _timestamp(baseline, "observed_at")
    after_time = _timestamp(after, "observed_at")
    if not setup_time <= baseline_time <= after_time:
        raise ContractRejected("negative observation sequence is invalid")
    before_ids = _matches(baseline, before_count, seed=pins.seed_id,
                          baseline_time=None, observed_time=baseline_time)
    if before_ids != ({pins.seed_id} if pins.seed_id else set()):
        raise ContractRejected("negative baseline seed inventory differs")
    if (after.get("schema_version") != "demo-co/google-create-recovery-negative/v1"
            or after.get("status") != "observed_provider_state"
            or after.get("attribution") != "provider_state_only"
            or after.get("auths_search_or_refusal_attested") is not False
            or after.get("provider_search_complete") is not True
            or after.get("all_matches_blank") is not True
            or after.get("baseline_generation") != pins.baseline_generation
            or after.get("baseline_sha256") != pins.baseline_sha256
            or _timestamp(after, "baseline_observed_at") != baseline_time
            or after.get("setup_seed_id") != pins.seed_id
            or after.get("project_a_direct_child_count") != 8
            or any(after.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))):
        raise ContractRejected("negative after-state differs from baseline")
    after_ids = _matches(after, after_count, seed=pins.seed_id,
                         baseline_time=baseline_time, observed_time=after_time)
    new_ids = after_ids - before_ids
    if (not before_ids <= after_ids
            or after_ids & ({pins.v4.candidate.candidate_id} | {
                item.document_id for item in source.neighbors})
            or after.get("new_child_ids") != sorted(new_ids)
            or len(new_ids) != after_count - before_count):
        raise ContractRejected("negative new-child inventory differs")
    return {"case": pins.case, "run_id": pins.run_id,
            "provider_match_count": after_count,
            "new_child_ids": sorted(new_ids), "authority": "none",
            "auths_search_or_refusal_attested": False}
