"""The negative producer cannot turn ambiguous Google state into authority."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.google_create_handoff import CHILD_TITLE
from employee_read_demo.google_create_negative_handoff import (
    BLANK_SHA256, CreateNegativePins,
    validate_negative_create_setup,
    validate_negative_precreate_baseline,
    validate_create_recovery_negative_observation,
)
from employee_read_demo.google_create_v4_handoff import (
    CreateV4BaselinePins, CreateV4CandidateBlankPins, CreateV4FinalPins,
    CreateV4NeighborPins,
)


class NegativeHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.at = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
        neighbors = tuple(CreateV4NeighborPins(
            role, f"old-{index}", "1" * 64, 8,
        ) for index, role in enumerate((
            "working", "jules_probe", "preserved_first", "second_auths",
            "clean_edit", "recovered_first",
        )))
        source = CreateV4BaselinePins(
            company="atlas-studio", instance="test-instance",
            definition_hash="1" * 64, customer_id="customer-1",
            jules_subject="jules-1", drive_id="drive-1", folder_id="project-a",
            source_verification_sha256="2" * 64,
            source_v3_baseline_generation=18,
            source_v3_baseline_sha256="3" * 64,
            source_v3_final_generation=20,
            source_v3_final_sha256="4" * 64,
            baseline_generation=21, baseline_sha256="5" * 64,
            neighbors=neighbors,
            prior_markers=tuple("ap071_" + char * 32 for char in "abc"),
        )
        candidate = CreateV4CandidateBlankPins(
            source, 22, "6" * 64, "old-seventh", "ap071_" + "d" * 32,
        )
        self.v4 = CreateV4FinalPins(candidate, 23, "7" * 64, "8" * 64, 40)
        self.source_paths = tuple(self.root / f"source-{index}" for index in range(3))
        self.paths = tuple(
            self.root / f"generation-{generation:04d}" / name
            for generation, name in (
                (24, "google-create-negative-setup.json"),
                (25, "google-create-negative-baseline.json"),
                (26, "google-create-recovery-negative.json"),
            )
        )

    @staticmethod
    def _write(path: Path, document: dict) -> str:
        path.parent.mkdir(mode=0o700, exist_ok=True)
        raw = json.dumps(document, sort_keys=True).encode()
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def _case(self, case: str) -> tuple[CreateNegativePins, dict, dict, dict]:
        marker = "ap071_" + "e" * 32
        common = {
            "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "1" * 64, "drive_id": "drive-1",
            "project_a_folder_id": "project-a", "run_id": "run-zero",
            "case": case, "marker": marker, "scratch_root_id": "scratch-root",
            "run_folder_id": "run-folder",
        }
        source = {
            "source_v4_baseline_generation": 21,
            "source_v4_baseline_sha256": "5" * 64,
            "source_v4_final_generation": 23,
            "source_v4_final_sha256": "7" * 64,
        }
        seed = "seed" if case == "multiple" else None
        item = lambda ident, created: {
            "file_id": ident, "title": CHILD_TITLE,
            "created_at": created.isoformat(), "raw_sha256": BLANK_SHA256,
            "raw_byte_count": 3,
        }
        before = [item(seed, self.at + timedelta(seconds=10))] if seed else []
        new = [item("new", self.at + timedelta(seconds=70))] if case != "zero" else []
        unchanged = {
            "original_seven_unchanged": True, "project_a_direct_child_count": 8,
            "canonical_project_a_unchanged": True,
            "canonical_project_b_unchanged": True,
            "jules_project_b_write_denied": True,
        }
        setup = common | source | {
            "schema_version": "demo-co/google-create-negative-setup/v1",
            "status": "ready", "attribution": "producer_setup_only",
            "observed_at": self.at.isoformat(), "seed_id": seed,
            "jules_subject": "jules-1",
            "scratch_journal_company": "atlas-studio-recovery-negative",
        }
        setup_sha = self._write(self.paths[0], setup)
        baseline = common | source | unchanged | {
            "schema_version": "demo-co/google-create-negative-baseline/v1",
            "status": "ready", "attribution": "provider_state_only",
            "observed_at": (self.at + timedelta(seconds=30)).isoformat(),
            "setup_generation": 24, "setup_sha256": setup_sha,
            "seed_id": seed, "provider_match_count": len(before), "matches": before,
        }
        baseline_sha = self._write(self.paths[1], baseline)
        matches = sorted(before + new, key=lambda entry: entry["file_id"])
        after = common | unchanged | {
            "schema_version": "demo-co/google-create-recovery-negative/v1",
            "status": "observed_provider_state",
            "attribution": "provider_state_only",
            "observed_at": (self.at + timedelta(seconds=90)).isoformat(),
            "baseline_generation": 25, "baseline_sha256": baseline_sha,
            "baseline_observed_at": baseline["observed_at"],
            "setup_seed_id": seed, "provider_search_complete": True,
            "provider_match_count": len(matches), "matches": matches,
            "new_child_ids": [entry["file_id"] for entry in new],
            "all_matches_blank": True,
            "auths_search_or_refusal_attested": False,
        }
        after_sha = self._write(self.paths[2], after)
        pins = CreateNegativePins(
            self.v4, "run-zero", case, marker, "scratch-root", "run-folder",
            seed, 24, setup_sha, 25, baseline_sha, 26, after_sha,
        )
        return pins, setup, baseline, after

    def _validate(self, pins: CreateNegativePins) -> dict:
        with patch("employee_read_demo.google_create_negative_handoff."
                   "validate_create_v4_observation") as source:
            result = validate_create_recovery_negative_observation(
                *self.source_paths, *self.paths, pins,
            )
        source.assert_called_once()
        return result

    def test_each_case_is_provider_state_only(self) -> None:
        for case, expected in (("zero", 0), ("multiple", 2), ("incomplete", 1)):
            with self.subTest(case=case):
                pins, _, _, _ = self._case(case)
                result = self._validate(pins)
                self.assertEqual(result["provider_match_count"], expected)
                self.assertEqual(result["authority"], "none")

    def test_setup_binds_only_the_reviewed_run_folder_and_marker(self) -> None:
        pins, setup, _, _ = self._case("multiple")
        with patch("employee_read_demo.google_create_negative_handoff."
                   "validate_create_v4_observation"):
            target = validate_negative_create_setup(
                *self.source_paths, self.paths[0], pins.setup_sha256, self.v4,
            )
        self.assertEqual(target.parent_id, "run-folder")
        self.assertEqual(target.marker, pins.marker)
        self.assertEqual(target.case, "multiple")
        changed = setup | {"project_a_folder_id": "other-folder"}
        digest = self._write(self.paths[0], changed)
        with patch("employee_read_demo.google_create_negative_handoff."
                   "validate_create_v4_observation"):
            with self.assertRaises(ContractRejected):
                validate_negative_create_setup(
                    *self.source_paths, self.paths[0], digest, self.v4,
                )

    def test_precreate_baseline_expires_and_refuses_wrong_inventory(self) -> None:
        pins, _, baseline, _ = self._case("multiple")
        with patch("employee_read_demo.google_create_negative_handoff."
                   "validate_create_v4_observation"):
            target, generation, _ = validate_negative_precreate_baseline(
                *self.source_paths, self.paths[0], pins.setup_sha256,
                self.paths[1], pins.baseline_sha256, self.v4,
                now=int((self.at + timedelta(minutes=1)).timestamp()),
            )
            self.assertEqual((target.parent_id, generation), ("run-folder", 25))
            with self.assertRaisesRegex(ContractRejected, "stale"):
                validate_negative_precreate_baseline(
                    *self.source_paths, self.paths[0], pins.setup_sha256,
                    self.paths[1], pins.baseline_sha256, self.v4,
                    now=int((self.at + timedelta(minutes=8)).timestamp()),
                )
            changed = baseline | {"matches": []}
            digest = self._write(self.paths[1], changed)
            with self.assertRaises(ContractRejected):
                validate_negative_precreate_baseline(
                    *self.source_paths, self.paths[0], pins.setup_sha256,
                    self.paths[1], digest, self.v4,
                    now=int((self.at + timedelta(minutes=1)).timestamp()),
                )

    def test_cross_run_and_ambiguous_provider_evidence_is_refused(self) -> None:
        pins, setup, baseline, after = self._case("multiple")
        self._validate(pins)
        for field, value in (
            ("run_folder_id", "other-folder"),
            ("provider_search_complete", False),
            ("auths_search_or_refusal_attested", True),
            ("new_child_ids", ["seed"]),
        ):
            with self.subTest(field=field):
                changed = after | {field: value}
                digest = self._write(self.paths[2], changed)
                with self.assertRaises(ContractRejected):
                    self._validate(replace(pins, observation_sha256=digest))
        self._write(self.paths[2], after)
        changed = baseline | {"seed_id": "other"}
        digest = self._write(self.paths[1], changed)
        with self.assertRaises(ContractRejected):
            self._validate(replace(pins, baseline_sha256=digest))
        self._write(self.paths[1], baseline)
        changed = setup | {"run_id": "other-run"}
        digest = self._write(self.paths[0], changed)
        with self.assertRaises(ContractRejected):
            self._validate(replace(pins, setup_sha256=digest))
