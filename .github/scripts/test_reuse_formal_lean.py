"""Offline negatives for evidence provenance, exact inputs and cold fallback."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("lean_reuse", Path(__file__).with_name("reuse-formal-lean.py"))
REUSE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REUSE)


def zipped(raw, name="lean.json"):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, raw)
    return result.getvalue()


class Evidence:
    def __init__(self):
        self.env = {
            "GITHUB_REPOSITORY": "owner/repo", "GITHUB_RUN_ID": "100", "AUTHS_PR_NUMBER": "7",
            "AUTHS_FORMAL_PHASE_CLOSURE_SHA256": "a" * 64,
            "AUTHS_FORMAL_TOOLCHAIN_CLOSURE_SHA256": "b" * 64,
            "AUTHS_FORMAL_EVIDENCE_CLOSURE_SHA256": "c" * 64,
        }
        repo = {"id": 1, "full_name": "owner/repo"}
        self.run = {
            "id": 99, "run_attempt": 2, "workflow_id": 4, "path": REUSE.WORKFLOW,
            "event": "pull_request", "repository": repo, "head_repository": repo,
            "head_branch": "feature", "head_sha": "d" * 40,
            "pull_requests": [{"number": 7, "base": {"repo": {"id": 1}},
                               "head": {"repo": {"id": 1}, "sha": "d" * 40}}],
        }
        self.current = copy.deepcopy(self.run)
        self.current["id"] = 100
        self.phase = {
            "schema": "auths-proof-formal-phase-result/v1", "phase": "lean",
            "head_sha": self.run["head_sha"], "run_id": "99", "run_attempt": "1",
            "execution": "executed-clean", "reproduction_count": 0,
            "planned_closure_sha256": "a" * 64, "toolchain_closure_sha256": "b" * 64,
            "evidence_closure_sha256": "c" * 64, "proof_inputs_sha256": "e" * 64,
            "source_closure_sha256": "f" * 64, "toolchain_lock_sha256": "0" * 64,
        }
        self.artifact = {
            "id": 88, "name": "auths-formal-phase-lean-99-1", "expired": False,
            "size_in_bytes": 512,
            "workflow_run": {"id": 99, "head_sha": "d" * 40,
                             "repository_id": 1, "head_repository_id": 1},
        }
        self.job = {"id": 77, "name": REUSE.JOB, "status": "completed",
                    "conclusion": "success", "head_sha": "d" * 40}
        self.raw = None
        self.member = "lean.json"
        self.calls = []
        self.verified = []
        self.accept = True
        self.tamper_archive = False
        self.workflow_runs = [self.current, self.run]

    def api(self, path, archive=False):
        self.calls.append(path)
        if path.endswith("/runs/100"):
            return self.current
        if "/actions/workflows/4/runs?" in path:
            return {"workflow_runs": self.workflow_runs}
        if "/actions/runs?" in path:
            # A real push creates14 unrelated workflows ahead of any prior CI.
            return {"workflow_runs": [dict(self.current, workflow_id=5)] * 14 + [self.run]}
        raw = self.raw if self.raw is not None else json.dumps(self.phase)
        data = zipped(raw, self.member)
        self.artifact.setdefault("digest", "sha256:" + hashlib.sha256(data).hexdigest())
        if "/artifacts?" in path:
            return {"artifacts": [self.artifact]}
        if "/attempts/" in path:
            # Producer attempt1 remains distinct from retried run attempt2.
            if "/attempts/1/" not in path:
                raise ValueError("wrong attempt queried")
            return {"jobs": [self.job]}
        if path.endswith("/artifacts/88/zip") and archive:
            return data + b"tamper" if self.tamper_archive else data
        raise ValueError("unexpected API request")

    def verify(self, raw, producer, environment, directory):
        self.verified.append((raw, producer))
        return self.accept

    def discover(self):
        return REUSE.discover(self.env, self.api, self.verify)


class ReuseTests(unittest.TestCase):
    def test_success_preserves_actual_producer_attempt_and_artifact(self):
        fixture = Evidence()
        self.assertTrue(fixture.discover())
        self.assertEqual(len(fixture.verified), 1)
        producer = fixture.verified[0][1]
        self.assertEqual(producer["AUTHS_REUSED_RUN_ATTEMPT"], "1")
        self.assertEqual(producer["AUTHS_REUSED_JOB_ID"], "77")
        self.assertEqual(producer["AUTHS_REUSED_ARTIFACT_ID"], "88")
        self.assertIn("/attempts/1/jobs?per_page=100", " ".join(fixture.calls))

    def test_discovery_queries_only_the_current_workflow_before_bounding(self):
        fixture = Evidence()
        self.assertTrue(fixture.discover())
        self.assertIn("repos/owner/repo/actions/workflows/4/runs?branch=feature&event=pull_request&per_page=50", fixture.calls)
        self.assertFalse(any("/actions/runs?" in path for path in fixture.calls))
        # The tenth CI run is reachable; the eleventh is a bounded cold miss.
        fixture = Evidence(); fixture.workflow_runs = [fixture.current] * 9 + [fixture.run]
        self.assertTrue(fixture.discover())
        fixture = Evidence(); fixture.workflow_runs = [fixture.current] * 10 + [fixture.run]
        self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)

    def test_current_pr_snapshot_does_not_replace_immutable_producer_revision(self):
        fixture = Evidence()
        fixture.run["pull_requests"][0]["head"]["sha"] = "e" * 40
        self.assertTrue(fixture.discover())
        self.assertEqual(fixture.verified[0][1]["AUTHS_REUSED_HEAD_SHA"], "d" * 40)
        for owner in ["run", "job", "artifact", "phase"]:
            with self.subTest(owner=owner):
                fixture = Evidence()
                fixture.run["pull_requests"][0]["head"]["sha"] = "e" * 40
                target = fixture.artifact["workflow_run"] if owner == "artifact" else getattr(fixture, owner)
                target["head_sha"] = "e" * 40
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)

    def test_untrusted_or_different_run_is_ineligible(self):
        changes = [
            ("id", 100), ("workflow_id", 5), ("path", "other.yml"),
            ("event", "workflow_dispatch"), ("head_branch", "other"),
            ("head_sha", "X" * 40), ("repository", {"id": 2, "full_name": "owner/repo"}),
            ("head_repository", {"id": 2, "full_name": "fork/repo"}),
            ("pull_requests", [{"number": 8}]), ("run_attempt", 0),
        ]
        for key, value in changes:
            with self.subTest(key=key):
                fixture = Evidence(); fixture.run[key] = value
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)

    def test_failed_skipped_running_or_wrong_producer_job_is_ineligible(self):
        for key, value in [("conclusion", "failure"), ("conclusion", "skipped"),
                           ("conclusion", "cancelled"), ("status", "in_progress"),
                           ("head_sha", "e" * 40), ("name", "formal proof fast"), ("id", 0)]:
            with self.subTest(key=key, value=value):
                fixture = Evidence(); fixture.job[key] = value
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)

    def test_artifact_metadata_and_archive_are_both_required(self):
        for key, value in [("id", 0), ("expired", True), ("size_in_bytes", 0),
                           ("size_in_bytes", REUSE.LIMIT + 1), ("name", "auths-formal-phase-lean-99-3"),
                           ("name", "auths-formal-phase-lean-99-01"), ("digest", "sha256:" + "0" * 64),
                           ("digest", ""), ("workflow_run", {"id": 98})]:
            with self.subTest(key=key, value=value):
                fixture = Evidence(); fixture.artifact[key] = value
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)
        fixture = Evidence(); fixture.tamper_archive = True
        self.assertFalse(fixture.discover())

    def test_wrong_phase_closure_and_missing_complete_attestation_are_ineligible(self):
        for key in ["schema", "phase", "head_sha", "run_id", "run_attempt", "execution",
                    "planned_closure_sha256", "toolchain_closure_sha256", "evidence_closure_sha256",
                    "proof_inputs_sha256", "source_closure_sha256", "toolchain_lock_sha256"]:
            with self.subTest(key=key):
                fixture = Evidence(); fixture.phase[key] = "wrong"
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)
        fixture = Evidence(); del fixture.phase["proof_inputs_sha256"]
        self.assertFalse(fixture.discover())
        fixture = Evidence(); fixture.phase["reused_from"] = {"run_id": "98"}
        self.assertFalse(fixture.discover())
        fixture = Evidence(); fixture.phase["reproduction_count"] = 1
        self.assertFalse(fixture.discover())

    def test_archive_paths_size_and_duplicate_json_refuse(self):
        for raw, member in [("[]", "lean.json"), ('{"phase":"lean","phase":"lean"}', "lean.json"),
                            ("x" * (REUSE.LIMIT + 1), "lean.json"), ("{}", "../lean.json")]:
            with self.subTest(member=member, size=len(raw)):
                fixture = Evidence(); fixture.raw = raw; fixture.member = member
                self.assertFalse(fixture.discover()); self.assertFalse(fixture.verified)

    def test_current_native_validator_refusal_is_a_cold_miss(self):
        fixture = Evidence(); fixture.accept = False
        self.assertFalse(fixture.discover()); self.assertEqual(len(fixture.verified), 1)

    def test_missing_or_unavailable_metadata_selects_fresh_work(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), patch.object(REUSE, "discover", side_effect=OSError("unavailable")):
                REUSE.main()
            self.assertEqual(output.read_text(), "reused=false\n")

    def test_workflow_retains_fresh_fallback_and_independent_qualification(self):
        workflow = Path(__file__).parents[1] / "workflows/ci.yml"
        source = workflow.read_text()
        self.assertEqual(source.count("run: python3 .github/scripts/reuse-formal-lean.py"), 2)
        for name in ["Compile the highest-value proofs, then the complete Lean libraries", "Clean and rebuild authoritative Lean evidence"]:
            self.assertIn(f"- name: {name}\n        if: steps.lean-reuse.outputs.reused != 'true'", source)
        self.assertIn("needs.formal-lean-authoritative-run.result == 'success'", source)
        self.assertIn("run: cargo xtask ci formal-evidence", source)


if __name__ == "__main__":
    unittest.main()
