"""Local Auths Drive-reader smoke over the producer's existing Jules consent.

This checks the Auths provider adapter and outside-task boundary only. It
does not create or verify an employee-to-agent delegation or activate a live
company import, and its output must never be labelled AP-SPEC-070 acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import replace
from pathlib import Path

from .contracts import TaskDescriptor, canonical_json
from .demo_co_contract import _unique_pairs
from .existing_consent_smoke import ExistingConsentPins, ExistingDemoCoConsentLease
from .google_drive import GoogleDenied, GoogleDriveReader
from .google_oauth import TOKEN_URL
from .operator_cli import _private_read, _private_write

HEX64 = re.compile(r"^[0-9a-f]{64}$")
QUALIFICATION = "provider_adapter_smoke_not_delegation_acceptance"
PRODUCER_QUALIFICATION = "partial_only_not_full_google_verification"


def _probe(report: dict, resource: str) -> dict:
    matches = [item for item in report.get("probes", []) if type(item) is dict
               and item.get("person") == "person-jules" and item.get("resource") == resource]
    if (len(matches) != 1 or matches[0].get("expected") != "allow"
            or matches[0].get("observed") != "allow" or matches[0].get("passed") is not True
            or not isinstance(matches[0].get("file_id"), str)
            or not isinstance(matches[0].get("content_sha256"), str)
            or not HEX64.fullmatch(matches[0]["content_sha256"])):
        raise ValueError("producer partial report lacks an allowed control probe")
    return matches[0]


def run(report_path: Path, report_sha256: str, oauth_client_path: Path,
        grant_path: Path, *, now: int | None = None) -> dict:
    if not HEX64.fullmatch(report_sha256):
        raise ValueError("operator report digest is invalid")
    raw = _private_read(report_path, 65_536)
    if hashlib.sha256(raw).hexdigest() != report_sha256:
        raise ValueError("producer partial report digest changed")
    report = json.loads(raw, object_pairs_hook=_unique_pairs)
    if (type(report) is not dict or report.get("schema_version") != "demo-co/google-partial-probe/v1"
            or report.get("qualification") != PRODUCER_QUALIFICATION
            or report.get("full_google_ready") is not False or report.get("passed") is not True
            or report.get("company") != "atlas-studio"
            or report.get("instance") != "live-test-atlas-20261025"
            or report.get("customer_id") != "C0218tf2n"
            or report.get("primary_domain") != "auths.dev"
            or not isinstance(report.get("definition_hash"), str)
            or not HEX64.fullmatch(report["definition_hash"])):
        raise ValueError("producer partial report is not the pinned Atlas smoke")
    identity = report.get("identities", {}).get("person-jules", {})
    if (type(identity) is not dict or identity.get("email") != "jules@auths.dev"
            or not isinstance(identity.get("google_subject"), str)
            or not identity["google_subject"] or identity.get("suspended") is not False):
        raise ValueError("producer partial report lacks active Jules identity")
    project_a = _probe(report, "doc-project-a-status")
    project_b = _probe(report, "doc-project-b-plan")
    if project_a["file_id"] == project_b["file_id"]:
        raise ValueError("producer project document IDs are not distinct")
    oauth = json.loads(_private_read(oauth_client_path, 4096), object_pairs_hook=_unique_pairs)
    installed = oauth.get("installed") if type(oauth) is dict else None
    if (type(installed) is not dict or not isinstance(installed.get("client_id"), str)
            or not installed["client_id"] or installed.get("token_uri") != TOKEN_URL):
        raise ValueError("reviewed OAuth client configuration is invalid")
    now = int(time.time()) if now is None else now
    task = TaskDescriptor(
        "auths.google-read-task/v1", "atlas-studio", "live-test-atlas-20261025",
        report["definition_hash"], "smoke-jules-principal", "smoke-jules-binding",
        "smoke-agent-principal", "atlas-drive", "smoke-demo-co-jules", 1,
        (project_a["file_id"],), "text", 262_144, 1, 262_144,
        now - 1, now + 120, "smoke-jules-project-a",
        "Existing-consent provider adapter smoke only",
    )
    pins = ExistingConsentPins(
        task.company_id, task.instance_id, "person-jules", report["customer_id"],
        report["primary_domain"], identity["email"], identity["google_subject"],
        installed["client_id"], task.employee_principal, task.identity_binding_ref,
        task.connection_id, task.connection_generation, task.task_id, task.file_ids,
    )
    reader = GoogleDriveReader(task, ExistingDemoCoConsentLease(grant_path, pins))
    try:
        reader.read_exact(replace(task.calls()[0], file_id=project_b["file_id"]))
    except GoogleDenied:
        if reader.trace.requests_started != 0:
            raise RuntimeError("outside-task probe contacted Google")
    else:
        raise RuntimeError("outside-task probe was not denied")
    content = reader.read_exact(task.calls()[0])
    matched = hashlib.sha256(content).hexdigest() == project_a["content_sha256"]
    if not matched:
        raise RuntimeError("Auths content differs from independent producer probe")
    return {
        "qualification": QUALIFICATION,
        "producer_report_sha256": report_sha256,
        "project_a": {"observed": "allow", "hash_matches_producer": True,
                      "provider_requests": reader.trace.requests_started,
                      "content_bytes": len(content)},
        "project_b_outside_task": {"observed": "deny_before_provider",
                                   "provider_requests": 0},
        "broker_owned_oauth_onboarding": False,
        "native_employee_agent_proof": False,
        "full_google_export_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a partial Jules existing-consent consumer smoke")
    parser.add_argument("--producer-report", required=True, type=Path)
    parser.add_argument("--producer-report-sha256", required=True)
    parser.add_argument("--oauth-client", required=True, type=Path)
    parser.add_argument("--employee-grant", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.producer_report, args.producer_report_sha256,
                 args.oauth_client, args.employee_grant)
    _private_write(args.out, canonical_json(result) + b"\n")
    print(f"Partial provider-adapter smoke passed; private report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
