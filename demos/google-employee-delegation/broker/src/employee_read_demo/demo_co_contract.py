"""Strict consumer of pinned demo_co artifacts; no mutable repo dependency."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

MAX_ARTIFACT_BYTES = 1_048_576
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ContractRejected(ValueError):
    pass


class ContractPending(RuntimeError):
    pass


@dataclass(frozen=True)
class OperatorPins:
    company_id: str
    instance_id: str
    definition_hash: str
    dataset_version: str
    bundle_sha256: str
    expectation_hash: str
    google_customer_id: str
    google_primary_domain: str

    def validate(self) -> None:
        if not all(HEX64.fullmatch(x) for x in (self.definition_hash, self.bundle_sha256, self.expectation_hash)):
            raise ContractRejected("invalid operator hash pin")
        if not all((self.company_id, self.instance_id, self.dataset_version,
                    self.google_customer_id, self.google_primary_domain)):
            raise ContractRejected("missing operator identity pin")


@dataclass(frozen=True)
class ImportStatus:
    google: str
    connections: str
    access_expectations: str
    reason: str


@dataclass(frozen=True)
class CompanyImport:
    bundle: dict[str, Any]
    expectations: dict[str, Any]
    bundle_sha256: str
    google_ready: bool

    @property
    def status(self) -> ImportStatus:
        if self.google_ready:
            return ImportStatus("ready", "validated", "validated", "live Google prerequisites recorded")
        state = self.bundle["capabilities"]["google_workspace"]["status"]
        return ImportStatus(state, "validated", "validated", "Google provider prerequisites are incomplete")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractRejected("duplicate JSON field")
        result[key] = value
    return result


def _load(path: Path, schema_name: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ContractRejected("artifact is missing, linked or oversized")
    raw = path.read_bytes()
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ContractRejected("artifact is oversized")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ContractRejected("invalid JSON constant")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractRejected("invalid JSON artifact") from error
    if type(document) is not dict:
        raise ContractRejected("artifact must be an object")
    schema = json.loads(files("employee_read_demo").joinpath("schemas", schema_name).read_text(encoding="utf-8"))
    if list(Draft202012Validator(schema).iter_errors(document)):
        raise ContractRejected("artifact violates pinned schema")
    return document, raw


def _unique(items: list[dict[str, Any]], key: str) -> None:
    values = [item[key] for item in items]
    if len(values) != len(set(values)):
        raise ContractRejected(f"duplicate {key}")


def validate_artifacts(connections: Path, access_expectations: Path, pins: OperatorPins) -> CompanyImport:
    pins.validate()
    bundle, bundle_raw = _load(connections, "connections-v1.schema.json")
    access, access_raw = _load(access_expectations, "access-expectations-v1.schema.json")
    if bundle.get("schema_version") != "demo-co/connections/v1" or access.get("schema_version") != "demo-co/access-expectations/v1":
        raise ContractRejected("unsupported artifact version")
    bundle_hash = hashlib.sha256(bundle_raw).hexdigest()
    if bundle_hash != pins.bundle_sha256:
        raise ContractRejected("bundle digest disagrees with operator pin")
    reference = bundle["access_expectations"]
    if (reference["schema_version"] != "demo-co/access-expectations/v1"
            or reference["path"] != access_expectations.name
            or reference["sha256"] != hashlib.sha256(access_raw).hexdigest()):
        raise ContractRejected("access-expectations reference mismatch")
    for document in (bundle, access):
        if (document["company_id"], document["instance_id"], document["definition_hash"], document["dataset_version"]) != (
            pins.company_id, pins.instance_id, pins.definition_hash, pins.dataset_version,
        ):
            raise ContractRejected("namespace or definition pin mismatch")
    if access["bundle_generation"] != bundle["bundle_generation"] or access["expectation_hash"] != pins.expectation_hash:
        raise ContractRejected("expectation generation or hash mismatch")
    if access["provider"] != "google_drive" or "google_workspace" not in bundle["capabilities"]:
        raise ContractRejected("Google capability is absent")
    if any(len(document[key]) > limit for document in (bundle, access) for key, limit in (("people", 256), ("resources", 1024))):
        raise ContractRejected("mapping count exceeds broker limits")
    if len(access["cases"]) > 4096 or len(bundle["services"]) > 64:
        raise ContractRejected("export collection exceeds broker limits")
    for document in (bundle, access):
        _unique(document["people"], "logical_person_id")
        _unique(document["resources"], "logical_resource_id")
    pairs = [(case["logical_person_id"], case["logical_resource_id"]) for case in access["cases"]]
    if len(pairs) != len(set(pairs)):
        raise ContractRejected("duplicate access expectation")
    expected_cases = sorted(({
        "person": case["logical_person_id"],
        "resource": case["logical_resource_id"],
        "expected": case["expected"],
    } for case in access["cases"]), key=lambda item: (item["person"], item["resource"]))
    expectation_hash = hashlib.sha256((json.dumps(
        expected_cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ) + "\n").encode("utf-8")).hexdigest()
    if expectation_hash != access["expectation_hash"]:
        raise ContractRejected("independent expectation hash mismatch")
    if access["people"] != bundle["people"] or access["resources"] != bundle["resources"]:
        raise ContractRejected("mapping disagreement between artifacts")
    person_ids = {person["logical_person_id"] for person in access["people"]}
    resource_ids = {resource["logical_resource_id"] for resource in access["resources"]}
    if any(person not in person_ids or resource not in resource_ids for person, resource in pairs):
        raise ContractRejected("access expectation references unknown mapping")
    google = bundle["capabilities"]["google_workspace"]
    ready = bundle["mode"] == "google" and google["status"] == "ready"
    if ready:
        tenant = bundle.get("google_tenant")
        if tenant != {"customer_id": pins.google_customer_id, "primary_domain": pins.google_primary_domain}:
            raise ContractRejected("Google tenant disagrees with operator pin")
        if google["provenance"] != "live_google" or not google.get("observed_at") or not google.get("evidence_ref"):
            raise ContractRejected("Google readiness lacks live evidence")
        people = [p for p in bundle["people"] if p["provider"] == "google" and p["status"] == "ready"]
        resources = [r for r in bundle["resources"] if r["provider"] == "google_drive" and r["kind"] == "document" and r["status"] == "ready"]
        if len(people) < 2 or not resources or any(not p.get("provider_subject") or not p.get("issuer") for p in people):
            raise ContractRejected("ready Google export lacks employee identities")
        if any(not r.get("provider_resource_id") or r["provenance"] != "live_google" for r in resources):
            raise ContractRejected("ready Google export lacks Drive IDs")
        if len({r["provider_resource_id"] for r in resources}) != len(resources):
            raise ContractRejected("duplicate Drive provider ID")
        outcomes = {case["expected"] for case in access["cases"] if case["status"] == "pass"
                    and case.get("observed") == case["expected"] and case.get("evidence_ref")}
        if outcomes != {"allow", "deny"}:
            raise ContractRejected("independent allowed and denied probes are missing")
    return CompanyImport(bundle, access, bundle_hash, ready)


def inspect_exports(connections: Path | None, access_expectations: Path | None,
                    pins: OperatorPins | None = None) -> ImportStatus:
    if connections is None or access_expectations is None or pins is None:
        return ImportStatus("not_configured", "not_configured", "not_configured",
                            "demo_co exports and operator pins have not been supplied")
    try:
        return validate_artifacts(connections, access_expectations, pins).status
    except ContractRejected as error:
        return ImportStatus("not_configured", "rejected", "rejected", str(error))


def import_company(connections: Path, access_expectations: Path, pins: OperatorPins) -> CompanyImport:
    accepted = validate_artifacts(connections, access_expectations, pins)
    if not accepted.google_ready:
        raise ContractPending(accepted.status.reason)
    return accepted
