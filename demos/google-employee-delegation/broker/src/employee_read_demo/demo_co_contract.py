"""Strict consumer of pinned demo_co artifacts; no mutable repo dependency."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

MAX_ARTIFACT_BYTES = 1_048_576
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


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
    scenario_sha256: tuple[str, ...] = ()
    google_verification_sha256: str | None = None

    def validate(self) -> None:
        if not all(HEX64.fullmatch(x) for x in (self.definition_hash, self.bundle_sha256, self.expectation_hash)):
            raise ContractRejected("invalid operator hash pin")
        if (not all(NAME.fullmatch(x) for x in (self.company_id, self.instance_id, self.dataset_version))
                or not self.google_customer_id or len(self.google_customer_id) > 128
                or not self.google_primary_domain or len(self.google_primary_domain) > 253):
            raise ContractRejected("missing operator identity pin")
        if len(self.scenario_sha256) > 4096 or any(not HEX64.fullmatch(x) for x in self.scenario_sha256):
            raise ContractRejected("invalid scenario digest pin")
        if self.google_verification_sha256 is not None and not HEX64.fullmatch(self.google_verification_sha256):
            raise ContractRejected("invalid Google verification digest pin")


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
    adoptable: bool = False

    @property
    def status(self) -> ImportStatus:
        if self.google_ready:
            return ImportStatus("ready", "validated", "validated", "live Google prerequisites recorded")
        state = self.bundle["capabilities"]["google_workspace"]["status"]
        return ImportStatus(state, "validated", "validated", "Google provider prerequisites are incomplete")


def prepare_operator_pins(connections: Path, access_expectations: Path,
                          *, company_id: str, instance_id: str,
                          definition_hash: str, dataset_version: str,
                          google_customer_id: str, google_primary_domain: str,
                          scenario_results: tuple[Path, ...] = (),
                          google_verification: Path | None = None) -> tuple[OperatorPins, CompanyImport]:
    """Build a review candidate from independently entered identities and exact artifact bytes."""
    _, bundle_raw = _load(connections, "connections-v1.schema.json")
    access, _ = _load(access_expectations, "access-expectations-v1.schema.json")
    if len(scenario_results) > 4096:
        raise ContractRejected("too many scenario results")
    scenario_hashes = []
    for path in scenario_results:
        _, raw = _load(path, "scenario-result-v1.schema.json")
        scenario_hashes.append(hashlib.sha256(raw).hexdigest())
    verification_hash = None
    if google_verification is not None:
        _, raw = _load(google_verification, "google-verification-v1.schema.json")
        verification_hash = hashlib.sha256(raw).hexdigest()
    pins = OperatorPins(
        company_id, instance_id, definition_hash, dataset_version,
        hashlib.sha256(bundle_raw).hexdigest(), access["expectation_hash"],
        google_customer_id, google_primary_domain,
        tuple(scenario_hashes), verification_hash,
    )
    accepted = validate_artifacts(connections, access_expectations, pins)
    if accepted.google_ready:
        if google_verification is None:
            raise ContractPending("live Google verification export is missing")
        import_company(connections, access_expectations, pins,
                       scenario_results=scenario_results,
                       google_verification=google_verification)
    return pins, accepted


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
    if list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)):
        raise ContractRejected("artifact violates pinned schema")
    return document, raw


def _unique(items: list[dict[str, Any]], *keys: str) -> None:
    values = [tuple(item[key] for key in keys) for item in items]
    if len(values) != len(set(values)):
        raise ContractRejected(f"duplicate {'/'.join(keys)}")


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
        _unique(document["people"], "provider", "logical_person_id")
        _unique(document["resources"], "provider", "logical_resource_id")
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
    google_people = [person for person in bundle["people"] if person["provider"] == "google"]
    drive_resources = [resource for resource in bundle["resources"]
                       if resource["provider"] == "google_drive"]
    if access["people"] != google_people or access["resources"] != drive_resources:
        raise ContractRejected("mapping disagreement between artifacts")
    person_ids = {person["logical_person_id"] for person in access["people"]
                  if person["provider"] == "google"}
    resource_ids = {resource["logical_resource_id"] for resource in access["resources"]
                    if resource["provider"] == "google_drive"}
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
        if len({p["provider_subject"] for p in people}) != len(people):
            raise ContractRejected("duplicate Google subject binding")
        outcomes = {case["expected"] for case in access["cases"] if case["status"] == "pass"
                    and case.get("observed") == case["expected"] and case.get("evidence_ref")}
        if outcomes != {"allow", "deny"}:
            raise ContractRejected("independent allowed and denied probes are missing")
    return CompanyImport(bundle, access, bundle_hash, ready)


def inspect_exports(connections: Path | None, access_expectations: Path | None,
                    pins: OperatorPins | None = None,
                    scenario_results: tuple[Path, ...] = (),
                    google_verification: Path | None = None) -> ImportStatus:
    if connections is None or access_expectations is None or pins is None:
        return ImportStatus("not_configured", "not_configured", "not_configured",
                            "demo_co exports and operator pins have not been supplied")
    try:
        accepted = validate_artifacts(connections, access_expectations, pins)
        if not accepted.google_ready:
            return accepted.status
        return import_company(connections, access_expectations, pins,
                              scenario_results=scenario_results,
                              google_verification=google_verification).status
    except ContractPending as error:
        return ImportStatus("not_configured", "validated", "validated", str(error))
    except ContractRejected as error:
        return ImportStatus("not_configured", "rejected", "rejected", str(error))


def import_company(connections: Path, access_expectations: Path, pins: OperatorPins,
                   *, scenario_results: tuple[Path, ...] = (),
                   google_verification: Path | None = None) -> CompanyImport:
    accepted = validate_artifacts(connections, access_expectations, pins)
    if not accepted.google_ready:
        raise ContractPending(accepted.status.reason)
    if google_verification is None or pins.google_verification_sha256 is None:
        raise ContractPending("pinned independent Google verification is missing")
    validate_google_verification(google_verification, pins, accepted)
    if not scenario_results or len(scenario_results) != len(pins.scenario_sha256):
        raise ContractPending("pinned independent Google scenario results are missing")
    observed: set[tuple[str, str, str]] = set()
    for path, digest in zip(scenario_results, pins.scenario_sha256):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ContractRejected("scenario result is missing, linked or oversized")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ContractRejected("scenario result digest disagrees with operator pin")
        result = validate_scenario_result(path, pins)
        if result["status"] == "pass":
            observed.add((result["person_id"], result["resource_id"], result["expected"]))
    required = {(case["logical_person_id"], case["logical_resource_id"], case["expected"])
                for case in accepted.expectations["cases"] if case["status"] == "pass"}
    if not required or not required <= observed:
        raise ContractRejected("passing access cases lack pinned independent scenarios")
    return CompanyImport(accepted.bundle, accepted.expectations, accepted.bundle_sha256, True, True)


def validate_google_verification(path: Path, pins: OperatorPins,
                                 accepted: CompanyImport) -> dict[str, Any]:
    """Pin producer-owned live Google probes before accepting its company export."""
    pins.validate()
    if pins.google_verification_sha256 is None:
        raise ContractPending("Google verification digest pin is missing")
    verification, raw = _load(path, "google-verification-v1.schema.json")
    if hashlib.sha256(raw).hexdigest() != pins.google_verification_sha256:
        raise ContractRejected("Google verification digest disagrees with operator pin")
    if verification.get("schema_version") != "demo-co/google-verification/v1":
        raise ContractRejected("unsupported Google verification version")
    if (verification["company"], verification["instance"],
            verification["definition_hash"], verification["customer_id"]) != (
                pins.company_id, pins.instance_id, pins.definition_hash,
                pins.google_customer_id):
        raise ContractRejected("Google verification namespace mismatch")
    if not verification["passed"] or not verification["people"] or not verification["probes"]:
        raise ContractRejected("independent Google verification did not pass")
    if len(verification["people"]) > 256 or len(verification["probes"]) > 4096:
        raise ContractRejected("Google verification exceeds broker limits")
    _unique(verification["people"], "person")
    _unique(verification["probes"], "person", "resource")
    people = {person["logical_person_id"]: person for person in accepted.bundle["people"]
              if person["provider"] == "google"}
    if {observed["person"] for observed in verification["people"]} != set(people):
        raise ContractRejected("Google person observations are incomplete")
    for observed in verification["people"]:
        expected = people.get(observed["person"])
        if (expected is None or observed["directory_id"] != expected["provider_directory_id"]
                or observed["subject"] != expected["provider_subject"]):
            raise ContractRejected("Google person observation disagrees with mapping")
    observed_probes = {(probe["person"], probe["resource"]): probe
                       for probe in verification["probes"]}
    if any(not probe["passed"] or probe["observed"] != probe["expected"]
           or probe["http_status"] is None for probe in verification["probes"]):
        raise ContractRejected("Google verification contains a failed probe")
    for case in accepted.expectations["cases"]:
        if case["status"] != "pass":
            continue
        probe = observed_probes.get((case["logical_person_id"], case["logical_resource_id"]))
        if (probe is None or not probe["passed"] or probe["expected"] != case["expected"]
                or probe["observed"] != case["expected"] or probe["http_status"] is None):
            raise ContractRejected("passing access case lacks matching Google probe")
    return verification


def validate_scenario_result(path: Path, pins: OperatorPins) -> dict[str, Any]:
    """Validate an independent producer observation without granting authority."""
    pins.validate()
    result, _ = _load(path, "scenario-result-v1.schema.json")
    if result.get("schema_version") != "demo-co/scenario-result/v1":
        raise ContractRejected("unsupported scenario result version")
    if (result["company_id"], result["instance_id"], result["dataset_version"]) != (
        pins.company_id, pins.instance_id, pins.dataset_version,
    ) or result["provider"] != "google_drive":
        raise ContractRejected("scenario result namespace mismatch")
    if result["status"] == "pass" and (
        result["mode"] != "google" or result.get("expected") not in {"allow", "deny"}
        or result.get("observed") != result["expected"] or not result.get("evidence_refs")
        or not result.get("person_id") or not result.get("resource_id")
    ):
        raise ContractRejected("passing Google scenario lacks matching live evidence")
    return result
