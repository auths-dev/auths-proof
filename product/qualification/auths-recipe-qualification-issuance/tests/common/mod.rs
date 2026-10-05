//! A complete synthetic candidate: a draft and the ten evidence artifacts it
//! closes over. Every value is a constant of this module and protects
//! nothing.

#![allow(dead_code, reason = "each test binary uses its own part")]

use auths_recipe_qualification::{
    EvidenceMemberKind, GitCommit, LiveEffects, QualificationEvidence, QualificationTuple,
};
use auths_recipe_qualification_issuance::{RecordDraft, evidence};
use serde_json::{Value, json};

pub const NOW: u64 = 1_790_000_000;
pub const HOUR: u64 = 60 * 60;
pub const DAY: u64 = 24 * HOUR;
pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn digest(byte: &str) -> String {
    byte.repeat(32)
}

pub fn tuple_json() -> Value {
    json!({
        "recipe_family": "example-refund-v1",
        "compiled_recipe_sha256": digest("11"),
        "profile_lock_sha256": digest("22"),
        "provider_contract_id": digest("33"),
        "gateway_semantic_closure_sha256": digest("44"),
        "target": {
            "os": "linux",
            "arch": "x86_64",
            "gateway_package": "auths-gateway",
            "gateway_version": "1.0.0-rc.1",
            "gateway_build_sha256": digest("55"),
            "store_kind": "postgresql-v1",
            "store_schema": "auths.gateway-store/1",
            "credential_store_kind": "aws-secrets-manager-v1",
        },
    })
}

pub fn tuple() -> QualificationTuple {
    serde_json::from_value(tuple_json()).expect("tuple")
}

pub fn draft_json() -> Value {
    json!({
        "qualification_id": format!("qlf_{}", "01".repeat(16)),
        "provider_kind": "example-payments",
        "tuple": tuple_json(),
        "not_before": NOW - 2 * HOUR,
        "not_after": NOW - 2 * HOUR + 90 * DAY,
        "provenance": {
            "repository": "github.com/auths-dev/auths-proof",
            "commit": COMMIT,
            "workflow": ".github/workflows/recipe-qualification.yml",
            "environment": "recipe-qualification",
        },
        "source_closure_sha256": digest("66"),
        "generated_artifacts_sha256": digest("77"),
        "installed_packages": [
            {"name": "auths-gateway", "version": "1.0.0-rc.1", "sha256": digest("88")},
        ],
        "recipe_decision_record_sha256": digest("99"),
        "corpus_manifest_sha256": digest("aa"),
        "not_applicable": [
            {"capability": "account-binding", "reason": "the recipe binds no provider account"},
            {"capability": "observer-rotation", "reason": "the target declares no observer"},
        ],
        "provider_resources": ["example-refund-0001"],
        "custody_descriptor": "aws-secrets-manager-v1 with a customer-managed key",
        "store_descriptor": "postgresql-v1 shared by two gateway instances",
        "residual_assumptions": ["the provider keeps its idempotency window"],
        "excluded_claims": ["whether a refund settles"],
    })
}

pub fn draft() -> RecordDraft {
    serde_json::from_value(draft_json()).expect("draft")
}

pub use auths_recipe_qualification_issuance::testkit::cases;

pub fn live_effects(member: EvidenceMemberKind) -> Option<LiveEffects> {
    (member == EvidenceMemberKind::Live).then_some(LiveEffects {
        entered: 3,
        confirmed_by_read_back: 3,
    })
}

pub fn commit() -> GitCommit {
    GitCommit::parse(COMMIT).expect("commit")
}

pub fn member_evidence(member: EvidenceMemberKind) -> QualificationEvidence {
    evidence(
        member,
        &commit(),
        &tuple(),
        cases(member),
        live_effects(member),
    )
    .expect("evidence")
}

pub fn all_evidence() -> Vec<QualificationEvidence> {
    EvidenceMemberKind::ALL
        .into_iter()
        .map(member_evidence)
        .collect()
}
