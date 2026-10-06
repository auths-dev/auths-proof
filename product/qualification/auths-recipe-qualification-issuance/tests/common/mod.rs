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

/// An executable test corpus. These fixtures test stage orchestration and
/// make no live-provider or production-qualification claim.
#[allow(
    clippy::too_many_lines,
    reason = "the closed test corpus keeps each scenario beside its operation sequence"
)]
pub fn executable_corpus() -> auths_recipe_qualification_issuance::execution::RunCorpus {
    use auths_recipe_qualification::{CapabilityKind, Scenario};
    use auths_recipe_qualification_issuance::execution::{
        CORPUS_SCHEMA, ExpectedObservation, Operation as Op, RunCase, RunCorpus,
        RunOutcome as Outcome, RunPhase, RunStep, RunVerdict, harness_scenario,
    };
    let step = |operation, outcome, entries, confirmed| RunStep {
        operation,
        expected: ExpectedObservation {
            verdict: RunVerdict {
                outcome,
                code: auths_recipe_qualification::BoundedText::parse("test.verdict").expect("code"),
                request_sha256: None,
                evidence_sha256: None,
            },
            credential_leases: u32::from(entries > 0),
            provider_entries: entries,
            confirmed_by_read_back: confirmed,
        },
    };
    let mut cases = Vec::new();
    for scenario in Scenario::ALL
        .into_iter()
        .filter(|scenario| harness_scenario(*scenario))
    {
        if scenario == Scenario::ObserverRotation {
            continue;
        }
        let mut steps = match scenario {
            Scenario::OracleAccepts => vec![
                step(Op::Oracle, Outcome::ResponseRecorded, 0, 0),
                step(Op::Submit, Outcome::ResponseRecorded, 1, 0),
            ],
            Scenario::OracleRejects => vec![
                step(Op::Oracle, Outcome::Refused, 0, 0),
                step(Op::Submit, Outcome::Refused, 0, 0),
            ],
            Scenario::ProofReplay | Scenario::FreshChallengeReplay => vec![
                step(Op::Submit, Outcome::ResponseRecorded, 1, 0),
                step(Op::Replay, Outcome::Refused, 0, 0),
            ],
            Scenario::TwoInstanceRace => vec![step(Op::Race, Outcome::ResponseRecorded, 1, 0)],
            Scenario::Restart => vec![
                step(Op::Submit, Outcome::Unknown, 1, 0),
                step(Op::Restart, Outcome::Complete, 0, 0),
                step(Op::Replay, Outcome::Refused, 0, 0),
            ],
            Scenario::Crash => vec![
                step(Op::Submit, Outcome::Unknown, 1, 0),
                step(Op::Crash, Outcome::Complete, 0, 0),
                step(Op::Replay, Outcome::Refused, 0, 0),
            ],
            Scenario::AmbiguousResponse => vec![
                step(Op::DropResponse, Outcome::Unknown, 1, 0),
                step(Op::Replay, Outcome::Refused, 0, 0),
            ],
            Scenario::ResponseLoss => vec![
                step(Op::DropResponse, Outcome::Unknown, 1, 0),
                step(Op::ReadBack, Outcome::Observed, 0, 1),
            ],
            Scenario::DelayedVisibility => vec![
                step(Op::DelayVisibility, Outcome::Unknown, 1, 0),
                step(Op::ReadBack, Outcome::Observed, 0, 1),
            ],
            Scenario::ProviderSecretRotation => vec![
                step(Op::Rotate, Outcome::Complete, 0, 0),
                step(Op::Submit, Outcome::ResponseRecorded, 1, 0),
            ],
            Scenario::ReadBackConfirmsWrite | Scenario::DeclaredCapability => vec![
                step(Op::Submit, Outcome::ResponseRecorded, 1, 0),
                step(Op::ReadBack, Outcome::Observed, 0, 1),
            ],
            Scenario::InstalledJourney
            | Scenario::NoRepositoryImport
            | Scenario::NoProviderToken => {
                vec![step(Op::InstalledConsumer, Outcome::Observed, 1, 1)]
            }
            _ => vec![step(Op::Probe, Outcome::Refused, 0, 0)],
        };
        if scenario == Scenario::OracleAccepts {
            for step in &mut steps {
                step.expected.verdict.request_sha256 = Some(tuple().compiled_recipe_sha256);
            }
        }
        let phase = if matches!(
            scenario.member(),
            EvidenceMemberKind::Live
                | EvidenceMemberKind::Recovery
                | EvidenceMemberKind::InstalledConsumer
        ) {
            RunPhase::Live
        } else {
            RunPhase::Offline
        };
        let capabilities = match scenario {
            Scenario::ResponseLoss | Scenario::DelayedVisibility => vec![CapabilityKind::Recovery],
            Scenario::DeclaredCapability => CapabilityKind::ALL
                .into_iter()
                .filter(|capability| {
                    scenario.may_show(*capability)
                        && !auths_recipe_qualification_issuance::testkit::ABSENT
                            .contains(capability)
                })
                .collect(),
            _ => Vec::new(),
        };
        cases.push(RunCase {
            id: auths_recipe_qualification::BoundedText::parse(format!("case-{scenario:?}"))
                .expect("id"),
            scenario,
            capabilities,
            phase,
            steps,
        });
    }
    RunCorpus {
        schema: CORPUS_SCHEMA.to_owned(),
        cases,
    }
}

/// A subprocess double at the provider-specific harness port. It tests the
/// real runner/CLI/script boundary; its observations claim no actual provider
/// effect. Live families must replace this with measured candidate facts.
#[cfg(unix)]
pub fn stage_fixture(work: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(work).expect("work");
    let corpus = executable_corpus();
    std::fs::write(
        work.join("corpus.json"),
        serde_json::to_vec(&corpus).expect("corpus"),
    )
    .expect("corpus");
    std::fs::write(work.join("tuple.json"), tuple_json().to_string()).expect("tuple");
    std::fs::write(
        work.join("tuple-digest"),
        tuple().digest().expect("digest").to_hex(),
    )
    .expect("digest");
    let harness = work.join("harness");
    std::fs::write(&harness, r#"#!/usr/bin/env python3
import json, os, pathlib, sys, time
_, verb, case_id, index, operation, work, output = sys.argv
assert verb == 'step'
work = pathlib.Path(work)
case = next(c for c in json.loads((work / 'corpus.json').read_text())['cases'] if c['id'] == case_id)
step = case['steps'][int(index)]
assert step['operation'] == operation
with (work / 'executed').open('a') as log:
    log.write(case_id + ':' + index + ':' + operation + '\n')
mode = (work / 'fault').read_text() if (work / 'fault').exists() else ''
if mode == 'timeout': time.sleep(3)
if mode == 'missing': sys.exit(0)
if mode == 'failed':
    print('synthetic-canary-must-not-leave-child', file=sys.stderr)
    sys.exit(1)
actual = {'tuple_sha256': (work / 'tuple-digest').read_text(), 'observed': step['expected'],
          'unauthorized_provider_entries': 0, 'secret_exposed': False,
          'repository_imported': False, 'provider_token_received': False}
if operation == 'installed-consumer':
    assert pathlib.Path.cwd() == work
    actual['provider_token_received'] = 'AUTHS_QUALIFICATION_PROVIDER_CREDENTIAL' in os.environ
    actual['repository_imported'] = 'PYTHONPATH' in os.environ
if mode == 'unauthorized': actual['unauthorized_provider_entries'] = 1
if mode == 'malformed': pathlib.Path(output).write_text('{')
elif mode == 'oversized': pathlib.Path(output).write_text(' ' * 16385)
else: pathlib.Path(output).write_text(json.dumps(actual))
"#).expect("harness");
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o700)).expect("executable");
    harness
}
