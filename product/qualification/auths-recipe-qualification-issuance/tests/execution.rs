//! The stage runner rejects missing execution, candidate drift, mismatches,
//! credential exposure, unauthorized entries, and false recovery claims.

mod common;

use auths_recipe_qualification::{LiveEffects, Scenario};
use auths_recipe_qualification_issuance::{
    IssuanceError,
    execution::{RunCase, RunObservation, RunOutcome},
};
use common::{executable_corpus, tuple};

fn run(
    case: &RunCase,
    mutate: impl Fn(usize, &mut RunObservation),
) -> Result<LiveEffects, IssuanceError> {
    case.execute(&tuple(), |index, step| {
        let mut actual = RunObservation {
            tuple_sha256: tuple().digest().expect("digest"),
            observed: step.expected.clone(),
            fresh_evidence: None,
            unauthorized_provider_entries: 0,
            secret_exposed: false,
            repository_imported: false,
            provider_token_received: false,
        };
        mutate(index, &mut actual);
        Ok(actual)
    })
    .map(|(_, effects)| effects)
}

#[test]
fn production_readiness_requires_a_read_only_live_probe_on_a_production_target() {
    use auths_recipe_qualification::{BoundedText, LifecycleStoreKind};
    use auths_recipe_qualification_issuance::execution::{Operation, RunPhase};
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::ApplicationCannotReadSecret)
        .expect("probe");
    case.scenario = Scenario::ProductionReadiness;
    case.phase = RunPhase::Live;
    case.steps.truncate(1);
    case.steps[0].operation = Operation::Probe;
    let expected = &mut case.steps[0].expected;
    expected.verdict.outcome = RunOutcome::Complete;
    expected.verdict.code = BoundedText::parse("production-readiness-passed").expect("code");
    expected.verdict.request_sha256 = None;
    expected.verdict.evidence_sha256 = Some(tuple().profile_lock_sha256);
    expected.credential_leases = 0;
    expected.provider_entries = 0;
    expected.confirmed_by_read_back = 0;
    assert!(run(&case, |_, _| {}).is_ok());
    for index in 0..4 {
        let mut changed = case.clone();
        match index {
            0 => changed.phase = RunPhase::Offline,
            1 => changed.steps[0].expected.credential_leases = 1,
            2 => changed.steps[0].expected.provider_entries = 1,
            _ => changed.steps[0].expected.verdict.evidence_sha256 = None,
        }
        assert_eq!(run(&changed, |_, _| {}), Err(IssuanceError::CaseFailed));
    }
    let mut development = tuple();
    development.target.store_kind = LifecycleStoreKind::SharedFileV1;
    let mut invoked = false;
    assert_eq!(
        case.execute(&development, |_, _| {
            invoked = true;
            Err(IssuanceError::CaseFailed)
        }),
        Err(IssuanceError::CaseFailed)
    );
    assert!(!invoked);
    case.phase = RunPhase::Commissioning;
    assert_eq!(run(&case, |_, _| {}), Err(IssuanceError::CaseFailed));
}

#[test]
fn commissioning_client_refusal_cannot_replace_an_ordinary_installed_effect() {
    use auths_recipe_qualification::{BoundedText, LifecycleStoreKind};
    use auths_recipe_qualification_issuance::execution::{Operation, RunPhase};
    let mut obsolete = executable_corpus();
    obsolete.schema = "auths.qualification-corpus/1".to_owned();
    assert!(obsolete.validate().is_err());
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::InstalledJourney)
        .expect("installed client");
    assert!(run(&case, |_, _| {}).is_ok());
    let mut unrelated_effect = case.steps[0].clone();
    unrelated_effect.operation = Operation::Submit;
    let expected = &mut case.steps[0].expected;
    expected.verdict.outcome = RunOutcome::Refused;
    expected.verdict.code = BoundedText::parse("gateway.qualification.unavailable").expect("code");
    expected.verdict.evidence_sha256 = None;
    expected.credential_leases = 0;
    expected.provider_entries = 0;
    expected.confirmed_by_read_back = 0;
    assert_eq!(
        run(&case, |_, _| {}),
        Err(IssuanceError::CaseFailed),
        "ordinary qualification needs a confirmed installed-client effect"
    );
    let mut masked = case.clone();
    masked.steps.push(unrelated_effect);
    assert_eq!(run(&masked, |_, _| {}), Err(IssuanceError::CaseFailed));
    case.phase = RunPhase::Commissioning;
    assert!(run(&case, |_, _| {}).is_ok());
    for mutation in 0..4 {
        let mut changed = case.clone();
        match mutation {
            0 => changed.steps[0].expected.credential_leases = 1,
            1 => changed.steps[0].expected.provider_entries = 1,
            2 => {
                changed.steps[0].expected.verdict.code =
                    BoundedText::parse("gateway.qualification.expired").expect("code")
            }
            _ => changed.steps[0].expected.verdict.outcome = RunOutcome::Complete,
        }
        assert_eq!(run(&changed, |_, _| {}), Err(IssuanceError::CaseFailed));
    }
    let mut development = tuple();
    development.target.store_kind = LifecycleStoreKind::SharedFileV1;
    let mut invoked = false;
    assert_eq!(
        case.execute(&development, |_, _| {
            invoked = true;
            Err(IssuanceError::CaseFailed)
        }),
        Err(IssuanceError::CaseFailed)
    );
    assert!(!invoked);
}

#[test]
fn replay_can_complete_an_unresolved_read_back_but_never_write_or_reacquire_after_observation() {
    use auths_recipe_qualification::BoundedText;
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::AmbiguousResponse)
        .expect("ambiguous response");
    let replay = &mut case.steps[1].expected;
    replay.credential_leases = 1;
    replay.verdict.outcome = RunOutcome::Unknown;
    replay.verdict.code = BoundedText::parse("unknown").expect("code");
    assert!(run(&case, |_, _| {}).is_ok());
    let replay = &mut case.steps[1].expected;
    replay.verdict.outcome = RunOutcome::Observed;
    replay.verdict.evidence_sha256 = Some(tuple().profile_lock_sha256);
    replay.confirmed_by_read_back = 1;
    assert!(run(&case, |_, _| {}).is_ok());
    for mutation in 0..3 {
        let mut changed = case.clone();
        match mutation {
            0 => changed.steps[1].expected.provider_entries = 1,
            1 => changed.steps[1].expected.credential_leases = 2,
            _ => {
                changed.steps[0].expected.verdict.outcome = RunOutcome::Observed;
                changed.steps[0].expected.verdict.evidence_sha256 =
                    Some(tuple().profile_lock_sha256);
                changed.steps[0].expected.confirmed_by_read_back = 1;
            }
        }
        assert_eq!(run(&changed, |_, _| {}), Err(IssuanceError::CaseFailed));
    }
}

#[test]
fn every_stage_executes_its_operations_and_a_missing_runner_refuses() {
    let corpus = executable_corpus();
    corpus.validate().expect("complete corpus");
    for case in &corpus.cases {
        let mut operations = 0;
        case.execute(&tuple(), |_, step| {
            operations += 1;
            Ok(RunObservation {
                tuple_sha256: tuple().digest().expect("digest"),
                observed: step.expected.clone(),
                fresh_evidence: None,
                unauthorized_provider_entries: 0,
                secret_exposed: false,
                repository_imported: false,
                provider_token_received: false,
            })
        })
        .expect("stage");
        assert_eq!(operations, case.steps.len());
        assert_eq!(
            case.execute(&tuple(), |_, _| Err(IssuanceError::CaseFailed)),
            Err(IssuanceError::CaseFailed)
        );
        let mut missing = corpus.clone();
        missing.cases.retain(|other| other.id != case.id);
        if case.scenario.always_required() {
            assert!(missing.validate().is_err(), "{:?}", case.scenario);
        }
    }
}

#[test]
fn observed_faults_and_changed_candidates_produce_no_passing_case() {
    let case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::ForgedProof)
        .expect("case");
    let faults: [fn(&mut RunObservation); 8] = [
        |actual| actual.observed.credential_leases = 1,
        |actual| actual.observed.provider_entries = 1,
        |actual| actual.unauthorized_provider_entries = 1,
        |actual| actual.secret_exposed = true,
        |actual| actual.repository_imported = true,
        |actual| actual.provider_token_received = true,
        |actual| actual.observed.verdict.outcome = RunOutcome::Observed,
        |actual| actual.tuple_sha256 = tuple().profile_lock_sha256,
    ];
    for fault in faults {
        assert_eq!(
            run(&case, |_, actual| fault(actual)),
            Err(IssuanceError::CaseFailed)
        );
    }
}

#[test]
fn differential_compares_the_actual_oracle_and_gateway_commitments() {
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::OracleAccepts)
        .expect("case");
    // Both observations can match their individually declared expectations
    // and still disagree. The differential runner must refuse that corpus.
    case.steps[1].expected.verdict.request_sha256 = Some(tuple().profile_lock_sha256);
    assert_eq!(run(&case, |_, _| {}), Err(IssuanceError::CaseFailed));
}

#[test]
fn recovery_requires_read_back_and_without_the_capability_stays_unknown() {
    for scenario in [Scenario::ResponseLoss, Scenario::DelayedVisibility] {
        let mut case = executable_corpus()
            .cases
            .into_iter()
            .find(|case| case.scenario == scenario)
            .expect("case");
        assert_eq!(
            run(&case, |_, _| {})
                .expect("read-back")
                .confirmed_by_read_back,
            1
        );
        case.capabilities.clear();
        assert_eq!(run(&case, |_, _| {}), Err(IssuanceError::CaseFailed));
        case.steps[1].expected.verdict.outcome = RunOutcome::Unknown;
        case.steps[1].expected.confirmed_by_read_back = 0;
        assert_eq!(
            run(&case, |_, _| {})
                .expect("unknown")
                .confirmed_by_read_back,
            0
        );
        case.steps.swap(0, 1);
        assert_eq!(
            run(&case, |_, _| {}),
            Err(IssuanceError::CaseFailed),
            "read-back before the lost response proves no recovery"
        );
    }
}

#[test]
fn a_reviewed_expectation_cannot_authorize_a_second_entry_or_a_hostile_lease() {
    for scenario in [
        Scenario::ForgedProof,
        Scenario::ProofReplay,
        Scenario::TwoInstanceRace,
        Scenario::Crash,
    ] {
        let mut case = executable_corpus()
            .cases
            .into_iter()
            .find(|case| case.scenario == scenario)
            .expect("case");
        case.steps
            .last_mut()
            .expect("step")
            .expected
            .provider_entries += 1;
        assert_eq!(run(&case, |_, _| {}), Err(IssuanceError::CaseFailed));
    }
}

#[test]
#[cfg(unix)]
fn subprocess_failures_invalidate_reports_and_installed_consumers_get_no_credential() {
    use std::{fs, process::Command};
    let directory = tempfile::tempdir().expect("directory");
    let work = directory.path();
    let harness = common::stage_fixture(work);
    let run = |phase: &str| {
        Command::new(env!("CARGO_BIN_EXE_auths-qualification"))
            .args(["run-stage", "--phase", phase, "--timeout-seconds", "1"])
            .arg("--corpus")
            .arg(work.join("corpus.json"))
            .arg("--harness")
            .arg(&harness)
            .arg("--tuple")
            .arg(work.join("tuple.json"))
            .arg("--work-dir")
            .arg(work)
            .env(
                "AUTHS_QUALIFICATION_PROVIDER_CREDENTIAL",
                "synthetic-provider-credential",
            )
            .env("PYTHONPATH", "/synthetic/repository/source")
            .output()
            .expect("runner")
    };
    for phase in ["offline", "live"] {
        let result = run(phase);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let executed = fs::read_to_string(work.join("executed")).expect("operations");
    for (case_index, case) in executable_corpus().cases.into_iter().enumerate() {
        let phase = serde_json::to_value(case.phase).expect("phase");
        let trace: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join(format!(
                "scan/trace/{}-{case_index:03}.json",
                phase.as_str().expect("token"),
            )))
            .expect("closed trace"),
        )
        .expect("trace JSON");
        assert_eq!(
            trace["tuple_sha256"],
            tuple().digest().expect("tuple").to_hex()
        );
        assert_eq!(trace["case"], case.id.as_str());
        assert_eq!(
            trace["observations"]
                .as_array()
                .expect("observations")
                .len(),
            case.steps.len()
        );
        for (index, step) in case.steps.iter().enumerate() {
            let operation = serde_json::to_value(step.operation).expect("operation");
            assert!(executed.lines().any(|line| line
                == format!(
                    "{}:{index}:{}",
                    case.id.as_str(),
                    operation.as_str().expect("token")
                )));
        }
    }
    for fault in [
        "unauthorized",
        "missing",
        "malformed",
        "oversized",
        "failed",
        "timeout",
    ] {
        fs::write(work.join("fault"), fault).expect("fault");
        let result = run("offline");
        assert!(!result.status.success(), "{fault}");
        assert!(
            !String::from_utf8_lossy(&result.stderr)
                .contains("synthetic-canary-must-not-leave-child")
        );
        assert!(
            !work.join("cases/hostile.offline.json").exists(),
            "no stale passing report after {fault}"
        );
    }
    fs::remove_file(work.join("fault")).expect("remove fault");
    assert!(run("offline").status.success());
    fs::write(work.join("corpus.json"), "{}").expect("invalid corpus");
    assert!(!run("offline").status.success());
    assert!(
        !work.join("cases/hostile.offline.json").exists(),
        "invalid corpus input also clears stale passing evidence"
    );
}

#[test]
fn fresh_evidence_is_closed_to_the_reviewed_subject_and_exact_candidate_digest() {
    use auths_recipe_qualification_issuance::execution::{
        EvidenceComparison, FreshEvidenceWitness,
    };
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::InstalledJourney)
        .expect("live journey");
    let subject = tuple().compiled_recipe_sha256;
    let response = tuple().profile_lock_sha256;
    case.steps[0].evidence_comparison = EvidenceComparison::IndependentReadBack {
        subject_sha256: subject,
    };
    case.steps[0].expected.verdict.evidence_sha256 = None;
    let set_witness = |actual: &mut RunObservation| {
        actual.observed.verdict.evidence_sha256 = Some(response);
        actual.fresh_evidence = Some(FreshEvidenceWitness::IndependentReadBack {
            subject_sha256: subject,
            response_sha256: response,
        });
    };
    assert!(run(&case, |_, actual| set_witness(actual)).is_ok());
    for index in 0..6 {
        assert_eq!(
            run(&case, |_, actual| {
                set_witness(actual);
                match index {
                    0 => actual.fresh_evidence = None,
                    1 => actual.observed.verdict.evidence_sha256 = None,
                    2 => actual.observed.verdict.evidence_sha256 = Some(subject),
                    3 => {
                        actual.fresh_evidence = Some(FreshEvidenceWitness::IndependentReadBack {
                            subject_sha256: response,
                            response_sha256: response,
                        })
                    }
                    4 => {
                        actual.fresh_evidence = Some(FreshEvidenceWitness::ProductionDoctor {
                            tuple_sha256: tuple().digest().expect("tuple"),
                            report_sha256: response,
                        })
                    }
                    _ => actual.observed.provider_entries += 1,
                }
            }),
            Err(IssuanceError::CaseFailed)
        );
    }
    let mut offline = case.clone();
    offline.phase = auths_recipe_qualification_issuance::execution::RunPhase::Offline;
    assert!(run(&offline, |_, actual| set_witness(actual)).is_err());
    let mut static_case = case.clone();
    static_case.steps[0].evidence_comparison = EvidenceComparison::Static {};
    assert!(run(&static_case, |_, actual| set_witness(actual)).is_err());
    case.steps[0].expected.verdict.evidence_sha256 = Some(response);
    assert!(
        run(&case, |_, actual| set_witness(actual)).is_err(),
        "two evidence sources are ambiguous"
    );
}

#[test]
fn a_dynamic_doctor_witness_must_match_the_actual_production_tuple() {
    use auths_recipe_qualification::{BoundedText, LifecycleStoreKind};
    use auths_recipe_qualification_issuance::execution::{
        EvidenceComparison, FreshEvidenceWitness, Operation, RunPhase,
    };
    let mut case = executable_corpus()
        .cases
        .into_iter()
        .find(|case| case.scenario == Scenario::ApplicationCannotReadSecret)
        .expect("probe");
    case.scenario = Scenario::ProductionReadiness;
    case.phase = RunPhase::Live;
    case.steps.truncate(1);
    case.steps[0].operation = Operation::Probe;
    case.steps[0].evidence_comparison = EvidenceComparison::ProductionDoctor {};
    let expected = &mut case.steps[0].expected;
    expected.verdict.outcome = RunOutcome::Complete;
    expected.verdict.code = BoundedText::parse("production-readiness-passed").expect("code");
    expected.verdict.evidence_sha256 = None;
    let report = tuple().profile_lock_sha256;
    let set = |actual: &mut RunObservation| {
        actual.observed.verdict.evidence_sha256 = Some(report);
        actual.fresh_evidence = Some(FreshEvidenceWitness::ProductionDoctor {
            tuple_sha256: tuple().digest().expect("tuple"),
            report_sha256: report,
        });
    };
    assert!(run(&case, |_, actual| set(actual)).is_ok());
    assert!(
        run(&case, |_, actual| {
            set(actual);
            actual.fresh_evidence = Some(FreshEvidenceWitness::ProductionDoctor {
                tuple_sha256: report,
                report_sha256: report,
            });
        })
        .is_err()
    );
    let mut development = tuple();
    development.target.store_kind = LifecycleStoreKind::SharedFileV1;
    let mut invoked = false;
    assert!(
        case.execute(&development, |_, _| {
            invoked = true;
            Err(IssuanceError::CaseFailed)
        })
        .is_err()
    );
    assert!(!invoked);
    case.phase = RunPhase::Commissioning;
    assert!(run(&case, |_, actual| set(actual)).is_err());
}

#[test]
fn offline_differential_requires_native_review_without_custody_or_provider_entry() {
    use auths_recipe_qualification_issuance::execution::{Operation, RunPhase};
    for scenario in [Scenario::OracleAccepts, Scenario::OracleRejects] {
        let case = executable_corpus()
            .cases
            .into_iter()
            .find(|case| case.scenario == scenario)
            .expect("differential case");
        assert_eq!(case.steps[1].operation, Operation::Review);
        assert_eq!(
            run(&case, |_, _| {}).expect("read-only comparison").entered,
            0
        );
        let mut impossible = case.clone();
        impossible.steps[1].expected.credential_leases = 1;
        let mut invoked = false;
        assert!(
            impossible
                .execute(&tuple(), |_, _| {
                    invoked = true;
                    Err(IssuanceError::CaseFailed)
                })
                .is_err()
        );
        assert!(!invoked, "invalid corpus must not start the harness");
        let mut old_submission = case.clone();
        old_submission.steps[1].operation = Operation::Submit;
        assert!(run(&old_submission, |_, _| {}).is_err());
        for index in 0..3 {
            assert!(
                run(&case, |step, actual| {
                    if step == 1 {
                        match index {
                            0 => actual.observed.credential_leases = 1,
                            1 => actual.observed.provider_entries = 1,
                            _ => actual.observed.confirmed_by_read_back = 1,
                        }
                    }
                })
                .is_err()
            );
        }
        let mut protected = case.clone();
        protected.phase = RunPhase::Commissioning;
        let mut invoked = false;
        assert!(
            protected
                .execute(&tuple(), |_, _| {
                    invoked = true;
                    Err(IssuanceError::CaseFailed)
                })
                .is_err()
        );
        assert!(!invoked);
    }
}
