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
    for case in executable_corpus().cases {
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
