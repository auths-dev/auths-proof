//! Native recovery accounting and refusal through the maintained engine and HTTP.
use super::*;
use crate::{
    AcquisitionStage, RecoveryDisposition as D, RecoveryEscalation as E, RecoveryNextAction as N,
};

fn response(status: u16, body: &[u8]) -> ReadResponse {
    ReadResponse {
        status,
        body: body.to_vec(),
        declared_length: body.len(),
    }
}

fn script(index: u64) -> (&'static str, Option<ReadResponse>, D, E) {
    match index {
        0 => (
            "zero-match",
            Some(response(404, b"{}")),
            D::ResponseUnusable,
            E::EvidenceUnusable,
        ),
        1 => (
            "multiple-matches",
            Some(response(
                200,
                br#"[{"fields":{"DemoStatus":"Approved"}},{"fields":{"DemoStatus":"Approved"}}]"#,
            )),
            D::ResponseUnusable,
            E::EvidenceUnusable,
        ),
        2 => (
            "unrelated-echo",
            Some(response(
                200,
                br#"{"fields":{"DemoStatus":"Approved","auths_echo":"unrelated-public-fixture"}}"#,
            )),
            D::Inconclusive,
            E::Inconclusive,
        ),
        3 => (
            "incomplete-json",
            Some(response(200, b"{")),
            D::ResponseUnusable,
            E::EvidenceUnusable,
        ),
        4 => (
            "truncated-http",
            Some(ReadResponse {
                status: 200,
                body: b"{".to_vec(),
                declared_length: 100,
            }),
            D::AcquisitionIncomplete,
            E::EvidenceIncomplete,
        ),
        5 => (
            "oversized-response",
            Some(ReadResponse {
                status: 200,
                body: vec![b' '; 16_385],
                declared_length: 16_385,
            }),
            D::AcquisitionIncomplete,
            E::EvidenceIncomplete,
        ),
        _ => (
            "state-equality-without-causation",
            None,
            D::Inconclusive,
            E::Inconclusive,
        ),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded native history constructs the recovery limits artifact"
)]
fn matrix(backend: Backend) {
    let case = Case::start(backend, Outcome::LostState);
    let runtime = runtime();
    let reader_controls = controls(true);
    let clock = Arc::clone(&reader_controls.clock);
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "bounded-reader",
        case.store.reopen(),
        reader_controls,
    ));
    let revision = engine
        .effect_configuration_revision()
        .expect("operator revision");
    engine
        .activate_effect_configuration(revision)
        .expect("withdraw writer root");
    runtime.block_on(reject_withdrawn_writer(
        &engine,
        &case.setup.installation.root,
    ));
    let mut cases = Vec::new();
    let mut last_operation = String::new();
    for index in 0..crate::effect::MAX_RECOVERY_ATTEMPTS {
        let operation = format!("bounded-reader-{index}");
        let (name, response, disposition, escalation) = script(index);
        *case.provider.read_response.lock().expect("script") = response;
        let call = runtime
            .block_on(engine.recovery_authorization_call(SOURCE, &operation))
            .expect("closed native call");
        let signed = author::signed(&call, true);
        let effect = runtime
            .block_on(engine.compile_recovery_effect(SOURCE, &signed.proof, &signed.action))
            .expect("native independent authority");
        let approval = author::approval(&effect, NOW + 1);
        let result = runtime
            .block_on(Box::pin(engine.recover(
                SOURCE,
                &signed.proof,
                &signed.action,
                approval.clone(),
            )))
            .expect("bounded observation");
        assert_eq!(result.disposition, disposition, "{name}");
        assert_eq!(result.source.stage(), crate::GatewayAttemptStage::Unknown);
        assert_eq!(
            record(&case.store, SOURCE),
            case.original,
            "inconclusive evidence cannot rewrite the source"
        );
        let report = result.report();
        assert_eq!(report.budget.retained_attempts, index + 1);
        assert_eq!(report.budget.retained_response_bytes, (index + 1) * 16_384);
        assert_eq!(report.budget.maximum_total_response_bytes, 16 * 16_384);
        assert_eq!(report.budget.maximum_transport_seconds, 15);
        assert_eq!(report.budget.maximum_total_transport_seconds, 240);
        assert_eq!(report.budget.maximum_evidence_age_seconds, 30);
        let exhausted = index + 1 == crate::effect::MAX_RECOVERY_ATTEMPTS;
        assert_eq!(
            report.escalation,
            if exhausted {
                E::CapacityExhausted
            } else {
                escalation
            }
        );
        assert_eq!(
            report
                .next_actions
                .contains(&N::RequestIndependentObservation),
            !exhausted
        );
        assert!(report.next_actions.contains(&N::Escalate));
        assert_eq!(
            case.provider.requests.lock().expect("requests").len() as u64,
            index + 2
        );
        let witness = engine.execution_witness();
        let retained_read = record(&case.store, &operation);
        let replay = runtime
            .block_on(Box::pin(engine.recover(
                SOURCE,
                &signed.proof,
                &signed.action,
                approval,
            )))
            .expect("historical read");
        assert_eq!(replay.report(), report);
        assert_eq!(
            engine.execution_witness(),
            witness,
            "replay never leases or sends again"
        );
        assert_eq!(record(&case.store, &operation), retained_read);
        if index == 6 {
            clock.set(NOW + 31);
            let at_limit = runtime
                .block_on(engine.refine_recovery(SOURCE, &operation))
                .expect("freshness boundary");
            assert_eq!(at_limit.disposition, D::Inconclusive);
            clock.set(NOW + 32);
            let stale = runtime
                .block_on(engine.refine_recovery(SOURCE, &operation))
                .expect("stale evidence remains history");
            assert_eq!(stale.disposition, D::EvidenceStale);
            assert_eq!(stale.report().escalation, E::EvidenceStale);
            assert_eq!(stale.budget, result.budget);
            assert_eq!(engine.execution_witness(), witness);
            clock.set(u64::MAX);
            assert_eq!(
                runtime
                    .block_on(engine.refine_recovery(SOURCE, &operation))
                    .expect_err("out-of-range clock cannot fabricate a report"),
                "gateway.recovery.unavailable"
            );
            clock.set(NOW + 1);
        }
        cases.push(json!({"case":name, "report":report, "replay_no_io_or_new_charge":true}));
        last_operation = operation;
    }
    let witness = engine.execution_witness();
    let requests = case.provider.requests.lock().expect("requests").len();
    let call = runtime
        .block_on(engine.recovery_authorization_call(SOURCE, "bounded-reader-over-limit"))
        .expect("proposed read");
    let signed = author::signed(&call, true);
    let effect = runtime
        .block_on(engine.compile_recovery_effect(SOURCE, &signed.proof, &signed.action))
        .expect("authority does not imply capacity");
    let approval = author::approval(&effect, NOW + 1);
    let refused = runtime
        .block_on(Box::pin(engine.recover(
            SOURCE,
            &signed.proof,
            &signed.action,
            approval,
        )))
        .expect("retained exhausted attempt");
    assert_eq!(refused.acquisition.stage, AcquisitionStage::NotEntered);
    assert_eq!(refused.acquisition.reserved_calls, 0);
    assert_eq!(refused.acquisition.reserved_bytes, 0);
    assert_eq!(refused.report().escalation, E::CapacityExhausted);
    assert_eq!(refused.budget.retained_attempts, 16);
    assert_eq!(refused.budget.retained_response_bytes, 16 * 16_384);
    assert_eq!(
        refused.report().next_actions,
        [N::InspectRetainedEvidence, N::Escalate]
    );
    assert_eq!(
        engine.execution_witness(),
        witness,
        "exhaustion precedes custody and transport"
    );
    assert_eq!(
        case.provider.requests.lock().expect("requests").len(),
        requests
    );
    assert_eq!(record(&case.store, SOURCE), case.original);
    assert_eq!(
        signed_bytes(&case.setup.installation.root, SOURCE),
        case.signed_source
    );
    let reopened_runtime = runtime;
    let (reopened, _) = reopened_runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "reopened-reader",
        case.store.reopen(),
        controls(true),
    ));
    let retained = reopened_runtime
        .block_on(reopened.refine_recovery(SOURCE, &last_operation))
        .expect("retained lifetime usage after reopen");
    assert_eq!(retained.budget, refused.budget);
    assert_eq!(retained.report().escalation, E::CapacityExhausted);
    assert_eq!(reopened.execution_witness().credential_lease_calls, 0);
    let artifact = serde_json::to_vec_pretty(&json!({
        "schema":"auths.native-recovery-limits/1", "adapter":backend.label(),
        "scope":"native signed independent recovery, exact approvals, withdrawn writer root, actual bounded HTTP and durable source-lifetime rows; writer uses a separate OS process",
        "excluded":["live provider and custody", "hostile OS or device power failure", "total prerequisite transport time"],
        "cases":cases, "exhausted":refused.report(), "reopen_preserves_lifetime_usage":true,
        "freshness_30_inclusive_31_stale":true, "out_of_range_clock_refuses_report":true,
        "source_actor_entry_and_all_original_charges_unchanged":true
    })).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-recovery-limits-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}

#[test]
fn native_file_recovery_limits_fixture_is_current() {
    matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_recovery_limits_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
