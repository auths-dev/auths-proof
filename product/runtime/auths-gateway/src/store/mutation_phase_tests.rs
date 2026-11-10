//! Structural differential evidence: one canonical wire representation, closed
//! shipping phases, and no loss of the old protocol's permitted payloads.
use super::*;
use serde_json::json;

#[test]
fn mutation_phase_payload_corpus_round_trips_the_existing_canonical_projection() {
    let stages = [
        GatewayAttemptStage::Reserved,
        GatewayAttemptStage::EntryGranted,
        GatewayAttemptStage::NotEntered,
        GatewayAttemptStage::Unknown,
        GatewayAttemptStage::ResponseRecorded,
        GatewayAttemptStage::Observed,
        GatewayAttemptStage::ObservedByProvider,
    ];
    let mut accepted = 0;
    for stage in stages {
        for mask in 0_u8..64 {
            let refusal = mask & 1 != 0;
            let status = mask & 2 != 0;
            let digest = mask & 4 != 0;
            let reading = mask & 8 != 0;
            let fact = mask & 16 != 0;
            let evidence = mask & 32 != 0;
            let wire = MutationWire {
                counters: Vec::new(),
                stage,
                refusal: refusal.then(|| "gateway.test.refused".to_owned()),
                response_status: status.then_some(200),
                response_digest: digest.then(|| "ab".repeat(32)),
                response_locator: None,
                observation_plan: None,
                observation_match: reading.then_some(false),
                observation_fact: fact.then_some(GatewayObservationFact::EchoMismatch),
                provider_evidence: evidence.then(|| EvidenceWire {
                    channel: GatewayEvidenceChannel::ReadBack,
                    locator: "https://provider.example/read".to_owned(),
                    echo: "token".to_owned(),
                    evidence_digest: "cd".repeat(32),
                    evidence_b64: Base64::encode_string(b"evidence"),
                    observed_at: 100,
                }),
                pre_entry: None,
                recovery_evidence: None,
                created_resource: None,
            };
            let response = status && digest;
            let expected = status == digest
                && match stage {
                    GatewayAttemptStage::Reserved
                    | GatewayAttemptStage::EntryGranted
                    | GatewayAttemptStage::Unknown => {
                        !refusal && !response && !reading && !fact && !evidence
                    }
                    GatewayAttemptStage::NotEntered => {
                        refusal && !response && !reading && !fact && !evidence
                    }
                    GatewayAttemptStage::ResponseRecorded => {
                        !refusal && response && !reading && !fact && !evidence
                    }
                    GatewayAttemptStage::Observed => !refusal && response && reading && !evidence,
                    GatewayAttemptStage::ObservedByProvider => {
                        !refusal && !reading && !fact && evidence
                    }
                };
            let bytes = canonical(&wire).expect("bounded synthetic wire");
            let parsed = serde_json::from_slice::<MutationState>(&bytes);
            assert_eq!(parsed.is_ok(), expected, "stage={stage:?}, mask={mask}");
            if let Ok(state) = parsed {
                accepted += 1;
                assert_eq!(state.stage(), stage);
                assert_eq!(canonical(&state).expect("closed state"), bytes);
                let round_trip: MutationState =
                    serde_json::from_slice(&bytes).expect("same canonical wire");
                assert_eq!(round_trip.response_status(), state.response_status());
                assert_eq!(round_trip.observation_fact(), state.observation_fact());
            }
        }
    }
    assert_eq!(accepted, 9);
}

#[test]
fn mutation_phase_rejects_foreign_fields_and_partial_observation_payloads() {
    for wire in [
        json!({"stage":"reserved", "response_locator":{"id":"unbound"}}),
        json!({"stage":"response-recorded", "response_status":200}),
        json!({"stage":"observed", "response_status":200, "response_digest":"ab".repeat(32)}),
        json!({"stage":"observed", "response_status":200, "response_digest":"ab".repeat(32), "observation_match":true, "observation_fact":"echo-mismatch"}),
        json!({"stage":"observed-by-provider", "response_status":200, "response_digest":"ab".repeat(32)}),
        json!({"stage":"not-entered"}),
        json!({"stage":"reserved", "foreign_authority":true}),
    ] {
        assert!(serde_json::from_value::<MutationState>(wire).is_err());
    }
}
