//! Native grant corpus and adapter conformance. Synthetic post-verification
//! commands exercise persistence, never claim installed resource authority.
use super::*;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};

const NOW: u64 = 1_790_000_000;

fn approved() -> Arc<ApprovedEffect> {
    let recipe = crate::CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("recipe");
    let arguments = serde_json::json!({
        "operation_id": "synthetic-entry", "record_id": "recTEST0000000001", "replacement": "Approved",
        "operator_namespace": recipe.namespace().as_str(), "recipe_digest": recipe.digest_hex(),
    });
    let command = crate::scenario_tests::admitted(
        &recipe,
        arguments.as_object().expect("arguments"),
        [11; 32],
        Vec::new(),
        60,
        Vec::new(),
        NOW,
    )
    .expect("post-native command");
    Arc::new(
        crate::effect::approve_driver_fixture(command, *recipe.digest(), NOW, None)
            .expect("approval"),
    )
}

async fn reserved(
    attempts: &GatewayAttempts,
    approved: &Arc<ApprovedEffect>,
) -> ClaimedGatewayAttempt {
    let BoundedClaim::Claimed(claim) = attempts.claim_bounded(approved, NOW).await.expect("claim")
    else {
        panic!("claim refused")
    };
    *claim
}

fn stale_copy(claim: &ClaimedGatewayAttempt) -> ClaimedGatewayAttempt {
    ClaimedGatewayAttempt {
        attempt: Attempt {
            store: Arc::clone(&claim.attempt.store),
            key: claim.attempt.key,
            stored: claim.attempt.stored.clone(),
            record: claim.attempt.record.clone(),
        },
    }
}

#[tokio::test]
async fn native_entry_fixture_is_current() {
    let store = TestAttempts::open(Backend::File);
    let approved = approved();
    let claim = reserved(store.attempts(), &approved).await;
    assert_eq!(claim.attempt.record.stage, GatewayAttemptStage::Reserved);
    assert!(claim.attempt.record.entry.is_none());
    let stale = stale_copy(&claim);
    let (granted, permit) = claim
        .grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW },
        )
        .await
        .expect("grant");
    assert_eq!(
        granted.attempt.record.stage,
        GatewayAttemptStage::EntryGranted
    );
    assert_eq!(permit.request().body(), approved.command().request.body());
    let audit = serde_json::to_value(granted.attempt.record.entry.as_ref().expect("audit"))
        .expect("audit JSON");
    drop(permit); // A crash before send still consumes the one grant.
    assert!(
        stale
            .grant_entry(
                Arc::clone(&approved),
                crate::entry::EntryValidation::Oracle { now: NOW }
            )
            .await
            .is_err()
    );
    let read = store
        .reopen()
        .read(
            approved.command().request.namespace(),
            approved.command().request.operation_id(),
        )
        .await
        .expect("read")
        .expect("retained");
    assert_eq!(read.stage(), GatewayAttemptStage::Unknown);
    let mut next = granted.attempt.record.clone();
    next.stage = GatewayAttemptStage::NotEntered;
    next.refusal = Some("test.no-send".to_owned());
    assert!(!valid_transition(&granted.attempt.record, &next).expect("transition"));
    // Canonical native records also seed the shipping decoder/transition fuzzer.
    // The nonce is private replay evidence, independent of signed effect bytes;
    // a fixed synthetic value makes the corpus reproducible.
    let mut entry = granted.attempt.record.clone();
    entry.nonce = "00112233445566778899aabbccddeeff".to_owned();
    let mut reserved = entry.clone();
    reserved.stage = GatewayAttemptStage::Reserved;
    reserved.entry = None;
    let mut refused = reserved.clone();
    refused.stage = GatewayAttemptStage::NotEntered;
    refused.refusal = Some("test.before-grant".to_owned());
    let mut unknown = entry.clone();
    unknown.stage = GatewayAttemptStage::Unknown;
    let mut response = entry.clone();
    response.stage = GatewayAttemptStage::ResponseRecorded;
    response.response_status = Some(200);
    response.response_digest = Some(hex::encode([9; 32]));
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/target_gateway_attempt");
    let write_seed = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, bytes).expect("seed");
        }
        assert_eq!(std::fs::read(path).expect("seed"), bytes);
    };
    for (name, record) in [
        ("reserved", &reserved),
        ("entry-granted", &entry),
        ("not-entered", &refused),
        ("unknown", &unknown),
        ("response-recorded", &response),
    ] {
        record.snapshot(false).expect("valid native record");
        write_seed(
            &format!("record-{name}-synthetic-entry"),
            &encode(record).expect("encode"),
        );
    }
    for (name, old, new) in [
        ("reserved-to-entry-granted", &reserved, &entry),
        ("reserved-to-not-entered", &reserved, &refused),
        ("entry-granted-to-unknown", &entry, &unknown),
        ("entry-granted-to-response-recorded", &entry, &response),
    ] {
        assert!(valid_transition(old, new).expect("transition"));
        let old = encode(old).expect("old");
        let mut bytes = u32::try_from(old.len())
            .expect("bounded length")
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(&old);
        bytes.extend_from_slice(&encode(new).expect("new"));
        write_seed(&format!("transition-{name}-synthetic-entry"), &bytes);
    }
    let fixture = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "auths.effect-entry-fixture/1",
        "scope": "native synthetic post-verification grant; no provider entry or installed authority claim",
        "reserved_stage": "reserved", "granted_stage": "entry-granted", "restart_projection": "unknown",
        "second_grant_refused": true, "post_grant_nonentry_refused": true, "entry_audit": audit,
    })).expect("fixture");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/effect-entry.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}

async fn grant_conformance(backend: Backend) {
    let store = TestAttempts::open(backend);
    let approved = approved();
    let claim = reserved(store.attempts(), &approved).await;
    let stale = stale_copy(&claim);
    let (left, right) = tokio::join!(
        claim.grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW }
        ),
        stale.grant_entry(
            Arc::clone(&approved),
            crate::entry::EntryValidation::Oracle { now: NOW }
        ),
    );
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "one acknowledged permit"
    );
    let (claim, permit) = left.or(right).expect("winner");
    drop(permit);
    assert!(
        claim
            .record_not_entered("test.no-send", None)
            .await
            .is_err(),
        "even unsent grants retain uncertainty"
    );
    let snapshot = store
        .reopen()
        .read(
            approved.command().request.namespace(),
            approved.command().request.operation_id(),
        )
        .await
        .expect("reopen")
        .expect("retained");
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
    assert!(matches!(
        store.attempts().claim_bounded(&approved, NOW).await,
        Err(GatewayAttemptError::Replay)
    ));
}

#[tokio::test]
async fn file_grant_has_one_winner_and_no_restart_permit() {
    grant_conformance(Backend::File).await;
}

#[tokio::test]
#[ignore = "requires the TLS PostgreSQL fixture"]
async fn postgres_grant_has_one_winner_and_no_restart_permit() {
    assert!(postgres_configured());
    grant_conformance(Backend::Postgres).await;
}
