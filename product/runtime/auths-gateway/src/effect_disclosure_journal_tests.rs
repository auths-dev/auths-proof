//! Native disclosure admission over the file journal that retained real HTTP
//! content. No recipient transport, grant or process isolation is claimed.
use super::*;
use crate::effect::{
    ApprovedEffect, DisclosureAcknowledgementRequest, DisclosureTarget, compile_disclosure,
};
use std::sync::Arc;

#[allow(
    clippy::too_many_lines,
    reason = "one native file admission/replay/capacity artifact corpus"
)]
pub(super) async fn corpus(
    retained: crate::RetainedContent,
    recipe: &CompiledRecipe,
    connection: &ConnectionRecord,
    policy: &EffectPolicy,
    store: &Arc<dyn crate::GatewayAttemptStore>,
    path: &std::path::Path,
) -> Value {
    let root = signer(h::ROOT_SEED);
    let observer = signer(h::OBSERVER_SEED);
    let releaser = signer(0x44);
    let recipient = SigningKey::from_bytes(&[51; 32]);
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let channel_policy = crate::effect::UnixDisclosurePolicy::new(0, 0, [20; 32]);
    let target = DisclosureTarget::new(
        retained.clone(),
        recipient.verifying_key().to_bytes(),
        channel_policy.commitment().expect("channel"),
        [21; 32],
    )
    .expect("target");
    let probe = target
        .authorization_call(
            recipe,
            &LogicalOperationId::parse("release-0").expect("operation"),
        )
        .expect("call");
    let trust = h::context_for_tool(&root, &observer.principal, NOW, &probe).expect("trust");
    let grant = h::grant_for_tool(
        &root,
        &releaser.principal,
        None,
        window(NOW - 3600, NOW + 3600),
        &probe,
    )
    .expect("grant");
    let installed = policy.installation(
        recipe,
        &trust,
        connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    let approve =
        |operation: &str, target: &DisclosureTarget, bounded: bool| -> Arc<ApprovedEffect> {
            let call = target
                .authorization_call(
                    recipe,
                    &LogicalOperationId::parse(operation).expect("operation"),
                )
                .expect("call");
            let bounded_grant = if bounded {
                let budget = crate::ArgumentCeilingPolicy::new(
                    "maximum_disclosure_bytes",
                    retained.bytes,
                    3600,
                    3,
                )
                .expect("policy")
                .with_sum(retained.bytes * 2, None)
                .expect("sum");
                Some(super::read_budget_tests::read_grant(
                    &root, &releaser, &call, &budget,
                ))
            } else {
                None
            };
            let signed = submission_for_call(
                &root,
                &releaser,
                bounded_grant.as_ref().unwrap_or(&grant),
                &call,
                &[],
            );
            let effect = compile_disclosure(&installed, target, NOW, &signed.proof, &signed.action)
                .expect("effect");
            let request = effect.approval_request(NOW, NOW + 60).expect("request");
            let signature = key
                .sign(&request.signing_message().expect("message"))
                .to_bytes();
            Arc::new(
                effect
                    .approve(request.with_signature(signature), &public, NOW)
                    .expect("approval"),
            )
        };
    let shared = crate::SharedConnection::new(
        Arc::clone(store),
        connection.provider_kind().clone(),
        connection.alias().clone(),
    );
    let loaded = shared.load().await.expect("load").expect("connection");
    let configuration = crate::configuration::SharedConfiguration::new(
        Arc::clone(store),
        policy.configuration_key(recipe.namespace()).expect("key"),
        [12; 32],
    );
    let validation = |now| {
        let qualification = Arc::new(crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::new(crate::FixedClock::at(now))),
            auths_recipe_qualification::VerifierState::default(),
        ));
        crate::entry::EntryValidation::Installed(Box::new(crate::entry::InstalledEntry {
            recipe: recipe.clone(),
            trust: trust.clone(),
            observer: None,
            policy: policy.clone(),
            configuration: configuration.clone(),
            connection: crate::entry::EntryConnection::Installed(Box::new(loaded.clone())),
            connection_key: crate::connection_key(connection.provider_kind(), connection.alias()),
            qualification,
            workload: connection.allowed_workloads()[0].clone(),
            profile: connection.allowed_profiles()[0].clone(),
            started: std::time::Instant::now(),
            #[cfg(unix)]
            commissioning: None,
        }))
    };
    let attempts =
        crate::GatewayAttempts::new(Arc::clone(store), policy.clone()).expect("attempts");
    let refused = approve("release-expired", &target, false);
    assert!(
        attempts
            .claim_disclosure(&refused, NOW, validation(NOW + 61))
            .await
            .is_err()
    );
    assert!(
        attempts
            .read_disclosure(&refused)
            .await
            .expect("read")
            .is_none()
    );
    let source_operation =
        LogicalOperationId::parse(retained.source.journal_identity().1).expect("source operation");
    let source_key =
        crate::GatewayAttemptKey::for_operation(policy, recipe.namespace(), &source_operation)
            .expect("source key");
    let source_bytes = store
        .load(crate::GatewayRecordKind::Attempt, &source_key)
        .expect("load")
        .expect("source");
    let mut source_value: Value = serde_json::from_slice(&source_bytes).expect("JSON");
    source_value["state"]["facts"]["phase"]["content"]["value"]["bytes"] =
        json!(retained.bytes + 1);
    let bad_source = serde_json::to_vec(&source_value).expect("bad bytes");
    store
        .replace(
            crate::GatewayRecordKind::Attempt,
            &source_key,
            &source_bytes,
            &bad_source,
        )
        .expect("inject source");
    let changed_source = approve("release-source-changed", &target, false);
    assert!(
        attempts
            .claim_disclosure(&changed_source, NOW, validation(NOW))
            .await
            .is_err()
    );
    assert!(
        attempts
            .read_disclosure(&changed_source)
            .await
            .expect("read")
            .is_none()
    );
    store
        .replace(
            crate::GatewayRecordKind::Attempt,
            &source_key,
            &bad_source,
            &source_bytes,
        )
        .expect("restore source");
    let connection_key = crate::connection_key(connection.provider_kind(), connection.alias());
    let original_connection = connection.to_canonical_cbor().expect("connection");
    let disabled = connection
        .transition_state(ConnectionState::Disabled, NOW)
        .expect("disabled")
        .to_canonical_cbor()
        .expect("bytes");
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &original_connection,
            &disabled,
        )
        .expect("disable");
    let disabled_effect = approve("release-disabled", &target, false);
    assert!(
        attempts
            .claim_disclosure(&disabled_effect, NOW, validation(NOW))
            .await
            .is_err()
    );
    assert!(
        attempts
            .read_disclosure(&disabled_effect)
            .await
            .expect("read")
            .is_none()
    );
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &disabled,
            &original_connection,
        )
        .expect("restore connection");
    let first = approve("release-0", &target, true);
    let (one, two) = tokio::join!(
        attempts.claim_disclosure(&first, NOW, validation(NOW)),
        attempts.claim_disclosure(&first, NOW, validation(NOW))
    );
    let first_snapshot = one.expect("winner");
    assert_eq!(first_snapshot, two.expect("equal replay"));
    assert_eq!(first_snapshot.stage, crate::DisclosureStage::Reserved);
    assert_eq!(first_snapshot.reserved_deliveries, 1);
    assert_eq!(first_snapshot.reserved_bytes, retained.bytes);
    assert_eq!(first_snapshot.policy_count_counters, 1);
    assert_eq!(first_snapshot.policy_byte_counters, 1);
    let operation = LogicalOperationId::parse("release-0").expect("operation");
    let first_key = crate::GatewayAttemptKey::for_operation(policy, recipe.namespace(), &operation)
        .expect("key");
    let first_bytes = store
        .load(crate::GatewayRecordKind::Attempt, &first_key)
        .expect("load")
        .expect("record");
    let original: Value = serde_json::from_slice(&first_bytes).expect("record JSON");
    for pointer in [
        "/schema",
        "/state/protocol",
        "/state/facts/allocation",
        "/state/facts/plan/source_binding",
        "/state/facts/plan/source_contract",
        "/state/facts/plan/protected_content/0",
        "/state/facts/plan/projection/0",
        "/state/facts/plan/bytes",
        "/state/facts/plan/recipient_key/0",
        "/state/facts/phase/stage",
    ] {
        let mut changed = original.clone();
        let value = changed.pointer_mut(pointer).expect("field");
        *value = match pointer {
            "/schema" => json!("auths.gateway-attempt/14"),
            "/state/protocol" => json!("acquisition"),
            "/state/facts/allocation" => json!(16),
            "/state/facts/plan/source_binding" | "/state/facts/plan/source_contract" => json!("{}"),
            "/state/facts/phase/stage" => json!("response-recorded"),
            _ => json!(value.as_u64().expect("integer") ^ 1),
        };
        let changed = serde_json::to_vec(&changed).expect("changed record");
        store
            .replace(
                crate::GatewayRecordKind::Attempt,
                &first_key,
                &first_bytes,
                &changed,
            )
            .expect("inject mutation");
        assert!(attempts.read_disclosure(&first).await.is_err(), "{pointer}");
        store
            .replace(
                crate::GatewayRecordKind::Attempt,
                &first_key,
                &changed,
                &first_bytes,
            )
            .expect("restore record");
    }
    let ack = DisclosureAcknowledgementRequest::for_delivery(
        first.effect().binding(),
        retained.bytes,
        recipient.verifying_key().to_bytes(),
    )
    .expect("ACK");
    let ack_signature = recipient
        .sign(&ack.signing_message().expect("message"))
        .to_bytes();
    assert!(
        attempts
            .acknowledge_disclosure(
                recipe.namespace(),
                &operation,
                &ack.with_signature(ack_signature)
            )
            .await
            .is_err(),
        "a valid signature cannot invent a grant"
    );
    assert_eq!(
        store
            .load(crate::GatewayRecordKind::Attempt, &first_key)
            .expect("load")
            .expect("record"),
        first_bytes
    );
    #[cfg(unix)]
    let live_policy = {
        let uid = rustix::process::geteuid().as_raw();
        crate::effect::UnixDisclosurePolicy::new(uid, uid, [22; 32])
    };
    #[cfg(not(unix))]
    let live_policy = crate::effect::UnixDisclosurePolicy::new(0, 0, [22; 32]);
    let alternate = DisclosureTarget::new(
        retained.clone(),
        recipient.verifying_key().to_bytes(),
        live_policy.commitment().expect("channel"),
        [21; 32],
    )
    .expect("target");
    let conflict = approve("release-0", &alternate, true);
    assert!(matches!(
        attempts
            .claim_disclosure(&conflict, NOW, validation(NOW))
            .await,
        Err(crate::GatewayAttemptError::BindingConflict)
    ));
    assert!(
        attempts
            .claim_content(&first, NOW, validation(NOW))
            .await
            .is_err()
    );
    assert!(
        attempts
            .claim_recovery(&first, NOW, validation(NOW))
            .await
            .is_err()
    );
    let mut history = vec![json!({"operation": "release-0", "snapshot": first_snapshot})];
    let second = approve("release-1", &target, true);
    history.push(json!({"operation": "release-1", "snapshot": attempts.claim_disclosure(&second, NOW, validation(NOW)).await.expect("second")}));
    let policy_exhausted = approve("release-policy-exhausted", &target, true);
    let exhausted = attempts
        .claim_disclosure(&policy_exhausted, NOW, validation(NOW))
        .await
        .expect("policy refusal");
    assert_eq!(exhausted.stage, crate::DisclosureStage::NotEntered);
    assert_eq!(exhausted.reserved_deliveries, 0);
    assert_eq!(exhausted.reserved_bytes, 0);
    assert_eq!(
        exhausted.refusal.as_deref(),
        Some("gateway.policy.sum-exhausted")
    );
    history.push(json!({"operation": "release-policy-exhausted", "snapshot": exhausted}));
    for index in 2..17 {
        let operation = format!("release-{index}");
        // A changed channel still shares the source's lifetime allowance.
        let effect = approve(&operation, &alternate, false);
        let snapshot = attempts
            .claim_disclosure(&effect, NOW, validation(NOW))
            .await
            .expect("admission");
        assert_eq!(
            snapshot.stage,
            if index < 16 {
                crate::DisclosureStage::Reserved
            } else {
                crate::DisclosureStage::NotEntered
            }
        );
        assert_eq!(snapshot.reserved_deliveries, u64::from(index < 16));
        history.push(json!({"operation": operation, "snapshot": snapshot}));
    }
    let reopened = crate::GatewayAttempts::new(
        Arc::new(crate::FileGatewayAttemptStore::open(path).expect("reopen")),
        policy.clone(),
    )
    .expect("attempts");
    assert_eq!(
        reopened
            .claim_disclosure(&first, NOW, validation(NOW))
            .await
            .expect("replay"),
        first_snapshot
    );
    assert_eq!(
        store
            .load(crate::GatewayRecordKind::Attempt, &first_key)
            .expect("load")
            .expect("record"),
        first_bytes
    );
    let listed = reopened.stages(64).await.expect("list");
    let disclosures = listed
        .iter()
        .filter(|(_, stage)| matches!(stage, crate::GatewayOperationStage::Disclosure(_)))
        .count();
    assert_eq!(disclosures, 18);
    let authentication = |effect: &ApprovedEffect| {
        crate::effect::disclosure_auth::RecipientAuthentication::synthetic(
            effect.effect().binding(),
            retained.bytes,
            &recipient,
            channel_policy.clone(),
        )
    };
    let first_grant = reopened
        .synthetic_disclosure_grant(&first, NOW, false, authentication(&first))
        .await
        .expect("synthetic grant");
    let second_grant = reopened
        .synthetic_disclosure_grant(&second, NOW, true, authentication(&second))
        .await
        .expect("synthetic unknown grant");
    assert_eq!(first_grant.stage, crate::DisclosureStage::Unknown);
    assert_eq!(second_grant.stage, crate::DisclosureStage::Unknown);
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &original_connection,
            &disabled,
        )
        .expect("disable before late ACK");
    let acknowledgement = |effect: &ApprovedEffect| {
        let statement = DisclosureAcknowledgementRequest::for_delivery(
            effect.effect().binding(),
            retained.bytes,
            recipient.verifying_key().to_bytes(),
        )
        .expect("statement");
        let signature = recipient
            .sign(&statement.signing_message().expect("message"))
            .to_bytes();
        statement.with_signature(signature)
    };
    let first_ack = acknowledgement(&first);
    let second_operation = LogicalOperationId::parse("release-1").expect("operation");
    assert!(
        reopened
            .acknowledge_disclosure(recipe.namespace(), &second_operation, &first_ack)
            .await
            .is_err(),
        "valid foreign ACK cannot change unknown history"
    );
    let (left, right) = tokio::join!(
        reopened.acknowledge_disclosure(recipe.namespace(), &operation, &first_ack),
        attempts.acknowledge_disclosure(recipe.namespace(), &operation, &first_ack),
    );
    let acknowledged = left.expect("ACK");
    assert_eq!(acknowledged, right.expect("concurrent exact ACK"));
    assert_eq!(acknowledged.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(acknowledged.revision, 3);
    assert_eq!(acknowledged.reserved_bytes, first_snapshot.reserved_bytes);
    let late = reopened
        .acknowledge_disclosure(
            recipe.namespace(),
            &second_operation,
            &acknowledgement(&second),
        )
        .await
        .expect("late ACK");
    assert_eq!(late.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(late.revision, 4);
    assert_eq!(late.reserved_deliveries, 1);
    let ack_bytes = store
        .load(crate::GatewayRecordKind::Attempt, &first_key)
        .expect("load")
        .expect("ACK record");
    let again = crate::GatewayAttempts::new(
        Arc::new(crate::FileGatewayAttemptStore::open(path).expect("reopen after ACK")),
        policy.clone(),
    )
    .expect("attempts");
    assert_eq!(
        again
            .acknowledge_disclosure(recipe.namespace(), &operation, &first_ack)
            .await
            .expect("ACK replay"),
        acknowledged
    );
    assert_eq!(
        store
            .load(crate::GatewayRecordKind::Attempt, &first_key)
            .expect("load")
            .expect("ACK record"),
        ack_bytes
    );
    assert!(
        again
            .synthetic_disclosure_grant(&first, NOW, false, authentication(&first))
            .await
            .is_err(),
        "history cannot regrant"
    );
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &disabled,
            &original_connection,
        )
        .expect("restore connection");
    #[cfg(unix)]
    live_delivery::corpus(
        &attempts,
        store,
        path,
        policy,
        recipe,
        connection,
        retained.bytes,
        &recipient,
        &live_policy,
        |index, channel: &crate::effect::UnixDisclosurePolicy| {
            let target = DisclosureTarget::new(
                retained.clone(),
                recipient.verifying_key().to_bytes(),
                channel.commitment().expect("channel"),
                [21; 32],
            )
            .expect("target");
            approve(&format!("release-{index}"), &target, false)
        },
        validation,
    )
    .await;
    let public_history = serde_json::to_string(&history).expect("public history");
    for private in [
        "PRIVATE-SYNTHETIC-CONTENT",
        "commitment",
        "recipient",
        "channel",
        "source_contract",
    ] {
        assert!(!public_history.contains(private), "{private}");
    }
    let fixture = json!({"schema": "auths.gateway-disclosure-journal-fixture/1",
        "scope": "native installed file admission with real retained HTTP source; no authenticated delivery; synthetic grant assumptions only; no independent process, PostgreSQL or isolation claim",
        "expired_approval_refused": true, "changed_source_refused": true, "disabled_connection_refused": true,
        "concurrent_same_operation_one_allocation": true, "changed_binding_conflicts": true, "record_mutations_and_obsolete_schema_refused": true,
        "ack_before_grant_refused": true, "cross_protocol_refused": true,
        "reopened_replay_preserves_record": true,
        "ack_history": {"assumption": "test-only synthetic retained grants, no recipient authentication or delivery", "foreign_ack_refused": true,
            "concurrent_exact_ack_preserves_revision": true, "ack_after_connection_disable": true,
            "acknowledged": acknowledged, "late_acknowledged": late}, "history": history});
    let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/disclosure-journal.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture bytes");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &bytes).expect("write");
    }
    assert_eq!(std::fs::read(&output).expect("fixture"), bytes);
    json!({"fixture": "disclosure-journal.json", "admissions": 16, "refusals": 2, "journal_only_delivered_bytes": 0, "unix_delivery_fixture": "disclosure-delivery.json"})
}

#[cfg(unix)]
#[path = "effect_disclosure_delivery_tests.rs"]
mod live_delivery;
