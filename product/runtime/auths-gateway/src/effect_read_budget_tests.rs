//! Native managed read budgets over the real file journal. Entry uses the
//! explicit-time test oracle; these histories make no provider or PG claim.
use super::*;
use crate::effect::{ApprovedEffect, RecoveryReadTarget, compile_recovery_acquisition};
use crate::entry::EntryValidation::Oracle;
use crate::store::{AcquisitionClaim, AcquisitionStage, BoundedClaim};
use crate::{ArgumentCeilingPolicy, GatewayAttemptStore};
use base64ct::Base64;
use std::sync::Arc;

pub(super) fn read_grant(
    root: &Signer,
    reader: &Signer,
    call: &McpToolCall,
    policy: &ArgumentCeilingPolicy,
) -> SignedGrant {
    let extension = CriticalExtension::new(
        ExtensionId::parse(auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1).expect("ID"),
        policy.extension_body(None).expect("policy"),
    )
    .expect("extension");
    let statement = GrantStatement::new(
        root.principal.clone(),
        reader.principal.clone(),
        call.profile_ref().expect("profile"),
        PermissionSet::new(vec![call.permission().expect("permission")]).expect("permissions"),
        window(NOW - 3_600, NOW + 3_600),
        AudienceSet::new(vec![audience()]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        CriticalExtensions::new(vec![extension]).expect("extensions"),
    );
    let descriptor = root.descriptor();
    let signature = root.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
    SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded policy admission/restart history produces the native corpus"
)]
pub(super) async fn corpus(
    source: &Arc<ApprovedEffect>,
    target: &RecoveryReadTarget,
    installed: &EffectInstallation<'_>,
    policy: &EffectPolicy,
    root: &Signer,
) -> Value {
    let mut cases = Vec::new();
    for (name, max_count, sum_calls) in [
        ("count", 1, None),
        ("sum", 4, Some(1)),
        ("sum-predecessor", 4, Some(2)),
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let path = std::fs::canonicalize(directory.path())
            .expect("path")
            .join("journal");
        let store = Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("store"));
        let attempts =
            crate::GatewayAttempts::new(store.clone(), policy.clone()).expect("attempts");
        let BoundedClaim::Claimed(claim) = attempts
            .claim_bounded(source, NOW, Oracle { now: NOW })
            .await
            .expect("source claim")
        else {
            panic!("source");
        };
        let (_, permit) = claim
            .grant_entry(
                source.clone(),
                Oracle { now: NOW },
                NOW,
                &crate::GatewayPreEntry::default(),
            )
            .await
            .expect("source grant");
        drop(permit);
        let reader = signer(0x33);
        let key = SigningKey::from_bytes(&[29; 32]);
        let public = key.verifying_key().to_bytes();
        let maximum = target.closed_request().maximum_response_bytes() as u64;
        let mut bound =
            ArgumentCeilingPolicy::new("maximum_response_bytes", maximum, 3_600, max_count)
                .expect("bound");
        if let Some(calls) = sum_calls {
            bound = bound.with_sum(calls * maximum, None).expect("sum");
        }
        let probe = target
            .authorization_call(
                installed.recipe,
                &LogicalOperationId::parse("budget-policy-probe").expect("operation"),
            )
            .expect("call");
        let mut rejected_policies = Vec::new();
        for (name, candidate) in [
            (
                "different-argument",
                ArgumentCeilingPolicy::new("amount", maximum, 3_600, 1).expect("policy"),
            ),
            (
                "response-above-ceiling",
                ArgumentCeilingPolicy::new("maximum_response_bytes", maximum - 1, 3_600, 1)
                    .expect("policy"),
            ),
            (
                "response-above-sum",
                ArgumentCeilingPolicy::new("maximum_response_bytes", maximum, 3_600, 1)
                    .expect("policy")
                    .with_sum(maximum - 1, None)
                    .expect("sum"),
            ),
        ] {
            let grant = read_grant(root, &reader, &probe, &candidate);
            let submission = submission_for_call(root, &reader, &grant, &probe, &[]);
            assert!(
                compile_recovery_acquisition(
                    installed,
                    target,
                    NOW + 2,
                    &submission.proof,
                    &submission.action
                )
                .is_err(),
                "{name}"
            );
            rejected_policies.push(name);
        }
        let compile = |operation: &str, now: u64| {
            let call = target
                .authorization_call(
                    installed.recipe,
                    &LogicalOperationId::parse(operation).expect("operation"),
                )
                .expect("call");
            let grant = read_grant(root, &reader, &call, &bound);
            let submission = submission_for_call(root, &reader, &grant, &call, &[]);
            let effect = compile_recovery_acquisition(
                installed,
                target,
                now,
                &submission.proof,
                &submission.action,
            )
            .expect("bounded read");
            let request = effect.approval_request(now, now + 1_000).expect("approval");
            let signature = key
                .sign(&request.signing_message().expect("message"))
                .to_bytes();
            Arc::new(
                effect
                    .approve(request.with_signature(signature), &public, now)
                    .expect("approved"),
            )
        };
        let prior_slots = u64::from(sum_calls == Some(2));
        if prior_slots == 1 {
            let prefix = compile("budget-prefix", NOW + 2);
            let AcquisitionClaim::Reserved(handle) = attempts
                .claim_recovery(&prefix, NOW + 2, Oracle { now: NOW + 2 })
                .await
                .expect("prefix")
            else {
                panic!("prefix reservation");
            };
            let (_, permit) = handle
                .grant_entry(prefix, Oracle { now: NOW + 2 }, NOW + 2)
                .await
                .expect("prefix grant");
            drop(permit);
        }
        let reads = [
            compile("budget-read-1", NOW + 2),
            compile("budget-read-2", NOW + 2),
        ];
        let compiled = reads[0].acquisition_bound().expect("managed budget");
        assert_eq!(compiled.argument, maximum);
        assert_eq!(compiled.counts.len(), 1);
        assert_eq!(compiled.sums.len(), usize::from(sum_calls.is_some()));
        assert_ne!(
            compiled.counts[0].key,
            crate::bounds::count_counter_key(
                installed.recipe.namespace(),
                &reader.principal,
                3_600,
                (NOW + 2) / 3_600
            )
        );
        if let Some(sum) = compiled.sums.first() {
            assert_ne!(
                sum.key,
                crate::bounds::sum_counter_key(
                    installed.recipe.namespace(),
                    &reader.principal,
                    "",
                    3_600,
                    (NOW + 2) / 3_600
                )
            );
        }
        let (first, second) = tokio::join!(
            attempts.claim_recovery(&reads[0], NOW + 2, Oracle { now: NOW + 2 }),
            attempts.claim_recovery(&reads[1], NOW + 2, Oracle { now: NOW + 2 }),
        );
        let mut winners = Vec::new();
        let mut refused = Vec::new();
        for (index, result) in [first, second].into_iter().enumerate() {
            match result.expect("atomic admission") {
                AcquisitionClaim::Reserved(handle) => winners.push((index, handle)),
                AcquisitionClaim::Existing(snapshot) => {
                    assert_eq!(snapshot.stage, AcquisitionStage::NotEntered);
                    assert_eq!(snapshot.reserved_calls, 0);
                    assert_eq!(snapshot.reserved_bytes, 0);
                    refused.push(snapshot);
                }
            }
        }
        assert_eq!(winners.len(), 1, "one final capacity winner");
        assert_eq!(refused.len(), 1);
        let (winner, handle) = winners.pop().expect("winner");
        let approved = &reads[winner];
        let compiled = approved.acquisition_bound().expect("bound");
        let counter_key = crate::GatewayAttemptKey::from_bytes(crate::bounds::count_slot_key(
            &compiled.counts[0].key,
            prior_slots,
        ));
        let original = store
            .load(crate::GatewayRecordKind::CountSlot, &counter_key)
            .expect("load")
            .expect("slot");
        let row: Value = serde_json::from_slice(&original).expect("slot");
        let changed = std::str::from_utf8(&original)
            .expect("UTF-8")
            .replace(row["claim"].as_str().expect("claim"), &"00".repeat(32));
        // Slots are deliberately immutable through the adapter. Inject storage
        // corruption directly, preserving a canonical row with a wrong claim.
        let slot_path = path.join(format!("slot-{}.json", hex::encode(counter_key.as_bytes())));
        let original_file = std::fs::read(&slot_path).expect("slot file");
        let mut envelope: Value = serde_json::from_slice(&original_file).expect("envelope");
        envelope["record_b64"] = json!(Base64::encode_string(changed.as_bytes()));
        std::fs::write(&slot_path, serde_json::to_vec(&envelope).expect("envelope"))
            .expect("inject");
        assert!(
            handle
                .grant_entry(approved.clone(), Oracle { now: NOW + 3 }, NOW + 3)
                .await
                .is_err(),
            "substituted membership denies entry"
        );
        std::fs::write(&slot_path, original_file).expect("restore");
        let AcquisitionClaim::Reserved(handle) = attempts
            .claim_recovery(approved, NOW + 3, Oracle { now: NOW + 3 })
            .await
            .expect("reopen")
        else {
            panic!("reserved");
        };
        let boundary = compiled.window_end;
        assert!(
            approved.validate_for_entry(installed, boundary).is_err(),
            "new window recompiles a different exact binding"
        );
        assert!(
            handle
                .grant_entry(approved.clone(), Oracle { now: boundary }, boundary)
                .await
                .is_err(),
            "expired fixed window denies oracle entry too"
        );
        let AcquisitionClaim::Reserved(handle) = attempts
            .claim_recovery(approved, NOW + 3, Oracle { now: NOW + 3 })
            .await
            .expect("reopen")
        else {
            panic!("reserved");
        };
        let (_, permit) = handle
            .grant_entry(approved.clone(), Oracle { now: NOW + 3 }, NOW + 3)
            .await
            .expect("read grant");
        drop(permit);
        let attempts = crate::GatewayAttempts::new(
            Arc::new(crate::FileGatewayAttemptStore::open(&path).expect("reopen store")),
            policy.clone(),
        )
        .expect("attempts");
        let AcquisitionClaim::Existing(retained) = attempts
            .claim_recovery(approved, NOW + 4, Oracle { now: NOW + 4 })
            .await
            .expect("replay")
        else {
            panic!("history only");
        };
        assert_eq!(retained.stage, AcquisitionStage::Unknown);
        assert_eq!(retained.reserved_calls, 1);
        assert_eq!(retained.reserved_bytes, maximum);
        let third = compile("budget-read-3", NOW + 4);
        let AcquisitionClaim::Existing(exhausted) = attempts
            .claim_recovery(&third, NOW + 4, Oracle { now: NOW + 4 })
            .await
            .expect("exhaustion")
        else {
            panic!("unknown retains charge");
        };
        assert_eq!(exhausted.stage, AcquisitionStage::NotEntered);
        assert_eq!(exhausted.reserved_calls, 0);
        let next = compile("budget-next-window", boundary);
        let AcquisitionClaim::Reserved(next) = attempts
            .claim_recovery(&next, boundary, Oracle { now: boundary })
            .await
            .expect("new window")
        else {
            panic!("fresh approved window");
        };
        assert_eq!(next.snapshot().expect("snapshot").reserved_calls, 1);
        cases.push(json!({"limit": name, "maximum_response_bytes": maximum,
            "prior_unknown_operations": prior_slots, "winning_operations": 1, "uncharged_refusals": refused, "retained_after_restart": retained,
            "substituted_membership_refused": true, "old_window_entry_refused": true,
            "new_window_requires_new_binding_and_approval": true,
            "mutation_counter_identity_distinct": true, "unknown_keeps_policy_charge": true,
            "rejected_policies": rejected_policies}));
    }
    json!({"schema": "auths.gateway-recovery-policy-budget-fixture/1", "scope": "native signed bounded read compilation; real file concurrent admission and restart; oracle entry; no provider or PostgreSQL claim", "cases": cases})
}
