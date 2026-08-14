use auths_bounded_policy::{CommitmentDigest, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, ExecutionIntentV1, LifecycleState, ProviderConditionDigest,
    ProviderContractId, ProviderRequestDigest, ProviderResultDigest, ProviderRetryClass,
    test_support::{CAPACITY_SCOPE, context, decision},
};
use auths_runtime::production::{
    InMemoryRecoveryStore, LifecycleCoordinator, RecoveryReferenceError, RecoveryReferenceSource,
    TrustedClock,
};
use auths_stores::{InMemoryLifecycleStore, LifecycleCapacityRuleV1};

#[derive(Clone, Copy)]
struct FixedClock;

impl TrustedClock for FixedClock {
    fn now(&self) -> VerifierTime {
        VerifierTime::from_unix_seconds(10)
    }
}

#[derive(Clone, Copy)]
struct FixedRandomness;

impl RecoveryReferenceSource for FixedRandomness {
    fn fill(&self, output: &mut [u8; 32]) -> Result<(), RecoveryReferenceError> {
        *output = [42; 32];
        Ok(())
    }
}

fn coordinator()
-> LifecycleCoordinator<InMemoryLifecycleStore, InMemoryRecoveryStore, FixedClock, FixedRandomness>
{
    let lifecycle = InMemoryLifecycleStore::new(
        vec![LifecycleCapacityRuleV1::Additive {
            scope_digest: CAPACITY_SCOPE,
            window_digest: None,
            unit: auths_bounded_policy::UnitId::parse("requests").unwrap(),
            ceiling: 10,
        }],
        10,
    )
    .unwrap();
    LifecycleCoordinator::with_dependencies(
        lifecycle,
        InMemoryRecoveryStore::new(10).unwrap(),
        FixedClock,
        FixedRandomness,
    )
}

#[test]
fn coordinator_orders_every_effect_capable_stage() {
    let coordinator = coordinator();
    let (reference, decision_stage) = coordinator
        .begin(decision("production-workflow", Some(1)), context(10))
        .unwrap();
    let reserved = coordinator.reserve(decision_stage, context(11)).unwrap();
    let intent = ExecutionIntentV1::new(
        CommitmentDigest::new([20; 32]),
        ProviderRequestDigest::new([21; 32]),
        ProviderConditionDigest::new([22; 32]),
        ProviderContractId::parse("auths.test.provider/1").unwrap(),
        ProviderRetryClass::ObserveBeforeRetry,
    );
    let intent = coordinator
        .record_intent(reserved, intent, context(12))
        .unwrap();
    let credential = coordinator
        .authorize_credential(intent, context(13))
        .unwrap();
    assert_eq!(credential.authorization().revision(), 4);
    let attempt = coordinator.start_attempt(credential, context(14)).unwrap();
    let provider = coordinator.enter_provider(attempt, context(15)).unwrap();
    assert_eq!(
        provider.authorization().provider_request_digest(),
        ProviderRequestDigest::new([21; 32])
    );
    let terminal = coordinator
        .commit(
            provider,
            ProviderResultDigest::new([23; 32]),
            DomainReceiptDigest::new([24; 32]),
            context(16),
        )
        .unwrap();
    assert_eq!(terminal.record().state(), LifecycleState::Committed);
    assert_eq!(
        coordinator.status(&reference).unwrap().state(),
        LifecycleState::Committed
    );
}

#[test]
fn recovery_reference_cannot_be_swapped_between_workflows() {
    let coordinator = coordinator();
    let (reference, _) = coordinator
        .begin(decision("production-workflow", Some(1)), context(10))
        .unwrap();
    let encoded = reference.to_url_token();
    let mut changed = encoded.into_bytes();
    changed[0] = if changed[0] == b'A' { b'B' } else { b'A' };
    let changed = String::from_utf8(changed).unwrap();
    let changed =
        auths_runtime::production::OpaqueRecoveryReference::parse_url_token(&changed).unwrap();
    assert!(coordinator.status(&changed).is_err());
}
