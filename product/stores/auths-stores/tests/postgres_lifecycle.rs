use auths_bounded_policy::{
    BoundedOutputs, CommitmentDigest, IntentId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, UnitId,
};
use auths_lifecycle::{
    LifecycleFailure, LifecycleState, ReservationSetV1, StoreError, StoreTransactionV1,
    TransitionCommandV1, TransitionDisposition, WorkflowId, execute_store_transaction,
    test_support::{CAPACITY_SCOPE, decision, decision_transaction, transaction},
};
use auths_stores::{LifecycleCapacityRuleV1, PostgresLifecycleStore};
use postgres::{Client, NoTls};
use std::sync::{Arc, Barrier};

const CONNECTION_ENV: &str = "AUTHS_LIFECYCLE_POSTGRES_URL";
const SECOND_CAPACITY_SCOPE: CommitmentDigest = CommitmentDigest::new([32; 32]);

fn connection_string() -> Option<String> {
    std::env::var(CONNECTION_ENV).ok()
}

fn rules() -> Vec<LifecycleCapacityRuleV1> {
    vec![
        LifecycleCapacityRuleV1::Additive {
            scope_digest: CAPACITY_SCOPE,
            window_digest: None,
            unit: UnitId::parse("requests").unwrap(),
            ceiling: 10,
        },
        LifecycleCapacityRuleV1::Additive {
            scope_digest: SECOND_CAPACITY_SCOPE,
            window_digest: None,
            unit: UnitId::parse("seats").unwrap(),
            ceiling: 1,
        },
    ]
}

fn clean(connection: &str) {
    let mut client = Client::connect(connection, NoTls).unwrap();
    client
        .batch_execute(
            "DROP TABLE IF EXISTS auths_lifecycle_records;
             DROP TABLE IF EXISTS auths_lifecycle_store_meta;",
        )
        .unwrap();
}

fn assert_final_capacity(connection: &str) {
    let first = Arc::new(PostgresLifecycleStore::connect(connection, rules(), 16).unwrap());
    let second = Arc::new(PostgresLifecycleStore::connect(connection, rules(), 16).unwrap());
    for (store, workflow) in [(&first, "workflow-1"), (&second, "workflow-2")] {
        execute_store_transaction(store.as_ref(), &decision_transaction(workflow, Some(6)))
            .unwrap();
    }

    let barrier = Arc::new(Barrier::new(3));
    let handles = [(&first, "workflow-1"), (&second, "workflow-2")].map(|(store, workflow)| {
        let store = Arc::clone(store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            execute_store_transaction(
                &*store,
                &transaction(workflow, Some(1), TransitionCommandV1::Reserve, 11),
            )
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded))
            ))
            .count(),
        1
    );
}

fn assert_restart_replay_and_conflict(connection: &str) {
    let reopened = PostgresLifecycleStore::connect(connection, rules(), 16).unwrap();
    let first_record = reopened
        .load(&WorkflowId::parse("workflow-1").unwrap())
        .unwrap()
        .unwrap();
    let second_record = reopened
        .load(&WorkflowId::parse("workflow-2").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        [first_record.state(), second_record.state()]
            .into_iter()
            .filter(|state| *state == LifecycleState::Reserved)
            .count(),
        1
    );

    let mut replay = decision_transaction("workflow-1", Some(6));
    replay.expected_revision = Some(first_record.revision());
    let replayed = execute_store_transaction(&reopened, &replay).unwrap();
    assert_eq!(replayed.disposition(), TransitionDisposition::ExactReplay);

    let mut conflict = decision_transaction("workflow-1", Some(5));
    conflict.expected_revision = Some(first_record.revision());
    assert!(matches!(
        execute_store_transaction(&reopened, &conflict),
        Err(StoreError::Rejected(LifecycleFailure::Conflict))
    ));
}

fn assert_transaction_abort(connection: &str) {
    let reopened = PostgresLifecycleStore::connect(connection, rules(), 16).unwrap();
    let mut admin = Client::connect(connection, NoTls).unwrap();
    admin
        .batch_execute(
            "CREATE OR REPLACE FUNCTION auths_test_abort_lifecycle_write()
             RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               RAISE EXCEPTION 'injected transaction abort';
             END;
             $$;
             CREATE TRIGGER auths_test_abort_lifecycle_write
             BEFORE INSERT ON auths_lifecycle_records
             FOR EACH ROW EXECUTE FUNCTION auths_test_abort_lifecycle_write();",
        )
        .unwrap();
    assert!(matches!(
        execute_store_transaction(
            &reopened,
            &decision_transaction("workflow-aborted", Some(1))
        ),
        Err(StoreError::Unavailable)
    ));
    assert!(
        reopened
            .load(&WorkflowId::parse("workflow-aborted").unwrap())
            .unwrap()
            .is_none()
    );
    admin
        .batch_execute(
            "DROP TRIGGER auths_test_abort_lifecycle_write ON auths_lifecycle_records;
             DROP FUNCTION auths_test_abort_lifecycle_write();",
        )
        .unwrap();
    execute_store_transaction(
        &reopened,
        &decision_transaction("workflow-aborted", Some(1)),
    )
    .unwrap();
}

fn two_intent_decision_transaction(workflow: &str) -> StoreTransactionV1 {
    let mut input = decision(workflow, None);
    let intents = [
        ("request-capacity", CAPACITY_SCOPE, "requests", 4_u64),
        ("seat-capacity", SECOND_CAPACITY_SCOPE, "seats", 2_u64),
    ]
    .into_iter()
    .map(|(intent_id, scope, unit, amount)| {
        ReservationIntentCommitmentV1::new(
            SchemaId::parse("auths.test.reservation/1").unwrap(),
            IntentId::parse(intent_id).unwrap(),
            scope,
            ReservationKind::additive(UnitId::parse(unit).unwrap(), amount).unwrap(),
            None,
            CommitmentDigest::new([1; 32]),
            CommitmentDigest::new([2; 32]),
            CommitmentDigest::new([3; 32]),
            CommitmentDigest::new([31; 32]),
            64,
        )
        .unwrap()
    })
    .collect::<Vec<_>>();
    input.outputs = BoundedOutputs::new(
        intents,
        Vec::new(),
        CommitmentDigest::new([5; 32]),
        CommitmentDigest::new([6; 32]),
    )
    .unwrap();
    input.reservations = ReservationSetV1::derive(
        &input.workflow_id,
        &input.domain_id,
        input.commitments.profile_id(),
        input
            .commitments
            .policy_commitment()
            .evaluator_semantic_id(),
        &input.executor_audience,
        &input.reservation_algebra_id,
        &input.outputs,
    )
    .unwrap();
    StoreTransactionV1 {
        workflow_id: input.workflow_id.clone(),
        expected_revision: None,
        command: TransitionCommandV1::RecordDecision(Box::new(input)),
        context: auths_lifecycle::test_support::context(10),
    }
}

fn assert_multi_intent_reservation_is_atomic(connection: &str) {
    clean(connection);
    let store = PostgresLifecycleStore::connect(connection, rules(), 16).unwrap();
    execute_store_transaction(&store, &two_intent_decision_transaction("workflow-multi")).unwrap();
    assert!(matches!(
        execute_store_transaction(
            &store,
            &transaction("workflow-multi", Some(1), TransitionCommandV1::Reserve, 11)
        ),
        Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded))
    ));
    assert_eq!(
        store
            .load(&WorkflowId::parse("workflow-multi").unwrap())
            .unwrap()
            .unwrap()
            .state(),
        LifecycleState::DecisionRecorded
    );
    execute_store_transaction(
        &store,
        &decision_transaction("workflow-after-multi", Some(10)),
    )
    .unwrap();
    execute_store_transaction(
        &store,
        &transaction(
            "workflow-after-multi",
            Some(1),
            TransitionCommandV1::Reserve,
            11,
        ),
    )
    .unwrap();
}

#[test]
#[ignore = "requires AUTHS_LIFECYCLE_POSTGRES_URL and a dedicated PostgreSQL database"]
fn multi_process_capacity_restart_replay_and_abort_are_atomic() {
    let Some(connection) = connection_string() else {
        panic!("{CONNECTION_ENV} must identify a dedicated PostgreSQL test database");
    };
    clean(&connection);

    assert_final_capacity(&connection);
    assert_restart_replay_and_conflict(&connection);
    assert_transaction_abort(&connection);
    assert_multi_intent_reservation_is_atomic(&connection);
    clean(&connection);
}
