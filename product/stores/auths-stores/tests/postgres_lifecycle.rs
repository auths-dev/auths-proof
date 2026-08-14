use auths_bounded_policy::{
    BoundedOutputs, CommitmentDigest, IntentId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, UnitId,
};
use auths_lifecycle::{
    LifecycleFailure, LifecycleState, ReservationSetV1, StoreError, StoreTransactionV1,
    TransitionCommandV1, TransitionDisposition, WorkflowId, execute_store_transaction,
    test_support::{CAPACITY_SCOPE, decision, decision_transaction, transaction},
};
use auths_stores::{
    LifecycleCapacityRuleV1, PostgresLifecycleStore, PostgresPoolConfig, PostgresServerName,
    PostgresStoreConfig, PostgresTlsConfig, SecretConnectionString,
};
use postgres::{Client, Config, config::SslMode};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use std::{
    path::PathBuf,
    str::FromStr as _,
    sync::{Arc, Barrier},
    time::Duration,
};
use tokio_postgres_rustls::MakeRustlsConnect;

const SECOND_CAPACITY_SCOPE: CommitmentDigest = CommitmentDigest::new([32; 32]);

fn configured() -> bool {
    [
        "AUTHS_POSTGRES_URL",
        "AUTHS_POSTGRES_CA_PEM",
        "AUTHS_POSTGRES_SERVER_NAME",
    ]
    .iter()
    .all(|name| std::env::var_os(name).is_some())
}

fn configuration() -> PostgresStoreConfig {
    configuration_with_pool(PostgresPoolConfig::default())
}

fn configuration_with_pool(pool: PostgresPoolConfig) -> PostgresStoreConfig {
    PostgresStoreConfig::new(
        SecretConnectionString::new(std::env::var("AUTHS_POSTGRES_URL").unwrap()).unwrap(),
        PostgresTlsConfig::new(
            PathBuf::from(std::env::var("AUTHS_POSTGRES_CA_PEM").unwrap()),
            PostgresServerName::parse(std::env::var("AUTHS_POSTGRES_SERVER_NAME").unwrap())
                .unwrap(),
        ),
        pool,
        2_048,
        rules(),
    )
    .unwrap()
}

fn short_pool() -> PostgresPoolConfig {
    PostgresPoolConfig::new(
        1,
        1,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_millis(50),
        Duration::from_secs(2),
    )
    .unwrap()
}

fn admin_client() -> Client {
    let config = Config::from_str(&std::env::var("AUTHS_POSTGRES_URL").unwrap()).unwrap();
    assert_eq!(config.get_ssl_mode(), SslMode::Require);
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(std::env::var("AUTHS_POSTGRES_CA_PEM").unwrap()).unwrap()
    {
        roots.add(certificate.unwrap()).unwrap();
    }
    config
        .connect(MakeRustlsConnect::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .unwrap()
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

fn clean() {
    let mut client = admin_client();
    client
        .batch_execute(
            "DROP TABLE IF EXISTS auths_recovery_leases;
             DROP TABLE IF EXISTS auths_recovery_references;
             DROP TABLE IF EXISTS auths_lifecycle_records;
             DROP TABLE IF EXISTS auths_lifecycle_store_meta;",
        )
        .unwrap();
}

fn assert_final_capacity() {
    let first = Arc::new(PostgresLifecycleStore::connect(configuration()).unwrap());
    let second = Arc::new(PostgresLifecycleStore::connect(configuration()).unwrap());
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

fn assert_restart_replay_and_conflict() {
    let reopened = PostgresLifecycleStore::connect(configuration()).unwrap();
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

fn assert_transaction_abort() {
    let reopened = PostgresLifecycleStore::connect(configuration()).unwrap();
    let mut admin = admin_client();
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

fn assert_multi_intent_reservation_is_atomic() {
    clean();
    let store = PostgresLifecycleStore::connect(configuration()).unwrap();
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

fn assert_thousand_deliveries_across_three_hosts() {
    clean();
    let stores = Arc::new([
        PostgresLifecycleStore::connect(configuration()).unwrap(),
        PostgresLifecycleStore::connect(configuration()).unwrap(),
        PostgresLifecycleStore::connect(configuration()).unwrap(),
    ]);
    for index in 0..100 {
        let workflow = format!("delivery-{index:03}");
        execute_store_transaction(
            &stores[index % stores.len()],
            &decision_transaction(&workflow, Some(1)),
        )
        .unwrap();
    }
    let handles = (0..stores.len())
        .map(|host| {
            let stores = Arc::clone(&stores);
            std::thread::spawn(move || {
                for delivery in (host..1_000).step_by(stores.len()) {
                    let workflow = format!("delivery-{:03}", delivery % 100);
                    execute_store_transaction(
                        &stores[host],
                        &transaction(
                            &workflow,
                            Some(1),
                            TransitionCommandV1::RecordDecision(Box::new(decision(
                                &workflow,
                                Some(1),
                            ))),
                            10,
                        ),
                    )
                    .unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
    for index in [0, 49, 99] {
        let workflow = WorkflowId::parse(&format!("delivery-{index:03}")).unwrap();
        assert!(
            stores[index % stores.len()]
                .load(&workflow)
                .unwrap()
                .is_some()
        );
    }
}

fn assert_corruption_and_schema_drift_fail_closed() {
    clean();
    let store = PostgresLifecycleStore::connect(configuration()).unwrap();
    execute_store_transaction(&store, &decision_transaction("workflow-corrupt", Some(1))).unwrap();
    let mut admin = admin_client();
    admin
        .execute(
            "UPDATE auths_lifecycle_records
             SET record_sha256 = decode(repeat('00', 32), 'hex')
             WHERE workflow_id = 'workflow-corrupt'",
            &[],
        )
        .unwrap();
    assert!(matches!(
        store.load(&WorkflowId::parse("workflow-corrupt").unwrap()),
        Err(StoreError::Corrupt)
    ));

    clean();
    let store = PostgresLifecycleStore::connect(configuration()).unwrap();
    admin
        .batch_execute(
            "ALTER TABLE auths_lifecycle_store_meta
               DROP CONSTRAINT auths_lifecycle_store_meta_contract_id_check;
             UPDATE auths_lifecycle_store_meta
               SET contract_id = 'auths.lifecycle.transactional-store/invalid';",
        )
        .unwrap();
    assert!(matches!(store.probe(), Err(StoreError::SchemaMismatch)));
}

fn assert_pool_and_lock_deadlines_fail_closed() {
    clean();
    let store = PostgresLifecycleStore::connect(configuration_with_pool(short_pool())).unwrap();
    let mut admin = admin_client();
    let mut blocker = admin.transaction().unwrap();
    blocker
        .query_one(
            "SELECT contract_id
             FROM auths_lifecycle_store_meta
             WHERE singleton = TRUE
             FOR UPDATE",
            &[],
        )
        .unwrap();
    assert!(matches!(
        execute_store_transaction(
            &store,
            &decision_transaction("workflow-lock-timeout", Some(1))
        ),
        Err(StoreError::Timeout)
    ));
    blocker.rollback().unwrap();
}

#[test]
#[ignore = "requires TLS PostgreSQL environment slots and a dedicated empty database"]
fn multi_process_capacity_restart_replay_and_abort_are_atomic() {
    assert!(
        configured(),
        "TLS PostgreSQL environment slots are required"
    );
    clean();

    assert_final_capacity();
    assert_restart_replay_and_conflict();
    assert_transaction_abort();
    assert_multi_intent_reservation_is_atomic();
    assert_thousand_deliveries_across_three_hosts();
    assert_corruption_and_schema_drift_fail_closed();
    assert_pool_and_lock_deadlines_fail_closed();
    clean();
}
