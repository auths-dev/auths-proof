//! Maintenance work bounds and conservative retention in the real file adapter.
use super::*;

fn fixture() -> (tempfile::TempDir, FileGatewayAttemptStore) {
    let directory = tempfile::tempdir().expect("directory");
    let root = fs::canonicalize(directory.path())
        .expect("canonical")
        .join("records");
    let store = FileGatewayAttemptStore::open(root).expect("store");
    (directory, store)
}

fn entry(kind: GatewayRecordKind, byte: u8, expiry: Option<u64>) -> GatewayRecordEntry {
    GatewayRecordEntry {
        kind,
        key: GatewayAttemptKey::from_bytes([byte; 32]),
        record: format!("public-retention-fixture-{byte}").into_bytes(),
        expires_at: expiry,
    }
}

#[test]
fn bounded_cursor_progress_preserves_every_durable_record_kind() {
    let (directory, store) = fixture();
    let permanent: Vec<_> = [
        GatewayRecordKind::Attempt,
        GatewayRecordKind::Connection,
        GatewayRecordKind::CommissioningBudget,
        GatewayRecordKind::EffectConfiguration,
        GatewayRecordKind::EffectAllocation,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, kind)| entry(kind, u8::try_from(index).expect("small"), None))
    .collect();
    for record in &permanent {
        store.insert(record).expect("durable");
    }
    let slots: Vec<_> = (20..28)
        .map(|byte| {
            entry(
                if byte % 2 == 0 {
                    GatewayRecordKind::CountSlot
                } else {
                    GatewayRecordKind::SumSlot
                },
                byte,
                Some(if byte < 24 { 100 } else { 200 }),
            )
        })
        .collect();
    for record in &slots {
        store.insert(record).expect("slot");
    }
    assert_eq!(
        store
            .sweep_batch(100, 0, 3)
            .expect("zero deletion")
            .inspected,
        0
    );
    let mut deleted = 0;
    for _ in 0..32 {
        let batch = store.sweep_batch(100, 1, 3).expect("bounded batch");
        assert!(batch.inspected <= 3 && batch.deleted <= 1);
        deleted += batch.deleted;
        if deleted == 4 {
            break;
        }
    }
    assert_eq!(
        deleted, 4,
        "cursor advances past permanent and unexpired records"
    );
    for record in &slots[4..] {
        assert_eq!(
            store.load(record.kind, &record.key).expect("future slot"),
            Some(record.record.clone())
        );
    }
    drop(store); // Cursor is deliberately not persisted; authority is persisted.
    let reopened = FileGatewayAttemptStore::open(
        fs::canonicalize(directory.path())
            .expect("canonical")
            .join("records"),
    )
    .expect("reopen");
    let mut deleted = 0;
    for _ in 0..32 {
        let batch = reopened
            .sweep_batch(200, 2, 3)
            .expect("bounded inclusive expiry");
        assert!(batch.inspected <= 3 && batch.deleted <= 2);
        deleted += batch.deleted;
        if deleted == 4 {
            break;
        }
    }
    assert_eq!(deleted, 4);
    for record in &permanent {
        assert_eq!(
            reopened.load(record.kind, &record.key).expect("retained"),
            Some(record.record.clone())
        );
    }
    assert_eq!(reopened.sweep_expired(u64::MAX, 100), Ok(0));
}

#[test]
fn corrupt_slot_is_not_treated_as_expired_or_absent() {
    let (_directory, store) = fixture();
    let record = entry(GatewayRecordKind::CountSlot, 42, Some(100));
    store.insert(&record).expect("slot");
    fs::write(store.path_for(record.kind, &record.key), b"invalid-slot").expect("damage");
    assert!(matches!(
        store.sweep_expired(1000, 100),
        Err(GatewayAttemptError::Corrupt)
    ));
    assert!(matches!(
        store.load(record.kind, &record.key),
        Err(GatewayAttemptError::Corrupt)
    ));
    assert!(store.path_for(record.kind, &record.key).exists());
}
