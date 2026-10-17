//! Frozen complete record validation and real canonical decoder parity.
use super::*;

fn original_validate(record: &ConnectionRecord) -> Result<(), ConnectionRecordError> {
    if !(1..=MAX_WORKLOADS).contains(&record.allowed_workloads.len())
        || !original_order(&record.allowed_workloads)
        || record
            .allowed_workloads
            .iter()
            .any(|value| !is_ascii_graphic(value, 128))
    {
        return Err(ConnectionRecordError::InvalidWorkloads);
    }
    if !(1..=MAX_PROFILES).contains(&record.allowed_profiles.len())
        || !original_order(&record.allowed_profiles)
    {
        return Err(ConnectionRecordError::InvalidProfiles);
    }
    if record.created_at_unix_seconds > record.updated_at_unix_seconds {
        return Err(ConnectionRecordError::InvalidTimestamps);
    }
    match (record.state, record.revoked_at_unix_seconds) {
        (ConnectionState::Revoked, Some(value))
            if (record.created_at_unix_seconds..=record.updated_at_unix_seconds)
                .contains(&value) => {}
        (ConnectionState::Revoked, _) | (_, Some(_)) => {
            return Err(ConnectionRecordError::InvalidTimestamps);
        }
        _ => {}
    }
    Ok(())
}

#[test]
fn complete_record_times_preserve_validation_and_decoder_behavior() {
    let values = [0, 1, 2, u64::MAX - 1, u64::MAX];
    let revocations = [
        None,
        Some(0),
        Some(1),
        Some(2),
        Some(u64::MAX - 1),
        Some(u64::MAX),
    ];
    let mut accepted = 0;
    let mut refused = 0;
    for state in [
        ConnectionState::Active,
        ConnectionState::Disabled,
        ConnectionState::Revoked,
    ] {
        for created in values {
            for updated in values {
                for revoked in revocations {
                    let mut record = super::tests::record();
                    record.state = state;
                    record.created_at_unix_seconds = created;
                    record.updated_at_unix_seconds = updated;
                    record.revoked_at_unix_seconds = revoked;
                    let expected = original_validate(&record);
                    assert_eq!(record.validate(), expected);
                    let bytes = record.to_canonical_cbor().unwrap();
                    match ConnectionRecord::from_canonical_cbor(&bytes) {
                        Ok(decoded) => {
                            assert_eq!(expected, Ok(()));
                            assert_eq!(decoded, record);
                            accepted += 1;
                        }
                        Err(error) => {
                            assert_eq!(expected, Err(error));
                            refused += 1;
                        }
                    }
                }
            }
        }
    }
    // Two non-revoked states * fifteen ordered pairs, plus thirty-five
    // created/revoked/updated triples with repetition among five values.
    assert_eq!((accepted, refused), (65, 385));
}

fn original_order<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
