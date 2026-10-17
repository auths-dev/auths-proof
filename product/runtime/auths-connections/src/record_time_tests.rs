//! Frozen complete record validation and real canonical decoder parity.
use super::*;

fn original_validate(record: &ConnectionRecord) -> Result<(), ConnectionRecordError> {
    if !(1..=MAX_WORKLOADS).contains(&record.allowed_workloads.len())
        || !original_order(&record.allowed_workloads)
        || record.allowed_workloads.iter().any(|value| {
            !(1..=128).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic())
        })
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

#[test]
fn complete_record_shape_preserves_all_guards_and_error_precedence() {
    let profile = |name: &str, version| {
        ConnectionProfile::new(SemanticId::parse(name).unwrap(), version).unwrap()
    };
    let workloads = [
        vec![],
        vec!["a".to_owned()],
        vec!["a".to_owned(), "b".to_owned()],
        vec!["b".to_owned(), "a".to_owned()],
        vec!["a".to_owned(), "a".to_owned()],
        vec![String::new()],
        vec!["a b".to_owned()],
        vec!["é".to_owned()],
        vec!["a".repeat(128)],
        vec!["a".repeat(129)],
        (0..256).map(|n| format!("w-{n:03}")).collect(),
        (0..257).map(|n| format!("w-{n:03}")).collect(),
    ];
    let profiles = [
        vec![],
        vec![profile("a", 1)],
        vec![profile("a", 1), profile("a", 2)],
        vec![profile("a", 2), profile("a", 1)],
        vec![profile("a", 1), profile("a", 1)],
        (0..31).map(|n| profile(&format!("p-{n:02}"), 1)).collect(),
        (0..32).map(|n| profile(&format!("p-{n:02}"), 1)).collect(),
        (0..33).map(|n| profile(&format!("p-{n:02}"), 1)).collect(),
    ];
    let times = [0, 1, 2, u64::MAX - 1, u64::MAX];
    let revocations = [
        None,
        Some(0),
        Some(1),
        Some(2),
        Some(u64::MAX - 1),
        Some(u64::MAX),
    ];
    let mut counts = [0; 4];
    for workloads in &workloads {
        for profiles in &profiles {
            for state in [
                ConnectionState::Active,
                ConnectionState::Disabled,
                ConnectionState::Revoked,
            ] {
                for created in times {
                    for updated in times {
                        for revoked in revocations {
                            let mut record = super::tests::record();
                            record.allowed_workloads.clone_from(workloads);
                            record.allowed_profiles.clone_from(profiles);
                            record.state = state;
                            record.created_at_unix_seconds = created;
                            record.updated_at_unix_seconds = updated;
                            record.revoked_at_unix_seconds = revoked;
                            let expected = original_validate(&record);
                            assert_eq!(record.validate(), expected);
                            // The unchanged decoder rejects collection bounds while reading,
                            // before it reaches complete semantic validation.
                            let expected_decode = if !(1..=256).contains(&workloads.len()) {
                                Err(ConnectionRecordError::InvalidWorkloads)
                            } else if !(1..=32).contains(&profiles.len()) {
                                Err(ConnectionRecordError::InvalidProfiles)
                            } else {
                                expected
                            };
                            let decoded = ConnectionRecord::from_canonical_cbor(
                                &record.to_canonical_cbor().unwrap(),
                            );
                            match decoded {
                                Ok(decoded) => {
                                    assert_eq!(expected_decode, Ok(()));
                                    assert_eq!(decoded, record);
                                }
                                Err(error) => assert_eq!(expected_decode, Err(error)),
                            }
                            counts[match expected {
                                Ok(()) => 0,
                                Err(ConnectionRecordError::InvalidWorkloads) => 1,
                                Err(ConnectionRecordError::InvalidProfiles) => 2,
                                Err(ConnectionRecordError::InvalidTimestamps) => 3,
                                Err(error) => panic!("unexpected frozen-validator result: {error}"),
                            }] += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(counts, [1040, 28_800, 7200, 6160]);
}
