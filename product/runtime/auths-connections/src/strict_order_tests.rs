//! Frozen ordering and complete-record/decoder checks for the two real consumers.
use super::*;
fn original_order<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn sequences<T: Clone>(alphabet: &[T; 4], maximum: u32) -> Vec<Vec<T>> {
    let mut output = Vec::new();
    for length in 0..=maximum {
        for mut code in 0..4_usize.pow(length) {
            let mut values = Vec::new();
            for _ in 0..length {
                values.push(alphabet[code % 4].clone());
                code /= 4;
            }
            output.push(values);
        }
    }
    output
}
#[test]
fn generic_ordering_preserves_both_real_comparators_and_integer_edges() {
    fn check<T: Ord>(values: Vec<Vec<T>>) {
        let mut accepted = 0;
        let mut checked = 0;
        for value in values {
            let actual = kernel::strictly_sorted_unique(&value);
            assert_eq!(actual, original_order(&value));
            accepted += usize::from(actual);
            checked += 1;
        }
        // Each subset of four distinct ordered keys gives exactly one strict list.
        assert_eq!((checked, accepted), (5461, 16));
    }
    let profiles = [
        ConnectionProfile::new(SemanticId::parse("a").unwrap(), 1).unwrap(),
        ConnectionProfile::new(SemanticId::parse("a").unwrap(), 2).unwrap(),
        ConnectionProfile::new(SemanticId::parse("b").unwrap(), 1).unwrap(),
        ConnectionProfile::new(SemanticId::parse("b").unwrap(), 2).unwrap(),
    ];
    check(sequences(&[0_u64, 1, 2, u64::MAX], 6));
    check(sequences(
        &[
            "a".to_owned(),
            "aa".to_owned(),
            "b".to_owned(),
            "z".to_owned(),
        ],
        6,
    ));
    check(sequences(&profiles, 6));
}
#[test]
fn complete_allowlist_records_and_decoder_keep_order_bounds_and_error_codes() {
    fn check(record: &ConnectionRecord, expected: Result<(), ConnectionRecordError>) -> bool {
        assert_eq!(record.validate(), expected);
        match ConnectionRecord::from_canonical_cbor(&record.to_canonical_cbor().unwrap()) {
            Ok(decoded) => {
                assert_eq!(expected, Ok(()));
                assert_eq!(&decoded, record);
                true
            }
            Err(error) => {
                assert_eq!(expected, Err(error));
                false
            }
        }
    }
    let mut workloads = sequences(
        &[
            "w-a".to_owned(),
            "w-b".to_owned(),
            "w-c".to_owned(),
            "w-d".to_owned(),
        ],
        4,
    );
    for length in [255, 256, 257] {
        workloads.push((0..length).map(|index| format!("w-{index:03}")).collect());
    }
    let mut workload_successes = 0;
    for values in &workloads {
        let valid = (1..=MAX_WORKLOADS).contains(&values.len()) && original_order(values);
        let mut record = super::tests::record();
        record.allowed_workloads.clone_from(values);
        workload_successes += usize::from(check(
            &record,
            if valid {
                Ok(())
            } else {
                Err(ConnectionRecordError::InvalidWorkloads)
            },
        ));
    }
    let profile = |id: &str, version| {
        ConnectionProfile::new(SemanticId::parse(id).unwrap(), version).unwrap()
    };
    let mut profiles = sequences(
        &[
            profile("a", 1),
            profile("a", 2),
            profile("b", 1),
            profile("b", 2),
        ],
        4,
    );
    for length in [31, 32, 33] {
        profiles.push(
            (0..length)
                .map(|index| profile(&format!("p-{index:02}"), 1))
                .collect(),
        );
    }
    let mut profile_successes = 0;
    for values in &profiles {
        let valid = (1..=MAX_PROFILES).contains(&values.len()) && original_order(values);
        let mut record = super::tests::record();
        record.allowed_profiles.clone_from(values);
        profile_successes += usize::from(check(
            &record,
            if valid {
                Ok(())
            } else {
                Err(ConnectionRecordError::InvalidProfiles)
            },
        ));
    }
    assert_eq!((workloads.len(), workload_successes), (344, 17));
    assert_eq!((profiles.len(), profile_successes), (344, 17));
}
