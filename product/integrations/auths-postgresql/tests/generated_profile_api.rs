use auths_postgresql::generated::profile_api::{
    Assignment, PreparedUpdateInput, UpdatePreflightInput,
};

#[test]
fn update_preflight_input_matches_the_cross_language_canonical_fixture() {
    let value = UpdatePreflightInput {
        relation: "public.users".into(),
        tenant_key: "tenant-a".into(),
        assignments: vec![Assignment {
            column: "status".into(),
            value: "active".into(),
        }],
    };
    let expected = hex::decode("a36872656c6174696f6e6c7075626c69632e75736572736974656e616e744b65796874656e616e742d616b61737369676e6d656e747381a26576616c75656661637469766566636f6c756d6e66737461747573").unwrap();
    assert_eq!(value.to_canonical_cbor().unwrap(), expected);
    assert_eq!(
        UpdatePreflightInput::from_canonical_cbor(&expected).unwrap(),
        value
    );

    let empty = UpdatePreflightInput {
        assignments: Vec::new(),
        ..value
    };
    assert!(empty.to_canonical_cbor().is_err());
}

#[test]
fn update_execution_accepts_only_a_bounded_prepared_token() {
    let value = PreparedUpdateInput {
        prepared_update: format!("pupd_{}", "A".repeat(43)),
    };
    let expected = hex::decode("a16e70726570617265645570646174657830707570645f41414141414141414141414141414141414141414141414141414141414141414141414141414141414141").unwrap();
    assert_eq!(value.to_canonical_cbor().unwrap(), expected);
    assert_eq!(
        PreparedUpdateInput::from_canonical_cbor(&expected).unwrap(),
        value
    );

    assert!(
        PreparedUpdateInput {
            prepared_update: "pupd_too-short".into(),
        }
        .to_canonical_cbor()
        .is_err()
    );
}
