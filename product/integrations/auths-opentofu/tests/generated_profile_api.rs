use auths_opentofu::generated::profile_api::{
    ApplyPreparedPlanInput, PlanPreflightInput, SourceFile,
};

#[test]
fn plan_preflight_source_input_matches_the_cross_language_canonical_fixture() {
    let value = PlanPreflightInput {
        source_files: vec![SourceFile {
            path: "main.tf".into(),
            contents: "resource \"x\" \"y\" {}".into(),
        }],
        variables: Vec::new(),
        dependency_lock: "lock".into(),
        modules: Vec::new(),
        workspace: "prod".into(),
    };
    let expected = hex::decode("a5676d6f64756c657380697661726961626c65738069776f726b73706163656470726f646b736f7572636546696c657381a26470617468676d61696e2e746668636f6e74656e7473737265736f757263652022782220227922207b7d6e646570656e64656e63794c6f636b646c6f636b").unwrap();
    assert_eq!(value.to_canonical_cbor().unwrap(), expected);
    assert_eq!(
        PlanPreflightInput::from_canonical_cbor(&expected).unwrap(),
        value
    );

    let mut trailing = expected;
    trailing.push(0);
    assert!(PlanPreflightInput::from_canonical_cbor(&trailing).is_err());
}

#[test]
fn apply_accepts_only_a_bounded_prepared_token() {
    let value = ApplyPreparedPlanInput {
        prepared_plan: format!("pplan_{}", "A".repeat(43)),
    };
    let expected = hex::decode("a16c7072657061726564506c616e783170706c616e5f41414141414141414141414141414141414141414141414141414141414141414141414141414141414141").unwrap();
    assert_eq!(value.to_canonical_cbor().unwrap(), expected);
    assert_eq!(
        ApplyPreparedPlanInput::from_canonical_cbor(&expected).unwrap(),
        value
    );

    assert!(
        ApplyPreparedPlanInput {
            prepared_plan: "pplan_too-short".into(),
        }
        .to_canonical_cbor()
        .is_err()
    );
}
