use super::*;

#[test]
fn complete_ordered_frame_matches_the_original_for_every_small_duplicate_key_input() {
    for category in 0..9u8 {
        let variants = [
            (category, String::from("a"), AdapterConfigurationId::new([0; 32])),
            (category, String::from("a"), AdapterConfigurationId::new([1; 32])),
            (category, String::from("b"), AdapterConfigurationId::new([1; 32])),
            ((category + 1) % 9, String::from("a"), AdapterConfigurationId::new([0; 32])),
        ];
        for length in 0..=6u32 {
            for mut code in 0..4usize.pow(length) {
                let mut entries = Vec::new();
                for _ in 0..length {
                    entries.push(variants[code % 4].clone());
                    code /= 4;
                }
                assert_eq!(configuration_from_entries(entries.clone()),
                    configuration_reference::configuration_from_entries(entries));
            }
        }
    }
}

#[test]
fn actual_builtin_roster_collection_and_configuration_frame_match_the_original() {
    let core = CoreSemantics::new().unwrap();
    let pure = PureRegistrySet::empty();
    assert_eq!(verifier_configuration_id(&[], &[], &pure, &core),
        configuration_reference::verifier_configuration_id(&[], &[], &pure, &core));
    assert_eq!(core.status.len(), 2);
    assert_eq!(core.claims.len(), CLAIMS.len());
    for (actual, expected) in core.claims.iter().zip(CLAIMS) {
        assert_eq!(actual.id().as_str(), expected);
    }
}
