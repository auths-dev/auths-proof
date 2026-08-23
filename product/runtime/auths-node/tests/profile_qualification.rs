use auths_node::built_in_local_profiles;
#[cfg(feature = "qualification-failpoints")]
use auths_node::built_in_qualification_local_profiles;
#[cfg(feature = "testkit-agent")]
use auths_node::built_in_testkit_local_profiles;

#[cfg(not(feature = "testkit-agent"))]
#[test]
fn production_build_advertises_no_unqualified_provider_profiles() {
    assert!(built_in_local_profiles().unwrap().is_empty());
}

#[cfg(feature = "qualification-failpoints")]
#[test]
fn qualification_build_advertises_the_exact_unqualified_profile_roster_without_claims() {
    assert!(built_in_local_profiles().unwrap().is_empty());
    let profiles = built_in_qualification_local_profiles().unwrap();
    let identities = profiles
        .iter()
        .map(|profile| {
            let advertised = profile.advertisement();
            assert!(advertised.qualification().is_none());
            format!(
                "{}/{}",
                advertised.profile().id(),
                advertised.profile().version()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        [
            "auths.opentofu.plan-preflight/1",
            "auths.opentofu.saved-plan-apply/1",
            "auths.postgresql.bounded-update/1",
            "auths.postgresql.update-preflight/1",
            "auths.stripe.refund/1",
        ]
    );
}

#[cfg(feature = "testkit-agent")]
#[test]
fn testkit_build_advertises_only_the_disposable_stripe_route() {
    assert!(built_in_local_profiles().unwrap().is_empty());
    let profiles = built_in_testkit_local_profiles().unwrap();
    assert_eq!(profiles.len(), 1);
    let profile = profiles[0].advertisement().profile();
    assert_eq!(profile.id(), "auths.stripe.refund");
    assert_eq!(profile.version(), 1);
}
