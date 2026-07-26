#![no_main]

use auths_model::{
    AcceptedRegistries, AssuranceClaimId, BudgetAlgebraId, BudgetCeiling, CanonicalAction,
    CapabilityId, MediaType, Permission, PrincipalMethodId, ProfileId, ProfilePolicyId, ProfileRef,
    RegistryManifestId, ResourceId, ResourceMatcherId, SignatureSuiteId,
};
use auths_ports::ProfileDecision;
use auths_registries::{
    EXACT_PROFILE_V1, ImmutableRegistries, NUMERIC_CEILING_V1, TARGET_V1_REGISTRY_MANIFEST,
    URI_NAMESPACE_V1,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let methods: [&dyn auths_ports::PrincipalMethod; 0] = [];
    let suites: [&dyn auths_ports::SignatureSuite; 0] = [];
    let Ok(registries) = ImmutableRegistries::new(&methods, &suites) else {
        return;
    };
    let profile = ProfileRef::new(ProfileId::parse("fuzz.profile").unwrap(), 1).unwrap();
    let matcher = ResourceMatcherId::parse(URI_NAMESPACE_V1).unwrap();
    let policy = ProfilePolicyId::parse(EXACT_PROFILE_V1).unwrap();
    let algebra = BudgetAlgebraId::parse(NUMERIC_CEILING_V1).unwrap();
    let accepted = AcceptedRegistries::new(
        RegistryManifestId::new(*TARGET_V1_REGISTRY_MANIFEST.as_bytes()),
        vec![PrincipalMethodId::parse("fuzz-method-v1").unwrap()],
        vec![SignatureSuiteId::parse("fuzz-suite-v1").unwrap()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![AssuranceClaimId::parse("offline-verifiable").unwrap()],
        Vec::new(),
        vec![matcher.clone()],
        vec![algebra.clone()],
        Vec::new(),
        vec![profile.clone()],
        vec![policy.clone()],
    )
    .unwrap();
    let suffix = core::str::from_utf8(data).unwrap_or("opaque");
    let namespace = ResourceId::parse("fuzz://root").unwrap();
    let resource = ResourceId::parse(&format!("fuzz://root/{suffix}"))
        .unwrap_or_else(|_| ResourceId::parse("fuzz://root/opaque").unwrap());
    if let Some(handler) = registries.resource_matcher(&accepted, &matcher) {
        let namespace_text = namespace.as_str();
        let resource_text = resource.as_str();
        let expected_match = resource_text == namespace_text
            || resource_text
                .strip_prefix(namespace_text)
                .is_some_and(|suffix| {
                    namespace_text.ends_with('/') || suffix.starts_with(['/', '?', '#'])
                });
        assert_eq!(handler.matches(&namespace, &resource), Ok(expected_match));
    }
    let action = CanonicalAction::new(
        profile,
        MediaType::parse("application/octet-stream").unwrap(),
        if data.is_empty() {
            vec![0]
        } else {
            data.to_vec()
        },
        Permission::new(CapabilityId::parse("fuzz").unwrap(), resource),
        Some(BudgetCeiling::new(algebra.clone(), 1)),
    )
    .unwrap();
    if let Some(handler) = registries.profile_policy(&accepted, &policy) {
        assert_eq!(handler.evaluate(&action), Ok(ProfileDecision::Accept));
    }
    if let Some(handler) = registries.budget_algebra(&accepted, &algebra) {
        let ceiling = BudgetCeiling::new(algebra.clone(), 2);
        let requested = BudgetCeiling::new(algebra, 1);
        assert_eq!(handler.covers(&ceiling, &requested), Ok(true));
        assert_eq!(handler.covers(&requested, &ceiling), Ok(false));
    }
});
