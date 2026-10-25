// Frozen pre-cutover configuration collection/framing. Test-only.
use super::*;

pub(super) fn verifier_configuration_id(
    principal_methods: &[&dyn PrincipalMethod],
    signature_suites: &[&dyn SignatureSuite],
    pure: &PureRegistrySet<'_>,
    core: &CoreSemantics,
) -> VerifierConfigurationId {
    let mut entries: Vec<(u8, String, AdapterConfigurationId)> = Vec::new();
    entries.extend(principal_methods.iter().map(|implementation| {
        (
            0,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(signature_suites.iter().map(|implementation| {
        (
            1,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(pure.resource_matchers.iter().map(|implementation| {
        (
            2,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.push((
        2,
        core.resource.id().as_str().into(),
        core.resource.configuration_id(),
    ));
    entries.extend(pure.profile_policies.iter().map(|implementation| {
        (
            3,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.push((
        3,
        core.profile.id().as_str().into(),
        core.profile.configuration_id(),
    ));
    entries.extend(pure.budget_algebras.iter().map(|implementation| {
        (
            4,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.push((
        4,
        core.budget.id().as_str().into(),
        core.budget.configuration_id(),
    ));
    entries.extend(pure.extension_handlers.iter().map(|implementation| {
        (
            5,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.push((
        5,
        core.extension.id().as_str().into(),
        core.extension.configuration_id(),
    ));
    entries.push((
        5,
        core.observation.id().as_str().into(),
        core.observation.configuration_id(),
    ));
    entries.push((
        5,
        core.bounded_policy.id().as_str().into(),
        core.bounded_policy.configuration_id(),
    ));
    entries.push((
        5,
        core.approval.id().as_str().into(),
        core.approval.configuration_id(),
    ));
    entries.extend(pure.status_methods.iter().map(|implementation| {
        (
            6,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(core.status.iter().map(|implementation| {
        (
            6,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(pure.assurance_claims.iter().map(|implementation| {
        (
            7,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(core.claims.iter().map(|implementation| {
        (
            7,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    entries.extend(pure.assurance_implications.iter().map(|implementation| {
        (
            8,
            implementation.id().as_str().into(),
            implementation.configuration_id(),
        )
    }));
    configuration_from_entries(entries)
}

pub(super) fn configuration_from_entries(
    mut entries: Vec<(u8, String, AdapterConfigurationId)>,
) -> VerifierConfigurationId {
    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut components = Vec::with_capacity(entries.len().saturating_mul(3));
    for (kind, id, configuration) in entries {
        components.push(vec![kind]);
        components.push(id.into_bytes());
        components.push(configuration.as_bytes().to_vec());
    }
    let digest = auths_ports::configuration_id(
        b"auths-proof-verifier-configuration-v1",
        components.iter().map(Vec::as_slice),
    );
    VerifierConfigurationId::new(*digest.as_bytes())
}
