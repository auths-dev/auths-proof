//! Exact immutable implementation registries for the pure verifier.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use auths_model::{
    AcceptedRegistries, AdapterConfigurationId, AssuranceClaim, AssuranceClaimId, BudgetAlgebraId,
    BudgetCeiling, CanonicalAction, ExtensionId, GrantId, GrantState, GrantStatusSnapshot,
    PrincipalId, PrincipalMethodId, PrincipalState, PrincipalStatusSnapshot, ProfilePolicyId,
    RegistryManifestId, ResourceId, ResourceMatcherId, SignatureSuiteId, StatusMethodId,
    StatusPolicy, Timestamp, VerifierConfigurationId,
};
use auths_ports::{
    AssuranceClaimRule, AssuranceImplication, BudgetAlgebra, CriticalExtensionHandler,
    PrincipalMethod, ProfileDecision, ProfilePolicy, RegistryOperationError, ResourceMatcher,
    SignatureSuite, StatusDecision, StatusMethod,
};
use core::fmt;

/// Pinned identifier for the complete target V1 executable registry.
pub const TARGET_V1_REGISTRY_MANIFEST: RegistryManifestId = RegistryManifestId::new([0x33; 32]);
/// Target V1 resource-matching algebra.
pub const URI_NAMESPACE_V1: &str = "uri-namespace-v1";
/// Target V1 profile policy used by the reference corpus.
pub const EXACT_PROFILE_V1: &str = "exact-v1";
/// Target V1 numeric stateful-budget algebra.
pub const NUMERIC_CEILING_V1: &str = "numeric-ceiling-v1";
/// Target V1 exact marker extension used to prove executable extension
/// selection without changing authority.
pub const EXACT_MARKER_EXTENSION_V1: &str = "exact-marker-v1";

const CLAIMS: [&str; 13] = [
    "self-certifying-identifier",
    "offline-verifiable",
    "controller-state-current-at",
    "historical-at",
    "statement-existence-proven-at",
    "rotation-aware",
    "revocation-checked-at",
    "witness-threshold-met",
    "pki-chain-validated",
    "workload-attested",
    "hardware-attested",
    "user-verified",
    "origin-bound",
];

struct UriNamespaceMatcher {
    id: ResourceMatcherId,
}

impl ResourceMatcher for UriNamespaceMatcher {
    fn id(&self) -> &ResourceMatcherId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, namespace: &ResourceId, resource: &ResourceId) -> u64 {
        u64::try_from(
            namespace
                .as_str()
                .len()
                .saturating_add(resource.as_str().len()),
        )
        .unwrap_or(u64::MAX)
    }

    fn matches(
        &self,
        namespace: &ResourceId,
        resource: &ResourceId,
    ) -> Result<bool, RegistryOperationError> {
        let namespace = namespace.as_str();
        let resource = resource.as_str();
        Ok(resource == namespace
            || resource.strip_prefix(namespace).is_some_and(|suffix| {
                namespace.ends_with('/') || suffix.starts_with(['/', '?', '#'])
            }))
    }
}

struct ExactProfilePolicy {
    id: ProfilePolicyId,
}

impl ProfilePolicy for ExactProfilePolicy {
    fn id(&self) -> &ProfilePolicyId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, action: &CanonicalAction) -> u64 {
        u64::try_from(action.body().len()).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        _action: &CanonicalAction,
    ) -> Result<ProfileDecision, RegistryOperationError> {
        Ok(ProfileDecision::Accept)
    }
}

struct NumericBudgetAlgebra {
    id: BudgetAlgebraId,
}

impl BudgetAlgebra for NumericBudgetAlgebra {
    fn id(&self) -> &BudgetAlgebraId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self) -> u64 {
        1
    }

    fn attenuates(
        &self,
        child: &BudgetCeiling,
        parent: &BudgetCeiling,
    ) -> Result<bool, RegistryOperationError> {
        if child.algebra() != &self.id || parent.algebra() != &self.id {
            return Err(RegistryOperationError::InvalidInput);
        }
        Ok(child.value() <= parent.value())
    }

    fn covers(
        &self,
        ceiling: &BudgetCeiling,
        requested: &BudgetCeiling,
    ) -> Result<bool, RegistryOperationError> {
        self.attenuates(requested, ceiling)
    }
}

struct ExactMarkerExtension {
    id: ExtensionId,
}

impl CriticalExtensionHandler for ExactMarkerExtension {
    fn id(&self) -> &ExtensionId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, extension: &auths_model::CriticalExtension) -> u64 {
        u64::try_from(extension.bytes().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        extension: &auths_model::CriticalExtension,
    ) -> Result<(), RegistryOperationError> {
        if extension.id() == &self.id && extension.bytes() == [1] {
            Ok(())
        } else {
            Err(RegistryOperationError::InvalidInput)
        }
    }
}

struct ExactClaimRule {
    id: AssuranceClaimId,
}

impl AssuranceClaimRule for ExactClaimRule {
    fn id(&self) -> &AssuranceClaimId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, claim: &AssuranceClaim) -> u64 {
        u64::try_from(claim.parameters().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn validate(&self, claim: &AssuranceClaim) -> Result<(), RegistryOperationError> {
        if claim.kind() == &self.id {
            Ok(())
        } else {
            Err(RegistryOperationError::InvalidInput)
        }
    }
}

struct ExactStatusMethod {
    id: StatusMethodId,
}

impl ExactStatusMethod {
    fn freshness(
        policy: &StatusPolicy,
        observed_at: Timestamp,
        valid_until: Timestamp,
        evaluation_time: Timestamp,
    ) -> StatusDecision {
        let StatusPolicy::SnapshotRequired { max_age, .. } = policy else {
            return StatusDecision::Active;
        };
        if observed_at > evaluation_time
            || valid_until < evaluation_time
            || evaluation_time.get().saturating_sub(observed_at.get()) > max_age.get()
        {
            StatusDecision::Stale
        } else {
            StatusDecision::Active
        }
    }
}

impl StatusMethod for ExactStatusMethod {
    fn id(&self) -> &StatusMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, statement_count: usize) -> u64 {
        u64::try_from(statement_count.saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn principal(
        &self,
        policy: &StatusPolicy,
        snapshot: &PrincipalStatusSnapshot,
        principal: &PrincipalId,
        evaluation_time: Timestamp,
    ) -> Result<StatusDecision, RegistryOperationError> {
        let StatusPolicy::SnapshotRequired { method, .. } = policy else {
            return Ok(StatusDecision::Active);
        };
        if method != &self.id {
            return Ok(StatusDecision::WrongMethod);
        }
        if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
            return Ok(StatusDecision::Stale);
        }
        let candidates: Vec<_> = snapshot
            .statements()
            .iter()
            .map(auths_model::SignedPrincipalStatus::statement)
            .filter(|statement| statement.principal() == principal)
            .collect();
        select_principal(policy, snapshot, &candidates, evaluation_time)
    }

    fn grant(
        &self,
        policy: &StatusPolicy,
        snapshot: &GrantStatusSnapshot,
        grant: GrantId,
        evaluation_time: Timestamp,
    ) -> Result<StatusDecision, RegistryOperationError> {
        let StatusPolicy::SnapshotRequired { method, .. } = policy else {
            return Ok(StatusDecision::Active);
        };
        if method != &self.id {
            return Ok(StatusDecision::WrongMethod);
        }
        if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
            return Ok(StatusDecision::Stale);
        }
        let candidates: Vec<_> = snapshot
            .statements()
            .iter()
            .map(auths_model::SignedGrantStatus::statement)
            .filter(|statement| statement.grant_id() == grant)
            .collect();
        select_grant(policy, snapshot, &candidates, evaluation_time)
    }
}

fn select_principal(
    policy: &StatusPolicy,
    snapshot: &PrincipalStatusSnapshot,
    candidates: &[&auths_model::PrincipalStatusStatement],
    evaluation_time: Timestamp,
) -> Result<StatusDecision, RegistryOperationError> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(StatusDecision::Active);
    };
    if candidates.is_empty() {
        return Ok(StatusDecision::Missing);
    }
    if candidates
        .iter()
        .all(|statement| statement.method() != method)
    {
        return Ok(StatusDecision::WrongMethod);
    }
    let mut trusted = Vec::new();
    for statement in candidates
        .iter()
        .copied()
        .filter(|statement| statement.method() == method)
    {
        let Some(rule) = snapshot
            .trust()
            .iter()
            .find(|rule| rule.method() == method && rule.issuer() == statement.issuer())
        else {
            continue;
        };
        if statement.sequence() < rule.sequence_floor() {
            return Ok(StatusDecision::Rollback);
        }
        trusted.push(statement);
    }
    if trusted.is_empty() {
        return Ok(StatusDecision::UntrustedIssuer);
    }
    let maximum = trusted
        .iter()
        .map(|statement| statement.sequence())
        .max()
        .ok_or(RegistryOperationError::InvalidInput)?;
    let latest: Vec<_> = trusted
        .into_iter()
        .filter(|statement| statement.sequence() == maximum)
        .collect();
    if latest.iter().any(|statement| {
        ExactStatusMethod::freshness(
            policy,
            statement.observed_at(),
            statement.valid_until(),
            evaluation_time,
        ) == StatusDecision::Stale
    }) {
        return Ok(StatusDecision::Stale);
    }
    Ok(
        if latest
            .iter()
            .any(|statement| statement.state() != PrincipalState::Active)
        {
            StatusDecision::Revoked
        } else {
            StatusDecision::Active
        },
    )
}

fn select_grant(
    policy: &StatusPolicy,
    snapshot: &GrantStatusSnapshot,
    candidates: &[&auths_model::GrantStatusStatement],
    evaluation_time: Timestamp,
) -> Result<StatusDecision, RegistryOperationError> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(StatusDecision::Active);
    };
    if candidates.is_empty() {
        return Ok(StatusDecision::Missing);
    }
    if candidates
        .iter()
        .all(|statement| statement.method() != method)
    {
        return Ok(StatusDecision::WrongMethod);
    }
    let mut trusted = Vec::new();
    for statement in candidates
        .iter()
        .copied()
        .filter(|statement| statement.method() == method)
    {
        let Some(rule) = snapshot
            .trust()
            .iter()
            .find(|rule| rule.method() == method && rule.issuer() == statement.issuer())
        else {
            continue;
        };
        if statement.sequence() < rule.sequence_floor() {
            return Ok(StatusDecision::Rollback);
        }
        trusted.push(statement);
    }
    if trusted.is_empty() {
        return Ok(StatusDecision::UntrustedIssuer);
    }
    let maximum = trusted
        .iter()
        .map(|statement| statement.sequence())
        .max()
        .ok_or(RegistryOperationError::InvalidInput)?;
    let latest: Vec<_> = trusted
        .into_iter()
        .filter(|statement| statement.sequence() == maximum)
        .collect();
    if latest.iter().any(|statement| {
        ExactStatusMethod::freshness(
            policy,
            statement.observed_at(),
            statement.valid_until(),
            evaluation_time,
        ) == StatusDecision::Stale
    }) {
        return Ok(StatusDecision::Stale);
    }
    Ok(
        if latest
            .iter()
            .any(|statement| statement.state() != GrantState::Active)
        {
            StatusDecision::Revoked
        } else {
            StatusDecision::Active
        },
    )
}

/// Additional pure implementations supplied by downstream profile packages.
pub struct PureRegistrySet<'a> {
    /// Resource-matching algebras.
    pub resource_matchers: &'a [&'a dyn ResourceMatcher],
    /// Effect-free profile policies.
    pub profile_policies: &'a [&'a dyn ProfilePolicy],
    /// Budget algebras.
    pub budget_algebras: &'a [&'a dyn BudgetAlgebra],
    /// Critical-extension handlers.
    pub extension_handlers: &'a [&'a dyn CriticalExtensionHandler],
    /// Status methods.
    pub status_methods: &'a [&'a dyn StatusMethod],
    /// Assurance claim validators.
    pub assurance_claims: &'a [&'a dyn AssuranceClaimRule],
    /// Explicit assurance implication rules.
    pub assurance_implications: &'a [&'a dyn AssuranceImplication],
}

impl PureRegistrySet<'_> {
    const fn empty() -> Self {
        Self {
            resource_matchers: &[],
            profile_policies: &[],
            budget_algebras: &[],
            extension_handlers: &[],
            status_methods: &[],
            assurance_claims: &[],
            assurance_implications: &[],
        }
    }
}

struct CoreSemantics {
    resource: UriNamespaceMatcher,
    profile: ExactProfilePolicy,
    budget: NumericBudgetAlgebra,
    extension: ExactMarkerExtension,
    status: Vec<ExactStatusMethod>,
    claims: Vec<ExactClaimRule>,
}

impl CoreSemantics {
    fn new() -> Result<Self, RegistryError> {
        Ok(Self {
            resource: UriNamespaceMatcher {
                id: ResourceMatcherId::parse(URI_NAMESPACE_V1)
                    .map_err(|_| RegistryError::InvalidBuiltin)?,
            },
            profile: ExactProfilePolicy {
                id: ProfilePolicyId::parse(EXACT_PROFILE_V1)
                    .map_err(|_| RegistryError::InvalidBuiltin)?,
            },
            budget: NumericBudgetAlgebra {
                id: BudgetAlgebraId::parse(NUMERIC_CEILING_V1)
                    .map_err(|_| RegistryError::InvalidBuiltin)?,
            },
            extension: ExactMarkerExtension {
                id: ExtensionId::parse(EXACT_MARKER_EXTENSION_V1)
                    .map_err(|_| RegistryError::InvalidBuiltin)?,
            },
            status: ["auths-principal-status-v1", "auths-grant-status-v1"]
                .into_iter()
                .map(|id| {
                    StatusMethodId::parse(id)
                        .map(|id| ExactStatusMethod { id })
                        .map_err(|_| RegistryError::InvalidBuiltin)
                })
                .collect::<Result<Vec<_>, _>>()?,
            claims: CLAIMS
                .into_iter()
                .map(|id| {
                    AssuranceClaimId::parse(id)
                        .map(|id| ExactClaimRule { id })
                        .map_err(|_| RegistryError::InvalidBuiltin)
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

// Kept as one exhaustive, auditable inventory so adding a registry category
// cannot silently omit its configuration commitment.
#[allow(clippy::too_many_lines)]
fn verifier_configuration_id(
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

/// Concrete implementations available to one verification call.
pub struct ImmutableRegistries<'a> {
    principal_methods: &'a [&'a dyn PrincipalMethod],
    signature_suites: &'a [&'a dyn SignatureSuite],
    pure: PureRegistrySet<'a>,
    core: CoreSemantics,
    configuration: VerifierConfigurationId,
}

impl<'a> ImmutableRegistries<'a> {
    /// Constructs the target V1 registry with core pure semantics.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::DuplicateImplementation`] when two
    /// implementations claim the same exact identifier.
    pub fn new(
        principal_methods: &'a [&'a dyn PrincipalMethod],
        signature_suites: &'a [&'a dyn SignatureSuite],
    ) -> Result<Self, RegistryError> {
        Self::with_pure(
            principal_methods,
            signature_suites,
            PureRegistrySet::empty(),
        )
    }

    /// Constructs the target V1 registry with additional exact pure handlers.
    ///
    /// # Errors
    ///
    /// Returns a typed error for duplicate exact identifiers or invalid core
    /// registry constants.
    pub fn with_pure(
        principal_methods: &'a [&'a dyn PrincipalMethod],
        signature_suites: &'a [&'a dyn SignatureSuite],
        pure: PureRegistrySet<'a>,
    ) -> Result<Self, RegistryError> {
        reject_duplicates(principal_methods.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(signature_suites.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(pure.resource_matchers.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(pure.profile_policies.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(pure.budget_algebras.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(
            pure.extension_handlers
                .iter()
                .map(|item| item.id().as_str()),
        )?;
        reject_duplicates(pure.status_methods.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(pure.assurance_claims.iter().map(|item| item.id().as_str()))?;
        reject_duplicates(
            pure.assurance_implications
                .iter()
                .map(|item| item.id().as_str()),
        )?;
        let core = CoreSemantics::new()?;
        if pure
            .resource_matchers
            .iter()
            .any(|item| item.id() == core.resource.id())
            || pure
                .profile_policies
                .iter()
                .any(|item| item.id() == core.profile.id())
            || pure
                .budget_algebras
                .iter()
                .any(|item| item.id() == core.budget.id())
            || pure
                .extension_handlers
                .iter()
                .any(|item| item.id() == core.extension.id())
            || pure
                .status_methods
                .iter()
                .any(|item| core.status.iter().any(|builtin| item.id() == builtin.id()))
            || pure
                .assurance_claims
                .iter()
                .any(|item| core.claims.iter().any(|builtin| item.id() == builtin.id()))
        {
            return Err(RegistryError::DuplicateImplementation);
        }
        let configuration =
            verifier_configuration_id(principal_methods, signature_suites, &pure, &core);
        Ok(Self {
            principal_methods,
            signature_suites,
            pure,
            core,
            configuration,
        })
    }

    /// Returns the pinned complete target V1 registry manifest identifier.
    #[must_use]
    pub const fn manifest_id(&self) -> RegistryManifestId {
        TARGET_V1_REGISTRY_MANIFEST
    }

    /// Returns a canonical commitment to all executable registry
    /// implementations and their immutable configuration.
    #[must_use]
    pub const fn configuration_id(&self) -> VerifierConfigurationId {
        self.configuration
    }

    /// Selects one exact, context-accepted principal method.
    #[must_use]
    pub fn principal_method(
        &self,
        accepted: &AcceptedRegistries,
        id: &PrincipalMethodId,
    ) -> Option<&'a dyn PrincipalMethod> {
        accepted.accepts_principal_method(id).then(|| {
            self.principal_methods
                .iter()
                .copied()
                .find(|implementation| implementation.id() == id)
        })?
    }

    /// Selects one exact, context-accepted signature suite.
    #[must_use]
    pub fn signature_suite(
        &self,
        accepted: &AcceptedRegistries,
        id: &SignatureSuiteId,
    ) -> Option<&'a dyn SignatureSuite> {
        accepted.accepts_signature_suite(id).then(|| {
            self.signature_suites
                .iter()
                .copied()
                .find(|implementation| implementation.id() == id)
        })?
    }

    /// Selects one exact resource matcher.
    #[must_use]
    pub fn resource_matcher(
        &self,
        accepted: &AcceptedRegistries,
        id: &ResourceMatcherId,
    ) -> Option<&dyn ResourceMatcher> {
        if !accepted.accepts_resource_matcher(id) {
            return None;
        }
        if self.core.resource.id() == id {
            return Some(&self.core.resource);
        }
        self.pure
            .resource_matchers
            .iter()
            .copied()
            .find(|implementation| implementation.id() == id)
    }

    /// Selects one exact profile policy.
    #[must_use]
    pub fn profile_policy(
        &self,
        accepted: &AcceptedRegistries,
        id: &ProfilePolicyId,
    ) -> Option<&dyn ProfilePolicy> {
        if !accepted.accepts_profile_policy(id) {
            return None;
        }
        if self.core.profile.id() == id {
            return Some(&self.core.profile);
        }
        self.pure
            .profile_policies
            .iter()
            .copied()
            .find(|implementation| implementation.id() == id)
    }

    /// Selects one exact budget algebra.
    #[must_use]
    pub fn budget_algebra(
        &self,
        accepted: &AcceptedRegistries,
        id: &BudgetAlgebraId,
    ) -> Option<&dyn BudgetAlgebra> {
        if !accepted.accepts_budget_algebra(id) {
            return None;
        }
        if self.core.budget.id() == id {
            return Some(&self.core.budget);
        }
        self.pure
            .budget_algebras
            .iter()
            .copied()
            .find(|implementation| implementation.id() == id)
    }

    /// Selects one exact critical-extension handler.
    #[must_use]
    pub fn extension_handler(
        &self,
        accepted: &AcceptedRegistries,
        id: &ExtensionId,
    ) -> Option<&dyn CriticalExtensionHandler> {
        if !accepted.accepts_critical_extension(id) {
            return None;
        }
        if self.core.extension.id() == id {
            return Some(&self.core.extension);
        }
        self.pure
            .extension_handlers
            .iter()
            .copied()
            .find(|implementation| implementation.id() == id)
    }

    /// Selects one exact status method.
    #[must_use]
    pub fn status_method(
        &self,
        accepted: &AcceptedRegistries,
        id: &StatusMethodId,
        principal: bool,
    ) -> Option<&dyn StatusMethod> {
        let accepted = if principal {
            accepted.accepts_principal_status_method(id)
        } else {
            accepted.accepts_grant_status_method(id)
        };
        if !accepted {
            return None;
        }
        self.core
            .status
            .iter()
            .find(|implementation| implementation.id() == id)
            .map(|implementation| implementation as &dyn StatusMethod)
            .or_else(|| {
                self.pure
                    .status_methods
                    .iter()
                    .copied()
                    .find(|implementation| implementation.id() == id)
            })
    }

    /// Selects one exact assurance claim validator.
    #[must_use]
    pub fn assurance_claim(
        &self,
        accepted: &AcceptedRegistries,
        id: &AssuranceClaimId,
    ) -> Option<&dyn AssuranceClaimRule> {
        if !accepted.accepts_assurance_claim(id) {
            return None;
        }
        self.core
            .claims
            .iter()
            .find(|implementation| implementation.id() == id)
            .map(|implementation| implementation as &dyn AssuranceClaimRule)
            .or_else(|| {
                self.pure
                    .assurance_claims
                    .iter()
                    .copied()
                    .find(|implementation| implementation.id() == id)
            })
    }

    /// Returns accepted explicit implication handlers in exact ID order.
    #[must_use]
    pub fn assurance_implications(
        &self,
        accepted: &AcceptedRegistries,
    ) -> Vec<&dyn AssuranceImplication> {
        let mut selected: Vec<_> = self
            .pure
            .assurance_implications
            .iter()
            .copied()
            .filter(|implementation| accepted.accepts_assurance_implication(implementation.id()))
            .collect();
        selected.sort_by(|left, right| left.id().cmp(right.id()));
        selected
    }
}

fn reject_duplicates<'a>(identifiers: impl Iterator<Item = &'a str>) -> Result<(), RegistryError> {
    let mut identifiers: Vec<_> = identifiers.collect();
    identifiers.sort_unstable();
    if identifiers.windows(2).any(|window| window[0] == window[1]) {
        Err(RegistryError::DuplicateImplementation)
    } else {
        Ok(())
    }
}

/// Immutable-registry construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// Multiple implementations claimed one exact identifier.
    DuplicateImplementation,
    /// A compile-time target V1 identifier violated model bounds.
    InvalidBuiltin,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateImplementation => "duplicate exact registry implementation",
            Self::InvalidBuiltin => "invalid target V1 registry identifier",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RegistryError {}
