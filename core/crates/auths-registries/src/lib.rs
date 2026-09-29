//! Exact immutable implementation registries for the pure verifier.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod template;

pub use template::TrustedContextTemplate;

use alloc::{string::String, vec, vec::Vec};
use auths_model::{
    AcceptedRegistries, AdapterConfigurationId, AssuranceClaim, AssuranceClaimId, BudgetAlgebraId,
    BudgetCeiling, CanonicalAction, CriticalExtensionLaws, ExtensionId, GrantId, GrantState,
    GrantStatusSnapshot, PrincipalId, PrincipalMethodId, PrincipalState, PrincipalStatusSnapshot,
    ProfilePolicyId, RegistryManifestId, ResourceId, ResourceMatcherId, SignatureSuiteId,
    StatusMethodId, StatusPolicy, Timestamp, TrustAnchor, VerifierConfigurationId,
    status_issuer_in_scope,
};
use auths_ports::{
    AssuranceClaimRule, AssuranceImplication, BudgetAlgebra, CriticalExtensionHandler,
    PrincipalMethod, ProfileDecision, ProfilePolicy, RegistryOperationError, ResourceMatcher,
    SignatureSuite, StatusDecision, StatusMethod,
};
use core::fmt;

/// Pinned identifier for the complete target V1 executable registry.
///
/// The set includes the `observation-requirement-v1` and
/// `bounded-policy-commitment-v1` critical extensions and the per-extension
/// attenuation laws; a context pinned to an earlier manifest is denied, not
/// dual-read.
pub const TARGET_V1_REGISTRY_MANIFEST: RegistryManifestId = RegistryManifestId::new([0x36; 32]);
/// Target V1 resource-matching algebra.
pub const URI_NAMESPACE_V1: &str = "uri-namespace-v1";
/// Target V1 profile policy used by the reference corpus.
pub const EXACT_PROFILE_V1: &str = "exact-v1";
/// Target V1 numeric stateful-budget algebra.
pub const NUMERIC_CEILING_V1: &str = "numeric-ceiling-v1";
/// Target V1 exact marker extension used to prove executable extension
/// selection without changing authority.
pub const EXACT_MARKER_EXTENSION_V1: &str = "exact-marker-v1";
/// Grant critical extension carrying observation requirements.
pub const OBSERVATION_REQUIREMENT_EXTENSION_V1: &str = "observation-requirement-v1";
/// Grant critical extension carrying approval requirements.
pub const APPROVAL_REQUIREMENT_EXTENSION_V1: &str = "approval-requirement-v1";
/// Grant critical extension committing to a closed product-layer policy.
pub const BOUNDED_POLICY_COMMITMENT_EXTENSION_V1: &str = "bounded-policy-commitment-v1";
/// Attenuation law committed by the `bounded-policy-commitment-v1` handler.
const BOUNDED_POLICY_ATTENUATION_LAW: &str = "attenuation-law:bounded-policy-link-v1";
/// Attenuation law committed by the `exact-marker-v1` handler.
const MARKER_ATTENUATION_LAW: &str = "attenuation-law:byte-equality-v1";
/// Attenuation law committed by the `observation-requirement-v1` handler.
const OBSERVATION_ATTENUATION_LAW: &str = "attenuation-law:requirement-narrowing-v1";

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
        auths_ports::configuration_id(
            self.id.as_str().as_bytes(),
            [MARKER_ATTENUATION_LAW.as_bytes()],
        )
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

    /// Byte equality. Adding the marker is refused, so it changes no
    /// authority.
    fn attenuates(
        &self,
        child: Option<&[u8]>,
        parent: Option<&[u8]>,
    ) -> Result<bool, RegistryOperationError> {
        Ok(match (child, parent) {
            (Some(child), Some(parent)) => child == parent,
            (Some(_) | None, None) | (None, Some(_)) => false,
        })
    }
}

/// Validates the canonical requirement list carried by a grant. The
/// requirements themselves are evaluated by the verifier's observation stage,
/// which needs the action, the attachments, and the trusted context that a
/// handler never sees.
struct ObservationRequirementExtension {
    id: ExtensionId,
}

fn decode_requirements(
    bytes: &[u8],
) -> Result<auths_model::ObservationRequirements, RegistryOperationError> {
    auths_codec::decode_observation_requirements(bytes).map_err(|error| match error {
        auths_codec::CodecError::LimitExceeded => RegistryOperationError::ResourceLimitExceeded,
        _ => RegistryOperationError::InvalidInput,
    })
}

impl CriticalExtensionHandler for ObservationRequirementExtension {
    fn id(&self) -> &ExtensionId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(
            self.id.as_str().as_bytes(),
            [OBSERVATION_ATTENUATION_LAW.as_bytes()],
        )
    }

    fn maximum_work_units(&self, extension: &auths_model::CriticalExtension) -> u64 {
        u64::try_from(extension.bytes().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        extension: &auths_model::CriticalExtension,
    ) -> Result<(), RegistryOperationError> {
        if extension.id() != &self.id {
            return Err(RegistryOperationError::InvalidInput);
        }
        decode_requirements(extension.bytes()).map(|_| ())
    }

    /// Every parent requirement is kept byte-identical or strictly narrowed,
    /// and the child may add requirements. Adding the extension where the
    /// parent has none only adds requirements, so it is accepted.
    fn attenuates(
        &self,
        child: Option<&[u8]>,
        parent: Option<&[u8]>,
    ) -> Result<bool, RegistryOperationError> {
        let Some(child) = child else {
            return Ok(false);
        };
        let child = decode_requirements(child)?;
        match parent {
            Some(parent) => Ok(auths_model::observation_requirements_attenuate(
                &child,
                &decode_requirements(parent)?,
            )),
            None => Ok(true),
        }
    }
}

fn decode_bounded_policy(
    bytes: &[u8],
) -> Result<auths_model::BoundedPolicyCommitment, RegistryOperationError> {
    auths_codec::decode_bounded_policy_commitment(bytes).map_err(|error| match error {
        auths_codec::CodecError::LimitExceeded => RegistryOperationError::ResourceLimitExceeded,
        _ => RegistryOperationError::InvalidInput,
    })
}

/// Validates the shape of a bounded-policy commitment and applies its link
/// law. Whether a child policy is tighter than its parent's is decided by the
/// product layer's registered evaluator, never here.
struct BoundedPolicyCommitmentExtension {
    id: ExtensionId,
}

impl CriticalExtensionHandler for BoundedPolicyCommitmentExtension {
    fn id(&self) -> &ExtensionId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(
            self.id.as_str().as_bytes(),
            [BOUNDED_POLICY_ATTENUATION_LAW.as_bytes()],
        )
    }

    fn maximum_work_units(&self, extension: &auths_model::CriticalExtension) -> u64 {
        u64::try_from(extension.bytes().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        extension: &auths_model::CriticalExtension,
    ) -> Result<(), RegistryOperationError> {
        if extension.id() != &self.id {
            return Err(RegistryOperationError::InvalidInput);
        }
        decode_bounded_policy(extension.bytes()).map(|_| ())
    }

    /// The child keeps the extension only by linking the digest of the
    /// parent's exact extension bytes; a child adding it to an unbounded
    /// parent carries no link.
    fn attenuates(
        &self,
        child: Option<&[u8]>,
        parent: Option<&[u8]>,
    ) -> Result<bool, RegistryOperationError> {
        let Some(child) = child else {
            return Ok(false);
        };
        let child = decode_bounded_policy(child)?;
        let parent_digest = match parent {
            Some(parent) => {
                decode_bounded_policy(parent)?;
                Some(
                    auths_codec::bounded_policy_link(parent)
                        .map_err(|_| RegistryOperationError::ResourceLimitExceeded)?,
                )
            }
            None => None,
        };
        Ok(auths_model::bounded_policy_link_accepts(
            child.parent(),
            parent_digest.as_ref(),
        ))
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
        anchor: &TrustAnchor,
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
            .filter(|statement| {
                statement.principal() == principal
                    && status_issuer_in_scope(snapshot.trust(), statement.issuer(), anchor)
            })
            .collect();
        select_principal(policy, snapshot, &candidates, evaluation_time)
    }

    fn grant(
        &self,
        policy: &StatusPolicy,
        snapshot: &GrantStatusSnapshot,
        grant: GrantId,
        anchor: &TrustAnchor,
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
            .filter(|statement| {
                statement.grant_id() == grant
                    && status_issuer_in_scope(snapshot.trust(), statement.issuer(), anchor)
            })
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
    observation: ObservationRequirementExtension,
    bounded_policy: BoundedPolicyCommitmentExtension,
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
            observation: ObservationRequirementExtension {
                id: ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1)
                    .map_err(|_| RegistryError::InvalidBuiltin)?,
            },
            bounded_policy: BoundedPolicyCommitmentExtension {
                id: ExtensionId::parse(BOUNDED_POLICY_COMMITMENT_EXTENSION_V1)
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
            || pure.extension_handlers.iter().any(|item| {
                item.id() == core.extension.id()
                    || item.id() == core.observation.id()
                    || item.id() == core.bounded_policy.id()
            })
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
        if self.core.observation.id() == id {
            return Some(&self.core.observation);
        }
        if self.core.bounded_policy.id() == id {
            return Some(&self.core.bounded_policy);
        }
        self.pure
            .extension_handlers
            .iter()
            .copied()
            .find(|implementation| implementation.id() == id)
    }

    /// The attenuation laws of the critical-extension handlers `accepted`
    /// selects. An identifier without an accepted handler has no law.
    #[must_use]
    pub fn extension_laws<'s>(
        &'s self,
        accepted: &'s AcceptedRegistries,
    ) -> AcceptedExtensionLaws<'s, 'a> {
        AcceptedExtensionLaws {
            registries: self,
            accepted,
        }
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

/// Attenuation laws of the handlers one trusted context accepts.
pub struct AcceptedExtensionLaws<'s, 'a> {
    registries: &'s ImmutableRegistries<'a>,
    accepted: &'s AcceptedRegistries,
}

impl AcceptedExtensionLaws<'_, '_> {
    /// Conservative work reservation for judging `child` against `parent`:
    /// each present payload's handler bound. Identifiers without a handler
    /// cost nothing, because the kernel refuses them without work.
    #[must_use]
    pub fn maximum_work_units(
        &self,
        child: &auths_model::CriticalExtensions,
        parent: &auths_model::CriticalExtensions,
    ) -> u64 {
        child
            .as_slice()
            .iter()
            .chain(parent.as_slice())
            .filter_map(|extension| {
                self.registries
                    .extension_handler(self.accepted, extension.id())
                    .map(|handler| handler.maximum_work_units(extension))
            })
            .fold(0, u64::saturating_add)
    }
}

impl CriticalExtensionLaws for AcceptedExtensionLaws<'_, '_> {
    fn attenuates(&self, id: &ExtensionId, child: Option<&[u8]>, parent: Option<&[u8]>) -> bool {
        self.registries
            .extension_handler(self.accepted, id)
            .is_some_and(|handler| handler.attenuates(child, parent).unwrap_or(false))
    }
}

/// Attenuation laws of the target V1 core critical-extension handlers,
/// independent of any trusted context. Pre-signing planning uses them; an
/// identifier outside the core set has no law and is refused.
pub struct CoreExtensionLaws {
    marker: ExactMarkerExtension,
    observation: ObservationRequirementExtension,
    bounded_policy: BoundedPolicyCommitmentExtension,
}

impl CoreExtensionLaws {
    /// Constructs the core laws.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidBuiltin`] if a compile-time identifier
    /// violates model bounds.
    pub fn target_v1() -> Result<Self, RegistryError> {
        let core = CoreSemantics::new()?;
        Ok(Self {
            marker: core.extension,
            observation: core.observation,
            bounded_policy: core.bounded_policy,
        })
    }
}

impl CriticalExtensionLaws for CoreExtensionLaws {
    fn attenuates(&self, id: &ExtensionId, child: Option<&[u8]>, parent: Option<&[u8]>) -> bool {
        let handler: &dyn CriticalExtensionHandler = if id == self.marker.id() {
            &self.marker
        } else if id == self.observation.id() {
            &self.observation
        } else if id == self.bounded_policy.id() {
            &self.bounded_policy
        } else {
            return false;
        };
        handler.attenuates(child, parent).unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use auths_model::{
        ConditionTest, FactName, ObservationCondition, ObservationRequirement,
        ObservationRequirements, ObservationSchemaId, ObservationSubject, ObserverAnchorId,
        StatusScope, StatusScopeAnchors, StatusTrustRule, UintRange,
    };

    fn laws() -> CoreExtensionLaws {
        CoreExtensionLaws::target_v1().expect("core laws")
    }

    fn id(value: &str) -> ExtensionId {
        ExtensionId::parse(value).expect("extension id")
    }

    fn condition(name: &str, hi: u64) -> ObservationCondition {
        ObservationCondition::new(
            FactName::parse(name).expect("fact name"),
            ConditionTest::UintRange(UintRange::new(0, hi).expect("range")),
        )
    }

    fn requirement(
        observer: &str,
        schema: &str,
        max_age: u32,
        conditions: Vec<ObservationCondition>,
    ) -> ObservationRequirement {
        ObservationRequirement::new(
            ObserverAnchorId::parse(observer).expect("observer"),
            ObservationSchemaId::parse(schema).expect("schema"),
            ObservationSubject::Resource(ResourceId::parse("mcp://record").expect("subject")),
            max_age,
            conditions,
        )
        .expect("requirement")
    }

    fn base() -> ObservationRequirement {
        requirement("observer", "auths.test/1", 60, vec![condition("a", 5)])
    }

    fn bytes(requirements: Vec<ObservationRequirement>) -> Vec<u8> {
        auths_codec::encode_observation_requirements(
            &ObservationRequirements::new(requirements).expect("requirements"),
        )
        .expect("canonical requirements")
    }

    fn observation(child: &[u8], parent: Option<&[u8]>) -> bool {
        laws().attenuates(
            &id(OBSERVATION_REQUIREMENT_EXTENSION_V1),
            Some(child),
            parent,
        )
    }

    #[test]
    fn marker_law_is_byte_equality_and_refuses_addition() {
        let marker = id(EXACT_MARKER_EXTENSION_V1);
        assert!(laws().attenuates(&marker, Some(&[1]), Some(&[1])));
        assert!(!laws().attenuates(&marker, Some(&[2]), Some(&[1])));
        assert!(!laws().attenuates(&marker, Some(&[1]), None));
        assert!(!laws().attenuates(&marker, None, Some(&[1])));
        assert!(!laws().attenuates(&id("unknown-v1"), Some(&[1]), Some(&[1])));
    }

    #[test]
    fn observation_law_accepts_exactly_the_narrowings() {
        let parent = bytes(vec![base()]);
        let narrowed_age = requirement("observer", "auths.test/1", 30, vec![condition("a", 5)]);
        let narrowed_conditions = requirement(
            "observer",
            "auths.test/1",
            60,
            vec![condition("a", 5), condition("b", 1)],
        );
        let other = requirement("observer", "auths.test/2", 60, vec![condition("a", 5)]);
        for (child, reason) in [
            (vec![base()], "identical"),
            (vec![narrowed_age], "a smaller maximum age"),
            (vec![narrowed_conditions], "an added condition"),
            (vec![base(), other.clone()], "an added requirement"),
        ] {
            assert!(observation(&bytes(child), Some(&parent)), "{reason}");
        }
        let widened_age = requirement("observer", "auths.test/1", 61, vec![condition("a", 5)]);
        let widened_range = requirement("observer", "auths.test/1", 60, vec![condition("a", 6)]);
        let other_observer = requirement("other", "auths.test/1", 60, vec![condition("a", 5)]);
        let mixed = requirement("observer", "auths.test/1", 30, vec![condition("b", 1)]);
        for (child, reason) in [
            (vec![widened_age], "a larger maximum age"),
            (vec![widened_range], "a changed condition"),
            (vec![other_observer], "another observer"),
            (vec![other], "another schema"),
            (vec![mixed], "narrower age but a dropped condition"),
        ] {
            assert!(!observation(&bytes(child), Some(&parent)), "{reason}");
        }
    }

    #[test]
    fn observation_law_needs_a_strict_narrowing_or_identity() {
        let parent = bytes(vec![requirement(
            "observer",
            "auths.test/1",
            60,
            vec![condition("a", 5), condition("b", 1)],
        )]);
        let reordered = bytes(vec![requirement(
            "observer",
            "auths.test/1",
            60,
            vec![condition("b", 1), condition("a", 5)],
        )]);
        assert!(!observation(&reordered, Some(&parent)));
    }

    fn bounded(policy: &[u8], parent: Option<auths_model::Digest>) -> Vec<u8> {
        let commitment = auths_model::PolicyCommitment::new(
            auths_model::PolicyIdentifier::parse("auths.test.policy/1", 128).expect("type"),
            1,
            auths_model::PolicyIdentifier::parse("auths.test.canonical/1", 64).expect("canon"),
            auths_codec::bounded_policy_digest(policy).expect("digest"),
            auths_model::PolicyIdentifier::parse("auths.test.evaluate/1", 128).expect("eval"),
        )
        .expect("commitment");
        auths_codec::encode_bounded_policy_commitment(
            &auths_model::BoundedPolicyCommitment::new(commitment, policy.to_vec(), parent)
                .expect("body"),
        )
        .expect("bytes")
    }

    #[test]
    fn bounded_policy_law_checks_only_the_parent_link() {
        let id = id(BOUNDED_POLICY_COMMITMENT_EXTENSION_V1);
        let parent = bounded(b"parent", None);
        let link = auths_codec::bounded_policy_link(&parent).expect("link");
        let linked = bounded(b"any tighter or looser policy", Some(link));
        assert!(laws().attenuates(&id, Some(&linked), Some(&parent)));
        let wrong = bounded(b"child", Some(auths_model::Digest::new([7; 32])));
        assert!(!laws().attenuates(&id, Some(&wrong), Some(&parent)));
        let unlinked = bounded(b"child", None);
        assert!(!laws().attenuates(&id, Some(&unlinked), Some(&parent)));
        assert!(
            laws().attenuates(&id, Some(&unlinked), None),
            "adding to an unbounded grant"
        );
        assert!(
            !laws().attenuates(&id, Some(&linked), None),
            "a link with no parent"
        );
        assert!(!laws().attenuates(&id, None, Some(&parent)));
    }

    #[test]
    fn bounded_policy_shape_opens_the_policy_digest() {
        let mut bytes = bounded(b"policy", None);
        let last = bytes.len() - 3;
        bytes[last] ^= 1;
        assert_eq!(
            auths_codec::decode_bounded_policy_commitment(&bytes),
            Err(auths_codec::CodecError::DigestMismatch)
        );
    }

    #[test]
    fn observation_law_accepts_addition_and_refuses_malformed_bytes() {
        assert!(observation(&bytes(vec![base()]), None));
        assert!(!observation(&[0xff], None));
        assert!(!observation(&bytes(vec![base()]), Some(&[0xff])));
        assert!(!laws().attenuates(
            &id(OBSERVATION_REQUIREMENT_EXTENSION_V1),
            None,
            Some(&bytes(vec![base()]))
        ));
    }

    const PRIMARY_STATUS: &str = "auths-principal-status-v1";
    const OTHER_STATUS: &str = "other-principal-status-v1";

    /// Reproducible xorshift cases for the scope property, with no generator
    /// dependency in this crate.
    struct Cases(u64);

    impl Cases {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let value = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
            usize::try_from(value % u64::try_from(bound).expect("small bound"))
                .expect("small value")
        }

        fn pick<'a, T>(&mut self, values: &'a [T]) -> &'a T {
            &values[self.below(values.len())]
        }

        fn sequence(&mut self, maximum: usize) -> u64 {
            u64::try_from(1 + self.below(maximum)).expect("small sequence")
        }
    }

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::parse(value).expect("principal")
    }

    fn method(value: &str) -> StatusMethodId {
        StatusMethodId::parse(value).expect("status method")
    }

    fn status_anchor(id: &str, root: &str) -> TrustAnchor {
        TrustAnchor::new(
            auths_model::TrustAnchorId::parse(id).expect("anchor ID"),
            principal(root),
            vec![PrincipalMethodId::parse("raw-key-v1").expect("method")],
            vec![
                auths_model::ProfileRef::new(
                    auths_model::ProfileId::parse("auths.mcp").expect("profile"),
                    1,
                )
                .expect("profile"),
            ],
            auths_model::PermissionSet::new(vec![auths_model::Permission::new(
                auths_model::CapabilityId::parse("tools/call").expect("capability"),
                ResourceId::parse("mcp://reports/read").expect("resource"),
            )])
            .expect("permissions"),
            Vec::new(),
            auths_model::AudienceSet::new(vec![
                auths_model::Audience::parse("audience://verifier").expect("audience"),
            ])
            .expect("audiences"),
            auths_model::ValidityWindow::new(Timestamp::new(0), Timestamp::new(100))
                .expect("validity"),
            None,
            1,
            auths_model::AssurancePolicyId::parse("policy").expect("policy"),
            StatusPolicy::ExpiryOnly,
        )
        .expect("anchor")
    }

    fn envelope() -> auths_model::SignatureEnvelope {
        auths_model::SignatureEnvelope::new(
            auths_model::SignatureDescriptor::new(
                PrincipalMethodId::parse("raw-key-v1").expect("method"),
                auths_model::VerificationMethod::parse("raw:issuer#key-1").expect("key"),
                SignatureSuiteId::parse("ed25519-v1").expect("suite"),
            ),
            auths_model::SignatureBytes::new(vec![1; 64]).expect("signature"),
        )
    }

    fn principal_statement(
        status_method: &str,
        subject: &str,
        state: PrincipalState,
        sequence: u64,
        issuer: &str,
    ) -> auths_model::SignedPrincipalStatus {
        auths_model::SignedPrincipalStatus::new(
            auths_model::PrincipalStatusStatement::new(
                method(status_method),
                principal(subject),
                state,
                sequence,
                Timestamp::new(40),
                Timestamp::new(100),
                principal(issuer),
                auths_model::CriticalExtensions::empty(),
            )
            .expect("principal status"),
            envelope(),
        )
    }

    fn grant_statement(
        grant: GrantId,
        state: GrantState,
        sequence: u64,
        issuer: &str,
    ) -> auths_model::SignedGrantStatus {
        auths_model::SignedGrantStatus::new(
            auths_model::GrantStatusStatement::new(
                method(PRIMARY_STATUS),
                grant,
                state,
                sequence,
                Timestamp::new(40),
                Timestamp::new(100),
                principal(issuer),
                auths_model::CriticalExtensions::empty(),
            )
            .expect("grant status"),
            envelope(),
        )
    }

    fn required() -> StatusPolicy {
        StatusPolicy::SnapshotRequired {
            method: method(PRIMARY_STATUS),
            max_age: auths_model::FreshnessLimit::new(100).expect("freshness"),
        }
    }

    fn exact() -> ExactStatusMethod {
        ExactStatusMethod {
            id: method(PRIMARY_STATUS),
        }
    }

    fn rule(status_method: &str, issuer: &str, floor: u64, scope: StatusScope) -> StatusTrustRule {
        StatusTrustRule::new(method(status_method), principal(issuer), floor, scope)
    }

    /// The same rules with every scope widened to `any`, under which scope
    /// filters nothing.
    fn unscoped(trust: &[StatusTrustRule]) -> Vec<StatusTrustRule> {
        trust
            .iter()
            .map(|rule| {
                StatusTrustRule::new(
                    rule.method().clone(),
                    rule.issuer().clone(),
                    rule.sequence_floor(),
                    StatusScope::AnyAnchor,
                )
            })
            .collect()
    }

    #[test]
    fn an_out_of_scope_issuer_is_invisible_under_every_method() {
        let verifier_anchor = status_anchor("anchor-v", "raw:v-root");
        let partner_anchor = status_anchor("anchor-f", "raw:f-root");
        let snapshot = PrincipalStatusSnapshot::with_trust(
            auths_model::StatusSnapshotId::new([1; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            vec![principal_statement(
                OTHER_STATUS,
                "raw:v-actor",
                PrincipalState::Revoked,
                1,
                "raw:f-root",
            )],
            Vec::new(),
            vec![rule(
                PRIMARY_STATUS,
                "raw:f-root",
                1,
                StatusScope::OwnAnchor,
            )],
        )
        .expect("snapshot");
        let subject = principal("raw:v-actor");
        let under = |anchor: &TrustAnchor| {
            exact()
                .principal(&required(), &snapshot, &subject, anchor, Timestamp::new(50))
                .expect("evaluation")
        };
        // Visible, the statement forces a method mismatch.
        assert_eq!(under(&partner_anchor), StatusDecision::WrongMethod);
        // Out of scope, it is absent, whatever its method.
        assert_eq!(under(&verifier_anchor), StatusDecision::Missing);
    }

    /// For every snapshot, anchor, and subject, the status result equals the
    /// result on the same snapshot with the anchor's out-of-scope statements
    /// removed and no scope left to apply: scope changes visibility and
    /// nothing else.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn scope_only_removes_out_of_scope_statements() {
        let anchors = [
            status_anchor("anchor-v", "raw:v-root"),
            status_anchor("anchor-f", "raw:f-root"),
        ];
        let issuers = ["raw:v-root", "raw:f-root", "raw:service", "raw:unknown"];
        let subjects = ["raw:v-root", "raw:v-actor", "raw:f-actor"];
        let grants = [GrantId::new([7; 32]), GrantId::new([8; 32])];
        let principal_states = [
            PrincipalState::Active,
            PrincipalState::Revoked,
            PrincipalState::Superseded,
        ];
        let grant_states = [GrantState::Active, GrantState::Revoked];
        let principal_snapshot = |statements: Vec<_>, trust: Vec<_>| {
            PrincipalStatusSnapshot::with_trust(
                auths_model::StatusSnapshotId::new([1; 32]),
                Timestamp::new(40),
                Timestamp::new(100),
                statements,
                Vec::new(),
                trust,
            )
        };
        let grant_snapshot = |statements: Vec<_>, trust: Vec<_>| {
            GrantStatusSnapshot::with_trust(
                auths_model::StatusSnapshotId::new([2; 32]),
                Timestamp::new(40),
                Timestamp::new(100),
                statements,
                Vec::new(),
                trust,
            )
        };
        let mut cases = Cases(0x5eed_0f5c_09e5_0001);
        let mut checked = 0usize;
        for _ in 0..4_000 {
            // Rules for the three named issuers; `raw:unknown` stays unnamed.
            let mut trust = Vec::new();
            for issuer in &issuers[..3] {
                let owner = matches!(*issuer, "raw:v-root" | "raw:f-root");
                let scope = match cases.below(4) {
                    0 if owner => StatusScope::OwnAnchor,
                    0 | 1 => StatusScope::Anchors(
                        StatusScopeAnchors::new(match cases.below(3) {
                            0 => vec![anchors[0].id().clone()],
                            1 => vec![anchors[1].id().clone()],
                            _ => vec![anchors[0].id().clone(), anchors[1].id().clone()],
                        })
                        .expect("listed anchors"),
                    ),
                    _ => StatusScope::AnyAnchor,
                };
                trust.push(rule(
                    PRIMARY_STATUS,
                    issuer,
                    cases.sequence(2),
                    scope.clone(),
                ));
                if cases.below(3) == 0 {
                    trust.push(rule(OTHER_STATUS, issuer, 1, scope));
                }
            }
            let principal_statements: Vec<_> = (0..cases.below(6))
                .map(|_| {
                    let status_method = if cases.below(5) == 0 {
                        OTHER_STATUS
                    } else {
                        PRIMARY_STATUS
                    };
                    let subject = *cases.pick(&subjects);
                    let state = *cases.pick(&principal_states);
                    let sequence = cases.sequence(4);
                    let issuer = *cases.pick(&issuers);
                    principal_statement(status_method, subject, state, sequence, issuer)
                })
                .collect();
            let grant_statements: Vec<_> = (0..cases.below(5))
                .map(|_| {
                    let grant = *cases.pick(&grants);
                    let state = *cases.pick(&grant_states);
                    let sequence = cases.sequence(4);
                    let issuer = *cases.pick(&issuers);
                    grant_statement(grant, state, sequence, issuer)
                })
                .collect();
            // A repeated statement is not a valid snapshot; draw again.
            let (Ok(scoped_principal), Ok(scoped_grant)) = (
                principal_snapshot(principal_statements.clone(), trust.clone()),
                grant_snapshot(grant_statements.clone(), trust.clone()),
            ) else {
                continue;
            };
            for anchor in &anchors {
                let visible = |issuer: &PrincipalId| status_issuer_in_scope(&trust, issuer, anchor);
                let reduced_principal = principal_snapshot(
                    principal_statements
                        .iter()
                        .filter(|signed| visible(signed.statement().issuer()))
                        .cloned()
                        .collect(),
                    unscoped(&trust),
                )
                .expect("reduced principal snapshot");
                let reduced_grant = grant_snapshot(
                    grant_statements
                        .iter()
                        .filter(|signed| visible(signed.statement().issuer()))
                        .cloned()
                        .collect(),
                    unscoped(&trust),
                )
                .expect("reduced grant snapshot");
                for subject in subjects.map(principal) {
                    let evaluate = |snapshot: &PrincipalStatusSnapshot| {
                        exact()
                            .principal(&required(), snapshot, &subject, anchor, Timestamp::new(50))
                            .expect("principal evaluation")
                    };
                    assert_eq!(evaluate(&scoped_principal), evaluate(&reduced_principal));
                }
                for grant in grants {
                    let evaluate = |snapshot: &GrantStatusSnapshot| {
                        exact()
                            .grant(&required(), snapshot, grant, anchor, Timestamp::new(50))
                            .expect("grant evaluation")
                    };
                    assert_eq!(evaluate(&scoped_grant), evaluate(&reduced_grant));
                }
                checked += 1;
            }
        }
        assert!(checked > 4_000, "too few valid cases: {checked}");
    }
}
