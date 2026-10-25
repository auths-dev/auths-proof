//! Bounded statically dispatched core registries.
//!
//! These registries own at most two principal methods and two signature suites
//! and expose only the built-in pure semantics. Their concrete P/S types name
//! the executable configuration; choosing this container alone earns no proof.

use alloc::{string::String, vec::Vec};
use auths_model::*;
use auths_ports::*;
use crate::{CoreSemantics, RegistryAccess, RegistryError, TARGET_V1_REGISTRY_MANIFEST};

/// Built-in resource semantics with a concrete dispatch type.
pub struct BuiltinResource(crate::UriNamespaceMatcher);

impl ResourceMatcher for BuiltinResource {
    fn id(&self) -> &ResourceMatcherId { self.0.id() }
    fn configuration_id(&self) -> AdapterConfigurationId { self.0.configuration_id() }
    fn maximum_work_units(&self, namespace: &ResourceId, resource: &ResourceId) -> u64 { self.0.maximum_work_units(namespace, resource) }
    fn matches(&self, namespace: &ResourceId, resource: &ResourceId) -> Result<bool, RegistryOperationError> { self.0.matches(namespace, resource) }
}

/// Built-in profile semantics with a concrete dispatch type.
pub struct BuiltinProfile(crate::ExactProfilePolicy);

impl ProfilePolicy for BuiltinProfile {
    fn id(&self) -> &ProfilePolicyId { self.0.id() }
    fn configuration_id(&self) -> AdapterConfigurationId { self.0.configuration_id() }
    fn maximum_work_units(&self, action: &CanonicalAction) -> u64 { self.0.maximum_work_units(action) }
    fn evaluate(&self, action: &CanonicalAction) -> Result<ProfileDecision, RegistryOperationError> { self.0.evaluate(action) }
    fn action_fact(&self, action: &CanonicalAction, name: &FactName) -> Result<Option<FactValue>, RegistryOperationError> { self.0.action_fact(action, name) }
}

/// Built-in budget semantics with a concrete dispatch type.
pub struct BuiltinBudget(crate::NumericBudgetAlgebra);

impl BudgetAlgebra for BuiltinBudget {
    fn id(&self) -> &BudgetAlgebraId { self.0.id() }
    fn configuration_id(&self) -> AdapterConfigurationId { self.0.configuration_id() }
    fn maximum_work_units(&self) -> u64 { self.0.maximum_work_units() }
    fn attenuates(&self, child: &BudgetCeiling, parent: &BudgetCeiling) -> Result<bool, RegistryOperationError> { self.0.attenuates(child, parent) }
    fn covers(&self, ceiling: &BudgetCeiling, requested: &BudgetCeiling) -> Result<bool, RegistryOperationError> { self.0.covers(ceiling, requested) }
}

/// Built-in status semantics with a concrete dispatch type.
pub struct BuiltinStatus(crate::ExactStatusMethod);

impl StatusMethod for BuiltinStatus {
    fn id(&self) -> &StatusMethodId { self.0.id() }
    fn configuration_id(&self) -> AdapterConfigurationId { self.0.configuration_id() }
    fn maximum_work_units(&self, statement_count: usize) -> u64 { self.0.maximum_work_units(statement_count) }
    fn principal(&self, policy: &StatusPolicy, snapshot: &PrincipalStatusSnapshot, principal: &PrincipalId, view: StatusView<'_>, evaluation_time: Timestamp) -> Result<StatusEvaluation, RegistryOperationError> { self.0.principal(policy, snapshot, principal, view, evaluation_time) }
    fn grant(&self, policy: &StatusPolicy, snapshot: &GrantStatusSnapshot, grant: GrantId, view: StatusView<'_>, evaluation_time: Timestamp) -> Result<StatusEvaluation, RegistryOperationError> { self.0.grant(policy, snapshot, grant, view, evaluation_time) }
}

/// Built-in claim semantics with a concrete dispatch type.
pub struct BuiltinClaim(crate::ExactClaimRule);

impl AssuranceClaimRule for BuiltinClaim {
    fn id(&self) -> &AssuranceClaimId { self.0.id() }
    fn configuration_id(&self) -> AdapterConfigurationId { self.0.configuration_id() }
    fn maximum_work_units(&self, claim: &AssuranceClaim) -> u64 { self.0.maximum_work_units(claim) }
    fn validate(&self, claim: &AssuranceClaim) -> Result<(), RegistryOperationError> { self.0.validate(claim) }
}

/// One of the four built-in critical-extension handlers. No caller can
/// supply another handler through this type.
pub struct BuiltinExtension { implementation: BuiltinExtensionKind }
enum BuiltinExtensionKind {
    Marker(crate::ExactMarkerExtension),
    Observation(crate::ObservationRequirementExtension),
    BoundedPolicy(crate::BoundedPolicyCommitmentExtension),
    Approval(crate::ApprovalRequirementExtension),
}

impl CriticalExtensionHandler for BuiltinExtension {
    fn id(&self) -> &ExtensionId {
        match &self.implementation {
            BuiltinExtensionKind::Marker(handler) => handler.id(),
            BuiltinExtensionKind::Observation(handler) => handler.id(),
            BuiltinExtensionKind::BoundedPolicy(handler) => handler.id(),
            BuiltinExtensionKind::Approval(handler) => handler.id(),
        }
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        match &self.implementation {
            BuiltinExtensionKind::Marker(handler) => handler.configuration_id(),
            BuiltinExtensionKind::Observation(handler) => handler.configuration_id(),
            BuiltinExtensionKind::BoundedPolicy(handler) => handler.configuration_id(),
            BuiltinExtensionKind::Approval(handler) => handler.configuration_id(),
        }
    }
    fn maximum_work_units(&self, extension: &CriticalExtension) -> u64 {
        match &self.implementation {
            BuiltinExtensionKind::Marker(handler) => handler.maximum_work_units(extension),
            BuiltinExtensionKind::Observation(handler) => handler.maximum_work_units(extension),
            BuiltinExtensionKind::BoundedPolicy(handler) => handler.maximum_work_units(extension),
            BuiltinExtensionKind::Approval(handler) => handler.maximum_work_units(extension),
        }
    }
    fn evaluate(&self, extension: &CriticalExtension) -> Result<(), RegistryOperationError> {
        match &self.implementation {
            BuiltinExtensionKind::Marker(handler) => handler.evaluate(extension),
            BuiltinExtensionKind::Observation(handler) => handler.evaluate(extension),
            BuiltinExtensionKind::BoundedPolicy(handler) => handler.evaluate(extension),
            BuiltinExtensionKind::Approval(handler) => handler.evaluate(extension),
        }
    }
    fn attenuates(&self, child: Option<&[u8]>, parent: Option<&[u8]>) -> Result<bool, RegistryOperationError> {
        match &self.implementation {
            BuiltinExtensionKind::Marker(handler) => handler.attenuates(child, parent),
            BuiltinExtensionKind::Observation(handler) => handler.attenuates(child, parent),
            BuiltinExtensionKind::BoundedPolicy(handler) => handler.attenuates(child, parent),
            BuiltinExtensionKind::Approval(handler) => handler.attenuates(child, parent),
        }
    }
}

/// No explicit assurance-implication edge belongs to this closed core set.
#[derive(Clone, Copy)]
pub enum BuiltinImplication {}
impl AssuranceImplication for BuiltinImplication {
    fn id(&self) -> &AssuranceImplicationId { match *self {} }
    fn configuration_id(&self) -> AdapterConfigurationId { match *self {} }
    fn source(&self) -> &AssuranceClaimId { match *self {} }
    fn target(&self) -> &AssuranceClaimId { match *self {} }
    fn maximum_work_units(&self) -> u64 { match *self {} }
    fn implies(&self, _claim: &AssuranceClaim) -> Result<bool, RegistryOperationError> { match *self {} }
}

/// Bounded static registry container for the core pure semantics.
///
/// P and S are normally the closed principal and suite enums exported by the
/// verifier. Keeping them generic lets the verifier use one algorithm for its
/// open adapter API and its declared closed configuration. No dynamic pure
/// handlers or caller-supplied implications can enter this container.
pub struct StaticCoreRegistries<P, S> {
    principal_methods: [Option<P>; 2],
    signature_suites: [Option<S>; 2],
    resource: BuiltinResource,
    profile: BuiltinProfile,
    budget: BuiltinBudget,
    extensions: [BuiltinExtension; 4],
    status: Vec<BuiltinStatus>,
    claims: Vec<BuiltinClaim>,
    configuration: VerifierConfigurationId,
}

impl<P: PrincipalMethod, S: SignatureSuite> StaticCoreRegistries<P, S> {
    /// Constructs an immutable, bounded registry with the built-in semantics.
    ///
    /// Empty slots are absent implementations. Configuration framing is
    /// identical to the open registry with the same implementations and no
    /// additional pure handlers.
    ///
    /// # Errors
    /// Returns a typed error for a duplicate exact principal/suite identifier
    /// or an invalid compiled core identifier.
    pub fn new(
        principal_methods: [Option<P>; 2],
        signature_suites: [Option<S>; 2],
    ) -> Result<Self, RegistryError> {
        if let (Some(left), Some(right)) = (&principal_methods[0], &principal_methods[1])
            && left.id() == right.id()
        {
            return Err(RegistryError::DuplicateImplementation);
        }
        if let (Some(left), Some(right)) = (&signature_suites[0], &signature_suites[1])
            && left.id() == right.id()
        {
            return Err(RegistryError::DuplicateImplementation);
        }
        let core = CoreSemantics::new()?;
        let mut entries: Vec<(u8, String, AdapterConfigurationId)> = Vec::new();
        let mut position = 0;
        while position < 2 {
            if let Some(method) = &principal_methods[position] {
                entries.push((0, method.id().as_str().into(), method.configuration_id()));
            }
            if let Some(suite) = &signature_suites[position] {
                entries.push((1, suite.id().as_str().into(), suite.configuration_id()));
            }
            position += 1;
        }
        entries.push((2, core.resource.id().as_str().into(), core.resource.configuration_id()));
        entries.push((3, core.profile.id().as_str().into(), core.profile.configuration_id()));
        entries.push((4, core.budget.id().as_str().into(), core.budget.configuration_id()));
        entries.push((5, core.extension.id().as_str().into(), core.extension.configuration_id()));
        entries.push((5, core.observation.id().as_str().into(), core.observation.configuration_id()));
        entries.push((5, core.bounded_policy.id().as_str().into(), core.bounded_policy.configuration_id()));
        entries.push((5, core.approval.id().as_str().into(), core.approval.configuration_id()));
        let mut position = 0;
        while position < core.status.len() {
            let method = &core.status[position];
            entries.push((6, method.id().as_str().into(), method.configuration_id()));
            position += 1;
        }
        let mut position = 0;
        while position < core.claims.len() {
            let rule = &core.claims[position];
            entries.push((7, rule.id().as_str().into(), rule.configuration_id()));
            position += 1;
        }
        let configuration = crate::configuration_from_entries(entries);
        let CoreSemantics { resource, profile, budget, extension, observation,
            bounded_policy, approval, status, claims } = core;
        Ok(Self {
            principal_methods, signature_suites,
            resource: BuiltinResource(resource), profile: BuiltinProfile(profile),
            budget: BuiltinBudget(budget),
            extensions: [
                BuiltinExtension { implementation: BuiltinExtensionKind::Marker(extension) },
                BuiltinExtension { implementation: BuiltinExtensionKind::Observation(observation) },
                BuiltinExtension { implementation: BuiltinExtensionKind::BoundedPolicy(bounded_policy) },
                BuiltinExtension { implementation: BuiltinExtensionKind::Approval(approval) },
            ],
            status: wrap_status(status),
            claims: wrap_claims(claims),
            configuration,
        })
    }
}

impl<P: PrincipalMethod, S: SignatureSuite> RegistryAccess for StaticCoreRegistries<P, S> {
    type Principal = P;
    type Signature = S;
    type Resource = BuiltinResource;
    type Profile = BuiltinProfile;
    type Budget = BuiltinBudget;
    type Extension = BuiltinExtension;
    type Status = BuiltinStatus;
    type Claim = BuiltinClaim;
    type Implication = BuiltinImplication;

    fn manifest_id(&self) -> RegistryManifestId { TARGET_V1_REGISTRY_MANIFEST }
    fn configuration_id(&self) -> VerifierConfigurationId { self.configuration }
    fn principal_method(&self, accepted: &AcceptedRegistries, id: &PrincipalMethodId) -> Option<&Self::Principal> {
        if !accepted.accepts_principal_method(id) { return None; }
        let mut position = 0;
        while position < self.principal_methods.len() {
            if let Some(implementation) = &self.principal_methods[position]
                && implementation.id() == id { return Some(implementation); }
            position += 1;
        }
        None
    }
    fn signature_suite(&self, accepted: &AcceptedRegistries, id: &SignatureSuiteId) -> Option<&Self::Signature> {
        if !accepted.accepts_signature_suite(id) { return None; }
        let mut position = 0;
        while position < self.signature_suites.len() {
            if let Some(implementation) = &self.signature_suites[position]
                && implementation.id() == id { return Some(implementation); }
            position += 1;
        }
        None
    }
    fn resource_matcher(&self, accepted: &AcceptedRegistries, id: &ResourceMatcherId) -> Option<&Self::Resource> {
        if accepted.accepts_resource_matcher(id) && self.resource.id() == id { Some(&self.resource) } else { None }
    }
    fn profile_policy(&self, accepted: &AcceptedRegistries, id: &ProfilePolicyId) -> Option<&Self::Profile> {
        if accepted.accepts_profile_policy(id) && self.profile.id() == id { Some(&self.profile) } else { None }
    }
    fn budget_algebra(&self, accepted: &AcceptedRegistries, id: &BudgetAlgebraId) -> Option<&Self::Budget> {
        if accepted.accepts_budget_algebra(id) && self.budget.id() == id { Some(&self.budget) } else { None }
    }
    fn extension_handler(&self, accepted: &AcceptedRegistries, id: &ExtensionId) -> Option<&Self::Extension> {
        if !accepted.accepts_critical_extension(id) { return None; }
        let mut position = 0;
        while position < self.extensions.len() {
            if self.extensions[position].id() == id { return Some(&self.extensions[position]); }
            position += 1;
        }
        None
    }
    fn assurance_claim(&self, accepted: &AcceptedRegistries, id: &AssuranceClaimId) -> Option<&Self::Claim> {
        if !accepted.accepts_assurance_claim(id) { return None; }
        let mut position = 0;
        while position < self.claims.len() {
            if self.claims[position].id() == id { return Some(&self.claims[position]); }
            position += 1;
        }
        None
    }
    fn status_method(&self, accepted: &AcceptedRegistries, id: &StatusMethodId, principal: bool)
    -> Option<&Self::Status> {
        let enabled = if principal { accepted.accepts_principal_status_method(id) }
            else { accepted.accepts_grant_status_method(id) };
        if !enabled { return None; }
        let mut position = 0;
        while position < self.status.len() {
            if self.status[position].id() == id { return Some(&self.status[position]); }
            position += 1;
        }
        None
    }
    fn assurance_implications(&self, _accepted: &AcceptedRegistries) -> Vec<&Self::Implication> {
        Vec::new()
    }
}

fn wrap_status(mut source: Vec<crate::ExactStatusMethod>) -> Vec<BuiltinStatus> {
    let mut output = Vec::with_capacity(source.len());
    while let Some(method) = source.pop() { output.push(BuiltinStatus(method)); }
    output.reverse();
    output
}
fn wrap_claims(mut source: Vec<crate::ExactClaimRule>) -> Vec<BuiltinClaim> {
    let mut output = Vec::with_capacity(source.len());
    while let Some(rule) = source.pop() { output.push(BuiltinClaim(rule)); }
    output.reverse();
    output
}
