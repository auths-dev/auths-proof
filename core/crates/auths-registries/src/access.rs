//! Registry selection shared by the open and closed verifier configurations.
//!
//! Associated handler types preserve static dispatch through the verifier. A
//! closed implementation supplies concrete enums; the extensible implementation
//! supplies its existing trait objects. Both run the same staged verifier.

use alloc::vec::Vec;
use auths_model::{
    AcceptedRegistries, AssuranceClaimId, BudgetAlgebraId, ExtensionId, PrincipalMethodId,
    ProfilePolicyId, RegistryManifestId, ResourceMatcherId, SignatureSuiteId, StatusMethodId,
    VerifierConfigurationId,
};
use auths_ports::{
    AssuranceClaimRule, AssuranceImplication, BudgetAlgebra, CriticalExtensionHandler,
    PrincipalMethod, ProfilePolicy, ResourceMatcher, SignatureSuite, StatusMethod,
};

/// Immutable executable registry selection for one verifier invocation.
///
/// Selection must require exact identifier equality and context acceptance.
/// A configuration commitment describes implementations; it never substitutes
/// for executing their checks. Formal claims must name the concrete registry
/// implementation and its selection/dispatch refinement.
pub trait RegistryAccess {
    /// Concrete principal-control handler carrier.
    type Principal: PrincipalMethod + ?Sized;
    /// Concrete signature-suite handler carrier.
    type Signature: SignatureSuite + ?Sized;
    /// Concrete resource-namespace handler carrier.
    type Resource: ResourceMatcher + ?Sized;
    /// Concrete profile-policy and action-fact handler carrier.
    type Profile: ProfilePolicy + ?Sized;
    /// Concrete budget-algebra handler carrier.
    type Budget: BudgetAlgebra + ?Sized;
    /// Concrete critical-extension handler carrier.
    type Extension: CriticalExtensionHandler + ?Sized;
    /// Concrete status-method handler carrier.
    type Status: StatusMethod + ?Sized;
    /// Concrete assurance-claim validator carrier.
    type Claim: AssuranceClaimRule + ?Sized;
    /// Concrete explicit assurance-implication carrier.
    type Implication: AssuranceImplication + ?Sized;

    /// Returns the exact implemented protocol registry manifest.
    fn manifest_id(&self) -> RegistryManifestId;
    /// Commits to every executable handler and its immutable configuration.
    fn configuration_id(&self) -> VerifierConfigurationId;
    /// Selects an exactly identified and context-accepted principal method.
    fn principal_method(&self, accepted: &AcceptedRegistries, id: &PrincipalMethodId)
    -> Option<&Self::Principal>;
    /// Selects an exactly identified and context-accepted signature suite.
    fn signature_suite(&self, accepted: &AcceptedRegistries, id: &SignatureSuiteId)
    -> Option<&Self::Signature>;
    /// Selects an exactly identified and context-accepted resource matcher.
    fn resource_matcher(&self, accepted: &AcceptedRegistries, id: &ResourceMatcherId)
    -> Option<&Self::Resource>;
    /// Selects an exactly identified and context-accepted profile policy.
    fn profile_policy(&self, accepted: &AcceptedRegistries, id: &ProfilePolicyId)
    -> Option<&Self::Profile>;
    /// Selects an exactly identified and context-accepted budget algebra.
    fn budget_algebra(&self, accepted: &AcceptedRegistries, id: &BudgetAlgebraId)
    -> Option<&Self::Budget>;
    /// Selects an exactly identified and context-accepted critical-extension handler.
    fn extension_handler(&self, accepted: &AcceptedRegistries, id: &ExtensionId)
    -> Option<&Self::Extension>;
    /// Selects an exact status method from the principal or grant accepted set.
    fn status_method(&self, accepted: &AcceptedRegistries, id: &StatusMethodId, principal: bool)
    -> Option<&Self::Status>;
    /// Selects an exactly identified and context-accepted claim validator.
    fn assurance_claim(&self, accepted: &AcceptedRegistries, id: &AssuranceClaimId)
    -> Option<&Self::Claim>;
    /// Returns context-accepted explicit implications in exact identifier order.
    fn assurance_implications(&self, accepted: &AcceptedRegistries) -> Vec<&Self::Implication>;

    /// Exposes only the attenuation laws selected by this same registry and context.
    fn extension_laws<'s>(
        &'s self,
        accepted: &'s AcceptedRegistries,
    ) -> crate::AcceptedExtensionLaws<'s, Self> {
        crate::AcceptedExtensionLaws { registries: self, accepted }
    }
}

impl<'a> RegistryAccess for crate::ImmutableRegistries<'a> {
    type Principal = dyn PrincipalMethod + 'a;
    type Signature = dyn SignatureSuite + 'a;
    type Resource = dyn ResourceMatcher + 'a;
    type Profile = dyn ProfilePolicy + 'a;
    type Budget = dyn BudgetAlgebra + 'a;
    type Extension = dyn CriticalExtensionHandler + 'a;
    type Status = dyn StatusMethod + 'a;
    type Claim = dyn AssuranceClaimRule + 'a;
    type Implication = dyn AssuranceImplication + 'a;

    fn manifest_id(&self) -> RegistryManifestId { self.manifest_id() }
    fn configuration_id(&self) -> VerifierConfigurationId { self.configuration_id() }
    fn principal_method(&self, accepted: &AcceptedRegistries, id: &PrincipalMethodId)
    -> Option<&Self::Principal> { self.principal_method(accepted, id) }
    fn signature_suite(&self, accepted: &AcceptedRegistries, id: &SignatureSuiteId)
    -> Option<&Self::Signature> { self.signature_suite(accepted, id) }
    fn resource_matcher(&self, accepted: &AcceptedRegistries, id: &ResourceMatcherId)
    -> Option<&Self::Resource> { self.resource_matcher(accepted, id) }
    fn profile_policy(&self, accepted: &AcceptedRegistries, id: &ProfilePolicyId)
    -> Option<&Self::Profile> { self.profile_policy(accepted, id) }
    fn budget_algebra(&self, accepted: &AcceptedRegistries, id: &BudgetAlgebraId)
    -> Option<&Self::Budget> { self.budget_algebra(accepted, id) }
    fn extension_handler(&self, accepted: &AcceptedRegistries, id: &ExtensionId)
    -> Option<&Self::Extension> { self.extension_handler(accepted, id) }
    fn status_method(&self, accepted: &AcceptedRegistries, id: &StatusMethodId, principal: bool)
    -> Option<&Self::Status> { self.status_method(accepted, id, principal) }
    fn assurance_claim(&self, accepted: &AcceptedRegistries, id: &AssuranceClaimId)
    -> Option<&Self::Claim> { self.assurance_claim(accepted, id) }
    fn assurance_implications(&self, accepted: &AcceptedRegistries) -> Vec<&Self::Implication> {
        self.assurance_implications(accepted)
    }
}
