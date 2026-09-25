//! Trusted-context templates for the target V1 registries.

use alloc::{collections::BTreeSet, vec, vec::Vec};
use auths_model::{
    AcceptedRegistries, AssuranceClaimId, AssurancePolicy, Audience, BudgetAlgebraId, Challenge,
    ChannelBindingId, CompositionRequirement, EvidenceTypeId, ExtensionId, GrantStatusSnapshot,
    ModelError, PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId, ProfileRef,
    ResourceMatcherId, SignatureSuiteId, StatusMethodId, StatusPolicy, StatusSnapshotId, Timestamp,
    TrustAnchor, TrustedContext, VerifierConfigurationId, VerifierLimits,
};

use crate::{EXACT_PROFILE_V1, NUMERIC_CEILING_V1, TARGET_V1_REGISTRY_MANIFEST, URI_NAMESPACE_V1};

/// Audience a template carries until a request binding replaces it.
const TEMPLATE_AUDIENCE: &str = "auths://request-template";

/// One immutable trusted-context template for the target V1 registries.
///
/// This is the single assembly behind the Rust SDK's `TrustedContextBuilder`
/// and the WASM package's template function, so equal inputs give equal
/// context bytes in every language.
///
/// The accepted registries derive from the inputs: every anchor's principal
/// methods and profiles, the status method of every anchor whose status
/// policy requires a snapshot, the assurance policy's claims, and the given
/// signature suites, evidence types, and critical extensions. The resource
/// matcher, budget algebra, and profile policy are the target V1 ones. The
/// template names no request: its audience, challenge, and evaluation time
/// are placeholders that a request binding replaces.
pub struct TrustedContextTemplate {
    configuration: VerifierConfigurationId,
    composition: CompositionRequirement,
    trust_anchors: Vec<TrustAnchor>,
    assurance_policy: AssurancePolicy,
    principal_status: PrincipalStatusSnapshot,
    grant_status: GrantStatusSnapshot,
    channel_policy: ChannelBindingId,
    limits: VerifierLimits,
    signature_suites: BTreeSet<SignatureSuiteId>,
    evidence_types: BTreeSet<EvidenceTypeId>,
    critical_extensions: BTreeSet<ExtensionId>,
    budget_free_profiles: BTreeSet<ProfileRef>,
}

impl TrustedContextTemplate {
    /// Starts a template from explicit roots, an assurance policy, and the
    /// accepted signature suites.
    ///
    /// Every anchor's principal methods are also accepted as evidence types.
    /// The template starts with empty principal and grant status snapshots,
    /// the `none-v1` channel policy, and the default verifier limits.
    ///
    /// # Errors
    ///
    /// Returns a model error when an anchor's principal method is not a valid
    /// evidence identifier or a compiled V1 identifier is invalid. An empty
    /// anchor set is rejected by [`Self::compile`].
    pub fn new(
        configuration: VerifierConfigurationId,
        composition: CompositionRequirement,
        trust_anchors: Vec<TrustAnchor>,
        assurance_policy: AssurancePolicy,
        signature_suites: impl IntoIterator<Item = SignatureSuiteId>,
    ) -> Result<Self, ModelError> {
        let evidence_types = trust_anchors
            .iter()
            .flat_map(TrustAnchor::accepted_methods)
            .map(|method| EvidenceTypeId::parse(method.as_str()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            configuration,
            composition,
            trust_anchors,
            assurance_policy,
            principal_status: PrincipalStatusSnapshot::new(
                StatusSnapshotId::new([0; 32]),
                Timestamp::new(0),
                Timestamp::new(u64::MAX),
                Vec::new(),
                Vec::new(),
            )?,
            grant_status: GrantStatusSnapshot::new(
                StatusSnapshotId::new([1; 32]),
                Timestamp::new(0),
                Timestamp::new(u64::MAX),
                Vec::new(),
                Vec::new(),
            )?,
            channel_policy: ChannelBindingId::parse("none-v1")?,
            limits: VerifierLimits::default(),
            signature_suites: signature_suites.into_iter().collect(),
            evidence_types,
            critical_extensions: BTreeSet::new(),
            budget_free_profiles: BTreeSet::new(),
        })
    }

    /// Replaces the principal status snapshot.
    #[must_use]
    pub fn with_principal_status(mut self, snapshot: PrincipalStatusSnapshot) -> Self {
        self.principal_status = snapshot;
        self
    }

    /// Replaces the grant status snapshot.
    #[must_use]
    pub fn with_grant_status(mut self, snapshot: GrantStatusSnapshot) -> Self {
        self.grant_status = snapshot;
        self
    }

    /// Selects the channel-binding policy.
    #[must_use]
    pub fn with_channel_policy(mut self, policy: ChannelBindingId) -> Self {
        self.channel_policy = policy;
        self
    }

    /// Selects the verifier limits.
    #[must_use]
    pub fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Accepts one more evidence type. Accepting one twice has no effect.
    #[must_use]
    pub fn accept_evidence_type(mut self, identifier: EvidenceTypeId) -> Self {
        self.evidence_types.insert(identifier);
        self
    }

    /// Accepts one critical extension. Accepting one twice has no effect.
    #[must_use]
    pub fn accept_critical_extension(mut self, identifier: ExtensionId) -> Self {
        self.critical_extensions.insert(identifier);
        self
    }

    /// Declares a profile whose canonical actions cannot express a budget, so
    /// an action of that profile provably spends zero.
    ///
    /// The declaration must come from the profile implementation itself; the
    /// template cannot see implementations. A profile that is never declared
    /// keeps the denying reading of an absent request under a bounded
    /// ceiling. [`Self::compile`] drops a declaration for a profile no anchor
    /// accepts, because the accepted profiles derive from the anchors.
    #[must_use]
    pub fn declare_budget_free_profile(mut self, profile: ProfileRef) -> Self {
        self.budget_free_profiles.insert(profile);
        self
    }

    /// Compiles the template into one immutable trusted context.
    ///
    /// # Errors
    ///
    /// Returns a model error when the anchors are empty or invalid, or when
    /// the profiles, status policies, registries, or limits disagree.
    pub fn compile(self) -> Result<TrustedContext, ModelError> {
        let principal_methods: BTreeSet<PrincipalMethodId> = self
            .trust_anchors
            .iter()
            .flat_map(TrustAnchor::accepted_methods)
            .cloned()
            .collect();
        let profiles: BTreeSet<ProfileRef> = self
            .trust_anchors
            .iter()
            .flat_map(TrustAnchor::profiles)
            .cloned()
            .collect();
        let principal_status_methods: BTreeSet<StatusMethodId> = self
            .trust_anchors
            .iter()
            .filter_map(|anchor| match anchor.status_policy() {
                StatusPolicy::ExpiryOnly => None,
                StatusPolicy::SnapshotRequired { method, .. } => Some(method.clone()),
            })
            .collect();
        let assurance_claims: BTreeSet<AssuranceClaimId> = self
            .assurance_policy
            .requirements()
            .iter()
            .map(|requirement| requirement.claim_kind().clone())
            .collect();
        let budget_free_profiles: Vec<ProfileRef> = self
            .budget_free_profiles
            .iter()
            .filter(|profile| profiles.contains(*profile))
            .cloned()
            .collect();
        let accepted = AcceptedRegistries::new(
            TARGET_V1_REGISTRY_MANIFEST,
            principal_methods.into_iter().collect(),
            self.signature_suites.into_iter().collect(),
            self.evidence_types.into_iter().collect(),
            principal_status_methods.into_iter().collect(),
            Vec::new(),
            assurance_claims.into_iter().collect(),
            Vec::new(),
            vec![ResourceMatcherId::parse(URI_NAMESPACE_V1)?],
            vec![BudgetAlgebraId::parse(NUMERIC_CEILING_V1)?],
            self.critical_extensions.into_iter().collect(),
            profiles.into_iter().collect(),
            vec![ProfilePolicyId::parse(EXACT_PROFILE_V1)?],
        )?
        .with_budget_free_profiles(budget_free_profiles)?;
        TrustedContext::new(
            self.configuration,
            self.composition,
            self.trust_anchors,
            accepted,
            Audience::parse(TEMPLATE_AUDIENCE)?,
            Challenge::new([0; 32]),
            Timestamp::new(0),
            self.assurance_policy,
            self.principal_status,
            self.grant_status,
            ResourceMatcherId::parse(URI_NAMESPACE_V1)?,
            ProfilePolicyId::parse(EXACT_PROFILE_V1)?,
            self.channel_policy,
            self.limits,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, AudienceSet, CapabilityId,
        FreshnessLimit, ParticipantRole, Permission, PermissionSet, PrincipalId, ProfileId,
        ResourceId, TrustAnchorId, ValidityWindow,
    };

    fn profile(name: &str) -> ProfileRef {
        ProfileRef::new(ProfileId::parse(name).expect("profile"), 1).expect("profile version")
    }

    fn anchor(
        principal: &str,
        method: &str,
        profile: ProfileRef,
        status: StatusPolicy,
    ) -> TrustAnchor {
        TrustAnchor::new(
            TrustAnchorId::parse(principal).expect("anchor"),
            PrincipalId::parse(principal).expect("principal"),
            vec![PrincipalMethodId::parse(method).expect("method")],
            vec![profile],
            PermissionSet::new(vec![Permission::new(
                CapabilityId::parse("tools/call").expect("capability"),
                ResourceId::parse("mcp://reports/read").expect("resource"),
            )])
            .expect("permissions"),
            vec![ResourceId::parse("mcp://reports").expect("namespace")],
            AudienceSet::new(vec![Audience::parse("mcp://reports").expect("audience")])
                .expect("audiences"),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).expect("validity"),
            None,
            1,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            status,
        )
        .expect("trust anchor")
    }

    fn snapshot_policy() -> StatusPolicy {
        StatusPolicy::SnapshotRequired {
            method: StatusMethodId::parse("auths-principal-status-v1").expect("status method"),
            max_age: FreshnessLimit::new(20).expect("freshness"),
        }
    }

    fn template(anchors: Vec<TrustAnchor>) -> TrustedContextTemplate {
        TrustedContextTemplate::new(
            VerifierConfigurationId::new([7; 32]),
            CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
            anchors,
            AssurancePolicy::new(
                AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
                vec![AssuranceRequirement::new(
                    ParticipantRole::Root,
                    AssuranceQuantifier::Every,
                    AssuranceClaimId::parse("raw-key-v1").expect("claim"),
                    None,
                )],
            )
            .expect("assurance policy"),
            [SignatureSuiteId::parse("ed25519-v1").expect("suite")],
        )
        .expect("template")
    }

    #[test]
    fn registries_derive_from_every_anchor_and_input() {
        let context = template(vec![
            anchor(
                "raw:root-a",
                "raw-key-v1",
                profile("auths.mcp"),
                snapshot_policy(),
            ),
            anchor(
                "raw:root-b",
                "did-key-v1",
                profile("auths.echo"),
                StatusPolicy::ExpiryOnly,
            ),
        ])
        .accept_evidence_type(EvidenceTypeId::parse("webauthn-v1").expect("evidence"))
        .accept_critical_extension(ExtensionId::parse("exact-marker-v1").expect("extension"))
        .compile()
        .expect("context");
        let registries = context.accepted_registries();
        assert_eq!(
            registries
                .principal_methods()
                .iter()
                .map(PrincipalMethodId::as_str)
                .collect::<Vec<_>>(),
            ["did-key-v1", "raw-key-v1"]
        );
        assert_eq!(
            registries
                .evidence_types()
                .iter()
                .map(EvidenceTypeId::as_str)
                .collect::<Vec<_>>(),
            ["did-key-v1", "raw-key-v1", "webauthn-v1"]
        );
        assert_eq!(
            registries
                .principal_status_methods()
                .iter()
                .map(StatusMethodId::as_str)
                .collect::<Vec<_>>(),
            ["auths-principal-status-v1"],
            "only an anchor that requires a snapshot contributes its status method"
        );
        assert!(
            registries
                .accepts_signature_suite(&SignatureSuiteId::parse("ed25519-v1").expect("suite"))
        );
        assert!(
            !registries.accepts_signature_suite(
                &SignatureSuiteId::parse("p256-sha256-v1").expect("suite")
            )
        );
        assert!(
            registries
                .accepts_assurance_claim(&AssuranceClaimId::parse("raw-key-v1").expect("claim"))
        );
        assert!(registries.accepts_critical_extension(
            &ExtensionId::parse("exact-marker-v1").expect("extension")
        ));
        assert!(registries.accepts_profile(&profile("auths.mcp")));
        assert!(registries.accepts_profile(&profile("auths.echo")));
        assert_eq!(context.expected_audience().as_str(), TEMPLATE_AUDIENCE);
        assert_eq!(context.evaluation_time(), Timestamp::new(0));
        assert_eq!(context.channel_policy().as_str(), "none-v1");
    }

    #[test]
    fn budget_free_declarations_outside_the_anchors_are_dropped() {
        let context = template(vec![anchor(
            "raw:root-a",
            "raw-key-v1",
            profile("auths.mcp"),
            StatusPolicy::ExpiryOnly,
        )])
        .declare_budget_free_profile(profile("auths.mcp"))
        .declare_budget_free_profile(profile("auths.unaccepted"))
        .compile()
        .expect("context");
        assert_eq!(
            context.accepted_registries().budget_free_profiles(),
            [profile("auths.mcp")]
        );
    }

    #[test]
    fn a_template_without_anchors_does_not_compile() {
        assert!(template(Vec::new()).compile().is_err());
    }
}
