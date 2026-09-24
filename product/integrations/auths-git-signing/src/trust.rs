//! Building repository trust and issuing grants.
//!
//! A repository's trust pins one root principal. The root may authorize
//! `git/sign-commit`, `git/sign-tag`, and `git/revoke-grant` for that
//! repository, and may delegate the first two. The executable method and
//! suite sets are parameters: the trusted context commits to exactly the set
//! the verifier will run, so enabling a method is a trust change a reviewer
//! can see.

use crate::action::{RepositoryId, SIGN_COMMIT, SIGN_TAG};
use crate::claims::registries;
use crate::revoke::REVOKE_GRANT;
use crate::sign::{Delegation, DelegationLink, GitProofSigner, SignError};
use auths_author::prepare_grant;
use auths_model::{
    AcceptedRegistries, ActionConstraint, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    Audience, AudienceSet, CapabilityId, Challenge, ChannelBindingId, CompositionRequirement,
    CriticalExtensions, EvidenceTypeId, GrantStatement, GrantStatusSnapshot, Permission,
    PermissionSet, PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot, ProfileId,
    ProfilePolicyId, ProfileRef, ResourceId, ResourceMatcherId, SignatureSuiteId, StatusPolicy,
    StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId, TrustedContext, ValidityWindow,
    VerifierLimits,
};
use auths_ports::{AssuranceClaimRule, PrincipalMethod, SignatureSuite};
use auths_registries::TARGET_V1_REGISTRY_MANIFEST;
use thiserror::Error;

use crate::action::{PROFILE_ID, PROFILE_VERSION};

/// Assurance policy identifier bound by Git signing trust and grants.
pub const ASSURANCE_POLICY: &str = "auths.git-signature/assurance-v1";
/// Maximum grant depth below the root that trust allows.
pub const MAX_ANCHOR_DEPTH: u16 = 4;

/// A capability a grant may carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitCapability {
    /// `git/sign-commit`.
    SignCommit,
    /// `git/sign-tag`.
    SignTag,
}

impl GitCapability {
    /// Parses `sign-commit` or `sign-tag`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustBuildError::Capability`] for any other value.
    pub fn parse(value: &str) -> Result<Self, TrustBuildError> {
        match value {
            "sign-commit" => Ok(Self::SignCommit),
            "sign-tag" => Ok(Self::SignTag),
            _ => Err(TrustBuildError::Capability),
        }
    }

    fn permission(self, repository: &RepositoryId) -> Result<Permission, TrustBuildError> {
        let (capability, collection) = match self {
            Self::SignCommit => (SIGN_COMMIT, "commits"),
            Self::SignTag => (SIGN_TAG, "tags"),
        };
        permission(capability, repository, collection)
    }
}

/// Why trust or a grant could not be built.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TrustBuildError {
    /// A capability name is not `sign-commit` or `sign-tag`.
    #[error("capability must be sign-commit or sign-tag")]
    Capability,
    /// A model or registry value was rejected.
    #[error("invalid trust or grant value")]
    Model,
    /// Signing the grant failed.
    #[error("could not sign the grant: {0}")]
    Sign(#[from] SignError),
    /// A grant issuer must establish control with exactly one evidence
    /// object, as self-certifying roots do.
    #[error("a grant issuer must present exactly one evidence object")]
    RootEvidence,
}

fn model<T, E>(result: Result<T, E>) -> Result<T, TrustBuildError> {
    result.map_err(|_| TrustBuildError::Model)
}

fn permission(
    capability: &str,
    repository: &RepositoryId,
    collection: &str,
) -> Result<Permission, TrustBuildError> {
    Ok(Permission::new(
        model(CapabilityId::parse(capability))?,
        model(ResourceId::parse(&format!(
            "git://{}/{collection}",
            repository.as_str()
        )))?,
    ))
}

fn profile() -> Result<ProfileRef, TrustBuildError> {
    model(ProfileRef::new(
        model(ProfileId::parse(PROFILE_ID))?,
        PROFILE_VERSION,
    ))
}

fn audience(repository: &RepositoryId) -> Result<Audience, TrustBuildError> {
    model(Audience::parse(&repository.audience()))
}

/// Builds the trusted context for `repository`, pinned to `root`.
///
/// `root_method` is the principal method of the root itself. `methods`,
/// `suites`, and `claims` are the executable sets every verifier of this
/// trust will run; their configuration commitment is bound into the context,
/// and every claim rule's identifier is accepted.
///
/// # Errors
///
/// Returns [`TrustBuildError::Model`] for an invalid value or registry set.
pub fn repository_trust(
    root: &PrincipalId,
    root_method: &PrincipalMethodId,
    repository: &RepositoryId,
    methods: &[&dyn PrincipalMethod],
    suites: &[&dyn SignatureSuite],
    claims: &[&dyn AssuranceClaimRule],
    validity: ValidityWindow,
) -> Result<TrustedContext, TrustBuildError> {
    let configuration = model(registries(methods, suites, claims))?.configuration_id();
    let method_ids: Vec<PrincipalMethodId> =
        methods.iter().map(|method| method.id().clone()).collect();
    let evidence_types = method_ids
        .iter()
        .map(|id| model(EvidenceTypeId::parse(id.as_str())))
        .collect::<Result<Vec<_>, _>>()?;
    let suite_ids: Vec<SignatureSuiteId> = suites.iter().map(|suite| suite.id().clone()).collect();
    let assurance = model(AssurancePolicyId::parse(ASSURANCE_POLICY))?;
    let audience = audience(repository)?;
    let anchor = model(TrustAnchor::new(
        model(TrustAnchorId::parse(root.as_str()))?,
        root.clone(),
        vec![root_method.clone()],
        vec![profile()?],
        model(PermissionSet::new(vec![
            permission(SIGN_COMMIT, repository, "commits")?,
            permission(SIGN_TAG, repository, "tags")?,
            permission(REVOKE_GRANT, repository, "grants")?,
        ]))?,
        vec![model(ResourceId::parse(&format!(
            "git://{}/",
            repository.as_str()
        )))?],
        model(AudienceSet::new(vec![audience.clone()]))?,
        validity,
        None,
        MAX_ANCHOR_DEPTH,
        assurance.clone(),
        StatusPolicy::ExpiryOnly,
    ))?;
    let registries = model(AcceptedRegistries::new(
        TARGET_V1_REGISTRY_MANIFEST,
        method_ids,
        suite_ids,
        evidence_types,
        Vec::new(),
        Vec::new(),
        [
            model(AssuranceClaimId::parse("offline-verifiable")),
            model(AssuranceClaimId::parse("self-certifying-identifier")),
        ]
        .into_iter()
        .chain(claims.iter().map(|claim| Ok(claim.id().clone())))
        .collect::<Result<Vec<_>, _>>()?,
        Vec::new(),
        vec![model(ResourceMatcherId::parse("uri-namespace-v1"))?],
        Vec::new(),
        Vec::new(),
        vec![profile()?],
        vec![model(ProfilePolicyId::parse("exact-v1"))?],
    ))?;
    model(TrustedContext::new(
        configuration,
        model(CompositionRequirement::new(None, 1, 1, 1))?,
        vec![anchor],
        registries,
        audience,
        Challenge::new([0; 32]),
        validity.not_before(),
        model(AssurancePolicy::new(assurance, Vec::new()))?,
        model(PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0; 32]),
            validity.not_before(),
            validity.expires_at(),
            Vec::new(),
            Vec::new(),
        ))?,
        model(GrantStatusSnapshot::new(
            StatusSnapshotId::new([0; 32]),
            validity.not_before(),
            validity.expires_at(),
            Vec::new(),
            Vec::new(),
        ))?,
        model(ResourceMatcherId::parse("uri-namespace-v1"))?,
        model(ProfilePolicyId::parse("exact-v1"))?,
        model(ChannelBindingId::parse("none-v1"))?,
        VerifierLimits::default(),
    ))
}

/// Issues a grant from `root` to `subject` for `capabilities` in
/// `repository`, valid for `validity`, and returns the one-link delegation.
///
/// The grant cannot be delegated further and covers any payload: each
/// signature still binds its exact object.
///
/// # Errors
///
/// Returns a [`TrustBuildError`] for an empty capability set, an invalid
/// value, or a signing failure.
pub fn issue_grant(
    root: &dyn GitProofSigner,
    subject: PrincipalId,
    repository: &RepositoryId,
    capabilities: &[GitCapability],
    validity: ValidityWindow,
) -> Result<Delegation, TrustBuildError> {
    if capabilities.is_empty() {
        return Err(TrustBuildError::Capability);
    }
    let permissions = capabilities
        .iter()
        .map(|capability| capability.permission(repository))
        .collect::<Result<Vec<_>, _>>()?;
    let statement = GrantStatement::new(
        root.principal(),
        subject,
        profile()?,
        model(PermissionSet::new(permissions))?,
        validity,
        model(AudienceSet::new(vec![audience(repository)?]))?,
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        model(AssurancePolicyId::parse(ASSURANCE_POLICY))?,
        CriticalExtensions::empty(),
    );
    let request = model(prepare_grant(statement, root.descriptor()))?;
    let grant = root.sign_grant(request)?;
    let [issuer_evidence] =
        <[_; 1]>::try_from(root.control_evidence()).map_err(|_| TrustBuildError::RootEvidence)?;
    Ok(Delegation::new(vec![DelegationLink::new(
        grant,
        issuer_evidence,
    )])?)
}

/// Returns `[now, now + seconds]`.
///
/// # Errors
///
/// Returns [`TrustBuildError::Model`] if the window is invalid.
pub fn window_from(now: u64, seconds: u64) -> Result<ValidityWindow, TrustBuildError> {
    model(ValidityWindow::new(
        Timestamp::new(now),
        Timestamp::new(now.saturating_add(seconds)),
    ))
}
