//! Local-fixture trust material for the open production reference stack.
//!
//! `[verification] trusted_context_path` is mandatory: a node that cannot state
//! its trust anchors cannot decide anything. That is deliberate, and it means
//! the reference compose stack needs a real `TrustedContext` on disk before it
//! can start. Nothing produced one, so all three replicas crash-looped on
//! `the trusted context is unavailable`.
//!
//! This module builds one, deterministically, from the same `AUTHS_LOCAL_SEED`
//! the stack already supplies. It is a LOCAL FIXTURE. The anchor's private key
//! is derivable by anyone holding the seed, which is the point for a
//! self-contained demo and disqualifying for anything else. A production
//! deployment supplies operator-held context bytes as a secret, exactly as
//! `config/production.example.toml` shows.

use auths_model::{
    AcceptedRegistries, AssuranceClaimId, AssurancePolicy, AssurancePolicyId, AssuranceQuantifier,
    AssuranceRequirement, Audience, AudienceSet, BudgetAlgebraId, BudgetCeiling, CapabilityId,
    Challenge, ChannelBindingId, CompositionRequirement, EvidenceTypeId, GrantStatusSnapshot,
    ParticipantRole, Permission, PermissionSet, PrincipalId, PrincipalMethodId,
    PrincipalStatusSnapshot, ProfileId, ProfilePolicyId, ProfileRef, ResourceId, ResourceMatcherId,
    SignatureSuiteId, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId,
    TrustedContext, ValidityWindow, VerifierConfigurationId, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::{RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

/// Environment slot carrying the stack's 32-byte unpadded base64url seed.
pub const SEED_ENV: &str = "AUTHS_LOCAL_SEED";

/// Domain separator: the anchor key must not be the node's custody key.
///
/// The node signs receipts with the seed directly. An authority root that could
/// also sign the receipts attesting to its own use would collapse two roles the
/// protocol keeps apart, so the anchor key is a separate derivation.
const ANCHOR_DOMAIN: &[u8] = b"auths.local-fixture.trust-anchor/1";

const ASSURANCE_POLICY: &str = "raw-key-baseline";
const RESOURCE_MATCHER: &str = "uri-namespace-v1";
const PROFILE_POLICY: &str = "exact-v1";
const CHANNEL_POLICY: &str = "none-v1";
const BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Audience the reference stack answers for.
pub const REFERENCE_AUDIENCE: &str = "auths.open-production/1";

/// The three profiles the reference stack enables.
pub const REFERENCE_PROFILES: [&str; 3] = [
    "auths.opentofu.saved-plan-apply/1",
    "auths.postgresql.bounded-update/1",
    "auths.github.issue-address/1",
];

/// Namespace the fixture anchor may delegate within, one per profile.
const REFERENCE_NAMESPACES: [&str; 3] = [
    "opentofu://reference",
    "postgresql://reference",
    "github://reference",
];

const REFERENCE_CAPABILITIES: [&str; 3] = ["apply", "update", "address"];

/// Anything that can go wrong assembling the fixture.
#[derive(Debug)]
pub struct FixtureError(pub String);

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FixtureError {}

fn fail(what: &str) -> FixtureError {
    FixtureError(what.to_owned())
}

/// Derives the fixture trust anchor's signing key from the stack seed.
///
/// Domain-separated so the anchor key and the node's custody key are
/// independent even though one seed produces both.
#[must_use]
pub fn anchor_signing_key(seed: &[u8; 32]) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN);
    hasher.update(seed);
    let derived: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&derived)
}

/// Derives the fixture trust anchor's raw-key descriptor and principal.
///
/// # Errors
///
/// Returns [`FixtureError`] when the derived key cannot form a raw-key
/// principal.
pub fn anchor_principal(seed: &[u8; 32]) -> Result<(SigningKey, PrincipalId), FixtureError> {
    let signing = anchor_signing_key(seed);
    let descriptor = RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| fail("the derived anchor key is not a valid raw-key descriptor"))?;
    let principal = descriptor
        .principal()
        .map_err(|_| fail("the derived anchor key has no principal"))?;
    Ok((signing, principal))
}

fn verifier_configuration() -> Result<VerifierConfigurationId, FixtureError> {
    let method = RawKeyMethod::new().map_err(|_| fail("raw-key method unavailable"))?;
    let suite = Ed25519Suite::new().map_err(|_| fail("ed25519 suite unavailable"))?;
    auths_registries::ImmutableRegistries::new(
        &[&method as &dyn PrincipalMethod],
        &[&suite as &dyn SignatureSuite],
    )
    .map(|registries| registries.configuration_id())
    .map_err(|_| fail("the verifier configuration could not be computed"))
}

fn profiles() -> Result<Vec<ProfileRef>, FixtureError> {
    REFERENCE_PROFILES
        .iter()
        .map(|qualified| {
            // A qualified profile is `<id>/<version>`; ProfileRef keeps them apart.
            let (id, version) = qualified
                .rsplit_once('/')
                .ok_or_else(|| fail("a reference profile id carries no version"))?;
            let version = version
                .parse::<u16>()
                .map_err(|_| fail("a reference profile version is not a number"))?;
            ProfileRef::new(
                ProfileId::parse(id).map_err(|_| fail("a reference profile id is malformed"))?,
                version,
            )
            .map_err(|_| fail("a reference profile reference is invalid"))
        })
        .collect()
}

fn permissions() -> Result<PermissionSet, FixtureError> {
    let mut entries = Vec::new();
    for (capability, namespace) in REFERENCE_CAPABILITIES.iter().zip(REFERENCE_NAMESPACES) {
        entries.push(Permission::new(
            CapabilityId::parse(capability)
                .map_err(|_| fail("a reference capability is malformed"))?,
            ResourceId::parse(namespace).map_err(|_| fail("a reference namespace is malformed"))?,
        ));
    }
    PermissionSet::new(entries).map_err(|_| fail("the reference permission set is invalid"))
}

fn registries(profiles: &[ProfileRef]) -> Result<AcceptedRegistries, FixtureError> {
    AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| fail("raw-key id"))?],
        vec![SignatureSuiteId::parse(ED25519_V1).map_err(|_| fail("ed25519 id"))?],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).map_err(|_| fail("raw-key evidence id"))?],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").map_err(|_| fail("assurance claim"))?,
            AssuranceClaimId::parse("self-certifying-identifier")
                .map_err(|_| fail("assurance claim"))?,
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse(RESOURCE_MATCHER).map_err(|_| fail("resource matcher"))?],
        vec![BudgetAlgebraId::parse(BUDGET_ALGEBRA).map_err(|_| fail("budget algebra"))?],
        Vec::new(),
        profiles.to_vec(),
        vec![ProfilePolicyId::parse(PROFILE_POLICY).map_err(|_| fail("profile policy"))?],
    )
    .map_err(|_| fail("the accepted registries are inconsistent"))
}

fn assurance() -> Result<(AssurancePolicyId, AssurancePolicy), FixtureError> {
    let id = AssurancePolicyId::parse(ASSURANCE_POLICY).map_err(|_| fail("assurance policy id"))?;
    let claim = AssuranceClaimId::parse("self-certifying-identifier")
        .map_err(|_| fail("assurance claim id"))?;
    let policy = AssurancePolicy::new(
        id.clone(),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                claim.clone(),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                claim,
                None,
            ),
        ],
    )
    .map_err(|_| fail("the assurance policy is invalid"))?;
    Ok((id, policy))
}

/// Builds the reference stack's trusted context.
///
/// `lifetime_seconds` sets both the anchor validity and the status-snapshot
/// freshness window. The stack is long-lived relative to a CI job, so this is
/// generated per run rather than committed -- a checked-in context would go
/// stale exactly the way a checked-in certificate does.
///
/// # Errors
///
/// Returns [`FixtureError`] when any component is rejected by the model.
pub fn build_context(
    seed: &[u8; 32],
    now: u64,
    lifetime_seconds: u64,
) -> Result<TrustedContext, FixtureError> {
    let (_signing, principal) = anchor_principal(seed)?;
    let profile_refs = profiles()?;
    let expires = now.saturating_add(lifetime_seconds);
    let audience = Audience::parse(REFERENCE_AUDIENCE)
        .map_err(|_| fail("the reference audience is malformed"))?;
    let (assurance_id, assurance_policy) = assurance()?;
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(principal.as_str()).map_err(|_| fail("the anchor id is malformed"))?,
        principal,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| fail("raw-key id"))?],
        profile_refs.clone(),
        permissions()?,
        REFERENCE_NAMESPACES
            .iter()
            .map(|namespace| {
                ResourceId::parse(namespace).map_err(|_| fail("a reference namespace is malformed"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        AudienceSet::new(vec![audience.clone()])
            .map_err(|_| fail("the audience set is invalid"))?,
        ValidityWindow::new(
            Timestamp::new(now.saturating_sub(60)),
            Timestamp::new(expires),
        )
        .map_err(|_| fail("the anchor validity window is invalid"))?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(BUDGET_ALGEBRA).map_err(|_| fail("budget algebra"))?,
            2,
        )),
        2,
        assurance_id,
        StatusPolicy::ExpiryOnly,
    )
    .map_err(|_| fail("the fixture trust anchor is invalid"))?;
    TrustedContext::new(
        verifier_configuration()?,
        CompositionRequirement::new(None, 1, 1, 1)
            .map_err(|_| fail("the composition requirement is invalid"))?,
        vec![anchor],
        registries(&profile_refs)?,
        audience,
        Challenge::new([0x22; 32]),
        Timestamp::new(now),
        assurance_policy,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x63; 32]),
            Timestamp::new(now.saturating_sub(60)),
            Timestamp::new(expires),
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| fail("the principal status snapshot is invalid"))?,
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x64; 32]),
            Timestamp::new(now.saturating_sub(60)),
            Timestamp::new(expires),
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| fail("the grant status snapshot is invalid"))?,
        ResourceMatcherId::parse(RESOURCE_MATCHER).map_err(|_| fail("resource matcher"))?,
        ProfilePolicyId::parse(PROFILE_POLICY).map_err(|_| fail("profile policy"))?,
        ChannelBindingId::parse(CHANNEL_POLICY).map_err(|_| fail("channel policy"))?,
        VerifierLimits::default(),
    )
    .map_err(|_| fail("the fixture trusted context is invalid"))
}

#[cfg(test)]
mod tests {
    use super::{anchor_signing_key, build_context};

    const SEED: [u8; 32] = [7; 32];

    #[test]
    fn the_anchor_key_is_not_the_custody_key() {
        // The seed signs receipts. If the anchor derived to the same key, one
        // key would both grant authority and attest to its own exercise.
        let anchor = anchor_signing_key(&SEED);
        assert_ne!(anchor.to_bytes(), SEED);
    }

    #[test]
    fn the_same_seed_always_derives_the_same_anchor() {
        assert_eq!(
            anchor_signing_key(&SEED).to_bytes(),
            anchor_signing_key(&SEED).to_bytes()
        );
    }

    #[test]
    fn a_different_seed_derives_a_different_anchor() {
        let other = anchor_signing_key(&[9; 32]);
        assert_ne!(anchor_signing_key(&SEED).to_bytes(), other.to_bytes());
    }

    #[test]
    fn the_context_encodes_canonically() {
        let context = build_context(&SEED, 1_700_000_000, 3_600).expect("fixture context");
        let bytes = auths_codec::encode_verifier_context(&context).expect("canonical bytes");
        assert!(!bytes.is_empty());
        let decoded = auths_codec::decode_verifier_context(&bytes).expect("round trip");
        assert_eq!(
            auths_codec::encode_verifier_context(&decoded).expect("re-encode"),
            bytes
        );
    }
}
