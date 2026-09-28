//! Separation of the root, operator, and observer principals, compared by
//! key.
//!
//! A production deployment keeps three principals apart: the root issues
//! grants, the operator runs the gateway and holds provider credentials, and
//! the observer signs what the gateway saw. The kernel already refuses an
//! observer whose identifier appears in a proof's authority chain. The
//! operator is not a kernel principal, so its separation is checked here,
//! where the gateway installs its trust, together with the static form of
//! the root and observer check.
//!
//! Identifier equality misses one key named under two methods: a
//! `raw-key-v1` identifier and a `did:key` identifier of the same Ed25519 or
//! P-256 key are different strings. Two principals therefore **overlap**
//! when their identifiers are equal or their key identities are equal, where
//! a key identity is the SHA-256 of the canonical `raw-key-v1` descriptor of
//! the one key an identifier names. Methods whose identifier does not name
//! one key keep identifier comparison.

use auths_model::{PrincipalId, TrustedContext, principal_id_equal};
use auths_raw_key_core::{RawKeyTypeV1, V1_PRINCIPAL_PREFIX, encode_v1};
use auths_verifier::VerifiedAction;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

/// The `did:key` method prefix.
const DID_KEY_PREFIX: &str = "did:key:";

/// An overlap between principals that a deployment keeps apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PrincipalSeparationError {
    /// The operator principal is also a trusted root.
    #[error("the operator principal is a trusted root")]
    OperatorIsRoot,
    /// The operator principal is also an observer, either an observer anchor
    /// of the trust or the gateway's own observer key.
    #[error("the operator principal is an observer")]
    OperatorIsObserver,
    /// An observer anchor, or the gateway's observer key, is a trusted root.
    #[error("an observer principal is a trusted root")]
    ObserverIsRoot,
    /// The gateway's observer key is not named by any observer anchor, so
    /// nothing it signs could satisfy a requirement of this trust.
    #[error("the gateway observer is not an observer anchor")]
    ObserverNotAnchored,
    /// Two distinct anchor identifiers of the trust name one key, which
    /// would count twice toward a composition requirement.
    #[error("two trust or observer anchors name one key")]
    KeyAliased,
}

impl PrincipalSeparationError {
    /// Returns the stable non-secret code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OperatorIsRoot => "gateway.trust.operator-is-root",
            Self::OperatorIsObserver => "gateway.trust.operator-is-observer",
            Self::ObserverIsRoot => "gateway.trust.observer-is-root",
            Self::ObserverNotAnchored => "gateway.trust.observer-not-anchored",
            Self::KeyAliased => "gateway.trust.key-aliased",
        }
    }
}

/// The key identity of `principal`: the SHA-256 of the canonical
/// `raw-key-v1` descriptor of the one key its identifier names.
///
/// A `raw-key-v1` identifier (`key:sha256:<base64url>`) encodes that digest
/// directly. A `did:key` identifier names a Multikey whose Ed25519 and P-256
/// forms are `raw-key-v1`'s two key types, so its descriptor is hashed. Any
/// other method returns `None`: `raw-key-v2` commits to another encoding,
/// `did:keri` keys rotate, and keyless methods use a new key per signature.
/// A malformed identifier of either method also returns `None`, so it keeps
/// identifier comparison.
#[must_use]
pub fn key_identity(principal: &PrincipalId) -> Option<[u8; 32]> {
    let text = principal.as_str();
    if let Some(encoded) = text.strip_prefix(V1_PRINCIPAL_PREFIX) {
        let mut digest = [0_u8; 32];
        let decoded = Base64UrlUnpadded::decode(encoded, &mut digest).ok()?;
        return (decoded.len() == 32 && Base64UrlUnpadded::encode_string(&digest) == encoded)
            .then_some(digest);
    }
    let multikey = auths_multikey::Multikey::parse(text.strip_prefix(DID_KEY_PREFIX)?).ok()?;
    let key_type = match multikey.key_type() {
        auths_multikey::MultikeyType::Ed25519 => RawKeyTypeV1::Ed25519,
        auths_multikey::MultikeyType::P256 => RawKeyTypeV1::P256,
    };
    let descriptor = encode_v1(key_type, multikey.public_key()).ok()?;
    Some(Sha256::digest(descriptor).into())
}

/// Whether two principals overlap: equal identifiers, or equal key
/// identities compared in constant time.
#[must_use]
pub fn principals_overlap(left: &PrincipalId, right: &PrincipalId) -> bool {
    if principal_id_equal(left, right) {
        return true;
    }
    match (key_identity(left), key_identity(right)) {
        (Some(left), Some(right)) => bool::from(left.ct_eq(&right)),
        _ => false,
    }
}

/// Refuses any overlap of `operator` (when one is authenticated), the roots
/// and observer anchors of `context`, and the gateway's own `observer` key
/// when one is installed.
///
/// # Errors
/// Returns the first overlap found, checked in the order operator-root,
/// operator-observer, observer-root, then an unanchored gateway observer.
/// The last keeps identifier equality, as the kernel requires an
/// observation's observer to equal its anchor.
pub fn check_principal_separation(
    context: &TrustedContext,
    operator: Option<&PrincipalId>,
    observer: Option<&PrincipalId>,
) -> Result<(), PrincipalSeparationError> {
    let roots: Vec<&PrincipalId> = context
        .trust_anchors()
        .iter()
        .map(auths_model::TrustAnchor::principal)
        .collect();
    let observers: Vec<&PrincipalId> = context
        .observer_anchors()
        .iter()
        .map(auths_model::ObserverAnchor::principal)
        .chain(observer)
        .collect();
    let overlaps = |set: &[&PrincipalId], principal: &PrincipalId| {
        set.iter()
            .any(|member| principals_overlap(member, principal))
    };
    if let Some(operator) = operator {
        if overlaps(&roots, operator) {
            return Err(PrincipalSeparationError::OperatorIsRoot);
        }
        if overlaps(&observers, operator) {
            return Err(PrincipalSeparationError::OperatorIsObserver);
        }
    }
    if observers
        .iter()
        .any(|principal| overlaps(&roots, principal))
    {
        return Err(PrincipalSeparationError::ObserverIsRoot);
    }
    if let Some(observer) = observer
        && !context
            .observer_anchors()
            .iter()
            .any(|anchor| principal_id_equal(anchor.principal(), observer))
    {
        return Err(PrincipalSeparationError::ObserverNotAnchored);
    }
    Ok(())
}

/// Refuses a trusted context in which two distinct identifiers among its
/// trust and observer anchors name one key.
///
/// # Errors
/// Returns [`PrincipalSeparationError::KeyAliased`].
pub fn check_anchor_aliasing(context: &TrustedContext) -> Result<(), PrincipalSeparationError> {
    let anchors: Vec<&PrincipalId> = context
        .trust_anchors()
        .iter()
        .map(auths_model::TrustAnchor::principal)
        .chain(
            context
                .observer_anchors()
                .iter()
                .map(auths_model::ObserverAnchor::principal),
        )
        .collect();
    for (index, left) in anchors.iter().enumerate() {
        for right in &anchors[index + 1..] {
            if !principal_id_equal(left, right) && principals_overlap(left, right) {
                return Err(PrincipalSeparationError::KeyAliased);
            }
        }
    }
    Ok(())
}

/// Refuses a proof in which the observer of an observation that satisfied a
/// requirement overlaps a principal of the authority it conditions: the
/// root or a grant issuer or subject of an authorized branch, or the
/// branch's actor. The kernel already refuses identifier equality; this
/// adds key identity.
///
/// # Errors
/// Returns `gateway.trust.observer-key-in-authority-chain` on an overlap and
/// `gateway.policy.proof-unavailable` when the verified proof cannot be
/// read again.
pub(crate) fn check_proof_observers(
    proof_cbor: &[u8],
    verified: &VerifiedAction,
) -> Result<(), &'static str> {
    if verified.observation_satisfactions().is_empty() {
        return Ok(());
    }
    let unavailable = "gateway.policy.proof-unavailable";
    let limits = auths_model::VerifierLimits::default();
    let mut authority: Vec<PrincipalId> = Vec::new();
    for branch in crate::bounds::authorized_chains(proof_cbor, verified)? {
        for grant in &branch.chain {
            authority.push(grant.statement().issuer().clone());
            authority.push(grant.statement().subject().clone());
        }
        authority.push(branch.actor);
    }
    for satisfaction in verified.observation_satisfactions() {
        let attachment = verified
            .canonical_action()
            .detached_attachments()
            .iter()
            .find(|attachment| attachment.digest() == satisfaction.observation())
            .ok_or(unavailable)?;
        let observation = auths_codec::decode_signed_observation(attachment.bytes(), &limits)
            .map_err(|_| unavailable)?;
        let observer = observation.statement().observer();
        if authority
            .iter()
            .any(|principal| principals_overlap(principal, observer))
        {
            return Err("gateway.trust.observer-key-in-authority-chain");
        }
    }
    Ok(())
}
