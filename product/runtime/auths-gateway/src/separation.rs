//! Separation of the root, operator, and observer principals.
//!
//! A production deployment keeps three principals apart: the root issues
//! grants, the operator runs the gateway and holds provider credentials, and
//! the observer signs what the gateway saw. The kernel already refuses an
//! observer that appears in a proof's authority chain. The operator is not a
//! kernel principal, so its separation is checked here, where the gateway
//! installs its trust, together with the static form of the root and observer
//! check. Any overlap refuses the installation with a stable code.

use auths_model::{PrincipalId, TrustedContext, principal_id_equal};
use thiserror::Error;

/// An overlap between principals that a production deployment keeps apart.
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
        }
    }
}

/// Refuses any overlap of `operator`, the roots and observer anchors of
/// `context`, and the gateway's own `observer` key when one is installed.
///
/// # Errors
/// Returns the first overlap found, checked in the order operator-root,
/// operator-observer, observer-root, then an unanchored gateway observer.
pub fn check_principal_separation(
    context: &TrustedContext,
    operator: &PrincipalId,
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
    let contains = |set: &[&PrincipalId], principal: &PrincipalId| {
        set.iter()
            .any(|member| principal_id_equal(member, principal))
    };
    if contains(&roots, operator) {
        return Err(PrincipalSeparationError::OperatorIsRoot);
    }
    if contains(&observers, operator) {
        return Err(PrincipalSeparationError::OperatorIsObserver);
    }
    if observers
        .iter()
        .any(|principal| contains(&roots, principal))
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
