//! Sealed input to the protected Stripe mutation boundary.

use auths_sdk::Authorized;

use crate::{
    claim::ClaimLease,
    profile::StripeRefundCommand,
    types::{ExactRefundActionV1, RefundEvidenceV1},
};

/// Command constructible only after product containment, Auths verification,
/// and a successful at-most-once claim.
pub struct VerifiedRefundCommand {
    authorized: Authorized<StripeRefundCommand>,
    evidence: RefundEvidenceV1,
    lease: ClaimLease,
}

impl VerifiedRefundCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripeRefundCommand>,
        evidence: RefundEvidenceV1,
        lease: ClaimLease,
    ) -> Self {
        Self {
            authorized,
            evidence,
            lease,
        }
    }

    /// Returns the exact Auths-verified action.
    #[must_use]
    pub const fn action(&self) -> &ExactRefundActionV1 {
        self.authorized.command().action()
    }

    /// Returns the exact fresh evidence used for authorization.
    #[must_use]
    pub const fn evidence(&self) -> &RefundEvidenceV1 {
        &self.evidence
    }

    /// Returns the durable claim lease.
    #[must_use]
    pub const fn lease(&self) -> &ClaimLease {
        &self.lease
    }

    /// Returns the lease after the provider request.
    #[must_use]
    pub fn into_lease(self) -> ClaimLease {
        self.lease
    }
}
