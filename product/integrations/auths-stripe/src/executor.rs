//! Sealed input to the protected Stripe mutation boundary.

use auths_lifecycle::ProviderCallAuthorizationV1;
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

mod sealed {
    pub trait Sealed {}
}

/// Read-only exact refund command accepted by the Stripe write adapter.
///
/// Only commands constructed by this crate after either the legacy claim
/// boundary or the shared durable lifecycle boundary can implement it.
pub trait RefundExecutionCommand: sealed::Sealed {
    /// Returns the exact Auths-verified action.
    fn action(&self) -> &ExactRefundActionV1;

    /// Returns the exact fresh evidence used for authorization.
    fn evidence(&self) -> &RefundEvidenceV1;
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

impl sealed::Sealed for VerifiedRefundCommand {}

impl RefundExecutionCommand for VerifiedRefundCommand {
    fn action(&self) -> &ExactRefundActionV1 {
        self.action()
    }

    fn evidence(&self) -> &RefundEvidenceV1 {
        self.evidence()
    }
}

/// Exact refund command sealed by durable shared lifecycle call entry.
pub struct LifecycleVerifiedRefundCommand {
    authorized: Authorized<StripeRefundCommand>,
    evidence: RefundEvidenceV1,
    call_authorization: ProviderCallAuthorizationV1,
}

impl LifecycleVerifiedRefundCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripeRefundCommand>,
        evidence: RefundEvidenceV1,
        call_authorization: ProviderCallAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            evidence,
            call_authorization,
        }
    }

    /// Returns the durable authorization for this exact provider call.
    #[must_use]
    pub const fn call_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.call_authorization
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
}

impl sealed::Sealed for LifecycleVerifiedRefundCommand {}

impl RefundExecutionCommand for LifecycleVerifiedRefundCommand {
    fn action(&self) -> &ExactRefundActionV1 {
        self.authorized.command().action()
    }

    fn evidence(&self) -> &RefundEvidenceV1 {
        &self.evidence
    }
}
