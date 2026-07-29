//! Verified-and-claimed command presented to the database boundary.

use auths_sdk::Authorized;

use crate::{
    claim::ClaimLease, compiler::CompiledBoundedUpdate, evidence::PostgresEvidenceV1,
    profile::PostgresUpdateCommand,
};

/// Exact command constructible only by the service after proof and claim.
pub struct VerifiedBoundedUpdateCommand {
    authorized: Authorized<PostgresUpdateCommand>,
    evidence: PostgresEvidenceV1,
    compiled: CompiledBoundedUpdate,
    lease: ClaimLease,
}

impl VerifiedBoundedUpdateCommand {
    pub(crate) const fn new(
        authorized: Authorized<PostgresUpdateCommand>,
        evidence: PostgresEvidenceV1,
        compiled: CompiledBoundedUpdate,
        lease: ClaimLease,
    ) -> Self {
        Self {
            authorized,
            evidence,
            compiled,
            lease,
        }
    }

    #[must_use]
    pub fn action(&self) -> &crate::action::PostgresBoundedUpdateV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn evidence(&self) -> &PostgresEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub const fn compiled(&self) -> &CompiledBoundedUpdate {
        &self.compiled
    }

    #[must_use]
    pub(crate) const fn lease(&self) -> &ClaimLease {
        &self.lease
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.lease.claim_id
    }
}
