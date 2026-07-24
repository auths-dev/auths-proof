//! Pure ports implemented by principal-control and grant-status adapters.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_proof_model::{
    AdapterId, AlgorithmId, AssuranceClaims, AuthorityStateEvidenceEntry, AuthorityStateMethod,
    EvidenceId, GrantId, PrincipalEvidenceEntry, PrincipalRef, ProofPurpose, Timestamp,
    VerificationMethodRef,
};
use core::fmt;

pub struct ControlProofInput<'a> {
    pub principal: &'a PrincipalRef,
    pub purpose: ProofPurpose,
    pub verification_method: &'a VerificationMethodRef,
    pub algorithm: &'a AlgorithmId,
    pub signing_bytes: &'a [u8],
    pub signature: &'a [u8],
    pub evidence: &'a PrincipalEvidenceEntry,
    pub asserted_signing_time: Timestamp,
    pub verification_time: Timestamp,
}

pub trait PrincipalControlVerifier {
    fn adapter_id(&self) -> &AdapterId;

    fn supports(&self, principal: &PrincipalRef) -> bool;

    fn verify_control(
        &self,
        input: ControlProofInput<'_>,
    ) -> Result<VerifiedPrincipal, PrincipalControlError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    principal: PrincipalRef,
    verification_method: VerificationMethodRef,
    adapter: AdapterId,
    evidence_id: EvidenceId,
    claims: AssuranceClaims,
}

impl VerifiedPrincipal {
    pub fn verified(
        principal: PrincipalRef,
        verification_method: VerificationMethodRef,
        adapter: AdapterId,
        evidence_id: EvidenceId,
        claims: AssuranceClaims,
    ) -> Self {
        Self {
            principal,
            verification_method,
            adapter,
            evidence_id,
            claims,
        }
    }

    pub const fn principal(&self) -> &PrincipalRef {
        &self.principal
    }
    pub const fn verification_method(&self) -> &VerificationMethodRef {
        &self.verification_method
    }
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }
    pub const fn claims(&self) -> &AssuranceClaims {
        &self.claims
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalControlError {
    UnsupportedPrincipal,
    AdapterMismatch,
    VerificationMethodMismatch,
    AlgorithmMismatch,
    InvalidEvidence,
    InvalidSignature,
    ResourceLimitExceeded,
}

impl fmt::Display for PrincipalControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPrincipal => "adapter does not support this principal",
            Self::AdapterMismatch => "evidence adapter does not match the selected adapter",
            Self::VerificationMethodMismatch => "verification method does not match the principal",
            Self::AlgorithmMismatch => "signature algorithm does not match the verification key",
            Self::InvalidEvidence => "principal evidence is invalid",
            Self::InvalidSignature => "signature verification failed",
            Self::ResourceLimitExceeded => "adapter resource limit exceeded",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrincipalControlError {}

pub struct AuthorityStateInput<'a> {
    pub grant_id: GrantId,
    pub issuer: &'a PrincipalRef,
    pub evidence: &'a AuthorityStateEvidenceEntry,
    pub verification_time: Timestamp,
}

pub trait AuthorityStateVerifier {
    fn method(&self) -> &AuthorityStateMethod;

    fn verify_active(
        &self,
        input: AuthorityStateInput<'_>,
    ) -> Result<VerifiedGrantStatus, AuthorityStateError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedGrantStatus {
    grant_id: GrantId,
    active: bool,
    checked_at: Timestamp,
}

impl VerifiedGrantStatus {
    pub const fn new(grant_id: GrantId, active: bool, checked_at: Timestamp) -> Self {
        Self {
            grant_id,
            active,
            checked_at,
        }
    }

    pub const fn grant_id(self) -> GrantId {
        self.grant_id
    }
    pub const fn active(self) -> bool {
        self.active
    }
    pub const fn checked_at(self) -> Timestamp {
        self.checked_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityStateError {
    InvalidEvidence,
    GrantNotFound,
    StaleEvidence,
    ResourceLimitExceeded,
}

impl fmt::Display for AuthorityStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEvidence => "authority-state evidence is invalid",
            Self::GrantNotFound => "grant is absent from authority-state evidence",
            Self::StaleEvidence => "authority-state evidence is stale",
            Self::ResourceLimitExceeded => "authority-state resource limit exceeded",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthorityStateError {}

pub struct AdapterRegistry<'a> {
    principal: &'a [&'a dyn PrincipalControlVerifier],
    authority_state: &'a [&'a dyn AuthorityStateVerifier],
}

impl<'a> AdapterRegistry<'a> {
    pub const fn new(
        principal: &'a [&'a dyn PrincipalControlVerifier],
        authority_state: &'a [&'a dyn AuthorityStateVerifier],
    ) -> Self {
        Self {
            principal,
            authority_state,
        }
    }

    pub fn principal(&self) -> &[&'a dyn PrincipalControlVerifier] {
        self.principal
    }

    pub fn authority_state(&self) -> &[&'a dyn AuthorityStateVerifier] {
        self.authority_state
    }

    pub fn principal_by_id(
        &self,
        adapter_id: &AdapterId,
    ) -> Option<&'a dyn PrincipalControlVerifier> {
        self.principal
            .iter()
            .copied()
            .find(|adapter| adapter.adapter_id() == adapter_id)
    }

    pub fn authority_state_by_method(
        &self,
        method: &AuthorityStateMethod,
    ) -> Option<&'a dyn AuthorityStateVerifier> {
        self.authority_state
            .iter()
            .copied()
            .find(|adapter| adapter.method() == method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_model::ModelError;

    struct Never;

    impl PrincipalControlVerifier for Never {
        fn adapter_id(&self) -> &AdapterId {
            static ID: std::sync::OnceLock<AdapterId> = std::sync::OnceLock::new();
            ID.get_or_init(|| AdapterId::parse("never").expect("adapter id"))
        }

        fn supports(&self, _principal: &PrincipalRef) -> bool {
            false
        }

        fn verify_control(
            &self,
            _input: ControlProofInput<'_>,
        ) -> Result<VerifiedPrincipal, PrincipalControlError> {
            Err(PrincipalControlError::UnsupportedPrincipal)
        }
    }

    #[test]
    fn registry_selection_is_exact() -> Result<(), ModelError> {
        let never = Never;
        let principal_adapters: [&dyn PrincipalControlVerifier; 1] = [&never];
        let registry = AdapterRegistry::new(&principal_adapters, &[]);
        assert!(registry
            .principal_by_id(&AdapterId::parse("never")?)
            .is_some());
        assert!(registry
            .principal_by_id(&AdapterId::parse("other")?)
            .is_none());
        Ok(())
    }
}
