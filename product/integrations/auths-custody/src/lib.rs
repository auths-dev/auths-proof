//! External custody boundary for exact Auths signing requests.
//!
//! This crate owns no private keys and imports no provider SDK. Concrete
//! `WebAuthn`, workload, KMS, HSM, and PKCS#11 clients implement
//! [`ExternalSigner`] and return a transaction-bound signature plus any
//! evidence acquired during the operation.

#![forbid(unsafe_code)]

use auths_author::{ExternalSigningRequest, SigningObjectId};
use auths_model::{
    ActionEnvelope, EvidenceObject, GrantStatement, GrantStatusStatement, PrincipalStatusStatement,
    SignatureBytes, SignatureDescriptor, SignedAction, SignedGrant, SignedGrantStatus,
    SignedPrincipalStatus,
};
use std::fmt;
use subtle::ConstantTimeEq as _;

/// Registered outer custody integration family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyKind {
    /// Browser authenticator ceremony.
    WebAuthn,
    /// SPIFFE workload or workload API signer.
    Workload,
    /// Cloud key-management service.
    Kms,
    /// Hardware security module.
    Hsm,
    /// PKCS#11 token or module.
    Pkcs11,
}

/// Immutable provider request bound to exact Auths signing bytes.
pub struct SigningIntent<'a> {
    kind: CustodyKind,
    object_id: SigningObjectId,
    descriptor: &'a SignatureDescriptor,
    signing_preimage: &'a [u8],
    transaction_digest: [u8; 32],
}

impl<'a> SigningIntent<'a> {
    fn from_request<T>(kind: CustodyKind, request: &'a ExternalSigningRequest<T>) -> Self {
        Self {
            kind,
            object_id: request.object_id(),
            descriptor: request.descriptor(),
            signing_preimage: request.signing_preimage(),
            transaction_digest: *request.transaction_digest().as_bytes(),
        }
    }

    /// Returns the selected custody family.
    #[must_use]
    pub const fn kind(&self) -> CustodyKind {
        self.kind
    }

    /// Returns the exact object identifier being signed.
    #[must_use]
    pub const fn object_id(&self) -> SigningObjectId {
        self.object_id
    }

    /// Returns the descriptor committed by the Auths signing request.
    #[must_use]
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        self.descriptor
    }

    /// Returns the exact domain-separated Auths signing preimage.
    #[must_use]
    pub const fn signing_preimage(&self) -> &[u8] {
        self.signing_preimage
    }

    /// Returns the SHA-256 transaction binding expected in provider output.
    #[must_use]
    pub const fn transaction_digest(&self) -> &[u8; 32] {
        &self.transaction_digest
    }
}

/// Complete output of one external signing transaction.
pub struct CustodySignature {
    signature: SignatureBytes,
    evidence: Vec<EvidenceObject>,
    transaction_digest: [u8; 32],
}

impl CustodySignature {
    /// Constructs provider output without interpreting its evidence.
    #[must_use]
    pub fn new(
        signature: SignatureBytes,
        evidence: Vec<EvidenceObject>,
        transaction_digest: [u8; 32],
    ) -> Self {
        Self {
            signature,
            evidence,
            transaction_digest,
        }
    }
}

/// Effect port implemented by one configured external custody client.
pub trait ExternalSigner: Send + Sync {
    /// Returns the exact custody family used for policy and diagnostics.
    fn kind(&self) -> CustodyKind;

    /// Signs one transaction-bound request.
    ///
    /// Implementations may run a browser ceremony or call a workload, KMS,
    /// HSM, or PKCS#11 API. They must not silently substitute a descriptor.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific failure without a partial signed object.
    fn sign(&self, request: &SigningIntent<'_>) -> Result<CustodySignature, CustodyError>;
}

/// Signed object and exact evidence acquired by its custody transaction.
pub struct SignedArtifact<T> {
    signed: T,
    evidence: Vec<EvidenceObject>,
}

impl<T> SignedArtifact<T> {
    /// Returns the complete signed target object.
    #[must_use]
    pub const fn signed(&self) -> &T {
        &self.signed
    }

    /// Returns evidence acquired by the same signing operation.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }

    /// Consumes the result into its signed object and evidence.
    #[must_use]
    pub fn into_parts(self) -> (T, Vec<EvidenceObject>) {
        (self.signed, self.evidence)
    }
}

/// Completes an externally signed grant as one atomic result.
///
/// # Errors
///
/// Returns a custody failure when the provider fails or returns output bound
/// to a different Auths transaction.
pub fn sign_grant(
    request: ExternalSigningRequest<GrantStatement>,
    signer: &dyn ExternalSigner,
) -> Result<SignedArtifact<SignedGrant>, CustodyError> {
    let output = sign_request(&request, signer)?;
    Ok(SignedArtifact {
        signed: request.complete(output.signature),
        evidence: output.evidence,
    })
}

/// Completes an externally signed action as one atomic result.
///
/// # Errors
///
/// Returns a custody failure when the provider fails or returns output bound
/// to a different Auths transaction.
pub fn sign_action(
    request: ExternalSigningRequest<ActionEnvelope>,
    signer: &dyn ExternalSigner,
) -> Result<SignedArtifact<SignedAction>, CustodyError> {
    let output = sign_request(&request, signer)?;
    Ok(SignedArtifact {
        signed: request.complete(output.signature),
        evidence: output.evidence,
    })
}

/// Completes an externally signed principal-status statement atomically.
///
/// # Errors
///
/// Returns a custody failure when the provider fails or returns output bound
/// to a different Auths transaction.
pub fn sign_principal_status(
    request: ExternalSigningRequest<PrincipalStatusStatement>,
    signer: &dyn ExternalSigner,
) -> Result<SignedArtifact<SignedPrincipalStatus>, CustodyError> {
    let output = sign_request(&request, signer)?;
    Ok(SignedArtifact {
        signed: request.complete(output.signature),
        evidence: output.evidence,
    })
}

/// Completes an externally signed grant-status statement atomically.
///
/// # Errors
///
/// Returns a custody failure when the provider fails or returns output bound
/// to a different Auths transaction.
pub fn sign_grant_status(
    request: ExternalSigningRequest<GrantStatusStatement>,
    signer: &dyn ExternalSigner,
) -> Result<SignedArtifact<SignedGrantStatus>, CustodyError> {
    let output = sign_request(&request, signer)?;
    Ok(SignedArtifact {
        signed: request.complete(output.signature),
        evidence: output.evidence,
    })
}

fn sign_request<T>(
    request: &ExternalSigningRequest<T>,
    signer: &dyn ExternalSigner,
) -> Result<CustodySignature, CustodyError> {
    let intent = SigningIntent::from_request(signer.kind(), request);
    let output = signer.sign(&intent)?;
    if !bool::from(output.transaction_digest.ct_eq(intent.transaction_digest())) {
        return Err(CustodyError::TransactionMismatch);
    }
    Ok(output)
}

/// Closed custody-boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    /// Provider, browser, token, or workload signer was unavailable.
    Unavailable,
    /// Provider rejected the operation or local policy.
    Rejected,
    /// Provider signature encoding was invalid.
    InvalidSignature,
    /// Returned output was bound to different Auths signing bytes.
    TransactionMismatch,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "external custody provider unavailable",
            Self::Rejected => "external custody provider rejected the request",
            Self::InvalidSignature => "external custody provider returned an invalid signature",
            Self::TransactionMismatch => "custody output is bound to a different Auths transaction",
        })
    }
}

impl std::error::Error for CustodyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_author::prepare_action;
    use auths_model::{
        ActionEnvelope, Audience, Challenge, ChannelBindingId, CriticalExtensions, Digest,
        MediaType, Permission, ProfileId, ProfileRef, ProofRef, ResourceId, SignatureSuiteId,
        ValidityWindow, VerificationMethod,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    struct FakeSigner {
        key: SigningKey,
        mismatch: bool,
    }

    impl ExternalSigner for FakeSigner {
        fn kind(&self) -> CustodyKind {
            CustodyKind::Hsm
        }

        fn sign(&self, request: &SigningIntent<'_>) -> Result<CustodySignature, CustodyError> {
            let signature = self
                .key
                .sign(request.signing_preimage())
                .to_bytes()
                .to_vec();
            let mut transaction = *request.transaction_digest();
            if self.mismatch {
                transaction[0] ^= 1;
            }
            Ok(CustodySignature::new(
                SignatureBytes::new(signature).map_err(|_| CustodyError::InvalidSignature)?,
                Vec::new(),
                transaction,
            ))
        }
    }

    fn request() -> ExternalSigningRequest<ActionEnvelope> {
        let envelope = ActionEnvelope::new(
            ProfileRef::new(ProfileId::parse("auths.mcp").unwrap(), 1).unwrap(),
            MediaType::parse("application/vnd.auths.mcp-call.v1+json").unwrap(),
            Digest::new([1; 32]),
            Permission::new(
                auths_model::CapabilityId::parse("tools/call").unwrap(),
                ResourceId::parse("mcp://reports/tools/read").unwrap(),
            ),
            None,
            Audience::parse("mcp://reports").unwrap(),
            Challenge::new([2; 32]),
            ValidityWindow::new(
                auths_model::Timestamp::new(1),
                auths_model::Timestamp::new(2),
            )
            .unwrap(),
            auths_model::PrincipalId::parse("raw:test").unwrap(),
            None,
            auths_model::PlanId::new([3; 32]),
            ChannelBindingId::parse("none-v1").unwrap(),
            ProofRef::new([4; 32]),
            Vec::new(),
            CriticalExtensions::empty(),
        );
        prepare_action(
            envelope,
            SignatureDescriptor::new(
                auths_model::PrincipalMethodId::parse("raw-key-v1").unwrap(),
                VerificationMethod::parse("raw:test").unwrap(),
                SignatureSuiteId::parse("ed25519-v1").unwrap(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn mismatched_provider_transaction_cannot_produce_a_signed_object() {
        let signer = FakeSigner {
            key: SigningKey::from_bytes(&[7; 32]),
            mismatch: true,
        };
        assert!(matches!(
            sign_action(request(), &signer),
            Err(CustodyError::TransactionMismatch)
        ));
    }
}
