//! Effect-boundary evidence assembly for target Auths principal methods.
//!
//! Browser, workload API, HSM, KMS, and PKCS#11 clients acquire bytes outside
//! the proof kernel. This crate packages those outputs into the exact,
//! content-addressed evidence forms consumed by pure principal methods.

#![forbid(unsafe_code)]

use auths_codec::evidence_id;
use auths_hsm_attested::{
    HSM_ATTESTED_MEDIA_TYPE, HSM_ATTESTED_V1, HsmAttestationEvidence, HsmKeyRecord,
};
use auths_model::{
    EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, ModelError, StatementRef,
};
use auths_spiffe_x509::{SPIFFE_X509_MEDIA_TYPE, SPIFFE_X509_V1, SpiffeError, SpiffeX509Evidence};
use auths_webauthn::{WEBAUTHN_MEDIA_TYPE, WEBAUTHN_V1, WebAuthnError, WebAuthnEvidence};
use std::fmt;

/// One exact addressed evidence object ready for a proof bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledEvidence {
    object: EvidenceObject,
}

impl AssembledEvidence {
    /// Returns the immutable content-addressed evidence object.
    #[must_use]
    pub const fn object(&self) -> &EvidenceObject {
        &self.object
    }

    /// Consumes the wrapper and returns the proof-model object.
    #[must_use]
    pub fn into_object(self) -> EvidenceObject {
        self.object
    }
}

/// Packages a leaf-first SPIFFE X.509-SVID chain.
///
/// The chain excludes verifier-local trust anchors. Certificate acquisition
/// and refresh remain workload API effects.
///
/// # Errors
///
/// Returns a typed failure for malformed, empty, oversized, or excessive
/// certificate chains and for content-addressing failure.
pub fn assemble_spiffe_x509(
    certificates: Vec<Vec<u8>>,
) -> Result<AssembledEvidence, EvidenceAssemblyError> {
    let evidence = SpiffeX509Evidence::new(certificates)?;
    address(SPIFFE_X509_V1, SPIFFE_X509_MEDIA_TYPE, evidence.encode()?)
}

/// Packages one `WebAuthn` assertion returned by a completed browser ceremony.
///
/// # Errors
///
/// Returns a typed failure for malformed or over-limit assertion components
/// and for content-addressing failure.
pub fn assemble_webauthn_assertion(
    credential_id: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
) -> Result<AssembledEvidence, EvidenceAssemblyError> {
    let evidence = WebAuthnEvidence::new(credential_id, authenticator_data, client_data_json)?;
    address(WEBAUTHN_V1, WEBAUTHN_MEDIA_TYPE, evidence.encode()?)
}

/// Packages a reviewed HSM/KMS/PKCS#11 attestation record and binds it to the
/// exact Auths signing preimage.
///
/// # Errors
///
/// Returns a typed failure for encoding or content-addressing failure.
pub fn assemble_hsm_attestation(
    record: &HsmKeyRecord,
    signing_preimage: &[u8],
) -> Result<AssembledEvidence, EvidenceAssemblyError> {
    if signing_preimage.is_empty() {
        return Err(EvidenceAssemblyError::InvalidInput);
    }
    let evidence = HsmAttestationEvidence::for_record(record, signing_preimage);
    address(HSM_ATTESTED_V1, HSM_ATTESTED_MEDIA_TYPE, evidence.encode()?)
}

/// Constructs an exact statement binding for assembled evidence.
///
/// # Errors
///
/// Returns a model failure when the evidence set is empty, excessive, or
/// contains duplicate identifiers.
pub fn bind(
    statement: StatementRef,
    evidence: &[AssembledEvidence],
) -> Result<auths_model::ControlBinding, EvidenceAssemblyError> {
    auths_model::ControlBinding::new(
        statement,
        evidence
            .iter()
            .map(|item| EvidenceId::new(*item.object.id().as_bytes()))
            .collect(),
    )
    .map_err(EvidenceAssemblyError::Model)
}

fn address(
    evidence_type: &str,
    media_type: &str,
    bytes: Vec<u8>,
) -> Result<AssembledEvidence, EvidenceAssemblyError> {
    let evidence_type =
        EvidenceTypeId::parse(evidence_type).map_err(EvidenceAssemblyError::Model)?;
    let media_type = MediaType::parse(media_type).map_err(EvidenceAssemblyError::Model)?;
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        evidence_type.clone(),
        media_type.clone(),
        bytes.clone(),
    )
    .map_err(EvidenceAssemblyError::Model)?;
    let id = evidence_id(&unaddressed).map_err(|_| EvidenceAssemblyError::Addressing)?;
    let object = EvidenceObject::new(id, evidence_type, media_type, bytes)
        .map_err(EvidenceAssemblyError::Model)?;
    Ok(AssembledEvidence { object })
}

/// Closed evidence-assembly failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAssemblyError {
    /// An input required for transaction binding is absent.
    InvalidInput,
    /// The proof model rejected an identifier, media type, or evidence bound.
    Model(ModelError),
    /// SPIFFE chain framing is invalid.
    Spiffe(SpiffeError),
    /// `WebAuthn` assertion framing is invalid.
    WebAuthn(WebAuthnError),
    /// HSM attestation framing is invalid.
    Hsm,
    /// Deterministic evidence identifier derivation failed.
    Addressing,
}

impl From<SpiffeError> for EvidenceAssemblyError {
    fn from(error: SpiffeError) -> Self {
        Self::Spiffe(error)
    }
}

impl From<WebAuthnError> for EvidenceAssemblyError {
    fn from(error: WebAuthnError) -> Self {
        Self::WebAuthn(error)
    }
}

impl From<auths_hsm_attested::HsmError> for EvidenceAssemblyError {
    fn from(_: auths_hsm_attested::HsmError) -> Self {
        Self::Hsm
    }
}

impl fmt::Display for EvidenceAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid evidence assembly input",
            Self::Model(_) => "evidence violates the Auths proof model",
            Self::Spiffe(_) => "invalid SPIFFE X.509-SVID evidence",
            Self::WebAuthn(_) => "invalid WebAuthn assertion evidence",
            Self::Hsm => "invalid HSM attestation evidence",
            Self::Addressing => "could not derive the canonical evidence identifier",
        })
    }
}

impl std::error::Error for EvidenceAssemblyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{SignatureSuiteId, Timestamp};
    use ed25519_dalek::SigningKey;

    #[test]
    fn hsm_evidence_changes_with_the_auths_transaction() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let record = HsmKeyRecord::new(
            SignatureSuiteId::parse("ed25519-v1").unwrap(),
            key.verifying_key().to_bytes().to_vec(),
            "pkcs11-v1".into(),
            "reference-hsm".into(),
            "hardware".into(),
            [1; 32],
            [2; 32],
            true,
            Timestamp::new(1),
            Timestamp::new(10),
        )
        .unwrap();
        let first = assemble_hsm_attestation(&record, b"first").unwrap();
        let second = assemble_hsm_attestation(&record, b"second").unwrap();
        assert_ne!(first.object().id(), second.object().id());
    }
}
