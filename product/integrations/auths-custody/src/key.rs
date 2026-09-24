//! Custody-held P-256 signing identities bound to one external signer.
//!
//! A [`CustodyIdentity`] is the public side of a custody key: its principal,
//! signature descriptor, and the control evidence a verifier needs. It is
//! derived from the provider's public key only. A [`CustodyKey`] pairs it
//! with the [`ExternalSigner`] that holds the private key, so every signature
//! goes through the transaction-bound request, the central response binding,
//! and local verification. There is no raw-preimage signing path.

use crate::{
    CustodyDescriptor, CustodyError, CustodyKind, CustodySignatureVerifier, ExternalSigner,
    P256SignatureVerifier, SignedArtifact, sign_request,
};
use auths_author::{ExternalSigningRequest, address_evidence};
use auths_did_key::{DID_KEY_MEDIA_TYPE, DID_KEY_V1, DidKeyEvidence};
use auths_model::{
    ActionEnvelope, EvidenceObject, EvidenceTypeId, GrantStatement, MediaType,
    ObservationStatement, PrincipalId, PrincipalMethodId, SignatureDescriptor, SignatureSuiteId,
    SignedAction, SignedGrant, SignedObservation, VerificationMethod,
};
use auths_multikey::{Multikey, MultikeyType};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use p256::{EncodedPoint, PublicKey};

const P256_SUITE: &str = "p256-sha256-v1";

/// The principal method a custody key is presented under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPrincipalForm {
    /// A self-certifying `raw-key-v1` principal.
    RawKeyV1,
    /// A `did:key` principal.
    DidKeyV1,
}

/// Public identity of one custody-held P-256 key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyIdentity {
    form: CustodyPrincipalForm,
    principal: PrincipalId,
    signature: SignatureDescriptor,
    control: EvidenceObject,
    public_key: Vec<u8>,
}

impl CustodyIdentity {
    /// Derives the identity of a P-256 key from its SEC1 public key, in
    /// compressed or uncompressed form.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::EvidenceMismatch`] for a key that is not a
    /// valid P-256 point or cannot be represented under `form`.
    pub fn p256(form: CustodyPrincipalForm, sec1: &[u8]) -> Result<Self, CustodyError> {
        let key = PublicKey::from_sec1_bytes(sec1).map_err(|_| CustodyError::EvidenceMismatch)?;
        let public_key = EncodedPoint::from(key).compress().as_bytes().to_vec();
        let invalid = |_| CustodyError::EvidenceMismatch;
        let suite = SignatureSuiteId::parse(P256_SUITE).map_err(invalid)?;
        let (principal, method, verification, evidence_type, media_type, bytes) = match form {
            CustodyPrincipalForm::RawKeyV1 => {
                let raw = RawKeyDescriptor::new(RawKeyType::P256, public_key.clone())
                    .map_err(|_| CustodyError::EvidenceMismatch)?;
                let principal = raw.principal().map_err(invalid)?;
                let verification =
                    VerificationMethod::parse(principal.as_str()).map_err(invalid)?;
                (
                    principal,
                    RAW_KEY_V1,
                    verification,
                    RAW_KEY_V1,
                    RAW_KEY_MEDIA_TYPE,
                    raw.encode(),
                )
            }
            CustodyPrincipalForm::DidKeyV1 => {
                let evidence = DidKeyEvidence::new(
                    Multikey::from_public_key(MultikeyType::P256, public_key.clone())
                        .map_err(|_| CustodyError::EvidenceMismatch)?,
                );
                (
                    evidence.principal().map_err(invalid)?,
                    DID_KEY_V1,
                    evidence.verification_method().map_err(invalid)?,
                    DID_KEY_V1,
                    DID_KEY_MEDIA_TYPE,
                    evidence
                        .encode()
                        .map_err(|_| CustodyError::EvidenceMismatch)?,
                )
            }
        };
        let control = address_evidence(
            EvidenceTypeId::parse(evidence_type).map_err(invalid)?,
            MediaType::parse(media_type).map_err(invalid)?,
            bytes,
        )
        .map_err(|_| CustodyError::EvidenceMismatch)?;
        Ok(Self {
            form,
            signature: SignatureDescriptor::new(
                PrincipalMethodId::parse(method).map_err(invalid)?,
                verification,
                suite,
            ),
            principal,
            control,
            public_key,
        })
    }

    /// Returns the principal method form.
    #[must_use]
    pub const fn form(&self) -> CustodyPrincipalForm {
        self.form
    }

    /// Returns the principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the exact signature descriptor.
    #[must_use]
    pub const fn signature(&self) -> &SignatureDescriptor {
        &self.signature
    }

    /// Returns the evidence object that establishes control of the principal.
    #[must_use]
    pub const fn control_evidence(&self) -> &EvidenceObject {
        &self.control
    }

    /// Returns the compressed SEC1 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// A custody-held key: the external signer, its public identity, and the
/// local verifier every returned signature must pass.
pub struct CustodyKey {
    signer: Box<dyn ExternalSigner>,
    verifier: P256SignatureVerifier,
    identity: CustodyIdentity,
    events: Box<dyn auths_operations::EventSink>,
}

impl CustodyKey {
    /// Binds `signer` to `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::PrincipalMismatch`] or
    /// [`CustodyError::DescriptorMismatch`] when the signer's descriptor does
    /// not describe exactly this identity.
    pub fn new(
        signer: Box<dyn ExternalSigner>,
        identity: CustodyIdentity,
    ) -> Result<Self, CustodyError> {
        let descriptor = signer.descriptor();
        if descriptor.principal() != identity.principal() {
            return Err(CustodyError::PrincipalMismatch);
        }
        if descriptor.signature() != identity.signature() {
            return Err(CustodyError::DescriptorMismatch);
        }
        let verifier = P256SignatureVerifier::from_sec1_bytes(identity.public_key())?;
        Ok(Self {
            signer,
            verifier,
            identity,
            events: Box::new(auths_operations::NoopEventSink),
        })
    }

    /// Sends custody outcomes to `events`.
    #[must_use]
    pub fn with_events(mut self, events: Box<dyn auths_operations::EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Returns the custody descriptor the signer reports.
    #[must_use]
    pub fn descriptor(&self) -> &CustodyDescriptor {
        self.signer.descriptor()
    }

    /// Returns the custody kind the signer reports.
    #[must_use]
    pub fn kind(&self) -> CustodyKind {
        self.signer.descriptor().kind()
    }

    /// Returns the public identity.
    #[must_use]
    pub const fn identity(&self) -> &CustodyIdentity {
        &self.identity
    }

    /// Signs one grant through the custody boundary.
    ///
    /// # Errors
    ///
    /// Returns the custody error when the key's lifecycle forbids signing or
    /// the provider response does not bind to this exact request.
    pub fn sign_grant(
        &self,
        request: ExternalSigningRequest<GrantStatement>,
    ) -> Result<SignedGrant, CustodyError> {
        crate::sign_grant(request, self.signer.as_ref(), &self.verifier, &*self.events)
            .map(SignedArtifact::into_parts)
            .map(|(grant, _)| grant)
    }

    /// Signs one action through the custody boundary.
    ///
    /// # Errors
    ///
    /// As [`CustodyKey::sign_grant`].
    pub fn sign_action(
        &self,
        request: ExternalSigningRequest<ActionEnvelope>,
    ) -> Result<SignedAction, CustodyError> {
        crate::sign_action(request, self.signer.as_ref(), &self.verifier, &*self.events)
            .map(SignedArtifact::into_parts)
            .map(|(action, _)| action)
    }

    /// Signs one observation through the custody boundary and attaches this
    /// key's control evidence.
    ///
    /// # Errors
    ///
    /// As [`CustodyKey::sign_grant`].
    pub fn sign_observation(
        &self,
        request: ExternalSigningRequest<ObservationStatement>,
    ) -> Result<SignedObservation, CustodyError> {
        sign_observation(
            request,
            self.signer.as_ref(),
            &self.verifier,
            &*self.events,
            vec![self.identity.control.clone()],
        )
    }
}

/// Completes one transaction-bound observation signature and attaches the
/// observer's `control` evidence.
///
/// # Errors
///
/// Returns a custody error when the key is unavailable, the provider output
/// does not bind to the exact request, or the evidence cannot be attached.
pub fn sign_observation(
    request: ExternalSigningRequest<ObservationStatement>,
    signer: &dyn ExternalSigner,
    verifier: &dyn CustodySignatureVerifier,
    events: &dyn auths_operations::EventSink,
    control: Vec<EvidenceObject>,
) -> Result<SignedObservation, CustodyError> {
    let output = sign_request(&request, signer, verifier);
    crate::observe_custody_result(events, &output);
    let (signature, _) = output?.into_parts();
    request
        .complete(signature, control)
        .map_err(|_| CustodyError::EvidenceMismatch)
}
