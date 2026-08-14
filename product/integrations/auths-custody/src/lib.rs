//! Transaction-bound external custody for Auths signing requests.

#![forbid(unsafe_code)]

use auths_author::{ExternalSigningRequest, SigningObjectId};
use auths_model::{
    ActionEnvelope, EvidenceObject, GrantStatement, GrantStatusStatement, PrincipalId,
    PrincipalStatusStatement, SignatureBytes, SignatureDescriptor, SignedAction, SignedGrant,
    SignedGrantStatus, SignedPrincipalStatus,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier as _};
use std::fmt;
use subtle::ConstantTimeEq as _;

const MAX_IDENTIFIER_BYTES: usize = 160;
const MAX_EVIDENCE_OBJECTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyKind {
    WebAuthn,
    Workload,
    Kms,
    Hsm,
    Pkcs11,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyAdapterId(String);

impl CustodyAdapterId {
    /// Parses a bounded adapter identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error for an empty, oversized, or
    /// non-canonical value.
    pub fn parse(value: &str) -> Result<Self, CustodyError> {
        parse_identifier(value)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyVersionId(String);

impl KeyVersionId {
    /// Parses a bounded provider key version.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error for an empty, oversized, or
    /// non-canonical value.
    pub fn parse(value: &str) -> Result<Self, CustodyError> {
        parse_identifier(value)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLifecycleState {
    Enrolled,
    Ready,
    RotationPending,
    ActiveCurrent,
    RetiringPrevious,
    Revoked,
    Disabled,
    Unavailable,
    Indeterminate,
}

impl KeyLifecycleState {
    #[must_use]
    pub const fn permits_signing(self) -> bool {
        matches!(self, Self::Ready | Self::ActiveCurrent)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CustodyDescriptor {
    kind: CustodyKind,
    adapter_id: CustodyAdapterId,
    principal: PrincipalId,
    signature: SignatureDescriptor,
    key_version: KeyVersionId,
    lifecycle: KeyLifecycleState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyConformanceCase {
    Valid,
    ChangedRequest,
    ChangedObject,
    ChangedPrincipal,
    ChangedDescriptor,
    ChangedSuite,
    ChangedKeyVersion,
    ChangedTransaction,
    ChangedPreimage,
    ChangedSignature,
    ChangedEvidence,
    HighS,
    MalformedDer,
    ReplayedResponse,
    ConcurrentReordering,
    TimeoutBeforeSend,
    DisconnectAfterSend,
    Throttled,
    Denied,
    Cancelled,
    DisabledKey,
    RevokedKey,
    ProviderOutage,
    RotationInFlight,
    PolicyWidening,
    KeyReplacement,
    TokenRemoval,
    SessionLoss,
    WrongObject,
    WrongPin,
    Redaction,
}

pub const CUSTODY_CONFORMANCE_CASES: &[CustodyConformanceCase] = &[
    CustodyConformanceCase::Valid,
    CustodyConformanceCase::ChangedRequest,
    CustodyConformanceCase::ChangedObject,
    CustodyConformanceCase::ChangedPrincipal,
    CustodyConformanceCase::ChangedDescriptor,
    CustodyConformanceCase::ChangedSuite,
    CustodyConformanceCase::ChangedKeyVersion,
    CustodyConformanceCase::ChangedTransaction,
    CustodyConformanceCase::ChangedPreimage,
    CustodyConformanceCase::ChangedSignature,
    CustodyConformanceCase::ChangedEvidence,
    CustodyConformanceCase::HighS,
    CustodyConformanceCase::MalformedDer,
    CustodyConformanceCase::ReplayedResponse,
    CustodyConformanceCase::ConcurrentReordering,
    CustodyConformanceCase::TimeoutBeforeSend,
    CustodyConformanceCase::DisconnectAfterSend,
    CustodyConformanceCase::Throttled,
    CustodyConformanceCase::Denied,
    CustodyConformanceCase::Cancelled,
    CustodyConformanceCase::DisabledKey,
    CustodyConformanceCase::RevokedKey,
    CustodyConformanceCase::ProviderOutage,
    CustodyConformanceCase::RotationInFlight,
    CustodyConformanceCase::PolicyWidening,
    CustodyConformanceCase::KeyReplacement,
    CustodyConformanceCase::TokenRemoval,
    CustodyConformanceCase::SessionLoss,
    CustodyConformanceCase::WrongObject,
    CustodyConformanceCase::WrongPin,
    CustodyConformanceCase::Redaction,
];

impl CustodyDescriptor {
    /// Creates a descriptor for one externally held key version.
    ///
    /// # Errors
    ///
    /// Returns a descriptor mismatch when no verification method is present.
    pub fn new(
        kind: CustodyKind,
        adapter_id: CustodyAdapterId,
        principal: PrincipalId,
        signature: SignatureDescriptor,
        key_version: KeyVersionId,
        lifecycle: KeyLifecycleState,
    ) -> Result<Self, CustodyError> {
        if signature.verification_method().as_str().is_empty() {
            return Err(CustodyError::DescriptorMismatch);
        }
        Ok(Self {
            kind,
            adapter_id,
            principal,
            signature,
            key_version,
            lifecycle,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> CustodyKind {
        self.kind
    }

    #[must_use]
    pub const fn adapter_id(&self) -> &CustodyAdapterId {
        &self.adapter_id
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub const fn signature(&self) -> &SignatureDescriptor {
        &self.signature
    }

    #[must_use]
    pub const fn key_version(&self) -> &KeyVersionId {
        &self.key_version
    }

    #[must_use]
    pub const fn lifecycle(&self) -> KeyLifecycleState {
        self.lifecycle
    }
}

pub struct SigningIntent<'a> {
    request_id: String,
    object_id: SigningObjectId,
    descriptor: &'a CustodyDescriptor,
    signing_preimage: &'a [u8],
    transaction_digest: [u8; 32],
}

impl<'a> SigningIntent<'a> {
    fn from_request<T>(
        request: &'a ExternalSigningRequest<T>,
        descriptor: &'a CustodyDescriptor,
    ) -> Result<Self, CustodyError> {
        if request.descriptor() != descriptor.signature() {
            return Err(CustodyError::DescriptorMismatch);
        }
        if !descriptor.lifecycle().permits_signing() {
            return Err(CustodyError::LifecycleNotPermitted);
        }
        Ok(Self {
            request_id: request.request_id(),
            object_id: request.object_id(),
            descriptor,
            signing_preimage: request.signing_preimage(),
            transaction_digest: *request.transaction_digest().as_bytes(),
        })
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn object_id(&self) -> SigningObjectId {
        self.object_id
    }

    #[must_use]
    pub const fn descriptor(&self) -> &CustodyDescriptor {
        self.descriptor
    }

    #[must_use]
    pub const fn signing_preimage(&self) -> &[u8] {
        self.signing_preimage
    }

    #[must_use]
    pub const fn transaction_digest(&self) -> &[u8; 32] {
        &self.transaction_digest
    }
}

pub struct RawSigningResponse {
    pub request_id: String,
    pub principal: PrincipalId,
    pub descriptor: SignatureDescriptor,
    pub signature: Vec<u8>,
    pub provider_key_version: KeyVersionId,
    pub evidence: Vec<EvidenceObject>,
    pub transaction_digest: [u8; 32],
}

pub struct UntrustedSigningResponse(RawSigningResponse);

impl UntrustedSigningResponse {
    /// Parses provider output into a bounded untrusted response.
    ///
    /// # Errors
    ///
    /// Returns invalid-provider-response when identifiers, signatures, or
    /// evidence exceed the closed response shape.
    pub fn parse(value: RawSigningResponse) -> Result<Self, CustodyProviderError> {
        parse_identifier(&value.request_id)
            .map_err(|_| CustodyProviderError::InvalidProviderResponse)?;
        if value.signature.is_empty()
            || value.signature.len() > auths_model::HARD_MAX_SIGNATURE_BYTES
            || value.evidence.len() > MAX_EVIDENCE_OBJECTS
        {
            return Err(CustodyProviderError::InvalidProviderResponse);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyProviderError {
    Denied,
    Cancelled,
    Throttled,
    Unavailable,
    RevokedKey,
    DisabledKey,
    ProviderUnknown,
    InvalidProviderResponse,
}

impl CustodyProviderError {
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::Denied => "custody.denied",
            Self::Cancelled => "custody.cancelled",
            Self::Throttled => "custody.throttled",
            Self::Unavailable => "custody.unavailable",
            Self::RevokedKey => "custody.revoked-key",
            Self::DisabledKey => "custody.disabled-key",
            Self::ProviderUnknown => "custody.provider-unknown",
            Self::InvalidProviderResponse => "custody.invalid-provider-response",
        }
    }
}

pub trait ExternalSigner: Send + Sync {
    fn descriptor(&self) -> &CustodyDescriptor;

    /// Requests a signature for one transaction-bound intent.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded failure without completing the Auths
    /// signing object.
    fn sign(
        &self,
        request: &SigningIntent<'_>,
    ) -> Result<UntrustedSigningResponse, CustodyProviderError>;
}

pub trait CustodySignatureVerifier: Send + Sync {
    /// Verifies provider output against the configured custody descriptor.
    ///
    /// # Errors
    ///
    /// Returns a custody error when the descriptor, signature, or evidence
    /// does not establish the expected key operation.
    fn verify(
        &self,
        descriptor: &CustodyDescriptor,
        preimage: &[u8],
        signature: &SignatureBytes,
        evidence: &[EvidenceObject],
    ) -> Result<(), CustodyError>;
}

pub struct P256SignatureVerifier {
    verification_key: VerifyingKey,
}

impl P256SignatureVerifier {
    /// Parses a SEC1-encoded P-256 verification key.
    ///
    /// # Errors
    ///
    /// Returns an evidence mismatch when the key encoding is invalid.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, CustodyError> {
        let verification_key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CustodyError::EvidenceMismatch)?;
        Ok(Self { verification_key })
    }
}

impl CustodySignatureVerifier for P256SignatureVerifier {
    fn verify(
        &self,
        descriptor: &CustodyDescriptor,
        preimage: &[u8],
        signature: &SignatureBytes,
        _evidence: &[EvidenceObject],
    ) -> Result<(), CustodyError> {
        if descriptor.signature().suite().as_str() != "p256-sha256-v1" {
            return Err(CustodyError::DescriptorMismatch);
        }
        let signature = P256Signature::from_slice(signature.as_slice())
            .map_err(|_| CustodyError::MalformedSignature)?;
        self.verification_key
            .verify(preimage, &signature)
            .map_err(|_| CustodyError::SignatureVerificationFailed)
    }
}

pub struct CustodySignature {
    signature: SignatureBytes,
    evidence: Vec<EvidenceObject>,
}

impl CustodySignature {
    #[must_use]
    pub fn into_parts(self) -> (SignatureBytes, Vec<EvidenceObject>) {
        (self.signature, self.evidence)
    }
}

/// Binds and verifies an untrusted provider response to its exact request.
///
/// # Errors
///
/// Returns a custody error for any request, principal, descriptor, key,
/// transaction, signature, or evidence mismatch.
pub fn validate_provider_response<T>(
    request: &ExternalSigningRequest<T>,
    descriptor: &CustodyDescriptor,
    response: UntrustedSigningResponse,
    verifier: &dyn CustodySignatureVerifier,
) -> Result<CustodySignature, CustodyError> {
    let RawSigningResponse {
        request_id,
        principal,
        descriptor: response_descriptor,
        signature,
        provider_key_version,
        evidence,
        transaction_digest,
    } = response.0;
    if request_id != request.request_id() {
        return Err(CustodyError::RequestMismatch);
    }
    if principal != *descriptor.principal() {
        return Err(CustodyError::PrincipalMismatch);
    }
    if response_descriptor != *descriptor.signature()
        || response_descriptor != *request.descriptor()
    {
        return Err(CustodyError::DescriptorMismatch);
    }
    if provider_key_version != *descriptor.key_version() {
        return Err(CustodyError::KeyVersionMismatch);
    }
    if !bool::from(transaction_digest.ct_eq(request.transaction_digest().as_bytes())) {
        return Err(CustodyError::TransactionMismatch);
    }
    let signature = canonical_signature(descriptor.signature(), signature)?;
    verifier.verify(
        descriptor,
        request.signing_preimage(),
        &signature,
        &evidence,
    )?;
    Ok(CustodySignature {
        signature,
        evidence,
    })
}

pub struct SignedArtifact<T> {
    signed: T,
    evidence: Vec<EvidenceObject>,
}

impl<T> SignedArtifact<T> {
    #[must_use]
    pub const fn signed(&self) -> &T {
        &self.signed
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }

    #[must_use]
    pub fn into_parts(self) -> (T, Vec<EvidenceObject>) {
        (self.signed, self.evidence)
    }
}

macro_rules! signing_operation {
    ($name:ident, $input:ty, $output:ty) => {
        /// Completes one transaction-bound Auths signing operation.
        ///
        /// # Errors
        ///
        /// Returns a custody error when the key is unavailable or provider
        /// output does not bind to the exact signing request.
        pub fn $name(
            request: ExternalSigningRequest<$input>,
            signer: &dyn ExternalSigner,
            verifier: &dyn CustodySignatureVerifier,
            events: &dyn auths_operations::EventSink,
        ) -> Result<SignedArtifact<$output>, CustodyError> {
            let output = sign_request(&request, signer, verifier);
            observe_custody_result(events, &output);
            let output = output?;
            Ok(SignedArtifact {
                signed: request.complete(output.signature),
                evidence: output.evidence,
            })
        }
    };
}

signing_operation!(sign_grant, GrantStatement, SignedGrant);
signing_operation!(sign_action, ActionEnvelope, SignedAction);
signing_operation!(
    sign_principal_status,
    PrincipalStatusStatement,
    SignedPrincipalStatus
);
signing_operation!(sign_grant_status, GrantStatusStatement, SignedGrantStatus);

fn observe_custody_result(
    events: &dyn auths_operations::EventSink,
    result: &Result<CustodySignature, CustodyError>,
) {
    use auths_operations::{
        OperationalEventV2, OperationalOutcome, OperationalReasonCode, OperationalStage,
    };
    let (outcome, reason) = match result {
        Ok(_) => (OperationalOutcome::Succeeded, OperationalReasonCode::None),
        Err(CustodyError::Provider(CustodyProviderError::Denied)) => (
            OperationalOutcome::Denied,
            OperationalReasonCode::CustodyDenied,
        ),
        Err(CustodyError::Provider(CustodyProviderError::ProviderUnknown)) => (
            OperationalOutcome::OutcomeUnknown,
            OperationalReasonCode::ProviderUnknown,
        ),
        Err(CustodyError::Provider(_)) => (
            OperationalOutcome::Unavailable,
            OperationalReasonCode::CustodyUnavailable,
        ),
        Err(_) => (OperationalOutcome::Failed, OperationalReasonCode::Denied),
    };
    events.record(&OperationalEventV2::runtime(
        None,
        OperationalStage::Credential,
        outcome,
        reason,
        0,
    ));
}

fn sign_request<T>(
    request: &ExternalSigningRequest<T>,
    signer: &dyn ExternalSigner,
    verifier: &dyn CustodySignatureVerifier,
) -> Result<CustodySignature, CustodyError> {
    let intent = SigningIntent::from_request(request, signer.descriptor())?;
    let response = signer.sign(&intent).map_err(CustodyError::Provider)?;
    validate_provider_response(request, signer.descriptor(), response, verifier)
}

fn canonical_signature(
    descriptor: &SignatureDescriptor,
    bytes: Vec<u8>,
) -> Result<SignatureBytes, CustodyError> {
    if descriptor.suite().as_str() != "p256-sha256-v1" {
        return SignatureBytes::new(bytes).map_err(|_| CustodyError::MalformedSignature);
    }
    let signature = if bytes.len() == 64 {
        P256Signature::from_slice(&bytes)
    } else {
        P256Signature::from_der(&bytes)
    }
    .map_err(|_| CustodyError::MalformedSignature)?;
    if signature.normalize_s().is_some() {
        return Err(CustodyError::NonCanonicalSignature);
    }
    SignatureBytes::new(signature.to_bytes().to_vec()).map_err(|_| CustodyError::MalformedSignature)
}

fn parse_identifier(value: &str) -> Result<(), CustodyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CustodyError::InvalidProviderResponse);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    Provider(CustodyProviderError),
    RequestMismatch,
    PrincipalMismatch,
    DescriptorMismatch,
    KeyVersionMismatch,
    TransactionMismatch,
    MalformedSignature,
    NonCanonicalSignature,
    SignatureVerificationFailed,
    EvidenceMismatch,
    LifecycleNotPermitted,
    InvalidProviderResponse,
}

impl CustodyError {
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::Provider(error) => error.stable_code(),
            Self::RequestMismatch => "custody.request-mismatch",
            Self::PrincipalMismatch => "custody.principal-mismatch",
            Self::DescriptorMismatch => "custody.descriptor-mismatch",
            Self::KeyVersionMismatch => "custody.key-version-mismatch",
            Self::TransactionMismatch => "custody.transaction-mismatch",
            Self::MalformedSignature => "custody.malformed-signature",
            Self::NonCanonicalSignature => "custody.non-canonical-signature",
            Self::SignatureVerificationFailed => "custody.signature-verification-failed",
            Self::EvidenceMismatch => "custody.evidence-mismatch",
            Self::LifecycleNotPermitted => "custody.lifecycle-not-permitted",
            Self::InvalidProviderResponse => "custody.invalid-provider-response",
        }
    }
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_code())
    }
}

impl std::error::Error for CustodyError {}

pub struct LanguageSigningResponse {
    request_id: String,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    signature: SignatureBytes,
    transaction_digest: [u8; 32],
}

impl LanguageSigningResponse {
    #[must_use]
    pub fn new(
        request_id: String,
        principal: PrincipalId,
        descriptor: SignatureDescriptor,
        signature: SignatureBytes,
        transaction_digest: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            principal,
            descriptor,
            signature,
            transaction_digest,
        }
    }
}

/// Binds a language-adapter signature to its exact native signing request.
///
/// # Errors
///
/// Returns a custody error when request, principal, descriptor, or transaction
/// identity differs from the expected native values.
pub fn bind_language_signing_response<T>(
    request: &ExternalSigningRequest<T>,
    expected_principal: &PrincipalId,
    response: LanguageSigningResponse,
) -> Result<SignatureBytes, CustodyError> {
    if response.request_id != request.request_id() {
        return Err(CustodyError::RequestMismatch);
    }
    if response.principal != *expected_principal {
        return Err(CustodyError::PrincipalMismatch);
    }
    if response.descriptor != *request.descriptor() {
        return Err(CustodyError::DescriptorMismatch);
    }
    if !bool::from(
        response
            .transaction_digest
            .ct_eq(request.transaction_digest().as_bytes()),
    ) {
        return Err(CustodyError::TransactionMismatch);
    }
    Ok(response.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_author::prepare_action;
    use auths_model::{
        Audience, Challenge, ChannelBindingId, CriticalExtensions, Digest, MediaType, Permission,
        PrincipalMethodId, ProfileId, ProfileRef, ProofRef, ResourceId, SignatureSuiteId,
        ValidityWindow, VerificationMethod,
    };
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    struct FakeSigner {
        descriptor: CustodyDescriptor,
        key: SigningKey,
        transaction_mismatch: bool,
    }

    impl ExternalSigner for FakeSigner {
        fn descriptor(&self) -> &CustodyDescriptor {
            &self.descriptor
        }

        fn sign(
            &self,
            request: &SigningIntent<'_>,
        ) -> Result<UntrustedSigningResponse, CustodyProviderError> {
            let signature: P256Signature = self.key.sign(request.signing_preimage());
            let signature = signature.normalize_s().unwrap_or(signature);
            let mut transaction_digest = *request.transaction_digest();
            if self.transaction_mismatch {
                transaction_digest[0] ^= 1;
            }
            UntrustedSigningResponse::parse(RawSigningResponse {
                request_id: request.request_id().to_owned(),
                principal: self.descriptor.principal().clone(),
                descriptor: self.descriptor.signature().clone(),
                signature: signature.to_der().as_bytes().to_vec(),
                provider_key_version: self.descriptor.key_version().clone(),
                evidence: Vec::new(),
                transaction_digest,
            })
        }
    }

    fn fixture() -> (
        ExternalSigningRequest<ActionEnvelope>,
        FakeSigner,
        P256SignatureVerifier,
    ) {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let verification = key.verifying_key().to_encoded_point(true);
        let principal = PrincipalId::parse("raw:p256-test").unwrap();
        let signature = SignatureDescriptor::new(
            PrincipalMethodId::parse("raw-key-v1").unwrap(),
            VerificationMethod::parse("raw:p256-test").unwrap(),
            SignatureSuiteId::parse("p256-sha256-v1").unwrap(),
        );
        let descriptor = CustodyDescriptor::new(
            CustodyKind::Kms,
            CustodyAdapterId::parse("test-kms-p256-v1").unwrap(),
            principal.clone(),
            signature.clone(),
            KeyVersionId::parse("sha256:test-key-version").unwrap(),
            KeyLifecycleState::ActiveCurrent,
        )
        .unwrap();
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
            principal,
            None,
            auths_model::PlanId::new([3; 32]),
            ChannelBindingId::parse("none-v1").unwrap(),
            ProofRef::new([4; 32]),
            Vec::new(),
            CriticalExtensions::empty(),
        );
        (
            prepare_action(envelope, signature).unwrap(),
            FakeSigner {
                descriptor,
                key,
                transaction_mismatch: false,
            },
            P256SignatureVerifier::from_sec1_bytes(verification.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn central_boundary_binds_and_verifies_provider_signature() {
        let (request, signer, verifier) = fixture();
        let result = sign_action(
            request,
            &signer,
            &verifier,
            &auths_operations::NoopEventSink,
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn mismatched_provider_transaction_cannot_complete_object() {
        let (request, mut signer, verifier) = fixture();
        signer.transaction_mismatch = true;
        let result = sign_action(
            request,
            &signer,
            &verifier,
            &auths_operations::NoopEventSink,
        );
        assert!(
            matches!(result, Err(CustodyError::TransactionMismatch)),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn disabled_key_cannot_reach_provider() {
        let (request, mut signer, verifier) = fixture();
        signer.descriptor.lifecycle = KeyLifecycleState::Disabled;
        assert!(matches!(
            sign_action(
                request,
                &signer,
                &verifier,
                &auths_operations::NoopEventSink,
            ),
            Err(CustodyError::LifecycleNotPermitted)
        ));
    }
}
