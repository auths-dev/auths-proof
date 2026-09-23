//! Shared custody conformance kit.
//!
//! [`ConformanceSigner`] is a deterministic P-256 [`ExternalSigner`] that
//! answers each [`CustodyConformanceCase`] the way a faulty, hostile, or
//! correct provider would. A consumer builds a [`CustodyKey`] over it for
//! every case, drives its own signing path, and compares the outcome with
//! [`expectation`]. The kit holds only fixed test keys.

use crate::{
    CUSTODY_CONFORMANCE_CASES, CustodyAdapterId, CustodyConformanceCase, CustodyDescriptor,
    CustodyError, CustodyIdentity, CustodyKey, CustodyKind, CustodyPrincipalForm,
    CustodyProviderError, ExternalSigner, KeyLifecycleState, KeyVersionId, RawSigningResponse,
    SigningIntent, UntrustedSigningResponse,
};
use auths_model::{
    EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, PrincipalId, SignatureDescriptor,
    SignatureSuiteId, VerificationMethod,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const KEY: [u8; 32] = [0x2a; 32];
const REPLACEMENT_KEY: [u8; 32] = [0x2b; 32];
const KEY_VERSION: &str = "sha256:conformance-key-version-1";
const NEXT_KEY_VERSION: &str = "sha256:conformance-key-version-2";

/// What the central custody boundary must do for one case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceExpectation {
    /// The object is signed and verifies.
    Signed,
    /// Nothing is signed; the boundary returns exactly this error.
    Refused(CustodyError),
    /// The case is decided when an adapter connects, not when it signs;
    /// adapter startup tests cover it.
    Startup,
}

/// The required outcome of `case` on any signing path.
#[must_use]
pub const fn expectation(case: CustodyConformanceCase) -> ConformanceExpectation {
    use ConformanceExpectation::{Refused, Signed, Startup};
    use CustodyConformanceCase as C;
    use CustodyProviderError as P;
    match case {
        C::Valid | C::Redaction => Signed,
        C::ChangedRequest | C::ChangedObject | C::ReplayedResponse | C::ConcurrentReordering => {
            Refused(CustodyError::RequestMismatch)
        }
        C::ChangedPrincipal => Refused(CustodyError::PrincipalMismatch),
        C::ChangedDescriptor | C::ChangedSuite => Refused(CustodyError::DescriptorMismatch),
        C::ChangedKeyVersion | C::RotationInFlight => Refused(CustodyError::KeyVersionMismatch),
        C::ChangedTransaction => Refused(CustodyError::TransactionMismatch),
        C::ChangedPreimage | C::ChangedSignature | C::KeyReplacement => {
            Refused(CustodyError::SignatureVerificationFailed)
        }
        C::ChangedEvidence => Refused(CustodyError::EvidenceMismatch),
        C::HighS => Refused(CustodyError::NonCanonicalSignature),
        C::MalformedDer => Refused(CustodyError::MalformedSignature),
        C::TimeoutBeforeSend | C::ProviderOutage | C::TokenRemoval | C::SessionLoss => {
            Refused(CustodyError::Provider(P::Unavailable))
        }
        C::DisconnectAfterSend => Refused(CustodyError::Provider(P::ProviderUnknown)),
        C::Throttled => Refused(CustodyError::Provider(P::Throttled)),
        C::Denied | C::WrongObject | C::WrongPin => Refused(CustodyError::Provider(P::Denied)),
        C::Cancelled => Refused(CustodyError::Provider(P::Cancelled)),
        C::DisabledKey => Refused(CustodyError::Provider(P::DisabledKey)),
        C::RevokedKey => Refused(CustodyError::Provider(P::RevokedKey)),
        C::PolicyWidening => Startup,
    }
}

/// Every case with its required outcome.
pub fn cases() -> impl Iterator<Item = (CustodyConformanceCase, ConformanceExpectation)> {
    CUSTODY_CONFORMANCE_CASES
        .iter()
        .map(|case| (*case, expectation(*case)))
}

/// Descriptor lifecycle states and whether each may reach the provider.
pub const LIFECYCLE_CASES: &[(KeyLifecycleState, bool)] = &[
    (KeyLifecycleState::Enrolled, false),
    (KeyLifecycleState::Ready, true),
    (KeyLifecycleState::RotationPending, false),
    (KeyLifecycleState::ActiveCurrent, true),
    (KeyLifecycleState::RetiringPrevious, false),
    (KeyLifecycleState::Revoked, false),
    (KeyLifecycleState::Disabled, false),
    (KeyLifecycleState::Unavailable, false),
    (KeyLifecycleState::Indeterminate, false),
];

/// Counts provider calls made by one [`ConformanceSigner`].
#[derive(Clone, Debug, Default)]
pub struct ConformanceProbe(Arc<AtomicUsize>);

impl ConformanceProbe {
    /// Returns how many times the provider was asked to sign.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A deterministic provider that answers exactly one conformance case.
pub struct ConformanceSigner {
    key: SigningKey,
    identity: CustodyIdentity,
    descriptor: CustodyDescriptor,
    case: CustodyConformanceCase,
    probe: ConformanceProbe,
}

impl ConformanceSigner {
    /// Builds a key of `kind` presented under `form`, in `lifecycle`, whose
    /// provider answers `case`, and a probe counting its provider calls.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed test key cannot form an identity.
    #[must_use]
    pub fn key(
        form: CustodyPrincipalForm,
        kind: CustodyKind,
        lifecycle: KeyLifecycleState,
        case: CustodyConformanceCase,
    ) -> (CustodyKey, ConformanceProbe) {
        let signer = Self::new(form, kind, lifecycle, case);
        let probe = signer.probe.clone();
        let identity = signer.identity.clone();
        let key = CustodyKey::new(Box::new(signer), identity).expect("conformance identity");
        (key, probe)
    }

    fn new(
        form: CustodyPrincipalForm,
        kind: CustodyKind,
        lifecycle: KeyLifecycleState,
        case: CustodyConformanceCase,
    ) -> Self {
        let key = SigningKey::from_slice(&KEY).expect("fixed P-256 key");
        let identity =
            CustodyIdentity::p256(form, key.verifying_key().to_encoded_point(true).as_bytes())
                .expect("fixed identity");
        let descriptor = CustodyDescriptor::new(
            kind,
            CustodyAdapterId::parse("conformance-p256-v1").expect("adapter"),
            identity.principal().clone(),
            identity.signature().clone(),
            KeyVersionId::parse(KEY_VERSION).expect("key version"),
            lifecycle,
        )
        .expect("descriptor");
        Self {
            key,
            identity,
            descriptor,
            case,
            probe: ConformanceProbe::default(),
        }
    }

    fn signature(key: &SigningKey, message: &[u8]) -> Signature {
        let signature: Signature = key.sign(message);
        signature.normalize_s().unwrap_or(signature)
    }
}

impl ExternalSigner for ConformanceSigner {
    fn descriptor(&self) -> &CustodyDescriptor {
        &self.descriptor
    }

    fn sign(
        &self,
        request: &SigningIntent<'_>,
    ) -> Result<UntrustedSigningResponse, CustodyProviderError> {
        use CustodyConformanceCase as C;
        self.probe.0.fetch_add(1, Ordering::SeqCst);
        let preimage = request.signing_preimage();
        let valid = Self::signature(&self.key, preimage);
        let mut response = RawSigningResponse {
            request_id: request.request_id().to_owned(),
            principal: self.descriptor.principal().clone(),
            descriptor: self.descriptor.signature().clone(),
            signature: valid.to_der().as_bytes().to_vec(),
            provider_key_version: self.descriptor.key_version().clone(),
            evidence: Vec::new(),
            transaction_digest: *request.transaction_digest(),
        };
        match self.case {
            C::Valid | C::Redaction | C::PolicyWidening => {}
            C::ChangedRequest => response.request_id.push('0'),
            C::ChangedObject | C::ReplayedResponse | C::ConcurrentReordering => {
                response.request_id = other_request(request.request_id());
            }
            C::ChangedPrincipal => {
                response.principal = PrincipalId::parse("key:sha256:conformance-other")
                    .map_err(|_| CustodyProviderError::InvalidProviderResponse)?;
            }
            C::ChangedDescriptor | C::ChangedSuite => {
                let current = self.descriptor.signature();
                response.descriptor = if self.case == C::ChangedSuite {
                    SignatureDescriptor::new(
                        current.principal_method().clone(),
                        current.verification_method().clone(),
                        SignatureSuiteId::parse("ed25519-v1")
                            .map_err(|_| CustodyProviderError::InvalidProviderResponse)?,
                    )
                } else {
                    SignatureDescriptor::new(
                        current.principal_method().clone(),
                        VerificationMethod::parse("key:sha256:conformance-other")
                            .map_err(|_| CustodyProviderError::InvalidProviderResponse)?,
                        current.suite().clone(),
                    )
                };
            }
            C::ChangedKeyVersion | C::RotationInFlight => {
                response.provider_key_version = KeyVersionId::parse(NEXT_KEY_VERSION)
                    .map_err(|_| CustodyProviderError::InvalidProviderResponse)?;
            }
            C::ChangedTransaction => response.transaction_digest[0] ^= 1,
            C::ChangedPreimage => {
                let mut changed = preimage.to_vec();
                changed.push(0);
                response.signature = Self::signature(&self.key, &changed)
                    .to_der()
                    .as_bytes()
                    .to_vec();
            }
            C::ChangedSignature => {
                let mut bytes = valid.to_bytes().to_vec();
                bytes[8] ^= 0x01;
                response.signature = bytes;
            }
            C::KeyReplacement => {
                let replacement = SigningKey::from_slice(&REPLACEMENT_KEY)
                    .map_err(|_| CustodyProviderError::InvalidProviderResponse)?;
                response.signature = Self::signature(&replacement, preimage)
                    .to_der()
                    .as_bytes()
                    .to_vec();
            }
            C::ChangedEvidence => {
                response.evidence = vec![
                    EvidenceObject::new(
                        EvidenceId::new([7; 32]),
                        EvidenceTypeId::parse("conformance-attestation-v1")
                            .map_err(|_| CustodyProviderError::InvalidProviderResponse)?,
                        MediaType::parse("application/octet-stream")
                            .map_err(|_| CustodyProviderError::InvalidProviderResponse)?,
                        vec![1, 2, 3],
                    )
                    .map_err(|_| CustodyProviderError::InvalidProviderResponse)?,
                ];
            }
            C::HighS => {
                let (r, s) = valid.split_scalars();
                let high = Signature::from_scalars(r, -*s)
                    .map_err(|_| CustodyProviderError::InvalidProviderResponse)?;
                response.signature = high.to_bytes().to_vec();
            }
            C::MalformedDer => response.signature = vec![0x30, 0x03, 0x02, 0x01],
            C::TimeoutBeforeSend | C::ProviderOutage | C::TokenRemoval | C::SessionLoss => {
                return Err(CustodyProviderError::Unavailable);
            }
            C::DisconnectAfterSend => return Err(CustodyProviderError::ProviderUnknown),
            C::Throttled => return Err(CustodyProviderError::Throttled),
            C::Denied | C::WrongObject | C::WrongPin => return Err(CustodyProviderError::Denied),
            C::Cancelled => return Err(CustodyProviderError::Cancelled),
            C::DisabledKey => return Err(CustodyProviderError::DisabledKey),
            C::RevokedKey => return Err(CustodyProviderError::RevokedKey),
        }
        UntrustedSigningResponse::parse(response)
    }
}

/// A well-formed request ID naming a different object and transaction, as a
/// response for another request would carry.
fn other_request(request_id: &str) -> String {
    let (kind, _) = request_id.split_once(':').unwrap_or((request_id, ""));
    format!("{kind}:{}:{}", "ab".repeat(32), "cd".repeat(32))
}
