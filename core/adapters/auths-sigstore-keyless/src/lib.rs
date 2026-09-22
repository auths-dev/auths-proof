//! Offline Sigstore keyless principal control with Rekor inclusion evidence.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod chain;
pub mod checkpoint;
pub mod ecdsa_der;
pub mod entry;
pub mod identity;
pub mod merkle;
#[cfg(test)]
mod public_good_tests;

use alloc::{format, string::String, vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, BoundError, BoundedBytes,
    BoundedSet, ClaimParameterId, Digest, EvidenceId, EvidenceSourceId, EvidenceTypeId, MediaType,
    PrincipalMethodId, Timestamp, VerificationMethod,
};
use auths_ports::{
    AlgorithmBinding, AlgorithmBindingSet, CertificatePathVerifier, ControlEvidence,
    ExtendedKeyUsage, KeyForm, PathError, PathInput, PrincipalControlError, PrincipalControlInput,
    PrincipalMethod, SignatureError, SignatureInput, SignatureSuite, TrustAnchorSet,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chain::{
    CertificateChain, LeafCertificate, MAX_CHAIN_LENGTH, spki_algorithm_identifier, spki_bit_string,
};
use checkpoint::{CheckpointOrigin, NoteName};
use core::{cmp::Ordering, fmt};
use entry::{LogId, RekorEntry};
use identity::{FulcioFacts, FulcioIssuerProfile, IssuerUrl, PolicyRejection, Subject};
use sha2::{Digest as _, Sha256};

pub const SIGSTORE_KEYLESS_V1: &str = "sigstore-keyless-v1";
pub const CHAIN_MEDIA_TYPE: &str = "application/vnd.auths.sigstore-certificate-chain.v1";
pub const ENTRY_MEDIA_TYPE: &str = "application/vnd.auths.sigstore-rekor-entry.v1";
pub const MAX_LOGS: usize = 4;
pub const MAX_ISSUERS: usize = 16;
pub const MAX_KEY_MATERIAL_BYTES: usize = 131_072;
pub const MAX_LEAF_VALIDITY: u64 = 3600;
pub const SIGNING_TIME_DRIFT: u64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    Malformed,
    NonCanonical,
    Validity,
    Limit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    Syntax,
    Origin,
    Signature,
    UnknownKey,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryError {
    Cbor,
    NonCanonical,
    Body,
    Proof,
    Limit,
    Checkpoint(CheckpointError),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionError {
    Certificate,
    Missing,
    Duplicate,
    IdentitySan,
    InvalidValue,
    Limit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowViolation {
    BeforeCertificate,
    AfterCertificate,
    SigningTimeDrift,
    Future,
    Overflow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    LogBinding,
    LogAlgorithm,
    UnregisteredSuite,
    InvalidKey,
    InvalidNote,
    Bindings,
    Logs(BoundError),
    Issuers(BoundError),
    LeafValidity,
    Model,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigstoreError {
    PrincipalSyntax,
    UnknownIssuer,
    MissingChain,
    DuplicateChain,
    MissingEntry,
    DuplicateEntry,
    Chain(ChainError),
    Entry(EntryError),
    UnknownLog,
    PreimageMismatch,
    EntrySignatureMismatch,
    LeafMismatch,
    SignedEntryTimestamp,
    Inclusion,
    Checkpoint(CheckpointError),
    SuiteContract,
    OutsideWindow(WindowViolation),
    Path(PathError),
    PathVerifierContract,
    Extension(ExtensionError),
    IssuerMismatch,
    SubjectMismatch,
    VerificationMethodMismatch,
    UnboundKeyAlgorithm,
    WorkloadSuiteMismatch,
    PolicyRejected(PolicyRejection),
    LimitExceeded,
}
impl fmt::Display for SigstoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sigstore.{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LogKind {
    Rfc6962Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RekorLog {
    id: LogId,
    note_key_name: NoteName,
    note_key_hint: [u8; 4],
    origin: CheckpointOrigin,
    spki: BoundedBytes<MAX_KEY_MATERIAL_BYTES>,
    binding: AlgorithmBinding,
    kind: LogKind,
}
impl RekorLog {
    /// Constructs one configured Rekor log verifier.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when the log key or binding is invalid,
    /// the suite is unregistered, or a configured bound is exceeded.
    pub fn new(
        origin: CheckpointOrigin,
        note_key_name: NoteName,
        spki: Vec<u8>,
        binding: AlgorithmBinding,
        kind: LogKind,
        suites: &[&dyn SignatureSuite],
    ) -> Result<Self, ConfigurationError> {
        let AlgorithmBinding::Spki {
            algorithm,
            suite,
            key_form,
        } = &binding
        else {
            return Err(ConfigurationError::LogBinding);
        };
        let parsed =
            spki_algorithm_identifier(&spki).map_err(|()| ConfigurationError::LogAlgorithm)?;
        if parsed != algorithm.as_bytes() {
            return Err(ConfigurationError::LogAlgorithm);
        }
        let implementation = suites
            .iter()
            .find(|candidate| candidate.id() == suite)
            .ok_or(ConfigurationError::UnregisteredSuite)?;
        let key = project_key(&spki, *key_form).map_err(|()| ConfigurationError::InvalidKey)?;
        implementation
            .validate_key(&key)
            .map_err(|_| ConfigurationError::InvalidKey)?;
        let id = LogId::new(Sha256::digest(&spki).into());
        let hint = note_key_hint(&note_key_name, &spki, suite.as_str())
            .map_err(|()| ConfigurationError::InvalidNote)?;
        Ok(Self {
            id,
            note_key_name,
            note_key_hint: hint,
            origin,
            spki: BoundedBytes::new(spki).map_err(|_| ConfigurationError::InvalidKey)?,
            binding,
            kind,
        })
    }
    #[must_use]
    pub const fn id(&self) -> LogId {
        self.id
    }
}
impl Ord for RekorLog {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}
impl PartialOrd for RekorLog {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
pub type LogSet = BoundedSet<RekorLog, MAX_LOGS>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerPolicy {
    url: IssuerUrl,
    profile: FulcioIssuerProfile,
}
impl IssuerPolicy {
    #[must_use]
    pub fn new(url: IssuerUrl, profile: FulcioIssuerProfile) -> Self {
        Self { url, profile }
    }
    #[must_use]
    pub const fn url(&self) -> &IssuerUrl {
        &self.url
    }
}
impl Ord for IssuerPolicy {
    fn cmp(&self, other: &Self) -> Ordering {
        self.url.cmp(&other.url)
    }
}
impl PartialOrd for IssuerPolicy {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
pub type IssuerPolicySet = BoundedSet<IssuerPolicy, MAX_ISSUERS>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeafValidity(u64);
impl LeafValidity {
    /// Constructs the maximum permitted Fulcio leaf validity.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when `seconds` is zero or exceeds the
    /// adapter's fixed maximum.
    pub fn new(seconds: u64) -> Result<Self, ConfigurationError> {
        if seconds == 0 || seconds > MAX_LEAF_VALIDITY {
            return Err(ConfigurationError::LeafValidity);
        }
        Ok(Self(seconds))
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub struct SigstoreKeylessMethod<'a> {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    chain_media: MediaType,
    entry_media: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    anchors: TrustAnchorSet,
    path_verifier: &'a dyn CertificatePathVerifier,
    key_bindings: AlgorithmBindingSet,
    logs: LogSet,
    issuers: IssuerPolicySet,
    leaf_validity: LeafValidity,
    suites: &'a [&'a dyn SignatureSuite],
}
impl<'a> SigstoreKeylessMethod<'a> {
    #[allow(clippy::too_many_arguments)]
    /// Constructs a keyless Sigstore principal method.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when identifiers, bindings, log policy,
    /// issuer policy, or configured bounds are invalid.
    pub fn new(
        anchors: TrustAnchorSet,
        path_verifier: &'a dyn CertificatePathVerifier,
        key_bindings: AlgorithmBindingSet,
        logs: Vec<RekorLog>,
        issuers: Vec<IssuerPolicy>,
        leaf_validity: LeafValidity,
        suites: &'a [&'a dyn SignatureSuite],
    ) -> Result<Self, ConfigurationError> {
        if key_bindings
            .as_slice()
            .iter()
            .any(|binding| !matches!(binding, AlgorithmBinding::Spki { .. }))
        {
            return Err(ConfigurationError::Bindings);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(SIGSTORE_KEYLESS_V1)
                .map_err(|_| ConfigurationError::Model)?,
            evidence_type: EvidenceTypeId::parse(SIGSTORE_KEYLESS_V1)
                .map_err(|_| ConfigurationError::Model)?,
            chain_media: MediaType::parse(CHAIN_MEDIA_TYPE)
                .map_err(|_| ConfigurationError::Model)?,
            entry_media: MediaType::parse(ENTRY_MEDIA_TYPE)
                .map_err(|_| ConfigurationError::Model)?,
            adapter: AdapterId::parse(SIGSTORE_KEYLESS_V1)
                .map_err(|_| ConfigurationError::Model)?,
            source: EvidenceSourceId::parse("adapter:sigstore-keyless-v1")
                .map_err(|_| ConfigurationError::Model)?,
            anchors,
            path_verifier,
            key_bindings,
            logs: BoundedSet::new(logs).map_err(ConfigurationError::Logs)?,
            issuers: BoundedSet::new(issuers).map_err(ConfigurationError::Issuers)?,
            leaf_validity,
            suites,
        })
    }
    /// Verifies keyless signing evidence and returns its control evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SigstoreError`] for malformed or inconsistent evidence,
    /// failed transparency/path/signature checks, or rejected workload policy.
    pub fn verify_detailed(
        &self,
        input: &PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, SigstoreError> {
        let (principal_issuer, principal_subject) = parse_principal(input.principal.as_str())?;
        let issuer = self
            .issuers
            .as_slice()
            .iter()
            .find(|v| v.url == principal_issuer)
            .ok_or(SigstoreError::UnknownIssuer)?;
        let (chain_evidence, entry_evidence) = self.select(input.evidence)?;
        let chain = CertificateChain::parse(chain_evidence.bytes(), self.leaf_validity.get())
            .map_err(SigstoreError::Chain)?;
        let entry = RekorEntry::parse(entry_evidence.bytes()).map_err(SigstoreError::Entry)?;
        let log = self
            .logs
            .as_slice()
            .iter()
            .find(|log| log.id == entry.log)
            .ok_or(SigstoreError::UnknownLog)?;
        bind_entry(&entry, input, &chain)?;
        verify_signed_entry_timestamp(self.suites, log, &entry)?;
        verify_inclusion(self.suites, log, &entry)?;
        let instant = signing_instant(
            chain.leaf(),
            entry.integrated,
            input.asserted_signing_time,
            input.evaluation_time,
        )?;
        let verified = self.verify_path(&chain, instant)?;
        let facts = FulcioFacts::extract(&verified)?;
        if facts.issuer != issuer.url {
            return Err(SigstoreError::IssuerMismatch);
        }
        if facts.subject != principal_subject {
            return Err(SigstoreError::SubjectMismatch);
        }
        let identity = facts.into_identity(&issuer.profile)?;
        let method = verification_method(input.principal.as_str(), chain.leaf().der().as_bytes())
            .map_err(|_| SigstoreError::LimitExceeded)?;
        if &method != input.verification_method {
            return Err(SigstoreError::VerificationMethodMismatch);
        }
        let selection = self
            .key_bindings
            .select_spki(verified.spki_algorithm())
            .ok_or(SigstoreError::UnboundKeyAlgorithm)?;
        if selection.suite() != input.signature_suite {
            return Err(SigstoreError::WorkloadSuiteMismatch);
        }
        let key = verified
            .key_bytes(selection.key_form())
            .map_err(SigstoreError::Path)?;
        let admitted = issuer
            .profile
            .admit(&identity)
            .map_err(SigstoreError::PolicyRejected)?;
        let claims = assurance_claims(
            &admitted,
            &entry,
            &verified,
            self.path_verifier.id().as_str(),
            &self.source,
        )?;
        ControlEvidence::new(
            key,
            claims,
            vec![
                EvidenceId::new(*chain_evidence.id().as_bytes()),
                EvidenceId::new(*entry_evidence.id().as_bytes()),
            ],
            self.adapter.clone(),
            1,
            self.maximum_work_units(),
        )
        .map_err(|_| SigstoreError::LimitExceeded)
    }
    fn verify_path(
        &self,
        chain: &CertificateChain,
        instant: Timestamp,
    ) -> Result<auths_ports::VerifiedLeaf, SigstoreError> {
        let verified = self
            .path_verifier
            .verify(PathInput {
                leaf: chain.leaf().der(),
                intermediates: chain.intermediates(),
                anchors: &self.anchors,
                at: instant,
                required_eku: &ExtendedKeyUsage::code_signing(),
            })
            .map_err(SigstoreError::Path)?;
        if verified.der() != chain.leaf().der()
            || verified.not_before() != chain.leaf().not_before()
            || verified.not_after() != chain.leaf().not_after()
            || verified.verified_at() != instant
            || verified.spki() != chain.leaf().spki()
            || verified.spki_algorithm() != chain.leaf().spki_algorithm()
        {
            return Err(SigstoreError::PathVerifierContract);
        }
        Ok(verified)
    }
    fn select<'b>(
        &self,
        evidence: &'b [&'b auths_model::EvidenceObject],
    ) -> Result<
        (
            &'b auths_model::EvidenceObject,
            &'b auths_model::EvidenceObject,
        ),
        SigstoreError,
    > {
        let mut chain = None;
        let mut entry = None;
        for item in evidence
            .iter()
            .copied()
            .filter(|item| item.evidence_type() == &self.evidence_type)
        {
            if item.media_type() == &self.chain_media {
                if chain.replace(item).is_some() {
                    return Err(SigstoreError::DuplicateChain);
                }
            } else if item.media_type() == &self.entry_media && entry.replace(item).is_some() {
                return Err(SigstoreError::DuplicateEntry);
            }
        }
        Ok((
            chain.ok_or(SigstoreError::MissingChain)?,
            entry.ok_or(SigstoreError::MissingEntry)?,
        ))
    }
}
impl PrincipalMethod for SigstoreKeylessMethod<'_> {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut c = Vec::new();
        for a in self.anchors.as_slice() {
            c.push(a.as_bytes().to_vec());
        }
        c.push(self.path_verifier.id().as_str().as_bytes().to_vec());
        c.push(self.path_verifier.configuration_id().as_bytes().to_vec());
        c.push(self.key_bindings.configuration_id().as_bytes().to_vec());
        for l in self.logs.as_slice() {
            c.push(l.id.bytes().to_vec());
            c.push(l.origin.as_str().as_bytes().to_vec());
            c.push(l.note_key_name.as_str().as_bytes().to_vec());
            c.push(l.note_key_hint.to_vec());
            c.push(l.spki.as_slice().to_vec());
            if let Some(s) = self.suites.iter().find(|s| s.id() == l.binding.suite()) {
                c.push(s.configuration_id().as_bytes().to_vec());
            }
        }
        for i in self.issuers.as_slice() {
            c.push(i.url.as_str().as_bytes().to_vec());
            c.extend(i.profile.components());
        }
        c.push(self.leaf_validity.get().to_be_bytes().to_vec());
        auths_ports::configuration_id(b"auths-sigstore-keyless-v1", c.iter().map(Vec::as_slice))
    }
    fn maximum_work_units(&self) -> u64 {
        self.path_verifier
            .maximum_work_units(MAX_CHAIN_LENGTH)
            .saturating_add(
                self.suites
                    .iter()
                    .map(|s| s.work_units())
                    .max()
                    .unwrap_or(0)
                    .saturating_mul(2),
            )
            .saturating_add(500)
    }
    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        self.verify_detailed(&input).map_err(map_error)
    }
}

/// Binds the logged entry to this action: the body must record the digest
/// of the exact signing preimage, the action signature, and the chain's leaf.
///
/// For a P-256 action the body carries the signature as DER, as Rekor
/// requires; it is compared by value, after conversion to the fixed-width
/// low-S form, and that form must equal the action signature byte for byte.
/// Any other suite compares the raw bytes.
fn bind_entry(
    entry: &RekorEntry,
    input: &PrincipalControlInput<'_>,
    chain: &CertificateChain,
) -> Result<(), SigstoreError> {
    let digest: [u8; 32] = Sha256::digest(input.signing_preimage).into();
    if entry.body.artifact_digest != Digest::new(digest) {
        return Err(SigstoreError::PreimageMismatch);
    }
    if !entry_signature_matches(
        input.signature_suite.as_str(),
        entry.body.signature.as_slice(),
        input.signature,
    ) {
        return Err(SigstoreError::EntrySignatureMismatch);
    }
    if entry.body.certificate != *chain.leaf().der() {
        return Err(SigstoreError::LeafMismatch);
    }
    Ok(())
}

/// Whether a logged entry signature is the action signature.
pub(crate) fn entry_signature_matches(suite: &str, logged: &[u8], action: &[u8]) -> bool {
    if suite == ecdsa_der::P256_SHA256_SUITE {
        ecdsa_der::low_s_fixed(logged).is_ok_and(|fixed| fixed.as_slice() == action)
    } else {
        logged == action
    }
}

/// Verifies the log's Signed Entry Timestamp over the re-derived entry
/// metadata.
pub(crate) fn verify_signed_entry_timestamp(
    suites: &[&dyn SignatureSuite],
    log: &RekorLog,
    entry: &RekorEntry,
) -> Result<(), SigstoreError> {
    verify_log_signature(
        suites,
        log,
        &entry.set_preimage(),
        entry.signed_entry_timestamp.as_slice(),
    )
    .map_err(|e| match e {
        SigstoreError::SuiteContract => e,
        _ => SigstoreError::SignedEntryTimestamp,
    })
}

/// Verifies that the entry body is included under the checkpoint root and
/// that the checkpoint is signed by the pinned log key.
pub(crate) fn verify_inclusion(
    suites: &[&dyn SignatureSuite],
    log: &RekorLog,
    entry: &RekorEntry,
) -> Result<(), SigstoreError> {
    let root = merkle::fold(
        entry.proof.index,
        entry.proof.tree_size,
        merkle::leaf_hash(&entry.body.raw),
        &entry.proof.hashes,
    )
    .map_err(|_| SigstoreError::Inclusion)?;
    if root != entry.checkpoint.root {
        return Err(SigstoreError::Inclusion);
    }
    if entry.checkpoint.origin != log.origin {
        return Err(SigstoreError::Checkpoint(CheckpointError::Origin));
    }
    let note = entry
        .checkpoint
        .signatures
        .iter()
        .find(|signature| {
            signature.name == log.note_key_name && signature.hint == log.note_key_hint
        })
        .ok_or(SigstoreError::Checkpoint(CheckpointError::UnknownKey))?;
    verify_log_signature(suites, log, &entry.checkpoint.body, &note.bytes).map_err(|e| match e {
        SigstoreError::SuiteContract => e,
        _ => SigstoreError::Checkpoint(CheckpointError::Signature),
    })
}

/// Verifies one signature by a pinned log key through its bound suite.
///
/// A log bound to the P-256 suite signs with DER ECDSA and may emit either
/// member of a malleability pair; the signature is converted to the suite's
/// fixed-width low-S form first. Malleability is irrelevant here: the
/// signer is a pinned log and the signed content is fixed by the evidence.
fn verify_log_signature(
    suites: &[&dyn SignatureSuite],
    log: &RekorLog,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SigstoreError> {
    let suite = suites
        .iter()
        .find(|candidate| candidate.id() == log.binding.suite())
        .ok_or(SigstoreError::SuiteContract)?;
    let AlgorithmBinding::Spki { key_form, .. } = log.binding else {
        return Err(SigstoreError::SuiteContract);
    };
    let key =
        project_key(log.spki.as_slice(), key_form).map_err(|()| SigstoreError::SuiteContract)?;
    let fixed;
    let signature = if log.binding.suite().as_str() == ecdsa_der::P256_SHA256_SUITE {
        fixed = ecdsa_der::low_s_fixed(signature)
            .map_err(|_| SigstoreError::Checkpoint(CheckpointError::Signature))?;
        fixed.as_slice()
    } else {
        signature
    };
    suite
        .verify(SignatureInput {
            verification_key: &key,
            signing_preimage: message,
            signature,
        })
        .map_err(|e| match e {
            SignatureError::InvalidKey => SigstoreError::SuiteContract,
            _ => SigstoreError::Checkpoint(CheckpointError::Signature),
        })
}

/// Derives a log's signed-note key hint.
///
/// A P-256 log uses Rekor's ECDSA key id, the first four bytes of SHA-256
/// of the DER `SubjectPublicKeyInfo` — the same bytes as the log id prefix.
/// Every other log uses the first four bytes of SHA-256 of the key name, a
/// newline, and the DER `SubjectPublicKeyInfo`.
fn note_key_hint(name: &NoteName, spki: &[u8], suite: &str) -> Result<[u8; 4], ()> {
    let digest: [u8; 32] = if suite == ecdsa_der::P256_SHA256_SUITE {
        Sha256::digest(spki).into()
    } else {
        let mut input = Vec::new();
        input.extend_from_slice(name.as_str().as_bytes());
        input.push(b'\n');
        input.extend_from_slice(spki);
        Sha256::digest(input).into()
    };
    digest[..4].try_into().map_err(|_| ())
}

fn signing_instant(
    leaf: &LeafCertificate,
    integrated: Timestamp,
    signing: Timestamp,
    now: Timestamp,
) -> Result<Timestamp, SigstoreError> {
    if integrated < leaf.not_before() {
        return Err(SigstoreError::OutsideWindow(
            WindowViolation::BeforeCertificate,
        ));
    }
    if integrated >= leaf.not_after() {
        return Err(SigstoreError::OutsideWindow(
            WindowViolation::AfterCertificate,
        ));
    }
    if integrated > now {
        return Err(SigstoreError::OutsideWindow(WindowViolation::Future));
    }
    let drift = integrated.get().abs_diff(signing.get());
    if drift > SIGNING_TIME_DRIFT {
        return Err(SigstoreError::OutsideWindow(
            WindowViolation::SigningTimeDrift,
        ));
    }
    Ok(integrated)
}
fn project_key(spki: &[u8], form: KeyForm) -> Result<Vec<u8>, ()> {
    match form {
        KeyForm::SubjectPublicKeyInfoDer => Ok(spki.to_vec()),
        KeyForm::BitStringContents => Ok(spki_bit_string(spki)?.to_vec()),
        KeyForm::Sec1Compressed => {
            let point = spki_bit_string(spki)?;
            if point.len() != 65 || point[0] != 4 {
                return Err(());
            }
            let mut out = Vec::with_capacity(33);
            out.push(if point[64] & 1 == 0 { 2 } else { 3 });
            out.extend_from_slice(&point[1..33]);
            Ok(out)
        }
    }
}
/// Derives the certificate-bound verification method for one principal.
///
/// # Errors
///
/// Returns [`auths_model::ModelError`] when the resulting method identifier
/// violates model bounds or syntax.
pub fn verification_method(
    principal: &str,
    leaf: &[u8],
) -> Result<VerificationMethod, auths_model::ModelError> {
    let digest: [u8; 32] = Sha256::digest(leaf).into();
    let value = Base64UrlUnpadded::encode_string(&digest);
    VerificationMethod::parse(&format!("{principal}#fulcio-{}", &value[..16]))
}
fn parse_principal(value: &str) -> Result<(IssuerUrl, Subject), SigstoreError> {
    let rest = value
        .strip_prefix("oidc-workload:")
        .ok_or(SigstoreError::PrincipalSyntax)?;
    let (a, b) = rest.split_once('#').ok_or(SigstoreError::PrincipalSyntax)?;
    if b.contains('#') {
        return Err(SigstoreError::PrincipalSyntax);
    }
    let issuer = pct(a)?;
    let subject = pct(b)?;
    if encode(issuer.as_bytes()) != a || encode(subject.as_bytes()) != b {
        return Err(SigstoreError::PrincipalSyntax);
    }
    Ok((
        IssuerUrl::parse(&issuer).map_err(|_| SigstoreError::PrincipalSyntax)?,
        Subject::parse(&subject).map_err(|_| SigstoreError::PrincipalSyntax)?,
    ))
}
fn pct(value: &str) -> Result<String, SigstoreError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            let pair = bytes
                .get(offset + 1..offset + 3)
                .ok_or(SigstoreError::PrincipalSyntax)?;
            decoded.push((hx(pair[0])? << 4) | hx(pair[1])?);
            offset += 3;
        } else {
            decoded.push(bytes[offset]);
            offset += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| SigstoreError::PrincipalSyntax)
}
fn hx(byte: u8) -> Result<u8, SigstoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SigstoreError::PrincipalSyntax),
    }
}
fn encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}
fn assurance_claims(
    admitted: &identity::AdmittedWorkload,
    entry: &RekorEntry,
    leaf: &auths_ports::VerifiedLeaf,
    path: &str,
    source: &EvidenceSourceId,
) -> Result<Vec<AssuranceClaim>, SigstoreError> {
    let (issuer, subject) = match &admitted.identity {
        identity::FulcioWorkloadIdentity::Generic(v) => (v.issuer.as_str(), v.subject.as_str()),
        identity::FulcioWorkloadIdentity::GithubActions(v) => {
            (v.issuer.as_str(), v.subject.as_str())
        }
    };
    let policy = Base64UrlUnpadded::encode_string(admitted.policy_digest.as_bytes());
    let leaf_digest = Base64UrlUnpadded::encode_string(&Sha256::digest(leaf.der().as_bytes()));
    let log = Base64UrlUnpadded::encode_string(entry.log.bytes());
    let root = Base64UrlUnpadded::encode_string(entry.checkpoint.root.as_bytes());
    Ok(vec![
        claim("oidc.issuer", vec![("issuer", issuer)], source)?,
        claim("oidc.subject", vec![("subject", subject)], source)?,
        claim("oidc.policy", vec![("policy_digest", &policy)], source)?,
        claim(
            "sigstore.certificate",
            vec![("leaf_digest", &leaf_digest), ("path_verifier", path)],
            source,
        )?,
        claim(
            "sigstore.transparency",
            vec![("log_id", &log), ("root_hash", &root)],
            source,
        )?,
    ])
}
fn claim(
    kind: &str,
    params: Vec<(&str, &str)>,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, SigstoreError> {
    AssuranceClaim::new(
        AssuranceClaimId::parse(kind).map_err(|_| SigstoreError::LimitExceeded)?,
        params
            .into_iter()
            .map(|(k, v)| Ok((ClaimParameterId::parse(k)?, ClaimParameterId::parse(v)?)))
            .collect::<Result<Vec<_>, auths_model::ModelError>>()
            .map_err(|_| SigstoreError::LimitExceeded)?,
        None,
        source.clone(),
    )
    .map_err(|_| SigstoreError::LimitExceeded)
}
fn map_error(e: SigstoreError) -> PrincipalControlError {
    match e {
        SigstoreError::PrincipalSyntax
        | SigstoreError::IssuerMismatch
        | SigstoreError::SubjectMismatch => PrincipalControlError::PrincipalMethodMismatch,
        SigstoreError::VerificationMethodMismatch => {
            PrincipalControlError::VerificationMethodMismatch
        }
        SigstoreError::MissingChain | SigstoreError::MissingEntry => {
            PrincipalControlError::MissingEvidence
        }
        SigstoreError::WorkloadSuiteMismatch => PrincipalControlError::SignatureSuiteMismatch,
        SigstoreError::SuiteContract
        | SigstoreError::Path(PathError::UnsupportedAlgorithm)
        | SigstoreError::UnboundKeyAlgorithm
        | SigstoreError::PathVerifierContract => PrincipalControlError::ExternalFactUnavailable,
        SigstoreError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}
