//! Pure SPIFFE X.509-SVID principal control for Auths target V1.
//!
//! Workload API acquisition remains outside the kernel. This method validates
//! bounded DER chains against verifier-local trust bundles, enforces the
//! SPIFFE URI SAN and client-auth EKU, derives the exact suite/key, and
//! optionally requires verifier-local revocation state.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, ClaimParameterId,
    EvidenceId, EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId,
    PrincipalMethodId, Timestamp, VerificationMethod,
};
use auths_ports::{
    AlgorithmBindingSet, CertificateDer as AuthsCertificateDer, CertificatePathVerifier,
    ControlEvidence, ExtendedKeyUsage, PathError, PathInput, PrincipalControlError,
    PrincipalControlInput, PrincipalMethod, TrustAnchorSet,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::{fmt, str};
use sha2::{Digest as _, Sha256};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

/// Exact target V1 principal-method and evidence identifier.
pub const SPIFFE_X509_V1: &str = "spiffe-x509-v1";
/// Exact X.509-SVID evidence media type.
pub const SPIFFE_X509_MEDIA_TYPE: &str = "application/vnd.auths.spiffe-x509-svid.v1";
/// SPIFFE principal prefix.
pub const PRINCIPAL_PREFIX: &str = "spiffe://";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-SPIFFE-X509\x00\x01";
const MAX_CHAIN_CERTIFICATES: usize = 8;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CHAIN_BYTES: usize = 32 * 1024;
const MAX_TRUST_DOMAINS: usize = 64;
const MAX_ROOTS: usize = 16;
const MAX_STATUS_RECORDS: usize = 512;

/// Verifier-local SPIFFE trust bundle and status policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusRequirement {
    Required,
    NotRequired,
}

/// Lifecycle state established for a leaf certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafStatus {
    Active,
    Revoked,
}

/// Verifier-local SPIFFE trust bundle and status policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiffeTrustDomain {
    name: String,
    roots: Vec<Vec<u8>>,
    anchors: TrustAnchorSet,
    status_requirement: StatusRequirement,
}

impl SpiffeTrustDomain {
    /// Constructs a bounded trust domain from DER trust anchors.
    ///
    /// # Errors
    ///
    /// Rejects malformed domains, empty/oversized or duplicate roots, and roots
    /// that cannot be interpreted as X.509 trust anchors.
    pub fn new(
        name: String,
        mut roots: Vec<Vec<u8>>,
        status_requirement: StatusRequirement,
    ) -> Result<Self, SpiffeError> {
        if !valid_trust_domain(&name) || roots.is_empty() || roots.len() > MAX_ROOTS {
            return Err(SpiffeError::InvalidTrustBundle);
        }
        roots.sort();
        if roots.windows(2).any(|window| window[0] == window[1]) {
            return Err(SpiffeError::InvalidTrustBundle);
        }
        let anchors = roots
            .iter()
            .cloned()
            .map(AuthsCertificateDer::new)
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .and_then(|anchors| TrustAnchorSet::new(anchors).ok())
            .ok_or(SpiffeError::InvalidTrustBundle)?;
        Ok(Self {
            name,
            roots,
            anchors,
            status_requirement,
        })
    }

    /// Returns the exact SPIFFE trust-domain name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the DER trust anchors.
    #[must_use]
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// Returns whether current leaf status is mandatory.
    #[must_use]
    pub const fn status_requirement(&self) -> StatusRequirement {
        self.status_requirement
    }
}

/// Verifier-local lifecycle observation for one leaf certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpiffeStatusRecord {
    leaf_digest: [u8; 32],
    status: LeafStatus,
    observed_at: Timestamp,
    valid_until: Timestamp,
}

impl SpiffeStatusRecord {
    /// Constructs a current or revoked leaf-certificate status fact.
    ///
    /// # Errors
    ///
    /// Rejects inverted observation windows.
    pub fn new(
        leaf_digest: [u8; 32],
        status: LeafStatus,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, SpiffeError> {
        if observed_at > valid_until {
            return Err(SpiffeError::InvalidStatus);
        }
        Ok(Self {
            leaf_digest,
            status,
            observed_at,
            valid_until,
        })
    }

    /// Returns the addressed leaf-certificate digest.
    #[must_use]
    pub const fn leaf_digest(&self) -> [u8; 32] {
        self.leaf_digest
    }

    /// Returns whether the leaf was active.
    #[must_use]
    pub const fn status(&self) -> LeafStatus {
        self.status
    }

    /// Returns when this status was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Returns the end of this status validity interval.
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }
}

/// Bounded DER leaf-plus-intermediates evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiffeX509Evidence {
    certificates: Vec<Vec<u8>>,
}

impl SpiffeX509Evidence {
    /// Constructs a leaf-first chain excluding verifier-local roots.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or excessive chain elements.
    pub fn new(certificates: Vec<Vec<u8>>) -> Result<Self, SpiffeError> {
        let total = certificates.iter().try_fold(0usize, |total, certificate| {
            total
                .checked_add(certificate.len())
                .ok_or(SpiffeError::LimitExceeded)
        })?;
        if certificates.is_empty()
            || certificates.len() > MAX_CHAIN_CERTIFICATES
            || total > MAX_CHAIN_BYTES
            || certificates.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES
            })
        {
            return Err(SpiffeError::LimitExceeded);
        }
        Ok(Self { certificates })
    }

    /// Encodes the unique leaf-first chain envelope.
    ///
    /// # Errors
    ///
    /// Returns a limit error if a bounded count or size cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, SpiffeError> {
        let count =
            u16::try_from(self.certificates.len()).map_err(|_| SpiffeError::LimitExceeded)?;
        let mut output = Vec::new();
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&count.to_be_bytes());
        for certificate in &self.certificates {
            let length =
                u32::try_from(certificate.len()).map_err(|_| SpiffeError::LimitExceeded)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(certificate);
        }
        Ok(output)
    }

    /// Decodes exact bounded chain evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, trailing bytes, and resource violations.
    pub fn decode(bytes: &[u8]) -> Result<Self, SpiffeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(EVIDENCE_DOMAIN.len())? != EVIDENCE_DOMAIN {
            return Err(SpiffeError::InvalidEvidence);
        }
        let count = usize::from(reader.u16()?);
        if count == 0 || count > MAX_CHAIN_CERTIFICATES {
            return Err(SpiffeError::LimitExceeded);
        }
        let mut certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(reader.u32()?).map_err(|_| SpiffeError::LimitExceeded)?;
            if length == 0 || length > MAX_CERTIFICATE_BYTES {
                return Err(SpiffeError::LimitExceeded);
            }
            certificates.push(reader.take(length)?.to_vec());
        }
        if !reader.finished() {
            return Err(SpiffeError::InvalidEvidence);
        }
        Self::new(certificates)
    }

    /// Returns the SHA-256 leaf certificate digest used by status records.
    #[must_use]
    pub fn leaf_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.certificates[0]).into()
    }
}

/// Pure SPIFFE X.509-SVID method.
pub struct SpiffeX509Method {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    trust_domains: Vec<SpiffeTrustDomain>,
    status: Vec<SpiffeStatusRecord>,
    path_verifier: Box<dyn CertificatePathVerifier>,
    key_bindings: AlgorithmBindingSet,
}

impl SpiffeX509Method {
    /// Constructs the method from verifier-local trust and status.
    ///
    /// # Errors
    ///
    /// Rejects duplicate/oversized trust domains or status sets.
    pub fn new(
        mut trust_domains: Vec<SpiffeTrustDomain>,
        mut status: Vec<SpiffeStatusRecord>,
        path_verifier: Box<dyn CertificatePathVerifier>,
        key_bindings: AlgorithmBindingSet,
    ) -> Result<Self, SpiffeError> {
        if trust_domains.len() > MAX_TRUST_DOMAINS || status.len() > MAX_STATUS_RECORDS {
            return Err(SpiffeError::LimitExceeded);
        }
        trust_domains.sort_by(|left, right| left.name.cmp(&right.name));
        if trust_domains
            .windows(2)
            .any(|window| window[0].name == window[1].name)
        {
            return Err(SpiffeError::InvalidTrustBundle);
        }
        status.sort_by_key(|record| record.leaf_digest);
        if status
            .windows(2)
            .any(|window| window[0].leaf_digest == window[1].leaf_digest)
        {
            return Err(SpiffeError::InvalidStatus);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(SPIFFE_X509_V1)?,
            evidence_type: EvidenceTypeId::parse(SPIFFE_X509_V1)?,
            media_type: MediaType::parse(SPIFFE_X509_MEDIA_TYPE)?,
            adapter: AdapterId::parse(SPIFFE_X509_V1)?,
            source: EvidenceSourceId::parse(SPIFFE_X509_V1)?,
            trust_domains,
            status,
            path_verifier,
            key_bindings,
        })
    }

    fn select_evidence<'a>(
        &self,
        evidence: &'a [&'a auths_model::EvidenceObject],
    ) -> Result<&'a auths_model::EvidenceObject, PrincipalControlError> {
        let mut selected = None;
        for item in evidence
            .iter()
            .copied()
            .filter(|item| item.evidence_type() == &self.evidence_type)
        {
            if selected.is_some() || item.media_type() != &self.media_type {
                return Err(PrincipalControlError::InvalidEvidence);
            }
            selected = Some(item);
        }
        selected.ok_or(PrincipalControlError::MissingEvidence)
    }
}

impl PrincipalMethod for SpiffeX509Method {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut components = Vec::new();
        for trust in &self.trust_domains {
            components.push(trust.name.as_bytes().to_vec());
            components.push(
                u64::try_from(trust.roots.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes()
                    .to_vec(),
            );
            for root in &trust.roots {
                components.push(root.clone());
            }
            components.push(vec![u8::from(matches!(
                trust.status_requirement,
                StatusRequirement::Required
            ))]);
        }
        for status in &self.status {
            components.push(status.leaf_digest.to_vec());
            components.push(vec![u8::from(matches!(status.status, LeafStatus::Active))]);
            components.push(status.observed_at.get().to_be_bytes().to_vec());
            components.push(status.valid_until.get().to_be_bytes().to_vec());
        }
        components.push(self.path_verifier.id().as_str().as_bytes().to_vec());
        components.push(self.path_verifier.configuration_id().as_bytes().to_vec());
        components.push(self.key_bindings.configuration_id().as_bytes().to_vec());
        auths_ports::configuration_id(
            SPIFFE_X509_V1.as_bytes(),
            components.iter().map(Vec::as_slice),
        )
    }

    fn maximum_work_units(&self) -> u64 {
        120_u64.saturating_add(
            self.path_verifier
                .maximum_work_units(MAX_CHAIN_CERTIFICATES),
        )
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        let trust_domain = spiffe_trust_domain(input.principal.as_str())
            .map_err(|_| PrincipalControlError::PrincipalMethodMismatch)?;
        let trust = self
            .trust_domains
            .iter()
            .find(|candidate| candidate.name == trust_domain)
            .ok_or(PrincipalControlError::ExternalFactUnavailable)?;
        let evidence = self.select_evidence(input.evidence)?;
        let chain = SpiffeX509Evidence::decode(evidence.bytes()).map_err(map_evidence_error)?;
        let certificates = chain
            .certificates
            .iter()
            .cloned()
            .map(AuthsCertificateDer::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_path_error)?;
        let verified = self
            .path_verifier
            .verify(PathInput {
                leaf: &certificates[0],
                intermediates: &certificates[1..],
                anchors: &trust.anchors,
                at: input.evaluation_time,
                required_eku: &ExtendedKeyUsage::client_auth(),
            })
            .map_err(map_path_error)?;
        let parsed = parse_leaf(&chain.certificates[0])
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if verified.der().as_bytes() != chain.certificates[0]
            || verified.spki() != parsed.spki.as_slice()
        {
            return Err(PrincipalControlError::ExternalFactUnavailable);
        }
        if parsed.principal != *input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        let selection = self
            .key_bindings
            .select_spki(verified.spki_algorithm())
            .ok_or(PrincipalControlError::ExternalFactUnavailable)?;
        if selection.suite() != input.signature_suite {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let public_key = verified
            .key_bytes(selection.key_form())
            .map_err(map_path_error)?;
        let method = svid_verification_method(input.principal, chain.leaf_digest())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if &method != input.verification_method {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        let status = self.status.iter().find(|status| {
            status.leaf_digest == chain.leaf_digest()
                && status.observed_at <= input.evaluation_time
                && input.evaluation_time <= status.valid_until
        });
        if status.is_some_and(|status| matches!(status.status, LeafStatus::Revoked)) {
            return Err(PrincipalControlError::PrincipalRevoked);
        }
        if matches!(trust.status_requirement, StatusRequirement::Required) && status.is_none() {
            return Err(PrincipalControlError::ExternalFactUnavailable);
        }
        let mut claims = vec![
            claim(
                "pki-chain-validated",
                vec![("trust-domain", trust.name.as_str())],
                Some(input.evaluation_time),
                &self.source,
            )?,
            claim(
                "workload-attested",
                vec![("trust-domain", trust.name.as_str())],
                Some(input.evaluation_time),
                &self.source,
            )?,
        ];
        if let Some(status) = status {
            claims.push(claim(
                "controller-state-current-at",
                Vec::new(),
                Some(status.observed_at),
                &self.source,
            )?);
            claims.push(claim(
                "revocation-checked-at",
                Vec::new(),
                Some(status.observed_at),
                &self.source,
            )?);
        }
        ControlEvidence::new(
            public_key,
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            120,
        )
    }
}

struct ParsedLeaf {
    principal: PrincipalId,
    spki: Vec<u8>,
}

fn parse_leaf(der: &[u8]) -> Result<ParsedLeaf, SpiffeError> {
    let (remainder, certificate) =
        parse_x509_certificate(der).map_err(|_| SpiffeError::InvalidCertificate)?;
    if !remainder.is_empty() {
        return Err(SpiffeError::InvalidCertificate);
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| SpiffeError::InvalidCertificate)?
        .ok_or(SpiffeError::InvalidCertificate)?;
    if san.value.general_names.len() != 1 {
        return Err(SpiffeError::InvalidCertificate);
    }
    let GeneralName::URI(uri) = &san.value.general_names[0] else {
        return Err(SpiffeError::InvalidCertificate);
    };
    spiffe_trust_domain(uri)?;
    let principal = PrincipalId::parse(uri)?;
    let eku = certificate
        .extended_key_usage()
        .map_err(|_| SpiffeError::InvalidCertificate)?
        .ok_or(SpiffeError::InvalidCertificate)?;
    if !eku.value.client_auth {
        return Err(SpiffeError::InvalidCertificate);
    }
    Ok(ParsedLeaf {
        principal,
        spki: certificate.public_key().raw.to_vec(),
    })
}

fn map_path_error(error: PathError) -> PrincipalControlError {
    match error {
        PathError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        PathError::UnsupportedAlgorithm
        | PathError::UnsupportedKeyForm
        | PathError::UntrustedAnchor => PrincipalControlError::ExternalFactUnavailable,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

/// Derives the leaf-specific verification method.
///
/// # Errors
///
/// Returns a model error if the method cannot be represented.
pub fn svid_verification_method(
    principal: &PrincipalId,
    leaf_digest: [u8; 32],
) -> Result<VerificationMethod, ModelError> {
    let digest = Base64UrlUnpadded::encode_string(&leaf_digest);
    VerificationMethod::parse(&format!("{}#svid-{}", principal.as_str(), &digest[..16]))
}

fn spiffe_trust_domain(principal: &str) -> Result<&str, SpiffeError> {
    let remainder = principal
        .strip_prefix(PRINCIPAL_PREFIX)
        .ok_or(SpiffeError::InvalidSpiffeId)?;
    let (domain, path) = remainder
        .split_once('/')
        .ok_or(SpiffeError::InvalidSpiffeId)?;
    if !valid_trust_domain(domain)
        || path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/'))
        })
    {
        return Err(SpiffeError::InvalidSpiffeId);
    }
    Ok(domain)
}

fn valid_trust_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn claim(
    identifier: &str,
    parameters: Vec<(&str, &str)>,
    observed_at: Option<Timestamp>,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, PrincipalControlError> {
    let parameters = parameters
        .into_iter()
        .map(|(key, value)| {
            Ok((
                ClaimParameterId::parse(key).map_err(|_| PrincipalControlError::InvalidEvidence)?,
                ClaimParameterId::parse(value)
                    .map_err(|_| PrincipalControlError::InvalidEvidence)?,
            ))
        })
        .collect::<Result<Vec<_>, PrincipalControlError>>()?;
    AssuranceClaim::new(
        AssuranceClaimId::parse(identifier).map_err(|_| PrincipalControlError::InvalidEvidence)?,
        parameters,
        observed_at,
        source.clone(),
    )
    .map_err(|_| PrincipalControlError::InvalidEvidence)
}

fn map_evidence_error(error: SpiffeError) -> PrincipalControlError {
    match error {
        SpiffeError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SpiffeError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SpiffeError::InvalidEvidence)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SpiffeError::InvalidEvidence)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, SpiffeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, SpiffeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

/// SPIFFE/X.509 trust, chain, or profile error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpiffeError {
    /// A target model identifier is invalid.
    Model(ModelError),
    /// The SPIFFE identifier is outside the closed grammar.
    InvalidSpiffeId,
    /// A verifier-local trust bundle is invalid.
    InvalidTrustBundle,
    /// Chain evidence framing is invalid.
    InvalidEvidence,
    /// A certificate is malformed or outside the SVID profile.
    InvalidCertificate,
    /// A lifecycle status fact is malformed.
    InvalidStatus,
    /// A target bound was exceeded.
    LimitExceeded,
}

impl From<ModelError> for SpiffeError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for SpiffeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid Auths model value: {error}"),
            Self::InvalidSpiffeId => formatter.write_str("invalid SPIFFE ID"),
            Self::InvalidTrustBundle => formatter.write_str("invalid SPIFFE trust bundle"),
            Self::InvalidEvidence => formatter.write_str("invalid X.509-SVID evidence"),
            Self::InvalidCertificate => formatter.write_str("invalid X.509-SVID certificate"),
            Self::InvalidStatus => formatter.write_str("invalid X.509-SVID status"),
            Self::LimitExceeded => formatter.write_str("X.509-SVID resource limit exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpiffeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId};
    use auths_path_webpki::WebPkiPathVerifier;
    use auths_ports::{
        AlgorithmBinding, AlgorithmIdentifierDer, ControlPurpose, KeyForm, PrincipalControlInput,
        SignatureSuite,
    };
    use auths_signature::{Ed25519Suite, P256Sha256Suite};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    fn trust_anchor(serial: u64) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params.serial_number = Some(serial.into());
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    fn spiffe_method(
        trust: Vec<SpiffeTrustDomain>,
        status: Vec<SpiffeStatusRecord>,
    ) -> SpiffeX509Method {
        let ed25519 = Ed25519Suite::new().unwrap();
        let p256 = P256Sha256Suite::new().unwrap();
        let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
        let bindings = AlgorithmBindingSet::new(
            vec![
                AlgorithmBinding::Spki {
                    algorithm: AlgorithmIdentifierDer::new(vec![
                        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                    ])
                    .unwrap(),
                    suite: ed25519.id().clone(),
                    key_form: KeyForm::BitStringContents,
                },
                AlgorithmBinding::Spki {
                    algorithm: AlgorithmIdentifierDer::new(vec![
                        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                    ])
                    .unwrap(),
                    suite: p256.id().clone(),
                    key_form: KeyForm::Sec1Compressed,
                },
            ],
            &suites,
        )
        .unwrap();
        SpiffeX509Method::new(trust, status, Box::new(WebPkiPathVerifier::new()), bindings).unwrap()
    }

    #[test]
    fn trust_roots_are_canonical_and_configuration_bound() {
        let first = trust_anchor(1);
        let second = trust_anchor(2);
        let forward = SpiffeTrustDomain::new(
            "auths.example".to_string(),
            vec![first.clone(), second.clone()],
            StatusRequirement::NotRequired,
        )
        .unwrap();
        let reverse = SpiffeTrustDomain::new(
            "auths.example".to_string(),
            vec![second.clone(), first.clone()],
            StatusRequirement::NotRequired,
        )
        .unwrap();
        assert_eq!(forward.roots(), reverse.roots());

        let forward_id = spiffe_method(vec![forward], Vec::new()).configuration_id();
        let reverse_id = spiffe_method(vec![reverse], Vec::new()).configuration_id();
        assert_eq!(forward_id, reverse_id);

        let changed_id = spiffe_method(
            vec![
                SpiffeTrustDomain::new(
                    "auths.example".to_string(),
                    vec![first],
                    StatusRequirement::NotRequired,
                )
                .unwrap(),
            ],
            Vec::new(),
        )
        .configuration_id();
        assert_ne!(forward_id, changed_id);

        assert_eq!(
            SpiffeTrustDomain::new(
                "auths.example".to_string(),
                vec![second.clone(), second],
                StatusRequirement::NotRequired,
            ),
            Err(SpiffeError::InvalidTrustBundle)
        );
    }

    #[test]
    fn validates_path_spiffe_san_eku_and_status() {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.subject_alt_names = vec![SanType::URI(
            "spiffe://auths.example/workload/reporter"
                .try_into()
                .unwrap(),
        )];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let evidence = SpiffeX509Evidence::new(vec![leaf.der().to_vec()]).unwrap();
        let digest = evidence.leaf_digest();
        let trust = SpiffeTrustDomain::new(
            "auths.example".to_string(),
            vec![ca.der().to_vec()],
            StatusRequirement::Required,
        )
        .unwrap();
        let status = SpiffeStatusRecord::new(
            digest,
            LeafStatus::Active,
            Timestamp::new(1_700_000_000),
            Timestamp::new(1_800_000_000),
        )
        .unwrap();
        let principal = PrincipalId::parse("spiffe://auths.example/workload/reporter").unwrap();
        let method_id = svid_verification_method(&principal, digest).unwrap();
        let object = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(SPIFFE_X509_V1).unwrap(),
            MediaType::parse(SPIFFE_X509_MEDIA_TYPE).unwrap(),
            evidence.encode().unwrap(),
        )
        .unwrap();
        let refs = [&object];
        let method = spiffe_method(vec![trust.clone()], vec![status]);
        let control = method
            .verify_control(PrincipalControlInput {
                principal: &principal,
                verification_method: &method_id,
                signature_suite: &SignatureSuiteId::parse("p256-sha256-v1").unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"exact Auths preimage",
                signature: b"test signature",
                asserted_signing_time: Timestamp::new(1_700_000_000),
                evidence: &refs,
                evaluation_time: Timestamp::new(1_700_000_000),
            })
            .unwrap();
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "pki-chain-validated")
        );

        let revoked = SpiffeStatusRecord::new(
            digest,
            LeafStatus::Revoked,
            Timestamp::new(1_700_000_000),
            Timestamp::new(1_800_000_000),
        )
        .unwrap();
        let revoked_method = spiffe_method(vec![trust], vec![revoked]);
        let error = revoked_method
            .verify_control(PrincipalControlInput {
                principal: &principal,
                verification_method: &method_id,
                signature_suite: &SignatureSuiteId::parse("p256-sha256-v1").unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"exact Auths preimage",
                signature: b"test signature",
                asserted_signing_time: Timestamp::new(1_700_000_000),
                evidence: &refs,
                evaluation_time: Timestamp::new(1_700_000_000),
            })
            .unwrap_err();
        assert_eq!(error, PrincipalControlError::PrincipalRevoked);
    }
}
