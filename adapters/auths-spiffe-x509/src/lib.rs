//! Pure SPIFFE X.509-SVID principal control for Auths target V1.
//!
//! Workload API acquisition remains outside the kernel. This method validates
//! bounded DER chains against verifier-local trust bundles, enforces the
//! SPIFFE URI SAN and client-auth EKU, derives the exact suite/key, and
//! optionally requires verifier-local revocation state.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, ClaimParameterId,
    EvidenceId, EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId,
    PrincipalMethodId, Timestamp, VerificationMethod,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::{fmt, str, time::Duration};
use p256::ecdsa::VerifyingKey as P256Key;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest as _, Sha256};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

/// Exact target V1 principal-method and evidence identifier.
pub const SPIFFE_X509_V1: &str = "spiffe-x509-v1";
/// Exact X.509-SVID evidence media type.
pub const SPIFFE_X509_MEDIA_TYPE: &str = "application/vnd.auths.spiffe-x509-svid.v1";
/// SPIFFE principal prefix.
pub const PRINCIPAL_PREFIX: &str = "spiffe://";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-SPIFFE-X509\x00\x01";
const ED25519_SUITE: &str = "ed25519-v1";
const P256_SUITE: &str = "p256-sha256-v1";
const MAX_CHAIN_CERTIFICATES: usize = 8;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CHAIN_BYTES: usize = 32 * 1024;
const MAX_TRUST_DOMAINS: usize = 64;
const MAX_ROOTS: usize = 16;
const MAX_STATUS_RECORDS: usize = 512;

/// Verifier-local SPIFFE trust bundle and status policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiffeTrustDomain {
    name: String,
    roots: Vec<Vec<u8>>,
    require_status: bool,
}

impl SpiffeTrustDomain {
    /// Constructs a bounded trust domain from DER trust anchors.
    ///
    /// # Errors
    ///
    /// Rejects malformed domains, empty/oversized roots, and roots that cannot
    /// be interpreted as X.509 trust anchors.
    pub fn new(
        name: String,
        roots: Vec<Vec<u8>>,
        require_status: bool,
    ) -> Result<Self, SpiffeError> {
        if !valid_trust_domain(&name)
            || roots.is_empty()
            || roots.len() > MAX_ROOTS
            || roots.iter().any(|root| {
                root.is_empty()
                    || root.len() > MAX_CERTIFICATE_BYTES
                    || webpki::anchor_from_trusted_cert(&CertificateDer::from(root.as_slice()))
                        .is_err()
            })
        {
            return Err(SpiffeError::InvalidTrustBundle);
        }
        Ok(Self {
            name,
            roots,
            require_status,
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
    pub const fn requires_status(&self) -> bool {
        self.require_status
    }
}

/// Verifier-local lifecycle observation for one leaf certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpiffeStatusRecord {
    leaf_digest: [u8; 32],
    active: bool,
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
        active: bool,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, SpiffeError> {
        if observed_at > valid_until {
            return Err(SpiffeError::InvalidStatus);
        }
        Ok(Self {
            leaf_digest,
            active,
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
    pub const fn is_active(&self) -> bool {
        self.active
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
        })
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
            components.push(vec![u8::from(trust.require_status)]);
        }
        for status in &self.status {
            components.push(status.leaf_digest.to_vec());
            components.push(vec![u8::from(status.active)]);
            components.push(status.observed_at.get().to_be_bytes().to_vec());
            components.push(status.valid_until.get().to_be_bytes().to_vec());
        }
        auths_ports::configuration_id(
            SPIFFE_X509_V1.as_bytes(),
            components.iter().map(Vec::as_slice),
        )
    }

    fn maximum_work_units(&self) -> u64 {
        120
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
        let mut selected = None;
        for evidence in input.evidence {
            if evidence.evidence_type() == &self.evidence_type {
                if selected.is_some() || evidence.media_type() != &self.media_type {
                    return Err(PrincipalControlError::InvalidEvidence);
                }
                selected = Some(*evidence);
            }
        }
        let evidence = selected.ok_or(PrincipalControlError::MissingEvidence)?;
        let chain = SpiffeX509Evidence::decode(evidence.bytes()).map_err(map_evidence_error)?;
        verify_path(&chain, trust, input.evaluation_time)
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        let parsed = parse_leaf(&chain.certificates[0])
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if parsed.principal != *input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        if parsed.suite.as_str() != input.signature_suite.as_str() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
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
        if status.is_some_and(|status| !status.active) {
            return Err(PrincipalControlError::PrincipalRevoked);
        }
        if trust.require_status && status.is_none() {
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
            parsed.public_key,
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            120,
        )
    }
}

fn verify_path(
    chain: &SpiffeX509Evidence,
    trust: &SpiffeTrustDomain,
    evaluation_time: Timestamp,
) -> Result<(), SpiffeError> {
    let leaf_der = CertificateDer::from(chain.certificates[0].as_slice());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| SpiffeError::InvalidChain)?;
    let intermediates: Vec<_> = chain.certificates[1..]
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let root_der: Vec<_> = trust
        .roots
        .iter()
        .map(|root| CertificateDer::from(root.as_slice()))
        .collect();
    let anchors = root_der
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SpiffeError::InvalidTrustBundle)?;
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(evaluation_time.get())),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|_| SpiffeError::InvalidChain)?;
    Ok(())
}

struct ParsedLeaf {
    principal: PrincipalId,
    suite: auths_model::SignatureSuiteId,
    public_key: Vec<u8>,
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
    let subject_key = certificate.public_key();
    let algorithm = subject_key.algorithm.algorithm.to_id_string();
    let key = subject_key.subject_public_key.data.as_ref();
    let (suite, public_key) = match algorithm.as_str() {
        "1.3.101.112" if key.len() == 32 => (
            auths_model::SignatureSuiteId::parse(ED25519_SUITE)?,
            key.to_vec(),
        ),
        "1.2.840.10045.2.1" => {
            let key = P256Key::from_sec1_bytes(key).map_err(|_| SpiffeError::InvalidCertificate)?;
            (
                auths_model::SignatureSuiteId::parse(P256_SUITE)?,
                key.to_encoded_point(true).as_bytes().to_vec(),
            )
        }
        _ => return Err(SpiffeError::UnsupportedKey),
    };
    Ok(ParsedLeaf {
        principal,
        suite,
        public_key,
    })
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
    /// Path building, validity, constraints, or EKU verification failed.
    InvalidChain,
    /// The leaf public-key algorithm is unsupported.
    UnsupportedKey,
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
            Self::InvalidChain => formatter.write_str("invalid X.509-SVID path"),
            Self::UnsupportedKey => formatter.write_str("unsupported X.509-SVID key"),
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
    use auths_ports::{ControlPurpose, PrincipalControlInput};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

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
        let trust =
            SpiffeTrustDomain::new("auths.example".to_string(), vec![ca.der().to_vec()], true)
                .unwrap();
        let status = SpiffeStatusRecord::new(
            digest,
            true,
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
        let method = SpiffeX509Method::new(vec![trust.clone()], vec![status]).unwrap();
        let control = method
            .verify_control(PrincipalControlInput {
                principal: &principal,
                verification_method: &method_id,
                signature_suite: &SignatureSuiteId::parse(P256_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"exact Auths preimage",
                asserted_signing_time: Timestamp::new(1_700_000_000),
                evidence: &refs,
                evaluation_time: Timestamp::new(1_700_000_000),
            })
            .unwrap();
        assert!(control
            .claims()
            .iter()
            .any(|claim| claim.kind().as_str() == "pki-chain-validated"));

        let revoked = SpiffeStatusRecord::new(
            digest,
            false,
            Timestamp::new(1_700_000_000),
            Timestamp::new(1_800_000_000),
        )
        .unwrap();
        let revoked_method = SpiffeX509Method::new(vec![trust], vec![revoked]).unwrap();
        let error = revoked_method
            .verify_control(PrincipalControlInput {
                principal: &principal,
                verification_method: &method_id,
                signature_suite: &SignatureSuiteId::parse(P256_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"exact Auths preimage",
                asserted_signing_time: Timestamp::new(1_700_000_000),
                evidence: &refs,
                evaluation_time: Timestamp::new(1_700_000_000),
            })
            .unwrap_err();
        assert_eq!(error, PrincipalControlError::PrincipalRevoked);
    }
}
