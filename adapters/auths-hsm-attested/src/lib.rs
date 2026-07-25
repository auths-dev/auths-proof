//! Pure HSM-attested principal control for Auths target V1.
//!
//! Provider APIs and device-certificate acquisition remain outside the
//! kernel. Verifier-local records pin their reviewed attestation result;
//! canonical evidence binds that record and the exact Auths transaction.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use auths_model::{
    AdapterId, AssuranceClaim, AssuranceClaimId, ClaimParameterId, EvidenceId, EvidenceSourceId,
    EvidenceTypeId, MediaType, ModelError, PrincipalId, PrincipalMethodId, SignatureSuiteId,
    Timestamp, VerificationMethod,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::{fmt, str};
use ed25519_dalek::VerifyingKey as Ed25519Key;
use p256::ecdsa::VerifyingKey as P256Key;
use sha2::{Digest as _, Sha256};

/// Exact target V1 principal-method and evidence identifier.
pub const HSM_ATTESTED_V1: &str = "hsm-attested-v1";
/// Exact attestation evidence media type.
pub const HSM_ATTESTED_MEDIA_TYPE: &str = "application/vnd.auths.hsm-attested.v1";
/// Canonical HSM principal prefix.
pub const PRINCIPAL_PREFIX: &str = "hsm:";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-HSM-ATTESTED\x00\x01";
const PRINCIPAL_DOMAIN: &[u8] = b"AUTHS-HSM-PRINCIPAL\x00\x01";
const ED25519_SUITE: &str = "ed25519-v1";
const P256_SUITE: &str = "p256-sha256-v1";
const MAX_RECORDS: usize = 256;
const MAX_TEXT: usize = 128;

/// Verifier-local result of one reviewed HSM attestation profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsmKeyRecord {
    principal: PrincipalId,
    verification_method: VerificationMethod,
    suite: SignatureSuiteId,
    public_key: Vec<u8>,
    profile: String,
    provider: String,
    protection_level: String,
    key_handle_digest: [u8; 32],
    device_chain_digest: [u8; 32],
    non_exportable: bool,
    observed_at: Timestamp,
    valid_until: Timestamp,
}

impl HsmKeyRecord {
    /// Constructs a validated, immutable attestation result.
    ///
    /// # Errors
    ///
    /// Rejects unknown suites, invalid public keys, malformed labels, and
    /// inverted validity windows.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite: SignatureSuiteId,
        public_key: Vec<u8>,
        profile: String,
        provider: String,
        protection_level: String,
        key_handle_digest: [u8; 32],
        device_chain_digest: [u8; 32],
        non_exportable: bool,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, HsmError> {
        validate_key(&suite, &public_key)?;
        if !valid_text(&profile)
            || !valid_text(&provider)
            || !valid_text(&protection_level)
            || observed_at > valid_until
        {
            return Err(HsmError::InvalidRecord);
        }
        let mut hasher = Sha256::new();
        hasher.update(PRINCIPAL_DOMAIN);
        hasher.update(suite.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(&public_key);
        hasher.update(key_handle_digest);
        let digest = Base64UrlUnpadded::encode_string(&hasher.finalize());
        let principal = PrincipalId::parse(&format!("{PRINCIPAL_PREFIX}{digest}"))?;
        let verification_method =
            VerificationMethod::parse(&format!("{}#key", principal.as_str()))?;
        Ok(Self {
            principal,
            verification_method,
            suite,
            public_key,
            profile,
            provider,
            protection_level,
            key_handle_digest,
            device_chain_digest,
            non_exportable,
            observed_at,
            valid_until,
        })
    }

    /// Returns the attested principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns its exact verification method.
    #[must_use]
    pub const fn verification_method(&self) -> &VerificationMethod {
        &self.verification_method
    }

    /// Returns the exact signature suite.
    #[must_use]
    pub const fn suite(&self) -> &SignatureSuiteId {
        &self.suite
    }

    /// Returns the registered verification key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the attestation profile.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the attestation provider.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the protection-level label.
    #[must_use]
    pub fn protection_level(&self) -> &str {
        &self.protection_level
    }

    /// Returns the key-handle digest.
    #[must_use]
    pub const fn key_handle_digest(&self) -> [u8; 32] {
        self.key_handle_digest
    }

    /// Returns the device-chain digest.
    #[must_use]
    pub const fn device_chain_digest(&self) -> [u8; 32] {
        self.device_chain_digest
    }

    /// Returns whether the key was observed as non-exportable.
    #[must_use]
    pub const fn non_exportable(&self) -> bool {
        self.non_exportable
    }

    /// Returns when the attestation was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Returns the end of the attestation validity interval.
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }
}

/// Canonical proof binding an attested key record to one Auths transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsmAttestationEvidence {
    profile: String,
    provider: String,
    protection_level: String,
    key_handle_digest: [u8; 32],
    device_chain_digest: [u8; 32],
    non_exportable: bool,
    transaction_digest: [u8; 32],
}

impl HsmAttestationEvidence {
    /// Creates evidence for one local record and exact Auths preimage.
    #[must_use]
    pub fn for_record(record: &HsmKeyRecord, signing_preimage: &[u8]) -> Self {
        Self {
            profile: record.profile.clone(),
            provider: record.provider.clone(),
            protection_level: record.protection_level.clone(),
            key_handle_digest: record.key_handle_digest,
            device_chain_digest: record.device_chain_digest,
            non_exportable: record.non_exportable,
            transaction_digest: Sha256::digest(signing_preimage).into(),
        }
    }

    /// Encodes the unique bounded evidence contract.
    ///
    /// # Errors
    ///
    /// Returns a limit error if a bounded string cannot be framed.
    pub fn encode(&self) -> Result<Vec<u8>, HsmError> {
        let mut output = Vec::new();
        output.extend_from_slice(EVIDENCE_DOMAIN);
        write_text(&mut output, &self.profile)?;
        write_text(&mut output, &self.provider)?;
        write_text(&mut output, &self.protection_level)?;
        output.extend_from_slice(&self.key_handle_digest);
        output.extend_from_slice(&self.device_chain_digest);
        output.push(u8::from(self.non_exportable));
        output.extend_from_slice(&self.transaction_digest);
        Ok(output)
    }

    /// Decodes exact bounded evidence bytes.
    ///
    /// # Errors
    ///
    /// Rejects wrong domains, malformed text, invalid booleans, truncation,
    /// and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HsmError> {
        let mut reader = Reader::new(bytes);
        if reader.take(EVIDENCE_DOMAIN.len())? != EVIDENCE_DOMAIN {
            return Err(HsmError::InvalidEvidence);
        }
        let profile = reader.text()?;
        let provider = reader.text()?;
        let protection_level = reader.text()?;
        let key_handle_digest = reader.array()?;
        let device_chain_digest = reader.array()?;
        let non_exportable = match reader.byte()? {
            0 => false,
            1 => true,
            _ => return Err(HsmError::InvalidEvidence),
        };
        let transaction_digest = reader.array()?;
        if !reader.finished() {
            return Err(HsmError::InvalidEvidence);
        }
        Ok(Self {
            profile,
            provider,
            protection_level,
            key_handle_digest,
            device_chain_digest,
            non_exportable,
            transaction_digest,
        })
    }
}

/// Pure HSM attestation principal method.
pub struct HsmAttestedMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    records: Vec<HsmKeyRecord>,
}

impl HsmAttestedMethod {
    /// Constructs a method from verifier-local attestation results.
    ///
    /// # Errors
    ///
    /// Rejects oversized or duplicate record sets.
    pub fn new(mut records: Vec<HsmKeyRecord>) -> Result<Self, HsmError> {
        if records.len() > MAX_RECORDS {
            return Err(HsmError::LimitExceeded);
        }
        records.sort_by(|left, right| left.principal.cmp(&right.principal));
        if records
            .windows(2)
            .any(|window| window[0].principal == window[1].principal)
        {
            return Err(HsmError::InvalidRecord);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(HSM_ATTESTED_V1)?,
            evidence_type: EvidenceTypeId::parse(HSM_ATTESTED_V1)?,
            media_type: MediaType::parse(HSM_ATTESTED_MEDIA_TYPE)?,
            adapter: AdapterId::parse(HSM_ATTESTED_V1)?,
            source: EvidenceSourceId::parse(HSM_ATTESTED_V1)?,
            records,
        })
    }
}

impl PrincipalMethod for HsmAttestedMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn maximum_work_units(&self) -> u64 {
        55
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        if !input.principal.as_str().starts_with(PRINCIPAL_PREFIX) {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        let record = self
            .records
            .iter()
            .find(|record| record.principal == *input.principal)
            .ok_or(PrincipalControlError::ExternalFactUnavailable)?;
        if &record.verification_method != input.verification_method {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        if &record.suite != input.signature_suite {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        if input.evaluation_time < record.observed_at || input.evaluation_time > record.valid_until
        {
            return Err(PrincipalControlError::ExternalFactUnavailable);
        }
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
        let attestation =
            HsmAttestationEvidence::decode(evidence.bytes()).map_err(map_evidence_error)?;
        if attestation.profile != record.profile
            || attestation.provider != record.provider
            || attestation.protection_level != record.protection_level
            || attestation.key_handle_digest != record.key_handle_digest
            || attestation.device_chain_digest != record.device_chain_digest
            || attestation.non_exportable != record.non_exportable
            || attestation.transaction_digest
                != <[u8; 32]>::from(Sha256::digest(input.signing_preimage))
        {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        let mut parameters = vec![
            ("profile", record.profile.as_str()),
            ("provider", record.provider.as_str()),
            ("level", record.protection_level.as_str()),
        ];
        if record.non_exportable {
            parameters.push(("exportability", "non-exportable"));
        }
        let claims = vec![
            claim(
                "hardware-attested",
                parameters,
                Some(record.observed_at),
                &self.source,
            )?,
            claim(
                "controller-state-current-at",
                Vec::new(),
                Some(record.observed_at),
                &self.source,
            )?,
            claim(
                "revocation-checked-at",
                Vec::new(),
                Some(record.observed_at),
                &self.source,
            )?,
            claim("offline-verifiable", Vec::new(), None, &self.source)?,
        ];
        ControlEvidence::new(
            record.public_key.clone(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            55,
        )
    }
}

fn validate_key(suite: &SignatureSuiteId, public_key: &[u8]) -> Result<(), HsmError> {
    match suite.as_str() {
        ED25519_SUITE => {
            let bytes: [u8; 32] = public_key.try_into().map_err(|_| HsmError::InvalidRecord)?;
            Ed25519Key::from_bytes(&bytes).map_err(|_| HsmError::InvalidRecord)?;
        }
        P256_SUITE => {
            P256Key::from_sec1_bytes(public_key).map_err(|_| HsmError::InvalidRecord)?;
            if public_key.len() != 33 {
                return Err(HsmError::InvalidRecord);
            }
        }
        _ => return Err(HsmError::UnsupportedSuite),
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn write_text(output: &mut Vec<u8>, value: &str) -> Result<(), HsmError> {
    if !valid_text(value) {
        return Err(HsmError::InvalidEvidence);
    }
    let length = u8::try_from(value.len()).map_err(|_| HsmError::LimitExceeded)?;
    output.push(length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
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

fn map_evidence_error(error: HsmError) -> PrincipalControlError {
    match error {
        HsmError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], HsmError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(HsmError::InvalidEvidence)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(HsmError::InvalidEvidence)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, HsmError> {
        Ok(self.take(1)?[0])
    }

    fn text(&mut self) -> Result<String, HsmError> {
        let length = usize::from(self.byte()?);
        let value = str::from_utf8(self.take(length)?).map_err(|_| HsmError::InvalidEvidence)?;
        if !valid_text(value) {
            return Err(HsmError::InvalidEvidence);
        }
        Ok(value.to_string())
    }

    fn array(&mut self) -> Result<[u8; 32], HsmError> {
        self.take(32)?
            .try_into()
            .map_err(|_| HsmError::InvalidEvidence)
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

/// HSM record or evidence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsmError {
    /// A target model identifier is invalid.
    Model(ModelError),
    /// A local attestation record is invalid.
    InvalidRecord,
    /// The evidence contract is malformed or contradictory.
    InvalidEvidence,
    /// The selected suite is outside the target HSM profile.
    UnsupportedSuite,
    /// A target bound was exceeded.
    LimitExceeded,
}

impl From<ModelError> for HsmError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for HsmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid Auths model value: {error}"),
            Self::InvalidRecord => formatter.write_str("invalid HSM attestation record"),
            Self::InvalidEvidence => formatter.write_str("invalid HSM attestation evidence"),
            Self::UnsupportedSuite => formatter.write_str("unsupported HSM signature suite"),
            Self::LimitExceeded => formatter.write_str("HSM evidence resource limit exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HsmError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{Digest, EvidenceObject};
    use auths_ports::{ControlPurpose, PrincipalControlInput};
    use ed25519_dalek::SigningKey;

    #[test]
    fn attestation_and_transaction_are_both_bound() {
        let key = SigningKey::from_bytes(&[51; 32]);
        let record = HsmKeyRecord::new(
            SignatureSuiteId::parse(ED25519_SUITE).unwrap(),
            key.verifying_key().to_bytes().to_vec(),
            "pkcs11-v1".to_string(),
            "example-hsm".to_string(),
            "fips-140-3-level-3".to_string(),
            [1; 32],
            [2; 32],
            true,
            Timestamp::new(10),
            Timestamp::new(30),
        )
        .unwrap();
        let preimage = b"exact Auths transaction";
        let evidence = HsmAttestationEvidence::for_record(&record, preimage);
        let object = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(HSM_ATTESTED_V1).unwrap(),
            MediaType::parse(HSM_ATTESTED_MEDIA_TYPE).unwrap(),
            evidence.encode().unwrap(),
        )
        .unwrap();
        let refs = [&object];
        let method = HsmAttestedMethod::new(vec![record.clone()]).unwrap();
        let control = method
            .verify_control(PrincipalControlInput {
                principal: record.principal(),
                verification_method: record.verification_method(),
                signature_suite: &SignatureSuiteId::parse(ED25519_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: preimage,
                asserted_signing_time: Timestamp::new(20),
                evidence: &refs,
                evaluation_time: Timestamp::new(20),
            })
            .unwrap();
        assert!(control
            .claims()
            .iter()
            .any(|claim| claim.kind().as_str() == "hardware-attested"));

        let error = method
            .verify_control(PrincipalControlInput {
                principal: record.principal(),
                verification_method: record.verification_method(),
                signature_suite: &SignatureSuiteId::parse(ED25519_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"a different Auths transaction",
                asserted_signing_time: Timestamp::new(20),
                evidence: &refs,
                evaluation_time: Timestamp::new(20),
            })
            .unwrap_err();
        assert_eq!(error, PrincipalControlError::InvalidEvidence);
    }
}
