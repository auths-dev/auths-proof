//! The authenticated operator: a signed statement naming the installation's
//! operator principal.
//!
//! A production installation names its operator only through a signed
//! `auths.gateway-operator-attestation/1` statement, canonical under
//! RFC 8785. The signing preimage is the schema, a NUL byte, and the
//! canonical statement. It starts with lowercase `auths.`, and every core
//! signing preimage starts with `AUTHS`, so the two can never be equal.
//!
//! Verification is the kernel's way of verifying a signed object: the
//! registered principal method the statement names establishes the key from
//! the attached control evidence with purpose `Assertion`, and the named
//! suite verifies the signature. An authenticated operator holds the key it
//! names; separation of persons is a separate gate.

use auths_model::{
    EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, PrincipalId, PrincipalMethodId,
    SignatureSuiteId, Timestamp, VerificationMethod,
};
use auths_ports::{
    ControlPurpose, PrincipalControlInput, PrincipalMethod, SignatureInput, SignatureSuite,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The statement's schema and the preimage's domain.
pub const OPERATOR_ATTESTATION_SCHEMA: &str = "auths.gateway-operator-attestation/1";
/// The largest attestation file accepted.
pub const MAX_OPERATOR_ATTESTATION_BYTES: usize = 16 * 1024;
/// The most control-evidence objects an attestation carries.
pub const MAX_OPERATOR_EVIDENCE: usize = 4;
/// How far ahead of the gateway clock the asserted signing time may be.
pub const MAX_ISSUED_AHEAD_SECONDS: u64 = 300;

/// Why an operator attestation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum OperatorAttestationError {
    /// The file is oversized, malformed, or not canonical.
    #[error("the operator attestation is malformed")]
    Malformed,
    /// The statement names a principal method or suite this gateway does
    /// not verify operators with.
    #[error("the operator attestation names an unsupported method or suite")]
    Unsupported,
    /// The installation block differs from the installation.
    #[error("the operator attestation names another installation")]
    InstallationMismatch,
    /// The asserted signing time is too far ahead of the gateway clock.
    #[error("the operator attestation is issued in the future")]
    IssuedInFuture,
    /// The control evidence does not establish the named key, or the
    /// signature does not verify.
    #[error("the operator attestation does not verify")]
    Unverified,
}

impl OperatorAttestationError {
    /// The stable code; every refusal of a present attestation shares it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "gateway.install.operator-attestation-invalid"
    }
}

/// The installation an attestation names. It must equal the manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorInstallation {
    /// The approved recipe digest, lowercase hex.
    pub recipe_digest: String,
    /// SHA-256 of the profile lock, lowercase hex.
    pub profile_lock_sha256: String,
    /// SHA-256 of the installed trusted context, lowercase hex.
    pub trusted_context_sha256: String,
    /// The provider kind.
    pub provider: String,
    /// The connection alias.
    pub alias: String,
    /// `development` or `production`.
    pub deployment: String,
}

/// The signed statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorStatement {
    /// Exactly [`OPERATOR_ATTESTATION_SCHEMA`].
    pub schema: String,
    /// The operator's principal.
    pub operator_principal: String,
    /// `raw-key-v1`, `did-key-v1`, or `did-keri-v1`.
    pub principal_method: String,
    /// The verification method the signature uses.
    pub verification_method: String,
    /// `ed25519-v1` or `p256-sha256-v1`.
    pub signature_suite: String,
    /// The installation the operator runs.
    pub installation: OperatorInstallation,
    /// The asserted signing time, in gateway-clock seconds.
    pub issued_at: u64,
}

impl OperatorStatement {
    /// The exact bytes the operator signs: the schema, a NUL byte, and the
    /// RFC 8785 statement.
    ///
    /// # Errors
    /// Returns [`OperatorAttestationError::Malformed`] when the statement
    /// cannot be canonicalized.
    pub fn preimage(&self) -> Result<Vec<u8>, OperatorAttestationError> {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| OperatorAttestationError::Malformed)?;
        let mut preimage =
            Vec::with_capacity(OPERATOR_ATTESTATION_SCHEMA.len() + 1 + canonical.len());
        preimage.extend_from_slice(OPERATOR_ATTESTATION_SCHEMA.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        Ok(preimage)
    }
}

/// One control-evidence object as the file carries it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorEvidence {
    /// The evidence type identifier.
    pub evidence_type: String,
    /// The evidence media type.
    pub media_type: String,
    /// The evidence bytes, base64url without padding.
    pub bytes_b64: String,
}

/// The attestation file: the statement, its signature, and at most four
/// control-evidence objects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAttestation {
    /// The signed statement.
    pub statement: OperatorStatement,
    /// The signature over [`OperatorStatement::preimage`], base64url
    /// without padding.
    pub signature_b64: String,
    /// The control evidence the principal method consumes.
    pub evidence: Vec<OperatorEvidence>,
}

/// Verifies an attestation file against the installation it must name at
/// gateway-clock time `now`, and returns the authenticated operator.
///
/// # Errors
/// Returns the first refusal; nothing about the operator is trusted then.
pub fn verify_operator_attestation(
    bytes: &[u8],
    expected: &OperatorInstallation,
    now: u64,
) -> Result<PrincipalId, OperatorAttestationError> {
    if bytes.is_empty() || bytes.len() > MAX_OPERATOR_ATTESTATION_BYTES {
        return Err(OperatorAttestationError::Malformed);
    }
    let file: OperatorAttestation =
        serde_json::from_slice(bytes).map_err(|_| OperatorAttestationError::Malformed)?;
    let statement = &file.statement;
    if statement.schema != OPERATOR_ATTESTATION_SCHEMA
        || file.evidence.is_empty()
        || file.evidence.len() > MAX_OPERATOR_EVIDENCE
    {
        return Err(OperatorAttestationError::Malformed);
    }
    let principal = PrincipalId::parse(&statement.operator_principal)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let method_id = PrincipalMethodId::parse(&statement.principal_method)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let verification_method = VerificationMethod::parse(&statement.verification_method)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let suite_id = SignatureSuiteId::parse(&statement.signature_suite)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    if statement.issued_at > now.saturating_add(MAX_ISSUED_AHEAD_SECONDS) {
        return Err(OperatorAttestationError::IssuedInFuture);
    }
    if statement.installation != *expected {
        return Err(OperatorAttestationError::InstallationMismatch);
    }
    let preimage = statement.preimage()?;
    let signature = Base64UrlUnpadded::decode_vec(&file.signature_b64)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let evidence = file
        .evidence
        .iter()
        .map(evidence_object)
        .collect::<Result<Vec<_>, _>>()?;
    let references: Vec<&EvidenceObject> = evidence.iter().collect();
    let input = PrincipalControlInput {
        principal: &principal,
        verification_method: &verification_method,
        signature_suite: &suite_id,
        purpose: ControlPurpose::Assertion,
        signing_preimage: &preimage,
        signature: &signature,
        asserted_signing_time: Timestamp::new(statement.issued_at),
        evidence: &references,
        evaluation_time: Timestamp::new(now),
    };
    let control = establish_control(method_id.as_str(), input)?;
    let message = control.signature_message().unwrap_or(&preimage);
    verify_signature(
        suite_id.as_str(),
        SignatureInput {
            verification_key: control.verification_key(),
            signing_preimage: message,
            signature: &signature,
        },
    )?;
    Ok(principal)
}

fn evidence_object(wire: &OperatorEvidence) -> Result<EvidenceObject, OperatorAttestationError> {
    let bytes = Base64UrlUnpadded::decode_vec(&wire.bytes_b64)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let evidence_type = EvidenceTypeId::parse(&wire.evidence_type)
        .map_err(|_| OperatorAttestationError::Malformed)?;
    let media_type =
        MediaType::parse(&wire.media_type).map_err(|_| OperatorAttestationError::Malformed)?;
    let draft = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        evidence_type.clone(),
        media_type.clone(),
        bytes.clone(),
    )
    .map_err(|_| OperatorAttestationError::Malformed)?;
    let id = auths_codec::evidence_id(&draft).map_err(|_| OperatorAttestationError::Malformed)?;
    EvidenceObject::new(id, evidence_type, media_type, bytes)
        .map_err(|_| OperatorAttestationError::Malformed)
}

/// Runs the registered principal method `method`.
fn establish_control(
    method: &str,
    input: PrincipalControlInput<'_>,
) -> Result<auths_ports::ControlEvidence, OperatorAttestationError> {
    let result = match method {
        auths_raw_key::RAW_KEY_V1 => auths_raw_key::RawKeyMethod::new()
            .map_err(|_| OperatorAttestationError::Unsupported)?
            .verify_control(input),
        auths_did_key::DID_KEY_V1 => auths_did_key::DidKeyMethod::new()
            .map_err(|_| OperatorAttestationError::Unsupported)?
            .verify_control(input),
        auths_did_keri::ADAPTER_ID => auths_did_keri::DidKeriMethod::new()
            .map_err(|_| OperatorAttestationError::Unsupported)?
            .verify_control(input),
        _ => return Err(OperatorAttestationError::Unsupported),
    };
    result.map_err(|_| OperatorAttestationError::Unverified)
}

/// Runs the registered signature suite `suite`.
fn verify_signature(
    suite: &str,
    input: SignatureInput<'_>,
) -> Result<(), OperatorAttestationError> {
    let result = match suite {
        auths_signature::ED25519_V1 => auths_signature::Ed25519Suite::new()
            .map_err(|_| OperatorAttestationError::Unsupported)?
            .verify(input),
        auths_signature::P256_SHA256_V1 => auths_signature::P256Sha256Suite::new()
            .map_err(|_| OperatorAttestationError::Unsupported)?
            .verify(input),
        _ => return Err(OperatorAttestationError::Unsupported),
    };
    result.map_err(|_| OperatorAttestationError::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Signer;

    const NOW: u64 = 1_790_000_000;

    fn installation() -> OperatorInstallation {
        OperatorInstallation {
            recipe_digest: "a".repeat(64),
            profile_lock_sha256: "b".repeat(64),
            trusted_context_sha256: "c".repeat(64),
            provider: "stripe".to_owned(),
            alias: "refunds".to_owned(),
            deployment: "production".to_owned(),
        }
    }

    fn statement(signer: &Signer) -> OperatorStatement {
        OperatorStatement {
            schema: OPERATOR_ATTESTATION_SCHEMA.to_owned(),
            operator_principal: signer.principal.as_str().to_owned(),
            principal_method: auths_raw_key::RAW_KEY_V1.to_owned(),
            verification_method: signer.principal.as_str().to_owned(),
            signature_suite: auths_signature::ED25519_V1.to_owned(),
            installation: installation(),
            issued_at: NOW,
        }
    }

    fn attestation(signer: &Signer, statement: OperatorStatement) -> OperatorAttestation {
        let preimage = statement.preimage().expect("preimage");
        let evidence = signer.evidence();
        OperatorAttestation {
            signature_b64: Base64UrlUnpadded::encode_string(signer.sign(&preimage).as_slice()),
            statement,
            evidence: vec![OperatorEvidence {
                evidence_type: evidence.evidence_type().as_str().to_owned(),
                media_type: evidence.media_type().as_str().to_owned(),
                bytes_b64: Base64UrlUnpadded::encode_string(evidence.bytes()),
            }],
        }
    }

    fn bytes(attestation: &OperatorAttestation) -> Vec<u8> {
        serde_json::to_vec(attestation).expect("json")
    }

    #[test]
    fn a_signed_attestation_authenticates_its_operator() {
        let operator = Signer::new(0x44);
        let signed = attestation(&operator, statement(&operator));
        assert_eq!(
            verify_operator_attestation(&bytes(&signed), &installation(), NOW),
            Ok(operator.principal.clone())
        );
        let preimage = signed.statement.preimage().expect("preimage");
        assert!(preimage.starts_with(b"auths.gateway-operator-attestation/1\0{"));
    }

    #[test]
    fn an_invalid_attestation_is_refused() {
        let operator = Signer::new(0x44);
        let other = Signer::new(0x45);
        let check = |attestation: &OperatorAttestation| {
            verify_operator_attestation(&bytes(attestation), &installation(), NOW)
        };

        let mut forged = attestation(&operator, statement(&operator));
        forged.signature_b64 = attestation(&other, statement(&operator)).signature_b64;
        assert_eq!(check(&forged), Err(OperatorAttestationError::Unverified));

        let mut borrowed = attestation(&operator, statement(&operator));
        borrowed.evidence = attestation(&other, statement(&other)).evidence;
        assert_eq!(check(&borrowed), Err(OperatorAttestationError::Unverified));

        let mut moved = statement(&operator);
        moved.installation.alias = "other".to_owned();
        assert_eq!(
            check(&attestation(&operator, moved)),
            Err(OperatorAttestationError::InstallationMismatch)
        );

        let mut early = statement(&operator);
        early.issued_at = NOW + MAX_ISSUED_AHEAD_SECONDS + 1;
        assert_eq!(
            check(&attestation(&operator, early)),
            Err(OperatorAttestationError::IssuedInFuture)
        );
        let mut edge = statement(&operator);
        edge.issued_at = NOW + MAX_ISSUED_AHEAD_SECONDS;
        assert!(check(&attestation(&operator, edge)).is_ok());

        let mut web = statement(&operator);
        web.principal_method = "did-web-v1".to_owned();
        assert_eq!(
            check(&attestation(&operator, web)),
            Err(OperatorAttestationError::Unsupported)
        );

        let mut crowded = attestation(&operator, statement(&operator));
        let extra = crowded.evidence[0].clone();
        crowded.evidence = vec![extra; MAX_OPERATOR_EVIDENCE + 1];
        assert_eq!(check(&crowded), Err(OperatorAttestationError::Malformed));

        let mut unknown =
            serde_json::to_value(attestation(&operator, statement(&operator))).expect("value");
        unknown["statement"]["role"] = serde_json::json!("root");
        assert_eq!(
            verify_operator_attestation(
                &serde_json::to_vec(&unknown).expect("json"),
                &installation(),
                NOW
            ),
            Err(OperatorAttestationError::Malformed)
        );
        assert_eq!(
            verify_operator_attestation(
                &vec![b' '; MAX_OPERATOR_ATTESTATION_BYTES + 1],
                &installation(),
                NOW
            ),
            Err(OperatorAttestationError::Malformed)
        );
        assert_eq!(
            OperatorAttestationError::Unverified.code(),
            "gateway.install.operator-attestation-invalid"
        );
    }
}
