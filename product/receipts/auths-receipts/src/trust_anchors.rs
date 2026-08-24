//! Canonical deployment-owned public receipt trust anchors.

use super::{
    ConfiguredReceiptVerifier, DecisionClass, ExecutionOutcome, PortableReceipt, ReceiptError,
    application_execution_lease_digest, decision_receipt_id, decode_attested_decision,
    decode_attested_execution, decode_portable_receipt, execution_receipt_id, portable_receipt_id,
    verify_decision_attestation, verify_execution_attestation,
};
use auths_model::{ProfileRef, VerificationMethod};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const SCHEMA: &str = "auths.receipt-trust-anchors/1";
const MAX_DOCUMENT_BYTES: usize = 65_536;
const MAX_ANCHORS: usize = 16;

/// Closed signer role for a portable receipt attestation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptTrustAnchorRole {
    Decision,
    Execution,
}

/// One retained Ed25519 public receipt key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptTrustAnchor {
    role: ReceiptTrustAnchorRole,
    key_id: String,
    verification_method: String,
    algorithm: String,
    public_key_base64url: String,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

impl ReceiptTrustAnchor {
    /// Constructs one bounded retained public receipt key.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptTrustAnchorsError`] when the key identity, method,
    /// validity interval, or public key is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: ReceiptTrustAnchorRole,
        key_id: impl Into<String>,
        verification_method: impl Into<String>,
        public_key: [u8; 32],
        not_before_unix_seconds: u64,
        not_after_unix_seconds: u64,
    ) -> Result<Self, ReceiptTrustAnchorsError> {
        let value = Self {
            role,
            key_id: key_id.into(),
            verification_method: verification_method.into(),
            algorithm: "Ed25519".to_owned(),
            public_key_base64url: Base64UrlUnpadded::encode_string(&public_key),
            not_before_unix_seconds,
            not_after_unix_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn role(&self) -> ReceiptTrustAnchorRole {
        self.role
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }

    /// Decodes the exact retained Ed25519 verification key.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptTrustAnchorsError`] when the encoded key is not the
    /// required canonical 32-byte Ed25519 public key.
    pub fn public_key(&self) -> Result<[u8; 32], ReceiptTrustAnchorsError> {
        let mut output = [0_u8; 32];
        Base64UrlUnpadded::decode(&self.public_key_base64url, &mut output)
            .map_err(|_| ReceiptTrustAnchorsError::Invalid)?;
        Ok(output)
    }

    /// Returns the canonical unpadded base64url Ed25519 public key.
    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    fn validate(&self) -> Result<(), ReceiptTrustAnchorsError> {
        let _ = VerificationMethod::parse(&self.verification_method)
            .map_err(|_| ReceiptTrustAnchorsError::Invalid)?;
        if !registered_token(&self.key_id)
            || self.algorithm != "Ed25519"
            || self.public_key_base64url.len() != 43
            || self.public_key()? == [0; 32]
            || self.not_before_unix_seconds >= self.not_after_unix_seconds
        {
            return Err(ReceiptTrustAnchorsError::Invalid);
        }
        Ok(())
    }
}

/// Complete canonical retained trust set for one deployment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptTrustAnchors {
    schema: String,
    anchors: Vec<ReceiptTrustAnchor>,
}

/// Signed common claims decoded only after native trust-anchor verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPortableReceipt {
    portable_id: String,
    profile: ProfileRef,
    decision_action: [u8; 32],
    decision_context: [u8; 32],
    decision: DecisionClass,
    decision_verification_method: String,
    decision_profile_claims: Vec<u8>,
    execution_command: Option<[u8; 32]>,
    execution_result: Option<[u8; 32]>,
    execution_outcome: Option<ExecutionOutcome>,
    execution_verification_method: Option<String>,
    execution_profile_claims: Option<Vec<u8>>,
}

impl VerifiedPortableReceipt {
    #[must_use]
    pub fn portable_id(&self) -> &str {
        &self.portable_id
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    #[must_use]
    pub const fn decision_action(&self) -> &[u8; 32] {
        &self.decision_action
    }

    #[must_use]
    pub const fn decision_context(&self) -> &[u8; 32] {
        &self.decision_context
    }

    #[must_use]
    pub const fn decision(&self) -> DecisionClass {
        self.decision
    }

    #[must_use]
    pub fn decision_verification_method(&self) -> &str {
        &self.decision_verification_method
    }

    #[must_use]
    pub fn decision_profile_claims(&self) -> &[u8] {
        &self.decision_profile_claims
    }

    #[must_use]
    pub const fn execution_command(&self) -> Option<&[u8; 32]> {
        self.execution_command.as_ref()
    }

    #[must_use]
    pub const fn execution_result(&self) -> Option<&[u8; 32]> {
        self.execution_result.as_ref()
    }

    #[must_use]
    pub const fn execution_outcome(&self) -> Option<ExecutionOutcome> {
        self.execution_outcome
    }

    #[must_use]
    pub fn execution_verification_method(&self) -> Option<&str> {
        self.execution_verification_method.as_deref()
    }

    #[must_use]
    pub fn execution_profile_claims(&self) -> Option<&[u8]> {
        self.execution_profile_claims.as_deref()
    }
}

/// Commits the exact native common-claim projection used by qualification
/// source records and the independent attester.
///
/// # Errors
///
/// Returns [`ReceiptError`] when the claim projection cannot be encoded
/// canonically.
pub fn verified_portable_receipt_claims_digest(
    receipt: &VerifiedPortableReceipt,
    operation_id: Option<&str>,
) -> Result<[u8; 32], ReceiptError> {
    let profile = format!(
        "{}/{}",
        receipt.profile.id().as_str(),
        receipt.profile.version()
    );
    let decision = match receipt.decision {
        DecisionClass::Authorized => "authorized",
        DecisionClass::Denied => "denied",
        DecisionClass::Indeterminate => "indeterminate",
    };
    let execution_outcome = receipt.execution_outcome.map(|outcome| match outcome {
        ExecutionOutcome::Succeeded => "succeeded",
        ExecutionOutcome::Failed => "failed",
        ExecutionOutcome::Indeterminate => "indeterminate",
    });
    let value = json!({
        "decisionActionSha256": hex_digest(&receipt.decision_action),
        "decisionClass": decision,
        "decisionContextSha256": hex_digest(&receipt.decision_context),
        "decisionVerificationMethod": receipt.decision_verification_method,
        "decisionProfileClaimsSha256": hex_digest(&Sha256::digest(&receipt.decision_profile_claims).into()),
        "executionCommandSha256": receipt.execution_command.map(|value| hex_digest(&value)),
        "executionOutcome": execution_outcome,
        "executionResultSha256": receipt.execution_result.map(|value| hex_digest(&value)),
        "executionVerificationMethod": receipt.execution_verification_method,
        "executionProfileClaimsSha256": receipt.execution_profile_claims.as_ref().map(|value| hex_digest(&Sha256::digest(value).into())),
        "operationId": operation_id,
        "portableReceiptId": receipt.portable_id,
        "profile": profile,
        "schema": "auths.qualification-native-receipt-claims/1",
    });
    let canonical =
        serde_json_canonicalizer::to_vec(&value).map_err(|_| ReceiptError::Malformed)?;
    Ok(Sha256::digest(canonical).into())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

impl ReceiptTrustAnchors {
    /// Constructs a role-separated, byte-sorted retained trust set.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptTrustAnchorsError`] when the set is empty, oversized,
    /// unsorted, duplicated, or contains an invalid anchor.
    pub fn new(anchors: Vec<ReceiptTrustAnchor>) -> Result<Self, ReceiptTrustAnchorsError> {
        let value = Self {
            schema: SCHEMA.to_owned(),
            anchors,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn anchors(&self) -> &[ReceiptTrustAnchor] {
        &self.anchors
    }

    fn validate(&self) -> Result<(), ReceiptTrustAnchorsError> {
        if self.schema != SCHEMA || self.anchors.is_empty() || self.anchors.len() > MAX_ANCHORS {
            return Err(ReceiptTrustAnchorsError::Invalid);
        }
        let mut keys = BTreeSet::new();
        let mut methods = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for anchor in &self.anchors {
            anchor.validate()?;
            if !keys.insert(anchor.key_id.as_str())
                || !methods.insert(anchor.verification_method.as_str())
                || !public_keys.insert(anchor.public_key()?)
            {
                return Err(ReceiptTrustAnchorsError::Invalid);
            }
        }
        if !self.anchors.windows(2).all(|pair| {
            (pair[0].role, pair[0].key_id.as_bytes()) < (pair[1].role, pair[1].key_id.as_bytes())
        }) {
            return Err(ReceiptTrustAnchorsError::Invalid);
        }
        Ok(())
    }
}

/// Encodes an exact canonical JCS trust-anchor document.
///
/// # Errors
///
/// Returns [`ReceiptTrustAnchorsError`] when the anchor set is invalid or the
/// canonical document exceeds its bound.
pub fn encode_receipt_trust_anchors(
    anchors: &ReceiptTrustAnchors,
) -> Result<Vec<u8>, ReceiptTrustAnchorsError> {
    anchors.validate()?;
    let bytes =
        serde_json_canonicalizer::to_vec(anchors).map_err(|_| ReceiptTrustAnchorsError::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ReceiptTrustAnchorsError::Limit);
    }
    Ok(bytes)
}

/// Decodes and canonicality-checks a deployment trust-anchor document.
///
/// # Errors
///
/// Returns [`ReceiptTrustAnchorsError`] when the document is malformed,
/// noncanonical, invalid, or exceeds its bound.
pub fn decode_receipt_trust_anchors(
    input: &[u8],
) -> Result<ReceiptTrustAnchors, ReceiptTrustAnchorsError> {
    if input.is_empty() || input.len() > MAX_DOCUMENT_BYTES {
        return Err(ReceiptTrustAnchorsError::Limit);
    }
    let value: ReceiptTrustAnchors =
        serde_json::from_slice(input).map_err(|_| ReceiptTrustAnchorsError::Invalid)?;
    value.validate()?;
    if encode_receipt_trust_anchors(&value)? != input {
        return Err(ReceiptTrustAnchorsError::NonCanonical);
    }
    Ok(value)
}

/// Natively verifies one canonical portable receipt under deployment-owned
/// retained trust. The optional operation identity is checked against the
/// signed execution lease and is never read from caller-authored JSON.
///
/// # Errors
///
/// Returns [`ReceiptError`] when parsing, signer selection, signature
/// verification, profile matching, or operation binding fails.
pub fn verify_portable_receipt_with_anchors(
    input: &[u8],
    anchors: &ReceiptTrustAnchors,
    expected_profile: Option<&ProfileRef>,
    expected_operation_id: Option<&str>,
) -> Result<VerifiedPortableReceipt, ReceiptError> {
    anchors
        .validate()
        .map_err(|_| ReceiptError::UnexpectedSigner)?;
    let portable = decode_portable_receipt(input)?;
    let decision = decode_attested_decision(portable.attested_decision())?;
    let decision_id = decision_receipt_id(decision.receipt())?;
    let decision_anchor = matching_anchor(
        anchors,
        ReceiptTrustAnchorRole::Decision,
        decision.signer().verification_method().as_str(),
        decision.receipt().decided_at().get(),
    )?;
    let suite = auths_signature::Ed25519Suite::new().map_err(|_| ReceiptError::UnexpectedSigner)?;
    let decision_key = decision_anchor
        .public_key()
        .map_err(|_| ReceiptError::UnexpectedSigner)?;
    let decision_verifier =
        ConfiguredReceiptVerifier::new(decision.signer().clone(), &decision_key, &suite);
    verify_decision_attestation(
        portable.attested_decision(),
        decision_id,
        decision.signer().verifier(),
        &decision_verifier,
    )?;
    if expected_profile.is_some_and(|profile| profile != decision.receipt().profile()) {
        return Err(ReceiptError::UnexpectedSigner);
    }

    let mut verified = VerifiedPortableReceipt {
        portable_id: portable_receipt_id(input)?,
        profile: decision.receipt().profile().clone(),
        decision_action: *decision.receipt().action_digest().as_bytes(),
        decision_context: *decision.receipt().context_digest().as_bytes(),
        decision: decision.receipt().decision(),
        decision_verification_method: decision.signer().verification_method().as_str().to_owned(),
        decision_profile_claims: decision.receipt().profile_claims().to_vec(),
        execution_command: None,
        execution_result: None,
        execution_outcome: None,
        execution_verification_method: None,
        execution_profile_claims: None,
    };

    if let PortableReceipt::Execution {
        attested_execution, ..
    } = portable
    {
        let execution = decode_attested_execution(&attested_execution)?;
        let execution_id = execution_receipt_id(execution.receipt())?;
        let execution_anchor = matching_anchor(
            anchors,
            ReceiptTrustAnchorRole::Execution,
            execution.signer().verification_method().as_str(),
            execution.receipt().completed_at().get(),
        )?;
        let execution_key = execution_anchor
            .public_key()
            .map_err(|_| ReceiptError::UnexpectedSigner)?;
        let execution_verifier =
            ConfiguredReceiptVerifier::new(execution.signer().clone(), &execution_key, &suite);
        verify_execution_attestation(
            &attested_execution,
            execution_id,
            execution.signer().verifier(),
            &execution_verifier,
        )?;
        let execution_claims =
            crate::decode_profile_receipt_claims(execution.receipt().profile_claims())?;
        if execution_claims.profile() != decision.receipt().profile()
            || execution_claims.phase() != crate::ProfileReceiptClaimPhase::Execution
            || execution.receipt().decision_receipt() != decision_id
            || expected_operation_id.is_some_and(|operation_id| {
                application_execution_lease_digest(operation_id, None, None)
                    .map_or(true, |expected| {
                        expected != execution.receipt().execution_lease()
                    })
            })
        {
            return Err(ReceiptError::DigestMismatch);
        }
        verified.execution_command = Some(*execution.receipt().command_digest().as_bytes());
        verified.execution_result = execution
            .receipt()
            .result_digest()
            .map(|digest| *digest.as_bytes());
        verified.execution_outcome = Some(execution.receipt().outcome());
        verified.execution_verification_method =
            Some(execution.signer().verification_method().as_str().to_owned());
        verified.execution_profile_claims = Some(execution.receipt().profile_claims().to_vec());
    }
    Ok(verified)
}

fn matching_anchor<'a>(
    anchors: &'a ReceiptTrustAnchors,
    role: ReceiptTrustAnchorRole,
    verification_method: &str,
    issuance_time: u64,
) -> Result<&'a ReceiptTrustAnchor, ReceiptError> {
    anchors
        .anchors()
        .iter()
        .find(|anchor| {
            anchor.role() == role
                && anchor.verification_method() == verification_method
                && issuance_time >= anchor.not_before_unix_seconds()
                && issuance_time <= anchor.not_after_unix_seconds()
        })
        .ok_or(ReceiptError::UnexpectedSigner)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiptTrustAnchorsError {
    #[error("invalid receipt trust-anchor document")]
    Invalid,
    #[error("receipt trust-anchor document exceeds its bound")]
    Limit,
    #[error("receipt trust-anchor document is not canonical")]
    NonCanonical,
}

fn registered_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(role: ReceiptTrustAnchorRole, key_id: &str, byte: u8) -> ReceiptTrustAnchor {
        ReceiptTrustAnchor::new(
            role,
            key_id,
            format!("did:key:{key_id}#key-{key_id}"),
            [byte; 32],
            10,
            20,
        )
        .unwrap()
    }

    #[test]
    fn canonical_document_round_trips_and_rejects_unknown_fields() {
        let value = ReceiptTrustAnchors::new(vec![
            anchor(ReceiptTrustAnchorRole::Decision, "decision-1", 1),
            anchor(ReceiptTrustAnchorRole::Execution, "execution-1", 2),
        ])
        .unwrap();
        let encoded = encode_receipt_trust_anchors(&value).unwrap();
        assert_eq!(decode_receipt_trust_anchors(&encoded).unwrap(), value);
        let mut noncanonical = encoded.clone();
        noncanonical.push(b' ');
        assert_eq!(
            decode_receipt_trust_anchors(&noncanonical),
            Err(ReceiptTrustAnchorsError::NonCanonical)
        );
    }

    #[test]
    fn duplicate_or_cross_role_key_material_is_rejected() {
        let duplicate = ReceiptTrustAnchors::new(vec![
            anchor(ReceiptTrustAnchorRole::Decision, "decision-1", 1),
            anchor(ReceiptTrustAnchorRole::Execution, "execution-1", 1),
        ]);
        assert_eq!(duplicate, Err(ReceiptTrustAnchorsError::Invalid));
    }
}
