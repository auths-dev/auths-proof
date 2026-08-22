//! Deployment-owned portable receipt attestation.

#![forbid(unsafe_code)]

use auths_lifecycle::{OperationEffectV1, OperationIdV1, OperationProfileV1};
use auths_model::{
    PrincipalId, ProfileId, ProfileRef, SignatureBytes, SignatureSuiteId, Timestamp,
    VerificationMethod,
};
use auths_receipts::{
    AttestedDecisionReceipt, AttestedExecutionReceipt, DecisionClass, ExecutionOutcome,
    PortableReceipt, ReceiptSigner, ReceiptTrustAnchor, ReceiptTrustAnchorRole,
    ReceiptTrustAnchors, application_execution_lease_digest, decision_receipt_id,
    decode_attested_decision, decode_attested_execution, decode_decision, decode_execution,
    decode_portable_receipt, encode_attested_decision, encode_attested_execution,
    encode_portable_decision, encode_portable_execution, portable_receipt_id,
    prepare_execution_receipt, prepare_profile_decision_receipt,
    verify_portable_receipt_with_anchors,
};
use auths_stores::{JournalDecisionClassV1, JournalReceiptV1, JournalRecordV1};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[cfg(any(test, feature = "testkit-agent"))]
const DECISION_KEY_DOMAIN: &[u8] = b"AUTHS-LOCAL-RECEIPT-DECISION\0\x01";
#[cfg(any(test, feature = "testkit-agent"))]
const EXECUTION_KEY_DOMAIN: &[u8] = b"AUTHS-LOCAL-RECEIPT-EXECUTION\0\x01";

/// Deployment-stable, role-separated signer and verifier for portable receipts.
pub(crate) struct ReceiptAttestor {
    decision_key: SigningKey,
    execution_key: SigningKey,
    decision_signer: ReceiptSigner,
    execution_signer: ReceiptSigner,
    anchors: ReceiptTrustAnchors,
    decision_not_before: u64,
    decision_not_after: u64,
    execution_not_before: u64,
    execution_not_after: u64,
}

/// Public verification material for one disposable testkit receipt role.
///
/// This projection is deliberately unavailable in production builds. It
/// exposes only the role-separated Ed25519 public key and its signer identity;
/// the derived signing keys remain private to the local agent.
#[cfg(feature = "testkit-agent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestkitReceiptAnchor {
    pub role: &'static str,
    pub principal: String,
    pub verification_method: String,
    pub suite: String,
    pub public_key: [u8; 32],
}

impl ReceiptAttestor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_signing_keys(
        decision_key_id: &str,
        decision_verification_method: &str,
        decision_seed: &[u8; 32],
        decision_not_before: u64,
        decision_not_after: u64,
        execution_key_id: &str,
        execution_verification_method: &str,
        execution_seed: &[u8; 32],
        execution_not_before: u64,
        execution_not_after: u64,
        mut prior: Vec<ReceiptTrustAnchor>,
    ) -> Result<Self, ReceiptAttestorError> {
        if decision_seed == &[0; 32]
            || execution_seed == &[0; 32]
            || decision_seed == execution_seed
            || decision_not_before >= decision_not_after
            || execution_not_before >= execution_not_after
        {
            return Err(ReceiptAttestorError::Invalid);
        }
        let decision_key = SigningKey::from_bytes(decision_seed);
        let execution_key = SigningKey::from_bytes(execution_seed);
        let decision_signer = configured_signer(decision_verification_method)?;
        let execution_signer = configured_signer(execution_verification_method)?;
        prior.push(
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Decision,
                decision_key_id,
                decision_verification_method,
                decision_key.verifying_key().to_bytes(),
                decision_not_before,
                decision_not_after,
            )
            .map_err(|_| ReceiptAttestorError::Invalid)?,
        );
        prior.push(
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Execution,
                execution_key_id,
                execution_verification_method,
                execution_key.verifying_key().to_bytes(),
                execution_not_before,
                execution_not_after,
            )
            .map_err(|_| ReceiptAttestorError::Invalid)?,
        );
        prior.sort_by(|left, right| {
            (left.role(), left.key_id().as_bytes()).cmp(&(right.role(), right.key_id().as_bytes()))
        });
        let anchors = ReceiptTrustAnchors::new(prior).map_err(|_| ReceiptAttestorError::Invalid)?;
        Ok(Self {
            decision_key,
            execution_key,
            decision_signer,
            execution_signer,
            anchors,
            decision_not_before,
            decision_not_after,
            execution_not_before,
            execution_not_after,
        })
    }

    #[cfg(any(test, feature = "testkit-agent"))]
    pub(crate) fn from_root_seed(
        key_id: &str,
        root_seed: &[u8; 32],
    ) -> Result<Self, ReceiptAttestorError> {
        if root_seed == &[0; 32] || !registered_token(key_id) {
            return Err(ReceiptAttestorError::Invalid);
        }
        let decision_method =
            format!("did:key:auths-local-agent-receipt-decision-{key_id}#key-{key_id}");
        let execution_method =
            format!("did:key:auths-local-agent-receipt-execution-{key_id}#key-{key_id}");
        Self::from_signing_keys(
            &format!("decision-{key_id}"),
            &decision_method,
            &derive_seed(DECISION_KEY_DOMAIN, root_seed),
            0,
            u64::MAX,
            &format!("execution-{key_id}"),
            &execution_method,
            &derive_seed(EXECUTION_KEY_DOMAIN, root_seed),
            0,
            u64::MAX,
            Vec::new(),
        )
    }

    #[cfg(feature = "testkit-agent")]
    pub(crate) fn testkit_anchors(&self) -> [TestkitReceiptAnchor; 2] {
        [
            TestkitReceiptAnchor {
                role: "decision",
                principal: self.decision_signer.verifier().as_str().to_owned(),
                verification_method: self
                    .decision_signer
                    .verification_method()
                    .as_str()
                    .to_owned(),
                suite: self.decision_signer.suite().as_str().to_owned(),
                public_key: self.decision_key.verifying_key().to_bytes(),
            },
            TestkitReceiptAnchor {
                role: "execution",
                principal: self.execution_signer.verifier().as_str().to_owned(),
                verification_method: self
                    .execution_signer
                    .verification_method()
                    .as_str()
                    .to_owned(),
                suite: self.execution_signer.suite().as_str().to_owned(),
                public_key: self.execution_key.verifying_key().to_bytes(),
            },
        ]
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decision(
        &self,
        profile: &OperationProfileV1,
        proof: &[u8],
        action: &[u8],
        context: &[u8],
        decision: DecisionClass,
        reason: String,
        now_unix_seconds: u64,
        profile_claims: &[u8],
    ) -> Result<JournalReceiptV1, ReceiptAttestorError> {
        if now_unix_seconds < self.decision_not_before || now_unix_seconds > self.decision_not_after
        {
            return Err(ReceiptAttestorError::Invalid);
        }
        let prepared = prepare_profile_decision_receipt(
            model_profile(profile)?,
            proof,
            action,
            context,
            decision,
            vec![reason],
            Timestamp::new(now_unix_seconds),
            profile_claims,
            &self.decision_signer,
        )
        .map_err(|_| ReceiptAttestorError::Invalid)?;
        let signature = self.decision_key.sign(prepared.signing_preimage());
        let attested = encode_attested_decision(&AttestedDecisionReceipt::new(
            decode_decision(prepared.canonical()).map_err(|_| ReceiptAttestorError::Invalid)?,
            self.decision_signer.clone(),
            SignatureBytes::new(signature.to_bytes().to_vec())
                .map_err(|_| ReceiptAttestorError::Invalid)?,
        ))
        .map_err(|_| ReceiptAttestorError::Invalid)?;
        let portable =
            encode_portable_decision(&attested).map_err(|_| ReceiptAttestorError::Invalid)?;
        journal_receipt(portable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execution(
        &self,
        decision: &JournalReceiptV1,
        operation_id: &OperationIdV1,
        command: &[u8],
        outcome: ExecutionOutcome,
        result: Option<&[u8]>,
        now_unix_seconds: u64,
        profile_claims: &[u8],
    ) -> Result<JournalReceiptV1, ReceiptAttestorError> {
        if now_unix_seconds < self.execution_not_before
            || now_unix_seconds > self.execution_not_after
        {
            return Err(ReceiptAttestorError::Invalid);
        }
        self.verify(decision, None)?;
        let portable =
            decode_portable_receipt(decision.bytes()).map_err(|_| ReceiptAttestorError::Invalid)?;
        let PortableReceipt::Decision { attested_decision } = portable else {
            return Err(ReceiptAttestorError::Invalid);
        };
        let decoded_decision = decode_attested_decision(&attested_decision)
            .map_err(|_| ReceiptAttestorError::Invalid)?;
        let decision_id = decision_receipt_id(decoded_decision.receipt())
            .map_err(|_| ReceiptAttestorError::Invalid)?;
        let prepared = prepare_execution_receipt(
            decision_id,
            operation_id.as_str(),
            None,
            None,
            command,
            outcome,
            result,
            Timestamp::new(now_unix_seconds),
            profile_claims,
            &self.execution_signer,
        )
        .map_err(|_| ReceiptAttestorError::Invalid)?;
        let signature = self.execution_key.sign(prepared.signing_preimage());
        let attested_execution = encode_attested_execution(&AttestedExecutionReceipt::new(
            decode_execution(prepared.canonical()).map_err(|_| ReceiptAttestorError::Invalid)?,
            self.execution_signer.clone(),
            SignatureBytes::new(signature.to_bytes().to_vec())
                .map_err(|_| ReceiptAttestorError::Invalid)?,
        ))
        .map_err(|_| ReceiptAttestorError::Invalid)?;
        let linked = encode_portable_execution(&attested_decision, &attested_execution)
            .map_err(|_| ReceiptAttestorError::Invalid)?;
        journal_receipt(linked)
    }

    /// Revalidates structure, IDs, link, signer roles, signature, and profile.
    pub(crate) fn verify(
        &self,
        receipt: &JournalReceiptV1,
        expected_profile: Option<&OperationProfileV1>,
    ) -> Result<(), ReceiptAttestorError> {
        let expected_profile = expected_profile.map(model_profile).transpose()?;
        let verified = verify_portable_receipt_with_anchors(
            receipt.bytes(),
            &self.anchors,
            expected_profile.as_ref(),
            None,
        )
        .map_err(|_| ReceiptAttestorError::Invalid)?;
        if verified.portable_id() != receipt.receipt_id() {
            return Err(ReceiptAttestorError::Invalid);
        }
        Ok(())
    }

    pub(crate) const fn trust_anchors(&self) -> &ReceiptTrustAnchors {
        &self.anchors
    }

    /// Verifies every retained receipt against the exact durable operation
    /// facts before any status, replay, recovery, or receipt export projects
    /// success to a caller.
    pub(crate) fn verify_for_record(
        &self,
        record: &JournalRecordV1,
        expected_decision_profile_claims: &[u8],
        expected_execution_profile_claims: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), ReceiptAttestorError> {
        let [decision, remaining @ ..] = record.receipts() else {
            return Err(ReceiptAttestorError::Invalid);
        };
        if remaining.len() > 1 {
            return Err(ReceiptAttestorError::Invalid);
        }
        self.verify(decision, Some(record.binding().profile()))?;
        let PortableReceipt::Decision { attested_decision } =
            decode_portable_receipt(decision.bytes()).map_err(|_| ReceiptAttestorError::Invalid)?
        else {
            return Err(ReceiptAttestorError::Invalid);
        };
        let decoded_decision = decode_attested_decision(&attested_decision)
            .map_err(|_| ReceiptAttestorError::Invalid)?;
        if decoded_decision.receipt().action_digest().as_bytes()
            != record.receipt_action_commitment()
            || decoded_decision.receipt().context_digest().as_bytes()
                != record.receipt_context_commitment()
            || decoded_decision.receipt().decision() != expected_decision(record)
            || decoded_decision.receipt().profile_claims() != expected_decision_profile_claims
        {
            return Err(ReceiptAttestorError::Invalid);
        }

        // `Executing/possible` immediately after the durable provider-entry
        // marker is a valid crash checkpoint with only the decision receipt.
        // The linked indeterminate execution receipt is required once the
        // operation advances to RecoveryRequired, and every terminal
        // provider-result state requires the pair.
        let execution_required = record.execution_outcome().is_some();
        let Some(execution) = remaining.first() else {
            return if execution_required || expected_execution_profile_claims.is_some() {
                Err(ReceiptAttestorError::Invalid)
            } else {
                Ok((decoded_decision.receipt().profile_claims().to_vec(), None))
            };
        };
        self.verify(execution, Some(record.binding().profile()))?;
        let PortableReceipt::Execution {
            attested_decision: linked_decision,
            attested_execution,
        } = decode_portable_receipt(execution.bytes())
            .map_err(|_| ReceiptAttestorError::Invalid)?
        else {
            return Err(ReceiptAttestorError::Invalid);
        };
        if linked_decision != attested_decision {
            return Err(ReceiptAttestorError::Invalid);
        }
        let decoded_execution = decode_attested_execution(&attested_execution)
            .map_err(|_| ReceiptAttestorError::Invalid)?;
        let expected_command = record
            .sealed_command()
            .map(Sha256::digest)
            .ok_or(ReceiptAttestorError::Invalid)?;
        let expected_result = record.execution_result_commitment().copied();
        let expected_lease =
            application_execution_lease_digest(record.operation_id().as_str(), None, None)
                .map_err(|_| ReceiptAttestorError::Invalid)?;
        if decoded_execution.receipt().execution_lease() != expected_lease
            || decoded_execution.receipt().command_digest().as_bytes()
                != expected_command.as_slice()
            || decoded_execution
                .receipt()
                .result_digest()
                .map(|value| *value.as_bytes())
                != expected_result
            || decoded_execution.receipt().outcome() != expected_execution(record)
            || Some(decoded_execution.receipt().profile_claims())
                != expected_execution_profile_claims
        {
            return Err(ReceiptAttestorError::Invalid);
        }
        Ok((
            decoded_decision.receipt().profile_claims().to_vec(),
            Some(decoded_execution.receipt().profile_claims().to_vec()),
        ))
    }
}

fn expected_decision(record: &JournalRecordV1) -> DecisionClass {
    match record.decision_class() {
        JournalDecisionClassV1::Authorized => DecisionClass::Authorized,
        JournalDecisionClassV1::Denied => DecisionClass::Denied,
        JournalDecisionClassV1::Indeterminate => DecisionClass::Indeterminate,
    }
}

fn expected_execution(record: &JournalRecordV1) -> ExecutionOutcome {
    match record.execution_outcome() {
        Some(auths_stores::JournalExecutionOutcomeV1::Succeeded) => ExecutionOutcome::Succeeded,
        Some(auths_stores::JournalExecutionOutcomeV1::Failed) => ExecutionOutcome::Failed,
        Some(auths_stores::JournalExecutionOutcomeV1::Indeterminate) => {
            ExecutionOutcome::Indeterminate
        }
        None => match record.projection().effect() {
            OperationEffectV1::Applied => ExecutionOutcome::Succeeded,
            OperationEffectV1::Possible => ExecutionOutcome::Indeterminate,
            OperationEffectV1::NotApplied => ExecutionOutcome::Failed,
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReceiptAttestorError {
    #[error("invalid local receipt")]
    Invalid,
}

fn model_profile(profile: &OperationProfileV1) -> Result<ProfileRef, ReceiptAttestorError> {
    ProfileRef::new(
        ProfileId::parse(profile.id()).map_err(|_| ReceiptAttestorError::Invalid)?,
        profile.version(),
    )
    .map_err(|_| ReceiptAttestorError::Invalid)
}

fn configured_signer(method: &str) -> Result<ReceiptSigner, ReceiptAttestorError> {
    let (principal, fragment) = method
        .rsplit_once('#')
        .ok_or(ReceiptAttestorError::Invalid)?;
    if fragment.is_empty() {
        return Err(ReceiptAttestorError::Invalid);
    }
    Ok(ReceiptSigner::new(
        PrincipalId::parse(principal).map_err(|_| ReceiptAttestorError::Invalid)?,
        VerificationMethod::parse(method).map_err(|_| ReceiptAttestorError::Invalid)?,
        SignatureSuiteId::parse("ed25519-v1").map_err(|_| ReceiptAttestorError::Invalid)?,
    ))
}

fn journal_receipt(bytes: Vec<u8>) -> Result<JournalReceiptV1, ReceiptAttestorError> {
    let id = portable_receipt_id(&bytes).map_err(|_| ReceiptAttestorError::Invalid)?;
    JournalReceiptV1::new(id, bytes).map_err(|_| ReceiptAttestorError::Invalid)
}

#[cfg(any(test, feature = "testkit-agent"))]
fn derive_seed(domain: &[u8], root: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(root);
    digest.finalize().into()
}

#[cfg(any(test, feature = "testkit-agent"))]
fn registered_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
