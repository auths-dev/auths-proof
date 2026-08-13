//! Canonical decision and execution receipts for target V1.

#![forbid(unsafe_code)]

mod disclosure;

pub use disclosure::{
    ReceiptDisclosure, ReceiptDisclosureLocator, ReceiptDisclosureProtector,
    ReceiptDisclosureStore, ReceiptInspection, ReceiptInspectionError, ReceiptProfileInspector,
    ReceiptProjection, ReceiptViewMode, VerifiedReceiptMetadata, decode_receipt_disclosure,
    encode_receipt_disclosure, inspect_attested_execution_receipt,
};

use auths_model::{
    CanonicalAction, ContextDigest, Digest, PROTOCOL_V1, PrincipalId, ProfileRef, ReceiptId,
    SignatureBytes, SignatureSuiteId, StatusSnapshotId, Timestamp, VerificationMethod,
    VerifierContext,
};
use auths_ports::{SignatureInput, SignatureSuite};
use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};
use std::fmt;

const IDENTIFIER_PREFIX: &[u8] = b"AUTHS-ID";
const DECISION_ID_TYPE: u16 = 7;
const EXECUTION_ID_TYPE: u16 = 8;
const AUDIT_BUNDLE_ID_TYPE: u16 = 9;
const MAX_REASON_COUNT: usize = 32;
const MAX_REASON_BYTES: usize = 128;
const MAX_AUDIT_EXECUTIONS: usize = 64;
const MAX_AUDIT_ARTIFACTS: usize = 64;
const MAX_AUDIT_BYTES: usize = 16 * 1024 * 1024;
const DECISION_SIGNATURE_DOMAIN: &[u8] = b"AUTHS-DECISION-RECEIPT\x00\x01";
const EXECUTION_SIGNATURE_DOMAIN: &[u8] = b"AUTHS-EXECUTION-RECEIPT\x00\x01";
const APPLICATION_EXECUTION_LEASE_DOMAIN: &[u8] = b"AUTHS-APPLICATION-EXECUTION-LEASE\x00\x01";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Canonical receipt bytes and the exact attestation preimage that binds them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedReceipt {
    id: ReceiptId,
    canonical: Vec<u8>,
    signing_preimage: Vec<u8>,
}

impl PreparedReceipt {
    /// Returns the deterministic inner receipt identifier.
    #[must_use]
    pub const fn id(&self) -> ReceiptId {
        self.id
    }

    /// Returns the canonical unattested receipt bytes.
    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the exact domain-separated bytes the attestor must sign.
    #[must_use]
    pub fn signing_preimage(&self) -> &[u8] {
        &self.signing_preimage
    }
}

/// Prepares an Auths decision receipt from the exact verified inputs.
///
/// Callers must parse and canonicality-check the inputs before invoking this
/// function. The receipt shape and every digest remain Rust-owned.
///
/// # Errors
///
/// Returns a typed receipt error for invalid reason or encoding inputs.
pub fn prepare_decision_receipt(
    authority_commitment: Digest,
    action: &CanonicalAction,
    context: &VerifierContext,
    decision: DecisionClass,
    reasons: Vec<String>,
    decided_at: Timestamp,
    signer: &ReceiptSigner,
) -> Result<PreparedReceipt, ReceiptError> {
    let canonical_action =
        auths_codec::encode_canonical_action(action).map_err(|_| ReceiptError::Malformed)?;
    let receipt = DecisionReceipt::new(
        authority_commitment,
        auths_codec::domain_commitment("auths.canonical-action.v1", &canonical_action)
            .map_err(|_| ReceiptError::Malformed)?,
        auths_codec::context_digest(context).map_err(|_| ReceiptError::Malformed)?,
        context.principal_status_snapshot().id(),
        context.grant_status_snapshot().id(),
        action.profile().clone(),
        decision,
        reasons,
        decided_at,
    )?;
    let id = decision_receipt_id(&receipt)?;
    Ok(PreparedReceipt {
        id,
        canonical: encode_decision(&receipt)?,
        signing_preimage: decision_signing_preimage(&receipt, signer)?,
    })
}

/// Derives one canonical application execution lease from its exact replay
/// identity and ordered plan position.
///
/// # Errors
///
/// Returns a limit or malformed error for an invalid idempotency key or plan
/// member projection.
pub fn application_execution_lease_digest(
    idempotency_key: &str,
    plan_commitment: Option<Digest>,
    member: Option<(u16, u16)>,
) -> Result<Digest, ReceiptError> {
    let key = idempotency_key.as_bytes();
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(ReceiptError::LimitExceeded);
    }
    if member.is_some_and(|(index, count)| count == 0 || index >= count)
        || plan_commitment.is_some() != member.is_some()
    {
        return Err(ReceiptError::Malformed);
    }
    let mut hasher = Sha256::new();
    hasher.update(APPLICATION_EXECUTION_LEASE_DOMAIN);
    hasher.update(
        u64::try_from(key.len())
            .map_err(|_| ReceiptError::LimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(key);
    match (plan_commitment, member) {
        (Some(plan), Some((index, count))) => {
            hasher.update([1]);
            hasher.update(plan.as_bytes());
            hasher.update(index.to_be_bytes());
            hasher.update(count.to_be_bytes());
        }
        (None, None) => hasher.update([0]),
        _ => return Err(ReceiptError::Malformed),
    }
    Ok(Digest::new(hasher.finalize().into()))
}

/// Prepares an Auths execution receipt for one exact decision and command.
///
/// # Errors
///
/// Returns a typed receipt error for invalid execution identity or encoding.
#[allow(clippy::too_many_arguments)]
pub fn prepare_execution_receipt(
    decision_receipt: ReceiptId,
    idempotency_key: &str,
    plan_commitment: Option<Digest>,
    member: Option<(u16, u16)>,
    command_bytes: &[u8],
    outcome: ExecutionOutcome,
    result: Option<&[u8]>,
    completed_at: Timestamp,
    signer: &ReceiptSigner,
) -> Result<PreparedReceipt, ReceiptError> {
    let receipt = ExecutionReceipt::new(
        decision_receipt,
        application_execution_lease_digest(idempotency_key, plan_commitment, member)?,
        raw_digest(command_bytes),
        outcome,
        result.map(raw_digest),
        completed_at,
    );
    let id = execution_receipt_id(&receipt)?;
    Ok(PreparedReceipt {
        id,
        canonical: encode_execution(&receipt)?,
        signing_preimage: execution_signing_preimage(&receipt, signer)?,
    })
}

fn raw_digest(bytes: &[u8]) -> Digest {
    Digest::new(Sha256::digest(bytes).into())
}

/// Stable decision class recorded by the pure verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionClass {
    /// Complete authorization.
    Authorized,
    /// Facts establish invalidity or insufficient authority.
    Denied,
    /// A required trustworthy fact is unavailable.
    Indeterminate,
}

/// Canonical public decision record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionReceipt {
    proof_digest: Digest,
    action_digest: Digest,
    context_digest: ContextDigest,
    principal_status: StatusSnapshotId,
    grant_status: StatusSnapshotId,
    profile: ProfileRef,
    decision: DecisionClass,
    reasons: Vec<String>,
    decided_at: Timestamp,
}

impl DecisionReceipt {
    /// Constructs a bounded decision record.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an empty, excessive, malformed, or duplicate
    /// reason sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_digest: Digest,
        action_digest: Digest,
        context_digest: ContextDigest,
        principal_status: StatusSnapshotId,
        grant_status: StatusSnapshotId,
        profile: ProfileRef,
        decision: DecisionClass,
        reasons: Vec<String>,
        decided_at: Timestamp,
    ) -> Result<Self, ReceiptError> {
        validate_reasons(&reasons)?;
        Ok(Self {
            proof_digest,
            action_digest,
            context_digest,
            principal_status,
            grant_status,
            profile,
            decision,
            reasons,
            decided_at,
        })
    }

    /// Returns the proof digest.
    #[must_use]
    pub const fn proof_digest(&self) -> Digest {
        self.proof_digest
    }

    /// Returns the action body digest.
    #[must_use]
    pub const fn action_digest(&self) -> Digest {
        self.action_digest
    }

    /// Returns the public verifier-context digest.
    #[must_use]
    pub const fn context_digest(&self) -> ContextDigest {
        self.context_digest
    }

    /// Returns the principal-status snapshot identifier.
    #[must_use]
    pub const fn principal_status(&self) -> StatusSnapshotId {
        self.principal_status
    }

    /// Returns the grant-status snapshot identifier.
    #[must_use]
    pub const fn grant_status(&self) -> StatusSnapshotId {
        self.grant_status
    }

    /// Returns the application profile.
    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    /// Returns the decision class.
    #[must_use]
    pub const fn decision(&self) -> DecisionClass {
        self.decision
    }

    /// Returns ordered stable reason codes.
    #[must_use]
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Returns the decision time.
    #[must_use]
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }
}

/// Execution outcome recorded separately from authority validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    /// Command completed successfully.
    Succeeded,
    /// Authorized command failed during execution.
    Failed,
}

/// Canonical execution record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    decision_receipt: ReceiptId,
    execution_lease: Digest,
    command_digest: Digest,
    outcome: ExecutionOutcome,
    result_digest: Option<Digest>,
    completed_at: Timestamp,
}

impl ExecutionReceipt {
    /// Constructs an execution record.
    #[must_use]
    pub const fn new(
        decision_receipt: ReceiptId,
        execution_lease: Digest,
        command_digest: Digest,
        outcome: ExecutionOutcome,
        result_digest: Option<Digest>,
        completed_at: Timestamp,
    ) -> Self {
        Self {
            decision_receipt,
            execution_lease,
            command_digest,
            outcome,
            result_digest,
            completed_at,
        }
    }

    /// Returns the decision receipt identifier.
    #[must_use]
    pub const fn decision_receipt(&self) -> ReceiptId {
        self.decision_receipt
    }

    /// Returns the execution lease identifier.
    #[must_use]
    pub const fn execution_lease(&self) -> Digest {
        self.execution_lease
    }

    /// Returns the verified command digest.
    #[must_use]
    pub const fn command_digest(&self) -> Digest {
        self.command_digest
    }

    /// Returns the execution outcome.
    #[must_use]
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    /// Returns the optional result digest.
    #[must_use]
    pub const fn result_digest(&self) -> Option<Digest> {
        self.result_digest
    }

    /// Returns the completion time.
    #[must_use]
    pub const fn completed_at(&self) -> Timestamp {
        self.completed_at
    }
}

/// Public identity and key reference used to attest receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptSigner {
    verifier: PrincipalId,
    verification_method: VerificationMethod,
    suite: SignatureSuiteId,
}

impl ReceiptSigner {
    /// Constructs an explicit receipt signer descriptor.
    #[must_use]
    pub const fn new(
        verifier: PrincipalId,
        verification_method: VerificationMethod,
        suite: SignatureSuiteId,
    ) -> Self {
        Self {
            verifier,
            verification_method,
            suite,
        }
    }

    /// Returns the verifier making the receipt claim.
    #[must_use]
    pub const fn verifier(&self) -> &PrincipalId {
        &self.verifier
    }

    /// Returns the verifier-local key identifier.
    #[must_use]
    pub const fn verification_method(&self) -> &VerificationMethod {
        &self.verification_method
    }

    /// Returns the registered signature suite.
    #[must_use]
    pub const fn suite(&self) -> &SignatureSuiteId {
        &self.suite
    }
}

/// Canonical decision receipt plus verifier attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedDecisionReceipt {
    receipt: DecisionReceipt,
    signer: ReceiptSigner,
    signature: SignatureBytes,
}

impl AttestedDecisionReceipt {
    /// Binds a verifier signature to one exact decision receipt.
    #[must_use]
    pub const fn new(
        receipt: DecisionReceipt,
        signer: ReceiptSigner,
        signature: SignatureBytes,
    ) -> Self {
        Self {
            receipt,
            signer,
            signature,
        }
    }

    /// Returns the attested decision.
    #[must_use]
    pub const fn receipt(&self) -> &DecisionReceipt {
        &self.receipt
    }

    /// Returns the verifier signer descriptor.
    #[must_use]
    pub const fn signer(&self) -> &ReceiptSigner {
        &self.signer
    }

    /// Returns the verifier signature.
    #[must_use]
    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

/// Canonical execution receipt plus executor/verifier attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedExecutionReceipt {
    receipt: ExecutionReceipt,
    signer: ReceiptSigner,
    signature: SignatureBytes,
}

impl AttestedExecutionReceipt {
    /// Binds a verifier signature to one exact execution receipt.
    #[must_use]
    pub const fn new(
        receipt: ExecutionReceipt,
        signer: ReceiptSigner,
        signature: SignatureBytes,
    ) -> Self {
        Self {
            receipt,
            signer,
            signature,
        }
    }

    /// Returns the attested execution.
    #[must_use]
    pub const fn receipt(&self) -> &ExecutionReceipt {
        &self.receipt
    }

    /// Returns the verifier signer descriptor.
    #[must_use]
    pub const fn signer(&self) -> &ReceiptSigner {
        &self.signer
    }

    /// Returns the verifier signature.
    #[must_use]
    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

/// Verifies receipt signatures using verifier-local key configuration.
pub trait ReceiptSignatureVerifier {
    /// Verifies one exact domain-separated signing preimage.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for an unknown signer, suite, key, or invalid
    /// signature.
    fn verify(
        &self,
        signer: &ReceiptSigner,
        signing_preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ReceiptError>;
}

/// Verifier-local receipt key bound to one registered signature suite.
pub struct ConfiguredReceiptVerifier<'a> {
    expected_signer: ReceiptSigner,
    verification_key: &'a [u8],
    suite: &'a dyn SignatureSuite,
}

impl<'a> ConfiguredReceiptVerifier<'a> {
    /// Binds one expected signer descriptor to public verification key bytes
    /// and an executable registered suite.
    #[must_use]
    pub const fn new(
        expected_signer: ReceiptSigner,
        verification_key: &'a [u8],
        suite: &'a dyn SignatureSuite,
    ) -> Self {
        Self {
            expected_signer,
            verification_key,
            suite,
        }
    }
}

impl ReceiptSignatureVerifier for ConfiguredReceiptVerifier<'_> {
    fn verify(
        &self,
        signer: &ReceiptSigner,
        signing_preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ReceiptError> {
        if signer != &self.expected_signer || signer.suite() != self.suite.id() {
            return Err(ReceiptError::UnexpectedSigner);
        }
        self.suite
            .verify(SignatureInput {
                verification_key: self.verification_key,
                signing_preimage,
                signature,
            })
            .map_err(|_| ReceiptError::InvalidSignature)
    }
}

/// Encodes a unique deterministic decision receipt.
///
/// # Errors
///
/// Returns a typed error only for an in-memory encoding invariant.
pub fn encode_decision(receipt: &DecisionReceipt) -> Result<Vec<u8>, ReceiptError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(11).map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 0)?;
    encoder
        .u16(PROTOCOL_V1)
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, receipt.proof_digest.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, receipt.action_digest.as_bytes())?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, receipt.context_digest.as_bytes())?;
    key(&mut encoder, 4)?;
    bytes(&mut encoder, receipt.principal_status.as_bytes())?;
    key(&mut encoder, 5)?;
    bytes(&mut encoder, receipt.grant_status.as_bytes())?;
    key(&mut encoder, 6)?;
    encoder
        .str(receipt.profile.id().as_str())
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 7)?;
    encoder
        .u16(receipt.profile.version())
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 8)?;
    encoder
        .u8(match receipt.decision {
            DecisionClass::Authorized => 0,
            DecisionClass::Denied => 1,
            DecisionClass::Indeterminate => 2,
        })
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 9)?;
    encoder
        .array(u64::try_from(receipt.reasons.len()).map_err(|_| ReceiptError::LimitExceeded)?)
        .map_err(|_| ReceiptError::Malformed)?;
    for reason in &receipt.reasons {
        encoder.str(reason).map_err(|_| ReceiptError::Malformed)?;
    }
    key(&mut encoder, 10)?;
    encoder
        .u64(receipt.decided_at.get())
        .map_err(|_| ReceiptError::Malformed)?;
    Ok(encoder.into_writer())
}

/// Encodes a unique deterministic execution receipt.
///
/// # Errors
///
/// Returns a typed error only for an in-memory encoding invariant.
pub fn encode_execution(receipt: &ExecutionReceipt) -> Result<Vec<u8>, ReceiptError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(7).map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 0)?;
    encoder
        .u16(PROTOCOL_V1)
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, receipt.decision_receipt.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, receipt.execution_lease.as_bytes())?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, receipt.command_digest.as_bytes())?;
    key(&mut encoder, 4)?;
    encoder
        .u8(match receipt.outcome {
            ExecutionOutcome::Succeeded => 0,
            ExecutionOutcome::Failed => 1,
        })
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 5)?;
    if let Some(digest) = receipt.result_digest {
        bytes(&mut encoder, digest.as_bytes())?;
    } else {
        encoder.null().map_err(|_| ReceiptError::Malformed)?;
    }
    key(&mut encoder, 6)?;
    encoder
        .u64(receipt.completed_at.get())
        .map_err(|_| ReceiptError::Malformed)?;
    Ok(encoder.into_writer())
}

/// Produces the exact domain-separated decision-receipt signing preimage.
///
/// # Errors
///
/// Returns a typed error if deterministic receipt encoding fails.
pub fn decision_signing_preimage(
    receipt: &DecisionReceipt,
    signer: &ReceiptSigner,
) -> Result<Vec<u8>, ReceiptError> {
    signing_preimage(
        DECISION_SIGNATURE_DOMAIN,
        signer,
        &encode_decision(receipt)?,
    )
}

/// Produces the exact domain-separated execution-receipt signing preimage.
///
/// # Errors
///
/// Returns a typed error if deterministic receipt encoding fails.
pub fn execution_signing_preimage(
    receipt: &ExecutionReceipt,
    signer: &ReceiptSigner,
) -> Result<Vec<u8>, ReceiptError> {
    signing_preimage(
        EXECUTION_SIGNATURE_DOMAIN,
        signer,
        &encode_execution(receipt)?,
    )
}

/// Encodes a canonical verifier-attested decision receipt.
///
/// # Errors
///
/// Returns a typed error if deterministic encoding fails.
pub fn encode_attested_decision(
    receipt: &AttestedDecisionReceipt,
) -> Result<Vec<u8>, ReceiptError> {
    encode_attested(
        0,
        &encode_decision(&receipt.receipt)?,
        &receipt.signer,
        &receipt.signature,
    )
}

/// Encodes a canonical verifier-attested execution receipt.
///
/// # Errors
///
/// Returns a typed error if deterministic encoding fails.
pub fn encode_attested_execution(
    receipt: &AttestedExecutionReceipt,
) -> Result<Vec<u8>, ReceiptError> {
    encode_attested(
        1,
        &encode_execution(&receipt.receipt)?,
        &receipt.signer,
        &receipt.signature,
    )
}

/// Decodes and canonicality-checks an attested decision receipt.
///
/// This validates structure and the content identifier. Use
/// [`verify_decision_attestation`] with verifier-local keys to establish
/// authenticity.
///
/// # Errors
///
/// Returns a typed error for malformed, non-canonical, or mismatched bytes.
pub fn decode_attested_decision(input: &[u8]) -> Result<AttestedDecisionReceipt, ReceiptError> {
    let (kind, payload, signer, signature) = decode_attested(input)?;
    if kind != 0 {
        return Err(ReceiptError::Malformed);
    }
    let receipt = decode_decision(&payload)?;
    let attested = AttestedDecisionReceipt::new(receipt, signer, signature);
    if encode_attested_decision(&attested)?.as_slice() != input {
        return Err(ReceiptError::NonCanonical);
    }
    Ok(attested)
}

/// Decodes and canonicality-checks an attested execution receipt.
///
/// This validates structure and the content identifier. Use
/// [`verify_execution_attestation`] with verifier-local keys to establish
/// authenticity.
///
/// # Errors
///
/// Returns a typed error for malformed, non-canonical, or mismatched bytes.
pub fn decode_attested_execution(input: &[u8]) -> Result<AttestedExecutionReceipt, ReceiptError> {
    let (kind, payload, signer, signature) = decode_attested(input)?;
    if kind != 1 {
        return Err(ReceiptError::Malformed);
    }
    let receipt = decode_execution(&payload)?;
    let attested = AttestedExecutionReceipt::new(receipt, signer, signature);
    if encode_attested_execution(&attested)?.as_slice() != input {
        return Err(ReceiptError::NonCanonical);
    }
    Ok(attested)
}

/// Verifies an attested decision receipt under verifier-local signer policy.
///
/// # Errors
///
/// Returns a typed error for invalid receipt bytes, unexpected verifier
/// identity, or invalid signature.
pub fn verify_decision_attestation(
    input: &[u8],
    expected: ReceiptId,
    expected_verifier: &PrincipalId,
    verifier: &dyn ReceiptSignatureVerifier,
) -> Result<AttestedDecisionReceipt, ReceiptError> {
    let attested = verify_attested_decision_bytes(input, expected)?;
    if attested.signer.verifier() != expected_verifier {
        return Err(ReceiptError::UnexpectedSigner);
    }
    verifier.verify(
        &attested.signer,
        &decision_signing_preimage(&attested.receipt, &attested.signer)?,
        attested.signature.as_slice(),
    )?;
    Ok(attested)
}

/// Verifies an attested execution receipt under verifier-local signer policy.
///
/// # Errors
///
/// Returns a typed error for invalid receipt bytes, unexpected verifier
/// identity, or invalid signature.
pub fn verify_execution_attestation(
    input: &[u8],
    expected: ReceiptId,
    expected_verifier: &PrincipalId,
    verifier: &dyn ReceiptSignatureVerifier,
) -> Result<AttestedExecutionReceipt, ReceiptError> {
    let attested = verify_attested_execution_bytes(input, expected)?;
    if attested.signer.verifier() != expected_verifier {
        return Err(ReceiptError::UnexpectedSigner);
    }
    verifier.verify(
        &attested.signer,
        &execution_signing_preimage(&attested.receipt, &attested.signer)?,
        attested.signature.as_slice(),
    )?;
    Ok(attested)
}

/// Decodes and canonicality-checks a decision receipt.
///
/// # Errors
///
/// Returns a typed error for malformed, unsupported, over-limit, or
/// non-canonical bytes.
pub fn decode_decision(input: &[u8]) -> Result<DecisionReceipt, ReceiptError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, 11)?;
    key_decode(&mut decoder, 0)?;
    version(&mut decoder)?;
    key_decode(&mut decoder, 1)?;
    let proof = Digest::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 2)?;
    let action = Digest::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 3)?;
    let context = ContextDigest::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 4)?;
    let principal_status = StatusSnapshotId::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 5)?;
    let grant_status = StatusSnapshotId::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 6)?;
    let profile_id =
        auths_model::ProfileId::parse(decoder.str().map_err(|_| ReceiptError::Malformed)?)
            .map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 7)?;
    let profile = ProfileRef::new(
        profile_id,
        decoder.u16().map_err(|_| ReceiptError::Malformed)?,
    )
    .map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 8)?;
    let decision = match decoder.u8().map_err(|_| ReceiptError::Malformed)? {
        0 => DecisionClass::Authorized,
        1 => DecisionClass::Denied,
        2 => DecisionClass::Indeterminate,
        _ => return Err(ReceiptError::Malformed),
    };
    key_decode(&mut decoder, 9)?;
    let count = decoder
        .array()
        .map_err(|_| ReceiptError::Malformed)?
        .ok_or(ReceiptError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| ReceiptError::LimitExceeded)?;
    if count > MAX_REASON_COUNT {
        return Err(ReceiptError::LimitExceeded);
    }
    let mut reasons = Vec::with_capacity(count);
    for _ in 0..count {
        reasons.push(
            decoder
                .str()
                .map_err(|_| ReceiptError::Malformed)?
                .to_owned(),
        );
    }
    key_decode(&mut decoder, 10)?;
    let decided_at = Timestamp::new(decoder.u64().map_err(|_| ReceiptError::Malformed)?);
    finish(&decoder, input)?;
    let receipt = DecisionReceipt::new(
        proof,
        action,
        context,
        principal_status,
        grant_status,
        profile,
        decision,
        reasons,
        decided_at,
    )?;
    if encode_decision(&receipt)?.as_slice() != input {
        return Err(ReceiptError::NonCanonical);
    }
    Ok(receipt)
}

/// Decodes and canonicality-checks an execution receipt.
///
/// # Errors
///
/// Returns a typed error for malformed, unsupported, or non-canonical bytes.
pub fn decode_execution(input: &[u8]) -> Result<ExecutionReceipt, ReceiptError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, 7)?;
    key_decode(&mut decoder, 0)?;
    version(&mut decoder)?;
    key_decode(&mut decoder, 1)?;
    let decision = ReceiptId::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 2)?;
    let lease = Digest::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 3)?;
    let command = Digest::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 4)?;
    let outcome = match decoder.u8().map_err(|_| ReceiptError::Malformed)? {
        0 => ExecutionOutcome::Succeeded,
        1 => ExecutionOutcome::Failed,
        _ => return Err(ReceiptError::Malformed),
    };
    key_decode(&mut decoder, 5)?;
    let result = if decoder.datatype().map_err(|_| ReceiptError::Malformed)? == Type::Null {
        decoder.null().map_err(|_| ReceiptError::Malformed)?;
        None
    } else {
        Some(Digest::new(digest(&mut decoder)?))
    };
    key_decode(&mut decoder, 6)?;
    let completed_at = Timestamp::new(decoder.u64().map_err(|_| ReceiptError::Malformed)?);
    finish(&decoder, input)?;
    let receipt = ExecutionReceipt::new(decision, lease, command, outcome, result, completed_at);
    if encode_execution(&receipt)?.as_slice() != input {
        return Err(ReceiptError::NonCanonical);
    }
    Ok(receipt)
}

/// Derives the canonical decision receipt identifier.
///
/// # Errors
///
/// Returns a typed error if deterministic encoding fails.
pub fn decision_receipt_id(receipt: &DecisionReceipt) -> Result<ReceiptId, ReceiptError> {
    Ok(ReceiptId::from_digest(domain_hash(
        DECISION_ID_TYPE,
        &encode_decision(receipt)?,
    )?))
}

/// Derives the canonical execution receipt identifier.
///
/// # Errors
///
/// Returns a typed error if deterministic encoding fails.
pub fn execution_receipt_id(receipt: &ExecutionReceipt) -> Result<ReceiptId, ReceiptError> {
    Ok(ReceiptId::from_digest(domain_hash(
        EXECUTION_ID_TYPE,
        &encode_execution(receipt)?,
    )?))
}

/// Verifies exact receipt bytes against an expected identifier.
///
/// # Errors
///
/// Returns [`ReceiptError::DigestMismatch`] for any canonical receipt with a
/// different identifier.
pub fn verify_decision_bytes(
    input: &[u8],
    expected: ReceiptId,
) -> Result<DecisionReceipt, ReceiptError> {
    let receipt = decode_decision(input)?;
    if decision_receipt_id(&receipt)? != expected {
        return Err(ReceiptError::DigestMismatch);
    }
    Ok(receipt)
}

/// Verifies exact execution-receipt bytes against an expected identifier.
///
/// # Errors
///
/// Returns [`ReceiptError::DigestMismatch`] for any canonical receipt with a
/// different identifier.
pub fn verify_execution_bytes(
    input: &[u8],
    expected: ReceiptId,
) -> Result<ExecutionReceipt, ReceiptError> {
    let receipt = decode_execution(input)?;
    if execution_receipt_id(&receipt)? != expected {
        return Err(ReceiptError::DigestMismatch);
    }
    Ok(receipt)
}

/// Verifies canonical attested decision bytes against the inner receipt ID.
///
/// This is a structural/content-address check and does not establish signer
/// authenticity.
///
/// # Errors
///
/// Returns a typed canonicality or identifier mismatch.
pub fn verify_attested_decision_bytes(
    input: &[u8],
    expected: ReceiptId,
) -> Result<AttestedDecisionReceipt, ReceiptError> {
    let receipt = decode_attested_decision(input)?;
    if decision_receipt_id(receipt.receipt())? != expected {
        return Err(ReceiptError::DigestMismatch);
    }
    Ok(receipt)
}

/// Verifies canonical attested execution bytes against the inner receipt ID.
///
/// This is a structural/content-address check and does not establish signer
/// authenticity.
///
/// # Errors
///
/// Returns a typed canonicality or identifier mismatch.
pub fn verify_attested_execution_bytes(
    input: &[u8],
    expected: ReceiptId,
) -> Result<AttestedExecutionReceipt, ReceiptError> {
    let receipt = decode_attested_execution(input)?;
    if execution_receipt_id(receipt.receipt())? != expected {
        return Err(ReceiptError::DigestMismatch);
    }
    Ok(receipt)
}

/// One optionally disclosed artifact in a minimized audit export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditArtifact {
    media_type: String,
    digest: Digest,
    bytes: Option<Vec<u8>>,
}

impl AuditArtifact {
    /// Constructs a disclosed artifact and computes its exact digest.
    ///
    /// # Errors
    ///
    /// Returns a limit error for an empty, oversized, or malformed media
    /// type or for an oversized disclosure.
    pub fn disclosed(media_type: impl Into<String>, bytes: Vec<u8>) -> Result<Self, ReceiptError> {
        let media_type = media_type.into();
        validate_audit_media_type(&media_type)?;
        if bytes.len() > MAX_AUDIT_BYTES {
            return Err(ReceiptError::LimitExceeded);
        }
        Ok(Self {
            media_type,
            digest: Digest::new(Sha256::digest(&bytes).into()),
            bytes: Some(bytes),
        })
    }

    /// Constructs a digest-only redacted artifact.
    ///
    /// # Errors
    ///
    /// Returns a limit error for a malformed media type.
    pub fn redacted(media_type: impl Into<String>, digest: Digest) -> Result<Self, ReceiptError> {
        let media_type = media_type.into();
        validate_audit_media_type(&media_type)?;
        Ok(Self {
            media_type,
            digest,
            bytes: None,
        })
    }

    /// Returns the artifact media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the committed artifact digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns disclosed bytes, or `None` for a redacted artifact.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

/// Portable, minimized decision and execution audit export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditBundle {
    decision_id: ReceiptId,
    decision: Vec<u8>,
    executions: Vec<(ReceiptId, Vec<u8>)>,
    artifacts: Vec<AuditArtifact>,
}

impl AuditBundle {
    /// Constructs a canonical audit bundle from exact receipt bytes.
    ///
    /// Every execution receipt must refer to `decision_id`; disclosed
    /// artifacts must match their digest. Collections are sorted and
    /// duplicate identifiers are rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed receipt, linkage, duplicate, or resource-limit error.
    pub fn new(
        decision_id: ReceiptId,
        decision: Vec<u8>,
        mut executions: Vec<(ReceiptId, Vec<u8>)>,
        mut artifacts: Vec<AuditArtifact>,
    ) -> Result<Self, ReceiptError> {
        verify_attested_decision_bytes(&decision, decision_id)?;
        if executions.len() > MAX_AUDIT_EXECUTIONS || artifacts.len() > MAX_AUDIT_ARTIFACTS {
            return Err(ReceiptError::LimitExceeded);
        }
        executions.sort_by_key(|entry| entry.0);
        if executions
            .windows(2)
            .any(|window| window[0].0 == window[1].0)
        {
            return Err(ReceiptError::Duplicate);
        }
        for (id, bytes) in &executions {
            let receipt = verify_attested_execution_bytes(bytes, *id)?;
            if receipt.receipt().decision_receipt() != decision_id {
                return Err(ReceiptError::LinkageMismatch);
            }
        }
        artifacts.sort_by(|left, right| {
            left.digest
                .cmp(&right.digest)
                .then_with(|| left.media_type.cmp(&right.media_type))
        });
        if artifacts
            .windows(2)
            .any(|window| window[0].digest == window[1].digest)
        {
            return Err(ReceiptError::Duplicate);
        }
        if artifacts.iter().any(|artifact| {
            artifact
                .bytes
                .as_ref()
                .is_some_and(|bytes| Digest::new(Sha256::digest(bytes).into()) != artifact.digest)
        }) {
            return Err(ReceiptError::DigestMismatch);
        }
        let total = executions.iter().try_fold(decision.len(), |total, entry| {
            total
                .checked_add(entry.1.len())
                .ok_or(ReceiptError::LimitExceeded)
        })?;
        let total = artifacts.iter().try_fold(total, |total, artifact| {
            total
                .checked_add(artifact.bytes.as_ref().map_or(0, Vec::len))
                .ok_or(ReceiptError::LimitExceeded)
        })?;
        if total > MAX_AUDIT_BYTES {
            return Err(ReceiptError::LimitExceeded);
        }
        Ok(Self {
            decision_id,
            decision,
            executions,
            artifacts,
        })
    }

    /// Returns the root decision receipt identifier.
    #[must_use]
    pub const fn decision_id(&self) -> ReceiptId {
        self.decision_id
    }

    /// Returns exact canonical decision receipt bytes.
    #[must_use]
    pub fn decision_bytes(&self) -> &[u8] {
        &self.decision
    }

    /// Returns canonical execution receipt entries.
    #[must_use]
    pub fn executions(&self) -> &[(ReceiptId, Vec<u8>)] {
        &self.executions
    }

    /// Returns sorted disclosed or redacted artifacts.
    #[must_use]
    pub fn artifacts(&self) -> &[AuditArtifact] {
        &self.artifacts
    }
}

/// Encodes a unique deterministic audit bundle.
///
/// # Errors
///
/// Returns a typed encoding or resource-limit failure.
pub fn encode_audit_bundle(bundle: &AuditBundle) -> Result<Vec<u8>, ReceiptError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 0)?;
    encoder
        .u16(PROTOCOL_V1)
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, bundle.decision_id.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, &bundle.decision)?;
    key(&mut encoder, 3)?;
    encoder
        .array(u64::try_from(bundle.executions.len()).map_err(|_| ReceiptError::LimitExceeded)?)
        .map_err(|_| ReceiptError::Malformed)?;
    for (id, receipt) in &bundle.executions {
        encoder.array(2).map_err(|_| ReceiptError::Malformed)?;
        bytes(&mut encoder, id.as_bytes())?;
        bytes(&mut encoder, receipt)?;
    }
    key(&mut encoder, 4)?;
    encoder
        .array(u64::try_from(bundle.artifacts.len()).map_err(|_| ReceiptError::LimitExceeded)?)
        .map_err(|_| ReceiptError::Malformed)?;
    for artifact in &bundle.artifacts {
        encoder.array(3).map_err(|_| ReceiptError::Malformed)?;
        encoder
            .str(&artifact.media_type)
            .map_err(|_| ReceiptError::Malformed)?;
        bytes(&mut encoder, artifact.digest.as_bytes())?;
        if let Some(disclosed) = &artifact.bytes {
            bytes(&mut encoder, disclosed)?;
        } else {
            encoder.null().map_err(|_| ReceiptError::Malformed)?;
        }
    }
    let output = encoder.into_writer();
    if output.len() > MAX_AUDIT_BYTES {
        return Err(ReceiptError::LimitExceeded);
    }
    Ok(output)
}

/// Decodes, canonicality-checks, and verifies all receipt links in an audit
/// bundle.
///
/// # Errors
///
/// Returns a typed failure for malformed, non-canonical, over-limit,
/// digest-mismatched, or incorrectly linked contents.
pub fn decode_audit_bundle(input: &[u8]) -> Result<AuditBundle, ReceiptError> {
    if input.len() > MAX_AUDIT_BYTES {
        return Err(ReceiptError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, 5)?;
    key_decode(&mut decoder, 0)?;
    version(&mut decoder)?;
    key_decode(&mut decoder, 1)?;
    let decision_id = ReceiptId::new(digest(&mut decoder)?);
    key_decode(&mut decoder, 2)?;
    let decision = decoder
        .bytes()
        .map_err(|_| ReceiptError::Malformed)?
        .to_vec();
    key_decode(&mut decoder, 3)?;
    let execution_count = definite_array(&mut decoder, MAX_AUDIT_EXECUTIONS)?;
    let mut executions = Vec::with_capacity(execution_count);
    for _ in 0..execution_count {
        if decoder.array().map_err(|_| ReceiptError::Malformed)? != Some(2) {
            return Err(ReceiptError::Malformed);
        }
        let id = ReceiptId::new(digest(&mut decoder)?);
        let receipt = decoder
            .bytes()
            .map_err(|_| ReceiptError::Malformed)?
            .to_vec();
        executions.push((id, receipt));
    }
    key_decode(&mut decoder, 4)?;
    let artifact_count = definite_array(&mut decoder, MAX_AUDIT_ARTIFACTS)?;
    let mut artifacts = Vec::with_capacity(artifact_count);
    for _ in 0..artifact_count {
        if decoder.array().map_err(|_| ReceiptError::Malformed)? != Some(3) {
            return Err(ReceiptError::Malformed);
        }
        let media_type = decoder
            .str()
            .map_err(|_| ReceiptError::Malformed)?
            .to_owned();
        let artifact_digest = Digest::new(digest(&mut decoder)?);
        let disclosed = if decoder.datatype().map_err(|_| ReceiptError::Malformed)? == Type::Null {
            decoder.null().map_err(|_| ReceiptError::Malformed)?;
            None
        } else {
            Some(
                decoder
                    .bytes()
                    .map_err(|_| ReceiptError::Malformed)?
                    .to_vec(),
            )
        };
        validate_audit_media_type(&media_type)?;
        artifacts.push(AuditArtifact {
            media_type,
            digest: artifact_digest,
            bytes: disclosed,
        });
    }
    finish(&decoder, input)?;
    let bundle = AuditBundle::new(decision_id, decision, executions, artifacts)?;
    if encode_audit_bundle(&bundle)?.as_slice() != input {
        return Err(ReceiptError::NonCanonical);
    }
    Ok(bundle)
}

/// Derives the deterministic audit-bundle identifier.
///
/// # Errors
///
/// Returns a typed error if deterministic encoding fails.
pub fn audit_bundle_id(bundle: &AuditBundle) -> Result<Digest, ReceiptError> {
    domain_hash(AUDIT_BUNDLE_ID_TYPE, &encode_audit_bundle(bundle)?)
}

fn signing_preimage(
    domain: &[u8],
    signer: &ReceiptSigner,
    canonical_receipt: &[u8],
) -> Result<Vec<u8>, ReceiptError> {
    let mut output = Vec::new();
    output.extend_from_slice(domain);
    signing_component(&mut output, signer.verifier.as_str().as_bytes())?;
    signing_component(&mut output, signer.verification_method.as_str().as_bytes())?;
    signing_component(&mut output, signer.suite.as_str().as_bytes())?;
    signing_component(&mut output, canonical_receipt)?;
    Ok(output)
}

fn signing_component(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ReceiptError> {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| ReceiptError::LimitExceeded)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_attested(
    kind: u8,
    payload: &[u8],
    signer: &ReceiptSigner,
    signature: &SignatureBytes,
) -> Result<Vec<u8>, ReceiptError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(7).map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 0)?;
    encoder
        .u16(PROTOCOL_V1)
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 1)?;
    encoder.u8(kind).map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, payload)?;
    key(&mut encoder, 3)?;
    encoder
        .str(signer.verifier.as_str())
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 4)?;
    encoder
        .str(signer.verification_method.as_str())
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 5)?;
    encoder
        .str(signer.suite.as_str())
        .map_err(|_| ReceiptError::Malformed)?;
    key(&mut encoder, 6)?;
    bytes(&mut encoder, signature.as_slice())?;
    Ok(encoder.into_writer())
}

fn decode_attested(
    input: &[u8],
) -> Result<(u8, Vec<u8>, ReceiptSigner, SignatureBytes), ReceiptError> {
    if input.len() > MAX_AUDIT_BYTES {
        return Err(ReceiptError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, 7)?;
    key_decode(&mut decoder, 0)?;
    version(&mut decoder)?;
    key_decode(&mut decoder, 1)?;
    let kind = decoder.u8().map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 2)?;
    let payload = decoder
        .bytes()
        .map_err(|_| ReceiptError::Malformed)?
        .to_vec();
    key_decode(&mut decoder, 3)?;
    let verifier = PrincipalId::parse(decoder.str().map_err(|_| ReceiptError::Malformed)?)
        .map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 4)?;
    let method = VerificationMethod::parse(decoder.str().map_err(|_| ReceiptError::Malformed)?)
        .map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 5)?;
    let suite = SignatureSuiteId::parse(decoder.str().map_err(|_| ReceiptError::Malformed)?)
        .map_err(|_| ReceiptError::Malformed)?;
    key_decode(&mut decoder, 6)?;
    let signature = SignatureBytes::new(
        decoder
            .bytes()
            .map_err(|_| ReceiptError::Malformed)?
            .to_vec(),
    )
    .map_err(|_| ReceiptError::Malformed)?;
    finish(&decoder, input)?;
    Ok((
        kind,
        payload,
        ReceiptSigner::new(verifier, method, suite),
        signature,
    ))
}

fn definite_array(decoder: &mut Decoder<'_>, maximum: usize) -> Result<usize, ReceiptError> {
    let count = decoder
        .array()
        .map_err(|_| ReceiptError::Malformed)?
        .ok_or(ReceiptError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| ReceiptError::LimitExceeded)?;
    if count > maximum {
        return Err(ReceiptError::LimitExceeded);
    }
    Ok(count)
}

fn validate_audit_media_type(value: &str) -> Result<(), ReceiptError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ReceiptError::LimitExceeded);
    }
    Ok(())
}

fn validate_reasons(reasons: &[String]) -> Result<(), ReceiptError> {
    if reasons.is_empty()
        || reasons.len() > MAX_REASON_COUNT
        || reasons.iter().any(|reason| {
            reason.is_empty()
                || reason.len() > MAX_REASON_BYTES
                || reason
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        })
    {
        return Err(ReceiptError::InvalidReason);
    }
    Ok(())
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), ReceiptError> {
    encoder.u8(value).map_err(|_| ReceiptError::Malformed)?;
    Ok(())
}

fn bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) -> Result<(), ReceiptError> {
    encoder.bytes(value).map_err(|_| ReceiptError::Malformed)?;
    Ok(())
}

fn exact_map(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ReceiptError> {
    if decoder.map().map_err(|_| ReceiptError::Malformed)? == Some(expected) {
        Ok(())
    } else {
        Err(ReceiptError::Malformed)
    }
}

fn key_decode(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), ReceiptError> {
    if decoder.u8().map_err(|_| ReceiptError::Malformed)? == expected {
        Ok(())
    } else {
        Err(ReceiptError::NonCanonical)
    }
}

fn version(decoder: &mut Decoder<'_>) -> Result<(), ReceiptError> {
    if decoder.u16().map_err(|_| ReceiptError::Malformed)? == PROTOCOL_V1 {
        Ok(())
    } else {
        Err(ReceiptError::UnsupportedProtocol)
    }
}

fn digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], ReceiptError> {
    decoder
        .bytes()
        .map_err(|_| ReceiptError::Malformed)?
        .try_into()
        .map_err(|_| ReceiptError::Malformed)
}

fn finish(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), ReceiptError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(ReceiptError::Malformed)
    }
}

fn domain_hash(identifier_type: u16, canonical: &[u8]) -> Result<Digest, ReceiptError> {
    let length = u64::try_from(canonical.len()).map_err(|_| ReceiptError::LimitExceeded)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTIFIER_PREFIX);
    hasher.update(PROTOCOL_V1.to_be_bytes());
    hasher.update(identifier_type.to_be_bytes());
    hasher.update(length.to_be_bytes());
    hasher.update(canonical);
    Ok(Digest::new(hasher.finalize().into()))
}

/// Canonical receipt failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// Input is malformed.
    Malformed,
    /// Input is valid but not canonical.
    NonCanonical,
    /// Protocol major is unsupported.
    UnsupportedProtocol,
    /// Receipt resource limit was exceeded.
    LimitExceeded,
    /// Stable reason sequence is invalid.
    InvalidReason,
    /// Canonical bytes do not match the expected receipt identifier.
    DigestMismatch,
    /// A receipt does not refer to the audit bundle's root decision.
    LinkageMismatch,
    /// A supposedly canonical audit collection contains duplicates.
    Duplicate,
    /// Receipt signer does not match verifier-local policy.
    UnexpectedSigner,
    /// Receipt signature is invalid or cannot be verified.
    InvalidSignature,
    /// Required receipt signing operation was unavailable.
    SigningUnavailable,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed receipt",
            Self::NonCanonical => "non-canonical receipt",
            Self::UnsupportedProtocol => "unsupported receipt protocol",
            Self::LimitExceeded => "receipt limit exceeded",
            Self::InvalidReason => "invalid receipt reason",
            Self::DigestMismatch => "receipt identifier mismatch",
            Self::LinkageMismatch => "audit receipt linkage mismatch",
            Self::Duplicate => "duplicate audit bundle entry",
            Self::UnexpectedSigner => "unexpected receipt signer",
            Self::InvalidSignature => "invalid receipt signature",
            Self::SigningUnavailable => "receipt signer unavailable",
        })
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{ProfileId, RegistryManifestId};
    use auths_ports::SignatureError;

    struct DigestVerifier;
    struct DigestSuite {
        id: SignatureSuiteId,
    }

    impl SignatureSuite for DigestSuite {
        fn id(&self) -> &SignatureSuiteId {
            &self.id
        }

        fn configuration_id(&self) -> auths_model::AdapterConfigurationId {
            auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
        }

        fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
            if input.verification_key != [7] {
                return Err(SignatureError::InvalidKey);
            }
            if input.signature == Sha256::digest(input.signing_preimage).as_slice() {
                Ok(())
            } else {
                Err(SignatureError::InvalidSignature)
            }
        }

        fn work_units(&self) -> u64 {
            1
        }
    }

    impl ReceiptSignatureVerifier for DigestVerifier {
        fn verify(
            &self,
            _signer: &ReceiptSigner,
            signing_preimage: &[u8],
            signature: &[u8],
        ) -> Result<(), ReceiptError> {
            if signature == Sha256::digest(signing_preimage).as_slice() {
                Ok(())
            } else {
                Err(ReceiptError::InvalidSignature)
            }
        }
    }

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            PrincipalId::parse("did:key:verifier").unwrap(),
            VerificationMethod::parse("did:key:verifier#receipt").unwrap(),
            SignatureSuiteId::parse("test-sha256-v1").unwrap(),
        )
    }

    fn attest_decision(receipt: DecisionReceipt) -> (ReceiptId, Vec<u8>) {
        let id = decision_receipt_id(&receipt).unwrap();
        let signer = signer();
        let signature = SignatureBytes::new(
            Sha256::digest(decision_signing_preimage(&receipt, &signer).unwrap()).to_vec(),
        )
        .unwrap();
        let bytes =
            encode_attested_decision(&AttestedDecisionReceipt::new(receipt, signer, signature))
                .unwrap();
        (id, bytes)
    }

    fn attest_execution(receipt: ExecutionReceipt) -> (ReceiptId, Vec<u8>) {
        let id = execution_receipt_id(&receipt).unwrap();
        let signer = signer();
        let signature = SignatureBytes::new(
            Sha256::digest(execution_signing_preimage(&receipt, &signer).unwrap()).to_vec(),
        )
        .unwrap();
        let bytes =
            encode_attested_execution(&AttestedExecutionReceipt::new(receipt, signer, signature))
                .unwrap();
        (id, bytes)
    }

    fn receipt() -> DecisionReceipt {
        DecisionReceipt::new(
            Digest::new([1; 32]),
            Digest::new([2; 32]),
            ContextDigest::new([3; 32]),
            StatusSnapshotId::new([4; 32]),
            StatusSnapshotId::new([5; 32]),
            ProfileRef::new(ProfileId::parse("auths.mcp").unwrap(), 1).unwrap(),
            DecisionClass::Authorized,
            vec!["authorized".into()],
            Timestamp::new(10),
        )
        .unwrap()
    }

    #[test]
    fn decision_receipt_round_trips_and_mutation_fails() {
        let receipt = receipt();
        let encoded = encode_decision(&receipt).unwrap();
        let id = decision_receipt_id(&receipt).unwrap();
        assert_eq!(verify_decision_bytes(&encoded, id).unwrap(), receipt);
        let mut changed = encoded;
        let last = changed.last_mut().unwrap();
        *last ^= 1;
        assert!(verify_decision_bytes(&changed, id).is_err());
    }

    #[test]
    fn unrelated_digest_types_do_not_compare() {
        let _manifest = RegistryManifestId::new([9; 32]);
        assert_ne!(
            decision_receipt_id(&receipt()).unwrap().as_bytes(),
            &[9; 32]
        );
    }

    #[test]
    fn execution_receipt_round_trips_and_binds_identifier() {
        let decision = decision_receipt_id(&receipt()).unwrap();
        let receipt = ExecutionReceipt::new(
            decision,
            Digest::new([6; 32]),
            Digest::new([7; 32]),
            ExecutionOutcome::Succeeded,
            Some(Digest::new([8; 32])),
            Timestamp::new(11),
        );
        let encoded = encode_execution(&receipt).unwrap();
        let id = execution_receipt_id(&receipt).unwrap();
        assert_eq!(verify_execution_bytes(&encoded, id).unwrap(), receipt);
        assert_eq!(
            verify_execution_bytes(&encoded, ReceiptId::new([0; 32])),
            Err(ReceiptError::DigestMismatch)
        );
    }

    #[test]
    fn application_execution_receipts_bind_replay_plan_command_and_result() {
        let plan = Digest::new([4; 32]);
        let first =
            application_execution_lease_digest("incident:0", Some(plan), Some((0, 2))).unwrap();
        assert_ne!(
            first,
            application_execution_lease_digest("incident:1", Some(plan), Some((0, 2))).unwrap()
        );
        assert_ne!(
            first,
            application_execution_lease_digest("incident:0", Some(plan), Some((1, 2))).unwrap()
        );
        assert_eq!(
            application_execution_lease_digest("incident:0", Some(plan), None),
            Err(ReceiptError::Malformed)
        );

        let decision = decision_receipt_id(&receipt()).unwrap();
        let prepared = prepare_execution_receipt(
            decision,
            "incident:0",
            Some(plan),
            Some((0, 2)),
            b"exact command",
            ExecutionOutcome::Succeeded,
            Some(b"exact result"),
            Timestamp::new(12),
            &signer(),
        )
        .unwrap();
        let decoded = decode_execution(prepared.canonical()).unwrap();
        assert_eq!(prepared.id(), execution_receipt_id(&decoded).unwrap());
        let changed = prepare_execution_receipt(
            decision,
            "incident:0",
            Some(plan),
            Some((0, 2)),
            b"changed command",
            ExecutionOutcome::Succeeded,
            Some(b"exact result"),
            Timestamp::new(12),
            &signer(),
        )
        .unwrap();
        assert_ne!(prepared.id(), changed.id());
    }

    #[test]
    fn verifier_attestation_binds_receipt_and_named_signer() {
        let (id, encoded) = attest_decision(receipt());
        let expected_signer = signer();
        let suite = DigestSuite {
            id: SignatureSuiteId::parse("test-sha256-v1").unwrap(),
        };
        let configured = ConfiguredReceiptVerifier::new(expected_signer, &[7], &suite);
        assert!(
            verify_decision_attestation(
                &encoded,
                id,
                &PrincipalId::parse("did:key:verifier").unwrap(),
                &configured
            )
            .is_ok()
        );
        assert_eq!(
            verify_decision_attestation(
                &encoded,
                id,
                &PrincipalId::parse("did:key:other").unwrap(),
                &DigestVerifier
            ),
            Err(ReceiptError::UnexpectedSigner)
        );
        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            verify_decision_attestation(
                &changed,
                id,
                &PrincipalId::parse("did:key:verifier").unwrap(),
                &DigestVerifier
            )
            .is_err()
        );
    }

    #[test]
    fn audit_bundle_verifies_links_and_redaction_offline() {
        let decision = receipt();
        let (decision_id, decision_bytes) = attest_decision(decision);
        let execution = ExecutionReceipt::new(
            decision_id,
            Digest::new([6; 32]),
            Digest::new([7; 32]),
            ExecutionOutcome::Succeeded,
            Some(Digest::new([8; 32])),
            Timestamp::new(11),
        );
        let (execution_id, execution_bytes) = attest_execution(execution);
        let disclosed = AuditArtifact::disclosed("application/cbor", b"proof".to_vec()).unwrap();
        let redacted = AuditArtifact::redacted("application/json", Digest::new([9; 32])).unwrap();
        let bundle = AuditBundle::new(
            decision_id,
            decision_bytes,
            vec![(execution_id, execution_bytes)],
            vec![redacted, disclosed],
        )
        .unwrap();
        let encoded = encode_audit_bundle(&bundle).unwrap();
        let decoded = decode_audit_bundle(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_ne!(audit_bundle_id(&bundle).unwrap(), Digest::new([0; 32]));

        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        assert!(decode_audit_bundle(&changed).is_err());
    }
}
