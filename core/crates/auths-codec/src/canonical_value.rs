//! Codec-owned values whose normalization has been performed explicitly.
//!
//! Model constructors validate structural fields. Some wire schemas also
//! normalize collection order using codec-derived identifiers. Keeping those
//! values behind this boundary makes an exact value round trip meaningful.

use crate::CodecError;
use alloc::vec::Vec;
use auths_model::{
    ApprovalRequirements, BoundedPolicyCommitment, EvidenceObject, GrantStatusSnapshot,
    PortableVerificationResult, PrincipalStatusSnapshot, ProofBundle, SignedApproval, SignedGrant,
    SignedGrantStatus, SignedObservation, SignedPrincipalStatus, TrustedContext,
    VerificationCode, VerificationDecision,
};
use core::ops::Deref;

/// An immutable protocol value constructed in its canonical representation.
///
/// Constructors are supplied by the codec for the concrete protocol types
/// needing normalization. There is no unchecked conversion from a model value
/// and no mutable projection of the stored value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Canonical<T> {
    value: T,
}

impl<T> Canonical<T> {
    /// Borrows the exact normalized value used by the encoder.
    #[must_use]
    pub const fn as_value(&self) -> &T {
        &self.value
    }

    /// Returns the normalized model value without changing any field.
    ///
    /// Rebuilding a different model value does not grant it canonical status;
    /// encoding it requires the concrete canonical constructor again.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }
}

impl<T> Deref for Canonical<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_value()
    }
}

/// Approval requirements normalized into canonical identifier order.
pub type CanonicalApprovalRequirements = Canonical<ApprovalRequirements>;

impl Canonical<ApprovalRequirements> {
    /// Normalizes an approval-requirement extension by its actual identifiers.
    ///
    /// The complete requirements and their multiplicity are preserved. The
    /// model constructor has already checked the one-to-four count and exact
    /// full-value uniqueness. Identifier collisions are not assumed impossible
    /// by this constructor; stable ordering retains the relative order of ties.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if an identifier cannot be derived, a protocol
    /// bound is exceeded, or the normalized model cannot be constructed.
    pub fn new(value: ApprovalRequirements) -> Result<Self, CodecError> {
        let ordered = crate::approval::normalize_requirement_values(
            value.as_slice(), auths_model::MAX_APPROVAL_REQUIREMENTS_PER_GRANT)?;
        let value = ApprovalRequirements::new(ordered)?;
        Ok(Self { value })
    }
}

/// A proof bundle with all identifier-ordered collections normalized.
pub type CanonicalProofBundle = Canonical<ProofBundle>;

/// A principal snapshot in the model order, with identifier-ordered ties.
pub type CanonicalPrincipalStatusSnapshot = Canonical<PrincipalStatusSnapshot>;

/// A grant snapshot in the model order, with identifier-ordered ties.
pub type CanonicalGrantStatusSnapshot = Canonical<GrantStatusSnapshot>;

/// A trusted context with canonical nested snapshots and approval requirements.
pub type CanonicalTrustedContext = Canonical<TrustedContext>;

/// A signed approval with content-consistent control evidence.
pub type CanonicalSignedApproval = Canonical<SignedApproval>;

/// A signed observation with content-consistent control evidence.
pub type CanonicalSignedObservation = Canonical<SignedObservation>;

/// A bounded policy whose carried bytes open its declared commitment.
pub type CanonicalBoundedPolicyCommitment = Canonical<BoundedPolicyCommitment>;

/// A portable result with consistent verdict tags and exact self commitment.
pub type CanonicalVerificationResult = Canonical<PortableVerificationResult>;

// Move complete signed records through the same stable identifier order as the
// wire writer. Derive each identifier once. Reversal before popping preserves
// input order for equal identifiers; no hash-injectivity premise is needed.
macro_rules! normalize_owned_records {
    ($name:ident, $derive:ident, $key:ident, $sort:ident, $record:ty, $id:ty, $maximum:expr, $identifier:path) => {
        fn $derive(mut records: Vec<$record>) -> Result<Vec<($id, $record)>, CodecError> {
            if records.len() > $maximum {
                return Err(CodecError::LimitExceeded);
            }
            let mut keyed = Vec::with_capacity(records.len());
            records.reverse();
            while let Some(record) = records.pop() {
                let identifier = $identifier(record.statement())?;
                keyed.push((identifier, record));
            }
            Ok(keyed)
        }

        fn $key(entry: &($id, $record)) -> $id {
            entry.0
        }

        fn $sort(mut keyed: Vec<($id, $record)>) -> Vec<($id, $record)> {
            keyed.sort_by_key($key);
            keyed
        }

        fn $name(records: Vec<$record>) -> Result<Vec<$record>, CodecError> {
            let keyed = $sort($derive(records)?);
            Ok(unkey_records(keyed))
        }
    };
}

// Discard only the temporary sorting keys, moving every complete record in
// the vector's current order. No Clone bound, payload copy or deduplication is
// involved. All three concrete signed-record normalizers use this same path.
pub(crate) fn unkey_records<Key, Value>(mut keyed: Vec<(Key, Value)>) -> Vec<Value> {
    let mut records = Vec::with_capacity(keyed.len());
    keyed.reverse();
    while let Some((_, record)) = keyed.pop() {
        records.push(record);
    }
    records
}

normalize_owned_records!(
    normalize_grants,
    derive_grant_keys,
    grant_sort_key,
    sort_grant_keys,
    SignedGrant,
    auths_model::GrantId,
    auths_model::HARD_MAX_GRANTS,
    crate::hash::grant_id
);
normalize_owned_records!(
    normalize_principal_status,
    derive_principal_status_keys,
    principal_status_sort_key,
    sort_principal_status_keys,
    SignedPrincipalStatus,
    auths_model::PrincipalStatusId,
    auths_model::HARD_MAX_PRINCIPAL_STATUS,
    crate::hash::principal_status_id
);
normalize_owned_records!(
    normalize_grant_status,
    derive_grant_status_keys,
    grant_status_sort_key,
    sort_grant_status_keys,
    SignedGrantStatus,
    auths_model::GrantStatusId,
    auths_model::HARD_MAX_GRANT_STATUS,
    crate::hash::grant_status_id
);

// Raw model construction cannot derive codec-owned content identifiers. A
// canonical bundle must earn the same evidence-integrity check as its decoder,
// including the evidence nested in signed approvals. Never repair a supplied
// identifier: reject the inconsistency and preserve the caller's exact bytes.
fn validate_evidence_values(values: &[EvidenceObject]) -> Result<(), CodecError> {
    if values.len() > auths_model::HARD_MAX_EVIDENCE {
        return Err(CodecError::LimitExceeded);
    }
    let mut index = 0;
    while index < values.len() {
        if crate::hash::evidence_id(&values[index])? != values[index].id() {
            return Err(CodecError::DigestMismatch);
        }
        index += 1;
    }
    Ok(())
}

impl Canonical<SignedApproval> {
    /// Checks every control-evidence content ID, retaining the exact statement,
    /// signature and evidence bytes. This does not verify the signature or
    /// establish approver authority.
    ///
    /// # Errors
    ///
    /// Returns a codec error for identifier derivation or an inconsistent ID.
    pub fn new(value: SignedApproval) -> Result<Self, CodecError> {
        checked_signed_approval(value)
    }
}

impl Canonical<SignedObservation> {
    /// Checks every control-evidence content ID without repairing any field.
    /// Signature verification, freshness and observer trust remain separate.
    ///
    /// # Errors
    ///
    /// Returns a codec error for identifier derivation or an inconsistent ID.
    pub fn new(value: SignedObservation) -> Result<Self, CodecError> {
        checked_signed_observation(value)
    }
}

impl Canonical<BoundedPolicyCommitment> {
    /// Checks that the exact supplied policy bytes open the declared policy
    /// commitment. A matching commitment grants no policy authority or claim
    /// about the evaluator's semantics.
    ///
    /// # Errors
    ///
    /// Returns a codec error for commitment derivation or a mismatched digest.
    pub fn new(value: BoundedPolicyCommitment) -> Result<Self, CodecError> {
        checked_bounded_policy(value)
    }
}

impl Canonical<PortableVerificationResult> {
    /// Checks the decision/code pair and the exact self-binding commitment.
    /// The commitment is derived through the real result projection that
    /// replaces its own digest with zero. No verdict, report or digest is
    /// repaired, and construction does not create a verified-action capability.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] for a contradictory decision/code
    /// pair, or a codec error if digest derivation fails or the digest differs.
    pub fn new(value: PortableVerificationResult) -> Result<Self, CodecError> {
        checked_verification_result(value)
    }
}

// These concrete source entry points own integrity checking once. Both the
// public constructors and decoders use them; the stable concrete names also
// expose each exact payload-preserving path to source refinement.
pub(crate) fn checked_signed_approval(value: SignedApproval) -> Result<CanonicalSignedApproval, CodecError> {
    validate_evidence_values(value.evidence())?;
    Ok(Canonical { value })
}

pub(crate) fn checked_signed_observation(value: SignedObservation) -> Result<CanonicalSignedObservation, CodecError> {
    validate_evidence_values(value.evidence())?;
    Ok(Canonical { value })
}

pub(crate) fn checked_bounded_policy(value: BoundedPolicyCommitment) -> Result<CanonicalBoundedPolicyCommitment, CodecError> {
    if crate::bounded_policy::bounded_policy_digest(value.policy())?
        != value.commitment().policy_digest()
    {
        return Err(CodecError::DigestMismatch);
    }
    Ok(Canonical { value })
}

pub(crate) fn checked_verification_result(value: PortableVerificationResult) -> Result<CanonicalVerificationResult, CodecError> {
    if !matches!(
        (value.decision(), value.code()),
        (VerificationDecision::Authorized, VerificationCode::Authorized)
            | (VerificationDecision::Denied, VerificationCode::Denied(_))
            | (VerificationDecision::Indeterminate, VerificationCode::Indeterminate(_))
    ) {
        return Err(CodecError::Malformed);
    }
    if crate::hash::verification_result_digest(&value)? != value.result_digest() {
        return Err(CodecError::DigestMismatch);
    }
    Ok(Canonical { value })
}

impl Canonical<ProofBundle> {
    /// Normalizes grants and both lifecycle statement lists by their actual
    /// unsigned identifiers, moving complete records without cloning payloads.
    /// Checks content identifiers for all direct and nested approval evidence.
    /// Every other field is reconstructed through the model's usual builders;
    /// approval order and multiplicity are retained exactly.
    ///
    /// # Errors
    ///
    /// Returns a codec error if identifier derivation or model validation fails.
    pub fn new(value: ProofBundle) -> Result<Self, CodecError> {
        let parts = value.into_parts();
        validate_evidence_values(&parts.evidence)?;
        let mut approval_index = 0;
        while approval_index < parts.approvals.len() {
            validate_evidence_values(parts.approvals[approval_index].evidence())?;
            approval_index += 1;
        }
        let grants = normalize_grants(parts.grants)?;
        let principal_status = normalize_principal_status(parts.principal_status)?;
        let grant_status = normalize_grant_status(parts.grant_status)?;
        let value = ProofBundle::new(
            parts.header,
            grants,
            parts.actions,
            parts.plan,
            parts.evidence,
            parts.bindings,
            principal_status,
            grant_status,
            parts.attachments,
            parts.canonical_body,
        )?
        .with_approvals(parts.approvals)?;
        Ok(Self { value })
    }
}

impl Canonical<PrincipalStatusSnapshot> {
    /// Establishes the model's principal/method/sequence/issuer ordering and
    /// identifier order within ties. The wire writer orders by identifier; its
    /// decoder then applies this same stable model ordering. Sorting by
    /// identifier before reconstruction makes that cycle a fixed point.
    /// Complete statements, signatures, trust rules and checkpoints are moved.
    ///
    /// # Errors
    ///
    /// Returns a codec error if identifier derivation or model validation fails.
    pub fn new(value: PrincipalStatusSnapshot) -> Result<Self, CodecError> {
        let parts = value.into_parts();
        let statements = normalize_principal_status(parts.statements)?;
        let value = PrincipalStatusSnapshot::with_trust(
            parts.id,
            parts.observed_at,
            parts.valid_until,
            statements,
            parts.checkpoints,
            parts.trust,
        )?;
        Ok(Self { value })
    }
}

impl Canonical<GrantStatusSnapshot> {
    /// Establishes the model's grant/method/sequence/issuer ordering with
    /// identifier order within ties, retaining every complete signed record.
    /// Identifier sorting precedes stable model reconstruction so decoding the
    /// encoded value yields the same stored order, including equal-key cases.
    ///
    /// # Errors
    ///
    /// Returns a codec error if identifier derivation or model validation fails.
    pub fn new(value: GrantStatusSnapshot) -> Result<Self, CodecError> {
        let parts = value.into_parts();
        let statements = normalize_grant_status(parts.statements)?;
        let value = GrantStatusSnapshot::with_trust(
            parts.id,
            parts.observed_at,
            parts.valid_until,
            statements,
            parts.checkpoints,
            parts.trust,
        )?;
        Ok(Self { value })
    }
}

impl Canonical<TrustedContext> {
    /// Normalizes both nested status snapshots and the approval requirements.
    /// Reconstructs every context field through the validated model builders,
    /// including the complete observer and approver rosters. An empty context
    /// approval list remains valid and does not use the nonempty extension
    /// constructor.
    ///
    /// # Errors
    ///
    /// Returns a codec error if normalization, identifier derivation or any
    /// ordinary context validation fails.
    pub fn new(value: TrustedContext) -> Result<Self, CodecError> {
        let parts = value.into_parts();
        let principal_status =
            CanonicalPrincipalStatusSnapshot::new(parts.principal_status_snapshot)?.into_value();
        let grant_status =
            CanonicalGrantStatusSnapshot::new(parts.grant_status_snapshot)?.into_value();
        let approval_requirements =
            crate::approval::normalize_requirement_values(
                &parts.approval_requirements, auths_model::MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION)?;
        let value = TrustedContext::new(
            parts.configuration,
            parts.composition,
            parts.trust_anchors,
            parts.accepted_registries,
            parts.expected_audience,
            parts.expected_challenge,
            parts.evaluation_time,
            parts.assurance_policy,
            principal_status,
            grant_status,
            parts.resource_matcher,
            parts.profile_policy,
            parts.channel_policy,
            parts.limits,
        )?
        .with_observer_anchors(parts.observer_anchors)?
        .with_approvals(parts.approver_anchors, approval_requirements)?;
        Ok(Self { value })
    }
}
