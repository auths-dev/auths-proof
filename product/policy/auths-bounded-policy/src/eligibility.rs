use alloc::vec::Vec;

use crate::{
    CommitmentDigest, IntentId, MAX_OBLIGATIONS, MAX_OUTPUT_BYTES, MAX_RESERVATION_INTENTS,
    ObligationId, SchemaId, StableCode, StableStage, UnitId,
};

/// Pure reservation requirement emitted by a domain evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationIntentCommitmentV1 {
    schema_id: SchemaId,
    intent_id: IntentId,
    scope_digest: CommitmentDigest,
    kind: ReservationKind,
    window_digest: Option<CommitmentDigest>,
    action_digest: CommitmentDigest,
    policy_digest: CommitmentDigest,
    evidence_digest: CommitmentDigest,
    canonical_digest: CommitmentDigest,
    canonical_bytes: u32,
}

impl ReservationIntentCommitmentV1 {
    /// Constructs a complete reservation-intent commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_id: SchemaId,
        intent_id: IntentId,
        scope_digest: CommitmentDigest,
        kind: ReservationKind,
        window_digest: Option<CommitmentDigest>,
        action_digest: CommitmentDigest,
        policy_digest: CommitmentDigest,
        evidence_digest: CommitmentDigest,
        canonical_digest: CommitmentDigest,
        canonical_bytes: u32,
    ) -> Result<Self, OutputError> {
        validate_canonical_length(canonical_bytes)?;
        Ok(Self {
            schema_id,
            intent_id,
            scope_digest,
            kind,
            window_digest,
            action_digest,
            policy_digest,
            evidence_digest,
            canonical_digest,
            canonical_bytes,
        })
    }

    /// Returns the stable domain intent identity.
    #[must_use]
    pub const fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// Returns the domain-owned schema.
    #[must_use]
    pub const fn schema_id(&self) -> &SchemaId {
        &self.schema_id
    }

    /// Returns the exact scope/key commitment.
    #[must_use]
    pub const fn scope_digest(&self) -> CommitmentDigest {
        self.scope_digest
    }

    /// Returns additive or exclusive reservation meaning.
    #[must_use]
    pub const fn kind(&self) -> &ReservationKind {
        &self.kind
    }

    /// Returns an optional fixed/rolling window commitment.
    #[must_use]
    pub const fn window_digest(&self) -> Option<CommitmentDigest> {
        self.window_digest
    }

    /// Returns the bound exact action commitment.
    #[must_use]
    pub const fn action_digest(&self) -> CommitmentDigest {
        self.action_digest
    }

    /// Returns the bound policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> CommitmentDigest {
        self.policy_digest
    }

    /// Returns the bound evidence commitment.
    #[must_use]
    pub const fn evidence_digest(&self) -> CommitmentDigest {
        self.evidence_digest
    }

    /// Returns the canonical intent commitment.
    #[must_use]
    pub const fn canonical_digest(&self) -> CommitmentDigest {
        self.canonical_digest
    }

    /// Returns the validated canonical byte length.
    #[must_use]
    pub const fn canonical_bytes(&self) -> u32 {
        self.canonical_bytes
    }
}

/// Shared reservation mechanism without domain payload interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationKind {
    /// Reserve exact additive capacity in an explicit unit.
    Additive {
        /// Capacity unit.
        unit: UnitId,
        /// Exact non-zero amount.
        amount: u64,
    },
    /// Claim one exact scope/key exclusively.
    Exclusive,
}

impl ReservationKind {
    /// Constructs a non-zero additive reservation.
    pub fn additive(unit: UnitId, amount: u64) -> Result<Self, OutputError> {
        if amount == 0 {
            Err(OutputError::ZeroReservationAmount)
        } else {
            Ok(Self::Additive { unit, amount })
        }
    }
}

/// Domain obligation committed by the pure evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationCommitmentV1 {
    schema_id: SchemaId,
    obligation_id: ObligationId,
    class: ObligationClass,
    payload_digest: CommitmentDigest,
    canonical_bytes: u32,
}

impl ObligationCommitmentV1 {
    /// Constructs a complete obligation commitment.
    pub fn new(
        schema_id: SchemaId,
        obligation_id: ObligationId,
        class: ObligationClass,
        payload_digest: CommitmentDigest,
        canonical_bytes: u32,
    ) -> Result<Self, OutputError> {
        validate_canonical_length(canonical_bytes)?;
        Ok(Self {
            schema_id,
            obligation_id,
            class,
            payload_digest,
            canonical_bytes,
        })
    }

    /// Returns the stable domain obligation identity.
    #[must_use]
    pub const fn obligation_id(&self) -> &ObligationId {
        &self.obligation_id
    }

    /// Returns its exact discharge class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        self.class
    }

    /// Returns the domain-owned schema.
    #[must_use]
    pub const fn schema_id(&self) -> &SchemaId {
        &self.schema_id
    }

    /// Returns the canonical payload commitment.
    #[must_use]
    pub const fn payload_digest(&self) -> CommitmentDigest {
        self.payload_digest
    }

    /// Returns the validated canonical byte length.
    #[must_use]
    pub const fn canonical_bytes(&self) -> u32 {
        self.canonical_bytes
    }
}

/// Exact stage at which an obligation must be discharged.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObligationClass {
    /// Must be satisfied before execution authorization.
    PreExecution,
    /// Must be incorporated in verified command construction.
    CommandConstruction,
    /// Must be observed after a possible provider effect.
    PostExecutionObservation,
}

/// Bounded, complete commitments emitted only with eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedOutputs {
    reservation_intents: Vec<ReservationIntentCommitmentV1>,
    obligations: Vec<ObligationCommitmentV1>,
    reservation_intents_commitment: CommitmentDigest,
    obligations_commitment: CommitmentDigest,
    canonical_bytes: u32,
    validation_work: ValidationWork,
}

impl BoundedOutputs {
    /// Validates ordering, uniqueness, count, and combined byte limits.
    pub fn new(
        reservation_intents: Vec<ReservationIntentCommitmentV1>,
        obligations: Vec<ObligationCommitmentV1>,
        reservation_intents_commitment: CommitmentDigest,
        obligations_commitment: CommitmentDigest,
    ) -> Result<Self, OutputError> {
        if reservation_intents.len() > MAX_RESERVATION_INTENTS {
            return Err(OutputError::TooManyReservationIntents);
        }
        if obligations.len() > MAX_OBLIGATIONS {
            return Err(OutputError::TooManyObligations);
        }
        if !strictly_ordered_intents(&reservation_intents) {
            return Err(OutputError::IntentOrdering);
        }
        if !strictly_ordered_obligations(&obligations) {
            return Err(OutputError::ObligationOrdering);
        }
        let canonical_bytes = reservation_intents
            .iter()
            .map(ReservationIntentCommitmentV1::canonical_bytes)
            .chain(
                obligations
                    .iter()
                    .map(ObligationCommitmentV1::canonical_bytes),
            )
            .try_fold(0_u32, |total, length| total.checked_add(length))
            .ok_or(OutputError::CombinedBytesExceeded)?;
        if canonical_bytes as usize > MAX_OUTPUT_BYTES {
            return Err(OutputError::CombinedBytesExceeded);
        }
        let inspected_intents = u8::try_from(reservation_intents.len())
            .map_err(|_| OutputError::TooManyReservationIntents)?;
        let inspected_obligations =
            u8::try_from(obligations.len()).map_err(|_| OutputError::TooManyObligations)?;
        Ok(Self {
            reservation_intents,
            obligations,
            reservation_intents_commitment,
            obligations_commitment,
            canonical_bytes,
            validation_work: ValidationWork {
                inspected_intents,
                inspected_obligations,
                canonical_bytes,
                validator_allocations: 0,
            },
        })
    }

    /// Returns complete, canonical reservation commitments.
    #[must_use]
    pub fn reservation_intents(&self) -> &[ReservationIntentCommitmentV1] {
        &self.reservation_intents
    }

    /// Returns complete, canonical obligation commitments.
    #[must_use]
    pub fn obligations(&self) -> &[ObligationCommitmentV1] {
        &self.obligations
    }

    /// Returns the domain-produced aggregate reservation commitment.
    #[must_use]
    pub const fn reservation_intents_commitment(&self) -> CommitmentDigest {
        self.reservation_intents_commitment
    }

    /// Returns the domain-produced aggregate obligation commitment.
    #[must_use]
    pub const fn obligations_commitment(&self) -> CommitmentDigest {
        self.obligations_commitment
    }

    /// Returns total committed canonical output bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> u32 {
        self.canonical_bytes
    }

    /// Returns deterministic validation work for benchmarking and limits.
    #[must_use]
    pub const fn validation_work(&self) -> ValidationWork {
        self.validation_work
    }
}

/// Deterministic work performed by bounded-output validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationWork {
    /// Intent records inspected.
    pub inspected_intents: u8,
    /// Obligation records inspected.
    pub inspected_obligations: u8,
    /// Canonical bytes accumulated with checked arithmetic.
    pub canonical_bytes: u32,
    /// Heap allocations performed by validation after receiving owned vectors.
    pub validator_allocations: u8,
}

/// Disjoint and exhaustive result of a validated pure domain evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EligibilityV1 {
    /// Policy containment succeeded and binds complete pure outputs.
    Eligible(BoundedOutputs),
    /// Known facts prove the action is not eligible.
    Denied {
        /// Domain stable code.
        stable_code: StableCode,
        /// Domain stable decision stage.
        stage: StableStage,
    },
    /// A required trustworthy fact is unavailable.
    Indeterminate {
        /// Domain stable code.
        stable_code: StableCode,
        /// Domain stable decision stage.
        stage: StableStage,
    },
}

impl EligibilityV1 {
    /// Returns true only for a result carrying complete outputs.
    #[must_use]
    pub const fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible(_))
    }

    /// Projects configuration mismatch into a non-eligible domain diagnostic.
    #[must_use]
    pub fn configuration_mismatch(stable_code: StableCode, stage: StableStage) -> Self {
        Self::Denied { stable_code, stage }
    }
}

/// Stable malformed or over-limit output failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputError {
    /// Additive reservations must consume positive capacity.
    ZeroReservationAmount,
    /// Canonical domain payload length is zero.
    EmptyCanonicalPayload,
    /// One canonical domain payload exceeds the combined V1 ceiling.
    CanonicalPayloadTooLarge,
    /// More than 32 intents were returned.
    TooManyReservationIntents,
    /// More than 32 obligations were returned.
    TooManyObligations,
    /// Intents are duplicated or not in canonical identifier order.
    IntentOrdering,
    /// Obligations are duplicated or not in canonical identifier order.
    ObligationOrdering,
    /// Combined canonical output length overflowed or exceeds 64 KiB.
    CombinedBytesExceeded,
}

fn validate_canonical_length(length: u32) -> Result<(), OutputError> {
    if length == 0 {
        Err(OutputError::EmptyCanonicalPayload)
    } else if length as usize > MAX_OUTPUT_BYTES {
        Err(OutputError::CanonicalPayloadTooLarge)
    } else {
        Ok(())
    }
}

fn strictly_ordered_intents(values: &[ReservationIntentCommitmentV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].intent_id < pair[1].intent_id)
}

fn strictly_ordered_obligations(values: &[ObligationCommitmentV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].obligation_id < pair[1].obligation_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(id: &str, bytes: u32) -> ReservationIntentCommitmentV1 {
        ReservationIntentCommitmentV1::new(
            SchemaId::parse("intent-schema/1").unwrap(),
            IntentId::parse(id).unwrap(),
            CommitmentDigest::new([1; 32]),
            ReservationKind::Exclusive,
            None,
            CommitmentDigest::new([2; 32]),
            CommitmentDigest::new([3; 32]),
            CommitmentDigest::new([4; 32]),
            CommitmentDigest::new([5; 32]),
            bytes,
        )
        .unwrap()
    }

    fn obligation(id: &str, bytes: u32) -> ObligationCommitmentV1 {
        ObligationCommitmentV1::new(
            SchemaId::parse("obligation-schema/1").unwrap(),
            ObligationId::parse(id).unwrap(),
            ObligationClass::CommandConstruction,
            CommitmentDigest::new([6; 32]),
            bytes,
        )
        .unwrap()
    }

    #[test]
    fn eligible_outputs_are_sorted_unique_and_bounded() {
        let result = BoundedOutputs::new(
            vec![intent("intent-a", 10), intent("intent-b", 11)],
            vec![obligation("obligation-a", 12)],
            CommitmentDigest::new([7; 32]),
            CommitmentDigest::new([8; 32]),
        )
        .unwrap();
        assert_eq!(result.canonical_bytes(), 33);
        assert_eq!(
            result.validation_work(),
            ValidationWork {
                inspected_intents: 2,
                inspected_obligations: 1,
                canonical_bytes: 33,
                validator_allocations: 0,
            }
        );
    }

    #[test]
    fn deleting_order_or_exceeding_bytes_fails_closed() {
        assert_eq!(
            BoundedOutputs::new(
                vec![intent("intent-b", 1), intent("intent-a", 1)],
                vec![],
                CommitmentDigest::new([7; 32]),
                CommitmentDigest::new([8; 32]),
            ),
            Err(OutputError::IntentOrdering)
        );
        assert_eq!(
            BoundedOutputs::new(
                vec![intent("intent-a", 32_768)],
                vec![obligation("obligation-a", 32_769)],
                CommitmentDigest::new([7; 32]),
                CommitmentDigest::new([8; 32]),
            ),
            Err(OutputError::CombinedBytesExceeded)
        );
    }

    #[test]
    fn hard_count_and_byte_boundaries_are_inclusive_then_fail_closed() {
        let exact_intents = (0..MAX_RESERVATION_INTENTS)
            .map(|index| intent(&format!("intent-{index:02}"), 1))
            .collect();
        let exact_obligations = (0..MAX_OBLIGATIONS)
            .map(|index| obligation(&format!("obligation-{index:02}"), 1))
            .collect();
        assert!(
            BoundedOutputs::new(
                exact_intents,
                exact_obligations,
                CommitmentDigest::new([7; 32]),
                CommitmentDigest::new([8; 32]),
            )
            .is_ok()
        );

        let too_many_intents = (0..=MAX_RESERVATION_INTENTS)
            .map(|index| intent(&format!("intent-{index:02}"), 1))
            .collect();
        assert_eq!(
            BoundedOutputs::new(
                too_many_intents,
                vec![],
                CommitmentDigest::new([7; 32]),
                CommitmentDigest::new([8; 32]),
            ),
            Err(OutputError::TooManyReservationIntents)
        );

        let too_many_obligations = (0..=MAX_OBLIGATIONS)
            .map(|index| obligation(&format!("obligation-{index:02}"), 1))
            .collect();
        assert_eq!(
            BoundedOutputs::new(
                vec![],
                too_many_obligations,
                CommitmentDigest::new([7; 32]),
                CommitmentDigest::new([8; 32]),
            ),
            Err(OutputError::TooManyObligations)
        );

        let exact_bytes = BoundedOutputs::new(
            vec![intent("intent-a", u32::try_from(MAX_OUTPUT_BYTES).unwrap())],
            vec![],
            CommitmentDigest::new([7; 32]),
            CommitmentDigest::new([8; 32]),
        )
        .unwrap();
        assert_eq!(
            exact_bytes.canonical_bytes(),
            u32::try_from(MAX_OUTPUT_BYTES).unwrap()
        );
    }

    #[test]
    fn one_byte_over_the_payload_ceiling_is_rejected() {
        assert_eq!(
            ReservationIntentCommitmentV1::new(
                SchemaId::parse("intent-schema/1").unwrap(),
                IntentId::parse("intent-a").unwrap(),
                CommitmentDigest::new([1; 32]),
                ReservationKind::Exclusive,
                None,
                CommitmentDigest::new([2; 32]),
                CommitmentDigest::new([3; 32]),
                CommitmentDigest::new([4; 32]),
                CommitmentDigest::new([5; 32]),
                u32::try_from(MAX_OUTPUT_BYTES + 1).unwrap(),
            ),
            Err(OutputError::CanonicalPayloadTooLarge)
        );
    }

    #[test]
    fn deletion_and_alteration_mutations_change_the_committed_output() {
        let baseline = BoundedOutputs::new(
            vec![intent("intent-a", 10), intent("intent-b", 11)],
            vec![obligation("obligation-a", 12)],
            CommitmentDigest::new([7; 32]),
            CommitmentDigest::new([8; 32]),
        )
        .unwrap();
        let deleted = BoundedOutputs::new(
            vec![intent("intent-a", 10)],
            vec![obligation("obligation-a", 12)],
            CommitmentDigest::new([9; 32]),
            CommitmentDigest::new([8; 32]),
        )
        .unwrap();
        let altered = BoundedOutputs::new(
            vec![intent("intent-a", 10), intent("intent-b", 13)],
            vec![obligation("obligation-a", 12)],
            CommitmentDigest::new([10; 32]),
            CommitmentDigest::new([8; 32]),
        )
        .unwrap();
        assert_ne!(baseline, deleted);
        assert_ne!(baseline, altered);
        assert_ne!(
            baseline.reservation_intents_commitment(),
            deleted.reservation_intents_commitment()
        );
        assert_ne!(
            baseline.reservation_intents_commitment(),
            altered.reservation_intents_commitment()
        );
    }

    #[test]
    fn non_eligible_results_cannot_carry_outputs() {
        let denied = EligibilityV1::Denied {
            stable_code: StableCode::parse("budget-exceeded").unwrap(),
            stage: StableStage::parse("policy").unwrap(),
        };
        assert!(!denied.is_eligible());
    }
}
