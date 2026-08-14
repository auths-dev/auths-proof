//! Exact projection from Stripe refund semantics into the shared lifecycle.
//!
//! The projection commits Stripe-owned payloads without teaching the shared
//! crates what a refund, currency, Charge, `PaymentIntent`, or Stripe request
//! means.

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, ObligationClass, ObligationCommitmentV1, ObligationId,
    PolicyCommitmentV1, PolicyTypeId, ProfileId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, UnitId, VerifierTime,
};
use auths_lifecycle::{
    CancellationDisposition, CapacityEntryV1, CapacitySnapshotV1, DecisionInputV1,
    DecisionReceiptDigest, DomainId, DomainReceiptDigest, ExecutionId, ExecutorAudienceId,
    LifecycleId, ReservationAlgebraId, ReservationSetV1, RevocationSnapshotV1, TransitionContextV1,
    WorkflowId,
};
use serde::Serialize;

use crate::{
    AggregateBudgetSnapshot, BOUNDED_CANONICALIZATION, BOUNDED_POLICY_VERSION,
    BoundedDecisionClass, BoundedRefundDecision, BoundedRefundEligibility, ExactRefundActionV1,
    RefundEvidenceV1, StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyV1,
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::DigestHex,
};

const PROFILE_ID: &str = "auths.stripe.exact-refund/1";
const POLICY_TYPE_ID: &str = "auths.stripe.bounded-refund-policy";
const EVIDENCE_SCHEMA_ID: &str = "auths.stripe.refund-evidence/1";
const EVIDENCE_SOURCE_ID: &str = "stripe-api-charge-read/1";
const STATE_SCHEMA_ID: &str = "auths.stripe.aggregate-budget-snapshot/1";
const CONFIGURATION_SEMANTIC_ID: &str = "auths.stripe.bounded-evaluator-configuration/1";
const INTENT_SCHEMA_ID: &str = "auths.stripe.refund-reservation-intent/1";
const OBLIGATION_SCHEMA_ID: &str = "auths.stripe.verified-refund-command/1";
const RESERVATION_ALGEBRA_ID: &str = "auths.stripe.refund-additive-budget/1";
const DOMAIN_ID: &str = "stripe";

/// Complete Stripe-owned inputs to the pure shared-lifecycle projection.
pub struct StripeLifecycleProjectionInput<'a> {
    /// Exact action chosen by the untrusted caller.
    pub action: &'a ExactRefundActionV1,
    /// Immutable configured refund policy.
    pub policy: &'a StripeBoundedRefundPolicyV1,
    /// Fresh normalized Stripe evidence.
    pub evidence: &'a RefundEvidenceV1,
    /// Aggregate state observed by the pure evaluator.
    pub aggregate_snapshot: &'a AggregateBudgetSnapshot,
    /// Eligible Stripe-local evaluator result.
    pub decision: &'a BoundedRefundDecision,
    /// Configuration required by the caller and proof context.
    pub required_configuration: &'a StripeBoundedEvaluatorConfigurationV1,
    /// Configuration actually executed.
    pub executed_configuration: &'a StripeBoundedEvaluatorConfigurationV1,
    /// Explicit verifier time used by the decision.
    pub verifier_time: u64,
}

/// Validated shared commitments derived without changing Stripe semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StripeLifecycleProjectionV1 {
    /// Complete immutable evaluation commitments.
    pub commitments: EvaluationCommitmentsV1,
    /// Eligible bounded outputs carrying only domain commitments.
    pub outputs: BoundedOutputs,
    /// Deterministically derived atomic reservation set.
    pub reservations: ReservationSetV1,
    /// Validated shared workflow identity.
    pub workflow_id: WorkflowId,
    /// Validated shared domain identity.
    pub domain_id: DomainId,
    /// Validated exact executor audience.
    pub executor_audience: ExecutorAudienceId,
    /// Closed additive reservation algebra.
    pub reservation_algebra_id: ReservationAlgebraId,
    /// Exact capacity view corresponding to the Stripe aggregate snapshot.
    pub capacity: CapacitySnapshotV1,
}

/// Durable identities supplied after exact Auths verification and Stripe
/// decision-receipt persistence.
pub struct StripeLifecycleDecisionBindings<'a> {
    /// Commitment to the successful Auths core authorization.
    pub core_authorization_digest: &'a DigestHex,
    /// Canonical shared-facing decision receipt commitment.
    pub decision_receipt_digest: &'a DigestHex,
    /// Unchanged canonical Stripe decision receipt commitment.
    pub domain_decision_receipt_digest: &'a DigestHex,
    /// Exact production build commitment.
    pub implementation_build_digest: &'a DigestHex,
    /// Exact authority expiry from the authorized action.
    pub expires_at: u64,
}

/// Closed failure before any lifecycle state can be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StripeLifecycleProjectionError {
    /// The Stripe evaluator did not produce eligible outputs.
    #[error("Stripe decision is not eligible")]
    NotEligible,
    /// A Stripe payload could not be canonicalized.
    #[error("Stripe lifecycle payload is not canonical")]
    Canonicalization,
    /// One digest was not exact lowercase SHA-256.
    #[error("Stripe lifecycle digest is malformed")]
    InvalidDigest,
    /// A shared identifier or hard limit rejected the projection.
    #[error("Stripe lifecycle projection violates the shared contract")]
    InvalidProjection,
}

/// Projects one eligible Stripe refund into the shared bounded/lifecycle types.
///
/// # Errors
///
/// Fails closed for non-eligible decisions, malformed digests, invalid shared
/// identifiers, incomplete reservation bindings, or exceeded output limits.
pub fn project_refund_lifecycle(
    input: &StripeLifecycleProjectionInput<'_>,
) -> Result<StripeLifecycleProjectionV1, StripeLifecycleProjectionError> {
    let eligibility = input
        .decision
        .eligibility
        .as_ref()
        .filter(|_| input.decision.class == BoundedDecisionClass::Eligible)
        .ok_or(StripeLifecycleProjectionError::NotEligible)?;
    let commitments = project_commitments(input)?;
    let outputs = project_outputs(input, eligibility, &commitments)?;
    let workflow_id = WorkflowId::parse(input.action.workflow_id()).map_err(invalid)?;
    let domain_id = DomainId::parse(DOMAIN_ID).map_err(invalid)?;
    let executor_audience =
        ExecutorAudienceId::parse(input.action.executor_audience()).map_err(invalid)?;
    let reservation_algebra_id =
        ReservationAlgebraId::parse(RESERVATION_ALGEBRA_ID).map_err(invalid)?;
    let reservations = ReservationSetV1::derive(
        &workflow_id,
        &domain_id,
        commitments.profile_id(),
        commitments.policy_commitment().evaluator_semantic_id(),
        &executor_audience,
        &reservation_algebra_id,
        &outputs,
    )
    .map_err(invalid)?;
    let capacity = project_capacity_snapshot(
        input.action.stripe_account_id().as_str(),
        &eligibility.reservations,
        input.aggregate_snapshot,
    )?;
    Ok(StripeLifecycleProjectionV1 {
        commitments,
        outputs,
        reservations,
        workflow_id,
        domain_id,
        executor_audience,
        reservation_algebra_id,
        capacity,
    })
}

fn project_outputs(
    input: &StripeLifecycleProjectionInput<'_>,
    eligibility: &BoundedRefundEligibility,
    commitments: &EvaluationCommitmentsV1,
) -> Result<BoundedOutputs, StripeLifecycleProjectionError> {
    let action_digest = commitments.exact_action_digest();
    let policy_digest = commitments.policy_commitment().policy_digest();
    let evidence_digest = commitments.evidence_digest();
    let mut intents = Vec::with_capacity(eligibility.reservations.len());
    for reservation in &eligibility.reservations {
        let canonical_bytes = canonical_json(reservation).map_err(canonical)?;
        let intent_id = format!("refund-budget-{}", reservation.budget_id);
        let scope = StripeReservationScope {
            account: input.action.stripe_account_id().as_str(),
            currency: reservation.currency.as_str(),
            budget_id: &reservation.budget_id,
        };
        let scope_digest = commitment(&canonical_digest(&scope).map_err(canonical)?)?;
        let window_digest = commitment(&canonical_digest(&reservation.window).map_err(canonical)?)?;
        let unit =
            UnitId::parse(&format!("minor-{}", reservation.currency.as_str())).map_err(invalid)?;
        intents.push(
            ReservationIntentCommitmentV1::new(
                SchemaId::parse(INTENT_SCHEMA_ID).map_err(invalid)?,
                IntentId::parse(&intent_id).map_err(invalid)?,
                scope_digest,
                ReservationKind::additive(unit.clone(), reservation.amount_minor)
                    .map_err(invalid)?,
                Some(window_digest),
                action_digest,
                policy_digest,
                evidence_digest,
                commitment(&crate::canonical::sha256(&canonical_bytes))?,
                u32::try_from(canonical_bytes.len()).map_err(invalid)?,
            )
            .map_err(invalid)?,
        );
    }
    intents.sort_by(|left, right| left.intent_id().cmp(right.intent_id()));
    let action_bytes = input.action.canonical_bytes().map_err(canonical)?;
    let obligation = ObligationCommitmentV1::new(
        SchemaId::parse(OBLIGATION_SCHEMA_ID).map_err(invalid)?,
        ObligationId::parse("construct-exact-refund-command").map_err(invalid)?,
        ObligationClass::CommandConstruction,
        action_digest,
        u32::try_from(action_bytes.len()).map_err(invalid)?,
    )
    .map_err(invalid)?;
    BoundedOutputs::new(
        intents,
        vec![obligation],
        commitment(&canonical_digest(&eligibility.reservations).map_err(canonical)?)?,
        commitment(&crate::canonical::sha256(&action_bytes))?,
    )
    .map_err(invalid)
}

fn project_commitments(
    input: &StripeLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, StripeLifecycleProjectionError> {
    let action_digest = commitment(&input.action.digest().map_err(canonical)?)?;
    let policy_digest = commitment(&input.policy.digest().map_err(canonical)?)?;
    let evidence_digest = commitment(&input.evidence.digest().map_err(canonical)?)?;
    let state_snapshot_digest =
        commitment(&canonical_digest(input.aggregate_snapshot).map_err(canonical)?)?;
    Ok(EvaluationCommitmentsV1::new(
        ProfileId::parse(PROFILE_ID).map_err(invalid)?,
        action_digest,
        PolicyCommitmentV1::new(
            PolicyTypeId::parse(POLICY_TYPE_ID).map_err(invalid)?,
            BOUNDED_POLICY_VERSION,
            canonicalization_id()?,
            policy_digest,
            EvaluatorSemanticId::parse(input.policy.evaluator_semantic_id()).map_err(invalid)?,
        )
        .map_err(invalid)?,
        SchemaId::parse(EVIDENCE_SCHEMA_ID).map_err(invalid)?,
        evidence_digest,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(invalid)?,
        VerifierTime::from_unix_seconds(input.evidence.observed_at()),
        SchemaId::parse(STATE_SCHEMA_ID).map_err(invalid)?,
        state_snapshot_digest,
        VerifierTime::from_unix_seconds(input.verifier_time),
        configuration_commitment(input.required_configuration, false)?,
        configuration_commitment(input.executed_configuration, true)?,
    ))
}

pub(crate) fn project_capacity_snapshot(
    account: &str,
    reservations: &[crate::RefundReservationIntent],
    aggregate_snapshot: &AggregateBudgetSnapshot,
) -> Result<CapacitySnapshotV1, StripeLifecycleProjectionError> {
    let mut capacity = Vec::with_capacity(reservations.len());
    for reservation in reservations {
        let scope = StripeReservationScope {
            account,
            currency: reservation.currency.as_str(),
            budget_id: &reservation.budget_id,
        };
        let scope_digest = commitment(&canonical_digest(&scope).map_err(canonical)?)?;
        let window_digest = commitment(&canonical_digest(&reservation.window).map_err(canonical)?)?;
        let usage = aggregate_snapshot.usages.iter().find(|usage| {
            usage.budget_id == reservation.budget_id && usage.window == reservation.window
        });
        let committed = usage.map_or(0, |value| value.committed_minor);
        let active = usage.map_or(Ok(0), |value| {
            value
                .reserved_minor
                .checked_add(value.outcome_unknown_minor)
                .ok_or(StripeLifecycleProjectionError::InvalidProjection)
        })?;
        capacity.push(CapacityEntryV1::Additive {
            scope_digest,
            window_digest: Some(window_digest),
            unit: UnitId::parse(&format!("minor-{}", reservation.currency.as_str()))
                .map_err(invalid)?,
            ceiling: reservation.limit_minor,
            committed,
            active,
        });
    }
    CapacitySnapshotV1::new(capacity).map_err(invalid)
}

impl StripeLifecycleProjectionV1 {
    /// Consumes the pure projection into a complete durable decision input.
    ///
    /// # Errors
    ///
    /// Rejects malformed digests or derived identifiers before persistence.
    pub fn into_decision_input(
        self,
        bindings: &StripeLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, StripeLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-STRIPE-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-STRIPE-EXECUTION\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let implementation_id = self
            .commitments
            .executed_configuration()
            .implementation_id()
            .cloned()
            .ok_or(StripeLifecycleProjectionError::InvalidProjection)?;
        Ok(DecisionInputV1 {
            core_authorized: true,
            core_authorization_digest: commitment(bindings.core_authorization_digest)?,
            workflow_id: self.workflow_id,
            lifecycle_id: LifecycleId::parse(&lifecycle_id).map_err(invalid)?,
            execution_id: ExecutionId::parse(&execution_id).map_err(invalid)?,
            recovery_reference_digest: auths_lifecycle::RecoveryReferenceDigest::new(
                *commitment(bindings.decision_receipt_digest)?.as_bytes(),
            ),
            domain_id: self.domain_id,
            executor_audience: self.executor_audience,
            reservation_algebra_id: self.reservation_algebra_id,
            commitments: self.commitments,
            outputs: self.outputs,
            reservations: self.reservations,
            decision_receipt_digest: DecisionReceiptDigest::new(
                *commitment(bindings.decision_receipt_digest)?.as_bytes(),
            ),
            domain_decision_receipt_digest: DomainReceiptDigest::new(
                *commitment(bindings.domain_decision_receipt_digest)?.as_bytes(),
            ),
            implementation_id,
            implementation_build_digest: commitment(bindings.implementation_build_digest)?,
            expires_at: VerifierTime::from_unix_seconds(bindings.expires_at),
            cancellation: CancellationDisposition::BeforeAttemptAllowed,
        })
    }

    /// Constructs the exact shared transition context for this evaluated
    /// Stripe snapshot.
    #[must_use]
    pub fn transition_context(&self, verifier_time: u64) -> TransitionContextV1 {
        TransitionContextV1 {
            verifier_time: VerifierTime::from_unix_seconds(verifier_time),
            executed_configuration: self.commitments.executed_configuration().clone(),
            revocation: RevocationSnapshotV1 {
                revoked: false,
                snapshot_digest: commit_bytes(b"auths.stripe.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

#[derive(Serialize)]
struct StripeReservationScope<'a> {
    account: &'a str,
    currency: &'a str,
    budget_id: &'a str,
}

fn configuration_commitment(
    configuration: &StripeBoundedEvaluatorConfigurationV1,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, StripeLifecycleProjectionError> {
    Ok(ConfigurationCommitmentV1::new(
        ConfigurationSemanticId::parse(CONFIGURATION_SEMANTIC_ID).map_err(invalid)?,
        canonicalization_id()?,
        commitment(&configuration.digest().map_err(canonical)?)?,
        executed
            .then(|| ImplementationId::parse(configuration.evaluator_implementation_id()))
            .transpose()
            .map_err(invalid)?,
    ))
}

fn canonicalization_id() -> Result<CanonicalizationId, StripeLifecycleProjectionError> {
    CanonicalizationId::parse(BOUNDED_CANONICALIZATION).map_err(invalid)
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, StripeLifecycleProjectionError> {
    let decoded =
        hex::decode(value.as_str()).map_err(|_| StripeLifecycleProjectionError::InvalidDigest)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| StripeLifecycleProjectionError::InvalidDigest)?;
    Ok(CommitmentDigest::new(bytes))
}

fn commit_bytes(value: &[u8]) -> CommitmentDigest {
    use sha2::{Digest as _, Sha256};

    CommitmentDigest::new(Sha256::digest(value).into())
}

fn derived_identifier(
    domain: &[u8],
    workflow: &str,
    action: CommitmentDigest,
    policy: CommitmentDigest,
) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((workflow.len() as u64).to_be_bytes());
    digest.update(workflow.as_bytes());
    digest.update(action.as_bytes());
    digest.update(policy.as_bytes());
    hex::encode(digest.finalize())
}

fn canonical(_: CanonicalError) -> StripeLifecycleProjectionError {
    StripeLifecycleProjectionError::Canonicalization
}

fn invalid<T>(_: T) -> StripeLifecycleProjectionError {
    StripeLifecycleProjectionError::InvalidProjection
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AggregateBudgetSnapshot, BoundedEvaluationContext, evaluate_bounded_refund,
        test_support::{
            NOW, bounded_action, bounded_configuration, bounded_policy, configuration, evidence,
        },
    };
    use auths_lifecycle::{
        LifecycleState, TransitionCommandV1, TransitionDisposition, apply_transition,
    };

    #[test]
    fn eligible_reference_decision_projects_without_changing_domain_commitments() {
        let exact_configuration = configuration(2_000);
        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let action = bounded_action(
            &exact_configuration,
            &policy,
            &evidence,
            1_000,
            "stripe-demo-workflow-01",
        );
        let bounded_configuration = bounded_configuration(&policy);
        let snapshot = AggregateBudgetSnapshot::default();
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            required_exact_configuration: &exact_configuration,
            executed_exact_configuration: &exact_configuration,
            required_bounded_configuration: &bounded_configuration,
            executed_bounded_configuration: &bounded_configuration,
            request_audience: action.executor_audience(),
            now: NOW,
        });
        let projection = project_refund_lifecycle(&StripeLifecycleProjectionInput {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            decision: &decision,
            required_configuration: &bounded_configuration,
            executed_configuration: &bounded_configuration,
            verifier_time: NOW,
        })
        .unwrap();

        assert_eq!(projection.outputs.reservation_intents().len(), 1);
        assert_eq!(projection.outputs.obligations().len(), 1);
        assert_eq!(projection.reservations.entries().len(), 1);
        assert_eq!(projection.capacity.entries().len(), 1);
        assert_eq!(
            projection.commitments.exact_action_digest(),
            commitment(&action.digest().unwrap()).unwrap()
        );
        assert_eq!(
            projection.commitments.policy_commitment().policy_digest(),
            commitment(&policy.digest().unwrap()).unwrap()
        );
        assert_eq!(
            projection.commitments.evidence_digest(),
            commitment(&evidence.digest().unwrap()).unwrap()
        );
    }

    #[test]
    fn projected_decision_and_reservation_follow_shared_state_machine() {
        let exact_configuration = configuration(2_000);
        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let action = bounded_action(
            &exact_configuration,
            &policy,
            &evidence,
            1_000,
            "stripe-demo-workflow-02",
        );
        let bounded_configuration = bounded_configuration(&policy);
        let snapshot = AggregateBudgetSnapshot::default();
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            required_exact_configuration: &exact_configuration,
            executed_exact_configuration: &exact_configuration,
            required_bounded_configuration: &bounded_configuration,
            executed_bounded_configuration: &bounded_configuration,
            request_audience: action.executor_audience(),
            now: NOW,
        });
        let projection = project_refund_lifecycle(&StripeLifecycleProjectionInput {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            decision: &decision,
            required_configuration: &bounded_configuration,
            executed_configuration: &bounded_configuration,
            verifier_time: NOW,
        })
        .unwrap();
        let context = projection.transition_context(NOW);
        let decision_digest = crate::canonical::sha256(b"stripe-decision-receipt");
        let core_digest = crate::canonical::sha256(b"authorized-core-result");
        let build_digest = crate::canonical::sha256(b"auths-stripe-test-build");
        let decision_input = projection
            .into_decision_input(&StripeLifecycleDecisionBindings {
                core_authorization_digest: &core_digest,
                decision_receipt_digest: &decision_digest,
                domain_decision_receipt_digest: &decision_digest,
                implementation_build_digest: &build_digest,
                expires_at: action.expires_at(),
            })
            .unwrap();
        let recorded = apply_transition(
            None,
            &TransitionCommandV1::RecordDecision(Box::new(decision_input)),
            &context,
        )
        .unwrap();
        assert_eq!(recorded.disposition, TransitionDisposition::Applied);
        assert_eq!(recorded.record.state(), LifecycleState::DecisionRecorded);
        let reserved = apply_transition(
            Some(&recorded.record),
            &TransitionCommandV1::Reserve,
            &context,
        )
        .unwrap();
        assert_eq!(reserved.record.state(), LifecycleState::Reserved);
        assert_eq!(reserved.record.reservations().len(), 1);
    }

    #[test]
    fn denied_reference_decision_cannot_manufacture_lifecycle_outputs() {
        let exact_configuration = configuration(2_000);
        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            500,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let action = bounded_action(
            &exact_configuration,
            &policy,
            &evidence,
            1_000,
            "stripe-demo-workflow-01",
        );
        let bounded_configuration = bounded_configuration(&policy);
        let snapshot = AggregateBudgetSnapshot::default();
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            required_exact_configuration: &exact_configuration,
            executed_exact_configuration: &exact_configuration,
            required_bounded_configuration: &bounded_configuration,
            executed_bounded_configuration: &bounded_configuration,
            request_audience: action.executor_audience(),
            now: NOW,
        });

        assert_eq!(
            project_refund_lifecycle(&StripeLifecycleProjectionInput {
                action: &action,
                policy: &policy,
                evidence: &evidence,
                aggregate_snapshot: &snapshot,
                decision: &decision,
                required_configuration: &bounded_configuration,
                executed_configuration: &bounded_configuration,
                verifier_time: NOW,
            }),
            Err(StripeLifecycleProjectionError::NotEligible)
        );
    }
}
