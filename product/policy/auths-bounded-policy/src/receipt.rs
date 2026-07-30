use crate::{
    CommitmentDigest, ConfigurationCommitmentV1, EligibilityV1, EvaluationCommitmentsV1,
    ImplementationId, ProfileId, VerifierTime,
};

/// Commitment-only decision envelope.
///
/// This envelope never claims that a provider accepted, executed, propagated,
/// or converged on an effect. The domain's canonical receipt remains
/// authoritative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDecisionEnvelopeV1 {
    profile: ProfileId,
    exact_action_digest: CommitmentDigest,
    policy_digest: CommitmentDigest,
    evaluator_semantic_id: crate::EvaluatorSemanticId,
    evidence_digest: CommitmentDigest,
    state_snapshot_digest: CommitmentDigest,
    verifier_time: VerifierTime,
    required_configuration: ConfigurationCommitmentV1,
    executed_configuration: ConfigurationCommitmentV1,
    eligibility: EligibilityV1,
    evaluator_implementation: ImplementationId,
    evaluator_build_digest: CommitmentDigest,
    domain_decision_receipt_digest: CommitmentDigest,
    previous_receipt_digest: Option<CommitmentDigest>,
}

impl BoundedDecisionEnvelopeV1 {
    /// Constructs a decision envelope from explicit evaluation commitments.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        commitments: &EvaluationCommitmentsV1,
        eligibility: EligibilityV1,
        evaluator_implementation: ImplementationId,
        evaluator_build_digest: CommitmentDigest,
        domain_decision_receipt_digest: CommitmentDigest,
        previous_receipt_digest: Option<CommitmentDigest>,
    ) -> Self {
        Self {
            profile: commitments.profile_id().clone(),
            exact_action_digest: commitments.exact_action_digest(),
            policy_digest: commitments.policy_commitment().policy_digest(),
            evaluator_semantic_id: commitments
                .policy_commitment()
                .evaluator_semantic_id()
                .clone(),
            evidence_digest: commitments.evidence_digest(),
            state_snapshot_digest: commitments.state_snapshot_digest(),
            verifier_time: commitments.verifier_time(),
            required_configuration: commitments.required_configuration().clone(),
            executed_configuration: commitments.executed_configuration().clone(),
            eligibility,
            evaluator_implementation,
            evaluator_build_digest,
            domain_decision_receipt_digest,
            previous_receipt_digest,
        }
    }

    /// Returns the selected profile.
    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Returns the exact action digest.
    #[must_use]
    pub const fn exact_action_digest(&self) -> CommitmentDigest {
        self.exact_action_digest
    }

    /// Returns the canonical policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> CommitmentDigest {
        self.policy_digest
    }

    /// Returns the evaluator semantics.
    #[must_use]
    pub const fn evaluator_semantic_id(&self) -> &crate::EvaluatorSemanticId {
        &self.evaluator_semantic_id
    }

    /// Returns the evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> CommitmentDigest {
        self.evidence_digest
    }

    /// Returns the state snapshot digest.
    #[must_use]
    pub const fn state_snapshot_digest(&self) -> CommitmentDigest {
        self.state_snapshot_digest
    }

    /// Returns explicit verifier time.
    #[must_use]
    pub const fn verifier_time(&self) -> VerifierTime {
        self.verifier_time
    }

    /// Returns required configuration.
    #[must_use]
    pub const fn required_configuration(&self) -> &ConfigurationCommitmentV1 {
        &self.required_configuration
    }

    /// Returns executed configuration.
    #[must_use]
    pub const fn executed_configuration(&self) -> &ConfigurationCommitmentV1 {
        &self.executed_configuration
    }

    /// Returns the pure decision.
    #[must_use]
    pub const fn eligibility(&self) -> &EligibilityV1 {
        &self.eligibility
    }

    /// Returns implementation provenance.
    #[must_use]
    pub const fn evaluator_implementation(&self) -> &ImplementationId {
        &self.evaluator_implementation
    }

    /// Returns build provenance.
    #[must_use]
    pub const fn evaluator_build_digest(&self) -> CommitmentDigest {
        self.evaluator_build_digest
    }

    /// Returns the domain's authoritative decision-receipt digest.
    #[must_use]
    pub const fn domain_decision_receipt_digest(&self) -> CommitmentDigest {
        self.domain_decision_receipt_digest
    }

    /// Returns optional receipt chaining.
    #[must_use]
    pub const fn previous_receipt_digest(&self) -> Option<CommitmentDigest> {
        self.previous_receipt_digest
    }
}
