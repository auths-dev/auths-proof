use crate::{
    CanonicalizationId, CommitmentDigest, ConfigurationSemanticId, EvaluatorSemanticId,
    EvidenceSourceId, ImplementationId, PolicyTypeId, ProfileId, SchemaId, VerifierTime,
    kernel::{ConfigurationMatchCode, configuration_match_code},
};

/// Immutable commitment to one closed domain policy and evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCommitmentV1 {
    policy_type: PolicyTypeId,
    policy_version: u16,
    canonicalization_id: CanonicalizationId,
    policy_digest: CommitmentDigest,
    evaluator_semantic_id: EvaluatorSemanticId,
}

impl PolicyCommitmentV1 {
    /// Constructs a policy commitment. Version zero is not a V1 schema.
    pub fn new(
        policy_type: PolicyTypeId,
        policy_version: u16,
        canonicalization_id: CanonicalizationId,
        policy_digest: CommitmentDigest,
        evaluator_semantic_id: EvaluatorSemanticId,
    ) -> Result<Self, CommitmentError> {
        if policy_version == 0 {
            return Err(CommitmentError::ZeroVersion);
        }
        Ok(Self {
            policy_type,
            policy_version,
            canonicalization_id,
            policy_digest,
            evaluator_semantic_id,
        })
    }

    /// Returns the closed policy schema identity.
    #[must_use]
    pub const fn policy_type(&self) -> &PolicyTypeId {
        &self.policy_type
    }

    /// Returns the non-zero policy schema version.
    #[must_use]
    pub const fn policy_version(&self) -> u16 {
        self.policy_version
    }

    /// Returns the immutable canonicalization identity.
    #[must_use]
    pub const fn canonicalization_id(&self) -> &CanonicalizationId {
        &self.canonicalization_id
    }

    /// Returns the domain-separated canonical policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> CommitmentDigest {
        self.policy_digest
    }

    /// Returns the immutable total evaluator identity.
    #[must_use]
    pub const fn evaluator_semantic_id(&self) -> &EvaluatorSemanticId {
        &self.evaluator_semantic_id
    }
}

/// Commitment to the configuration one evaluator required or executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationCommitmentV1 {
    semantic_id: ConfigurationSemanticId,
    canonicalization_id: CanonicalizationId,
    configuration_digest: CommitmentDigest,
    implementation_id: Option<ImplementationId>,
}

impl ConfigurationCommitmentV1 {
    /// Constructs a configuration commitment.
    ///
    /// A required commitment may omit `implementation_id` to permit any
    /// registered implementation of the exact semantics. An executed
    /// commitment records the implementation that actually ran.
    #[must_use]
    pub const fn new(
        semantic_id: ConfigurationSemanticId,
        canonicalization_id: CanonicalizationId,
        configuration_digest: CommitmentDigest,
        implementation_id: Option<ImplementationId>,
    ) -> Self {
        Self {
            semantic_id,
            canonicalization_id,
            configuration_digest,
            implementation_id,
        }
    }

    /// Returns the semantic identity.
    #[must_use]
    pub const fn semantic_id(&self) -> &ConfigurationSemanticId {
        &self.semantic_id
    }

    /// Returns the canonicalization identity.
    #[must_use]
    pub const fn canonicalization_id(&self) -> &CanonicalizationId {
        &self.canonicalization_id
    }

    /// Returns the canonical configuration digest.
    #[must_use]
    pub const fn configuration_digest(&self) -> CommitmentDigest {
        self.configuration_digest
    }

    /// Returns the optional pinned or executed implementation.
    #[must_use]
    pub const fn implementation_id(&self) -> Option<&ImplementationId> {
        self.implementation_id.as_ref()
    }
}

/// Complete explicit commitments supplied to one pure evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationCommitmentsV1 {
    profile_id: ProfileId,
    exact_action_digest: CommitmentDigest,
    policy_commitment: PolicyCommitmentV1,
    evidence_schema_id: SchemaId,
    evidence_digest: CommitmentDigest,
    evidence_source_id: EvidenceSourceId,
    evidence_observed_at: VerifierTime,
    state_snapshot_schema_id: SchemaId,
    state_snapshot_digest: CommitmentDigest,
    verifier_time: VerifierTime,
    required_configuration: ConfigurationCommitmentV1,
    executed_configuration: ConfigurationCommitmentV1,
}

impl EvaluationCommitmentsV1 {
    /// Constructs a complete, I/O-free evaluation context.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        profile_id: ProfileId,
        exact_action_digest: CommitmentDigest,
        policy_commitment: PolicyCommitmentV1,
        evidence_schema_id: SchemaId,
        evidence_digest: CommitmentDigest,
        evidence_source_id: EvidenceSourceId,
        evidence_observed_at: VerifierTime,
        state_snapshot_schema_id: SchemaId,
        state_snapshot_digest: CommitmentDigest,
        verifier_time: VerifierTime,
        required_configuration: ConfigurationCommitmentV1,
        executed_configuration: ConfigurationCommitmentV1,
    ) -> Self {
        Self {
            profile_id,
            exact_action_digest,
            policy_commitment,
            evidence_schema_id,
            evidence_digest,
            evidence_source_id,
            evidence_observed_at,
            state_snapshot_schema_id,
            state_snapshot_digest,
            verifier_time,
            required_configuration,
            executed_configuration,
        }
    }

    /// Returns the selected profile identity.
    #[must_use]
    pub const fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Returns the exact canonical action commitment.
    #[must_use]
    pub const fn exact_action_digest(&self) -> CommitmentDigest {
        self.exact_action_digest
    }

    /// Returns the immutable policy/evaluator commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> &PolicyCommitmentV1 {
        &self.policy_commitment
    }

    /// Returns the evidence schema.
    #[must_use]
    pub const fn evidence_schema_id(&self) -> &SchemaId {
        &self.evidence_schema_id
    }

    /// Returns the evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> CommitmentDigest {
        self.evidence_digest
    }

    /// Returns the evidence acquisition identity.
    #[must_use]
    pub const fn evidence_source_id(&self) -> &EvidenceSourceId {
        &self.evidence_source_id
    }

    /// Returns when evidence was observed.
    #[must_use]
    pub const fn evidence_observed_at(&self) -> VerifierTime {
        self.evidence_observed_at
    }

    /// Returns the state snapshot schema.
    #[must_use]
    pub const fn state_snapshot_schema_id(&self) -> &SchemaId {
        &self.state_snapshot_schema_id
    }

    /// Returns the exact state snapshot commitment.
    #[must_use]
    pub const fn state_snapshot_digest(&self) -> CommitmentDigest {
        self.state_snapshot_digest
    }

    /// Returns the explicit verifier time.
    #[must_use]
    pub const fn verifier_time(&self) -> VerifierTime {
        self.verifier_time
    }

    /// Returns the configuration required by the caller/context.
    #[must_use]
    pub const fn required_configuration(&self) -> &ConfigurationCommitmentV1 {
        &self.required_configuration
    }

    /// Returns the configuration actually executed.
    #[must_use]
    pub const fn executed_configuration(&self) -> &ConfigurationCommitmentV1 {
        &self.executed_configuration
    }
}

/// Total result of the configuration equality gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationMatch {
    /// Required and executed meaning match exactly.
    Match,
    /// Semantic identity differs.
    SemanticMismatch,
    /// Canonicalization identity differs.
    CanonicalizationMismatch,
    /// Canonical configuration bytes differ.
    DigestMismatch,
    /// A required implementation pin differs or execution omitted provenance.
    ImplementationMismatch,
}

/// Compares required and executed configuration in immutable diagnostic order.
#[must_use]
pub fn configuration_match(
    required: &ConfigurationCommitmentV1,
    executed: &ConfigurationCommitmentV1,
) -> ConfigurationMatch {
    let implementation_equal_or_unpinned = !required
        .implementation_id
        .as_ref()
        .is_some_and(|required_id| executed.implementation_id.as_ref() != Some(required_id));
    match configuration_match_code(
        required.semantic_id == executed.semantic_id,
        required.canonicalization_id == executed.canonicalization_id,
        required.configuration_digest == executed.configuration_digest,
        implementation_equal_or_unpinned,
    ) {
        ConfigurationMatchCode::Match => ConfigurationMatch::Match,
        ConfigurationMatchCode::SemanticMismatch => ConfigurationMatch::SemanticMismatch,
        ConfigurationMatchCode::CanonicalizationMismatch => {
            ConfigurationMatch::CanonicalizationMismatch
        }
        ConfigurationMatchCode::DigestMismatch => ConfigurationMatch::DigestMismatch,
        ConfigurationMatchCode::ImplementationMismatch => {
            ConfigurationMatch::ImplementationMismatch
        }
    }
}

/// Invalid commitment carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentError {
    /// Schema version zero is reserved as invalid.
    ZeroVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(
        semantic: &str,
        canonicalization: &str,
        digest: u8,
        implementation: Option<&str>,
    ) -> ConfigurationCommitmentV1 {
        ConfigurationCommitmentV1::new(
            ConfigurationSemanticId::parse(semantic).unwrap(),
            CanonicalizationId::parse(canonicalization).unwrap(),
            CommitmentDigest::new([digest; 32]),
            implementation.map(|value| ImplementationId::parse(value).unwrap()),
        )
    }

    #[test]
    fn required_and_executed_can_differ_and_are_reported() {
        let required = configuration("config/1", "canon/1", 1, Some("reference/1"));
        let executed = configuration("config/1", "canon/1", 1, Some("optimized/1"));
        assert_eq!(
            configuration_match(&required, &executed),
            ConfigurationMatch::ImplementationMismatch
        );
        assert_ne!(required, executed);
    }

    #[test]
    fn unpinned_required_configuration_accepts_registered_equivalent_build() {
        let required = configuration("config/1", "canon/1", 1, None);
        let executed = configuration("config/1", "canon/1", 1, Some("optimized/1"));
        assert_eq!(
            configuration_match(&required, &executed),
            ConfigurationMatch::Match
        );
    }

    #[test]
    fn mismatch_order_is_immutable_and_fail_closed() {
        let required = configuration("required/1", "canon-a/1", 1, Some("required/1"));
        let executed = configuration("executed/1", "canon-b/1", 2, Some("executed/1"));
        assert_eq!(
            configuration_match(&required, &executed),
            ConfigurationMatch::SemanticMismatch
        );
    }

    #[test]
    fn every_configuration_field_mutation_has_one_stable_diagnostic() {
        let required = configuration("config/1", "canon/1", 1, Some("reference/1"));
        for (executed, expected) in [
            (
                configuration("config/2", "canon/1", 1, Some("reference/1")),
                ConfigurationMatch::SemanticMismatch,
            ),
            (
                configuration("config/1", "canon/2", 1, Some("reference/1")),
                ConfigurationMatch::CanonicalizationMismatch,
            ),
            (
                configuration("config/1", "canon/1", 2, Some("reference/1")),
                ConfigurationMatch::DigestMismatch,
            ),
            (
                configuration("config/1", "canon/1", 1, Some("optimized/1")),
                ConfigurationMatch::ImplementationMismatch,
            ),
        ] {
            assert_eq!(configuration_match(&required, &executed), expected);
        }
    }
}
