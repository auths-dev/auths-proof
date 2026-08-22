//! Fixture and mutation tooling for application-profile authors.

#![forbid(unsafe_code)]

mod api;
mod manifest;
mod qualification;
mod qualification_harness;
mod qualification_ledger;
mod roster;

pub use api::{ProfileApi, ProfileApiError, ProfileType};
pub use manifest::{
    ConnectionContract, DomainManifest, ProfileClient, ProfileContracts, ProfileEvidence,
    ProfileLimits, ProfileManifest, ProfilePackage, ProfilePackageError, ProfileSources,
    QualificationManifest,
};
pub use qualification::{
    QualificationArtifact, QualificationAttestation, QualificationCandidateArtifact,
    QualificationError, QualificationEvidenceLedgerReference, QualificationIndex,
    QualificationIndexEntry, QualificationNamedDigest, QualificationObservation,
    QualificationObservationRecord, QualificationObserverTrustRegistry, QualificationProfile,
    QualificationProposal, QualificationProtectedObservation, QualificationProviderCallCount,
    QualificationProviderRun, QualificationRecord, QualificationReleaseBuild,
    QualificationReleaseBuildArtifact, QualificationScenario, QualificationScenarioCaseV1,
    QualificationScenarioExpectation, QualificationScenarioHookStage, QualificationScenarioHookV1,
    QualificationScenarioManifest, QualificationScenarioProgramV1, QualificationScenarioTopology,
    QualificationTarget, QualificationTrustIdentity, QualificationTrustKey,
    QualificationTrustRegistry, QualificationVerifiedRecordBinding, VerifiedQualification,
    VerifiedQualificationObservation, qualification_scenario_program,
    qualification_scenario_program_sha256, validate_qualification_key_separation,
    validate_qualification_trust_separation,
};
pub use qualification_harness::{
    QualificationAdapterMetadata, QualificationAttemptKind, QualificationCandidateCollectionV1,
    QualificationCaseVector, QualificationCleanupEvidence, QualificationCollectedOperation,
    QualificationCollectedScenario, QualificationCollectionAdapter,
    QualificationCommonOperationEvidence, QualificationCommonOperationInstanceEvidence,
    QualificationCommonPhaseEvidence, QualificationCommonReceiptClaims, QualificationCompletion,
    QualificationCounters, QualificationEffect, QualificationFailpoint, QualificationHarnessError,
    QualificationInstalledClient, QualificationInstalledClientOutcome, QualificationOperationRole,
    QualificationOutcomeKind, QualificationPhaseClient, QualificationProtectedObserver,
    QualificationProtectedSetup, QualificationProtectedSetupInput, QualificationProviderTruth,
    QualificationReceiptDecisionClass, QualificationReceiptExecutionOutcome,
    QualificationReceiptState, QualificationRedactedAttempt, QualificationRedactedOperation,
    QualificationRedactedOperationInstance, QualificationRunContext, QualificationRunReference,
    QualificationSetupCaseV1, QualificationSetupHandoffV1, QualificationSetupVectorV1,
    QualificationVector, qualification_pre_admission_attempt_count,
    validate_scenario_program_projection,
};
pub use qualification_ledger::{
    QualificationAdmissionFaultV1, QualificationAgentTrust, QualificationClientBridgeBindingV1,
    QualificationClientProxyObservationV1, QualificationClientProxyRecordV1,
    QualificationCrashActionContextV1, QualificationCrashActionFactsV1,
    QualificationCrashActionRecordV1, QualificationCrashPhaseContextV1,
    QualificationCrashProcessIdentityV1, QualificationCredentialBrokerObservationV1,
    QualificationCredentialBrokerRecordV1, QualificationCredentialRequirementV1,
    QualificationDecisionSnapshotState, QualificationDecisionSnapshotV1,
    QualificationDurableDecisionAckV1, QualificationEvidenceEvent, QualificationEvidenceEventKind,
    QualificationEvidenceEventPayload, QualificationEvidenceLedger,
    QualificationEvidenceLedgerError, QualificationEvidenceLedgerPlanV1,
    QualificationEvidenceLedgerRecord, QualificationEvidenceLedgerTrustRegistry,
    QualificationEvidencePhaseCommitment, QualificationEvidencePhasePlanV1,
    QualificationEvidenceSource, QualificationEvidenceSourceTrustRegistry,
    QualificationJournalDecisionContext, QualificationJournalDecisionContextRecord,
    QualificationJournalState, QualificationProfileStateFactV1,
    QualificationProfileStateObservationV1, QualificationProfileStateRecordV1,
    QualificationProviderObserverRecordV1, QualificationProviderProxyObservationV1,
    QualificationProviderProxyRecordV1, QualificationReceiptVerifierRecordV1,
    QualificationSourceEventContextV1, QualificationSourceProcessBindingV1,
    QualificationSupervisorPhaseRequestV1, qualification_common_phase_matches_ledger,
    qualification_event_marker_sha256, qualification_evidence_event_chain_valid,
    qualification_state_directory_commitment, qualification_supervisor_phase_context_sha256,
};
pub use roster::{
    ProfileQualification, ProfileRoster, ProfileRosterEntry, ProfileRosterError,
    ProfileRosterProfile,
};

use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Language-neutral fixture emitted by a profile's canonicalization contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileFixture {
    /// Exact canonical action CBOR used by the engine boundary.
    pub canonical_action_cbor: Vec<u8>,
    /// SHA-256 of the canonical profile body.
    pub canonical_body_sha256: String,
    /// Human-reviewable profile display with no workflow decision semantics.
    pub review: FixtureReview,
}

/// Serializable neutral review display included in generated fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureReview {
    /// Profile-owned display title.
    pub title: String,
    /// Ordered profile-owned display fields.
    pub fields: Vec<(String, String)>,
    /// Digest the display claims to represent.
    pub canonical_digest_hex: String,
}

impl From<&ReviewDisplay> for FixtureReview {
    fn from(display: &ReviewDisplay) -> Self {
        Self {
            title: display.title().to_owned(),
            fields: display.fields().to_vec(),
            canonical_digest_hex: display.canonical_digest_hex().to_owned(),
        }
    }
}

/// Builds a reproducible cross-language fixture for one profile input.
///
/// The input is canonicalized twice and both complete actions must be equal.
/// The review display must bind the SHA-256 digest of the canonical body.
///
/// # Errors
///
/// Returns a profile error or a conformance error if deterministic
/// canonicalization/display binding is violated.
pub fn build_fixture<P: ActionProfile>(
    profile: &P,
    input: &[u8],
) -> Result<ProfileFixture, ProfileKitError> {
    let first = profile.canonicalize(input)?;
    let second = profile.canonicalize(input)?;
    if first != second {
        return Err(ProfileKitError::NondeterministicCanonicalization);
    }
    let display = profile.review_display(&first)?;
    let body_digest = hex_digest(first.body());
    if display.canonical_digest_hex() != body_digest {
        return Err(ProfileKitError::DisplayDigestMismatch);
    }
    Ok(ProfileFixture {
        canonical_action_cbor: auths_codec::encode_canonical_action(&first)?,
        canonical_body_sha256: body_digest,
        review: FixtureReview::from(&display),
    })
}

/// Serializes a fixture using deterministic compact JSON for other language
/// runners.
///
/// # Errors
///
/// Returns an error only if the serializable fixture cannot be encoded.
pub fn fixture_json(fixture: &ProfileFixture) -> Result<Vec<u8>, ProfileKitError> {
    Ok(serde_json::to_vec(fixture)?)
}

/// Produces bounded generic hostile-input mutations for a profile test suite.
#[must_use]
pub fn hostile_mutations(input: &[u8]) -> Vec<Vec<u8>> {
    let mut mutations = vec![Vec::new()];
    if !input.is_empty() {
        mutations.push(input[..input.len() - 1].to_vec());
        let mut flipped = input.to_vec();
        flipped[input.len() / 2] ^= 0x80;
        mutations.push(flipped);
    }
    let mut suffixed = input.to_vec();
    suffixed.push(0);
    mutations.push(suffixed);
    mutations
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Profile-development contract failure.
#[derive(Debug, Error)]
pub enum ProfileKitError {
    /// Selected profile rejected or could not decode the input.
    #[error("profile contract failed: {0}")]
    Profile(#[from] ProfileContractError),
    /// Repeated canonicalization returned different complete actions.
    #[error("profile canonicalization is nondeterministic")]
    NondeterministicCanonicalization,
    /// Review display did not bind the canonical body digest.
    #[error("review display digest does not bind the canonical action body")]
    DisplayDigestMismatch,
    /// Canonical action CBOR encoding failed.
    #[error("canonical action encoding failed: {0:?}")]
    Codec(auths_codec::CodecError),
    /// Cross-language fixture JSON encoding failed.
    #[error("profile fixture JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<auths_codec::CodecError> for ProfileKitError {
    fn from(error: auths_codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
    };
    use auths_profile_api::ProfileBudgetExpression;
    use auths_verifier::VerifiedAction;
    use std::cell::Cell;

    struct TestProfile {
        calls: Cell<u8>,
        nondeterministic: bool,
    }

    impl ActionProfile for TestProfile {
        type Command = ();

        // `canonicalize` always passes `None`.
        const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Inexpressible;

        fn canonicalize(&self, _untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
            let call = self.calls.get();
            self.calls.set(call.saturating_add(1));
            let body = if self.nondeterministic && call > 0 {
                b"{\"value\":2}".to_vec()
            } else {
                b"{\"value\":1}".to_vec()
            };
            CanonicalAction::new(
                ProfileRef::new(ProfileId::parse("auths.test").unwrap(), 1).unwrap(),
                MediaType::parse("application/json").unwrap(),
                body,
                Permission::new(
                    CapabilityId::parse("test/run").unwrap(),
                    ResourceId::parse("test://fixture").unwrap(),
                ),
                None,
            )
            .map_err(|_| ProfileContractError::MeaningMismatch)
        }

        fn review_display(
            &self,
            action: &CanonicalAction,
        ) -> Result<ReviewDisplay, ProfileContractError> {
            Ok(ReviewDisplay::new(
                "Test",
                Vec::new(),
                hex_digest(action.body()),
            ))
        }

        fn decode_verified(
            &self,
            _action: &VerifiedAction,
        ) -> Result<Self::Command, ProfileContractError> {
            Ok(())
        }
    }

    #[test]
    fn fixture_binds_canonical_bytes_and_display() {
        let fixture = build_fixture(
            &TestProfile {
                calls: Cell::new(0),
                nondeterministic: false,
            },
            b"input",
        )
        .unwrap();
        assert!(!fixture.canonical_action_cbor.is_empty());
        assert_eq!(
            fixture.canonical_body_sha256,
            fixture.review.canonical_digest_hex
        );
    }

    #[test]
    fn fixture_rejects_nondeterministic_profile() {
        let error = build_fixture(
            &TestProfile {
                calls: Cell::new(0),
                nondeterministic: true,
            },
            b"input",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProfileKitError::NondeterministicCanonicalization
        ));
    }
}
