//! Consuming projections for codec-owned canonical reconstruction.
//!
//! These parts are data, not validated replacement models. Rebuilding a model
//! uses its ordinary constructors, which retain all bounds and consistency
//! checks. Moving parts avoids cloning potentially large statement payloads.

use crate::*;
use alloc::vec::Vec;

/// Owned fields of a status snapshot, before constructor validation.
pub struct StatusSnapshotParts<Statement> {
    /// Externally supplied snapshot identity.
    pub id: StatusSnapshotId,
    /// Inclusive observation time.
    pub observed_at: Timestamp,
    /// Inclusive end of coverage.
    pub valid_until: Timestamp,
    /// Complete signed statements, retaining their order and payloads.
    pub statements: Vec<Statement>,
    /// Checkpoint evidence identities.
    pub checkpoints: Vec<EvidenceId>,
    /// Complete issuer trust rules.
    pub trust: Vec<StatusTrustRule>,
}

impl PrincipalStatusSnapshot {
    /// Moves every snapshot field out without changing or cloning a value.
    #[must_use]
    pub fn into_parts(self) -> StatusSnapshotParts<SignedPrincipalStatus> {
        StatusSnapshotParts {
            id: self.id, observed_at: self.observed_at, valid_until: self.valid_until,
            statements: self.statements, checkpoints: self.checkpoints, trust: self.trust,
        }
    }
}

impl GrantStatusSnapshot {
    /// Moves every snapshot field out without changing or cloning a value.
    #[must_use]
    pub fn into_parts(self) -> StatusSnapshotParts<SignedGrantStatus> {
        StatusSnapshotParts {
            id: self.id, observed_at: self.observed_at, valid_until: self.valid_until,
            statements: self.statements, checkpoints: self.checkpoints, trust: self.trust,
        }
    }
}

/// Owned proof fields for reconstruction through [`ProofBundle::new`].
pub struct ProofBundleParts {
    /// Exact protocol header.
    pub header: BundleHeader,
    /// Complete signed grants.
    pub grants: Vec<SignedGrant>,
    /// Complete signed actions.
    pub actions: Vec<SignedAction>,
    /// Complete authorization plan.
    pub plan: AuthorizationPlan,
    /// Complete control evidence.
    pub evidence: Vec<EvidenceObject>,
    /// Statement-to-evidence bindings.
    pub bindings: Vec<ControlBinding>,
    /// Complete signed principal status.
    pub principal_status: Vec<SignedPrincipalStatus>,
    /// Complete signed grant status.
    pub grant_status: Vec<SignedGrantStatus>,
    /// Signed attachment descriptors.
    pub attachments: Vec<AttachmentDescriptor>,
    /// Optional exact inline body.
    pub canonical_body: Option<Vec<u8>>,
    /// Complete signed approvals, retaining order and repetitions.
    pub approvals: Vec<SignedApproval>,
}

impl ProofBundle {
    /// Moves all proof fields out. Reconstruct using the ordinary validated
    /// constructor and [`Self::with_approvals`].
    #[must_use]
    pub fn into_parts(self) -> ProofBundleParts {
        ProofBundleParts {
            header: self.header, grants: self.grants, actions: self.actions, plan: self.plan,
            evidence: self.evidence, bindings: self.bindings, principal_status: self.principal_status,
            grant_status: self.grant_status, attachments: self.attachments,
            canonical_body: self.canonical_body, approvals: self.approvals,
        }
    }
}

/// Owned context fields for reconstruction through [`TrustedContext::new`]
/// and its validated observer/approval builders.
pub struct TrustedContextParts {
    /// Exact executable configuration commitment.
    pub configuration: VerifierConfigurationId,
    /// Exact branch, actor and root requirements.
    pub composition: CompositionRequirement,
    /// Complete authority anchors.
    pub trust_anchors: Vec<TrustAnchor>,
    /// Complete accepted registry selection.
    pub accepted_registries: AcceptedRegistries,
    /// Exact relying-party audience.
    pub expected_audience: Audience,
    /// Exact relying-party challenge.
    pub expected_challenge: Challenge,
    /// Verifier evaluation time.
    pub evaluation_time: Timestamp,
    /// Complete assurance requirements.
    pub assurance_policy: AssurancePolicy,
    /// Complete principal lifecycle snapshot.
    pub principal_status_snapshot: PrincipalStatusSnapshot,
    /// Complete grant lifecycle snapshot.
    pub grant_status_snapshot: GrantStatusSnapshot,
    /// Selected resource matcher.
    pub resource_matcher: ResourceMatcherId,
    /// Selected profile policy.
    pub profile_policy: ProfilePolicyId,
    /// Selected channel policy.
    pub channel_policy: ChannelBindingId,
    /// Exact deployment bounds.
    pub limits: VerifierLimits,
    /// Complete observer roster.
    pub observer_anchors: Vec<ObserverAnchor>,
    /// Complete approver roster.
    pub approver_anchors: Vec<ApproverAnchor>,
    /// Complete approval requirements in stored order.
    pub approval_requirements: Vec<ApprovalRequirement>,
}

impl TrustedContext {
    /// Moves every context field without cloning, changing its configuration,
    /// or dropping either observer or approver state.
    #[must_use]
    pub fn into_parts(self) -> TrustedContextParts {
        TrustedContextParts {
            configuration: self.configuration, composition: self.composition,
            trust_anchors: self.trust_anchors, accepted_registries: self.accepted_registries,
            expected_audience: self.expected_audience, expected_challenge: self.expected_challenge,
            evaluation_time: self.evaluation_time, assurance_policy: self.assurance_policy,
            principal_status_snapshot: self.principal_status_snapshot,
            grant_status_snapshot: self.grant_status_snapshot, resource_matcher: self.resource_matcher,
            profile_policy: self.profile_policy, channel_policy: self.channel_policy,
            limits: self.limits, observer_anchors: self.observer_anchors,
            approver_anchors: self.approver_anchors, approval_requirements: self.approval_requirements,
        }
    }
}
