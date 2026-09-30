//! Native K-of-N approval vocabulary.
//!
//! An approval requirement names a set of approver principals and a
//! threshold K. It is carried by the trusted context, where the relying
//! party fixes it, or by a grant's `approval-requirement-v1` critical
//! extension, where the issuer conditions the authority it delegates. An
//! approver approves one exact action by signing an approval statement that
//! binds the action's meaning, the relying party's audience and challenge,
//! and the requirement's identifier. Approvals confer no authority: an
//! approver is never a trust anchor, a branch, or an actor.
//!
//! The predicates at the end of this module are pure, bounded, and written in
//! the restricted style the mechanical Rust-to-Lean translation accepts.

use crate::{
    ApprovalDigest, ApprovalRequirementId, Audience, BudgetCeiling, Challenge, Digest,
    EvidenceObject, HARD_MAX_REGISTRY_ENTRIES, MediaType, ModelError, Permission, PrincipalId,
    PrincipalMethodId, ProtocolVersion, SignatureEnvelope, StatusPolicy, ValidityWindow,
    principal_id_equal,
};
use alloc::vec::Vec;

/// Maximum approver principals named by one approval requirement.
pub const MAX_APPROVERS_PER_REQUIREMENT: usize = 16;
/// Maximum approval requirements carried by one grant.
pub const MAX_APPROVAL_REQUIREMENTS_PER_GRANT: usize = 4;
/// Maximum distinct approval requirements evaluated for one grant chain.
pub const MAX_APPROVAL_REQUIREMENTS_PER_CHAIN: usize = 16;
/// Maximum distinct approval requirements evaluated in one verification.
pub const MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION: usize = 64;
/// Maximum bytes of one canonical signed approval.
pub const MAX_SIGNED_APPROVAL_BYTES: usize = 4_096;
/// Maximum control-evidence objects carried by one signed approval.
pub const MAX_APPROVAL_EVIDENCE: usize = 4;

/// "K of these N principals": one to sixteen distinct approvers and a
/// threshold between one and their number.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ApprovalRequirement {
    approvers: Vec<PrincipalId>,
    threshold: u16,
}

impl ApprovalRequirement {
    /// Constructs a requirement with its approvers in canonical ascending
    /// order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidApprovalRequirement`] for no approvers,
    /// more than [`MAX_APPROVERS_PER_REQUIREMENT`], a repeated approver, a zero
    /// threshold, or a threshold above the number of approvers.
    pub fn new(mut approvers: Vec<PrincipalId>, threshold: u16) -> Result<Self, ModelError> {
        approvers.sort();
        if approvers.is_empty()
            || approvers.len() > MAX_APPROVERS_PER_REQUIREMENT
            || approvers.windows(2).any(|window| window[0] == window[1])
            || threshold == 0
            || usize::from(threshold) > approvers.len()
        {
            return Err(ModelError::InvalidApprovalRequirement);
        }
        Ok(Self {
            approvers,
            threshold,
        })
    }

    /// Returns the approver principals in ascending order.
    #[must_use]
    pub fn approvers(&self) -> &[PrincipalId] {
        &self.approvers
    }

    /// Returns K, the number of distinct approvers that must approve.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }
}

/// The one to four requirements carried by a grant's
/// `approval-requirement-v1` critical extension. The canonical encoding
/// orders them by identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequirements(Vec<ApprovalRequirement>);

impl ApprovalRequirements {
    /// Validates a bounded, duplicate-free requirement list.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidApprovalRequirement`] for an empty list or
    /// a repeated requirement, and [`ModelError::CollectionLimitExceeded`]
    /// above [`MAX_APPROVAL_REQUIREMENTS_PER_GRANT`].
    pub fn new(requirements: Vec<ApprovalRequirement>) -> Result<Self, ModelError> {
        if requirements.is_empty() {
            return Err(ModelError::InvalidApprovalRequirement);
        }
        if requirements.len() > MAX_APPROVAL_REQUIREMENTS_PER_GRANT {
            return Err(ModelError::CollectionLimitExceeded);
        }
        for (index, requirement) in requirements.iter().enumerate() {
            if requirements[..index].contains(requirement) {
                return Err(ModelError::InvalidApprovalRequirement);
            }
        }
        Ok(Self(requirements))
    }

    /// Returns the requirements.
    #[must_use]
    pub fn as_slice(&self) -> &[ApprovalRequirement] {
        &self.0
    }
}

/// How the verifier checks one approver: accepted principal methods, a
/// validity window, and a principal-status policy. An approver anchor lets
/// the verifier check that approver's signatures and nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproverAnchor {
    principal: PrincipalId,
    accepted_methods: Vec<PrincipalMethodId>,
    validity: ValidityWindow,
    status_policy: StatusPolicy,
}

impl ApproverAnchor {
    /// Constructs a canonical approver anchor.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidApproverAnchor`] when the accepted method
    /// list is empty or exceeds the registry bound.
    pub fn new(
        principal: PrincipalId,
        mut accepted_methods: Vec<PrincipalMethodId>,
        validity: ValidityWindow,
        status_policy: StatusPolicy,
    ) -> Result<Self, ModelError> {
        accepted_methods.sort();
        accepted_methods.dedup();
        if accepted_methods.is_empty() || accepted_methods.len() > HARD_MAX_REGISTRY_ENTRIES {
            return Err(ModelError::InvalidApproverAnchor);
        }
        Ok(Self {
            principal,
            accepted_methods,
            validity,
            status_policy,
        })
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn accepted_methods(&self) -> &[PrincipalMethodId] {
        &self.accepted_methods
    }

    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }

    #[must_use]
    pub const fn status_policy(&self) -> &StatusPolicy {
        &self.status_policy
    }
}

/// What an approver signs: the exact action's meaning, the relying party's
/// audience and challenge, the requirement it approves for, and a window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalStatement {
    version: ProtocolVersion,
    approver: PrincipalId,
    requirement: ApprovalRequirementId,
    media_type: MediaType,
    body_digest: Digest,
    permission: Permission,
    requested_budget: Option<BudgetCeiling>,
    attributes: Option<Digest>,
    audience: Audience,
    challenge: Challenge,
    validity: ValidityWindow,
}

impl ApprovalStatement {
    /// Constructs an approval statement for protocol V1.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        approver: PrincipalId,
        requirement: ApprovalRequirementId,
        media_type: MediaType,
        body_digest: Digest,
        permission: Permission,
        requested_budget: Option<BudgetCeiling>,
        attributes: Option<Digest>,
        audience: Audience,
        challenge: Challenge,
        validity: ValidityWindow,
    ) -> Self {
        Self {
            version: ProtocolVersion::V1,
            approver,
            requirement,
            media_type,
            body_digest,
            permission,
            requested_budget,
            attributes,
            audience,
            challenge,
            validity,
        }
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }
    #[must_use]
    pub const fn approver(&self) -> &PrincipalId {
        &self.approver
    }
    #[must_use]
    pub const fn requirement(&self) -> ApprovalRequirementId {
        self.requirement
    }
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }
    /// Returns the SHA-256 of the approved canonical body.
    #[must_use]
    pub const fn body_digest(&self) -> Digest {
        self.body_digest
    }
    #[must_use]
    pub const fn permission(&self) -> &Permission {
        &self.permission
    }
    #[must_use]
    pub const fn requested_budget(&self) -> Option<&BudgetCeiling> {
        self.requested_budget.as_ref()
    }
    /// Returns the request-attributes digest, which canonical actions do not
    /// carry yet, so a matching approval has none.
    #[must_use]
    pub const fn attributes(&self) -> Option<Digest> {
        self.attributes
    }
    #[must_use]
    pub const fn audience(&self) -> &Audience {
        &self.audience
    }
    #[must_use]
    pub const fn challenge(&self) -> Challenge {
        self.challenge
    }
    #[must_use]
    pub const fn validity(&self) -> ValidityWindow {
        self.validity
    }
}

/// An approval statement, the approver's signature, and the approver's
/// bounded control evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedApproval {
    statement: ApprovalStatement,
    signature: SignatureEnvelope,
    evidence: Vec<EvidenceObject>,
}

impl SignedApproval {
    /// Constructs a signed approval with canonical control evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidApproval`] for more than
    /// [`MAX_APPROVAL_EVIDENCE`] evidence objects or a repeated evidence
    /// identifier.
    pub fn new(
        statement: ApprovalStatement,
        signature: SignatureEnvelope,
        mut evidence: Vec<EvidenceObject>,
    ) -> Result<Self, ModelError> {
        if evidence.len() > MAX_APPROVAL_EVIDENCE {
            return Err(ModelError::InvalidApproval);
        }
        evidence.sort_by_key(EvidenceObject::id);
        if evidence
            .windows(2)
            .any(|window| window[0].id() == window[1].id())
        {
            return Err(ModelError::InvalidApproval);
        }
        Ok(Self {
            statement,
            signature,
            evidence,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &ApprovalStatement {
        &self.statement
    }
    #[must_use]
    pub const fn signature(&self) -> &SignatureEnvelope {
        &self.signature
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }
}

/// The approvals that counted for one requirement that authorized, reported
/// in the portable result.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ApprovalSatisfaction {
    requirement: ApprovalRequirementId,
    approvals: Vec<ApprovalDigest>,
}

impl ApprovalSatisfaction {
    /// Constructs a satisfaction with its approval digests in ascending order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidApproval`] for no digest, more than
    /// [`MAX_APPROVERS_PER_REQUIREMENT`], or a repeated digest.
    pub fn new(
        requirement: ApprovalRequirementId,
        mut approvals: Vec<ApprovalDigest>,
    ) -> Result<Self, ModelError> {
        approvals.sort();
        if approvals.is_empty()
            || approvals.len() > MAX_APPROVERS_PER_REQUIREMENT
            || approvals.windows(2).any(|window| window[0] == window[1])
        {
            return Err(ModelError::InvalidApproval);
        }
        Ok(Self {
            requirement,
            approvals,
        })
    }

    /// Content identifier of the satisfied requirement.
    #[must_use]
    pub const fn requirement(&self) -> ApprovalRequirementId {
        self.requirement
    }

    /// Digests of the approvals that counted, one per counted approver.
    #[must_use]
    pub fn approvals(&self) -> &[ApprovalDigest] {
        &self.approvals
    }
}

/// One approval's verdict for one requirement.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalVerdict {
    /// Authentic, current, bound to this exact action and requirement, and
    /// from an eligible approver.
    Counted,
    /// Eligible, but its signature or status could not be decided.
    Pending,
    /// Ineligible, or invalid.
    Ignored,
}

/// One approval's approver and verdict, as the counting predicate consumes
/// them.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalOutcome {
    approver: PrincipalId,
    verdict: ApprovalVerdict,
}

impl ApprovalOutcome {
    #[must_use]
    pub const fn new(approver: PrincipalId, verdict: ApprovalVerdict) -> Self {
        Self { approver, verdict }
    }
    #[must_use]
    pub const fn approver(&self) -> &PrincipalId {
        &self.approver
    }
    #[must_use]
    pub const fn verdict(&self) -> ApprovalVerdict {
        self.verdict
    }
}

/// Distinct approver counts for one requirement.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalCounts {
    /// Listed approvers with a counted approval.
    pub counted: usize,
    /// Listed approvers with a pending and no counted approval.
    pub pending: usize,
}

/// The verdict of one approver over per-approval outcomes: counted when some
/// outcome for it is counted, pending when none is counted and some is
/// pending, and ignored otherwise.
#[doc(hidden)]
#[must_use]
pub fn approver_verdict(outcomes: &[ApprovalOutcome], approver: &PrincipalId) -> ApprovalVerdict {
    let mut pending = false;
    let mut index = 0;
    while index < outcomes.len() {
        if principal_id_equal(&outcomes[index].approver, approver) {
            match outcomes[index].verdict {
                ApprovalVerdict::Counted => return ApprovalVerdict::Counted,
                ApprovalVerdict::Pending => pending = true,
                ApprovalVerdict::Ignored => {}
            }
        }
        index += 1;
    }
    if pending {
        ApprovalVerdict::Pending
    } else {
        ApprovalVerdict::Ignored
    }
}

/// Distinct counting over per-approval outcomes: each listed approver counts
/// once, as counted, pending, or not at all. The requirement's decision is
/// the generated `threshold_counts(K, counted, pending)`.
#[doc(hidden)]
#[must_use]
pub fn approval_counts(approvers: &[PrincipalId], outcomes: &[ApprovalOutcome]) -> ApprovalCounts {
    let mut counted = 0;
    let mut pending = 0;
    let mut index = 0;
    while index < approvers.len() {
        match approver_verdict(outcomes, &approvers[index]) {
            ApprovalVerdict::Counted => counted += 1,
            ApprovalVerdict::Pending => pending += 1,
            ApprovalVerdict::Ignored => {}
        }
        index += 1;
    }
    ApprovalCounts { counted, pending }
}

/// Whether `principals` contains `principal`.
#[doc(hidden)]
#[must_use]
pub fn principal_ids_contain(principals: &[PrincipalId], principal: &PrincipalId) -> bool {
    let mut index = 0;
    while index < principals.len() {
        if principal_id_equal(&principals[index], principal) {
            return true;
        }
        index += 1;
    }
    false
}

/// Whether every principal of `narrower` is in `wider`.
#[doc(hidden)]
#[must_use]
pub fn principal_ids_subset(narrower: &[PrincipalId], wider: &[PrincipalId]) -> bool {
    let mut index = 0;
    while index < narrower.len() {
        if !principal_ids_contain(wider, &narrower[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// A child requirement covers a parent requirement when its approvers are a
/// subset of the parent's and its threshold is at least the parent's. Byte
/// identity is the case of equal sets and equal thresholds.
#[doc(hidden)]
#[must_use]
pub fn approval_requirement_covers(
    child: &ApprovalRequirement,
    parent: &ApprovalRequirement,
) -> bool {
    if !principal_ids_subset(&child.approvers, &parent.approvers) {
        return false;
    }
    child.threshold >= parent.threshold
}

/// Some child requirement covers the parent requirement.
#[doc(hidden)]
#[must_use]
pub fn approval_requirement_retained(
    child: &ApprovalRequirements,
    parent: &ApprovalRequirement,
) -> bool {
    let mut index = 0;
    while index < child.0.len() {
        if approval_requirement_covers(&child.0[index], parent) {
            return true;
        }
        index += 1;
    }
    false
}

/// The `approval-requirement-v1` attenuation law for a child and parent that
/// both carry the extension: every parent requirement is covered by some
/// child requirement. The child may add requirements.
#[doc(hidden)]
#[must_use]
pub fn approval_requirements_attenuate(
    child: &ApprovalRequirements,
    parent: &ApprovalRequirements,
) -> bool {
    let mut index = 0;
    while index < parent.0.len() {
        if !approval_requirement_retained(child, &parent.0[index]) {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn principal(index: usize) -> PrincipalId {
        PrincipalId::parse(&alloc::format!("test:approver-{index:02}")).expect("principal")
    }

    fn verdict_of(code: u8) -> ApprovalVerdict {
        match code % 3 {
            0 => ApprovalVerdict::Counted,
            1 => ApprovalVerdict::Pending,
            _ => ApprovalVerdict::Ignored,
        }
    }

    /// Brute-force distinct counting from the definition.
    fn reference(approvers: &[PrincipalId], outcomes: &[ApprovalOutcome]) -> ApprovalCounts {
        let mut counts = ApprovalCounts {
            counted: 0,
            pending: 0,
        };
        for approver in approvers {
            let mine: Vec<_> = outcomes
                .iter()
                .filter(|outcome| outcome.approver() == approver)
                .collect();
            if mine
                .iter()
                .any(|outcome| outcome.verdict() == ApprovalVerdict::Counted)
            {
                counts.counted += 1;
            } else if mine
                .iter()
                .any(|outcome| outcome.verdict() == ApprovalVerdict::Pending)
            {
                counts.pending += 1;
            }
        }
        counts
    }

    proptest! {
        #[test]
        fn counting_is_distinct_and_order_and_repetition_invariant(
            listed in 1usize..=16,
            raw in proptest::collection::vec((0usize..20, any::<u8>()), 0..40),
            rotation in 0usize..40,
        ) {
            let approvers: Vec<_> = (0..listed).map(principal).collect();
            let outcomes: Vec<_> = raw
                .iter()
                .map(|(who, code)| ApprovalOutcome::new(principal(*who), verdict_of(*code)))
                .collect();
            let counts = approval_counts(&approvers, &outcomes);
            prop_assert_eq!(counts, reference(&approvers, &outcomes));
            prop_assert!(counts.counted + counts.pending <= approvers.len());

            let mut rotated = outcomes.clone();
            if !rotated.is_empty() {
                let shift = rotation % rotated.len();
                rotated.rotate_left(shift);
            }
            prop_assert_eq!(approval_counts(&approvers, &rotated), counts);

            let mut repeated = outcomes.clone();
            repeated.extend(outcomes.iter().cloned());
            prop_assert_eq!(approval_counts(&approvers, &repeated), counts);

            let mut with_strays = outcomes.clone();
            with_strays.push(ApprovalOutcome::new(principal(99), ApprovalVerdict::Counted));
            prop_assert_eq!(approval_counts(&approvers, &with_strays), counts);
        }
    }

    #[test]
    fn a_counted_approval_dominates_a_pending_one_for_the_same_approver() {
        let approvers = vec![principal(1)];
        let outcomes = vec![
            ApprovalOutcome::new(principal(1), ApprovalVerdict::Pending),
            ApprovalOutcome::new(principal(1), ApprovalVerdict::Counted),
        ];
        assert_eq!(
            approval_counts(&approvers, &outcomes),
            ApprovalCounts {
                counted: 1,
                pending: 0
            }
        );
    }

    #[test]
    fn requirement_constructor_rejects_invalid_shapes() {
        assert!(ApprovalRequirement::new(Vec::new(), 1).is_err());
        assert!(ApprovalRequirement::new(vec![principal(1)], 0).is_err());
        assert!(ApprovalRequirement::new(vec![principal(1), principal(2)], 3).is_err());
        assert!(ApprovalRequirement::new(vec![principal(1), principal(1)], 1).is_err());
        assert!(ApprovalRequirement::new((0..17).map(principal).collect(), 1).is_err());
        let sorted = ApprovalRequirement::new(vec![principal(2), principal(1)], 2).unwrap();
        assert_eq!(sorted.approvers(), &[principal(1), principal(2)]);
    }

    #[test]
    fn covering_is_subset_and_higher_threshold() {
        let parent = ApprovalRequirement::new((1..=3).map(principal).collect(), 2).unwrap();
        let narrower = ApprovalRequirement::new(vec![principal(1), principal(2)], 2).unwrap();
        let higher = ApprovalRequirement::new((1..=3).map(principal).collect(), 3).unwrap();
        let lower = ApprovalRequirement::new((1..=3).map(principal).collect(), 1).unwrap();
        let wider = ApprovalRequirement::new((1..=4).map(principal).collect(), 2).unwrap();
        assert!(approval_requirement_covers(&parent, &parent));
        assert!(approval_requirement_covers(&narrower, &parent));
        assert!(approval_requirement_covers(&higher, &parent));
        assert!(!approval_requirement_covers(&lower, &parent));
        assert!(!approval_requirement_covers(&wider, &parent));
        let parents = ApprovalRequirements::new(vec![parent.clone()]).unwrap();
        let kept = ApprovalRequirements::new(vec![narrower, wider.clone()]).unwrap();
        let dropped = ApprovalRequirements::new(vec![wider]).unwrap();
        assert!(approval_requirements_attenuate(&kept, &parents));
        assert!(!approval_requirements_attenuate(&dropped, &parents));
    }
}
