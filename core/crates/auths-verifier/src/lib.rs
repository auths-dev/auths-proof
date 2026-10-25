//! Pure staged target V1 authority verifier.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod approval;
mod authority;
use authority::verify_authority_measured;
#[cfg(test)]
mod authority_reference;
#[cfg(test)]
mod authority_parity_tests;
mod action_binding;
mod branch;
use branch::{control_for, verify_branch};
#[cfg(test)]
use branch::branch_chain;
#[cfg(test)]
use auths_model::ApprovalSatisfaction;
use action_binding::validate_action_binding;
pub mod closed;
mod collections;
pub mod causal;
mod observation;
mod ordered_set;
mod policy;
use policy::{evaluate_branch_assurance, evaluate_extensions};
#[cfg(test)]
mod policy_parity_tests;
mod resolution;
mod signature_control;
mod sealed;
pub use sealed::{SealedVerificationResult, VerifiedAction, VerifiedAuthority};
pub(crate) use sealed::bind_verified_action;
mod work_meter;
use work_meter::WorkMeter;
pub(crate) use resolution::resolve_proof;
pub(crate) use signature_control::verify_principal_control;
use signature_control::evaluate_signature;
use ordered_set::OrderedSet;
pub mod trace;

use alloc::{boxed::Box, vec::Vec};
use auths_assurance::{evaluate_with_implications, grant_issuer_role};
use auths_authority::EffectiveAuthority;
use auths_codec::{
    CodecError, action_id, action_signing_preimage, attachment_digest, body_digest, context_digest,
    decode_bundle, decode_canonical_action, decode_verifier_context, encode_canonical_action,
    encode_verification_result, grant_id, grant_signing_preimage,
    grant_status_id, grant_status_signing_preimage, plan_id, principal_status_id,
    principal_status_signing_preimage, proof_digest,
};
use auths_composition::{
    BranchOutcome, EvaluationEvent, evaluate_observed as evaluate_plan_observed,
};
use auths_model::{
    ActionId, AssuranceSatisfaction, CanonicalAction, ContextDigest,
    DenialReason, Digest, EvidenceObject, GrantId, GrantStatusId, ObservationSatisfaction,
    ParticipantAssurance, ParticipantRole, PlanId, PortableVerificationResult, PrincipalId,
    PrincipalStatusId, ProfileBudgetExpression, ProofBundle, ProofRef, Requirement,
    SignatureEnvelope, SignedAction, SignedGrant, SignedGrantStatus, SignedPrincipalStatus,
    StatementRef, StatusPolicy, Timestamp, TrustAnchor, TrustedContext, VerificationCode,
    VerificationDecision, VerificationResources, VerificationStage, VerifierConfigurationId,
    status_issuer_in_scope,
};
use auths_ports::{
    AssuranceClaimRule as _, BudgetAlgebra as _,
    CriticalExtensionHandler as _, PrincipalMethod as _, ProfilePolicy as _,
    SignatureSuite as _, StatusMethod as _,
    ControlEvidence, ControlPurpose, PrincipalControlError, PrincipalControlInput, ProfileDecision,
    RegistryOperationError, SignatureError, SignatureInput, StatusDecision,
    diagnostics::DiagnosticMode,
};
use auths_registries::RegistryAccess;
#[cfg(test)]
use auths_registries::ImmutableRegistries;
use trace::{
    FactKind, FactOrigin, FactResult, FactValue, TraceCollector, TraceError, VerificationTrace,
};

/// One stable verifier failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationFailure {
    /// Available facts establish invalidity or insufficient authority.
    Denied(DenialReason),
    /// A trustworthy required fact or capability was unavailable.
    Indeterminate(Requirement),
}

/// Complete pure verifier result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    /// Every proof, authority, status, assurance, and action check passed.
    Authorized(Box<VerifiedAction>),
    /// Available facts establish invalidity or insufficient authority.
    Denied(DenialReason),
    /// A trustworthy required fact or capability was unavailable.
    Indeterminate(Requirement),
}

/// Ordinary sealed outcome plus the bounded trace from the same execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainedVerification {
    outcome: VerificationOutcome,
    trace: VerificationTrace,
}

impl ExplainedVerification {
    /// Exact ordinary verifier outcome.
    #[must_use]
    pub const fn outcome(&self) -> &VerificationOutcome {
        &self.outcome
    }

    /// Bounded deterministic execution trace.
    #[must_use]
    pub const fn trace(&self) -> &VerificationTrace {
        &self.trace
    }

    /// Consumes the diagnostic wrapper without changing the sealed outcome.
    #[must_use]
    pub fn into_outcome(self) -> VerificationOutcome {
        self.outcome
    }
}

impl From<VerificationFailure> for VerificationOutcome {
    fn from(failure: VerificationFailure) -> Self {
        match failure {
            VerificationFailure::Denied(reason) => Self::Denied(reason),
            VerificationFailure::Indeterminate(requirement) => Self::Indeterminate(requirement),
        }
    }
}

/// Successfully bounded and canonically decoded proof bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedProof {
    bundle: ProofBundle,
    proof_digest: Digest,
}

impl DecodedProof {
    /// Returns the validated proof bundle.
    #[must_use]
    pub const fn bundle(&self) -> &ProofBundle {
        &self.bundle
    }

    /// Returns SHA-256 over the exact canonical proof bytes.
    #[must_use]
    pub const fn proof_digest(&self) -> Digest {
        self.proof_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct GrantRecord {
    id: GrantId,
    index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ActionRecord {
    id: ActionId,
    index: usize,
}


struct AuthorityDiagnostics {
    collect: bool,
    plan_events: Vec<EvaluationEvent>,
    authorized_branches: usize,
    distinct_actors: usize,
    distinct_roots: usize,
    /// Counted approvers, threshold, and verdict of each context approval
    /// requirement evaluated, in evaluation order.
    context_approvals: Vec<(usize, u16, FactResult)>,
}

impl AuthorityDiagnostics {
    const fn discard() -> Self {
        Self {
            collect: false,
            plan_events: Vec::new(),
            authorized_branches: 0,
            distinct_actors: 0,
            distinct_roots: 0,
            context_approvals: Vec::new(),
        }
    }

    fn collect() -> Self {
        Self {
            collect: true,
            plan_events: Vec::new(),
            authorized_branches: 0,
            distinct_actors: 0,
            distinct_roots: 0,
            context_approvals: Vec::new(),
        }
    }

    fn record_context_approval(&mut self, evaluated: &approval::Evaluated) {
        if self.collect {
            let result = match evaluated.verdict {
                approval::Verdict::Authorized(_) => FactResult::Satisfied,
                approval::Verdict::Denied => FactResult::Contradicted,
                approval::Verdict::Indeterminate => FactResult::Unavailable,
            };
            self.context_approvals
                .push((evaluated.counts.counted, evaluated.threshold, result));
        }
    }

    fn record_plan_event(&mut self, event: EvaluationEvent) {
        if self.collect {
            self.plan_events.push(event);
        }
    }

    fn record_composition_counts(
        &mut self,
        authorized_branches: usize,
        distinct_actors: usize,
        distinct_roots: usize,
    ) {
        if self.collect {
            self.authorized_branches = authorized_branches;
            self.distinct_actors = distinct_actors;
            self.distinct_roots = distinct_roots;
        }
    }
}


/// Proof whose complete digest graph has been resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProof {
    decoded: DecodedProof,
    plan_id: PlanId,
    grants: Vec<GrantRecord>,
    actions: Vec<ActionRecord>,
}

impl ResolvedProof {
    /// Returns the decoded source stage.
    #[must_use]
    pub const fn decoded(&self) -> &DecodedProof {
        &self.decoded
    }

    /// Returns the recomputed authorization-plan identifier.
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedControl {
    statement: StatementRef,
    principal: PrincipalId,
    result: Result<ControlEvidence, VerificationFailure>,
}

/// Resolved proof with a recorded principal-control result for each statement.
///
/// Non-resource failures remain facts for branch evaluation: an invalid
/// alternative branch does not by itself deny a sufficient authorization plan.
/// Resource exhaustion aborts the stage. This value is not an action capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlVerifiedProof {
    resolved: ResolvedProof,
    controls: Vec<VerifiedControl>,
    work_units: u64,
}

impl ControlVerifiedProof {
    /// Returns the resolved source stage.
    #[must_use]
    pub const fn resolved(&self) -> &ResolvedProof {
        &self.resolved
    }

    /// Returns deterministic adapter and cryptographic work charged.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }
}

/// Runs the complete pure target V1 verifier.
#[must_use]
pub fn verify<R: RegistryAccess + ?Sized>(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
) -> VerificationOutcome {
    verify_internal(
        proof_bytes,
        canonical_action,
        context,
        registries,
        &mut TraceCollector::discard(),
    )
}

/// Runs the exact ordinary verifier path while retaining bounded diagnostic
/// facts.
///
/// # Errors
///
/// Returns [`TraceError::CapacityExceeded`] before verification when bounded
/// diagnostic memory cannot be reserved. The ordinary [`verify`] API remains
/// available and unaffected.
pub fn verify_explained<R: RegistryAccess + ?Sized>(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
) -> Result<ExplainedVerification, TraceError> {
    let mut trace = TraceCollector::collect(trace::HARD_MAX_TRACE_EVENTS)?;
    let outcome = verify_internal(
        proof_bytes,
        canonical_action,
        context,
        registries,
        &mut trace,
    );
    Ok(ExplainedVerification {
        outcome,
        trace: trace.finish(),
    })
}

fn failure_code(failure: VerificationFailure) -> VerificationCode {
    match failure {
        VerificationFailure::Denied(reason) => VerificationCode::Denied(reason),
        VerificationFailure::Indeterminate(requirement) => {
            VerificationCode::Indeterminate(requirement)
        }
    }
}

fn failure_fact_kind(failure: VerificationFailure) -> FactKind {
    match failure {
        VerificationFailure::Denied(reason) => match reason {
            DenialReason::ResourceLimitExceeded => FactKind::WorkReservation,
            DenialReason::InvalidSignature
            | DenialReason::PrincipalMethodMismatch
            | DenialReason::VerificationMethodMismatch
            | DenialReason::SignatureSuiteMismatch => FactKind::PrincipalControl,
            DenialReason::UntrustedRoot => FactKind::TrustAnchorAcceptedMethod,
            DenialReason::BrokenGrantChain => FactKind::GrantLinkage,
            DenialReason::DelegationExpanded | DenialReason::ObservationRequirementDropped => {
                FactKind::GrantPermissionAttenuation
            }
            DenialReason::PermissionNotGranted => FactKind::ActionPermission,
            DenialReason::ActionConstraintMismatch | DenialReason::ActionBodyMismatch => {
                FactKind::ActionBodyDigest
            }
            DenialReason::BudgetCeilingExceeded => FactKind::ActionBudget,
            DenialReason::AuthorizationPlanInvalid | DenialReason::PlanActionMismatch => {
                FactKind::PlanNode
            }
            DenialReason::CompositionRequirementNotMet => FactKind::MinimumAuthorizedBranches,
            DenialReason::AudienceMismatch => FactKind::ActionAudience,
            DenialReason::ChallengeMismatch => FactKind::ActionChallenge,
            DenialReason::ActionOutsideValidity => FactKind::ActionValidity,
            DenialReason::PrincipalRevoked
            | DenialReason::StatusSequenceRollback
            | DenialReason::StatusMethodMismatch
            | DenialReason::StatusIssuerUntrusted => FactKind::PrincipalStatus,
            DenialReason::GrantRevoked => FactKind::GrantStatus,
            DenialReason::RegistryManifestMismatch => FactKind::RegistryManifestAccepted,
            DenialReason::VerifierConfigurationMismatch => FactKind::ContextConfigurationMatches,
            DenialReason::ResourceNamespaceMismatch => FactKind::ResourceNamespace,
            DenialReason::CriticalExtensionUnknown => FactKind::CriticalExtension,
            DenialReason::AttachmentMissing
            | DenialReason::AttachmentDigestMismatch
            | DenialReason::AttachmentLengthMismatch
            | DenialReason::DuplicateAttachment
            | DenialReason::UnusedCriticalAttachment
            | DenialReason::OpaqueAttachmentNotAllowed => FactKind::Attachment,
            DenialReason::LocalPolicyDenied => FactKind::ProfilePolicy,
            DenialReason::ObservationConditionFalse | DenialReason::ObserverInAuthorityChain => {
                FactKind::CriticalExtension
            }
            DenialReason::ApprovalThresholdNotMet => FactKind::ApprovalRequirement,
            DenialReason::MalformedProof
            | DenialReason::NonCanonicalProof
            | DenialReason::DigestMismatch
            | DenialReason::DuplicateObject
            | DenialReason::MissingReference
            | DenialReason::ReferenceCycle
            | DenialReason::AmbiguousTerminalGrant
            | DenialReason::UnusedCriticalEvidence => FactKind::PlanNode,
        },
        VerificationFailure::Indeterminate(requirement) => match requirement {
            Requirement::UnsupportedPrincipalMethod
            | Requirement::UnsupportedSignatureSuite
            | Requirement::UnsupportedEvidenceType
            | Requirement::MissingPrincipalEvidence
            | Requirement::HistoricalStateUnavailable => FactKind::PrincipalControl,
            Requirement::UnsupportedStatusMethod
            | Requirement::MissingPrincipalStatus
            | Requirement::StaleStatus => FactKind::PrincipalStatus,
            Requirement::MissingGrantStatus => FactKind::GrantStatus,
            Requirement::UnsupportedProfile => FactKind::TrustAnchorProfile,
            Requirement::UnsupportedProfilePolicy => FactKind::ProfilePolicy,
            Requirement::UnsupportedResourceMatcher => FactKind::ResourceNamespace,
            Requirement::UnsupportedBudgetAlgebra => FactKind::ActionBudget,
            Requirement::UnsupportedCriticalExtension
            | Requirement::ObservationMissing
            | Requirement::ObservationActionFactUnavailable => FactKind::CriticalExtension,
            Requirement::UnsupportedAssuranceClaim | Requirement::AssuranceRequirementNotMet => {
                FactKind::AssuranceRequirement
            }
            Requirement::UnsupportedProtocol | Requirement::ExternalFactUnavailable => {
                FactKind::PlanNode
            }
            Requirement::ApprovalUnavailable => FactKind::ApprovalRequirement,
        },
    }
}

fn record_configuration_facts<R: RegistryAccess + ?Sized>(
    context: &TrustedContext,
    registries: &R,
    trace: &mut TraceCollector,
) -> (Option<u32>, Option<u32>) {
    let configuration_matches = context.configuration() == registries.configuration_id();
    let configuration = trace.record(
        VerificationStage::Resolve,
        FactKind::ContextConfigurationMatches,
        FactOrigin::TrustedContext,
        FactValue::Equal(configuration_matches),
        if configuration_matches {
            FactResult::Satisfied
        } else {
            FactResult::Contradicted
        },
        (!configuration_matches).then_some(VerificationCode::Denied(
            DenialReason::VerifierConfigurationMismatch,
        )),
    );
    let registry_matches = context.accepted_registries().manifest_id() == registries.manifest_id();
    let registry = trace.record(
        VerificationStage::Resolve,
        FactKind::RegistryManifestAccepted,
        FactOrigin::ExecutableRegistry,
        FactValue::Equal(registry_matches),
        if registry_matches {
            FactResult::Satisfied
        } else {
            FactResult::Contradicted
        },
        (!registry_matches).then_some(VerificationCode::Denied(
            DenialReason::RegistryManifestMismatch,
        )),
    );
    (configuration, registry)
}

fn record_failure(
    trace: &mut TraceCollector,
    stage: VerificationStage,
    origin: FactOrigin,
    value: FactValue,
    failure: VerificationFailure,
    parents: &[u32],
) -> Option<u32> {
    trace.record_with_parents(
        stage,
        failure_fact_kind(failure),
        origin,
        value,
        match failure {
            VerificationFailure::Denied(_) => FactResult::Contradicted,
            VerificationFailure::Indeterminate(_) => FactResult::Unavailable,
        },
        Some(failure_code(failure)),
        parents,
    )
}

#[allow(clippy::too_many_lines)]
fn verify_internal<R: RegistryAccess + ?Sized>(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
    trace: &mut TraceCollector,
) -> VerificationOutcome {
    let (configuration_node, registry_node) =
        record_configuration_facts(context, registries, trace);

    let (decoded, decode_node) = match decode_proof(proof_bytes, context) {
        Ok(decoded) => {
            let node = trace.record(
                VerificationStage::Decode,
                FactKind::Attachment,
                FactOrigin::Proof,
                FactValue::Present(true),
                FactResult::Satisfied,
                None,
            );
            trace.set_final_node(node);
            (decoded, node)
        }
        Err(failure) => {
            let node = record_failure(
                trace,
                VerificationStage::Decode,
                FactOrigin::Proof,
                FactValue::Present(false),
                failure,
                &[],
            );
            trace.set_final_node(node);
            return failure.into();
        }
    };
    let (resolved, resolve_node) = match resolve_proof(decoded, context) {
        Ok(resolved) => {
            let parents: Vec<_> = decode_node.into_iter().collect();
            let node = trace.record_with_parents(
                VerificationStage::Resolve,
                FactKind::ExpectedPlanMatches,
                FactOrigin::Derived,
                FactValue::Equal(true),
                FactResult::Satisfied,
                None,
                &parents,
            );
            trace.set_final_node(node);
            (resolved, node)
        }
        Err(failure) => {
            let parents: Vec<_> = decode_node.into_iter().collect();
            let node = record_failure(
                trace,
                VerificationStage::Resolve,
                FactOrigin::TrustedContext,
                FactValue::Equal(false),
                failure,
                &parents,
            );
            trace.set_final_node(node);
            return failure.into();
        }
    };
    let (controlled, principal_node) = match verify_principal_control(resolved, context, registries)
    {
        Ok(controlled) => {
            let parents: Vec<_> = [resolve_node, configuration_node, registry_node]
                .into_iter()
                .flatten()
                .collect();
            let node = trace.record_with_parents(
                VerificationStage::PrincipalControl,
                FactKind::PrincipalControl,
                FactOrigin::ExecutableRegistry,
                FactValue::Present(true),
                FactResult::Satisfied,
                None,
                &parents,
            );
            trace.set_final_node(node);
            (controlled, node)
        }
        Err(failure) => {
            let parents: Vec<_> = [resolve_node, configuration_node, registry_node]
                .into_iter()
                .flatten()
                .collect();
            let node = record_failure(
                trace,
                VerificationStage::PrincipalControl,
                FactOrigin::ExecutableRegistry,
                FactValue::Present(false),
                failure,
                &parents,
            );
            trace.set_final_node(node);
            return failure.into();
        }
    };
    let mut meter = WorkMeter::from_used(context.limits().max_work_units(), controlled.work_units);
    let mut diagnostics = AuthorityDiagnostics::collect();
    let authority = match verify_authority_measured(
        controlled,
        canonical_action,
        context,
        registries,
        &mut meter,
        &mut diagnostics,
    ) {
        Ok(authority) => authority,
        Err(failure) => {
            let plan_root = record_plan_events(trace, &diagnostics.plan_events, principal_node);
            // Once the plan authorizes, only the composition floors and the
            // context's approval requirements can refuse.
            let node = if plan_root.is_some()
                && matches!(
                    diagnostics.plan_events.last().map(|event| event.outcome()),
                    Some(BranchOutcome::Authorized)
                )
                && failure != VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
            {
                record_composition_decision(
                    trace,
                    context.composition(),
                    &diagnostics,
                    plan_root,
                    failure_code(failure),
                )
            } else if plan_root.is_some() {
                plan_root
            } else {
                let parents: Vec<_> = principal_node.into_iter().collect();
                record_failure(
                    trace,
                    VerificationStage::Authority,
                    FactOrigin::Derived,
                    FactValue::Present(false),
                    failure,
                    &parents,
                )
            };
            trace.set_final_node(node);
            return failure.into();
        }
    };
    let action = bind_verified_action(authority);
    let plan_root = record_plan_events(trace, &diagnostics.plan_events, principal_node);
    let final_node = record_composition_decision(
        trace,
        context.composition(),
        &diagnostics,
        plan_root,
        VerificationCode::Authorized,
    );
    trace.set_final_node(final_node);
    VerificationOutcome::Authorized(Box::new(action))
}

fn branch_fact_result(outcome: BranchOutcome) -> FactResult {
    match outcome {
        BranchOutcome::Authorized => FactResult::Satisfied,
        BranchOutcome::Denied(_) | BranchOutcome::StructurallyInvalid(_) => {
            FactResult::Contradicted
        }
        BranchOutcome::Indeterminate(_) => FactResult::Unavailable,
    }
}

fn branch_verification_code(outcome: BranchOutcome) -> VerificationCode {
    match outcome {
        BranchOutcome::Authorized => VerificationCode::Authorized,
        BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
            VerificationCode::Denied(reason)
        }
        BranchOutcome::Indeterminate(requirement) => VerificationCode::Indeterminate(requirement),
    }
}

fn record_plan_events(
    trace: &mut TraceCollector,
    events: &[EvaluationEvent],
    principal_node: Option<u32>,
) -> Option<u32> {
    let mut stack: Vec<Option<u32>> = Vec::new();
    for event in events {
        match *event {
            EvaluationEvent::Proof { outcome, .. } => {
                let parents: Vec<_> = principal_node.into_iter().collect();
                let node = trace.record_with_parents(
                    VerificationStage::Authority,
                    FactKind::PlanNode,
                    FactOrigin::Proof,
                    FactValue::Present(true),
                    branch_fact_result(outcome),
                    Some(branch_verification_code(outcome)),
                    &parents,
                );
                stack.push(node);
            }
            EvaluationEvent::Aggregate {
                child_count,
                required,
                authorized,
                outcome,
                ..
            } => {
                if child_count > stack.len() {
                    return None;
                }
                let children = stack.split_off(stack.len() - child_count);
                let parents: Vec<_> = children.into_iter().flatten().collect();
                let node = trace.record_with_parents(
                    VerificationStage::Authority,
                    FactKind::PlanNode,
                    FactOrigin::Derived,
                    FactValue::Count {
                        actual: u64::try_from(authorized).unwrap_or(u64::MAX),
                        required: u64::from(required),
                    },
                    branch_fact_result(outcome),
                    Some(branch_verification_code(outcome)),
                    &parents,
                );
                stack.push(node);
            }
        }
    }
    if stack.len() == 1 {
        stack.pop().flatten()
    } else {
        None
    }
}

fn record_composition_decision(
    trace: &mut TraceCollector,
    requirement: auths_model::CompositionRequirement,
    diagnostics: &AuthorityDiagnostics,
    plan_root: Option<u32>,
    code: VerificationCode,
) -> Option<u32> {
    let constraints = [
        (
            FactKind::MinimumAuthorizedBranches,
            diagnostics.authorized_branches,
            requirement.minimum_authorized_branches(),
        ),
        (
            FactKind::MinimumDistinctActors,
            diagnostics.distinct_actors,
            requirement.minimum_distinct_actors(),
        ),
        (
            FactKind::MinimumDistinctRoots,
            diagnostics.distinct_roots,
            requirement.minimum_distinct_roots(),
        ),
    ];
    let plan_parents: Vec<_> = plan_root.into_iter().collect();
    let mut parents = plan_parents.clone();
    for (kind, actual, required) in constraints {
        let satisfied = actual >= usize::from(required);
        if let Some(node) = trace.record_with_parents(
            VerificationStage::Authority,
            kind,
            FactOrigin::TrustedContext,
            FactValue::Count {
                actual: u64::try_from(actual).unwrap_or(u64::MAX),
                required: u64::from(required),
            },
            if satisfied {
                FactResult::Satisfied
            } else {
                FactResult::Contradicted
            },
            (!satisfied).then_some(VerificationCode::Denied(
                DenialReason::CompositionRequirementNotMet,
            )),
            &plan_parents,
        ) {
            parents.push(node);
        }
    }
    for &(counted, threshold, result) in &diagnostics.context_approvals {
        if let Some(node) = trace.record_with_parents(
            VerificationStage::Authority,
            FactKind::ApprovalRequirement,
            FactOrigin::TrustedContext,
            FactValue::Count {
                actual: u64::try_from(counted).unwrap_or(u64::MAX),
                required: u64::from(threshold),
            },
            result,
            match result {
                FactResult::Satisfied | FactResult::NotEvaluated => None,
                FactResult::Contradicted => Some(VerificationCode::Denied(
                    DenialReason::ApprovalThresholdNotMet,
                )),
                FactResult::Unavailable => Some(VerificationCode::Indeterminate(
                    Requirement::ApprovalUnavailable,
                )),
            },
            &plan_parents,
        ) {
            parents.push(node);
        }
    }
    trace.record_with_parents(
        VerificationStage::Complete,
        FactKind::Decision,
        FactOrigin::Derived,
        FactValue::Present(code == VerificationCode::Authorized),
        match code {
            VerificationCode::Authorized => FactResult::Satisfied,
            VerificationCode::Denied(_) => FactResult::Contradicted,
            VerificationCode::Indeterminate(_) => FactResult::Unavailable,
        },
        Some(code),
        &parents,
    )
}

/// Executes the complete byte-oriented portable V1 ABI.
///
/// Canonical action and trusted-context decode failures are represented as
/// canonical decode-stage results. The only returned error is an internal
/// failure to encode the result object itself.
///
/// # Errors
///
/// Returns [`CodecError`] only if the constructed portable result cannot be
/// canonically encoded.
pub fn verify_v1<R: RegistryAccess + ?Sized>(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    registries: &R,
) -> Result<Vec<u8>, CodecError> {
    verify_v1_sealed(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
        registries,
    )
    .map(|result| result.cbor)
}

/// Executes the byte-oriented V1 ABI without discarding native authority.
///
/// # Errors
///
/// Returns [`CodecError`] only if the constructed portable result cannot be
/// canonically encoded.
pub fn verify_v1_sealed<R: RegistryAccess + ?Sized>(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    registries: &R,
) -> Result<SealedVerificationResult, CodecError> {
    let proof_input_digest = body_digest(proof_cbor);
    let action_input_digest = body_digest(canonical_action_cbor);
    let input_resources = VerificationResources::new(
        u64::try_from(proof_cbor.len()).unwrap_or(u64::MAX),
        u64::try_from(canonical_action_cbor.len()).unwrap_or(u64::MAX),
        u64::try_from(trusted_context_cbor.len()).unwrap_or(u64::MAX),
        0,
        0,
        0,
        0,
    );
    let context = match decode_verifier_context(trusted_context_cbor) {
        Ok(context) => context,
        Err(error) => {
            let result = portable_failure(
                codec_failure(error),
                VerificationStage::Decode,
                proof_input_digest,
                action_input_digest,
                ContextDigest::new([0; 32]),
                None,
                input_resources,
                registries.manifest_id(),
                None,
                registries.configuration_id(),
            );
            return seal_portable(result, None);
        }
    };
    let canonical_action = match decode_canonical_action(canonical_action_cbor, context.limits()) {
        Ok(action) => action,
        Err(error) => {
            let result = portable_failure(
                codec_failure(error),
                VerificationStage::Decode,
                proof_input_digest,
                action_input_digest,
                infallible_encoding(context_digest(&context)),
                None,
                input_resources,
                context.accepted_registries().manifest_id(),
                Some(context.configuration()),
                registries.configuration_id(),
            );
            return seal_portable(result, None);
        }
    };
    let (portable, action) =
        verify_portable_sealed(proof_cbor, &canonical_action, &context, registries);
    seal_portable(portable, action)
}

/// Runs the complete `verify_v1` contract and returns a canonically encodable
/// language-neutral result for every verdict.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn verify_portable<R: RegistryAccess + ?Sized>(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
) -> PortableVerificationResult {
    verify_portable_sealed(proof_bytes, canonical_action, context, registries).0
}

#[allow(clippy::too_many_lines)]
fn verify_portable_sealed<R: RegistryAccess + ?Sized>(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
) -> (PortableVerificationResult, Option<Box<VerifiedAction>>) {
    let action_bytes = infallible_encoding(encode_canonical_action(canonical_action));
    let (public_context_digest, context_byte_count) =
        infallible_encoding(auths_codec::context_digest_and_size(context));
    let proof_input_digest = body_digest(proof_bytes);
    let action_digest = body_digest(&action_bytes);
    let local_configuration = registries.configuration_id();
    let mut resources = VerificationResources::new(
        u64::try_from(proof_bytes.len()).unwrap_or(u64::MAX),
        u64::try_from(action_bytes.len()).unwrap_or(u64::MAX),
        u64::try_from(context_byte_count).unwrap_or(u64::MAX),
        0,
        0,
        0,
        0,
    );

    let decoded = match decode_proof(proof_bytes, context) {
        Ok(decoded) => decoded,
        Err(failure) => {
            return (
                portable_failure(
                    failure,
                    VerificationStage::Decode,
                    proof_input_digest,
                    action_digest,
                    public_context_digest,
                    None,
                    resources,
                    context.accepted_registries().manifest_id(),
                    Some(context.configuration()),
                    local_configuration,
                ),
                None,
            );
        }
    };
    let bundle = decoded.bundle();
    let object_count = bundle
        .grants()
        .len()
        .saturating_add(bundle.actions().len())
        .saturating_add(bundle.evidence().len())
        .saturating_add(bundle.bindings().len())
        .saturating_add(bundle.principal_status().len())
        .saturating_add(bundle.grant_status().len())
        .saturating_add(bundle.attachments().len())
        .saturating_add(bundle.approvals().len());
    let shape = bundle.plan().validate(context.limits()).ok();
    resources = VerificationResources::new(
        resources.proof_bytes(),
        resources.action_bytes(),
        resources.context_bytes(),
        u64::try_from(object_count).unwrap_or(u64::MAX),
        shape.as_ref().map_or(0, |shape| {
            u64::try_from(shape.leaves().len()).unwrap_or(u64::MAX)
        }),
        shape.as_ref().map_or(0, |shape| {
            u64::try_from(shape.maximum_depth()).unwrap_or(u64::MAX)
        }),
        0,
    );
    let resolved = match resolve_proof(decoded, context) {
        Ok(resolved) => resolved,
        Err(failure) => {
            return (
                portable_failure(
                    failure,
                    VerificationStage::Resolve,
                    proof_input_digest,
                    action_digest,
                    public_context_digest,
                    None,
                    resources,
                    context.accepted_registries().manifest_id(),
                    Some(context.configuration()),
                    local_configuration,
                ),
                None,
            );
        }
    };
    let resolved_plan = Some(resolved.plan_id());
    let controlled = match verify_principal_control(resolved, context, registries) {
        Ok(controlled) => controlled,
        Err(failure) => {
            return (
                portable_failure(
                    failure,
                    VerificationStage::PrincipalControl,
                    proof_input_digest,
                    action_digest,
                    public_context_digest,
                    resolved_plan,
                    resources,
                    context.accepted_registries().manifest_id(),
                    Some(context.configuration()),
                    local_configuration,
                ),
                None,
            );
        }
    };
    resources = VerificationResources::new(
        resources.proof_bytes(),
        resources.action_bytes(),
        resources.context_bytes(),
        resources.object_count(),
        resources.plan_leaves(),
        resources.plan_depth(),
        controlled.work_units(),
    );
    let mut authority_meter =
        WorkMeter::from_used(context.limits().max_work_units(), controlled.work_units());
    let mut diagnostics = AuthorityDiagnostics::discard();
    match verify_authority_measured(
        controlled,
        canonical_action,
        context,
        registries,
        &mut authority_meter,
        &mut diagnostics,
    ) {
        Ok(authority) => {
            let resources = VerificationResources::new(
                resources.proof_bytes(),
                resources.action_bytes(),
                resources.context_bytes(),
                resources.object_count(),
                resources.plan_leaves(),
                resources.plan_depth(),
                authority.work_units,
            );
            let portable = finalize_portable(
                PortableVerificationResult::new(
                    VerificationDecision::Authorized,
                    VerificationStage::Complete,
                    VerificationCode::Authorized,
                    proof_input_digest,
                    action_digest,
                    public_context_digest,
                    Some(authority.plan_id),
                    authority.authorized_branches.clone(),
                    authority.assurance.clone(),
                    authority.assurance_satisfactions.clone(),
                    resources,
                    context.accepted_registries().manifest_id(),
                    Some(context.configuration()),
                    local_configuration,
                )
                .with_observation_satisfactions(authority.observation_satisfactions.clone())
                .with_approval_satisfactions(authority.approval_satisfactions.clone()),
            );
            (portable, Some(Box::new(bind_verified_action(authority))))
        }
        Err(failure) => {
            let resources = VerificationResources::new(
                resources.proof_bytes(),
                resources.action_bytes(),
                resources.context_bytes(),
                resources.object_count(),
                resources.plan_leaves(),
                resources.plan_depth(),
                authority_meter.used,
            );
            (
                portable_failure(
                    failure,
                    VerificationStage::Authority,
                    proof_input_digest,
                    action_digest,
                    public_context_digest,
                    resolved_plan,
                    resources,
                    context.accepted_registries().manifest_id(),
                    Some(context.configuration()),
                    local_configuration,
                ),
                None,
            )
        }
    }
}

/// Unwraps the canonical encoding, or digest, of an already constructed model
/// value.
fn infallible_encoding<T>(encoded: Result<T, CodecError>) -> T {
    // INVARIANT: the V1 encoders write valid major tags into a `Vec` and
    // frame only lengths that fit in `u64`, so no
    // constructed model value makes them return `Err`.
    encoded.expect("canonical V1 encoding of a constructed model value cannot fail")
}

fn seal_portable(
    portable: PortableVerificationResult,
    action: Option<Box<VerifiedAction>>,
) -> Result<SealedVerificationResult, CodecError> {
    let canonical = auths_codec::CanonicalVerificationResult::new(portable)?;
    let cbor = encode_verification_result(&canonical)?;
    Ok(SealedVerificationResult {
        portable: canonical.into_value(),
        cbor,
        action,
    })
}

#[allow(clippy::too_many_arguments)]
fn portable_failure(
    failure: VerificationFailure,
    stage: VerificationStage,
    proof_digest: Digest,
    action_digest: Digest,
    context_digest: ContextDigest,
    plan_id: Option<PlanId>,
    resources: VerificationResources,
    manifest: auths_model::RegistryManifestId,
    required_configuration: Option<VerifierConfigurationId>,
    local_configuration: VerifierConfigurationId,
) -> PortableVerificationResult {
    let (decision, code) = match failure {
        VerificationFailure::Denied(reason) => (
            VerificationDecision::Denied,
            VerificationCode::Denied(reason),
        ),
        VerificationFailure::Indeterminate(requirement) => (
            VerificationDecision::Indeterminate,
            VerificationCode::Indeterminate(requirement),
        ),
    };
    finalize_portable(PortableVerificationResult::new(
        decision,
        stage,
        code,
        proof_digest,
        action_digest,
        context_digest,
        plan_id,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        resources,
        manifest,
        required_configuration,
        local_configuration,
    ))
}

fn finalize_portable(result: PortableVerificationResult) -> PortableVerificationResult {
    auths_codec::verification_result_digest(&result)
        .map_or(result.clone(), |digest| result.with_result_digest(digest))
}

/// Performs bounded deterministic CBOR decoding.
///
/// # Errors
///
/// Returns a stable failure class for malformed, non-canonical, unsupported,
/// or over-limit bytes.
pub fn decode_proof(
    proof_bytes: &[u8],
    context: &TrustedContext,
) -> Result<DecodedProof, VerificationFailure> {
    let bundle = decode_bundle(proof_bytes, context.limits()).map_err(codec_failure)?;
    let digest = proof_digest(&bundle).map_err(codec_failure)?;
    Ok(DecodedProof {
        bundle: bundle.into_value(),
        proof_digest: digest,
    })
}


fn codec_failure(error: CodecError) -> VerificationFailure {
    match error {
        CodecError::LimitExceeded => {
            VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
        }
        CodecError::Model(auths_model::ModelError::UnsupportedProtocol) => {
            VerificationFailure::Indeterminate(Requirement::UnsupportedProtocol)
        }
        CodecError::Malformed | CodecError::Model(_) => {
            VerificationFailure::Denied(DenialReason::MalformedProof)
        }
        CodecError::NonCanonical => VerificationFailure::Denied(DenialReason::NonCanonicalProof),
        CodecError::DigestMismatch => VerificationFailure::Denied(DenialReason::DigestMismatch),
        CodecError::DuplicateObject => VerificationFailure::Denied(DenialReason::DuplicateObject),
    }
}


fn control_failure(error: PrincipalControlError) -> VerificationFailure {
    match error {
        PrincipalControlError::PrincipalMethodMismatch | PrincipalControlError::InvalidEvidence => {
            VerificationFailure::Denied(DenialReason::PrincipalMethodMismatch)
        }
        PrincipalControlError::VerificationMethodMismatch => {
            VerificationFailure::Denied(DenialReason::VerificationMethodMismatch)
        }
        PrincipalControlError::SignatureSuiteMismatch => {
            VerificationFailure::Denied(DenialReason::SignatureSuiteMismatch)
        }
        PrincipalControlError::MissingEvidence => {
            VerificationFailure::Indeterminate(Requirement::MissingPrincipalEvidence)
        }
        PrincipalControlError::ResourceLimitExceeded => {
            VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
        }
        PrincipalControlError::ExternalFactUnavailable => {
            VerificationFailure::Indeterminate(Requirement::ExternalFactUnavailable)
        }
        PrincipalControlError::HistoricalStateUnavailable => {
            VerificationFailure::Indeterminate(Requirement::HistoricalStateUnavailable)
        }
        PrincipalControlError::PrincipalRevoked => {
            VerificationFailure::Denied(DenialReason::PrincipalRevoked)
        }
    }
}

fn signature_failure(_error: SignatureError) -> VerificationFailure {
    VerificationFailure::Denied(DenialReason::InvalidSignature)
}


/// Authority established for one authorization-plan branch that authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BranchAuthority {
    action_id: ActionId,
    authority_not_after: Timestamp,
    assurance: Vec<ParticipantAssurance>,
    assurance_satisfactions: Vec<AssuranceSatisfaction>,
    observation_satisfactions: Vec<ObservationSatisfaction>,
    approval_requirements: Vec<auths_model::ApprovalRequirementId>,
}




/// Reads only evidence already selected by the assurance evaluator.
fn assurance_horizon(
    satisfactions: &[AssuranceSatisfaction],
    context: &TrustedContext,
) -> Result<Timestamp, VerificationFailure> {
    let mut valid_through = Timestamp::new(u64::MAX);
    for satisfaction in satisfactions {
        let requirement = context
            .assurance_policy()
            .requirements()
            .get(usize::from(satisfaction.requirement_index()))
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::AssuranceRequirementNotMet,
            ))?;
        if let Some(age) = requirement.maximum_age() {
            let observed =
                satisfaction
                    .claim()
                    .observed_at()
                    .ok_or(VerificationFailure::Indeterminate(
                        Requirement::AssuranceRequirementNotMet,
                    ))?;
            valid_through =
                valid_through.min(Timestamp::new(observed.get().saturating_add(age.get())));
        }
    }
    Ok(valid_through)
}




/// Applies the accepted-extension rule to one status statement about a
/// principal or grant being evaluated.
///
/// No registered critical extension defines status semantics, and a grant or
/// action handler never evaluates a status statement, so the first extension
/// decides: one the context does not accept is unknown, and an accepted one
/// has no status handler. A statement is refused whether or not selection
/// would pick it, because every statement about the subject takes part in
/// selection.
fn check_status_extensions(
    extensions: &auths_model::CriticalExtensions,
    context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    match extensions.as_slice().first() {
        None => Ok(()),
        Some(extension)
            if !context
                .accepted_registries()
                .accepts_critical_extension(extension.id()) =>
        {
            Err(VerificationFailure::Denied(
                DenialReason::CriticalExtensionUnknown,
            ))
        }
        Some(_) => Err(VerificationFailure::Indeterminate(
            Requirement::UnsupportedCriticalExtension,
        )),
    }
}

/// What an absent principal-status statement means.
///
/// The trust anchor must be named by the snapshot. For every other principal
/// in the branch the snapshot is a revocation list, so a principal it does not
/// name is active once the snapshot itself is fresh.
#[derive(Clone, Copy)]
enum StatusListing {
    Required,
    RevocationList,
}


/// Refuses a registry's unusable temporal witness before sealing authority.
fn status_horizon(
    evaluation: auths_ports::StatusEvaluation,
    evaluation_time: Timestamp,
) -> Result<Timestamp, VerificationFailure> {
    if evaluation.valid_through() < evaluation_time {
        Err(VerificationFailure::Indeterminate(Requirement::StaleStatus))
    } else {
        Ok(evaluation.valid_through())
    }
}

fn status_decision(decision: StatusDecision, principal: bool) -> Result<(), VerificationFailure> {
    match decision {
        StatusDecision::Active => Ok(()),
        StatusDecision::Revoked => Err(VerificationFailure::Denied(if principal {
            DenialReason::PrincipalRevoked
        } else {
            DenialReason::GrantRevoked
        })),
        StatusDecision::Missing => Err(VerificationFailure::Indeterminate(if principal {
            Requirement::MissingPrincipalStatus
        } else {
            Requirement::MissingGrantStatus
        })),
        StatusDecision::Stale => Err(VerificationFailure::Indeterminate(Requirement::StaleStatus)),
        StatusDecision::Rollback => Err(VerificationFailure::Denied(
            DenialReason::StatusSequenceRollback,
        )),
        StatusDecision::UntrustedIssuer => Err(VerificationFailure::Denied(
            DenialReason::StatusIssuerUntrusted,
        )),
        StatusDecision::WrongMethod => Err(VerificationFailure::Denied(
            DenialReason::StatusMethodMismatch,
        )),
    }
}




fn registry_operation_failure(error: RegistryOperationError) -> VerificationFailure {
    match error {
        RegistryOperationError::ResourceLimitExceeded => {
            VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
        }
        RegistryOperationError::InvalidInput => {
            VerificationFailure::Denied(DenialReason::LocalPolicyDenied)
        }
    }
}

#[cfg(test)]
#[path = "reference_stages.rs"]
mod reference_stages;
#[cfg(test)]
#[path = "stage_parity_tests.rs"]
mod stage_parity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use auths_codec::{encode_bundle, evidence_id};
    use auths_model::{
        AcceptedRegistries, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
        AssuranceQuantifier, AssuranceRequirement, Audience, AudienceSet, AuthorizationPlan,
        BudgetCeiling, BundleHeader, CapabilityId, Challenge, ChannelBindingId,
        CompositionRequirement, ControlBinding, CriticalExtensions, EvidenceId, EvidenceTypeId,
        GrantStatusSnapshot, MediaType, ParticipantRole, Permission, PermissionSet,
        PrincipalMethodId, PrincipalStatusSnapshot, ProfileId, ProfilePolicyId, ProfileRef,
        ResourceId, SignatureBytes, SignatureDescriptor, SignatureSuiteId, SignedAction,
        StatusSnapshotId, Timestamp, TrustAnchorId, ValidityWindow, VerificationMethod,
        VerifierLimits,
    };
    use auths_raw_key::{
        RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType,
    };
    use auths_signature::{ED25519_V1, Ed25519Suite};
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn explained_and_ordinary_paths_are_identical() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();

        let ordinary = verify(
            &fixture.bytes,
            &fixture.canonical,
            &fixture.context,
            &registries,
        );
        let explained = verify_explained(
            &fixture.bytes,
            &fixture.canonical,
            &fixture.context,
            &registries,
        )
        .unwrap();

        assert_eq!(&ordinary, explained.outcome());
        assert!(!explained.trace().events().is_empty());
        assert_eq!(
            explained.trace().final_node() as usize + 1,
            explained.trace().events().len()
        );
    }

    struct Fixture {
        bytes: Vec<u8>,
        canonical: CanonicalAction,
        context: TrustedContext,
        action: SignedAction,
    }

    fn target_fixture(mutate_signature: bool) -> Fixture {
        target_fixture_with_budget(mutate_signature, None, None)
    }

    fn numeric_ceiling(value: u64) -> BudgetCeiling {
        BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(),
            value,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn target_fixture_with_budget(
        mutate_signature: bool,
        anchor_ceiling: Option<BudgetCeiling>,
        requested_budget: Option<BudgetCeiling>,
    ) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let descriptor = RawKeyDescriptor::new(
            RawKeyType::Ed25519,
            signing_key.verifying_key().to_bytes().into(),
        )
        .unwrap();
        let principal = descriptor.principal().unwrap();
        let profile = ProfileRef::new(ProfileId::parse("auths.mcp").unwrap(), 1).unwrap();
        let permission = Permission::new(
            CapabilityId::parse("tools/call").unwrap(),
            ResourceId::parse("mcp://reports/read").unwrap(),
        );
        let body = br#"{"arguments":{"path":"/reports/q3.pdf"},"name":"read"}"#.to_vec();
        let canonical = CanonicalAction::new(
            profile.clone(),
            MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").unwrap(),
            body.clone(),
            permission.clone(),
            requested_budget.clone(),
        )
        .unwrap();
        let proof_ref = ProofRef::new([1; 32]);
        let plan = AuthorizationPlan::proof(proof_ref);
        let computed_plan = plan_id(&plan).unwrap();
        let challenge = Challenge::new([2; 32]);
        let channel = ChannelBindingId::parse("none-v1").unwrap();
        let envelope = auths_model::ActionEnvelope::new(
            profile.clone(),
            canonical.media_type().clone(),
            body_digest(&body),
            permission.clone(),
            requested_budget,
            Audience::parse("mcp://reports").unwrap(),
            challenge,
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(20)).unwrap(),
            principal.clone(),
            None,
            computed_plan,
            channel.clone(),
            proof_ref,
            Vec::new(),
            CriticalExtensions::empty(),
        );
        let signature_descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).unwrap(),
            VerificationMethod::parse(principal.as_str()).unwrap(),
            SignatureSuiteId::parse(ED25519_V1).unwrap(),
        );
        let preimage = action_signing_preimage(&envelope, &signature_descriptor).unwrap();
        let mut signature = signing_key.sign(&preimage).to_bytes().to_vec();
        if mutate_signature {
            signature[0] ^= 1;
        }
        let signed_action = SignedAction::new(
            envelope,
            SignatureEnvelope::new(
                signature_descriptor,
                SignatureBytes::new(signature).unwrap(),
            ),
        );
        let statement = StatementRef::Action(action_id(signed_action.envelope()).unwrap());
        let evidence_type = EvidenceTypeId::parse(RAW_KEY_V1).unwrap();
        let evidence_media = MediaType::parse(RAW_KEY_MEDIA_TYPE).unwrap();
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            evidence_type.clone(),
            evidence_media.clone(),
            descriptor.encode(),
        )
        .unwrap();
        let evidence_identifier = evidence_id(&unaddressed).unwrap();
        let evidence = EvidenceObject::new(
            evidence_identifier,
            evidence_type,
            evidence_media,
            descriptor.encode(),
        )
        .unwrap();
        let bundle = ProofBundle::new(
            BundleHeader::v1(),
            Vec::new(),
            vec![signed_action.clone()],
            plan,
            vec![evidence],
            vec![ControlBinding::new(statement, vec![evidence_identifier]).unwrap()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(body),
        )
        .unwrap();

        let policy_id = AssurancePolicyId::parse("raw-key-baseline").unwrap();
        let claim = AssuranceClaimId::parse("self-certifying-identifier").unwrap();
        let assurance_policy = AssurancePolicy::new(
            policy_id.clone(),
            vec![
                AssuranceRequirement::new(
                    ParticipantRole::Root,
                    AssuranceQuantifier::Every,
                    claim.clone(),
                    None,
                ),
                AssuranceRequirement::new(
                    ParticipantRole::Actor,
                    AssuranceQuantifier::Every,
                    claim.clone(),
                    None,
                ),
            ],
        )
        .unwrap();
        let accepted = AcceptedRegistries::new(
            auths_registries::TARGET_V1_REGISTRY_MANIFEST,
            vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
            vec![SignatureSuiteId::parse(ED25519_V1).unwrap()],
            vec![EvidenceTypeId::parse(RAW_KEY_V1).unwrap()],
            Vec::new(),
            Vec::new(),
            vec![
                claim,
                AssuranceClaimId::parse("offline-verifiable").unwrap(),
            ],
            Vec::new(),
            vec![auths_model::ResourceMatcherId::parse("uri-namespace-v1").unwrap()],
            vec![auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap()],
            Vec::new(),
            vec![profile.clone()],
            vec![ProfilePolicyId::parse("exact-v1").unwrap()],
        )
        .unwrap();
        let anchor = TrustAnchor::new(
            TrustAnchorId::parse("local-root").unwrap(),
            principal,
            vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
            vec![profile],
            PermissionSet::new(vec![permission]).unwrap(),
            vec![ResourceId::parse("mcp://reports").unwrap()],
            AudienceSet::new(vec![Audience::parse("mcp://reports").unwrap()]).unwrap(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
            anchor_ceiling,
            4,
            policy_id,
            StatusPolicy::ExpiryOnly,
        )
        .unwrap();
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let configuration = ImmutableRegistries::new(&methods, &suites)
            .unwrap()
            .configuration_id();
        let context = TrustedContext::new(
            configuration,
            CompositionRequirement::exact(computed_plan),
            vec![anchor],
            accepted,
            Audience::parse("mcp://reports").unwrap(),
            challenge,
            Timestamp::new(15),
            assurance_policy,
            PrincipalStatusSnapshot::new(
                StatusSnapshotId::new([4; 32]),
                Timestamp::new(0),
                Timestamp::new(100),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            GrantStatusSnapshot::new(
                StatusSnapshotId::new([5; 32]),
                Timestamp::new(0),
                Timestamp::new(100),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            auths_model::ResourceMatcherId::parse("uri-namespace-v1").unwrap(),
            ProfilePolicyId::parse("exact-v1").unwrap(),
            channel,
            VerifierLimits::default(),
        )
        .unwrap();
        Fixture {
            bytes: auths_codec::CanonicalProofBundle::new(auths_model::ProofBundle::clone(&bundle)).and_then(|canonical| encode_bundle(&canonical)).unwrap(),
            canonical,
            context,
            action: signed_action,
        }
    }

    #[test]
    fn raw_key_root_authorizes_exact_action() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let outcome = verify(
            &fixture.bytes,
            &fixture.canonical,
            &fixture.context,
            &registries,
        );
        let VerificationOutcome::Authorized(action) = outcome else {
            panic!("expected target proof to authorize: {outcome:?}");
        };
        assert_eq!(action.canonical_action(), &fixture.canonical);
        assert_eq!(action.authorized_branches(), &[ProofRef::new([1; 32])]);
    }

    fn verify_budget_fixture(
        anchor_ceiling: Option<BudgetCeiling>,
        requested_budget: Option<BudgetCeiling>,
    ) -> VerificationOutcome {
        let fixture = target_fixture_with_budget(false, anchor_ceiling, requested_budget);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        verify(
            &fixture.bytes,
            &fixture.canonical,
            &fixture.context,
            &registries,
        )
    }

    /// Regression: a bounded authority used to be satisfied by an action that
    /// declared no budget at all, because the terminal coverage check was
    /// gated on `(Some(ceiling), Some(requested))`. An unbounded request under
    /// a bounded ceiling now denies.
    #[test]
    fn bounded_ceiling_denies_an_action_that_requests_no_budget() {
        assert_eq!(
            verify_budget_fixture(Some(numeric_ceiling(10_000)), None),
            VerificationOutcome::Denied(DenialReason::BudgetCeilingExceeded)
        );
    }

    #[test]
    fn bounded_ceiling_authorizes_a_request_within_the_ceiling() {
        let outcome =
            verify_budget_fixture(Some(numeric_ceiling(10_000)), Some(numeric_ceiling(10_000)));
        assert!(
            matches!(outcome, VerificationOutcome::Authorized(_)),
            "expected an in-ceiling request to authorize: {outcome:?}"
        );
    }

    #[test]
    fn bounded_ceiling_denies_a_request_over_the_ceiling() {
        assert_eq!(
            verify_budget_fixture(Some(numeric_ceiling(10_000)), Some(numeric_ceiling(10_001))),
            VerificationOutcome::Denied(DenialReason::BudgetCeilingExceeded)
        );
    }

    /// The denial above must not depend on statement order inside
    /// [`verify_authority_and_assurance`].
    ///
    /// `validate_budget_constraints` runs at the top of that function, before
    /// `EffectiveAuthority::authorizes`. It is deliberately kept — it is the
    /// only thing that resolves the ceiling's algebra against the accepted
    /// registries (yielding `Indeterminate(UnsupportedBudgetAlgebra)` for an
    /// algebra the verifier does not implement) and the only thing that meters
    /// the comparison's work. But it must never be the *sole* reason a bounded
    /// ceiling denies an absent request, or a kernel regression would be
    /// invisible here. This drives the authority kernel with that guard
    /// bypassed entirely.
    #[test]
    fn the_authority_kernel_denies_an_absent_request_without_the_verifier_guard() {
        let fixture = target_fixture_with_budget(false, Some(numeric_ceiling(10_000)), None);
        let anchor = fixture
            .context
            .trust_anchors()
            .first()
            .expect("fixture anchor");
        let authority = EffectiveAuthority::from_anchor(anchor);
        assert_eq!(
            authority.authorizes(
                fixture.action.envelope(),
                fixture.context.accepted_registries()
            ),
            Err(DenialReason::BudgetCeilingExceeded),
            "the kernel alone must deny; the Wave 1 guard is defense in depth"
        );

        // The same kernel, same guard-free path, still authorizes a request
        // that is inside the ceiling: this is not a blanket budget denial.
        let inside = target_fixture_with_budget(
            false,
            Some(numeric_ceiling(10_000)),
            Some(numeric_ceiling(10_000)),
        );
        let inside_anchor = inside
            .context
            .trust_anchors()
            .first()
            .expect("fixture anchor");
        assert_eq!(
            EffectiveAuthority::from_anchor(inside_anchor).authorizes(
                inside.action.envelope(),
                inside.context.accepted_registries()
            ),
            Ok(())
        );
    }

    /// Evidence that `validate_budget_constraints` is not a duplicate of the
    /// kernel and must be kept.
    ///
    /// The kernel compares algebra *identifiers* bytewise and then applies the
    /// numeric `<=` unconditionally. It has no notion of "this verifier does
    /// not implement that algebra". Only the verifier guard resolves the
    /// ceiling's algebra against the accepted registries, so only it can fail
    /// closed with `Indeterminate(UnsupportedBudgetAlgebra)`. Delete the guard
    /// and this case silently becomes a numeric comparison the verifier is not
    /// entitled to make.
    #[test]
    fn only_the_verifier_guard_can_reject_an_unimplemented_budget_algebra() {
        let unknown = BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("credits-v1").unwrap(),
            10_000,
        );
        let inside = BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("credits-v1").unwrap(),
            5_000,
        );
        let fixture = target_fixture_with_budget(false, Some(unknown), Some(inside));

        // The kernel alone authorizes: same algebra id, 5_000 <= 10_000.
        let anchor = fixture
            .context
            .trust_anchors()
            .first()
            .expect("fixture anchor");
        assert_eq!(
            EffectiveAuthority::from_anchor(anchor).authorizes(
                fixture.action.envelope(),
                fixture.context.accepted_registries()
            ),
            Ok(())
        );

        // The full verifier refuses to decide, because it cannot evaluate that
        // algebra. This is the capability the guard uniquely provides.
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        assert_eq!(
            verify(
                &fixture.bytes,
                &fixture.canonical,
                &fixture.context,
                &registries,
            ),
            VerificationOutcome::Indeterminate(Requirement::UnsupportedBudgetAlgebra)
        );
    }

    /// Rebuilds a context that declares exactly the given profiles budget-free.
    ///
    /// Everything else — anchors, registries, policies, limits — is carried
    /// across unchanged, so a verdict that differs between the original and the
    /// rebuilt context can only be caused by this one declaration.
    fn declaring_budget_free(
        context: &TrustedContext,
        profiles: Vec<ProfileRef>,
    ) -> TrustedContext {
        TrustedContext::new(
            context.configuration(),
            context.composition(),
            context.trust_anchors().to_vec(),
            context
                .accepted_registries()
                .clone()
                .with_budget_free_profiles(profiles)
                .expect("budget-free declaration"),
            context.expected_audience().clone(),
            context.expected_challenge(),
            context.evaluation_time(),
            context.assurance_policy().clone(),
            context.principal_status_snapshot().clone(),
            context.grant_status_snapshot().clone(),
            context.resource_matcher().clone(),
            context.profile_policy().clone(),
            context.channel_policy().clone(),
            context.limits().clone(),
        )
        .expect("rebuilt context")
    }

    /// The v1.0 blocker: a profile whose canonical body has no budget field is
    /// unusable under any bounded grant chain unless the verifier is told so.
    ///
    /// `bounded_ceiling_denies_an_action_that_requests_no_budget` above proves
    /// the denial for a profile that *can* express a budget, and must stay
    /// green. This drives byte-identical proof material through a context that
    /// differs in exactly one declaration, and the verdict flips.
    #[test]
    fn a_budget_free_profile_authorizes_under_a_bounded_ceiling() {
        let fixture = target_fixture_with_budget(false, Some(numeric_ceiling(10_000)), None);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();

        // Undeclared: the action states no bound at all, so it is denied.
        assert_eq!(
            verify(
                &fixture.bytes,
                &fixture.canonical,
                &fixture.context,
                &registries,
            ),
            VerificationOutcome::Denied(DenialReason::BudgetCeilingExceeded)
        );

        // Declared budget-free: the same action provably spends zero.
        let declared = declaring_budget_free(
            &fixture.context,
            vec![fixture.action.envelope().profile().clone()],
        );
        let outcome = verify(&fixture.bytes, &fixture.canonical, &declared, &registries);
        assert!(
            matches!(outcome, VerificationOutcome::Authorized(_)),
            "a budget-free profile spends zero, which every ceiling covers: {outcome:?}"
        );

        // The kernel must reach the same answer with the verifier's own
        // `validate_budget_constraints` guard bypassed, so correctness cannot
        // rest on which of the two runs first.
        let anchor = declared.trust_anchors().first().expect("fixture anchor");
        assert_eq!(
            EffectiveAuthority::from_anchor(anchor)
                .authorizes(fixture.action.envelope(), declared.accepted_registries()),
            Ok(())
        );
    }

    /// An unbounded authority is still the top scope: it does not require the
    /// action to declare a budget.
    #[test]
    fn unbounded_authority_still_authorizes_an_action_without_a_budget() {
        let outcome = verify_budget_fixture(None, None);
        assert!(
            matches!(outcome, VerificationOutcome::Authorized(_)),
            "expected an unbounded authority to authorize: {outcome:?}"
        );
    }

    #[test]
    fn work_reservation_enforces_exact_boundary_and_overflow() {
        let mut meter = WorkMeter::new(10);
        assert_eq!(meter.reserve(9), Ok(()));
        assert_eq!(meter.reserve(1), Ok(()));
        assert_eq!(
            meter.reserve(1),
            Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded
            ))
        );
        let mut overflow = WorkMeter::from_used(u64::MAX, u64::MAX);
        assert_eq!(
            overflow.reserve(1),
            Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded
            ))
        );
    }

    #[test]
    fn signature_mutation_is_denied() {
        let fixture = target_fixture(true);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        assert_eq!(
            verify(
                &fixture.bytes,
                &fixture.canonical,
                &fixture.context,
                &registries,
            ),
            VerificationOutcome::Denied(DenialReason::InvalidSignature)
        );
    }

    #[test]
    fn canonical_body_mutation_is_denied() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let mutated = CanonicalAction::new(
            fixture.canonical.profile().clone(),
            fixture.canonical.media_type().clone(),
            b"mutated".to_vec(),
            fixture.canonical.permission().clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            verify(&fixture.bytes, &mutated, &fixture.context, &registries),
            VerificationOutcome::Denied(DenialReason::ActionBodyMismatch)
        );
    }

    #[test]
    fn portable_result_round_trips_with_self_digest() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let result = verify_portable(
            &fixture.bytes,
            &fixture.canonical,
            &fixture.context,
            &registries,
        );
        assert_eq!(result.decision(), VerificationDecision::Authorized);
        assert_eq!(
            result.required_configuration(),
            Some(result.local_configuration())
        );
        assert_ne!(result.result_digest().as_bytes(), &[0; 32]);
        let bytes = auths_codec::CanonicalVerificationResult::new(auths_model::PortableVerificationResult::clone(&result)).and_then(|canonical| auths_codec::encode_verification_result(&canonical)).unwrap();
        assert_eq!(
            auths_codec::decode_verification_result(&bytes).unwrap().into_value(),
            result
        );
    }

    #[test]
    fn byte_oriented_portable_abi_is_total_and_deterministic() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let action_bytes = auths_codec::encode_canonical_action(&fixture.canonical).unwrap();
        let context_bytes = auths_codec::CanonicalTrustedContext::new(auths_model::TrustedContext::clone(&fixture.context)).and_then(|canonical| auths_codec::encode_verifier_context(&canonical)).unwrap();

        let bytes = verify_v1(&fixture.bytes, &action_bytes, &context_bytes, &registries).unwrap();
        let decoded = auths_codec::decode_verification_result(&bytes).unwrap();
        assert_eq!(
            decoded,
            verify_portable(
                &fixture.bytes,
                &fixture.canonical,
                &fixture.context,
                &registries,
            )
        );
        assert_eq!(
            verify_v1(&fixture.bytes, &action_bytes, &context_bytes, &registries,).unwrap(),
            bytes
        );

        let malformed = verify_v1(&fixture.bytes, &[0xff], &context_bytes, &registries).unwrap();
        let malformed = auths_codec::decode_verification_result(&malformed).unwrap();
        assert_eq!(malformed.decision(), VerificationDecision::Denied);
        assert_eq!(malformed.stage(), VerificationStage::Decode);
        assert_eq!(
            malformed.code(),
            VerificationCode::Denied(DenialReason::MalformedProof)
        );
        assert_eq!(
            malformed.result_digest(),
            auths_codec::verification_result_digest(&malformed).unwrap()
        );
    }

    #[test]
    fn sealed_portable_result_releases_authority_only_on_success() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let action_bytes = auths_codec::encode_canonical_action(&fixture.canonical).unwrap();
        let context_bytes = auths_codec::CanonicalTrustedContext::new(auths_model::TrustedContext::clone(&fixture.context)).and_then(|canonical| auths_codec::encode_verifier_context(&canonical)).unwrap();

        let authorized =
            verify_v1_sealed(&fixture.bytes, &action_bytes, &context_bytes, &registries).unwrap();
        assert_eq!(
            authorized.cbor(),
            verify_v1(&fixture.bytes, &action_bytes, &context_bytes, &registries).unwrap()
        );
        assert_eq!(
            authorized.action().unwrap().canonical_action(),
            &fixture.canonical
        );

        assert_eq!(
            authorized.action().unwrap().authority_not_after(),
            Timestamp::new(20)
        );

        let denied =
            verify_v1_sealed(&fixture.bytes, b"invalid", &context_bytes, &registries).unwrap();
        assert_eq!(denied.portable().decision(), VerificationDecision::Denied);
        assert!(denied.action().is_none());

        let no_methods: [&dyn auths_ports::PrincipalMethod; 0] = [];
        let no_suites: [&dyn auths_ports::SignatureSuite; 0] = [];
        let empty_registries = ImmutableRegistries::new(&no_methods, &no_suites).unwrap();
        let unsupported_context = fixture
            .context
            .with_configuration(empty_registries.configuration_id())
            .unwrap();
        let unsupported_context =
            auths_codec::CanonicalTrustedContext::new(auths_model::TrustedContext::clone(&unsupported_context)).and_then(|canonical| auths_codec::encode_verifier_context(&canonical)).unwrap();
        let indeterminate = verify_v1_sealed(
            &fixture.bytes,
            &action_bytes,
            &unsupported_context,
            &empty_registries,
        )
        .unwrap();
        assert_eq!(
            indeterminate.portable().decision(),
            VerificationDecision::Indeterminate
        );
        assert!(indeterminate.action().is_none());
    }

    fn verify_composition_fixture(
        fixture: &auths_testkit::CorpusFixture,
        minimum_authorized_branches: u16,
        minimum_distinct_actors: u16,
        minimum_distinct_roots: u16,
    ) -> VerificationOutcome {
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .unwrap()
            .with_configuration(registries.configuration_id())
            .unwrap();
        let context = context
            .with_composition(
                CompositionRequirement::new(
                    context.composition().expected_plan(),
                    minimum_authorized_branches,
                    minimum_distinct_actors,
                    minimum_distinct_roots,
                )
                .unwrap(),
            )
            .unwrap();
        verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        )
    }

    fn explain_composition_fixture(
        fixture: &auths_testkit::CorpusFixture,
        minimum_authorized_branches: u16,
        minimum_distinct_actors: u16,
        minimum_distinct_roots: u16,
    ) -> ExplainedVerification {
        let raw_key = RawKeyMethod::new().unwrap();
        let did_key = auths_did_key::DidKeyMethod::new().unwrap();
        let did_keri = auths_did_keri::DidKeriMethod::new().unwrap();
        let did_web =
            auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
                .unwrap();
        let webauthn =
            auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
                .unwrap();
        let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
            .unwrap();
        let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
        let spiffe = auths_testkit::spiffe_corpus_method(spiffe_trust, spiffe_status).unwrap();
        let ed25519 = Ed25519Suite::new().unwrap();
        let p256 = auths_signature::P256Sha256Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
            &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
        ];
        let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .unwrap()
            .with_configuration(registries.configuration_id())
            .unwrap();
        let context = context
            .with_composition(
                CompositionRequirement::new(
                    context.composition().expected_plan(),
                    minimum_authorized_branches,
                    minimum_distinct_actors,
                    minimum_distinct_roots,
                )
                .unwrap(),
            )
            .unwrap();
        verify_explained(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        )
        .unwrap()
    }

    fn plan_leaf_contributions(
        explained: &ExplainedVerification,
    ) -> Vec<(FactResult, causal::Contribution)> {
        causal::causal_slice(explained.trace())
            .into_iter()
            .filter(|fact| {
                fact.fact.kind() == FactKind::PlanNode
                    && matches!(fact.fact.value(), FactValue::Present(true))
            })
            .map(|fact| (fact.fact.result(), fact.contribution))
            .collect()
    }

    #[test]
    fn all_of_marks_every_successful_leaf_as_necessary_support() {
        let explained = explain_composition_fixture(&auths_testkit::all_of(), 1, 1, 1);
        assert_eq!(
            plan_leaf_contributions(&explained),
            vec![
                (
                    FactResult::Satisfied,
                    causal::Contribution::NecessarySupport
                ),
                (
                    FactResult::Satisfied,
                    causal::Contribution::NecessarySupport
                ),
            ]
        );
    }

    #[test]
    fn any_of_distinguishes_sufficient_alternative_from_failed_branch() {
        let explained =
            explain_composition_fixture(&auths_testkit::any_of_valid_invalid_signature(), 1, 1, 1);
        assert_eq!(
            plan_leaf_contributions(&explained),
            vec![
                (
                    FactResult::Satisfied,
                    causal::Contribution::SufficientAlternative,
                ),
                (
                    FactResult::Contradicted,
                    causal::Contribution::Informational
                ),
            ]
        );
    }

    #[test]
    fn k_of_n_truth_table_drives_authorized_denied_and_indeterminate_slices() {
        let authorized =
            explain_composition_fixture(&auths_testkit::threshold_mixed_success(), 1, 1, 1);
        assert_eq!(
            plan_leaf_contributions(&authorized),
            vec![
                (
                    FactResult::Satisfied,
                    causal::Contribution::SufficientAlternative,
                ),
                (
                    FactResult::Satisfied,
                    causal::Contribution::SufficientAlternative,
                ),
                (
                    FactResult::Contradicted,
                    causal::Contribution::Informational
                ),
            ]
        );

        let denied = explain_composition_fixture(&auths_testkit::threshold_mixed_denied(), 1, 1, 1);
        assert_eq!(
            plan_leaf_contributions(&denied),
            vec![
                (FactResult::Satisfied, causal::Contribution::Informational),
                (
                    FactResult::Contradicted,
                    causal::Contribution::ContributingBlocker,
                ),
                (
                    FactResult::Contradicted,
                    causal::Contribution::ContributingBlocker,
                ),
            ]
        );

        let indeterminate =
            explain_composition_fixture(&auths_testkit::threshold_mixed_indeterminate(), 1, 1, 1);
        assert_eq!(
            plan_leaf_contributions(&indeterminate),
            vec![
                (
                    FactResult::Satisfied,
                    causal::Contribution::SufficientAlternative,
                ),
                (
                    FactResult::Contradicted,
                    causal::Contribution::ContributingBlocker,
                ),
                (
                    FactResult::Unavailable,
                    causal::Contribution::ContributingBlocker,
                ),
            ]
        );
    }

    #[test]
    fn local_composition_floors_are_explicit_context_constraints() {
        let explained = explain_composition_fixture(
            &auths_testkit::composition_same_actor_two_branches(),
            2,
            2,
            1,
        );
        assert_eq!(
            explained.outcome(),
            &VerificationOutcome::Denied(DenialReason::CompositionRequirementNotMet)
        );
        let constraints: Vec<_> = causal::causal_slice(explained.trace())
            .into_iter()
            .filter(|fact| {
                matches!(
                    fact.fact.kind(),
                    FactKind::MinimumAuthorizedBranches
                        | FactKind::MinimumDistinctActors
                        | FactKind::MinimumDistinctRoots
                )
            })
            .collect();
        assert_eq!(constraints.len(), 3);
        assert!(
            constraints
                .iter()
                .all(|fact| fact.contribution == causal::Contribution::ContextConstraint)
        );
        assert_eq!(
            constraints
                .iter()
                .filter(|fact| fact.fact.result() == FactResult::Contradicted)
                .count(),
            1
        );
    }

    #[test]
    fn backward_slice_excludes_recorded_non_ancestors() {
        let fixture = target_fixture(false);
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let explained =
            verify_explained(&[0xff], &fixture.canonical, &fixture.context, &registries).unwrap();
        let slice = causal::causal_slice(explained.trace());
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].fact.sequence(), explained.trace().final_node());
        assert_eq!(slice[0].contribution, causal::Contribution::Decisive);
    }

    #[test]
    fn verifier_required_plan_cannot_be_weakened() {
        let fixture = auths_testkit::raw_key_chain();
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .unwrap()
            .with_configuration(registries.configuration_id())
            .unwrap();
        let wrong_plan = context
            .with_composition(CompositionRequirement::exact(auths_model::PlanId::new(
                [0xa5; 32],
            )))
            .unwrap();
        assert_eq!(
            verify(
                fixture.proof_bytes(),
                fixture.canonical_action(),
                &wrong_plan,
                &registries,
            ),
            VerificationOutcome::Denied(DenialReason::CompositionRequirementNotMet)
        );
    }

    #[test]
    fn minimum_authorized_branches_is_enforced_independently() {
        let fixture = auths_testkit::raw_key_chain();
        assert_eq!(
            verify_composition_fixture(&fixture, 2, 1, 1),
            VerificationOutcome::Denied(DenialReason::CompositionRequirementNotMet)
        );
    }

    #[test]
    fn actor_diversity_counts_principals_not_authorized_branches() {
        let fixture = auths_testkit::composition_same_actor_two_branches();
        assert!(matches!(
            verify_composition_fixture(&fixture, 2, 1, 1),
            VerificationOutcome::Authorized(_)
        ));
        assert_eq!(
            verify_composition_fixture(&fixture, 2, 2, 1),
            VerificationOutcome::Denied(DenialReason::CompositionRequirementNotMet)
        );
    }

    #[test]
    fn root_diversity_counts_principals_not_distinct_actors() {
        let fixture = auths_testkit::composition_shared_root_two_actors();
        assert!(matches!(
            verify_composition_fixture(&fixture, 2, 2, 1),
            VerificationOutcome::Authorized(_)
        ));
        assert_eq!(
            verify_composition_fixture(&fixture, 2, 2, 2),
            VerificationOutcome::Denied(DenialReason::CompositionRequirementNotMet)
        );
    }

    #[test]
    fn distinct_actors_and_roots_satisfy_composition_diversity() {
        let fixture = auths_testkit::composition_distinct_roots_two_actors();
        assert!(matches!(
            verify_composition_fixture(&fixture, 2, 2, 2),
            VerificationOutcome::Authorized(_)
        ));
    }

    #[test]
    fn executable_configuration_mismatch_fails_closed() {
        let fixture = auths_testkit::raw_key_chain();
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
        assert_eq!(
            verify(
                fixture.proof_bytes(),
                fixture.canonical_action(),
                &context,
                &registries,
            ),
            VerificationOutcome::Denied(DenialReason::VerifierConfigurationMismatch)
        );
    }

    #[test]
    fn portable_mismatch_reports_required_and_local_configurations() {
        let fixture = auths_testkit::raw_key_chain();
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
        let required_configuration = context.configuration();
        let local_configuration = registries.configuration_id();
        assert_ne!(required_configuration, local_configuration);

        let action_bytes =
            auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
        let result_bytes = verify_v1(
            fixture.proof_bytes(),
            &action_bytes,
            fixture.context_bytes(),
            &registries,
        )
        .unwrap();
        let result = auths_codec::decode_verification_result(&result_bytes).unwrap();

        assert_eq!(result.decision(), VerificationDecision::Denied);
        assert_eq!(result.stage(), VerificationStage::PrincipalControl);
        assert_eq!(
            result.code(),
            VerificationCode::Denied(DenialReason::VerifierConfigurationMismatch)
        );
        assert_eq!(
            result.required_configuration(),
            Some(required_configuration)
        );
        assert_eq!(result.local_configuration(), local_configuration);
    }

    #[test]
    fn target_corpus_matches_normative_outcomes() {
        let raw_key = RawKeyMethod::new().unwrap();
        let did_key = auths_did_key::DidKeyMethod::new().unwrap();
        let did_keri = auths_did_keri::DidKeriMethod::new().unwrap();
        let did_web =
            auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
                .unwrap();
        let webauthn =
            auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
                .unwrap();
        let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
            .unwrap();
        let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
        let spiffe = auths_testkit::spiffe_corpus_method(spiffe_trust, spiffe_status).unwrap();
        let ed25519 = Ed25519Suite::new().unwrap();
        let p256 = auths_signature::P256Sha256Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
            &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
        ];
        let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        for fixture in auths_testkit::corpus() {
            // A vector whose fault is in the canonical-action input bytes has
            // no in-process form: the portable ABI rejects those bytes before
            // the proof is read, which the portable conformance test checks.
            if fixture.has_raw_action() {
                continue;
            }
            let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
            let encoded = auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
            if auths_codec::decode_canonical_action(&encoded, context.limits()).is_err() {
                continue;
            }
            let actual = verify(
                fixture.proof_bytes(),
                fixture.canonical_action(),
                &context,
                &registries,
            );
            let expected = match fixture.expected() {
                auths_testkit::Expected::Authorized => {
                    assert!(
                        matches!(actual, VerificationOutcome::Authorized(_)),
                        "{}: {actual:?}",
                        fixture.name()
                    );
                    continue;
                }
                auths_testkit::Expected::Denied(reason) => VerificationOutcome::Denied(reason),
                auths_testkit::Expected::Indeterminate(requirement) => {
                    VerificationOutcome::Indeterminate(requirement)
                }
            };
            assert_eq!(actual, expected, "{}", fixture.name());
        }
    }

    #[test]
    fn in_process_verification_bounds_detached_attachments_by_the_attachment_limit() {
        let method = RawKeyMethod::new().unwrap();
        let suite = Ed25519Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 1] = [&method];
        let suites: [&dyn auths_ports::SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let corpus = auths_testkit::corpus();
        let run = |name: &str| {
            let fixture = corpus
                .iter()
                .find(|fixture| fixture.name() == name)
                .unwrap();
            let context = auths_codec::decode_verifier_context(fixture.context_bytes())
                .unwrap()
                .with_configuration(registries.configuration_id())
                .unwrap();
            verify(
                fixture.proof_bytes(),
                fixture.canonical_action(),
                &context,
                &registries,
            )
        };
        // Detached bytes larger than the whole proof may authorize: only the
        // attachment limit bounds them.
        assert!(matches!(
            run("attachment-larger-than-bundle-limit"),
            VerificationOutcome::Authorized(_)
        ));
        // A lowered attachment limit binds an action built in process, which
        // no decoder has bounded.
        assert_eq!(
            run("attachment-bytes-over-limit"),
            VerificationOutcome::Denied(DenialReason::ResourceLimitExceeded)
        );
    }
}

#[cfg(test)]
mod temporal_tests;
