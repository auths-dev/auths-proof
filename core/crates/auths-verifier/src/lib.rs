//! Pure staged target V1 authority verifier.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod causal;
pub mod trace;

use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use auths_assurance::{evaluate_with_implications, grant_issuer_role};
use auths_authority::EffectiveAuthority;
use auths_codec::{
    CodecError, action_id, action_signing_preimage, attachment_digest, body_digest, context_digest,
    decode_bundle, decode_canonical_action, decode_verifier_context, encode_canonical_action,
    encode_verification_result, encode_verifier_context, grant_id, grant_signing_preimage,
    grant_status_id, grant_status_signing_preimage, plan_id, principal_status_id,
    principal_status_signing_preimage, proof_digest,
};
use auths_composition::{
    BranchOutcome, EvaluationEvent, evaluate_observed as evaluate_plan_observed,
};
use auths_model::{
    ActionId, AssuranceSatisfaction, CanonicalAction, ContextDigest, DenialReason, Digest,
    EvidenceObject, GrantId, GrantStatusId, ParticipantAssurance, ParticipantRole, PlanId,
    PortableVerificationResult, PrincipalId, PrincipalStatusId, ProfileBudgetExpression,
    ProofBundle, ProofRef, Requirement, SignatureEnvelope, SignedAction, SignedGrant, StatementRef,
    StatusPolicy, Timestamp, TrustAnchor, TrustedContext, VerificationCode, VerificationDecision,
    VerificationResources, VerificationStage, VerifierConfigurationId,
};
use auths_ports::{
    ControlEvidence, ControlPurpose, PrincipalControlError, PrincipalControlInput, ProfileDecision,
    RegistryOperationError, SignatureError, SignatureInput, StatusDecision,
    diagnostics::DiagnosticMode,
};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GrantRecord {
    id: GrantId,
    index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActionRecord {
    id: ActionId,
    index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkMeter {
    used: u64,
    limit: u64,
}

struct AuthorityDiagnostics {
    collect: bool,
    plan_events: Vec<EvaluationEvent>,
    authorized_branches: usize,
    distinct_actors: usize,
    distinct_roots: usize,
}

impl AuthorityDiagnostics {
    const fn discard() -> Self {
        Self {
            collect: false,
            plan_events: Vec::new(),
            authorized_branches: 0,
            distinct_actors: 0,
            distinct_roots: 0,
        }
    }

    fn collect() -> Self {
        Self {
            collect: true,
            plan_events: Vec::new(),
            authorized_branches: 0,
            distinct_actors: 0,
            distinct_roots: 0,
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

impl WorkMeter {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    const fn from_used(limit: u64, used: u64) -> Self {
        Self { used, limit }
    }

    fn reserve(&mut self, maximum: u64) -> Result<(), VerificationFailure> {
        let next = self
            .used
            .checked_add(maximum)
            .ok_or(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ))?;
        if next > self.limit {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
        self.used = next;
        Ok(())
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

/// Resolved proof whose signed statements have established principal control.
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

/// Authority established for the satisfied authorization-plan branches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthority {
    canonical_action: CanonicalAction,
    proof_digest: Digest,
    context_digest: ContextDigest,
    plan_id: PlanId,
    action_ids: Vec<ActionId>,
    authorized_branches: Vec<ProofRef>,
    assurance: Vec<ParticipantAssurance>,
    assurance_satisfactions: Vec<AssuranceSatisfaction>,
    work_units: u64,
}

/// Sealed data consumed by downstream profile decoders.
///
/// Fields have no public constructor. Applications can obtain this value only
/// from [`verify`] or [`bind_verified_action`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAction {
    canonical_action: CanonicalAction,
    proof_digest: Digest,
    context_digest: ContextDigest,
    plan_id: PlanId,
    action_ids: Vec<ActionId>,
    authorized_branches: Vec<ProofRef>,
    assurance: Vec<ParticipantAssurance>,
    assurance_satisfactions: Vec<AssuranceSatisfaction>,
    work_units: u64,
}

/// Portable decision data paired with the sealed action from the same run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedVerificationResult {
    portable: PortableVerificationResult,
    cbor: Vec<u8>,
    action: Option<Box<VerifiedAction>>,
}

impl SealedVerificationResult {
    /// Returns the language-neutral decision data.
    #[must_use]
    pub const fn portable(&self) -> &PortableVerificationResult {
        &self.portable
    }

    /// Returns the canonical portable decision bytes.
    #[must_use]
    pub fn cbor(&self) -> &[u8] {
        &self.cbor
    }

    /// Returns the sealed action only when the decision is authorized.
    #[must_use]
    pub fn action(&self) -> Option<&VerifiedAction> {
        self.action.as_deref()
    }

    /// Consumes the result into decision data, canonical bytes, and capability.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PortableVerificationResult,
        Vec<u8>,
        Option<Box<VerifiedAction>>,
    ) {
        (self.portable, self.cbor, self.action)
    }
}

impl VerifiedAction {
    /// Returns exact profile-canonical bytes and derived meaning.
    #[must_use]
    pub const fn canonical_action(&self) -> &CanonicalAction {
        &self.canonical_action
    }

    /// Returns the canonical proof digest.
    #[must_use]
    pub const fn proof_digest(&self) -> Digest {
        self.proof_digest
    }

    /// Returns the public trusted-context digest.
    #[must_use]
    pub const fn context_digest(&self) -> ContextDigest {
        self.context_digest
    }

    /// Returns the authorization-plan identifier.
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// Returns action identifiers for satisfied branches in canonical order.
    #[must_use]
    pub fn action_ids(&self) -> &[ActionId] {
        &self.action_ids
    }

    /// Returns satisfied proof references in deterministic evaluation order.
    #[must_use]
    pub fn authorized_branches(&self) -> &[ProofRef] {
        &self.authorized_branches
    }

    /// Returns role-indexed assurance reports for satisfied branches.
    #[must_use]
    pub fn assurance(&self) -> &[ParticipantAssurance] {
        &self.assurance
    }

    /// Returns canonical evidence selected for each assurance requirement.
    #[must_use]
    pub fn assurance_satisfactions(&self) -> &[AssuranceSatisfaction] {
        &self.assurance_satisfactions
    }

    /// Returns deterministic proof-kernel work charged.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }
}

/// Runs the complete pure target V1 verifier.
#[must_use]
pub fn verify(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
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
pub fn verify_explained(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
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
            DenialReason::DelegationExpanded => FactKind::GrantPermissionAttenuation,
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
            Requirement::UnsupportedCriticalExtension => FactKind::CriticalExtension,
            Requirement::UnsupportedAssuranceClaim | Requirement::AssuranceRequirementNotMet => {
                FactKind::AssuranceRequirement
            }
            Requirement::UnsupportedProtocol | Requirement::ExternalFactUnavailable => {
                FactKind::PlanNode
            }
        },
    }
}

fn record_configuration_facts(
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
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
fn verify_internal(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
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
            let node = if plan_root.is_some()
                && matches!(
                    diagnostics.plan_events.last().map(|event| event.outcome()),
                    Some(BranchOutcome::Authorized)
                )
                && failure
                    == VerificationFailure::Denied(DenialReason::CompositionRequirementNotMet)
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
pub fn verify_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    registries: &ImmutableRegistries<'_>,
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
pub fn verify_v1_sealed(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    registries: &ImmutableRegistries<'_>,
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
                context_digest(&context).unwrap_or_else(|_| ContextDigest::new([0; 32])),
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
pub fn verify_portable(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
) -> PortableVerificationResult {
    verify_portable_sealed(proof_bytes, canonical_action, context, registries).0
}

#[allow(clippy::too_many_lines)]
fn verify_portable_sealed(
    proof_bytes: &[u8],
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
) -> (PortableVerificationResult, Option<Box<VerifiedAction>>) {
    let action_bytes = encode_canonical_action(canonical_action).unwrap_or_default();
    let context_bytes = encode_verifier_context(context).unwrap_or_default();
    let proof_input_digest = body_digest(proof_bytes);
    let action_digest = body_digest(&action_bytes);
    let public_context_digest =
        context_digest(context).unwrap_or_else(|_| ContextDigest::new([0; 32]));
    let local_configuration = registries.configuration_id();
    let mut resources = VerificationResources::new(
        u64::try_from(proof_bytes.len()).unwrap_or(u64::MAX),
        u64::try_from(action_bytes.len()).unwrap_or(u64::MAX),
        u64::try_from(context_bytes.len()).unwrap_or(u64::MAX),
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
        .saturating_add(bundle.attachments().len());
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
            let portable = finalize_portable(PortableVerificationResult::new(
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
            ));
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

fn seal_portable(
    portable: PortableVerificationResult,
    action: Option<Box<VerifiedAction>>,
) -> Result<SealedVerificationResult, CodecError> {
    let cbor = encode_verification_result(&portable)?;
    Ok(SealedVerificationResult {
        portable,
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
        bundle,
        proof_digest: digest,
    })
}

/// Resolves and validates the complete digest/reference graph.
///
/// # Errors
///
/// Returns a stable denial for missing, duplicate, cyclic, mismatched,
/// ambiguous, or unused critical references.
pub fn resolve_proof(
    decoded: DecodedProof,
    context: &TrustedContext,
) -> Result<ResolvedProof, VerificationFailure> {
    let bundle = decoded.bundle();
    let computed_plan_id = plan_id(bundle.plan()).map_err(codec_failure)?;
    require_expected_plan(context, computed_plan_id)?;
    let mut grants = Vec::with_capacity(bundle.grants().len());
    for (index, grant) in bundle.grants().iter().enumerate() {
        grants.push(GrantRecord {
            id: grant_id(grant.statement()).map_err(codec_failure)?,
            index,
        });
    }
    grants.sort_by_key(|record| record.id);
    if grants.windows(2).any(|window| window[0].id == window[1].id) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    let mut actions = Vec::with_capacity(bundle.actions().len());
    let mut proof_refs = BTreeSet::new();
    for (index, action) in bundle.actions().iter().enumerate() {
        if action.envelope().authorization_plan() != computed_plan_id {
            return Err(VerificationFailure::Denied(
                DenialReason::PlanActionMismatch,
            ));
        }
        if !proof_refs.insert(action.envelope().proof_ref()) {
            return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
        }
        actions.push(ActionRecord {
            id: action_id(action.envelope()).map_err(codec_failure)?,
            index,
        });
    }
    actions.sort_by_key(|record| record.id);
    if actions
        .windows(2)
        .any(|window| window[0].id == window[1].id)
    {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }

    let shape = bundle
        .plan()
        .validate(context.limits())
        .map_err(|_| VerificationFailure::Denied(DenialReason::AuthorizationPlanInvalid))?;
    if shape.leaves().len() != bundle.actions().len()
        || shape.leaves().iter().any(|reference| {
            !bundle
                .actions()
                .iter()
                .any(|action| action.envelope().proof_ref() == *reference)
        })
    {
        return Err(VerificationFailure::Denied(DenialReason::MissingReference));
    }

    let evidence_ids: BTreeSet<_> = bundle.evidence().iter().map(EvidenceObject::id).collect();
    if evidence_ids.len() != bundle.evidence().len() {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }

    let principal_status = principal_status_records(context)?;
    let grant_status = grant_status_records(context)?;
    let mut bound_statements = BTreeSet::new();
    for binding in bundle.bindings() {
        if !bound_statements.insert(binding.statement()) {
            return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
        }
        if !statement_exists(
            binding.statement(),
            &grants,
            &actions,
            &principal_status,
            &grant_status,
        ) || binding
            .evidence()
            .iter()
            .any(|id| !evidence_ids.contains(id))
        {
            return Err(VerificationFailure::Denied(DenialReason::MissingReference));
        }
    }

    let mut used_grants = BTreeSet::new();
    for action in bundle.actions() {
        resolve_chain(bundle, &grants, action, &mut used_grants)?;
    }
    if used_grants.len() != grants.len() {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalEvidence,
        ));
    }

    reject_duplicate_attachments(bundle)?;
    validate_carried_status(bundle, context)?;
    Ok(ResolvedProof {
        decoded,
        plan_id: computed_plan_id,
        grants,
        actions,
    })
}

fn require_expected_plan(
    context: &TrustedContext,
    actual: PlanId,
) -> Result<(), VerificationFailure> {
    if context
        .composition()
        .expected_plan()
        .is_some_and(|expected| expected != actual)
    {
        Err(VerificationFailure::Denied(
            DenialReason::CompositionRequirementNotMet,
        ))
    } else {
        Ok(())
    }
}

/// Verifies exact principal methods, exact signature suites, and all supplied
/// signed statements.
///
/// # Errors
///
/// Returns a stable denial or indeterminate requirement. Work is charged
/// before the configured maximum can be exceeded.
pub fn verify_principal_control(
    resolved: ResolvedProof,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
) -> Result<ControlVerifiedProof, VerificationFailure> {
    if context.accepted_registries().manifest_id() != registries.manifest_id() {
        return Err(VerificationFailure::Denied(
            DenialReason::RegistryManifestMismatch,
        ));
    }
    if context.configuration() != registries.configuration_id() {
        return Err(VerificationFailure::Denied(
            DenialReason::VerifierConfigurationMismatch,
        ));
    }
    let mut controls = Vec::new();
    let mut meter = WorkMeter::new(context.limits().max_work_units());
    let bundle = resolved.decoded.bundle();

    for record in &resolved.grants {
        let grant = &bundle.grants()[record.index];
        let preimage = grant_signing_preimage(grant.statement(), grant.signature().descriptor())
            .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::Grant(record.id),
            grant.statement().issuer(),
            grant.signature(),
            &preimage,
            ControlPurpose::CapabilityDelegation,
            grant.statement().validity().not_before(),
            bundle,
            context,
            registries,
            &mut meter,
        )?;
        controls.push(control);
    }
    for record in &resolved.actions {
        let action = &bundle.actions()[record.index];
        let preimage = action_signing_preimage(action.envelope(), action.signature().descriptor())
            .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::Action(record.id),
            action.envelope().actor(),
            action.signature(),
            &preimage,
            ControlPurpose::CapabilityInvocation,
            action.envelope().validity().not_before(),
            bundle,
            context,
            registries,
            &mut meter,
        )?;
        controls.push(control);
    }
    verify_status_controls(bundle, context, registries, &mut meter, &mut controls)?;
    for control in &controls {
        let Ok(evidence) = &control.result else {
            continue;
        };
        let bound: BTreeSet<_> = bundle
            .bindings()
            .iter()
            .find(|binding| binding.statement() == control.statement)
            .map(auths_model::ControlBinding::evidence)
            .unwrap_or_default()
            .iter()
            .copied()
            .collect();
        let consumed: BTreeSet<_> = evidence.consumed_evidence().iter().copied().collect();
        if bound != consumed {
            return Err(VerificationFailure::Denied(
                DenialReason::UnusedCriticalEvidence,
            ));
        }
    }
    let consumed: BTreeSet<_> = bundle
        .bindings()
        .iter()
        .flat_map(auths_model::ControlBinding::evidence)
        .copied()
        .chain(
            context
                .principal_status_snapshot()
                .checkpoints()
                .iter()
                .chain(context.grant_status_snapshot().checkpoints())
                .copied(),
        )
        .collect();
    if bundle
        .evidence()
        .iter()
        .any(|evidence| !consumed.contains(&evidence.id()))
    {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalEvidence,
        ));
    }
    Ok(ControlVerifiedProof {
        resolved,
        controls,
        work_units: meter.used,
    })
}

fn verify_status_controls(
    bundle: &ProofBundle,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
    controls: &mut Vec<VerifiedControl>,
) -> Result<(), VerificationFailure> {
    for status in context.principal_status_snapshot().statements() {
        let id = principal_status_id(status.statement()).map_err(codec_failure)?;
        let preimage =
            principal_status_signing_preimage(status.statement(), status.signature().descriptor())
                .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::PrincipalStatus(id),
            status.statement().issuer(),
            status.signature(),
            &preimage,
            ControlPurpose::Assertion,
            status.statement().observed_at(),
            bundle,
            context,
            registries,
            meter,
        )?;
        controls.push(control);
    }
    for status in context.grant_status_snapshot().statements() {
        let id = grant_status_id(status.statement()).map_err(codec_failure)?;
        let preimage =
            grant_status_signing_preimage(status.statement(), status.signature().descriptor())
                .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::GrantStatus(id),
            status.statement().issuer(),
            status.signature(),
            &preimage,
            ControlPurpose::Assertion,
            status.statement().observed_at(),
            bundle,
            context,
            registries,
            meter,
        )?;
        controls.push(control);
    }
    Ok(())
}

/// Evaluates action binding, every authority branch, status, assurance, and
/// the authorization plan.
///
/// # Errors
///
/// Returns a stable denial or indeterminate requirement.
pub fn verify_authority(
    controlled: ControlVerifiedProof,
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
) -> Result<VerifiedAuthority, VerificationFailure> {
    let mut meter = WorkMeter::from_used(context.limits().max_work_units(), controlled.work_units);
    let mut diagnostics = AuthorityDiagnostics::discard();
    verify_authority_measured(
        controlled,
        canonical_action,
        context,
        registries,
        &mut meter,
        &mut diagnostics,
    )
}

fn verify_authority_measured(
    controlled: ControlVerifiedProof,
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
    diagnostics: &mut AuthorityDiagnostics,
) -> Result<VerifiedAuthority, VerificationFailure> {
    validate_action_binding(&controlled, canonical_action, context, registries, meter)?;
    let context_digest = context_digest(context).map_err(codec_failure)?;
    let mut authorized_branches = Vec::new();
    let mut assurance = Vec::new();
    let mut assurance_satisfactions = Vec::new();
    let mut action_ids = Vec::new();
    let bundle = controlled.resolved.decoded.bundle();

    let outcome = evaluate_plan_observed(
        bundle.plan(),
        context.limits(),
        &mut |reference| match verify_branch(&controlled, reference, context, registries, meter) {
            Ok((action_id, reports, satisfactions)) => {
                authorized_branches.push(reference);
                action_ids.push(action_id);
                assurance.extend(reports);
                assurance_satisfactions.extend(satisfactions);
                BranchOutcome::Authorized
            }
            Err(VerificationFailure::Denied(reason)) => BranchOutcome::Denied(reason),
            Err(VerificationFailure::Indeterminate(requirement)) => {
                BranchOutcome::Indeterminate(requirement)
            }
        },
        &mut |event| diagnostics.record_plan_event(event),
    )
    .map_err(VerificationFailure::Denied)?;

    match outcome {
        BranchOutcome::Authorized => {}
        BranchOutcome::Denied(reason) => return Err(VerificationFailure::Denied(reason)),
        BranchOutcome::Indeterminate(requirement) => {
            return Err(VerificationFailure::Indeterminate(requirement));
        }
        BranchOutcome::StructurallyInvalid(reason) => {
            return Err(VerificationFailure::Denied(reason));
        }
    }
    let composition = context.composition();
    let distinct_actors: BTreeSet<_> = assurance
        .iter()
        .filter(|report| report.role() == ParticipantRole::Actor)
        .map(ParticipantAssurance::principal)
        .collect();
    let distinct_roots: BTreeSet<_> = assurance
        .iter()
        .filter(|report| report.role() == ParticipantRole::Root)
        .map(ParticipantAssurance::principal)
        .collect();
    diagnostics.record_composition_counts(
        authorized_branches.len(),
        distinct_actors.len(),
        distinct_roots.len(),
    );
    if authorized_branches.len() < usize::from(composition.minimum_authorized_branches())
        || distinct_actors.len() < usize::from(composition.minimum_distinct_actors())
        || distinct_roots.len() < usize::from(composition.minimum_distinct_roots())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::CompositionRequirementNotMet,
        ));
    }
    assurance.sort_by(|left, right| {
        left.role()
            .cmp(&right.role())
            .then_with(|| left.principal().cmp(right.principal()))
    });
    assurance.dedup();
    action_ids.sort();
    action_ids.dedup();
    authorized_branches.sort();
    authorized_branches.dedup();
    assurance_satisfactions.sort();
    assurance_satisfactions.dedup();
    let ControlVerifiedProof { resolved, .. } = controlled;
    Ok(VerifiedAuthority {
        canonical_action: canonical_action.clone(),
        proof_digest: resolved.decoded.proof_digest,
        context_digest,
        plan_id: resolved.plan_id,
        action_ids,
        authorized_branches,
        assurance,
        assurance_satisfactions,
        work_units: meter.used,
    })
}

/// Seals a verified authority result as a downstream-consumable action.
#[must_use]
pub fn bind_verified_action(authority: VerifiedAuthority) -> VerifiedAction {
    VerifiedAction {
        canonical_action: authority.canonical_action,
        proof_digest: authority.proof_digest,
        context_digest: authority.context_digest,
        plan_id: authority.plan_id,
        action_ids: authority.action_ids,
        authorized_branches: authority.authorized_branches,
        assurance: authority.assurance,
        assurance_satisfactions: authority.assurance_satisfactions,
        work_units: authority.work_units,
    }
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

fn principal_status_records(
    context: &TrustedContext,
) -> Result<Vec<PrincipalStatusId>, VerificationFailure> {
    let mut values = Vec::new();
    for status in context.principal_status_snapshot().statements() {
        values.push(principal_status_id(status.statement()).map_err(codec_failure)?);
    }
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    Ok(values)
}

fn grant_status_records(
    context: &TrustedContext,
) -> Result<Vec<GrantStatusId>, VerificationFailure> {
    let mut values = Vec::new();
    for status in context.grant_status_snapshot().statements() {
        values.push(grant_status_id(status.statement()).map_err(codec_failure)?);
    }
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    Ok(values)
}

fn statement_exists(
    statement: StatementRef,
    grants: &[GrantRecord],
    actions: &[ActionRecord],
    principal_status: &[PrincipalStatusId],
    grant_status: &[GrantStatusId],
) -> bool {
    match statement {
        StatementRef::Grant(id) => grants.binary_search_by_key(&id, |record| record.id).is_ok(),
        StatementRef::Action(id) => actions
            .binary_search_by_key(&id, |record| record.id)
            .is_ok(),
        StatementRef::PrincipalStatus(id) => principal_status.binary_search(&id).is_ok(),
        StatementRef::GrantStatus(id) => grant_status.binary_search(&id).is_ok(),
    }
}

fn resolve_chain(
    bundle: &ProofBundle,
    grants: &[GrantRecord],
    action: &SignedAction,
    used: &mut BTreeSet<GrantId>,
) -> Result<(), VerificationFailure> {
    let mut cursor = action.envelope().terminal_grant();
    let mut branch = BTreeSet::new();
    while let Some(id) = cursor {
        if !branch.insert(id) {
            return Err(VerificationFailure::Denied(DenialReason::ReferenceCycle));
        }
        let position = grants
            .binary_search_by_key(&id, |record| record.id)
            .map_err(|_| VerificationFailure::Denied(DenialReason::MissingReference))?;
        let grant = &bundle.grants()[grants[position].index];
        cursor = grant.statement().parent();
        used.insert(id);
    }
    Ok(())
}

fn reject_duplicate_attachments(bundle: &ProofBundle) -> Result<(), VerificationFailure> {
    if bundle
        .attachments()
        .windows(2)
        .any(|window| window[0].digest() == window[1].digest())
    {
        Err(VerificationFailure::Denied(
            DenialReason::DuplicateAttachment,
        ))
    } else {
        Ok(())
    }
}

fn validate_carried_status(
    bundle: &ProofBundle,
    context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    if bundle.principal_status().iter().any(|carried| {
        context
            .principal_status_snapshot()
            .statements()
            .iter()
            .any(|current| {
                current.statement().principal() == carried.statement().principal()
                    && current.statement().purpose() == carried.statement().purpose()
                    && current.statement().sequence() > carried.statement().sequence()
            })
    }) || bundle.grant_status().iter().any(|carried| {
        context
            .grant_status_snapshot()
            .statements()
            .iter()
            .any(|current| {
                current.statement().grant_id() == carried.statement().grant_id()
                    && current.statement().sequence() > carried.statement().sequence()
            })
    }) {
        return Err(VerificationFailure::Denied(
            DenialReason::StatusSequenceRollback,
        ));
    }
    if bundle.principal_status().iter().any(|carried| {
        !context
            .principal_status_snapshot()
            .statements()
            .contains(carried)
    }) || bundle.grant_status().iter().any(|carried| {
        !context
            .grant_status_snapshot()
            .statements()
            .contains(carried)
    }) {
        Err(VerificationFailure::Denied(DenialReason::DigestMismatch))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_signed(
    statement: StatementRef,
    principal: &PrincipalId,
    signature: &SignatureEnvelope,
    signing_preimage: &[u8],
    purpose: ControlPurpose,
    asserted_signing_time: Timestamp,
    bundle: &ProofBundle,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<VerifiedControl, VerificationFailure> {
    let descriptor = signature.descriptor();
    let result = (|| {
        let method = registries
            .principal_method(context.accepted_registries(), descriptor.principal_method())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedPrincipalMethod,
            ))?;
        let suite = registries
            .signature_suite(context.accepted_registries(), descriptor.suite())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedSignatureSuite,
            ))?;
        let evidence = bound_evidence(bundle, statement)?;
        if evidence.iter().any(|object| {
            !context
                .accepted_registries()
                .accepts_evidence_type(object.evidence_type())
        }) {
            return Err(VerificationFailure::Indeterminate(
                Requirement::UnsupportedEvidenceType,
            ));
        }
        let method_reservation = method.maximum_work_units();
        meter.reserve(method_reservation)?;
        meter.reserve(suite.work_units())?;
        let control = method
            .evaluate_control(
                PrincipalControlInput {
                    principal,
                    verification_method: descriptor.verification_method(),
                    signature_suite: descriptor.suite(),
                    purpose,
                    signing_preimage,
                    asserted_signing_time,
                    evidence: &evidence,
                    evaluation_time: context.evaluation_time(),
                },
                DiagnosticMode::Discard,
            )
            .into_result()
            .map_err(control_failure)?;
        if control.work_units() > method_reservation {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
        suite
            .verify(SignatureInput {
                verification_key: control.verification_key(),
                signing_preimage: control.signature_message().unwrap_or(signing_preimage),
                signature: signature.signature().as_slice(),
            })
            .map_err(signature_failure)?;
        Ok(control)
    })();
    if result
        == Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ))
    {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    Ok(VerifiedControl {
        statement,
        principal: principal.clone(),
        result,
    })
}

fn bound_evidence(
    bundle: &ProofBundle,
    statement: StatementRef,
) -> Result<Vec<&EvidenceObject>, VerificationFailure> {
    let binding = bundle
        .bindings()
        .iter()
        .find(|binding| binding.statement() == statement)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::MissingPrincipalEvidence,
        ))?;
    let mut objects = Vec::with_capacity(binding.evidence().len());
    for id in binding.evidence() {
        objects.push(
            bundle
                .evidence()
                .iter()
                .find(|object| object.id() == *id)
                .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?,
        );
    }
    Ok(objects)
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

fn validate_action_binding(
    controlled: &ControlVerifiedProof,
    canonical: &CanonicalAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let bundle = controlled.resolved.decoded.bundle();
    if bundle
        .canonical_body()
        .is_some_and(|body| body != canonical.body())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::ActionBodyMismatch,
        ));
    }
    let expected_digest = body_digest(canonical.body());
    let first = bundle
        .actions()
        .first()
        .ok_or(VerificationFailure::Denied(
            DenialReason::AuthorizationPlanInvalid,
        ))?
        .envelope();
    for signed in bundle.actions() {
        let action = signed.envelope();
        if action.profile() != canonical.profile()
            || action.body_media_type() != canonical.media_type()
            || action.canonical_body_digest() != expected_digest
            || action.permission() != canonical.permission()
            || action.requested_budget() != canonical.requested_budget()
        {
            return Err(VerificationFailure::Denied(
                DenialReason::ActionBodyMismatch,
            ));
        }
        if !context
            .accepted_registries()
            .accepts_profile(action.profile())
        {
            return Err(VerificationFailure::Indeterminate(
                Requirement::UnsupportedProfile,
            ));
        }
        if action.audience() != context.expected_audience() {
            return Err(VerificationFailure::Denied(DenialReason::AudienceMismatch));
        }
        if action.challenge() != context.expected_challenge() {
            return Err(VerificationFailure::Denied(DenialReason::ChallengeMismatch));
        }
        if !action.validity().contains(context.evaluation_time()) {
            return Err(VerificationFailure::Denied(
                DenialReason::ActionOutsideValidity,
            ));
        }
        if action.channel_binding() != context.channel_policy() {
            return Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied));
        }
        if !same_shared_action(first, action) {
            return Err(VerificationFailure::Denied(
                DenialReason::PlanActionMismatch,
            ));
        }
        evaluate_extensions(action.extensions(), context, registries, meter)?;
    }
    validate_attachments(bundle, canonical, context)?;
    let profile_policy = registries
        .profile_policy(context.accepted_registries(), context.profile_policy())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedProfilePolicy,
        ))?;
    meter.reserve(profile_policy.maximum_work_units(canonical))?;
    match profile_policy
        .evaluate(canonical)
        .map_err(registry_operation_failure)?
    {
        ProfileDecision::Accept => Ok(()),
        ProfileDecision::Deny => Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied)),
    }
}

fn validate_attachments(
    bundle: &ProofBundle,
    canonical: &CanonicalAction,
    context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    let descriptors = bundle
        .actions()
        .first()
        .map(|action| action.envelope().attachments())
        .unwrap_or_default();
    if descriptors != bundle.attachments() {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalAttachment,
        ));
    }
    if descriptors
        .windows(2)
        .any(|window| window[0].digest() == window[1].digest())
        || canonical
            .detached_attachments()
            .windows(2)
            .any(|window| window[0].digest() == window[1].digest())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::DuplicateAttachment,
        ));
    }
    let total = canonical
        .detached_attachments()
        .iter()
        .try_fold(0usize, |total, attachment| {
            total.checked_add(attachment.bytes().len())
        })
        .ok_or(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ))?;
    if total > context.limits().get(auths_model::LimitKind::BundleBytes) {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    for descriptor in descriptors {
        let detached = canonical
            .detached_attachments()
            .iter()
            .find(|attachment| attachment.digest() == descriptor.digest());
        let Some(detached) = detached else {
            if descriptor.required() {
                return Err(VerificationFailure::Denied(DenialReason::AttachmentMissing));
            }
            continue;
        };
        let length = u64::try_from(detached.bytes().len())
            .map_err(|_| VerificationFailure::Denied(DenialReason::AttachmentLengthMismatch))?;
        if length != descriptor.byte_length() {
            return Err(VerificationFailure::Denied(
                DenialReason::AttachmentLengthMismatch,
            ));
        }
        if attachment_digest(detached.bytes()) != descriptor.digest() {
            return Err(VerificationFailure::Denied(
                DenialReason::AttachmentDigestMismatch,
            ));
        }
        if descriptor.encrypted() && !descriptor.opaque_allowed() {
            return Err(VerificationFailure::Denied(
                DenialReason::OpaqueAttachmentNotAllowed,
            ));
        }
    }
    if canonical.detached_attachments().iter().any(|attachment| {
        !descriptors
            .iter()
            .any(|descriptor| descriptor.digest() == attachment.digest())
    }) {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalAttachment,
        ));
    }
    Ok(())
}

fn same_shared_action(
    left: &auths_model::ActionEnvelope,
    right: &auths_model::ActionEnvelope,
) -> bool {
    left.profile() == right.profile()
        && left.body_media_type() == right.body_media_type()
        && left.canonical_body_digest() == right.canonical_body_digest()
        && left.permission() == right.permission()
        && left.requested_budget() == right.requested_budget()
        && left.audience() == right.audience()
        && left.challenge() == right.challenge()
        && left.validity() == right.validity()
        && left.authorization_plan() == right.authorization_plan()
        && left.channel_binding() == right.channel_binding()
        && left.attachments() == right.attachments()
        && left.extensions() == right.extensions()
}

fn verify_branch(
    controlled: &ControlVerifiedProof,
    proof_ref: ProofRef,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<
    (
        ActionId,
        Vec<ParticipantAssurance>,
        Vec<AssuranceSatisfaction>,
    ),
    VerificationFailure,
> {
    let bundle = controlled.resolved.decoded.bundle();
    let action = bundle
        .actions()
        .iter()
        .find(|action| action.envelope().proof_ref() == proof_ref)
        .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
    let action_id = action_id(action.envelope()).map_err(codec_failure)?;
    let chain = branch_chain(&controlled.resolved, action)?;
    let root_principal = chain.first().map_or(action.envelope().actor(), |grant| {
        grant.statement().issuer()
    });
    let root_statement = match chain.first() {
        Some(grant) => StatementRef::Grant(grant_id(grant.statement()).map_err(codec_failure)?),
        None => StatementRef::Action(action_id),
    };
    let root_control = control_for(controlled, root_statement)?;

    let mut first_failure = None;
    for anchor in context
        .trust_anchors()
        .iter()
        .filter(|anchor| anchor.principal() == root_principal)
    {
        match verify_branch_from_anchor(
            controlled,
            action,
            action_id,
            &chain,
            root_control,
            anchor,
            context,
            registries,
            meter,
        ) {
            Ok((reports, satisfactions)) => {
                return Ok((action_id, reports, satisfactions));
            }
            Err(failure) => first_failure.get_or_insert(failure),
        };
    }
    Err(first_failure.unwrap_or(VerificationFailure::Denied(DenialReason::UntrustedRoot)))
}

#[allow(clippy::too_many_arguments)]
fn verify_branch_from_anchor(
    controlled: &ControlVerifiedProof,
    action: &SignedAction,
    action_id: ActionId,
    chain: &[&SignedGrant],
    root_control: (&PrincipalId, &ControlEvidence),
    anchor: &TrustAnchor,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(Vec<ParticipantAssurance>, Vec<AssuranceSatisfaction>), VerificationFailure> {
    if !anchor
        .accepted_methods()
        .contains(action_or_first_method(action, chain))
        || anchor.assurance_policy() != context.assurance_policy().id()
    {
        return Err(VerificationFailure::Denied(DenialReason::UntrustedRoot));
    }
    check_principal_status(
        controlled,
        anchor.status_policy(),
        anchor.principal(),
        context,
        registries,
        meter,
    )?;
    for grant in chain {
        let id = grant_id(grant.statement()).map_err(codec_failure)?;
        check_grant_status(
            controlled,
            grant.statement().status_policy(),
            id,
            context,
            registries,
            meter,
        )?;
    }
    validate_resource_constraints(anchor, chain, action, context, registries, meter)?;
    validate_budget_constraints(anchor, chain, action, context, registries, meter)?;
    let mut authority = EffectiveAuthority::from_anchor(anchor);
    let mut reports = Vec::new();
    if chain.is_empty() {
        reports.push(participant_report(
            root_control.0,
            root_control.1,
            ParticipantRole::Root,
        )?);
    }
    for (index, grant) in chain.iter().enumerate() {
        let id = grant_id(grant.statement()).map_err(codec_failure)?;
        authority
            .delegate(id, grant.statement())
            .map_err(VerificationFailure::Denied)?;
        let control = control_for(controlled, StatementRef::Grant(id))?;
        reports.push(participant_report(
            control.0,
            control.1,
            grant_issuer_role(index),
        )?);
        evaluate_extensions(grant.statement().extensions(), context, registries, meter)?;
    }
    authority
        .authorizes(action.envelope(), context.accepted_registries())
        .map_err(VerificationFailure::Denied)?;
    let action_control = control_for(controlled, StatementRef::Action(action_id))?;
    reports.push(participant_report(
        action_control.0,
        action_control.1,
        ParticipantRole::Actor,
    )?);
    validate_assurance_claims(&reports, context, registries, meter)?;
    let implications = registries.assurance_implications(context.accepted_registries());
    for implication in &implications {
        meter.reserve(implication.maximum_work_units())?;
    }
    let satisfactions = evaluate_with_implications(
        context.assurance_policy(),
        &reports,
        context.evaluation_time(),
        |claim, target| {
            implications.iter().any(|implication| {
                implication.source() == claim.kind()
                    && implication.target() == target
                    && implication.implies(claim).unwrap_or(false)
            })
        },
    )
    .map_err(VerificationFailure::Indeterminate)?;
    Ok((reports, satisfactions))
}

fn action_or_first_method<'a>(
    action: &'a SignedAction,
    chain: &'a [&SignedGrant],
) -> &'a auths_model::PrincipalMethodId {
    chain.first().map_or_else(
        || action.signature().descriptor().principal_method(),
        |grant| grant.signature().descriptor().principal_method(),
    )
}

fn branch_chain<'a>(
    resolved: &'a ResolvedProof,
    action: &SignedAction,
) -> Result<Vec<&'a SignedGrant>, VerificationFailure> {
    let bundle = resolved.decoded.bundle();
    let mut reversed = Vec::new();
    let mut cursor = action.envelope().terminal_grant();
    while let Some(id) = cursor {
        let position = resolved
            .grants
            .binary_search_by_key(&id, |record| record.id)
            .map_err(|_| VerificationFailure::Denied(DenialReason::MissingReference))?;
        let grant = &bundle.grants()[resolved.grants[position].index];
        reversed.push(grant);
        cursor = grant.statement().parent();
    }
    reversed.reverse();
    Ok(reversed)
}

fn control_for(
    controlled: &ControlVerifiedProof,
    statement: StatementRef,
) -> Result<(&PrincipalId, &ControlEvidence), VerificationFailure> {
    let control = controlled
        .controls
        .iter()
        .find(|control| control.statement == statement)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::MissingPrincipalEvidence,
        ))?;
    control
        .result
        .as_ref()
        .map(|evidence| (&control.principal, evidence))
        .map_err(|failure| *failure)
}

fn participant_report(
    principal: &PrincipalId,
    evidence: &ControlEvidence,
    role: ParticipantRole,
) -> Result<ParticipantAssurance, VerificationFailure> {
    ParticipantAssurance::new(
        principal.clone(),
        role,
        evidence.claims().to_vec(),
        evidence.consumed_evidence().to_vec(),
        evidence.adapter().clone(),
        evidence.adapter_version(),
    )
    .map_err(|_| VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))
}

fn evaluate_extensions(
    extensions: &auths_model::CriticalExtensions,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    for extension in extensions.as_slice() {
        if !context
            .accepted_registries()
            .accepts_critical_extension(extension.id())
        {
            return Err(VerificationFailure::Denied(
                DenialReason::CriticalExtensionUnknown,
            ));
        }
        let handler = registries
            .extension_handler(context.accepted_registries(), extension.id())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedCriticalExtension,
            ))?;
        meter.reserve(handler.maximum_work_units(extension))?;
        handler
            .evaluate(extension)
            .map_err(registry_operation_failure)?;
    }
    Ok(())
}

fn check_principal_status(
    controlled: &ControlVerifiedProof,
    policy: &StatusPolicy,
    principal: &PrincipalId,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(());
    };
    let implementation = registries
        .status_method(context.accepted_registries(), method, true)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedStatusMethod,
        ))?;
    for status in context
        .principal_status_snapshot()
        .statements()
        .iter()
        .filter(|status| status.statement().principal() == principal)
    {
        let identifier = principal_status_id(status.statement()).map_err(codec_failure)?;
        control_for(controlled, StatementRef::PrincipalStatus(identifier))?;
    }
    meter.reserve(
        implementation.maximum_work_units(context.principal_status_snapshot().statements().len()),
    )?;
    let decision = implementation
        .principal(
            policy,
            context.principal_status_snapshot(),
            principal,
            context.evaluation_time(),
        )
        .map_err(registry_operation_failure)?;
    status_decision(decision, true)
}

fn check_grant_status(
    controlled: &ControlVerifiedProof,
    policy: &StatusPolicy,
    grant_id: GrantId,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(());
    };
    let implementation = registries
        .status_method(context.accepted_registries(), method, false)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedStatusMethod,
        ))?;
    for status in context
        .grant_status_snapshot()
        .statements()
        .iter()
        .filter(|status| status.statement().grant_id() == grant_id)
    {
        let identifier = grant_status_id(status.statement()).map_err(codec_failure)?;
        control_for(controlled, StatementRef::GrantStatus(identifier))?;
    }
    meter.reserve(
        implementation.maximum_work_units(context.grant_status_snapshot().statements().len()),
    )?;
    let decision = implementation
        .grant(
            policy,
            context.grant_status_snapshot(),
            grant_id,
            context.evaluation_time(),
        )
        .map_err(registry_operation_failure)?;
    status_decision(decision, false)
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

fn validate_resource_constraints(
    anchor: &TrustAnchor,
    chain: &[&SignedGrant],
    action: &SignedAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let matcher = registries
        .resource_matcher(context.accepted_registries(), context.resource_matcher())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedResourceMatcher,
        ))?;
    let resources = chain
        .iter()
        .flat_map(|grant| grant.statement().permissions().as_slice())
        .map(auths_model::Permission::resource)
        .chain(core::iter::once(action.envelope().permission().resource()));
    for resource in resources {
        let mut allowed = false;
        for namespace in anchor.resource_namespaces() {
            meter.reserve(matcher.maximum_work_units(namespace, resource))?;
            allowed |= matcher
                .matches(namespace, resource)
                .map_err(registry_operation_failure)?;
        }
        if !allowed {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceNamespaceMismatch,
            ));
        }
    }
    Ok(())
}

fn validate_budget_constraints(
    anchor: &TrustAnchor,
    chain: &[&SignedGrant],
    action: &SignedAction,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let mut parent = anchor.budget_ceiling();
    for grant in chain {
        let child = grant.statement().budget_ceiling();
        if let Some(parent_budget) = parent {
            let child_budget = child.ok_or(VerificationFailure::Denied(
                DenialReason::DelegationExpanded,
            ))?;
            let algebra = registries
                .budget_algebra(context.accepted_registries(), parent_budget.algebra())
                .ok_or(VerificationFailure::Indeterminate(
                    Requirement::UnsupportedBudgetAlgebra,
                ))?;
            meter.reserve(algebra.maximum_work_units())?;
            if !algebra
                .attenuates(child_budget, parent_budget)
                .map_err(registry_operation_failure)?
            {
                return Err(VerificationFailure::Denied(
                    DenialReason::DelegationExpanded,
                ));
            }
        }
        parent = child;
    }
    if let Some(ceiling) = parent {
        // A bounded terminal authority requires a bounded request *when the
        // action's profile is able to state one*. An action of a profile that
        // could have declared a budget and did not states no bound at all, so
        // there is nothing for the ceiling to bound and it is denied. An action
        // of a profile whose canonical body has no budget field provably spends
        // zero, and zero is within every ceiling.
        let expression = context
            .accepted_registries()
            .profile_budget_expression(action.envelope().profile());
        let Some(requested) = action.envelope().requested_budget() else {
            return match expression {
                ProfileBudgetExpression::Inexpressible => Ok(()),
                ProfileBudgetExpression::Expressible => Err(VerificationFailure::Denied(
                    DenialReason::BudgetCeilingExceeded,
                )),
            };
        };
        let algebra = registries
            .budget_algebra(context.accepted_registries(), ceiling.algebra())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedBudgetAlgebra,
            ))?;
        meter.reserve(algebra.maximum_work_units())?;
        if !algebra
            .covers(ceiling, requested)
            .map_err(registry_operation_failure)?
        {
            return Err(VerificationFailure::Denied(
                DenialReason::BudgetCeilingExceeded,
            ));
        }
    }
    Ok(())
}

fn validate_assurance_claims(
    reports: &[ParticipantAssurance],
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    for claim in reports.iter().flat_map(ParticipantAssurance::claims) {
        let rule = registries
            .assurance_claim(context.accepted_registries(), claim.kind())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedAssuranceClaim,
            ))?;
        meter.reserve(rule.maximum_work_units(claim))?;
        rule.validate(claim).map_err(registry_operation_failure)?;
    }
    Ok(())
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
        RegistryManifestId, ResourceId, SignatureBytes, SignatureDescriptor, SignatureSuiteId,
        SignedAction, StatusSnapshotId, Timestamp, TrustAnchorId, ValidityWindow,
        VerificationMethod, VerifierLimits,
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
            RegistryManifestId::new([0x33; 32]),
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
            bytes: encode_bundle(&bundle).unwrap(),
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
            context.expected_challenge().clone(),
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
        let bytes = auths_codec::encode_verification_result(&result).unwrap();
        assert_eq!(
            auths_codec::decode_verification_result(&bytes).unwrap(),
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
        let context_bytes = auths_codec::encode_verifier_context(&fixture.context).unwrap();

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
        let context_bytes = auths_codec::encode_verifier_context(&fixture.context).unwrap();

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
            auths_codec::encode_verifier_context(&unsupported_context).unwrap();
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
        let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status).unwrap();
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
        let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status).unwrap();
        let ed25519 = Ed25519Suite::new().unwrap();
        let p256 = auths_signature::P256Sha256Suite::new().unwrap();
        let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
            &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
        ];
        let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        for fixture in auths_testkit::corpus() {
            let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
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
}
