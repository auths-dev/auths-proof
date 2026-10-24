//! Approval steps: native K-of-N approvals.
//!
//! An approval requirement is "K of these N principals". The trusted
//! context's requirements are evaluated once per request, after the plan
//! authorizes and the composition floors hold; the requirements a grant
//! carries in `approval-requirement-v1` are evaluated for each branch whose
//! chain carries them, after its observation stage. Each requirement counts
//! distinct approvers whose approval is authentic, current, bound to the exact
//! action and to the requirement's identifier, and not from a principal of
//! the proof's authority. An approval that fails any check is ignored, never
//! denying; only limits deny. The verdict is the generated threshold function
//! over the counted and pending approvers.
//!
//! A requirement's verdict depends only on the requirement, the proof, the
//! canonical action, and the trusted context, never on the branch, so each
//! distinct requirement is evaluated at most once per verification.

use crate::{
    ControlVerifiedProof, VerificationFailure, WorkMeter, check_status_extensions, codec_failure,
    control_for, evaluate_signature, registry_operation_failure,
};
use alloc::vec::Vec;
use crate::collections::try_fold_items;
use auths_codec::{
    CodecError, approval_digest, approval_requirement_id, approval_signing_preimage, body_digest,
    decode_approval_requirements, principal_status_id,
};
use auths_composition::{ThresholdTruth, evaluate_threshold_counts};
use auths_model::{
    ApprovalCounts, ApprovalDigest, ApprovalOutcome, ApprovalRequirement, ApprovalRequirementId,
    ApprovalSatisfaction, ApprovalStatement, ApprovalVerdict, ApproverAnchor, CanonicalAction,
    CriticalExtension, EvidenceId, EvidenceObject, SignedPrincipalStatus,
    DenialReason, MAX_APPROVAL_REQUIREMENTS_PER_CHAIN, MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION,
    PrincipalId, ProofBundle, Requirement, SignedApproval, SignedGrant, StatementRef, StatusPolicy,
    StatusView, Timestamp, TrustedContext, approval_counts, principal_id_equal,
    principal_ids_contain, status_issuer_visible,
};
use auths_ports::{ControlPurpose, StatusDecision, StatusMethod as _};
use auths_registries::{APPROVAL_REQUIREMENT_EXTENSION_V1, RegistryAccess};

/// The inputs every approval check reads.
pub(crate) struct Inputs<'a, R: RegistryAccess + ?Sized> {
    pub(crate) controlled: &'a ControlVerifiedProof,
    pub(crate) canonical: &'a CanonicalAction,
    pub(crate) context: &'a TrustedContext,
    pub(crate) registries: &'a R,
}

/// One requirement's evaluated verdict.
#[derive(Clone, Debug)]
pub(crate) enum Verdict {
    Authorized(ApprovalSatisfaction),
    Denied,
    Indeterminate,
}

/// One evaluated requirement: its verdict and its distinct counts.
#[derive(Clone, Debug)]
pub(crate) struct Evaluated {
    pub(crate) verdict: Verdict,
    pub(crate) counts: ApprovalCounts,
    pub(crate) threshold: u16,
    valid_through: Timestamp,
}

/// The proof's approvals, the authority principals, and every requirement
/// evaluated so far.
pub(crate) struct Approvals<'a> {
    candidates: Vec<(ApprovalDigest, &'a SignedApproval)>,
    authority: Vec<&'a PrincipalId>,
    evaluated: Vec<(ApprovalRequirementId, Evaluated)>,
}

fn limit_or_malformed(error: CodecError) -> VerificationFailure {
    if error == CodecError::LimitExceeded {
        VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
    } else {
        VerificationFailure::Denied(DenialReason::MalformedProof)
    }
}

/// Collects the distinct requirements carried by every grant in the chain,
/// root first, in first-appearance order.
pub(crate) fn chain_requirements(
    chain: &[&SignedGrant],
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    let requirements = try_fold_items!(chain, Vec::new(), accumulated, _index, grant =>
        collect_grant_requirements(accumulated, grant))?;
    if requirements.len() > MAX_APPROVAL_REQUIREMENTS_PER_CHAIN {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    Ok(requirements)
}

/// Returns the trusted context's requirements in ascending identifier order.
pub(crate) fn context_requirements(
    context: &TrustedContext,
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    let ordered = auths_codec::sorted_approval_requirements(context.approval_requirements())
        .map_err(|error| codec_failure(error))?;
    let mut output = Vec::with_capacity(ordered.len());
    let mut position = 0;
    while position < ordered.len() {
        output.push((ordered[position].0, ApprovalRequirement::clone(ordered[position].1)));
        position += 1;
    }
    Ok(output)
}

/// Whether an approval binds the requirement and the exact action: its
/// requirement identifier, the canonical action's media type, body digest,
/// permission, requested budget, and (absent) request attributes, and the
/// context's audience and challenge.
fn binds_exact(
    statement: &ApprovalStatement,
    requirement: ApprovalRequirementId,
    canonical: &CanonicalAction,
    context: &TrustedContext,
) -> bool {
    statement.requirement() == requirement
        && statement.media_type() == canonical.media_type()
        && statement.body_digest() == body_digest(canonical.body())
        && statement.permission() == canonical.permission()
        && statement.requested_budget() == canonical.requested_budget()
        && statement.attributes().is_none()
        && statement.audience() == context.expected_audience()
        && statement.challenge() == context.expected_challenge()
}

/// Maps a failure of a check whose refusal ignores an approval: exhaustion
/// stops the verification, a denial ignores the approval, and an unavailable
/// fact makes it pending.
fn classify(failure: VerificationFailure) -> Result<ApprovalVerdict, VerificationFailure> {
    match failure {
        VerificationFailure::Denied(DenialReason::ResourceLimitExceeded) => Err(failure),
        VerificationFailure::Denied(_) => Ok(ApprovalVerdict::Ignored),
        VerificationFailure::Indeterminate(_) => Ok(ApprovalVerdict::Pending),
    }
}

// Each fold step owns its partial value and exposes the original first-error
// result. The aggregate chain bound deliberately remains after collection so
// malformed/limit refusal precedence is not changed by this source reshape.
fn append_requirement(
    mut output: Vec<(ApprovalRequirementId, ApprovalRequirement)>,
    requirement: &ApprovalRequirement,
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    let identifier = approval_requirement_id(requirement).map_err(|error| codec_failure(error))?;
    let mut known = false;
    let mut position = 0;
    while position < output.len() && !known {
        known = output[position].0 == identifier;
        position += 1;
    }
    if !known { output.push((identifier, requirement.clone())); }
    Ok(output)
}

fn collect_extension_requirements(
    output: Vec<(ApprovalRequirementId, ApprovalRequirement)>, extension: &CriticalExtension,
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    if extension.id().as_str() != APPROVAL_REQUIREMENT_EXTENSION_V1 { return Ok(output); }
    let decoded = decode_approval_requirements(extension.bytes()).map_err(|error| limit_or_malformed(error))?;
    try_fold_items!(decoded.as_slice(), output, accumulated, _index, requirement =>
        append_requirement(accumulated, requirement))
}

fn collect_grant_requirements(
    output: Vec<(ApprovalRequirementId, ApprovalRequirement)>, grant: &SignedGrant,
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    try_fold_items!(grant.statement().extensions().as_slice(), output, accumulated, _index, extension =>
        collect_extension_requirements(accumulated, extension))
}

fn index_approval(
    mut keys: Vec<(ApprovalDigest, usize)>, index: usize, approval: &SignedApproval,
) -> Result<Vec<(ApprovalDigest, usize)>, VerificationFailure> {
    keys.push((approval_digest(approval).map_err(|error| codec_failure(error))?, index));
    Ok(keys)
}

struct ApprovalTally {
    outcomes: Vec<ApprovalOutcome>,
    counted: Vec<ApprovalDigest>,
    valid_through: Timestamp,
}
impl ApprovalTally {
    const fn empty() -> Self {
        Self { outcomes: Vec::new(), counted: Vec::new(), valid_through: Timestamp::new(u64::MAX) }
    }
}

fn already_counted(outcomes: &[ApprovalOutcome], approver: &PrincipalId) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < outcomes.len() && !found {
        found = outcomes[position].verdict() == ApprovalVerdict::Counted
            && principal_id_equal(outcomes[position].approver(), approver);
        position += 1;
    }
    found
}

#[allow(clippy::too_many_arguments)]
fn evaluate_candidate<R: RegistryAccess + ?Sized>(
    mut tally: ApprovalTally, digest: ApprovalDigest, approval: &SignedApproval,
    identifier: ApprovalRequirementId, requirement: &ApprovalRequirement,
    authority: &[&PrincipalId], inputs: &Inputs<'_, R>, meter: &mut WorkMeter,
) -> Result<ApprovalTally, VerificationFailure> {
    let statement = approval.statement();
    let approver = statement.approver();
    let evaluation_time = inputs.context.evaluation_time();
    if !principal_ids_contain(requirement.approvers(), approver)
        || authority.binary_search(&approver).is_ok()
        || already_counted(&tally.outcomes, approver)
        || !binds_exact(statement, identifier, inputs.canonical, inputs.context)
        || !statement.validity().contains(evaluation_time)
    { return Ok(tally); }
    let Some(anchor) = inputs.context.approver_anchor(approver) else { return Ok(tally); };
    if !anchor.validity().contains(evaluation_time)
        || !anchor.accepted_methods().contains(approval.signature().descriptor().principal_method())
    { return Ok(tally); }
    let (verdict, status_not_after) = match signature_verdict(approval, inputs, meter)? {
        ApprovalVerdict::Counted => status_verdict(anchor, inputs, meter)?,
        other => (other, evaluation_time),
    };
    if verdict == ApprovalVerdict::Ignored { return Ok(tally); }
    if verdict == ApprovalVerdict::Counted {
        tally.counted.push(digest);
        tally.valid_through = tally.valid_through.min(statement.validity().expires_at())
            .min(anchor.validity().expires_at()).min(status_not_after);
    }
    tally.outcomes.push(ApprovalOutcome::new(approver.clone(), verdict));
    Ok(tally)
}

fn borrowed_evidence(evidence: &[EvidenceObject]) -> Vec<&EvidenceObject> {
    let mut output = Vec::with_capacity(evidence.len());
    let mut position = 0;
    while position < evidence.len() { output.push(&evidence[position]); position += 1; }
    output
}

fn evidence_identifiers(evidence: &[EvidenceObject]) -> Vec<EvidenceId> {
    let mut output = Vec::with_capacity(evidence.len());
    let mut position = 0;
    while position < evidence.len() { output.push(evidence[position].id()); position += 1; }
    output
}

impl<'a> Approvals<'a> {
    /// Removes byte-identical repetitions, orders the approvals by digest, and
    /// collects the authority principals: every grant issuer and subject and
    /// every actor in the proof.
    pub(crate) fn new(bundle: &'a ProofBundle) -> Result<Self, VerificationFailure> {
        let mut indexed = try_fold_items!(bundle.approvals(), Vec::new(), keys, index, approval =>
            index_approval(keys, index, approval))?;
        // The original stable digest sort kept the first occurrence. An index
        // tie-break preserves that representative without a comparison callback.
        indexed.sort();
        let mut candidates: Vec<(ApprovalDigest, &'a SignedApproval)> = Vec::with_capacity(indexed.len());
        let mut position = 0;
        while position < indexed.len() {
            let (digest, index) = indexed[position];
            let distinct = match candidates.last() {
                None => true,
                Some((known, _)) => *known != digest,
            };
            if distinct { candidates.push((digest, &bundle.approvals()[index])); }
            position += 1;
        }
        let mut authority = Vec::new();
        let mut position = 0;
        while position < bundle.grants().len() {
            let statement = bundle.grants()[position].statement();
            authority.push(statement.issuer());
            authority.push(statement.subject());
            position += 1;
        }
        let mut position = 0;
        while position < bundle.actions().len() {
            authority.push(bundle.actions()[position].envelope().actor());
            position += 1;
        }
        authority.sort();
        authority.dedup();
        Ok(Self { candidates, authority, evaluated: Vec::new() })
    }

    /// Evaluates a list of requirements in order. The first denied requirement
    /// denies; otherwise an indeterminate one makes the list indeterminate.
    pub(crate) fn evaluate_list<R: RegistryAccess + ?Sized>(
        &mut self,
        requirements: &[(ApprovalRequirementId, ApprovalRequirement)],
        inputs: &Inputs<'_, R>,
        meter: &mut WorkMeter,
    ) -> Result<(), VerificationFailure> {
        let unavailable = try_fold_items!(requirements, false, unavailable, _index, (identifier, requirement) =>
            self.evaluate_requirement_in_list(unavailable, *identifier, requirement, inputs, meter))?;
        if unavailable {
            Err(VerificationFailure::Indeterminate(Requirement::ApprovalUnavailable))
        } else { Ok(()) }
    }

    /// Returns an evaluated requirement.
    pub(crate) fn get(&self, identifier: ApprovalRequirementId) -> Option<&Evaluated> {
        let mut position = 0;
        while position < self.evaluated.len() {
            if self.evaluated[position].0 == identifier { return Some(&self.evaluated[position].1); }
            position += 1;
        }
        None
    }

    /// Returns the satisfaction of every listed requirement that authorized.
    pub(crate) fn satisfactions(&self, identifiers: &[ApprovalRequirementId]) -> Vec<ApprovalSatisfaction> {
        let mut output = Vec::new();
        let mut position = 0;
        while position < identifiers.len() {
            if let Some(Evaluated { verdict: Verdict::Authorized(satisfaction), .. }) = self.get(identifiers[position]) {
                output.push(satisfaction.clone());
            }
            position += 1;
        }
        output.sort();
        output.dedup();
        output
    }

    /// Horizon of only the requirements belonging to successful branches or
    /// the context. Cached requirements from failed alternative branches do
    /// not shorten the selected witness.
    pub(crate) fn valid_through(&self, identifiers: &[ApprovalRequirementId]) -> Timestamp {
        let mut horizon = Timestamp::new(u64::MAX);
        let mut position = 0;
        while position < identifiers.len() {
            if let Some(evaluated) = self.get(identifiers[position])
                && matches!(evaluated.verdict, Verdict::Authorized(_))
            { horizon = horizon.min(evaluated.valid_through); }
            position += 1;
        }
        horizon
    }

    fn evaluate<R: RegistryAccess + ?Sized>(
        &mut self,
        identifier: ApprovalRequirementId,
        requirement: &ApprovalRequirement,
        inputs: &Inputs<'_, R>,
        meter: &mut WorkMeter,
    ) -> Result<Evaluated, VerificationFailure> {
        if let Some(evaluated) = self.get(identifier) { return Ok(evaluated.clone()); }
        if self.evaluated.len() >= MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION {
            return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
        }
        let tally = try_fold_items!(&self.candidates, ApprovalTally::empty(), tally, _index, (digest, approval) =>
            evaluate_candidate(tally, *digest, approval, identifier, requirement, &self.authority, inputs, meter))?;
        let counts = approval_counts(requirement.approvers(), &tally.outcomes);
        let verdict = match evaluate_threshold_counts(requirement.threshold(), counts.counted, counts.pending) {
            ThresholdTruth::Authorized => Verdict::Authorized(
                ApprovalSatisfaction::new(identifier, tally.counted)
                    .map_err(|_| VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))?),
            ThresholdTruth::Indeterminate => Verdict::Indeterminate,
            ThresholdTruth::Denied => Verdict::Denied,
        };
        let evaluated = Evaluated { verdict, counts, threshold: requirement.threshold(), valid_through: tally.valid_through };
        self.evaluated.push((identifier, evaluated.clone()));
        Ok(evaluated)
    }

    fn evaluate_requirement_in_list<R: RegistryAccess + ?Sized>(
        &mut self, unavailable: bool, identifier: ApprovalRequirementId,
        requirement: &ApprovalRequirement, inputs: &Inputs<'_, R>, meter: &mut WorkMeter,
    ) -> Result<bool, VerificationFailure> {
        match self.evaluate(identifier, requirement, inputs, meter)?.verdict {
            Verdict::Authorized(_) => Ok(unavailable),
            Verdict::Indeterminate => Ok(true),
            Verdict::Denied => Err(VerificationFailure::Denied(DenialReason::ApprovalThresholdNotMet)),
        }
    }
}

/// Verifies an approval's signature as stage 3 verifies a proof statement's,
/// with purpose assertion, asserted signing time `not_before`, and the
/// approval's own evidence, which the method must consume exactly.
fn signature_verdict<R: RegistryAccess + ?Sized>(
    approval: &SignedApproval,
    inputs: &Inputs<'_, R>,
    meter: &mut WorkMeter,
) -> Result<ApprovalVerdict, VerificationFailure> {
    let statement = approval.statement();
    let Ok(preimage) = approval_signing_preimage(
        statement,
        approval.signature().descriptor(),
        inputs.canonical.profile(),
    ) else {
        return Ok(ApprovalVerdict::Ignored);
    };
    match evaluate_signature(
        statement.approver(),
        approval.signature(),
        &preimage,
        ControlPurpose::Assertion,
        statement.validity().not_before(),
        || Ok(borrowed_evidence(approval.evidence())),
        inputs.context,
        inputs.registries,
        meter,
    ) {
        Ok(control) => {
            let supplied = evidence_identifiers(approval.evidence());
            Ok(if control.consumed_evidence() == supplied.as_slice() {
                ApprovalVerdict::Counted
            } else {
                ApprovalVerdict::Ignored
            })
        }
        Err(failure) => classify(failure),
    }
}

// None means every relevant supplied attestation was authentic and accepted.
// Some preserves the first unavailable/invalid fact as the approval's verdict;
// resource exhaustion remains a request-level failure rather than an ignore.
fn check_status_attestation<R: RegistryAccess + ?Sized>(
    status: &SignedPrincipalStatus, principal: &PrincipalId, inputs: &Inputs<'_, R>,
) -> Result<Option<ApprovalVerdict>, VerificationFailure> {
    if status.statement().principal() != principal
        || !status_issuer_visible(inputs.context.principal_status_snapshot().trust(),
            status.statement().issuer(), StatusView::Approver)
    { return Ok(None); }
    let identifier = principal_status_id(status.statement()).map_err(|error| codec_failure(error))?;
    if let Err(failure) = control_for(inputs.controlled, StatementRef::PrincipalStatus(identifier)) {
        return classify(failure).map(|verdict| Some(verdict));
    }
    if let Err(failure) = check_status_extensions(status.statement().extensions(), inputs.context) {
        return classify(failure).map(|verdict| Some(verdict));
    }
    Ok(None)
}

fn check_status_attestations<R: RegistryAccess + ?Sized>(
    statements: &[SignedPrincipalStatus], principal: &PrincipalId, inputs: &Inputs<'_, R>,
) -> Result<Option<ApprovalVerdict>, VerificationFailure> {
    let mut outcome = Ok(None);
    let mut position = 0;
    while position < statements.len() && matches!(outcome, Ok(None)) {
        outcome = check_status_attestation(&statements[position], principal, inputs);
        position += 1;
    }
    outcome
}

/// Checks the approver's principal status as the trust anchor's is checked,
/// except that only issuers visible to an approver take part: those the
/// snapshot does not know, and those whose every rule has scope `any`.
fn status_verdict<R: RegistryAccess + ?Sized>(
    anchor: &ApproverAnchor,
    inputs: &Inputs<'_, R>,
    meter: &mut WorkMeter,
) -> Result<(ApprovalVerdict, Timestamp), VerificationFailure> {
    let policy = anchor.status_policy();
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok((ApprovalVerdict::Counted, Timestamp::new(u64::MAX)));
    };
    let context = inputs.context;
    let Some(implementation) =
        inputs
            .registries
            .status_method(context.accepted_registries(), method, true)
    else {
        return Ok((ApprovalVerdict::Pending, context.evaluation_time()));
    };
    let principal = anchor.principal();
    let snapshot = context.principal_status_snapshot();
    if let Some(verdict) = check_status_attestations(snapshot.statements(), principal, inputs)? {
        return Ok((verdict, context.evaluation_time()));
    }
    meter.reserve(implementation.maximum_work_units(snapshot.statements().len()))?;
    let decision = match implementation.principal(
        policy,
        snapshot,
        principal,
        StatusView::Approver,
        context.evaluation_time(),
    ) {
        Ok(decision) => decision,
        Err(error) => {
            return classify(registry_operation_failure(error))
                .map(|verdict| (verdict, context.evaluation_time()));
        }
    };
    if decision.decision() == StatusDecision::Active
        && decision.valid_through() < context.evaluation_time()
    {
        return Ok((ApprovalVerdict::Pending, context.evaluation_time()));
    }
    Ok((
        match decision.decision() {
            StatusDecision::Active => ApprovalVerdict::Counted,
            StatusDecision::Missing | StatusDecision::Stale => ApprovalVerdict::Pending,
            StatusDecision::Revoked
            | StatusDecision::Rollback
            | StatusDecision::UntrustedIssuer
            | StatusDecision::WrongMethod => ApprovalVerdict::Ignored,
        },
        decision.valid_through(),
    ))
}

#[cfg(test)]
#[path = "approval_reference.rs"]
mod reference;
#[cfg(test)]
#[path = "approval_parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_registries::ImmutableRegistries;
    use alloc::{format, vec};
    use auths_model::{
        ApprovalRequirements, CriticalExtension, CriticalExtensions, ExtensionId, GrantStatement,
        VerifierLimits,
    };

    fn principal(index: usize) -> PrincipalId {
        PrincipalId::parse(&format!("test:approver-{index:02}")).expect("principal")
    }

    /// A grant carrying `count` distinct requirements, each two of a pair of
    /// principals starting at `first`.
    fn grant_with_requirements(template: &SignedGrant, first: usize, count: usize) -> SignedGrant {
        let requirements = (first..first + count)
            .map(|index| {
                ApprovalRequirement::new(vec![principal(index), principal(index + 1)], 2)
                    .expect("requirement")
            })
            .collect();
        let bytes = auths_codec::encode_approval_requirements(
            &auths_codec::CanonicalApprovalRequirements::new(
                ApprovalRequirements::new(requirements).expect("requirements"),
            ).expect("canonical requirement value"),
        )
        .expect("canonical requirements");
        let statement = template.statement();
        SignedGrant::new(
            GrantStatement::new(
                statement.issuer().clone(),
                statement.subject().clone(),
                statement.profile().clone(),
                statement.permissions().clone(),
                statement.validity(),
                statement.audiences().clone(),
                statement.action_constraint().clone(),
                statement.budget_ceiling().cloned(),
                statement.remaining_depth(),
                statement.parent(),
                statement.status_policy().clone(),
                statement.assurance_floor().clone(),
                CriticalExtensions::new(vec![
                    CriticalExtension::new(
                        ExtensionId::parse(APPROVAL_REQUIREMENT_EXTENSION_V1)
                            .expect("extension id"),
                        bytes,
                    )
                    .expect("extension"),
                ])
                .expect("extensions"),
            ),
            template.signature().clone(),
        )
    }

    /// Delegates may add requirements, so a chain can carry more distinct
    /// requirements than one grant: 16 is accepted and 17 is a resource-limit
    /// denial.
    #[test]
    fn chain_requirement_bound_is_exact() {
        let fixture = auths_testkit::corpus()
            .into_iter()
            .find(|fixture| fixture.name() == "approval-grant-2-of-3")
            .expect("corpus fixture");
        let bundle = auths_codec::decode_bundle(fixture.proof_bytes(), &VerifierLimits::default())
            .expect("fixture proof");
        let template = &bundle.grants()[0];
        let at_limit: Vec<SignedGrant> = (0..4)
            .map(|grant| grant_with_requirements(template, grant * 4, 4))
            .collect();
        let references: Vec<&SignedGrant> = at_limit.iter().collect();
        assert_eq!(chain_requirements(&references).map(|all| all.len()), Ok(16));

        let mut over = at_limit;
        over.push(grant_with_requirements(template, 16, 1));
        let references: Vec<&SignedGrant> = over.iter().collect();
        assert_eq!(
            chain_requirements(&references).map(|all| all.len()),
            Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded
            ))
        );
    }
}
