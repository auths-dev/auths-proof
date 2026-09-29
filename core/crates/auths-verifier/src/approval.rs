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
use auths_codec::{
    CodecError, approval_digest, approval_requirement_id, approval_signing_preimage, body_digest,
    decode_approval_requirements, principal_status_id,
};
use auths_composition::{ThresholdTruth, evaluate_threshold_counts};
use auths_model::{
    ApprovalCounts, ApprovalDigest, ApprovalOutcome, ApprovalRequirement, ApprovalRequirementId,
    ApprovalSatisfaction, ApprovalStatement, ApprovalVerdict, ApproverAnchor, CanonicalAction,
    DenialReason, MAX_APPROVAL_REQUIREMENTS_PER_CHAIN, MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION,
    PrincipalId, ProofBundle, Requirement, SignedApproval, SignedGrant, StatementRef, StatusPolicy,
    StatusView, TrustedContext, approval_counts, principal_id_equal, principal_ids_contain,
    status_issuer_visible,
};
use auths_ports::{ControlPurpose, StatusDecision};
use auths_registries::{APPROVAL_REQUIREMENT_EXTENSION_V1, ImmutableRegistries};

/// The inputs every approval check reads.
pub(crate) struct Inputs<'a, 'r> {
    pub(crate) controlled: &'a ControlVerifiedProof,
    pub(crate) canonical: &'a CanonicalAction,
    pub(crate) context: &'a TrustedContext,
    pub(crate) registries: &'a ImmutableRegistries<'r>,
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
    let mut requirements: Vec<(ApprovalRequirementId, ApprovalRequirement)> = Vec::new();
    for grant in chain {
        for extension in grant.statement().extensions().as_slice() {
            if extension.id().as_str() != APPROVAL_REQUIREMENT_EXTENSION_V1 {
                continue;
            }
            let decoded =
                decode_approval_requirements(extension.bytes()).map_err(limit_or_malformed)?;
            for requirement in decoded.as_slice() {
                let identifier = approval_requirement_id(requirement).map_err(codec_failure)?;
                if !requirements.iter().any(|(known, _)| *known == identifier) {
                    requirements.push((identifier, requirement.clone()));
                }
            }
        }
    }
    if requirements.len() > MAX_APPROVAL_REQUIREMENTS_PER_CHAIN {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    Ok(requirements)
}

/// Returns the trusted context's requirements in ascending identifier order.
pub(crate) fn context_requirements(
    context: &TrustedContext,
) -> Result<Vec<(ApprovalRequirementId, ApprovalRequirement)>, VerificationFailure> {
    Ok(
        auths_codec::sorted_approval_requirements(context.approval_requirements())
            .map_err(codec_failure)?
            .into_iter()
            .map(|(identifier, requirement)| (identifier, requirement.clone()))
            .collect(),
    )
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

impl<'a> Approvals<'a> {
    /// Removes byte-identical repetitions, orders the approvals by digest, and
    /// collects the authority principals: every grant issuer and subject and
    /// every actor in the proof.
    pub(crate) fn new(bundle: &'a ProofBundle) -> Result<Self, VerificationFailure> {
        let mut candidates = Vec::with_capacity(bundle.approvals().len());
        for approval in bundle.approvals() {
            candidates.push((approval_digest(approval).map_err(codec_failure)?, approval));
        }
        candidates.sort_by_key(|(digest, _)| *digest);
        candidates.dedup_by_key(|(digest, _)| *digest);
        let mut authority: Vec<&PrincipalId> = bundle
            .grants()
            .iter()
            .flat_map(|grant| [grant.statement().issuer(), grant.statement().subject()])
            .chain(
                bundle
                    .actions()
                    .iter()
                    .map(|action| action.envelope().actor()),
            )
            .collect();
        authority.sort();
        authority.dedup();
        Ok(Self {
            candidates,
            authority,
            evaluated: Vec::new(),
        })
    }

    /// Evaluates a list of requirements in order. The first denied requirement
    /// denies; otherwise an indeterminate one makes the list indeterminate.
    pub(crate) fn evaluate_list(
        &mut self,
        requirements: &[(ApprovalRequirementId, ApprovalRequirement)],
        inputs: &Inputs<'_, '_>,
        meter: &mut WorkMeter,
    ) -> Result<(), VerificationFailure> {
        let mut unavailable = false;
        for (identifier, requirement) in requirements {
            match self
                .evaluate(*identifier, requirement, inputs, meter)?
                .verdict
            {
                Verdict::Authorized(_) => {}
                Verdict::Denied => {
                    return Err(VerificationFailure::Denied(
                        DenialReason::ApprovalThresholdNotMet,
                    ));
                }
                Verdict::Indeterminate => unavailable = true,
            }
        }
        if unavailable {
            Err(VerificationFailure::Indeterminate(
                Requirement::ApprovalUnavailable,
            ))
        } else {
            Ok(())
        }
    }

    /// Returns an evaluated requirement.
    pub(crate) fn get(&self, identifier: ApprovalRequirementId) -> Option<&Evaluated> {
        self.evaluated
            .iter()
            .find(|(known, _)| *known == identifier)
            .map(|(_, evaluated)| evaluated)
    }

    /// Returns the satisfaction of every listed requirement that authorized.
    pub(crate) fn satisfactions(
        &self,
        identifiers: &[ApprovalRequirementId],
    ) -> Vec<ApprovalSatisfaction> {
        let mut satisfactions: Vec<ApprovalSatisfaction> = identifiers
            .iter()
            .filter_map(|identifier| match self.get(*identifier) {
                Some(Evaluated {
                    verdict: Verdict::Authorized(satisfaction),
                    ..
                }) => Some(satisfaction.clone()),
                _ => None,
            })
            .collect();
        satisfactions.sort();
        satisfactions.dedup();
        satisfactions
    }

    fn evaluate(
        &mut self,
        identifier: ApprovalRequirementId,
        requirement: &ApprovalRequirement,
        inputs: &Inputs<'_, '_>,
        meter: &mut WorkMeter,
    ) -> Result<Evaluated, VerificationFailure> {
        if let Some(evaluated) = self.get(identifier) {
            return Ok(evaluated.clone());
        }
        if self.evaluated.len() >= MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
        let evaluation_time = inputs.context.evaluation_time();
        let mut outcomes: Vec<ApprovalOutcome> = Vec::new();
        let mut counted = Vec::new();
        for (digest, approval) in &self.candidates {
            let statement = approval.statement();
            let approver = statement.approver();
            if !principal_ids_contain(requirement.approvers(), approver)
                || self.authority.binary_search(&approver).is_ok()
                || outcomes.iter().any(|outcome| {
                    outcome.verdict() == ApprovalVerdict::Counted
                        && principal_id_equal(outcome.approver(), approver)
                })
                || !binds_exact(statement, identifier, inputs.canonical, inputs.context)
                || !statement.validity().contains(evaluation_time)
            {
                continue;
            }
            let Some(anchor) = inputs.context.approver_anchor(approver) else {
                continue;
            };
            if !anchor.validity().contains(evaluation_time)
                || !anchor
                    .accepted_methods()
                    .contains(approval.signature().descriptor().principal_method())
            {
                continue;
            }
            let verdict = match signature_verdict(approval, inputs, meter)? {
                ApprovalVerdict::Counted => status_verdict(anchor, inputs, meter)?,
                other => other,
            };
            if verdict == ApprovalVerdict::Ignored {
                continue;
            }
            if verdict == ApprovalVerdict::Counted {
                counted.push(*digest);
            }
            outcomes.push(ApprovalOutcome::new(approver.clone(), verdict));
        }
        let counts = approval_counts(requirement.approvers(), &outcomes);
        let verdict = match evaluate_threshold_counts(
            requirement.threshold(),
            counts.counted,
            counts.pending,
        ) {
            ThresholdTruth::Authorized => {
                Verdict::Authorized(ApprovalSatisfaction::new(identifier, counted).map_err(
                    |_| VerificationFailure::Denied(DenialReason::ResourceLimitExceeded),
                )?)
            }
            ThresholdTruth::Indeterminate => Verdict::Indeterminate,
            ThresholdTruth::Denied => Verdict::Denied,
        };
        let evaluated = Evaluated {
            verdict,
            counts,
            threshold: requirement.threshold(),
        };
        self.evaluated.push((identifier, evaluated.clone()));
        Ok(evaluated)
    }
}

/// Verifies an approval's signature as stage 3 verifies a proof statement's,
/// with purpose assertion, asserted signing time `not_before`, and the
/// approval's own evidence, which the method must consume exactly.
fn signature_verdict(
    approval: &SignedApproval,
    inputs: &Inputs<'_, '_>,
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
        || Ok(approval.evidence().iter().collect()),
        inputs.context,
        inputs.registries,
        meter,
    ) {
        Ok(control) => {
            let supplied: Vec<_> = approval
                .evidence()
                .iter()
                .map(auths_model::EvidenceObject::id)
                .collect();
            Ok(if control.consumed_evidence() == supplied.as_slice() {
                ApprovalVerdict::Counted
            } else {
                ApprovalVerdict::Ignored
            })
        }
        Err(failure) => classify(failure),
    }
}

/// Checks the approver's principal status as the trust anchor's is checked,
/// except that only issuers visible to an approver take part: those the
/// snapshot does not know, and those whose every rule has scope `any`.
fn status_verdict(
    anchor: &ApproverAnchor,
    inputs: &Inputs<'_, '_>,
    meter: &mut WorkMeter,
) -> Result<ApprovalVerdict, VerificationFailure> {
    let policy = anchor.status_policy();
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(ApprovalVerdict::Counted);
    };
    let context = inputs.context;
    let Some(implementation) =
        inputs
            .registries
            .status_method(context.accepted_registries(), method, true)
    else {
        return Ok(ApprovalVerdict::Pending);
    };
    let principal = anchor.principal();
    let snapshot = context.principal_status_snapshot();
    for status in snapshot.statements().iter().filter(|status| {
        status.statement().principal() == principal
            && status_issuer_visible(
                snapshot.trust(),
                status.statement().issuer(),
                StatusView::Approver,
            )
    }) {
        let identifier = principal_status_id(status.statement()).map_err(codec_failure)?;
        if let Err(failure) =
            control_for(inputs.controlled, StatementRef::PrincipalStatus(identifier))
        {
            return classify(failure);
        }
        if let Err(failure) = check_status_extensions(status.statement().extensions(), context) {
            return classify(failure);
        }
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
        Err(error) => return classify(registry_operation_failure(error)),
    };
    Ok(match decision {
        StatusDecision::Active => ApprovalVerdict::Counted,
        StatusDecision::Missing | StatusDecision::Stale => ApprovalVerdict::Pending,
        StatusDecision::Revoked
        | StatusDecision::Rollback
        | StatusDecision::UntrustedIssuer
        | StatusDecision::WrongMethod => ApprovalVerdict::Ignored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
            &ApprovalRequirements::new(requirements).expect("requirements"),
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
