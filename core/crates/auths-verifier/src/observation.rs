//! Observation stage: evidence-conditioned authority.
//!
//! Runs for one authorization-plan branch after its authority is
//! established. Every observation requirement carried by a grant in the
//! branch's chain must be met by an attached observation that is authentic,
//! from the anchored observer, about the exact subject inside the anchor's
//! namespaces, fresh at the evaluation time, and satisfies every condition.
//! A requirement with eligible observations that all falsify a condition is
//! denied; a requirement with no eligible observation, or whose action facts
//! the profile cannot supply, is indeterminate. Denial dominates.

use crate::{VerificationFailure, WorkMeter, registry_operation_failure};
use alloc::vec::Vec;
use crate::collections::try_fold_items;
use auths_codec::{CodecError, decode_observation_requirements, decode_signed_observation};
use auths_model::{
    AttachmentDigest, CanonicalAction, DenialReason, FactValue, MAX_OBSERVATION_ATTACHMENTS,
    MAX_OBSERVATION_BYTES, MAX_OBSERVATION_REQUIREMENTS_PER_CHAIN, OBSERVATION_MEDIA_TYPE,
    ObservationRequirement, ObservationSatisfaction, ObservationSubject, ObserverAnchor,
    PrincipalId, Requirement, RequirementVerdict, ResourceId, SignedAction, SignedGrant,
    AttachmentDescriptor, DetachedAttachment, CriticalExtension, EvidenceObject, EvidenceId, FactName,
    ObservationCondition,
    SignedObservation, Timestamp, TrustedContext, observation_conditions_hold, observation_fresh,
    observation_schema_equal, observation_subject_equal, principal_id_equal,
    requirement_subject_equal, requirement_verdict,
};
use auths_ports::{
    ControlPurpose, PrincipalControlInput, PrincipalControlError, ProfilePolicy, ResourceMatcher, SignatureInput,
    PrincipalMethod as _, SignatureSuite as _,
    diagnostics::DiagnosticMode,
};
use auths_registries::{RegistryAccess, OBSERVATION_REQUIREMENT_EXTENSION_V1};

/// One decoded observation attachment and its lazily established
/// authenticity.
struct Candidate {
    digest: AttachmentDigest,
    observation: SignedObservation,
    authentic: Option<bool>,
}

/// The exact selected observation and its inclusive freshness endpoint.
struct Satisfied {
    record: ObservationSatisfaction,
    valid_through: Timestamp,
}

/// Shared inputs of one branch's observation stage.
pub(crate) struct Stage<'a, R: RegistryAccess + ?Sized> {
    pub(crate) chain: &'a [&'a SignedGrant],
    pub(crate) root: &'a PrincipalId,
    pub(crate) action: &'a SignedAction,
    pub(crate) canonical: &'a CanonicalAction,
    pub(crate) context: &'a TrustedContext,
    pub(crate) registries: &'a R,
}

fn limit_or_malformed(error: CodecError) -> VerificationFailure {
    if error == CodecError::LimitExceeded {
        VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)
    } else {
        VerificationFailure::Denied(DenialReason::MalformedProof)
    }
}

/// Rejects an action whose signed observation attachments exceed the count
/// or per-attachment byte bound. Runs for every action, before authority.
pub(crate) fn validate_observation_attachments(action: &SignedAction) -> Result<(), VerificationFailure> {
    let _ = try_fold_items!(action.envelope().attachments(), 0usize, count, _position, descriptor =>
        count_observation_descriptor(count, descriptor))?;
    Ok(())
}

/// Collects the distinct requirements carried by every grant in the chain,
/// in first-appearance order.
pub(crate) fn chain_requirements(chain: &[&SignedGrant]) -> Result<Vec<ObservationRequirement>, VerificationFailure> {
    let requirements = try_fold_items!(chain, Vec::new(), accumulated, _position, grant =>
        collect_grant_requirements(accumulated, grant))?;
    if requirements.len() > MAX_OBSERVATION_REQUIREMENTS_PER_CHAIN {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    Ok(requirements)
}

/// Denies a child grant that drops a parent's observation requirement: no
/// child requirement addresses it with the same schema and subject. A child
/// requirement that addresses it without keeping or narrowing it falls
/// through to the authority kernel, whose extension law denies the edge as
/// expanded.
pub(crate) fn require_parent_requirements(parent: &SignedGrant, child: &SignedGrant) -> Result<(), VerificationFailure> {
    let parents = chain_requirements(&[parent])?;
    if parents.is_empty() { return Ok(()); }
    // Preserve the established refusal order: malformed child requirements
    // address no parent, while the enclosing extension/authority checks still
    // reject their payload. A malformed parent is propagated above.
    let children = chain_requirements(&[child]).unwrap_or_default();
    if every_parent_addressed(&parents, &children) { Ok(()) }
    else { Err(VerificationFailure::Denied(DenialReason::ObservationRequirementDropped)) }
}

impl<R: RegistryAccess + ?Sized> Stage<'_, R> {
    /// Evaluates every requirement in the chain and returns the observation
    /// that satisfied each one.
    pub(crate) fn evaluate(&self, meter: &mut WorkMeter)
    -> Result<(Vec<ObservationSatisfaction>, Timestamp), VerificationFailure> {
        let requirements = chain_requirements(self.chain)?;
        if requirements.is_empty() { return Ok((Vec::new(), Timestamp::new(u64::MAX))); }
        // All observer/authority-separation checks precede attachment decoding.
        let anchors = try_fold_items!(&requirements, Vec::with_capacity(requirements.len()), anchors, _position, requirement =>
            self.append_anchor(anchors, requirement))?;
        let mut candidates = self.candidates()?;
        let initial = ObservationTally { satisfactions: Vec::with_capacity(requirements.len()), unavailable: None,
            valid_through: Timestamp::new(u64::MAX) };
        let tally = try_fold_items!(&requirements, initial, tally, position, requirement =>
            self.evaluate_requirement(tally, requirement, anchor_at(&anchors, position), &mut candidates, meter))?;
        match tally.unavailable {
            Some(failure) => Err(failure),
            None => Ok((tally.satisfactions, tally.valid_through)),
        }
    }

    fn in_authority_chain(&self, principal: &PrincipalId) -> bool {
        principal_id_equal(principal, self.root)
            || principal_id_equal(principal, self.action.envelope().actor())
            || chain_contains_principal(self.chain, principal)
    }

    fn candidates(&self) -> Result<Vec<Candidate>, VerificationFailure> {
        let mut candidates = try_fold_items!(self.action.envelope().attachments(), Vec::new(), candidates, _position, descriptor =>
            self.append_candidate(candidates, descriptor))?;
        candidates.sort();
        Ok(candidates)
    }

    /// The outer `Result` carries failures that stop the whole stage; the
    /// inner one is this requirement's own verdict.
    fn requirement(
        &self,
        requirement: &ObservationRequirement,
        anchor: Option<&ObserverAnchor>,
        candidates: &mut [Candidate],
        meter: &mut WorkMeter,
    ) -> Result<Result<Satisfied, VerificationFailure>, VerificationFailure> {
        let Some(anchor) = anchor else {
            return Ok(Err(VerificationFailure::Indeterminate(
                Requirement::ObservationMissing,
            )));
        };
        let policy = self
            .registries
            .profile_policy(
                self.context.accepted_registries(),
                self.context.profile_policy(),
            )
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedProfilePolicy,
            ))?;
        let Some((subject, action_values)) = self.action_facts(requirement, policy, meter)? else {
            return Ok(Err(VerificationFailure::Indeterminate(
                Requirement::ObservationActionFactUnavailable,
            )));
        };
        let conditions = u64::try_from(requirement.conditions().len()).unwrap_or(u64::MAX);
        let observations = u64::try_from(candidates.len()).unwrap_or(u64::MAX);
        meter.reserve(conditions.saturating_mul(observations).saturating_add(1))?;
        let scan = self.scan_candidates(requirement, anchor, &subject, &action_values, candidates, meter)?;
        let any_eligible = scan.any_eligible;
        let satisfying = scan.satisfying;
        let verdict = requirement_verdict(any_eligible, satisfying.is_some());
        Ok(match (verdict, satisfying) {
            (RequirementVerdict::Satisfied, Some((digest, valid_through))) => {
                let id = auths_codec::observation_requirement_id(requirement)
                    .map_err(|error| limit_or_malformed(error))?;
                Ok(Satisfied {
                    record: ObservationSatisfaction::new(id, digest),
                    valid_through,
                })
            }
            (RequirementVerdict::ConditionFalse, _) => Err(VerificationFailure::Denied(
                DenialReason::ObservationConditionFalse,
            )),
            _ => Err(VerificationFailure::Indeterminate(
                Requirement::ObservationMissing,
            )),
        })
    }

    /// Resolves the requirement's subject and each condition's action fact.
    /// `None` means the profile cannot supply a value the requirement needs.
    #[allow(
        clippy::type_complexity,
        reason = "the pair is the resolved subject and one action value per condition"
    )]
    fn action_facts<P: ProfilePolicy + ?Sized>(&self, requirement: &ObservationRequirement, policy: &P, meter: &mut WorkMeter)
    -> Result<Option<(ResourceId, Vec<Option<FactValue>>)>, VerificationFailure> {
        let subject = match requirement.subject() {
            ObservationSubject::Resource(resource) => resource.clone(),
            ObservationSubject::ActionFact(name) => match self.resolve_action_fact(policy, name, meter)? {
                Some(FactValue::Text(text)) => match ResourceId::parse(text.as_str()) {
                    Ok(resource) => resource, Err(_) => return Ok(None),
                },
                _ => return Ok(None),
            },
        };
        let values = self.gather_action_values(requirement.conditions(), policy, meter)?;
        Ok(values.map(|values| (subject, values)))
    }

    fn eligible(
        &self,
        requirement: &ObservationRequirement,
        anchor: &ObserverAnchor,
        subject: &ResourceId,
        candidate: &mut Candidate,
        meter: &mut WorkMeter,
    ) -> Result<bool, VerificationFailure> {
        let statement = candidate.observation.statement();
        if !principal_id_equal(statement.observer(), anchor.principal())
            || statement.schema() != requirement.schema()
            || !anchor.schemas().contains(requirement.schema())
            || !observation_subject_equal(subject, statement.subject())
            || !observation_fresh(
                statement.observed_at().get(),
                self.context.evaluation_time().get(),
                u64::from(requirement.max_age_seconds()),
                anchor.validity().not_before().get(),
                anchor.validity().expires_at().get(),
            )
            || !anchor.accepted_methods().contains(
                candidate
                    .observation
                    .signature()
                    .descriptor()
                    .principal_method(),
            )
            || !self.subject_in_namespaces(anchor, statement.subject(), meter)?
        {
            return Ok(false);
        }
        if let Some(authentic) = candidate.authentic {
            return Ok(authentic);
        }
        let authentic = self.authentic(&candidate.observation, meter)?;
        candidate.authentic = Some(authentic);
        Ok(authentic)
    }

    fn subject_in_namespaces(&self, anchor: &ObserverAnchor, subject: &ResourceId, meter: &mut WorkMeter)
    -> Result<bool, VerificationFailure> {
        let matcher = self.registries.resource_matcher(self.context.accepted_registries(), self.context.resource_matcher())
            .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedResourceMatcher))?;
        let mut outcome = Ok(false);
        let mut position = 0;
        while position < anchor.subject_namespaces().len() && matches!(&outcome, Ok(false)) {
            outcome = match_namespace(&anchor.subject_namespaces()[position], subject, matcher, meter);
            position += 1;
        }
        outcome
    }

    /// Verifies the observer's signature with the same principal-method and
    /// signature-suite registry used for every other signed statement. Any
    /// failure other than resource exhaustion makes the observation ignored.
    fn authentic(
        &self,
        observation: &SignedObservation,
        meter: &mut WorkMeter,
    ) -> Result<bool, VerificationFailure> {
        let descriptor = observation.signature().descriptor();
        let accepted = self.context.accepted_registries();
        let (Some(method), Some(suite)) = (
            self.registries
                .principal_method(accepted, descriptor.principal_method()),
            self.registries
                .signature_suite(accepted, descriptor.suite()),
        ) else {
            return Ok(false);
        };
        if !evidence_accepted(observation.evidence(), accepted) { return Ok(false); }
        let reservation = method.maximum_work_units();
        meter.reserve(reservation)?;
        meter.reserve(suite.work_units())?;
        let statement = observation.statement();
        let Ok(preimage) = auths_codec::observation_signing_preimage(statement, descriptor) else {
            return Ok(false);
        };
        let evidence = borrowed_evidence(observation.evidence());
        let evaluated = method
            .evaluate_control(
                PrincipalControlInput {
                    principal: statement.observer(),
                    verification_method: descriptor.verification_method(),
                    signature_suite: descriptor.suite(),
                    purpose: ControlPurpose::Assertion,
                    signing_preimage: &preimage,
                    signature: observation.signature().signature().as_slice(),
                    asserted_signing_time: statement.observed_at(),
                    evidence: &evidence,
                    evaluation_time: self.context.evaluation_time(),
                },
                DiagnosticMode::Discard,
            )
            .into_result();
        let Some(control) = control_result(evaluated)? else { return Ok(false); };
        if control.work_units() > reservation {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
        let supplied = evidence_identifiers(observation.evidence());
        if control.consumed_evidence() != supplied.as_slice() {
            return Ok(false);
        }
        Ok(suite
            .verify(SignatureInput {
                verification_key: control.verification_key(),
                signing_preimage: control.signature_message().unwrap_or(&preimage),
                signature: observation.signature().signature().as_slice(),
            })
            .is_ok())
    }
}

// Candidate equality/order is its stable sort key only. No candidate is
// deduplicated or authenticated by this comparison; signature checks use the
// complete observation and evidence below.
impl PartialEq for Candidate { fn eq(&self, other: &Self) -> bool { self.digest == other.digest } }
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}
impl Ord for Candidate { fn cmp(&self, other: &Self) -> core::cmp::Ordering { self.digest.cmp(&other.digest) } }

struct ObservationTally {
    satisfactions: Vec<ObservationSatisfaction>,
    unavailable: Option<VerificationFailure>,
    valid_through: Timestamp,
}
struct CandidateScan {
    any_eligible: bool,
    satisfying: Option<(AttachmentDigest, Timestamp)>,
}

fn count_observation_descriptor(count: usize, descriptor: &AttachmentDescriptor) -> Result<usize, VerificationFailure> {
    if descriptor.media_type().as_str() != OBSERVATION_MEDIA_TYPE { return Ok(count); }
    let next = count.checked_add(1).ok_or(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))?;
    let oversized = match usize::try_from(descriptor.byte_length()) {
        Ok(length) => length > MAX_OBSERVATION_BYTES,
        Err(_) => true,
    };
    if next > MAX_OBSERVATION_ATTACHMENTS || oversized {
        Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))
    } else { Ok(next) }
}
fn append_requirement(mut requirements: Vec<ObservationRequirement>, requirement: &ObservationRequirement) -> Vec<ObservationRequirement> {
    if !requirements.contains(requirement) { requirements.push(requirement.clone()); }
    requirements
}
fn collect_extension_requirements(requirements: Vec<ObservationRequirement>, extension: &CriticalExtension)
-> Result<Vec<ObservationRequirement>, VerificationFailure> {
    if extension.id().as_str() != OBSERVATION_REQUIREMENT_EXTENSION_V1 { return Ok(requirements); }
    let decoded = decode_observation_requirements(extension.bytes()).map_err(|error| limit_or_malformed(error))?;
    let mut output = requirements;
    let mut position = 0;
    while position < decoded.as_slice().len() {
        output = append_requirement(output, &decoded.as_slice()[position]);
        position += 1;
    }
    Ok(output)
}
fn collect_grant_requirements(requirements: Vec<ObservationRequirement>, grant: &SignedGrant)
-> Result<Vec<ObservationRequirement>, VerificationFailure> {
    try_fold_items!(grant.statement().extensions().as_slice(), requirements, accumulated, _position, extension =>
        collect_extension_requirements(accumulated, extension))
}
fn addresses_parent(children: &[ObservationRequirement], parent: &ObservationRequirement) -> bool {
    let mut position = 0;
    let mut addressed = false;
    while position < children.len() && !addressed {
        let child = &children[position];
        addressed = observation_schema_equal(child.schema(), parent.schema())
            && requirement_subject_equal(child.subject(), parent.subject());
        position += 1;
    }
    addressed
}
fn every_parent_addressed(parents: &[ObservationRequirement], children: &[ObservationRequirement]) -> bool {
    let mut position = 0;
    let mut kept = true;
    while position < parents.len() && kept { kept = addresses_parent(children, &parents[position]); position += 1; }
    kept
}
fn chain_contains_principal(chain: &[&SignedGrant], principal: &PrincipalId) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < chain.len() && !found {
        let statement = chain[position].statement();
        found = principal_id_equal(principal, statement.issuer()) || principal_id_equal(principal, statement.subject());
        position += 1;
    }
    found
}
fn anchor_for<'a>(anchors: &'a [ObserverAnchor], identifier: &auths_model::ObserverAnchorId) -> Option<&'a ObserverAnchor> {
    let mut position = 0;
    while position < anchors.len() {
        if anchors[position].id() == identifier { return Some(&anchors[position]); }
        position += 1;
    }
    None
}
fn anchor_at<'a>(anchors: &[Option<&'a ObserverAnchor>], position: usize) -> Option<&'a ObserverAnchor> {
    match anchors.get(position) { Some(anchor) => *anchor, None => None }
}
fn payload_for(payloads: &[DetachedAttachment], digest: AttachmentDigest) -> Option<&DetachedAttachment> {
    let mut position = 0;
    while position < payloads.len() {
        if payloads[position].digest() == digest { return Some(&payloads[position]); }
        position += 1;
    }
    None
}
fn evidence_accepted(evidence: &[EvidenceObject], accepted: &auths_model::AcceptedRegistries) -> bool {
    let mut position = 0;
    let mut valid = true;
    while position < evidence.len() && valid {
        valid = accepted.accepts_evidence_type(evidence[position].evidence_type());
        position += 1;
    }
    valid
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

// Unlike invalid optional evidence, resource exhaustion is a stage failure.
// Keep the payload generic so the exact move/classification can be source-
// refined without assuming anything about an adapter's successful output.
fn control_result<T>(result: Result<T, PrincipalControlError>) -> Result<Option<T>, VerificationFailure> {
    match result {
        Ok(control) => Ok(Some(control)),
        Err(PrincipalControlError::ResourceLimitExceeded) => Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)),
        Err(_) => Ok(None),
    }
}
fn match_namespace<M: ResourceMatcher + ?Sized>(namespace: &ResourceId, subject: &ResourceId, matcher: &M, meter: &mut WorkMeter)
-> Result<bool, VerificationFailure> {
    meter.reserve(matcher.maximum_work_units(namespace, subject))?;
    matcher.matches(namespace, subject).map_err(|error| registry_operation_failure(error))
}

impl<R: RegistryAccess + ?Sized> Stage<'_, R> {
    fn append_anchor<'s>(&'s self, mut anchors: Vec<Option<&'s ObserverAnchor>>, requirement: &ObservationRequirement)
    -> Result<Vec<Option<&'s ObserverAnchor>>, VerificationFailure> {
        let anchor = anchor_for(self.context.observer_anchors(), requirement.observer_anchor());
        if let Some(anchor) = anchor && self.in_authority_chain(anchor.principal()) {
            return Err(VerificationFailure::Denied(DenialReason::ObserverInAuthorityChain));
        }
        anchors.push(anchor);
        Ok(anchors)
    }
    fn append_candidate(&self, mut candidates: Vec<Candidate>, descriptor: &AttachmentDescriptor)
    -> Result<Vec<Candidate>, VerificationFailure> {
        if descriptor.media_type().as_str() != OBSERVATION_MEDIA_TYPE { return Ok(candidates); }
        let Some(detached) = payload_for(self.canonical.detached_attachments(), descriptor.digest()) else { return Ok(candidates); };
        let observation = decode_signed_observation(detached.bytes(), self.context.limits()).map_err(|error| limit_or_malformed(error))?;
        candidates.push(Candidate { digest: descriptor.digest(), observation: observation.into_value(), authentic: None });
        Ok(candidates)
    }
    fn evaluate_requirement(&self, mut tally: ObservationTally, requirement: &ObservationRequirement,
        anchor: Option<&ObserverAnchor>, candidates: &mut [Candidate], meter: &mut WorkMeter)
    -> Result<ObservationTally, VerificationFailure> {
        match self.requirement(requirement, anchor, candidates, meter)? {
            Ok(satisfied) => {
                tally.valid_through = tally.valid_through.min(satisfied.valid_through);
                tally.satisfactions.push(satisfied.record);
            }
            Err(VerificationFailure::Denied(reason)) => return Err(VerificationFailure::Denied(reason)),
            Err(unavailable) => if tally.unavailable.is_none() { tally.unavailable = Some(unavailable); },
        }
        Ok(tally)
    }
    #[allow(clippy::too_many_arguments)]
    fn consider_candidate(&self, mut scan: CandidateScan, requirement: &ObservationRequirement, anchor: &ObserverAnchor,
        subject: &ResourceId, action_values: &[Option<FactValue>], candidate: &mut Candidate, meter: &mut WorkMeter)
    -> Result<CandidateScan, VerificationFailure> {
        if !self.eligible(requirement, anchor, subject, candidate, meter)? { return Ok(scan); }
        scan.any_eligible = true;
        if observation_conditions_hold(requirement.conditions(), action_values, candidate.observation.statement().facts()) {
            let statement = candidate.observation.statement();
            let horizon = anchor.validity().expires_at().min(Timestamp::new(statement.observed_at().get()
                .saturating_add(u64::from(requirement.max_age_seconds()))));
            scan.satisfying = Some((candidate.digest, horizon));
        }
        Ok(scan)
    }
    #[allow(clippy::too_many_arguments)]
    fn scan_candidates(&self, requirement: &ObservationRequirement, anchor: &ObserverAnchor, subject: &ResourceId,
        action_values: &[Option<FactValue>], candidates: &mut [Candidate], meter: &mut WorkMeter)
    -> Result<CandidateScan, VerificationFailure> {
        let mut outcome = Ok(CandidateScan { any_eligible: false, satisfying: None });
        let mut position = 0;
        while position < candidates.len() && matches!(&outcome, Ok(scan) if scan.satisfying.is_none()) {
            outcome = match outcome {
                Ok(scan) => self.consider_candidate(scan, requirement, anchor, subject, action_values, &mut candidates[position], meter),
                Err(failure) => Err(failure),
            };
            position += 1;
        }
        outcome
    }
    fn resolve_action_fact<P: ProfilePolicy + ?Sized>(&self, policy: &P, name: &FactName, meter: &mut WorkMeter)
    -> Result<Option<FactValue>, VerificationFailure> {
        meter.reserve(policy.maximum_work_units(self.canonical))?;
        policy.action_fact(self.canonical, name).map_err(|error| registry_operation_failure(error))
    }
    fn append_action_value<P: ProfilePolicy + ?Sized>(&self, values: Option<Vec<Option<FactValue>>>, condition: &ObservationCondition,
        policy: &P, meter: &mut WorkMeter) -> Result<Option<Vec<Option<FactValue>>>, VerificationFailure> {
        let Some(mut values) = values else { return Ok(None); };
        match condition.action_fact() {
            None => values.push(None),
            Some(name) => match self.resolve_action_fact(policy, name, meter)? {
                Some(value) => values.push(Some(value)),
                None => return Ok(None),
            },
        }
        Ok(Some(values))
    }
    fn gather_action_values<P: ProfilePolicy + ?Sized>(&self, conditions: &[ObservationCondition], policy: &P, meter: &mut WorkMeter)
    -> Result<Option<Vec<Option<FactValue>>>, VerificationFailure> {
        let mut outcome = Ok(Some(Vec::with_capacity(conditions.len())));
        let mut position = 0;
        while position < conditions.len() && matches!(&outcome, Ok(Some(_))) {
            outcome = match outcome {
                Ok(values) => self.append_action_value(values, &conditions[position], policy, meter),
                Err(failure) => Err(failure),
            };
            position += 1;
        }
        outcome
    }
}

#[cfg(test)]
#[path = "observation_reference.rs"]
mod reference;
#[cfg(test)]
#[path = "observation_parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_registries::ImmutableRegistries;
    use alloc::vec;
    use auths_model::{
        ConditionTest, CriticalExtension, CriticalExtensions, ExtensionId, FactName,
        GrantStatement, ObservationCondition, ObservationRequirements, ObservationSchemaId,
        ObserverAnchorId, UintRange, VerifierLimits,
    };

    /// A grant carrying `count` distinct requirements, each a narrowing of
    /// the same base requirement by one extra range atom.
    fn grant_with_requirements(template: &SignedGrant, first: u64, count: u64) -> SignedGrant {
        let requirements = (first..first + count)
            .map(|hi| {
                ObservationRequirement::new(
                    ObserverAnchorId::parse("observer").expect("anchor"),
                    ObservationSchemaId::parse("auths.test/1").expect("schema"),
                    auths_model::ObservationSubject::Resource(
                        ResourceId::parse("mcp://record").expect("subject"),
                    ),
                    60,
                    vec![ObservationCondition::new(
                        FactName::parse("count").expect("fact"),
                        ConditionTest::UintRange(UintRange::new(0, hi).expect("range")),
                    )],
                )
                .expect("requirement")
            })
            .collect();
        let bytes = auths_codec::encode_observation_requirements(
            &ObservationRequirements::new(requirements).expect("requirements"),
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
                        ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1)
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

    /// Delegates may add requirements, so a chain of five grants can carry
    /// more distinct requirements than the chain bound: 32 is accepted and
    /// 33 is a resource-limit denial.
    #[test]
    fn chain_requirement_bound_is_exact() {
        let fixture = auths_testkit::corpus()
            .into_iter()
            .find(|fixture| fixture.name() == "observation-requirement-preserved")
            .expect("corpus fixture");
        let bundle = auths_codec::decode_bundle(fixture.proof_bytes(), &VerifierLimits::default())
            .expect("fixture proof");
        let template = &bundle.grants()[0];
        let at_limit: Vec<SignedGrant> = (0..4)
            .map(|grant| grant_with_requirements(template, grant * 8, 8))
            .collect();
        let references: Vec<&SignedGrant> = at_limit.iter().collect();
        assert_eq!(chain_requirements(&references).map(|all| all.len()), Ok(32));

        let mut over = at_limit;
        over.push(grant_with_requirements(template, 32, 1));
        let references: Vec<&SignedGrant> = over.iter().collect();
        assert_eq!(
            chain_requirements(&references).map(|all| all.len()),
            Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded
            ))
        );
    }
}
