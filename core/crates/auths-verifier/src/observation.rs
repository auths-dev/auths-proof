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
use auths_codec::{CodecError, decode_observation_requirements, decode_signed_observation};
use auths_model::{
    AttachmentDigest, CanonicalAction, DenialReason, FactValue, MAX_OBSERVATION_ATTACHMENTS,
    MAX_OBSERVATION_BYTES, MAX_OBSERVATION_REQUIREMENTS_PER_CHAIN, OBSERVATION_MEDIA_TYPE,
    ObservationRequirement, ObservationSatisfaction, ObservationSubject, ObserverAnchor,
    PrincipalId, Requirement, RequirementVerdict, ResourceId, SignedAction, SignedGrant,
    SignedObservation, TrustedContext, observation_conditions_hold, observation_fresh,
    observation_schema_equal, observation_subject_equal, principal_id_equal,
    requirement_subject_equal, requirement_verdict,
};
use auths_ports::{
    ControlPurpose, PrincipalControlInput, ProfilePolicy, ResourceMatcher, SignatureInput,
    diagnostics::DiagnosticMode,
};
use auths_registries::{ImmutableRegistries, OBSERVATION_REQUIREMENT_EXTENSION_V1};

/// One decoded observation attachment and its lazily established
/// authenticity.
struct Candidate {
    digest: AttachmentDigest,
    observation: SignedObservation,
    authentic: Option<bool>,
}

/// Shared inputs of one branch's observation stage.
pub(crate) struct Stage<'a, 'r> {
    pub(crate) chain: &'a [&'a SignedGrant],
    pub(crate) root: &'a PrincipalId,
    pub(crate) action: &'a SignedAction,
    pub(crate) canonical: &'a CanonicalAction,
    pub(crate) context: &'a TrustedContext,
    pub(crate) registries: &'a ImmutableRegistries<'r>,
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
pub(crate) fn validate_observation_attachments(
    action: &SignedAction,
) -> Result<(), VerificationFailure> {
    let mut count = 0usize;
    for descriptor in action.envelope().attachments() {
        if descriptor.media_type().as_str() != OBSERVATION_MEDIA_TYPE {
            continue;
        }
        count += 1;
        let oversized = usize::try_from(descriptor.byte_length())
            .map_or(true, |length| length > MAX_OBSERVATION_BYTES);
        if count > MAX_OBSERVATION_ATTACHMENTS || oversized {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
    }
    Ok(())
}

/// Collects the distinct requirements carried by every grant in the chain,
/// in first-appearance order.
pub(crate) fn chain_requirements(
    chain: &[&SignedGrant],
) -> Result<Vec<ObservationRequirement>, VerificationFailure> {
    let mut requirements: Vec<ObservationRequirement> = Vec::new();
    for grant in chain {
        for extension in grant.statement().extensions().as_slice() {
            if extension.id().as_str() != OBSERVATION_REQUIREMENT_EXTENSION_V1 {
                continue;
            }
            let decoded =
                decode_observation_requirements(extension.bytes()).map_err(limit_or_malformed)?;
            for requirement in decoded.as_slice() {
                if !requirements.contains(requirement) {
                    requirements.push(requirement.clone());
                }
            }
        }
    }
    if requirements.len() > MAX_OBSERVATION_REQUIREMENTS_PER_CHAIN {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    Ok(requirements)
}

/// Denies a child grant that drops a parent's observation requirement: no
/// child requirement addresses it with the same schema and subject. A child
/// requirement that addresses it without keeping or narrowing it falls
/// through to the authority kernel, whose extension law denies the edge as
/// expanded.
pub(crate) fn require_parent_requirements(
    parent: &SignedGrant,
    child: &SignedGrant,
) -> Result<(), VerificationFailure> {
    let parent_requirements = chain_requirements(&[parent])?;
    if parent_requirements.is_empty() {
        return Ok(());
    }
    let child_requirements = chain_requirements(&[child]).unwrap_or_default();
    if parent_requirements.iter().all(|parent| {
        child_requirements.iter().any(|child| {
            observation_schema_equal(child.schema(), parent.schema())
                && requirement_subject_equal(child.subject(), parent.subject())
        })
    }) {
        Ok(())
    } else {
        Err(VerificationFailure::Denied(
            DenialReason::ObservationRequirementDropped,
        ))
    }
}

impl Stage<'_, '_> {
    /// Evaluates every requirement in the chain and returns the observation
    /// that satisfied each one.
    pub(crate) fn evaluate(
        &self,
        meter: &mut WorkMeter,
    ) -> Result<Vec<ObservationSatisfaction>, VerificationFailure> {
        let requirements = chain_requirements(self.chain)?;
        if requirements.is_empty() {
            return Ok(Vec::new());
        }
        let mut anchors = Vec::with_capacity(requirements.len());
        for requirement in &requirements {
            let anchor = self
                .context
                .observer_anchors()
                .iter()
                .find(|anchor| anchor.id() == requirement.observer_anchor());
            if let Some(anchor) = anchor
                && self.in_authority_chain(anchor.principal())
            {
                return Err(VerificationFailure::Denied(
                    DenialReason::ObserverInAuthorityChain,
                ));
            }
            anchors.push(anchor);
        }
        let mut candidates = self.candidates()?;
        let mut satisfactions = Vec::with_capacity(requirements.len());
        let mut unavailable = None;
        for (requirement, anchor) in requirements.iter().zip(anchors) {
            match self.requirement(requirement, anchor, &mut candidates, meter)? {
                Ok(satisfaction) => satisfactions.push(satisfaction),
                Err(VerificationFailure::Denied(reason)) => {
                    return Err(VerificationFailure::Denied(reason));
                }
                Err(indeterminate) => {
                    unavailable.get_or_insert(indeterminate);
                }
            }
        }
        match unavailable {
            Some(failure) => Err(failure),
            None => Ok(satisfactions),
        }
    }

    fn in_authority_chain(&self, principal: &PrincipalId) -> bool {
        principal_id_equal(principal, self.root)
            || principal_id_equal(principal, self.action.envelope().actor())
            || self.chain.iter().any(|grant| {
                principal_id_equal(principal, grant.statement().issuer())
                    || principal_id_equal(principal, grant.statement().subject())
            })
    }

    fn candidates(&self) -> Result<Vec<Candidate>, VerificationFailure> {
        let mut candidates = Vec::new();
        for descriptor in self.action.envelope().attachments() {
            if descriptor.media_type().as_str() != OBSERVATION_MEDIA_TYPE {
                continue;
            }
            let Some(detached) = self
                .canonical
                .detached_attachments()
                .iter()
                .find(|attachment| attachment.digest() == descriptor.digest())
            else {
                continue;
            };
            let observation = decode_signed_observation(detached.bytes(), self.context.limits())
                .map_err(limit_or_malformed)?;
            candidates.push(Candidate {
                digest: descriptor.digest(),
                observation,
                authentic: None,
            });
        }
        candidates.sort_by_key(|candidate| candidate.digest);
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
    ) -> Result<Result<ObservationSatisfaction, VerificationFailure>, VerificationFailure> {
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
        let mut any_eligible = false;
        let mut satisfying = None;
        for candidate in candidates.iter_mut() {
            if !self.eligible(requirement, anchor, &subject, candidate, meter)? {
                continue;
            }
            any_eligible = true;
            if observation_conditions_hold(
                requirement.conditions(),
                &action_values,
                candidate.observation.statement().facts(),
            ) {
                satisfying = Some(candidate.digest);
                break;
            }
        }
        let verdict = requirement_verdict(any_eligible, satisfying.is_some());
        Ok(match (verdict, satisfying) {
            (RequirementVerdict::Satisfied, Some(digest)) => {
                let id = auths_codec::observation_requirement_id(requirement)
                    .map_err(limit_or_malformed)?;
                Ok(ObservationSatisfaction::new(id, digest))
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
    fn action_facts(
        &self,
        requirement: &ObservationRequirement,
        policy: &dyn ProfilePolicy,
        meter: &mut WorkMeter,
    ) -> Result<Option<(ResourceId, Vec<Option<FactValue>>)>, VerificationFailure> {
        let mut resolve = |name| -> Result<Option<FactValue>, VerificationFailure> {
            meter.reserve(policy.maximum_work_units(self.canonical))?;
            policy
                .action_fact(self.canonical, name)
                .map_err(registry_operation_failure)
        };
        let subject = match requirement.subject() {
            ObservationSubject::Resource(resource) => resource.clone(),
            ObservationSubject::ActionFact(name) => match resolve(name)? {
                Some(FactValue::Text(text)) => match ResourceId::parse(text.as_str()) {
                    Ok(resource) => resource,
                    Err(_) => return Ok(None),
                },
                _ => return Ok(None),
            },
        };
        let mut action_values = Vec::with_capacity(requirement.conditions().len());
        for condition in requirement.conditions() {
            match condition.action_fact() {
                None => action_values.push(None),
                Some(name) => match resolve(name)? {
                    Some(value) => action_values.push(Some(value)),
                    None => return Ok(None),
                },
            }
        }
        Ok(Some((subject, action_values)))
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

    fn subject_in_namespaces(
        &self,
        anchor: &ObserverAnchor,
        subject: &ResourceId,
        meter: &mut WorkMeter,
    ) -> Result<bool, VerificationFailure> {
        let matcher: &dyn ResourceMatcher = self
            .registries
            .resource_matcher(
                self.context.accepted_registries(),
                self.context.resource_matcher(),
            )
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedResourceMatcher,
            ))?;
        for namespace in anchor.subject_namespaces() {
            meter.reserve(matcher.maximum_work_units(namespace, subject))?;
            if matcher
                .matches(namespace, subject)
                .map_err(registry_operation_failure)?
            {
                return Ok(true);
            }
        }
        Ok(false)
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
        if observation
            .evidence()
            .iter()
            .any(|object| !accepted.accepts_evidence_type(object.evidence_type()))
        {
            return Ok(false);
        }
        let reservation = method.maximum_work_units();
        meter.reserve(reservation)?;
        meter.reserve(suite.work_units())?;
        let statement = observation.statement();
        let Ok(preimage) = auths_codec::observation_signing_preimage(statement, descriptor) else {
            return Ok(false);
        };
        let evidence: Vec<_> = observation.evidence().iter().collect();
        let Ok(control) = method
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
            .into_result()
        else {
            return Ok(false);
        };
        if control.work_units() > reservation {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceLimitExceeded,
            ));
        }
        let supplied: Vec<_> = observation
            .evidence()
            .iter()
            .map(auths_model::EvidenceObject::id)
            .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
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
