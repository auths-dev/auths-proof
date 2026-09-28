//! The pre-entry evidence re-read: requirement selection before the claim,
//! and the evaluation of what the gateway read after the lease.
//!
//! It adds no condition language. A requirement a grant of an authorized
//! branch already carries is selected when its schema is the gateway
//! read-back schema, its anchor is the installed gateway observer's and
//! covers the subject, and its subject resolves to one of the recipe's
//! pre-entry subjects. After the lease the gateway reads once, signs one
//! read-back observation per pointer, and evaluates the selected
//! requirements again on those observations with the shipping predicates.
//! The write stays unconditional; only the window is narrowed.

use crate::observer::{READ_BACK_SCHEMA, read_back_facts};
use crate::{ClosedActionRead, GatewayObserver};
use auths_gateway_kernel::order::PreEntryResult;
use auths_model::{
    CanonicalAction, FactValue, ObservationCondition, ObservationFacts, ObservationRequirement,
    ObservationSubject, PrincipalId, RequirementVerdict, ResourceId, TrustedContext,
    observation_conditions_hold, observation_fresh, requirement_verdict,
};
use auths_ports::ProfilePolicy as _;
use auths_profile_mcp::McpArgumentsPolicy;
use serde_json::Value;

/// One selected requirement, resolved against the verified action.
#[derive(Clone, Debug)]
pub(crate) struct SelectedRequirement {
    /// The resolved subject, `<url>#<pointer>`.
    subject: String,
    /// The requirement's conditions.
    conditions: Vec<ObservationCondition>,
    /// The resolved action value of each condition, in order.
    action_values: Vec<Option<FactValue>>,
    /// The requirement's maximum age.
    max_age_seconds: u64,
    /// The inclusive validity of the anchor that pins the observer.
    anchor_validity: (u64, u64),
}

/// Why no pre-entry re-read can be selected; both refuse before the claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SelectionRefusal {
    /// No observer key is provisioned.
    ObserverUnavailable,
    /// No requirement of an authorized branch is selected.
    RequirementMissing,
}

impl SelectionRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ObserverUnavailable => "gateway.pre-entry.observer-unavailable",
            Self::RequirementMissing => "gateway.pre-entry.requirement-missing",
        }
    }
}

/// Selects every requirement the re-read can satisfy, or refuses before the
/// claim. `requirements` are the observation requirements of every grant
/// of every authorized branch; `read` is the verified pre-entry read and
/// `pointers` the recipe's pre-entry pointers.
pub(crate) fn select(
    requirements: &[ObservationRequirement],
    action: &CanonicalAction,
    context: &TrustedContext,
    observer: Option<&PrincipalId>,
    read: &ClosedActionRead,
    pointers: &[String],
    covers: impl Fn(&ResourceId, &ResourceId) -> bool,
) -> Result<Vec<SelectedRequirement>, SelectionRefusal> {
    let observer = observer.ok_or(SelectionRefusal::ObserverUnavailable)?;
    let facts = McpArgumentsPolicy::new().map_err(|_| SelectionRefusal::RequirementMissing)?;
    let fact = |name| facts.action_fact(action, name).ok().flatten();
    let subjects: Vec<String> = pointers
        .iter()
        .map(|pointer| read.subject(pointer))
        .collect();
    let mut selected = Vec::new();
    for requirement in requirements {
        if requirement.schema().as_str() != READ_BACK_SCHEMA {
            continue;
        }
        let subject = match requirement.subject() {
            ObservationSubject::Resource(resource) => Some(resource.as_str().to_owned()),
            ObservationSubject::ActionFact(name) => match fact(name) {
                Some(FactValue::Text(text)) => Some(text.as_str().to_owned()),
                _ => None,
            },
        };
        let Some(subject) = subject.filter(|subject| subjects.contains(subject)) else {
            continue;
        };
        let Ok(resource) = ResourceId::parse(&subject) else {
            continue;
        };
        let Some(anchor) = context.observer_anchors().iter().find(|anchor| {
            anchor.id().as_str() == requirement.observer_anchor().as_str()
                && anchor.principal().as_str() == observer.as_str()
                && anchor
                    .schemas()
                    .iter()
                    .any(|schema| schema.as_str() == READ_BACK_SCHEMA)
                && anchor
                    .subject_namespaces()
                    .iter()
                    .any(|namespace| covers(namespace, &resource))
        }) else {
            continue;
        };
        let action_values = requirement
            .conditions()
            .iter()
            .map(|condition| condition.action_fact().and_then(&fact))
            .collect();
        selected.push(SelectedRequirement {
            subject,
            conditions: requirement.conditions().to_vec(),
            action_values,
            max_age_seconds: u64::from(requirement.max_age_seconds()),
            anchor_validity: (
                anchor.validity().not_before().get(),
                anchor.validity().expires_at().get(),
            ),
        });
    }
    if selected.is_empty() {
        Err(SelectionRefusal::RequirementMissing)
    } else {
        Ok(selected)
    }
}

/// One signed pre-entry observation and what the evaluation needs of it.
#[derive(Clone, Debug)]
pub(crate) struct PreEntryObservation {
    pub(crate) subject: String,
    pub(crate) observed_at: u64,
    pub(crate) facts: ObservationFacts,
    pub(crate) bytes: Vec<u8>,
}

/// Signs one read-back observation per pointer of a complete 2xx JSON
/// response with no version mismatch, taken at `observed_at`. `None` when a
/// pointer is absent or its value has no fact form.
pub(crate) fn sign_observations(
    observer: &GatewayObserver,
    read: &ClosedActionRead,
    pointers: &[String],
    body: &[u8],
    observed_at: u64,
) -> Option<Vec<PreEntryObservation>> {
    if body.len() > read.maximum_response_bytes() {
        return None;
    }
    let document: Value = serde_json::from_slice(body).ok()?;
    pointers
        .iter()
        .map(|pointer| {
            let facts = read_back_facts(document.pointer(pointer)?, None).ok()?;
            let subject = read.subject(pointer);
            let signed = observer
                .sign(READ_BACK_SCHEMA, &subject, observed_at, facts.clone())
                .ok()?;
            Some(PreEntryObservation {
                subject,
                observed_at,
                facts: ObservationFacts::new(facts).ok()?,
                bytes: signed.bytes().to_vec(),
            })
        })
        .collect()
}

/// Evaluates every selected requirement on the signed observations at the
/// gateway clock `now`: satisfied when each has a fresh satisfying
/// observation; `condition-false` when one has a fresh observation that
/// makes a condition false (a false condition dominates); otherwise
/// unavailable.
pub(crate) fn evaluate(
    selected: &[SelectedRequirement],
    observations: &[PreEntryObservation],
    now: u64,
) -> PreEntryResult {
    let mut all_satisfied = true;
    let mut any_false = false;
    for requirement in selected {
        let mut any_eligible = false;
        let mut any_satisfying = false;
        for observation in observations
            .iter()
            .filter(|observation| observation.subject == requirement.subject)
        {
            if !observation_fresh(
                observation.observed_at,
                now,
                requirement.max_age_seconds,
                requirement.anchor_validity.0,
                requirement.anchor_validity.1,
            ) {
                continue;
            }
            any_eligible = true;
            any_satisfying |= observation_conditions_hold(
                &requirement.conditions,
                &requirement.action_values,
                &observation.facts,
            );
        }
        match requirement_verdict(any_eligible, any_satisfying) {
            RequirementVerdict::Satisfied => {}
            RequirementVerdict::ConditionFalse => {
                all_satisfied = false;
                any_false = true;
            }
            RequirementVerdict::Missing => all_satisfied = false,
        }
    }
    if any_false {
        PreEntryResult::ConditionFalse
    } else if all_satisfied {
        PreEntryResult::Satisfied
    } else {
        PreEntryResult::Unavailable
    }
}
