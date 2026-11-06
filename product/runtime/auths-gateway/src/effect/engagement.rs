//! Installed engagement scope in the existing effect owner. These projections
//! are private data; native authority and the final writer fence remain required.
use super::{EffectBindingError, Reservation, ReservationWindow, Unit, canonical, commitment};
use crate::participant_enrollment::{
    EnrollmentInvocation, EnrollmentScopePins, EnrollmentTree, ParentEnrollmentPins,
    ParticipantCeilings, root_enrollment_commitment,
};
use auths_model::TrustedContext;
use serde::{Deserialize, Serialize};

/// Operator-installed engagement root and exact gateway workload. This is not
/// participant input, a portable grant, or a current enrollment snapshot.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementPolicy {
    root: ParentEnrollmentPins,
    executor: String,
}
impl std::fmt::Debug for EngagementPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementPolicy { private: [redacted] }")
    }
}
impl EngagementPolicy {
    /// Pins the complete immutable root and independently registered workload.
    /// No enrollment, admission, or provider operation is performed.
    ///
    /// # Errors
    /// Refuses invalid root commitments, bounds, inactive roots, or workloads.
    pub fn new(root: ParentEnrollmentPins, executor: String) -> Result<Self, EffectBindingError> {
        let policy = Self { root, executor };
        policy.validate()?;
        Ok(policy)
    }
    pub(crate) fn validate(&self) -> Result<(), EffectBindingError> {
        if !self.root.active
            || !super::label(&self.executor)
            || root_enrollment_commitment(&self.root).map_err(|_| EffectBindingError::Invalid)?
                != self.root.enrollment_commitment
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn root(&self) -> &ParentEnrollmentPins {
        &self.root
    }
    pub(crate) fn executor(&self) -> &str {
        &self.executor
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Ancestor {
    enrollment: [u8; 32],
    principal: String,
    instance: u64,
    not_before: u64,
    expires_at: u64,
    ceilings: ParticipantCeilings,
    resource_grant: [u8; 32],
}

/// Complete immutable scope projection covered by the exact effect approval.
/// Mutable whole-tree revision is deliberately absent: sibling enrollment does
/// not alter an existing participant's approved path. Fresh activity is fenced.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EngagementScope {
    schema: String,
    authority_namespace: String,
    authority_partition: String,
    authority_epoch: u64,
    engagement: [u8; 32],
    root: [u8; 32],
    executor: String,
    scope: EnrollmentScopePins,
    ancestors: Vec<Ancestor>,
}

impl EngagementScope {
    pub(super) fn compile(
        policy: &EngagementPolicy,
        tree: &EnrollmentTree,
        context: &TrustedContext,
        recipe: [u8; 32],
        connection: [u8; 32],
        now: u64,
        invocation: EnrollmentInvocation<'_>,
    ) -> Result<Self, EffectBindingError> {
        policy.validate()?;
        // Use the maintained tree decoder's independent installation comparison;
        // a caller-supplied tree cannot replace installed root/channel/scope pins.
        let tree = EnrollmentTree::decode(
            &tree.encode().map_err(|_| EffectBindingError::Invalid)?,
            &policy.root,
        )
        .map_err(|_| EffectBindingError::Invalid)?;
        let canonical = auths_codec::decode_canonical_action(
            invocation.action,
            &auths_model::VerifierLimits::default(),
        )
        .map_err(|_| EffectBindingError::Invalid)?;
        let call: serde_json::Value =
            serde_json::from_slice(canonical.body()).map_err(|_| EffectBindingError::Invalid)?;
        // Scope choice is an exact native-verifier comparison below; these are
        // bounded lookup hints only, never executable request parameters.
        let service = call
            .get("service")
            .and_then(serde_json::Value::as_str)
            .ok_or(EffectBindingError::Invalid)?;
        let tool = call
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or(EffectBindingError::Invalid)?;
        let mut matches = policy.root.scopes.iter().filter(|scope| {
            scope.recipe_digest == hex::encode(recipe)
                && scope.connection_binding == connection
                && scope.service == service
                && scope.tool == tool
                && matches!(&scope.resource, crate::participant_enrollment::EnrollmentResourceBinding::Exact { handle }
                    if call.get("arguments").and_then(|arguments| arguments.get(&scope.resource_argument))
                        .and_then(serde_json::Value::as_str) == Some(handle.as_str()))
        });
        let scope = matches.next().ok_or(EffectBindingError::Invalid)?;
        if matches.next().is_some() {
            return Err(EffectBindingError::Invalid);
        }
        let participant = tree
            .verify_operation_scope(context, &scope.scope_id, now, &invocation)
            .map_err(|_| EffectBindingError::Invalid)?;
        let path = tree
            .active_principal_path(participant.principal(), now)
            .map_err(|_| EffectBindingError::Invalid)?;
        let ancestors = path
            .iter()
            .map(|pins| {
                let grant = pins
                    .scopes
                    .iter()
                    .find(|entry| entry.scope_id == scope.scope_id)
                    .ok_or(EffectBindingError::Invalid)?;
                Ok(Ancestor {
                    enrollment: pins.enrollment_commitment,
                    principal: pins.principal.as_str().to_owned(),
                    instance: pins.instance_generation,
                    not_before: pins.not_before,
                    expires_at: pins.expires_at,
                    ceilings: pins.ceilings,
                    resource_grant: *grant.parent_grant.as_bytes(),
                })
            })
            .collect::<Result<Vec<_>, EffectBindingError>>()?;
        let result = Self {
            schema: "auths.effect-engagement-scope/1".to_owned(),
            authority_namespace: policy.root.admission_namespace.clone(),
            authority_partition: policy.root.admission_partition.clone(),
            authority_epoch: policy.root.partition_generation,
            engagement: policy.root.engagement_commitment,
            root: policy.root.enrollment_commitment,
            executor: policy.executor.clone(),
            scope: scope.clone(),
            ancestors,
        };
        result.validate()?;
        Ok(result)
    }

    pub(super) fn validate(&self) -> Result<(), EffectBindingError> {
        use crate::participant_enrollment::{MAX_JSON_INTEGER, MAX_PARTICIPANTS, identifier};
        if self.schema != "auths.effect-engagement-scope/1"
            || crate::OperatorNamespace::parse(&self.authority_namespace).is_err()
            || !identifier(&self.authority_partition)
            || !super::label(&self.executor)
            || !(1..=MAX_JSON_INTEGER).contains(&self.authority_epoch)
            || self.ancestors.is_empty()
            || self.ancestors.len() > MAX_PARTICIPANTS
            || self.ancestors[0].enrollment != self.root
            || self.ancestors[0].resource_grant != *self.scope.parent_grant.as_bytes()
            || !identifier(&self.scope.scope_id)
            || !identifier(&self.scope.resource_argument)
            || !identifier(&self.scope.service)
            || !identifier(&self.scope.tool)
            || crate::control_namespace::is_control_service(&self.scope.service)
            || !self.scope.resource.valid()
            || matches!(
                self.scope.resource,
                crate::participant_enrollment::EnrollmentResourceBinding::CreatedChild { .. }
            )
            || crate::participant_enrollment::resource_audience(
                &self.engagement,
                self.authority_epoch,
                &self.scope.recipe_digest,
            )
            .is_err()
        {
            return Err(EffectBindingError::Invalid);
        }
        for (index, ancestor) in self.ancestors.iter().enumerate() {
            let principal = auths_model::PrincipalId::parse(&ancestor.principal)
                .map_err(|_| EffectBindingError::Invalid)?;
            if !(1..=MAX_JSON_INTEGER).contains(&ancestor.instance)
                || ancestor.not_before >= ancestor.expires_at
                || ancestor.expires_at > MAX_JSON_INTEGER
                || !ancestor.ceilings.within(ancestor.ceilings)
                || self.ancestors[..index].iter().any(|previous| {
                    previous.enrollment == ancestor.enrollment
                        || previous.resource_grant == ancestor.resource_grant
                        || auths_model::PrincipalId::parse(&previous.principal)
                            .map_or(true, |p| crate::principals_overlap(&p, &principal))
                })
                || index.checked_sub(1).is_some_and(|parent| {
                    let parent = &self.ancestors[parent];
                    ancestor.not_before < parent.not_before
                        || ancestor.expires_at > parent.expires_at
                        || !ancestor.ceilings.within(parent.ceilings)
                })
            {
                return Err(EffectBindingError::Invalid);
            }
        }
        Ok(())
    }

    pub(super) fn independent_approver(
        &self,
        approver: &[u8; 32],
    ) -> Result<(), EffectBindingError> {
        use auths_raw_key::{RawKeyDescriptor, RawKeyType};
        let actor = self.ancestors.last().ok_or(EffectBindingError::Invalid)?;
        let actor = auths_model::PrincipalId::parse(&actor.principal)
            .map_err(|_| EffectBindingError::Invalid)?;
        let human = RawKeyDescriptor::new(RawKeyType::Ed25519, approver.to_vec())
            .map_err(|_| EffectBindingError::Invalid)?
            .principal()
            .map_err(|_| EffectBindingError::Invalid)?;
        if crate::principals_overlap(&actor, &human) {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    pub(super) fn matches_installation(&self, recipe: &[u8; 32], connection: &[u8; 32]) -> bool {
        self.scope.recipe_digest == hex::encode(recipe)
            && &self.scope.connection_binding == connection
    }

    pub(super) fn reservations(
        &self,
        unit: Unit,
        amount: u64,
    ) -> Result<Vec<Reservation>, EffectBindingError> {
        self.ancestors
            .iter()
            .map(|ancestor| {
                let ceiling = match unit {
                    Unit::MutationCount => u64::from(ancestor.ceilings.writes),
                    Unit::AcquisitionCount => u64::from(ancestor.ceilings.provider_reads),
                    Unit::DisclosureCount => u64::from(ancestor.ceilings.disclosures),
                    Unit::DisclosureBytes => ancestor.ceilings.disclosure_bytes,
                    _ => return Err(EffectBindingError::Invalid),
                };
                if amount > ceiling {
                    return Err(EffectBindingError::Invalid);
                }
                Ok(Reservation {
                    key: commitment(
                        "auths.engagement-ancestor-capacity/1",
                        &canonical(&(
                            &self.authority_namespace,
                            &self.authority_partition,
                            self.authority_epoch,
                            self.engagement,
                            ancestor.enrollment,
                            unit,
                        ))?,
                    )?,
                    unit,
                    amount,
                    ceiling,
                    window: ReservationWindow::EngagementLifetime,
                })
            })
            .collect()
    }
}
