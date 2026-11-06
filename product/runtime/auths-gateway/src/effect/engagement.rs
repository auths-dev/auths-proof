//! Installed engagement scope in the existing effect owner. These projections
//! are private data; native authority and the final writer fence remain required.
use super::{
    EffectBinding, EffectBindingError, EffectInstallation, Protocol, Reservation,
    ReservationWindow, Scope, Unit, canonical, commitment,
};
use crate::participant_enrollment::{
    EnrollmentInvocation, EnrollmentScopePins, EnrollmentTree, ParentEnrollmentPins,
    ParticipantCeilings, root_enrollment_commitment,
};
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
    capacity_enrollment: [u8; 32],
    principal: String,
    instance: u64,
    not_before: u64,
    expires_at: u64,
    ceilings: ParticipantCeilings,
    resource_grant: [u8; 32],
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    channel_id: String,
    channel_binding: [u8; 32],
    consent_scope: String,
    ancestors: Vec<Ancestor>,
}

/// Closed native compiler purpose; a source is protected journal provenance,
/// never a separate application map or a writer's current read authority.
#[derive(Clone, Copy)]
pub(super) enum ScopePurpose<'a> {
    Mutation,
    Content,
    Recovery(&'a EffectBinding),
    Disclosure {
        source: &'a EffectBinding,
        recipient: &'a str,
        channel: [u8; 32],
    },
}

impl ScopePurpose<'_> {
    fn source(&self) -> Option<&EffectBinding> {
        match self {
            Self::Recovery(source) | Self::Disclosure { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Scope {
    pub(super) fn created_lineage(&self) -> Option<&super::CreatedLineage> {
        match self {
            Self::Engagement { bound } => bound.lineage.as_ref(),
            Self::Unscoped => None,
        }
    }
    pub(super) fn creation_parent(
        &self,
    ) -> Result<([u8; 32], [u8; 32], u64, EnrollmentScopePins), EffectBindingError> {
        match self {
            Self::Engagement { bound }
                if bound.lineage.is_none()
                    && matches!(
                        bound.scope.resource,
                        crate::participant_enrollment::EnrollmentResourceBinding::Exact { .. }
                    ) =>
            {
                Ok((
                    bound.root,
                    bound.engagement,
                    bound.authority_epoch,
                    bound.scope.clone(),
                ))
            }
            _ => Err(EffectBindingError::Invalid),
        }
    }
    pub(super) fn prerequisite_reservations(
        &self,
    ) -> Result<Vec<super::EngagementReservation>, EffectBindingError> {
        let reservations = match self {
            Self::Unscoped => Vec::new(),
            Self::Engagement { bound } if bound.recipient.is_none() => {
                bound.reservations(Unit::AcquisitionCount, 1)?
            }
            Self::Engagement { .. } => return Err(EffectBindingError::Invalid),
        };
        let mut reservations: Vec<_> = reservations
            .into_iter()
            .map(|reservation| super::EngagementReservation {
                key: reservation.key,
                unit: reservation.unit,
                amount: reservation.amount,
                ceiling: reservation.ceiling,
            })
            .collect();
        reservations.sort_by_key(|r| (r.key, r.unit));
        Ok(reservations)
    }
    pub(super) fn compile(
        installed: &EffectInstallation<'_>,
        now: u64,
        invocation: EnrollmentInvocation<'_>,
        purpose: ScopePurpose<'_>,
    ) -> Result<Self, EffectBindingError> {
        let Some(policy) = installed.engagement else {
            if purpose
                .source()
                .is_some_and(|source| !matches!(source.wire.scope, Scope::Unscoped))
            {
                return Err(EffectBindingError::Invalid);
            }
            return Ok(Self::Unscoped);
        };
        let tree = installed.enrollment.ok_or(EffectBindingError::Invalid)?;
        let connection = commitment(
            "auths.effect-installation/1",
            &installed
                .connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        )?;
        let bound = EngagementScope::compile(
            installed, policy, tree, connection, now, invocation, &purpose,
        )?;
        let scope = Self::Engagement {
            bound: Box::new(bound),
        };
        if purpose
            .source()
            .is_some_and(|source| !scope.same_flow(&source.wire.scope))
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(scope)
    }
    pub(super) fn same_flow(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unscoped, Self::Unscoped) => true,
            (Self::Engagement { bound: a }, Self::Engagement { bound: b }) => {
                a.authority_namespace == b.authority_namespace
                    && a.authority_partition == b.authority_partition
                    && a.authority_epoch == b.authority_epoch
                    && a.engagement == b.engagement
                    && a.root == b.root
                    && a.scope.recipe_digest == b.scope.recipe_digest
                    && a.scope.connection_binding == b.scope.connection_binding
                    && a.scope.service == b.scope.service
                    && a.scope.resource == b.scope.resource
                    && a.lineage == b.lineage
            }
            _ => false,
        }
    }
    pub(super) fn reservations(
        &self,
        protocol: &Protocol,
    ) -> Result<Vec<Reservation>, EffectBindingError> {
        let Self::Engagement { bound } = self else {
            return Ok(Vec::new());
        };
        match protocol {
            Protocol::Mutation { .. } if bound.recipient.is_none() => {
                bound.reservations(Unit::MutationCount, 1)
            }
            Protocol::Acquisition { .. } if bound.recipient.is_none() => {
                bound.reservations(Unit::AcquisitionCount, 1)
            }
            Protocol::Disclosure {
                recipient,
                channel,
                maximum_bytes,
                ..
            } => {
                bound.validate_recipient(recipient, channel)?;
                let mut reservations = bound.reservations(Unit::DisclosureCount, 1)?;
                reservations.extend(bound.reservations(Unit::DisclosureBytes, *maximum_bytes)?);
                Ok(reservations)
            }
            _ => Err(EffectBindingError::Invalid),
        }
    }
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
    recipient: Option<Recipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lineage: Option<super::CreatedLineage>,
}

impl EngagementScope {
    #[allow(
        clippy::too_many_lines,
        reason = "one native scope projection binds independently verified actor and recipient paths"
    )]
    fn compile(
        installed: &EffectInstallation<'_>,
        policy: &EngagementPolicy,
        tree: &EnrollmentTree,
        connection: [u8; 32],
        now: u64,
        invocation: EnrollmentInvocation<'_>,
        purpose: &ScopePurpose<'_>,
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
            scope.recipe_digest == installed.recipe.digest_hex()
                && scope.connection_binding == connection
                && scope.service == service
                && scope.tool == tool
                && if let Some(source) = purpose.source() {
                    matches!(&source.wire.scope, Scope::Engagement { bound } if bound.scope.resource == scope.resource)
                } else {
                        let args = call.get("arguments");
                        let args = if matches!(purpose, ScopePurpose::Content) { args.and_then(|args| args.get("resource_arguments")) } else { args };
                        let handle=args.and_then(|args| args.get(&scope.resource_argument)).and_then(serde_json::Value::as_str);
                        match &scope.resource {
                            crate::participant_enrollment::EnrollmentResourceBinding::Exact {handle: expected} => handle==Some(expected.as_str()),
                            crate::participant_enrollment::EnrollmentResourceBinding::CreatedChild{..} => installed.lineages.iter().any(|lineage|
                                lineage.admits(&policy.root,scope) && handle==Some(lineage.resource.as_str())),
                        }
                }
        });
        let scope = matches.next().ok_or(EffectBindingError::Invalid)?;
        if matches.next().is_some() {
            return Err(EffectBindingError::Invalid);
        }
        let lineage = if matches!(
            scope.resource,
            crate::participant_enrollment::EnrollmentResourceBinding::CreatedChild { .. }
        ) {
            let mut matches = installed
                .lineages
                .iter()
                .filter(|lineage| lineage.admits(&policy.root, scope));
            let lineage = matches.next().ok_or(EffectBindingError::Invalid)?;
            if matches.next().is_some()
                || purpose
                    .source()
                    .is_some_and(|source| source.created_lineage() != Some(lineage))
            {
                return Err(EffectBindingError::Invalid);
            }
            Some(lineage.clone())
        } else {
            None
        };
        let participant = match (lineage.as_ref(), purpose.source()) {
            (Some(lineage), source) => tree.verify_created_scope(
                installed.context,
                &scope.scope_id,
                now,
                &invocation,
                lineage,
                source.map(|_| &scope.resource),
            ),
            (None, Some(_)) => tree.verify_compiled_scope(
                installed.context,
                &scope.scope_id,
                now,
                &invocation,
                &scope.resource,
            ),
            (None, None) => {
                tree.verify_operation_scope(installed.context, &scope.scope_id, now, &invocation)
            }
        }
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
                    capacity_enrollment: tree
                        .capacity_origin(pins.enrollment_commitment)
                        .map_err(|_| EffectBindingError::Invalid)?,
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
            schema: "auths.effect-engagement-scope/3".to_owned(),
            authority_namespace: policy.root.admission_namespace.clone(),
            authority_partition: policy.root.admission_partition.clone(),
            authority_epoch: policy.root.partition_generation,
            engagement: policy.root.engagement_commitment,
            root: policy.root.enrollment_commitment,
            executor: policy.executor.clone(),
            scope: scope.clone(),
            lineage,
            ancestors,
            recipient: match purpose {
                ScopePurpose::Disclosure {
                    recipient, channel, ..
                } => {
                    let principal = auths_model::PrincipalId::parse(recipient)
                        .map_err(|_| EffectBindingError::Invalid)?;
                    let (channel_id, path) = tree
                        .delivery_path(
                            &principal,
                            channel,
                            &scope.resource,
                            &scope.recipe_digest,
                            &connection,
                            now,
                        )
                        .map_err(|_| EffectBindingError::Invalid)?;
                    let consent_scope = path
                        .last()
                        .and_then(|pins| {
                            pins.scopes.iter().find(|candidate| {
                                candidate.resource == scope.resource
                                    && candidate.recipe_digest == scope.recipe_digest
                                    && candidate.connection_binding == connection
                            })
                        })
                        .map(|scope| scope.scope_id.clone())
                        .ok_or(EffectBindingError::Invalid)?;
                    let ancestors = path
                        .iter()
                        .map(|pins| {
                            let grant = pins
                                .scopes
                                .iter()
                                .find(|scope| scope.scope_id == consent_scope)
                                .ok_or(EffectBindingError::Invalid)?;
                            Ok(Ancestor {
                                enrollment: pins.enrollment_commitment,
                                capacity_enrollment: tree
                                    .capacity_origin(pins.enrollment_commitment)
                                    .map_err(|_| EffectBindingError::Invalid)?,
                                principal: pins.principal.as_str().to_owned(),
                                instance: pins.instance_generation,
                                not_before: pins.not_before,
                                expires_at: pins.expires_at,
                                ceilings: pins.ceilings,
                                resource_grant: *grant.parent_grant.as_bytes(),
                            })
                        })
                        .collect::<Result<Vec<_>, EffectBindingError>>()?;
                    Some(Recipient {
                        channel_id,
                        channel_binding: *channel,
                        consent_scope,
                        ancestors,
                    })
                }
                _ => None,
            },
        };
        result.validate()?;
        Ok(result)
    }

    pub(super) fn validate(&self) -> Result<(), EffectBindingError> {
        use crate::participant_enrollment::{MAX_JSON_INTEGER, MAX_PARTICIPANTS, identifier};
        if self.schema != "auths.effect-engagement-scope/3"
            || crate::OperatorNamespace::parse(&self.authority_namespace).is_err()
            || !identifier(&self.authority_partition)
            || !super::label(&self.executor)
            || !(1..=MAX_JSON_INTEGER).contains(&self.authority_epoch)
            || self.ancestors.is_empty()
            || self.ancestors.len() > MAX_PARTICIPANTS
            || self.ancestors[0].enrollment != self.root
            || self.ancestors[0].capacity_enrollment != self.root
            || self.ancestors[0].resource_grant != *self.scope.parent_grant.as_bytes()
            || !identifier(&self.scope.scope_id)
            || !identifier(&self.scope.resource_argument)
            || !identifier(&self.scope.service)
            || !identifier(&self.scope.tool)
            || crate::control_namespace::is_control_service(&self.scope.service)
            || !self.scope.resource.valid()
            || match (&self.scope.resource, &self.lineage) {
                (crate::participant_enrollment::EnrollmentResourceBinding::Exact { .. }, None) => {
                    false
                }
                (
                    crate::participant_enrollment::EnrollmentResourceBinding::CreatedChild {
                        ..
                    },
                    Some(lineage),
                ) => {
                    lineage.validate().is_err()
                        || lineage.root != self.root
                        || lineage.engagement != self.engagement
                        || lineage.authority_epoch != self.authority_epoch
                        || lineage.connection != self.scope.connection_binding
                        || !lineage.matches_resource(&self.scope.resource)
                }
                _ => true,
            }
            || crate::participant_enrollment::resource_audience(
                &self.engagement,
                self.authority_epoch,
                &self.scope.recipe_digest,
            )
            .is_err()
        {
            return Err(EffectBindingError::Invalid);
        }
        validate_path(&self.ancestors)?;
        if let Some(recipient) = &self.recipient {
            if !identifier(&recipient.channel_id)
                || !identifier(&recipient.consent_scope)
                || recipient
                    .ancestors
                    .first()
                    .is_none_or(|ancestor| ancestor.enrollment != self.root)
            {
                return Err(EffectBindingError::Invalid);
            }
            validate_path(&recipient.ancestors)?;
            for node in &recipient.ancestors {
                for actor in &self.ancestors {
                    if node.enrollment == actor.enrollment {
                        if !same_identity(node, actor) {
                            return Err(EffectBindingError::Invalid);
                        }
                    } else {
                        if node.capacity_enrollment == actor.capacity_enrollment {
                            return Err(EffectBindingError::Invalid);
                        }
                        let node = auths_model::PrincipalId::parse(&node.principal)
                            .map_err(|_| EffectBindingError::Invalid)?;
                        let actor = auths_model::PrincipalId::parse(&actor.principal)
                            .map_err(|_| EffectBindingError::Invalid)?;
                        if crate::principals_overlap(&node, &actor) {
                            return Err(EffectBindingError::Invalid);
                        }
                    }
                }
            }
            if self.exposure_ancestors().len() > MAX_PARTICIPANTS {
                return Err(EffectBindingError::Invalid);
            }
        }
        Ok(())
    }

    fn exposure_ancestors(&self) -> Vec<&Ancestor> {
        let mut nodes: Vec<_> = self.ancestors.iter().collect();
        if let Some(recipient) = &self.recipient {
            for node in &recipient.ancestors {
                if !nodes
                    .iter()
                    .any(|existing| existing.enrollment == node.enrollment)
                {
                    nodes.push(node);
                }
            }
        }
        nodes
    }
    fn validate_recipient(
        &self,
        recipient: &str,
        channel: &[u8; 32],
    ) -> Result<(), EffectBindingError> {
        let registered = self.recipient.as_ref().ok_or(EffectBindingError::Invalid)?;
        let leaf = registered
            .ancestors
            .last()
            .ok_or(EffectBindingError::Invalid)?;
        let expected = auths_model::PrincipalId::parse(&leaf.principal)
            .map_err(|_| EffectBindingError::Invalid)?;
        let recipient =
            auths_model::PrincipalId::parse(recipient).map_err(|_| EffectBindingError::Invalid)?;
        if &registered.channel_binding != channel
            || !crate::principals_overlap(&expected, &recipient)
        {
            return Err(EffectBindingError::Invalid);
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
        let nodes = if matches!(unit, Unit::DisclosureCount | Unit::DisclosureBytes) {
            self.exposure_ancestors()
        } else {
            self.ancestors.iter().collect()
        };
        nodes
            .into_iter()
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
                            ancestor.capacity_enrollment,
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

fn same_identity(a: &Ancestor, b: &Ancestor) -> bool {
    a.enrollment == b.enrollment
        && a.capacity_enrollment == b.capacity_enrollment
        && a.principal == b.principal
        && a.instance == b.instance
        && a.not_before == b.not_before
        && a.expires_at == b.expires_at
        && a.ceilings == b.ceilings
}
fn validate_path(ancestors: &[Ancestor]) -> Result<(), EffectBindingError> {
    use crate::participant_enrollment::{MAX_JSON_INTEGER, MAX_PARTICIPANTS};
    if ancestors.is_empty() || ancestors.len() > MAX_PARTICIPANTS {
        return Err(EffectBindingError::Invalid);
    }
    for (index, ancestor) in ancestors.iter().enumerate() {
        let principal = auths_model::PrincipalId::parse(&ancestor.principal)
            .map_err(|_| EffectBindingError::Invalid)?;
        if !(1..=MAX_JSON_INTEGER).contains(&ancestor.instance)
            || ancestor.not_before >= ancestor.expires_at
            || ancestor.expires_at > MAX_JSON_INTEGER
            || !ancestor.ceilings.within(ancestor.ceilings)
            || ancestors[..index].iter().any(|previous| {
                previous.enrollment == ancestor.enrollment
                    || previous.capacity_enrollment == ancestor.capacity_enrollment
                    || previous.resource_grant == ancestor.resource_grant
                    || auths_model::PrincipalId::parse(&previous.principal)
                        .map_or(true, |p| crate::principals_overlap(&p, &principal))
            })
            || index.checked_sub(1).is_some_and(|parent| {
                let parent = &ancestors[parent];
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
