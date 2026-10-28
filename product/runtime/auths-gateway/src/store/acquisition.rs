//! Typed recovery acquisitions in the existing operation journal. Permanent
//! allocation slots, the source operation and current entry dependencies share
//! the same adapter fence. No stored grant can recreate a read permit.

use super::*;
use crate::effect::{
    AcquisitionCapacity, AcquisitionPlan, ClosedPrerequisiteRead, PrerequisiteKind,
};

mod recovery;
pub(super) use recovery::RecoveryEvidenceLink;
pub use recovery::{
    GatewayRecoveryReport, RecoveryDisposition, RecoverySnapshot, RecoverySourceFacts,
};

const ALLOCATION_SCHEMA: &str = "auths.effect-allocation/1";

/// Public facts about a bounded acquisition, with no content or private digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcquisitionSnapshot {
    /// Durable journal revision.
    pub revision: u64,
    /// A recovered grant projects unknown, never a fresh permit.
    pub stage: AcquisitionStage,
    /// Permanently allocated invocation units, including uncertain entry.
    pub reserved_calls: u64,
    /// Permanently allocated response-byte ceiling.
    pub reserved_bytes: u64,
    /// Recorded HTTP status; it is not a mutation outcome or disclosure ACK.
    pub response_status: Option<u16>,
    /// Bounded received byte count, without the content or its commitment.
    pub response_bytes: Option<u64>,
    /// Whether required response-version headers matched the installed recipe.
    pub response_version_ok: Option<bool>,
}

/// Acquisition has no mutation-observed or disclosure-acknowledged state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionStage {
    /// Capacity held; no provider permit.
    Reserved,
    /// A durable grant exists; execution may have occurred.
    EntryGranted,
    /// No grant was issued.
    NotEntered,
    /// A grant exists without a recorded response.
    Unknown,
    /// A provider response is retained privately.
    ResponseRecorded,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquisitionState {
    plan: AcquisitionPlan,
    allocation: Option<u64>,
    phase: AcquisitionPhase,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "kebab-case", deny_unknown_fields)]
enum AcquisitionPhase {
    Reserved,
    EntryGranted,
    NotEntered { code: String },
    Unknown,
    ResponseRecorded { response: AcquisitionResponse },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionResponse {
    status: u16,
    version_ok: bool,
    body_b64: String,
    received_at: u64,
}

impl AcquisitionPhase {
    const fn kernel(&self) -> transition::Stage {
        match self {
            Self::Reserved => transition::Stage::Reserved,
            Self::EntryGranted => transition::Stage::EntryGranted,
            Self::NotEntered { .. } => transition::Stage::NotEntered,
            Self::Unknown => transition::Stage::Unknown,
            Self::ResponseRecorded { .. } => transition::Stage::ResponseRecorded,
        }
    }
}

impl JournalProtocol for AcquisitionState {
    fn wrap(self) -> ProtocolState {
        ProtocolState::Acquisition(self)
    }

    fn extract(state: ProtocolState) -> Result<Self, GatewayAttemptError> {
        match state {
            ProtocolState::Acquisition(state) => Ok(state),
            ProtocolState::Mutation(_) => Err(GatewayAttemptError::BindingConflict),
        }
    }

    fn view(record: &Record<Self>) -> Result<AttemptView, GatewayAttemptError> {
        Ok(AttemptView {
            protocol: transition::Protocol::Acquisition,
            revision: record.revision,
            fixed: canonical(&(
                &record.schema,
                &record.binding_canonical,
                &record.approval_canonical,
                &record.namespace,
                &record.operation_id,
                &record.action_commitment,
                &record.recipe_digest,
                &record.nonce,
                record.evaluated_at,
                &record.state.plan,
                record.state.allocation,
            ))?,
            entry: record
                .entry
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            stage: record.state.phase.kernel(),
            refusal: matches!(record.state.phase, AcquisitionPhase::NotEntered { .. }),
            response: match &record.state.phase {
                AcquisitionPhase::ResponseRecorded { response } => canonical(response)?,
                _ => Vec::new(),
            },
            pre_entry: Vec::new(),
            locator: Vec::new(),
            reading: Reading::None,
            evidence: false,
            observation: false,
            link: Link::None,
        })
    }

    fn validate(record: &Record<Self>) -> Result<(), GatewayAttemptError> {
        let binding = record.validate_header()?;
        let capacity = record
            .state
            .plan
            .validate(&binding)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        if !transition::consistent(&Self::view(record)?)
            || record
                .entry
                .as_ref()
                .is_some_and(|entry| entry.pre_entry.is_some())
            || match record.state.allocation {
                Some(slot) => slot >= capacity.attempts,
                None => !matches!(record.state.phase, AcquisitionPhase::NotEntered { .. }),
            }
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        match &record.state.phase {
            AcquisitionPhase::NotEntered { code } if !valid_code(code) => {
                return Err(GatewayAttemptError::Corrupt);
            }
            AcquisitionPhase::ResponseRecorded { response } => {
                let body = response.body(&capacity)?;
                let entry = record.entry.as_ref().ok_or(GatewayAttemptError::Corrupt)?;
                if response.received_at < entry.granted_at
                    || response.received_at > MAX_JSON_INTEGER
                    || !(100..=599).contains(&response.status)
                    || body.len() > MAX_EVIDENCE_BYTES
                {
                    return Err(GatewayAttemptError::Corrupt);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl AcquisitionResponse {
    fn body(&self, capacity: &AcquisitionCapacity) -> Result<Vec<u8>, GatewayAttemptError> {
        if self.body_b64.len() > MAX_EVIDENCE_BYTES.div_ceil(3) * 4 {
            return Err(GatewayAttemptError::Corrupt);
        }
        let body = Base64::decode_vec(&self.body_b64).map_err(|_| GatewayAttemptError::Corrupt)?;
        if body.len() as u64 > capacity.maximum_bytes
            || Base64::encode_string(&body) != self.body_b64
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(body)
    }
}

impl Record<AcquisitionState> {
    pub(super) fn snapshot(&self) -> Result<AcquisitionSnapshot, GatewayAttemptError> {
        AcquisitionState::validate(self)?;
        let capacity = self
            .state
            .plan
            .capacity()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let (stage, response_status, response_bytes) = match &self.state.phase {
            AcquisitionPhase::Reserved => (AcquisitionStage::Reserved, None, None),
            AcquisitionPhase::EntryGranted | AcquisitionPhase::Unknown => {
                (AcquisitionStage::Unknown, None, None)
            }
            AcquisitionPhase::NotEntered { .. } => (AcquisitionStage::NotEntered, None, None),
            AcquisitionPhase::ResponseRecorded { response } => (
                AcquisitionStage::ResponseRecorded,
                Some(response.status),
                Some(response.body(&capacity)?.len() as u64),
            ),
        };
        Ok(AcquisitionSnapshot {
            revision: self.revision,
            stage,
            reserved_calls: u64::from(self.state.allocation.is_some()),
            reserved_bytes: if self.state.allocation.is_some() {
                capacity.maximum_bytes
            } else {
                0
            },
            response_status,
            response_bytes,
            response_version_ok: match &self.state.phase {
                AcquisitionPhase::ResponseRecorded { response } => Some(response.version_ok),
                _ => None,
            },
        })
    }
}

/// One immutable slot charges both distinct units at the same atomic admission.
/// Every read of this source has the same native maximum, so slot i holds one
/// call and that maximum, and cumulative bytes are (i + 1) * maximum. No expiry.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    schema: String,
    claim: String,
    source: String,
    count_key: String,
    bytes_key: String,
    slot: u64,
    calls: u64,
    bytes: u64,
}

impl Allocation {
    fn new(
        plan: &AcquisitionPlan,
        key: GatewayAttemptKey,
        slot: u64,
    ) -> Result<Self, GatewayAttemptError> {
        let source = plan.source().map_err(|_| GatewayAttemptError::Corrupt)?;
        let capacity = plan.capacity().map_err(|_| GatewayAttemptError::Corrupt)?;
        if slot >= capacity.attempts {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        Ok(Self {
            schema: ALLOCATION_SCHEMA.to_owned(),
            claim: hex::encode(key.as_bytes()),
            source: hex::encode(source.id().as_bytes()),
            count_key: hex::encode(capacity.count_key),
            bytes_key: hex::encode(capacity.bytes_key),
            slot,
            calls: 1,
            bytes: capacity.maximum_bytes,
        })
    }
}

fn allocation_key(capacity: &AcquisitionCapacity, slot: u64) -> GatewayAttemptKey {
    GatewayAttemptKey(crate::bounds::count_slot_key(&capacity.count_key, slot))
}

/// Admission reserves capacity but grants no provider capability.
pub enum AcquisitionClaim {
    /// An equal reservation can resume only through fresh fenced authorization.
    Reserved(Box<ReservedAcquisition>),
    /// Existing immutable facts; no provider or custody call is warranted.
    Existing(AcquisitionSnapshot),
}

/// A typed handle to the same durable journal used for mutations.
pub struct ReservedAcquisition {
    attempt: Attempt<AcquisitionState>,
    source_key: GatewayAttemptKey,
}

pub(crate) struct PrerequisiteResponse {
    pub(crate) kind: PrerequisiteKind,
    pub(crate) response: crate::transport::ProviderResponse,
    pub(crate) received_at: u64,
    pub(crate) observed_at: u64,
}

impl Record<AcquisitionState> {
    fn prerequisite_response(&self, now: u64) -> Result<PrerequisiteResponse, GatewayAttemptError> {
        let AcquisitionPlan::Prerequisite(plan) = &self.state.plan else {
            return Err(GatewayAttemptError::BindingConflict);
        };
        let AcquisitionPhase::ResponseRecorded { response } = &self.state.phase else {
            return Err(GatewayAttemptError::InvalidTransition);
        };
        // The response can describe state sampled before receipt. Use the
        // grant's earlier time for evidence freshness; preserve receipt time
        // separately rather than refreshing either during replay.
        let observed_at = self
            .entry
            .as_ref()
            .ok_or(GatewayAttemptError::Corrupt)?
            .granted_at;
        if now < response.received_at
            || !now
                .checked_sub(observed_at)
                .is_some_and(|age| age <= crate::effect::MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS)
        {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let capacity = self
            .state
            .plan
            .capacity()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        Ok(PrerequisiteResponse {
            kind: plan.kind().map_err(|_| GatewayAttemptError::Corrupt)?,
            response: crate::transport::ProviderResponse {
                status: response.status,
                version_ok: response.version_ok,
                body: response.body(&capacity)?,
            },
            received_at: response.received_at,
            observed_at,
        })
    }
}

impl GatewayAttempts {
    pub(crate) async fn read_prerequisite(
        &self,
        approved: &ApprovedEffect,
        kind: PrerequisiteKind,
        now: u64,
    ) -> Result<PrerequisiteResponse, GatewayAttemptError> {
        let (plan, _) = approved
            .prerequisite(kind)
            .map_err(|_| GatewayAttemptError::BindingConflict)?;
        let binding = approved.effect().binding();
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let (namespace, operation, _, _) = binding.journal_identity();
        let parent = self.key(
            &OperatorNamespace::parse(namespace).map_err(|_| GatewayAttemptError::Corrupt)?,
            &LogicalOperationId::parse(operation).map_err(|_| GatewayAttemptError::Corrupt)?,
        )?;
        let key = prerequisite_key(parent, plan.index());
        let store = Arc::clone(&self.store);
        let bytes = blocking(move || store.load(GatewayRecordKind::Attempt, &key))
            .await?
            .ok_or(GatewayAttemptError::Unavailable)?;
        let record: Record<AcquisitionState> = decode_as(&bytes)?;
        if record.validate_header()? != *binding
            || record.state.plan != AcquisitionPlan::Prerequisite(plan)
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        record.prerequisite_response(now)
    }

    /// Returns retained facts for this exact approved read, without any I/O
    /// outside the journal. A stored grant projects unknown, never a permit.
    ///
    /// # Errors
    /// Refuses a different protocol, operation binding or installed partition,
    /// and corrupt/unavailable state.
    pub async fn read_recovery(
        &self,
        approved: &ApprovedEffect,
    ) -> Result<Option<AcquisitionSnapshot>, GatewayAttemptError> {
        if approved.recovery_target().is_none()
            || !self.policy.contains(approved.effect().binding())
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let binding = approved.effect().binding();
        let (namespace, operation, _, _) = binding.journal_identity();
        let key = self.key(
            &OperatorNamespace::parse(namespace).map_err(|_| GatewayAttemptError::Corrupt)?,
            &LogicalOperationId::parse(operation).map_err(|_| GatewayAttemptError::Corrupt)?,
        )?;
        let store = Arc::clone(&self.store);
        let Some(bytes) = blocking(move || store.load(GatewayRecordKind::Attempt, &key)).await?
        else {
            return Ok(None);
        };
        let record: Record<AcquisitionState> = decode_as(&bytes)?;
        if record.binding_canonical.as_bytes()
            != binding
                .to_private_bytes()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .as_slice()
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        record.snapshot().map(Some)
    }

    /// Atomically admits one recovery read and its permanent count/byte slot.
    /// Equal reservations reopen without charging twice; post-grant replay is
    /// history only. Changed bindings under any protocol conflict.
    ///
    /// # Errors
    /// Refuses non-acquisitions, changed source/partition, invalid approval and
    /// corrupt or unavailable state. No error can return a transport permit.
    pub(crate) async fn claim_recovery(
        &self,
        approved: &Arc<ApprovedEffect>,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<AcquisitionClaim, GatewayAttemptError> {
        let target = approved
            .recovery_target()
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        let plan = AcquisitionPlan::Recovery(
            target
                .journal_plan()
                .map_err(|_| GatewayAttemptError::Corrupt)?,
        );
        self.claim_acquisition(approved, plan, evaluated_at, validation)
            .await
    }

    pub(crate) async fn claim_prerequisite(
        &self,
        approved: &Arc<ApprovedEffect>,
        kind: PrerequisiteKind,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<AcquisitionClaim, GatewayAttemptError> {
        let (plan, _) = approved
            .prerequisite(kind)
            .map_err(|_| GatewayAttemptError::BindingConflict)?;
        self.claim_acquisition(
            approved,
            AcquisitionPlan::Prerequisite(plan),
            evaluated_at,
            validation,
        )
        .await
    }

    async fn claim_acquisition(
        &self,
        approved: &Arc<ApprovedEffect>,
        plan: AcquisitionPlan,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<AcquisitionClaim, GatewayAttemptError> {
        let binding = approved.effect().binding();
        let capacity = plan
            .validate(binding)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let (namespace, operation, _, _) = binding.journal_identity();
        let namespace =
            OperatorNamespace::parse(namespace).map_err(|_| GatewayAttemptError::Corrupt)?;
        let operation =
            LogicalOperationId::parse(operation).map_err(|_| GatewayAttemptError::Corrupt)?;
        let key = self.key(&namespace, &operation)?;
        let source = plan.source().map_err(|_| GatewayAttemptError::Corrupt)?;
        let source_operation = LogicalOperationId::parse(source.journal_identity().1)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let source_key = self.key(&namespace, &source_operation)?;
        let key = match &plan {
            AcquisitionPlan::Recovery(_) => key,
            AcquisitionPlan::Prerequisite(plan) => prerequisite_key(source_key, plan.index()),
        };
        let expected_plan = plan.clone();
        let expected = String::from_utf8(
            binding
                .to_private_bytes()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .to_vec(),
        )
        .map_err(|_| GatewayAttemptError::Corrupt)?;
        let store = Arc::clone(&self.store);
        let admission = Admission {
            approved: Arc::clone(approved),
            validation,
            authorization_started_at: evaluated_at,
        };
        let mut dependencies = vec![(GatewayRecordKind::Attempt, source_key)];
        dependencies.extend(admission.dependencies());
        let reserved = blocking(move || {
            if store.load(GatewayRecordKind::Attempt, &key)?.is_some() {
                return Err(existing_binding(&*store, key, &expected));
            }
            let base = Record::new(
                admission.approved.effect().binding(),
                admission.approved.approval(),
                evaluated_at,
                AcquisitionState {
                    plan,
                    allocation: None,
                    phase: AcquisitionPhase::Reserved,
                },
            )?;
            base.validate_header()?;
            for slot in 0..capacity.attempts {
                let mut record = base.clone();
                record.state.allocation = Some(slot);
                AcquisitionState::validate(&record)?;
                let stored = encode(&record)?;
                let allocation = Allocation::new(&record.state.plan, key, slot)?;
                let entries = [
                    GatewayRecordEntry {
                        kind: GatewayRecordKind::Attempt,
                        key,
                        record: stored.clone(),
                        expires_at: None,
                    },
                    GatewayRecordEntry {
                        kind: GatewayRecordKind::EffectAllocation,
                        key: allocation_key(&capacity, slot),
                        record: canonical(&allocation)?,
                        expires_at: None,
                    },
                ];
                match insert_acquisition(
                    &*store,
                    &mut record,
                    &entries,
                    &dependencies,
                    &admission,
                    source_key,
                    key,
                )? {
                    GatewayInsert::Inserted => {
                        let stored = encode(&record)?;
                        return Ok((record, stored));
                    }
                    GatewayInsert::Exists { index: 0 } => {
                        return Err(existing_binding(&*store, key, &base.binding_canonical));
                    }
                    GatewayInsert::Exists { index: 1 } => {}
                    GatewayInsert::Exists { .. } => return Err(GatewayAttemptError::Corrupt),
                }
            }
            let mut record = base;
            record.state.phase = AcquisitionPhase::NotEntered {
                code: "gateway.acquisition.exhausted".to_owned(),
            };
            AcquisitionState::validate(&record)?;
            let stored = encode(&record)?;
            let entries = [GatewayRecordEntry {
                kind: GatewayRecordKind::Attempt,
                key,
                record: stored,
                expires_at: None,
            }];
            match insert_acquisition(
                &*store,
                &mut record,
                &entries,
                &dependencies,
                &admission,
                source_key,
                key,
            )? {
                GatewayInsert::Inserted => {
                    let stored = encode(&record)?;
                    Ok((record, stored))
                }
                GatewayInsert::Exists { .. } => {
                    Err(existing_binding(&*store, key, &record.binding_canonical))
                }
            }
        })
        .await;
        let (record, stored) = match reserved {
            Ok(value) => value,
            Err(GatewayAttemptError::Replay) => {
                let store = Arc::clone(&self.store);
                let bytes = blocking(move || store.load(GatewayRecordKind::Attempt, &key))
                    .await?
                    .ok_or(GatewayAttemptError::Unavailable)?;
                let record: Record<AcquisitionState> = decode_as(&bytes)?;
                if record.state.plan != expected_plan
                    || record.binding_canonical.as_bytes()
                        != binding
                            .to_private_bytes()
                            .map_err(|_| GatewayAttemptError::Corrupt)?
                            .as_slice()
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                (record, bytes)
            }
            Err(error) => return Err(error),
        };
        if matches!(record.state.phase, AcquisitionPhase::Reserved) {
            Ok(AcquisitionClaim::Reserved(Box::new(ReservedAcquisition {
                source_key,
                attempt: Attempt {
                    store: Arc::clone(&self.store),
                    key,
                    stored,
                    record,
                },
            })))
        } else {
            Ok(AcquisitionClaim::Existing(record.snapshot()?))
        }
    }
}

impl ReservedAcquisition {
    /// Inspects the reservation without granting entry or reading a provider.
    ///
    /// # Errors
    /// Refuses malformed retained facts.
    pub fn snapshot(&self) -> Result<AcquisitionSnapshot, GatewayAttemptError> {
        self.attempt.record.snapshot()
    }

    pub(crate) async fn grant_entry(
        self,
        approved: Arc<ApprovedEffect>,
        validation: crate::entry::EntryValidation,
        authorization_started_at: u64,
    ) -> Result<(GrantedAcquisition, AcquisitionEntryPermit), GatewayAttemptError> {
        let (plan, request) = match &self.attempt.record.state.plan {
            AcquisitionPlan::Recovery(_) => {
                let target = approved
                    .recovery_target()
                    .ok_or(GatewayAttemptError::InvalidTransition)?;
                (
                    AcquisitionPlan::Recovery(
                        target
                            .journal_plan()
                            .map_err(|_| GatewayAttemptError::Corrupt)?,
                    ),
                    AcquisitionRequest::Recovery(target.closed_request().clone()),
                )
            }
            AcquisitionPlan::Prerequisite(plan) => {
                let kind = plan.kind().map_err(|_| GatewayAttemptError::Corrupt)?;
                let (plan, read) = approved
                    .prerequisite(kind)
                    .map_err(|_| GatewayAttemptError::BindingConflict)?;
                (
                    AcquisitionPlan::Prerequisite(plan),
                    AcquisitionRequest::Prerequisite(read),
                )
            }
        };
        blocking(move || {
            let mut attempt = self.attempt;
            let capacity = plan.capacity().map_err(|_| GatewayAttemptError::Corrupt)?;
            let slot = attempt
                .record
                .state
                .allocation
                .ok_or(GatewayAttemptError::Corrupt)?;
            let dependencies = validation.dependencies();
            let mut keys = vec![
                (GatewayRecordKind::Attempt, attempt.key),
                (GatewayRecordKind::Attempt, self.source_key),
                (
                    GatewayRecordKind::EffectAllocation,
                    allocation_key(&capacity, slot),
                ),
            ];
            keys.extend_from_slice(&dependencies);
            let mut committed = None;
            attempt.store.fenced_replace(&keys, &mut |snapshots| {
                if snapshots.len() != keys.len()
                    || snapshots[0].as_deref() != Some(attempt.stored.as_slice())
                {
                    return Err(GatewayAttemptError::Conflict);
                }
                let current: Record<AcquisitionState> = decode_as(
                    snapshots[0]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?,
                )?;
                if !matches!(current.state.phase, AcquisitionPhase::Reserved)
                    || current.state.plan != plan
                    || current.binding_canonical.as_bytes()
                        != approved
                            .effect()
                            .binding()
                            .to_private_bytes()
                            .map_err(|_| GatewayAttemptError::Corrupt)?
                            .as_slice()
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                let source = decode(
                    snapshots[1]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?,
                )?;
                let source_matches = eligible_source(&plan, &source, self.source_key, attempt.key)?;
                if !source_matches
                    || snapshots[2].as_deref()
                        != Some(canonical(&Allocation::new(&plan, attempt.key, slot)?)?.as_slice())
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                let now = validation
                    .validate(&approved, &snapshots[3..], authorization_started_at)
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                let mut next = current.clone();
                next.record_grant(
                    &approved,
                    authorization_started_at,
                    now,
                    None,
                    &snapshots[1..],
                )?;
                next.state.phase = AcquisitionPhase::EntryGranted;
                if !valid_transition(&current, &next)? {
                    return Err(GatewayAttemptError::InvalidTransition);
                }
                let bytes = encode(&next)?;
                committed = Some((next, bytes.clone()));
                Ok(bytes)
            })?;
            let (record, stored) = committed.ok_or(GatewayAttemptError::Unavailable)?;
            attempt.record = record;
            attempt.stored = stored;
            Ok((
                GrantedAcquisition { attempt },
                AcquisitionEntryPermit {
                    _approved: approved,
                    request,
                },
            ))
        })
        .await
    }
}

pub(crate) enum AcquisitionRequest {
    Recovery(ClosedObservationRequest),
    Prerequisite(ClosedPrerequisiteRead),
}

pub(crate) struct AcquisitionEntryPermit {
    _approved: Arc<ApprovedEffect>,
    request: AcquisitionRequest,
}

impl AcquisitionEntryPermit {
    pub(crate) fn request(&self) -> &AcquisitionRequest {
        &self.request
    }
}

pub(crate) struct GrantedAcquisition {
    attempt: Attempt<AcquisitionState>,
}

impl GrantedAcquisition {
    pub(crate) async fn record_unknown(self) -> Result<AcquisitionSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.phase = AcquisitionPhase::Unknown;
        self.attempt.advance(next).await?.record.snapshot()
    }

    pub(crate) async fn record_response(
        self,
        status: u16,
        version_ok: bool,
        bytes: &[u8],
        received_at: u64,
    ) -> Result<AcquisitionSnapshot, GatewayAttemptError> {
        let capacity = self
            .attempt
            .record
            .state
            .plan
            .capacity()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        if bytes.len() as u64 > capacity.maximum_bytes || !(100..=599).contains(&status) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = self.attempt.record.clone();
        next.state.phase = AcquisitionPhase::ResponseRecorded {
            response: AcquisitionResponse {
                status,
                version_ok,
                body_b64: Base64::encode_string(bytes),
                received_at,
            },
        };
        self.attempt.advance(next).await?.record.snapshot()
    }
}

/// Component identity deliberately excludes the effect digest: changing the
/// approval under the same logical operation and ordinal must conflict.
pub(super) fn prerequisite_key(parent: GatewayAttemptKey, index: u8) -> GatewayAttemptKey {
    let mut hash = Sha256::new();
    hash.update(b"auths.gateway-prerequisite-key/1\0");
    hash.update(parent.as_bytes());
    hash.update([index]);
    GatewayAttemptKey(hash.finalize().into())
}

/// Final mutation entry observes exactly these child records and permanent
/// allocations under the same writer fence as its authority and mutation slots.
pub(super) fn prerequisite_dependencies(
    parent: GatewayAttemptKey,
    plans: &[crate::effect::PrerequisitePlan],
) -> Result<Vec<(GatewayRecordKind, GatewayAttemptKey)>, GatewayAttemptError> {
    let mut keys = Vec::with_capacity(plans.len() * 2);
    for plan in plans {
        let capacity = plan.capacity().map_err(|_| GatewayAttemptError::Corrupt)?;
        keys.push((
            GatewayRecordKind::Attempt,
            prerequisite_key(parent, plan.index()),
        ));
        keys.push((
            GatewayRecordKind::EffectAllocation,
            allocation_key(&capacity, 0),
        ));
    }
    Ok(keys)
}

pub(super) fn validate_prerequisites(
    parent: GatewayAttemptKey,
    binding: &EffectBinding,
    plans: &[crate::effect::PrerequisitePlan],
    snapshots: &[Option<Vec<u8>>],
    now: u64,
) -> Result<Vec<PrerequisiteResponse>, GatewayAttemptError> {
    if snapshots.len() != plans.len() * 2 {
        return Err(GatewayAttemptError::Corrupt);
    }
    let mut evidence = Vec::with_capacity(plans.len());
    for (plan, rows) in plans.iter().zip(snapshots.chunks_exact(2)) {
        let record: Record<AcquisitionState> =
            decode_as(rows[0].as_deref().ok_or(GatewayAttemptError::Corrupt)?)?;
        let expected = AcquisitionPlan::Prerequisite(plan.clone());
        let key = prerequisite_key(parent, plan.index());
        if record.validate_header()? != *binding
            || record.state.plan != expected
            || record.state.allocation != Some(0)
            || rows[1].as_deref()
                != Some(canonical(&Allocation::new(&expected, key, 0)?)?.as_slice())
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        evidence.push(record.prerequisite_response(now)?);
    }
    Ok(evidence)
}

fn eligible_source(
    plan: &AcquisitionPlan,
    source: &Record,
    source_key: GatewayAttemptKey,
    key: GatewayAttemptKey,
) -> Result<bool, GatewayAttemptError> {
    Ok(match plan {
        AcquisitionPlan::Recovery(plan) => {
            source
                .recovery_target()?
                .journal_plan()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                == *plan
        }
        AcquisitionPlan::Prerequisite(plan) => {
            source.state.stage == GatewayAttemptStage::Reserved
                && source.entry.is_none()
                && source.validate_header()?
                    == plan.source().map_err(|_| GatewayAttemptError::Corrupt)?
                && key == prerequisite_key(source_key, plan.index())
        }
    })
}

fn insert_acquisition(
    store: &dyn GatewayAttemptStore,
    record: &mut Record<AcquisitionState>,
    entries: &[GatewayRecordEntry],
    dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
    admission: &Admission,
    source_key: GatewayAttemptKey,
    key: GatewayAttemptKey,
) -> Result<GatewayInsert, GatewayAttemptError> {
    store.fenced_insert_all(entries, dependencies, &mut |snapshots| {
        if snapshots.len() != dependencies.len() || snapshots.is_empty() {
            return Err(GatewayAttemptError::Corrupt);
        }
        let source = decode(
            snapshots[0]
                .as_deref()
                .ok_or(GatewayAttemptError::Corrupt)?,
        )?;
        if !eligible_source(&record.state.plan, &source, source_key, key)? {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        admission.stamp(record, &snapshots[1..])?;
        if record.evaluated_at < source.evaluated_at {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        encode(record)
    })
}
