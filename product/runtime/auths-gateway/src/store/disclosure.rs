//! Disclosure facts in the existing operation journal and transaction contract.
//! Admission reserves capacity only. Persisted facts never mint a delivery permit.
use super::acquisition::{append_dependencies, select_snapshots};
use super::*;
use crate::effect::disclosure_auth::RecipientAuthentication;
use crate::effect::{DisclosureAcknowledgement, DisclosurePlan};

/// Redacted disclosure facts, separate from provider response and observation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSnapshot {
    /// Exact retained journal revision.
    pub revision: u64,
    /// A retained grant without an ACK is conservatively unknown.
    pub stage: DisclosureStage,
    /// Stable pre-entry refusal, when the reservation was not admitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// Permanent source invocation allocation; empty delivery also consumes one.
    pub reserved_deliveries: u64,
    /// Exact projected-byte allocation, retained on uncertainty.
    pub reserved_bytes: u64,
    /// Fixed-window native policy count counters.
    pub policy_count_counters: u64,
    /// Fixed-window native policy byte counters.
    pub policy_byte_counters: u64,
}

/// Disclosure cannot record provider responses or mutation observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisclosureStage {
    /// Reservation has no delivery permission.
    Reserved,
    /// Closed before any delivery grant.
    NotEntered,
    /// Delivery may have happened; no redelivery or refund follows.
    Unknown,
    /// Exact authenticated recipient assertion, not proof of human attention.
    Acknowledged,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DisclosureState {
    plan: DisclosurePlan,
    allocation: Option<u64>,
    counters: Vec<CounterWire>,
    phase: DisclosurePhase,
    authentication: Option<RecipientAuthentication>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "kebab-case", deny_unknown_fields)]
enum DisclosurePhase {
    Reserved,
    NotEntered { code: String },
    EntryGranted,
    Unknown,
    Acknowledged { acknowledgement: String },
}

impl DisclosurePhase {
    const fn kernel(&self) -> transition::Stage {
        match self {
            Self::Reserved => transition::Stage::Reserved,
            Self::NotEntered { .. } => transition::Stage::NotEntered,
            Self::EntryGranted => transition::Stage::EntryGranted,
            Self::Unknown => transition::Stage::Unknown,
            Self::Acknowledged { .. } => transition::Stage::Acknowledged,
        }
    }
}

impl JournalProtocol for DisclosureState {
    fn wrap(self) -> ProtocolState {
        ProtocolState::Disclosure(Box::new(self))
    }
    fn extract(state: ProtocolState) -> Result<Self, GatewayAttemptError> {
        match state {
            ProtocolState::Disclosure(state) => Ok(*state),
            _ => Err(GatewayAttemptError::BindingConflict),
        }
    }
    fn view(record: &Record<Self>) -> Result<AttemptView, GatewayAttemptError> {
        Ok(AttemptView {
            protocol: transition::Protocol::Disclosure,
            revision: record.revision,
            fixed: canonical(&(
                &record.schema,
                &record.binding_canonical,
                &record.authority_canonical_b64,
                &record.approval_canonical,
                &record.namespace,
                &record.operation_id,
                &record.action_commitment,
                &record.recipe_digest,
                &record.nonce,
                record.evaluated_at,
                &record.state.plan,
                record.state.allocation,
                &record.state.counters,
            ))?,
            entry: record
                .entry
                .as_ref()
                .map(|entry| canonical(&(entry, &record.state.authentication)))
                .transpose()?
                .unwrap_or_default(),
            stage: record.state.phase.kernel(),
            refusal: matches!(record.state.phase, DisclosurePhase::NotEntered { .. }),
            acknowledgement: match &record.state.phase {
                DisclosurePhase::Acknowledged { acknowledgement } => {
                    acknowledgement.as_bytes().to_vec()
                }
                _ => Vec::new(),
            },
            response: Vec::new(),
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
        if record.entry.is_some() != record.state.authentication.is_some() {
            return Err(GatewayAttemptError::Corrupt);
        }
        if let Some(authentication) = &record.state.authentication {
            authentication
                .validate(
                    &binding,
                    capacity.maximum_bytes,
                    record.state.plan.recipient_key(),
                )
                .map_err(|_| GatewayAttemptError::Corrupt)?;
        }
        let counters = capacity::decode_counters(&record.state.counters)?;
        if record.state.allocation.is_some() {
            let counts: Vec<_> = counters
                .iter()
                .filter(|c| c.kind == GatewayCounterKind::Count)
                .map(|c| c.counter)
                .collect();
            let sums: Vec<_> = counters
                .iter()
                .filter(|c| c.kind == GatewayCounterKind::Sum)
                .map(|c| c.counter)
                .collect();
            if !binding.matches_disclosure_counters(&counts, &sums) {
                return Err(GatewayAttemptError::Corrupt);
            }
        } else if !counters.is_empty() {
            return Err(GatewayAttemptError::Corrupt);
        }
        if !transition::consistent(&Self::view(record)?)
            || record.entry.as_ref().is_some_and(|e| e.pre_entry.is_some())
            || match record.state.allocation {
                Some(slot) => slot >= capacity.attempts,
                None => !matches!(record.state.phase, DisclosurePhase::NotEntered { .. }),
            }
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        match &record.state.phase {
            DisclosurePhase::NotEntered { code } if !valid_code(code) => {
                return Err(GatewayAttemptError::Corrupt);
            }
            DisclosurePhase::Acknowledged { acknowledgement } => {
                DisclosureAcknowledgement::from_private_bytes(acknowledgement.as_bytes())
                    .and_then(|ack| ack.verify(&binding, capacity.maximum_bytes))
                    .map_err(|_| GatewayAttemptError::Corrupt)?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Record<DisclosureState> {
    pub(super) fn disclosure_snapshot(&self) -> Result<DisclosureSnapshot, GatewayAttemptError> {
        DisclosureState::validate(self)?;
        let allocated = self.state.allocation.is_some();
        Ok(DisclosureSnapshot {
            revision: self.revision,
            stage: match self.state.phase {
                DisclosurePhase::Reserved => DisclosureStage::Reserved,
                DisclosurePhase::NotEntered { .. } => DisclosureStage::NotEntered,
                DisclosurePhase::EntryGranted | DisclosurePhase::Unknown => {
                    DisclosureStage::Unknown
                }
                DisclosurePhase::Acknowledged { .. } => DisclosureStage::Acknowledged,
            },
            refusal: match &self.state.phase {
                DisclosurePhase::NotEntered { code } => Some(code.clone()),
                _ => None,
            },
            reserved_deliveries: u64::from(allocated),
            reserved_bytes: if allocated {
                self.state
                    .plan
                    .capacity()
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .maximum_bytes
            } else {
                0
            },
            policy_count_counters: self
                .state
                .counters
                .iter()
                .filter(|c| c.kind == GatewayCounterKind::Count)
                .count() as u64,
            policy_byte_counters: self
                .state
                .counters
                .iter()
                .filter(|c| c.kind == GatewayCounterKind::Sum)
                .count() as u64,
        })
    }
}

fn allocation(
    plan: &DisclosurePlan,
    key: GatewayAttemptKey,
    slot: u64,
) -> Result<capacity::SourceAllocation, GatewayAttemptError> {
    capacity::SourceAllocation::new(
        *plan
            .source()
            .map_err(|_| GatewayAttemptError::Corrupt)?
            .id()
            .as_bytes(),
        &plan.capacity().map_err(|_| GatewayAttemptError::Corrupt)?,
        key,
        slot,
    )
}

fn source_matches(plan: &DisclosurePlan, bytes: Option<&[u8]>) -> Result<u64, GatewayAttemptError> {
    let (source, received_at) =
        acquisition::retained(bytes.ok_or(GatewayAttemptError::Unavailable)?)?;
    if !plan
        .matches_source(&source)
        .map_err(|_| GatewayAttemptError::Corrupt)?
    {
        return Err(GatewayAttemptError::BindingConflict);
    }
    Ok(received_at)
}

impl GatewayAttempts {
    /// Reads exact disclosure history only. No source fetch, credential lease,
    /// recipient authentication or delivery occurs on replay.
    ///
    /// # Errors
    /// Refuses protocol/partition/binding mismatches and corrupt/unavailable state.
    pub async fn read_disclosure(
        &self,
        approved: &ApprovedEffect,
    ) -> Result<Option<DisclosureSnapshot>, GatewayAttemptError> {
        approved
            .disclosure_plan()
            .map_err(|_| GatewayAttemptError::BindingConflict)?;
        let binding = approved.effect().binding();
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
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
        let record: Record<DisclosureState> = decode_as(&bytes)?;
        if record.validate_header()? != *binding {
            return Err(GatewayAttemptError::BindingConflict);
        }
        record.disclosure_snapshot().map(Some)
    }

    /// Atomic reservation only. Recipient authentication and the later fresh
    /// grant are independent; this method cannot return any content or permit.
    #[allow(
        clippy::too_many_lines,
        reason = "one atomic source and policy allocation admission under the existing writer fence"
    )]
    pub(crate) async fn claim_disclosure(
        &self,
        approved: &Arc<ApprovedEffect>,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<DisclosureSnapshot, GatewayAttemptError> {
        let binding = approved.effect().binding();
        let plan = approved
            .disclosure_plan()
            .map_err(|_| GatewayAttemptError::BindingConflict)?;
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
        let bound = approved.disclosure_bound().cloned();
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
        let native_indices = append_dependencies(&mut dependencies, &admission.dependencies());
        let result = blocking(move || {
            if store.load(GatewayRecordKind::Attempt, &key)?.is_some() {
                return Err(existing_binding(&*store, key, &expected));
            }
            let base = Record::new(
                admission.approved.effect().binding(),
                admission.approved.approval(),
                admission.approved.effect().native_authority(),
                evaluated_at,
                DisclosureState {
                    plan,
                    allocation: None,
                    counters: Vec::new(),
                    phase: DisclosurePhase::Reserved,
                    authentication: None,
                },
            )?;
            base.validate_header()?;
            let mut candidate = bound
                .as_ref()
                .map(|b| capacity::CapacityCandidate::new(&*store, b))
                .transpose()?;
            let mut slot = 0;
            for _ in 0..MAX_CLAIM_ROUNDS {
                let refusal = if slot >= capacity.attempts {
                    Some("gateway.disclosure.exhausted")
                } else {
                    candidate
                        .as_ref()
                        .and_then(capacity::CapacityCandidate::refusal)
                };
                let mut record = base.clone();
                let mut slots = Vec::new();
                if let Some(code) = refusal {
                    record.state.phase = DisclosurePhase::NotEntered {
                        code: code.to_owned(),
                    };
                } else {
                    record.state.allocation = Some(slot);
                    if let Some(candidate) = &candidate {
                        (record.state.counters, slots) =
                            candidate.batch(key, &record.namespace, &record.operation_id)?;
                    }
                }
                DisclosureState::validate(&record)?;
                let mut entries = vec![GatewayRecordEntry {
                    kind: GatewayRecordKind::Attempt,
                    key,
                    record: encode(&record)?,
                    expires_at: None,
                }];
                if refusal.is_none() {
                    entries.push(GatewayRecordEntry {
                        kind: GatewayRecordKind::EffectAllocation,
                        key: capacity::allocation_key(&capacity, slot),
                        record: canonical(&allocation(&record.state.plan, key, slot)?)?,
                        expires_at: None,
                    });
                    entries.extend(slots);
                }
                let fenced_candidate = if refusal.is_none() {
                    candidate.as_ref()
                } else {
                    None
                };
                let native_end = dependencies.len();
                let mut fenced = dependencies.clone();
                if let Some(candidate) = fenced_candidate {
                    fenced.extend(candidate.dependencies());
                }
                let outcome = store.fenced_insert_all(&entries, &fenced, &mut |snapshots| {
                    if snapshots.len() != fenced.len() {
                        return Err(GatewayAttemptError::Corrupt);
                    }
                    let received_at = source_matches(&record.state.plan, snapshots[0].as_deref())?;
                    admission.stamp(&mut record, &select_snapshots(snapshots, &native_indices)?)?;
                    if record.evaluated_at < received_at {
                        return Err(GatewayAttemptError::InvalidTransition);
                    }
                    if let Some(candidate) = fenced_candidate {
                        candidate.validate_predecessors(&snapshots[native_end..])?;
                    }
                    encode(&record)
                })?;
                match outcome {
                    GatewayInsert::Inserted => return record.disclosure_snapshot(),
                    GatewayInsert::Exists { index: 0 } => {
                        return Err(existing_binding(&*store, key, &base.binding_canonical));
                    }
                    GatewayInsert::Exists { index: 1 } if refusal.is_none() => {
                        let bytes = store
                            .load(
                                GatewayRecordKind::EffectAllocation,
                                &capacity::allocation_key(&capacity, slot),
                            )?
                            .ok_or(GatewayAttemptError::Corrupt)?;
                        let occupied: capacity::SourceAllocation =
                            serde_json::from_slice(&bytes)
                                .map_err(|_| GatewayAttemptError::Corrupt)?;
                        occupied.validate_occupied(
                            &allocation(&record.state.plan, key, slot)?,
                            &bytes,
                        )?;
                        slot += 1;
                    }
                    GatewayInsert::Exists { index } if refusal.is_none() => {
                        candidate
                            .as_mut()
                            .ok_or(GatewayAttemptError::Corrupt)?
                            .advance(&*store, index - 2)?;
                    }
                    GatewayInsert::Exists { .. } => return Err(GatewayAttemptError::Corrupt),
                }
            }
            Err(GatewayAttemptError::Conflict)
        })
        .await;
        match result {
            Err(GatewayAttemptError::Replay) => self
                .read_disclosure(approved)
                .await?
                .ok_or(GatewayAttemptError::Unavailable),
            other => other,
        }
    }

    /// Adds an exact authenticated historical ACK to a retained disclosure
    /// grant. Current authority/approval expiry cannot erase legitimate history.
    /// Exact canonical replay returns the same revision. No delivery is retried.
    ///
    /// # Errors
    /// Refuses absent grants, other protocols/partitions, substituted ACK fields,
    /// conflicting evidence, corrupt state and failed/ambiguous persistence.
    pub async fn acknowledge_disclosure(
        &self,
        namespace: &OperatorNamespace,
        operation: &LogicalOperationId,
        acknowledgement: &DisclosureAcknowledgement,
    ) -> Result<DisclosureSnapshot, GatewayAttemptError> {
        let key = self.key(namespace, operation)?;
        // One concurrent evidence writer may win the CAS. Re-read once so an
        // exact ACK becomes a read-only replay; no network effect is retried.
        for _ in 0..2 {
            let store = Arc::clone(&self.store);
            let stored = blocking(move || store.load(GatewayRecordKind::Attempt, &key))
                .await?
                .ok_or(GatewayAttemptError::Unavailable)?;
            let record: Record<DisclosureState> = decode_as(&stored)?;
            let binding = record.validate_header()?;
            if !self.policy.contains(&binding)
                || binding.journal_identity().0 != namespace.as_str()
                || binding.journal_identity().1 != operation.as_str()
            {
                return Err(GatewayAttemptError::BindingConflict);
            }
            let bytes = record
                .state
                .plan
                .capacity()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .maximum_bytes;
            let verified = acknowledgement
                .verify(&binding, bytes)
                .map_err(|_| GatewayAttemptError::BindingConflict)?;
            let view = DisclosureState::view(&record)?;
            if transition::exact_acknowledgement_replay(&view, verified.as_private_bytes()) {
                return record.disclosure_snapshot();
            }
            let mut next = record.clone();
            next.state.phase = DisclosurePhase::Acknowledged {
                acknowledgement: std::str::from_utf8(verified.as_private_bytes())
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .to_owned(),
            };
            match (Attempt {
                store: Arc::clone(&self.store),
                key,
                stored,
                record,
            })
            .advance(next)
            .await
            {
                Ok(attempt) => return attempt.record.disclosure_snapshot(),
                Err(GatewayAttemptError::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        Err(GatewayAttemptError::Conflict)
    }
}

/// Test-only retained grant assumption for exercising historical ACK persistence.
/// This returns no permit, authenticates no live peer and sends no bytes.
#[cfg(test)]
impl GatewayAttempts {
    pub(crate) async fn synthetic_disclosure_grant(
        &self,
        approved: &ApprovedEffect,
        now: u64,
        unknown: bool,
        authentication: RecipientAuthentication,
    ) -> Result<DisclosureSnapshot, GatewayAttemptError> {
        let binding = approved.effect().binding();
        let (namespace, operation, _, _) = binding.journal_identity();
        let key = self.key(
            &OperatorNamespace::parse(namespace).map_err(|_| GatewayAttemptError::Corrupt)?,
            &LogicalOperationId::parse(operation).map_err(|_| GatewayAttemptError::Corrupt)?,
        )?;
        let stored = self
            .store
            .load(GatewayRecordKind::Attempt, &key)?
            .ok_or(GatewayAttemptError::Unavailable)?;
        let record: Record<DisclosureState> = decode_as(&stored)?;
        if record.validate_header()? != *binding {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let mut next = record.clone();
        next.record_grant(approved, now, now, None, &[])?;
        next.state.phase = DisclosurePhase::EntryGranted;
        next.state.authentication = Some(authentication);
        if !valid_transition(&record, &next)? {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let replacement = encode(&next)?;
        self.store
            .replace(GatewayRecordKind::Attempt, &key, &stored, &replacement)?;
        let attempt = Attempt {
            store: Arc::clone(&self.store),
            key,
            stored: replacement,
            record: next,
        };
        if unknown {
            let mut next = attempt.record.clone();
            next.state.phase = DisclosurePhase::Unknown;
            attempt.advance(next).await?.record.disclosure_snapshot()
        } else {
            attempt.record.disclosure_snapshot()
        }
    }
}

/// Newly acknowledged local delivery authority. No clone, decoder or public
/// plaintext accessor exists; only the closed transport consumes this value.
#[cfg(unix)]
pub(crate) struct DisclosureEntryPermit {
    _approved: Arc<ApprovedEffect>,
    channel: crate::disclosure_transport::AuthenticatedDisclosureChannel,
    content: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(unix)]
impl DisclosureEntryPermit {
    pub(crate) fn into_delivery(
        self,
    ) -> (
        crate::disclosure_transport::AuthenticatedDisclosureChannel,
        zeroize::Zeroizing<Vec<u8>>,
    ) {
        (self.channel, self.content)
    }
}

#[cfg(unix)]
pub(crate) struct GrantedDisclosure {
    attempt: Attempt<DisclosureState>,
}

#[cfg(unix)]
impl GrantedDisclosure {
    pub(crate) async fn record_unknown(self) -> Result<DisclosureSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.phase = DisclosurePhase::Unknown;
        self.attempt
            .advance(next)
            .await?
            .record
            .disclosure_snapshot()
    }
}

#[cfg(unix)]
impl GatewayAttempts {
    /// Fresh native, source, capacity and live-channel validation under the
    /// common writer fence. The permit exists only after durable acknowledgement.
    #[allow(
        clippy::too_many_lines,
        reason = "one final fenced disclosure decision and acknowledgement boundary"
    )]
    pub(crate) async fn grant_disclosure(
        &self,
        approved: Arc<ApprovedEffect>,
        validation: crate::entry::EntryValidation,
        authorization_started_at: u64,
        channel: crate::disclosure_transport::AuthenticatedDisclosureChannel,
    ) -> Result<(GrantedDisclosure, DisclosureEntryPermit), GatewayAttemptError> {
        let binding = approved.effect().binding();
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let plan = approved
            .disclosure_plan()
            .map_err(|_| GatewayAttemptError::BindingConflict)?;
        let capacity = plan
            .validate(binding)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
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
        let store = Arc::clone(&self.store);
        blocking(move || {
            let stored = store
                .load(GatewayRecordKind::Attempt, &key)?
                .ok_or(GatewayAttemptError::Unavailable)?;
            let record: Record<DisclosureState> = decode_as(&stored)?;
            if !matches!(record.state.phase, DisclosurePhase::Reserved)
                || record.state.plan != plan
                || record.validate_header()? != *approved.effect().binding()
            {
                return Err(GatewayAttemptError::BindingConflict);
            }
            let slot = record
                .state
                .allocation
                .ok_or(GatewayAttemptError::Corrupt)?;
            let mut keys = vec![
                (GatewayRecordKind::Attempt, key),
                (GatewayRecordKind::Attempt, source_key),
                (
                    GatewayRecordKind::EffectAllocation,
                    capacity::allocation_key(&capacity, slot),
                ),
            ];
            let native_indices = append_dependencies(&mut keys, &validation.dependencies());
            let native_end = keys.len();
            keys.extend(capacity::dependencies(&record.state.counters)?);
            let mut committed = None;
            store.fenced_replace(&keys, &mut |snapshots| {
                if snapshots.len() != keys.len()
                    || snapshots[0].as_deref() != Some(stored.as_slice())
                {
                    return Err(GatewayAttemptError::Conflict);
                }
                let current: Record<DisclosureState> = decode_as(
                    snapshots[0]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?,
                )?;
                if !matches!(current.state.phase, DisclosurePhase::Reserved)
                    || current.state.plan != plan
                    || current.validate_header()? != *approved.effect().binding()
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                let source_at = source_matches(&plan, snapshots[1].as_deref())?;
                if snapshots[2].as_deref()
                    != Some(canonical(&allocation(&plan, key, slot)?)?.as_slice())
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                let now = validation
                    .validate(
                        &approved,
                        &select_snapshots(snapshots, &native_indices)?,
                        authorization_started_at,
                    )
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                if now < source_at {
                    return Err(GatewayAttemptError::InvalidTransition);
                }
                capacity::validate_reservations(
                    &current.namespace,
                    &current.operation_id,
                    &current.state.counters,
                    key,
                    approved.disclosure_bound(),
                    &snapshots[native_end..],
                    now,
                )?;
                channel
                    .validate(
                        approved.effect().binding(),
                        capacity.maximum_bytes,
                        plan.recipient_key(),
                    )
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                let content = acquisition::retained_bytes(
                    snapshots[1]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?,
                )?;
                if content.len() as u64 != capacity.maximum_bytes {
                    return Err(GatewayAttemptError::Corrupt);
                }
                let mut next = current.clone();
                next.record_grant(
                    &approved,
                    authorization_started_at,
                    now,
                    None,
                    &snapshots[1..],
                )?;
                next.state.phase = DisclosurePhase::EntryGranted;
                next.state.authentication = Some(channel.evidence());
                if !valid_transition(&current, &next)? {
                    return Err(GatewayAttemptError::InvalidTransition);
                }
                let bytes = encode(&next)?;
                committed = Some((next, bytes.clone(), content));
                Ok(bytes)
            })?;
            let (record, stored, content) = committed.ok_or(GatewayAttemptError::Unavailable)?;
            Ok((
                GrantedDisclosure {
                    attempt: Attempt {
                        store,
                        key,
                        stored,
                        record,
                    },
                },
                DisclosureEntryPermit {
                    _approved: approved,
                    channel,
                    content,
                },
            ))
        })
        .await
    }
}
