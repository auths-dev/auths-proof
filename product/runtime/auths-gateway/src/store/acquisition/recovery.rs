//! Source refinement from retained, separately authorized acquisition history.
//! The same adapter fence orders the source, read and permanent allocation.
//! This path has no credential/transport capability and never refreshes evidence.

use super::*;
use crate::effect::MAX_RECOVERY_EVIDENCE_AGE_SECONDS;
use crate::recipe::ReadBack;

/// Why a recorded recovery acquisition did or did not refine its source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryDisposition {
    /// Fresh, supported evidence was durably added to the original mutation.
    Recorded,
    /// This exact evidence was already recorded; no timestamp or charge changed.
    AlreadyRecorded,
    /// The source already has terminal facts from another observation.
    SourceFinal,
    /// The acquisition has no complete response. Its charges remain retained.
    AcquisitionIncomplete,
    /// Status, version headers, JSON or projection did not provide usable evidence.
    ResponseUnusable,
    /// Evidence is too old, or the clock is earlier than its receipt time.
    EvidenceStale,
    /// A comparison cannot establish the source's effect or causal link.
    Inconclusive,
}

/// Protected journal history from a recovery refinement. Provider evidence in
/// `source` remains private; this value is deliberately not serializable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    /// Original mutation facts and attribution; never replaced by reader identity.
    pub source: GatewayAttemptSnapshot,
    /// Independently charged read facts without its private response bytes.
    pub acquisition: AcquisitionSnapshot,
    /// The bounded evidence decision, without implying a new execution permit.
    pub disposition: RecoveryDisposition,
    /// Source-lifetime charges inspected under the same source/read fence.
    pub budget: RecoveryBudget,
    /// Receipt time of this read's complete response, never refreshed by replay.
    pub acquisition_received_at: Option<u64>,
}

/// Native lifetime accounting, including failed and ambiguous observations.
/// These are retained reservations, not measurements of bytes actually received.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryBudget {
    /// Permanent observation allocations for this source, across operation IDs.
    pub retained_attempts: u64,
    /// Maximum number of independently authorized observation entries.
    pub maximum_attempts: u64,
    /// Maximum retained response bytes for each observation.
    pub maximum_response_bytes: u64,
    /// Sum of the permanent response-byte reservations, without refunds.
    pub retained_response_bytes: u64,
    /// Maximum response-byte reservation across all observation entries.
    pub maximum_total_response_bytes: u64,
    /// Deadline for each observation transport, excluding prerequisite transports.
    pub maximum_transport_seconds: u64,
    /// Sum of the observation transport deadlines at the lifetime attempt limit.
    pub maximum_total_transport_seconds: u64,
    /// Maximum evidence age when independently acquired evidence is recorded.
    pub maximum_evidence_age_seconds: u64,
}

/// Reason to seek operator attention; it never changes evidence or accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryEscalation {
    /// No additional escalation follows from the retained recovery facts.
    None,
    /// No observation capacity remains and the source is still unresolved.
    CapacityExhausted,
    /// The observation has no complete retained response.
    EvidenceIncomplete,
    /// The response does not satisfy the declared observation contract.
    EvidenceUnusable,
    /// The evidence is outside the declared freshness interval.
    EvidenceStale,
    /// The observation cannot establish the source effect or its causal link.
    Inconclusive,
}

/// Operator proposals, never execution permits. All provider I/O still requires
/// fresh native authorization, exact approval, admission and an entry grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryNextAction {
    /// Inspect retained evidence without changing the original attribution.
    InspectRetainedEvidence,
    /// Request a new independently authorized read, subject to all current gates.
    RequestIndependentObservation,
    /// Seek operator attention while preserving uncertainty and every charge.
    Escalate,
}

/// Public recovery projection containing no response bytes, locators, echo,
/// private commitments, proof, approval or credential material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewayRecoveryReport {
    /// Versioned native projection schema.
    pub schema: &'static str,
    /// Distinct facts about the original mutation.
    pub source: RecoverySourceFacts,
    /// Independently charged acquisition facts.
    pub acquisition: AcquisitionSnapshot,
    /// Evidence decision; response alone never implies mutation success.
    pub disposition: RecoveryDisposition,
    /// Same-fence lifetime accounting; no separate recovery ledger is maintained.
    pub budget: RecoveryBudget,
    /// Why the unresolved source requires operator attention.
    pub escalation: RecoveryEscalation,
    /// Proposals only; none authorizes mutation retry, redelivery or refund.
    pub next_actions: Vec<RecoveryNextAction>,
    /// Complete response receipt time even when its contents are unusable.
    pub acquisition_received_at: Option<u64>,
}

/// Safe source facts without the protected evidence used to establish them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoverySourceFacts {
    /// Conservative source stage.
    pub stage: GatewayAttemptStage,
    /// Durable source revision.
    pub revision: u64,
    /// HTTP status of the original write, when retained.
    pub response_status: Option<u16>,
    /// State equality is not causal attribution.
    pub observation_match: Option<bool>,
    /// Whether the declared provider echo linked the observed state.
    pub provider_linked: bool,
    /// Receipt time of the independent evidence, never refreshed by replay.
    pub recovery_received_at: Option<u64>,
}

impl RecoverySnapshot {
    /// Produces the native bounded public report. It exposes no private digest
    /// or provider response, even when the source has linked evidence.
    #[must_use]
    pub fn report(&self) -> GatewayRecoveryReport {
        let can_observe = !matches!(
            self.source.stage(),
            GatewayAttemptStage::NotEntered
                | GatewayAttemptStage::Observed
                | GatewayAttemptStage::ObservedByProvider
        );
        let exhausted = self.budget.retained_attempts >= self.budget.maximum_attempts;
        let escalation = if !can_observe {
            RecoveryEscalation::None
        } else if exhausted {
            RecoveryEscalation::CapacityExhausted
        } else {
            match self.disposition {
                RecoveryDisposition::AcquisitionIncomplete => {
                    RecoveryEscalation::EvidenceIncomplete
                }
                RecoveryDisposition::ResponseUnusable => RecoveryEscalation::EvidenceUnusable,
                RecoveryDisposition::EvidenceStale => RecoveryEscalation::EvidenceStale,
                RecoveryDisposition::Inconclusive => RecoveryEscalation::Inconclusive,
                _ => RecoveryEscalation::None,
            }
        };
        let mut next_actions = vec![RecoveryNextAction::InspectRetainedEvidence];
        if can_observe && !exhausted {
            next_actions.push(RecoveryNextAction::RequestIndependentObservation);
        }
        if escalation != RecoveryEscalation::None {
            next_actions.push(RecoveryNextAction::Escalate);
        }
        GatewayRecoveryReport {
            schema: "auths.gateway-recovery/2",
            source: RecoverySourceFacts {
                stage: self.source.stage(),
                revision: self.source.revision(),
                response_status: self.source.response_status(),
                observation_match: self.source.observation_match(),
                provider_linked: self.source.provider_evidence().is_some(),
                recovery_received_at: self.source.recovery_received_at(),
            },
            acquisition: self.acquisition.clone(),
            disposition: self.disposition,
            budget: self.budget.clone(),
            escalation,
            next_actions,
            acquisition_received_at: self.acquisition_received_at,
        }
    }
}

/// Immutable provenance stored beside the source's terminal observation facts.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryEvidenceLink {
    acquisition_effect: String,
    acquisition_operation: String,
    acquisition_revision: u64,
    response_digest: String,
    received_at: u64,
    recorded_at: u64,
}

impl std::fmt::Debug for RecoveryEvidenceLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryEvidenceLink { private: [redacted] }")
    }
}

impl RecoveryEvidenceLink {
    pub(in crate::store) const fn received_at(&self) -> u64 {
        self.received_at
    }

    pub(in crate::store) fn validate(&self, source: &Record) -> Result<(), GatewayAttemptError> {
        let operation = LogicalOperationId::parse(&self.acquisition_operation)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        digest_bytes(&self.acquisition_effect)?;
        digest_bytes(&self.response_digest)?;
        if operation.as_str() == source.operation_id
            || !(3..=MAX_JSON_INTEGER).contains(&self.acquisition_revision)
            || self.received_at < source.evaluated_at
            || self.recorded_at > MAX_JSON_INTEGER
            || !fresh(self.received_at, self.recorded_at)
            || !matches!(
                source.state.stage,
                GatewayAttemptStage::Observed | GatewayAttemptStage::ObservedByProvider
            )
            || source
                .state
                .provider_evidence
                .as_ref()
                .is_some_and(|evidence| {
                    evidence.observed_at != self.received_at
                        || evidence.evidence_digest != self.response_digest
                })
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(())
    }
}

fn fresh(received_at: u64, now: u64) -> bool {
    now.checked_sub(received_at)
        .is_some_and(|age| age <= MAX_RECOVERY_EVIDENCE_AGE_SECONDS)
}

impl Record<AcquisitionState> {
    fn response_link(&self, now: u64) -> Result<Option<RecoveryEvidenceLink>, GatewayAttemptError> {
        let AcquisitionPhase::ResponseRecorded { response } = &self.state.phase else {
            return Ok(None);
        };
        let capacity = self
            .state
            .plan
            .capacity()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let body = response.body(&capacity)?;
        Ok(Some(RecoveryEvidenceLink {
            acquisition_effect: hex::encode(self.validate_header()?.id().as_bytes()),
            acquisition_operation: self.operation_id.clone(),
            acquisition_revision: self.revision,
            response_digest: hex::encode(Sha256::digest(&body)),
            received_at: response.received_at,
            recorded_at: now,
        }))
    }
}

/// Returns a proposed mutation transition, or truthful unchanged history. The
/// request/echo/projection comes only from the retained source contract.
fn refinement(
    source: &Record,
    read: &Record<AcquisitionState>,
    now: u64,
) -> Result<Result<Record, RecoveryDisposition>, GatewayAttemptError> {
    let Some(link) = read.response_link(now)? else {
        return Ok(Err(RecoveryDisposition::AcquisitionIncomplete));
    };
    if let Some(existing) = &source.state.recovery_evidence {
        let mut expected = link;
        expected.recorded_at = existing.recorded_at;
        return Ok(Err(if existing == &expected {
            RecoveryDisposition::AlreadyRecorded
        } else {
            RecoveryDisposition::SourceFinal
        }));
    }
    if matches!(
        source.state.stage,
        GatewayAttemptStage::Observed
            | GatewayAttemptStage::ObservedByProvider
            | GatewayAttemptStage::NotEntered
    ) {
        return Ok(Err(RecoveryDisposition::SourceFinal));
    }
    if !fresh(link.received_at, now) {
        return Ok(Err(RecoveryDisposition::EvidenceStale));
    }
    let AcquisitionPhase::ResponseRecorded { response } = &read.state.phase else {
        return Err(GatewayAttemptError::Corrupt);
    };
    if !(200..=299).contains(&response.status) || !response.version_ok {
        return Ok(Err(RecoveryDisposition::ResponseUnusable));
    }
    let capacity = read
        .state
        .plan
        .capacity()
        .map_err(|_| GatewayAttemptError::Corrupt)?;
    let body = response.body(&capacity)?;
    let target = source.recovery_target_data()?;
    let request = target.closed_request();
    let token = source.echo_token()?;
    let Some(reading) = request.read_back(Some(&token), &body) else {
        return Ok(Err(RecoveryDisposition::ResponseUnusable));
    };
    let mut next = source.clone();
    match reading {
        ReadBack::EchoMatched => {
            // A response-derived locator cannot resolve an unknown send. The
            // shared reducer checks this link condition again before commit.
            if source.state.response_status.is_none()
                && !transition::resolves_unknown(source.link())
            {
                return Ok(Err(RecoveryDisposition::Inconclusive));
            }
            next.state.stage = GatewayAttemptStage::ObservedByProvider;
            next.state.provider_evidence = Some(EvidenceWire {
                channel: GatewayEvidenceChannel::ReadBack,
                locator: request.url().to_owned(),
                echo: token,
                evidence_digest: link.response_digest.clone(),
                evidence_b64: response.body_b64.clone(),
                observed_at: response.received_at,
            });
        }
        ReadBack::Value { matched } => {
            if source.state.response_status.is_none() {
                return Ok(Err(RecoveryDisposition::Inconclusive));
            }
            next.state.stage = GatewayAttemptStage::Observed;
            next.state.observation_match = Some(matched);
        }
        ReadBack::EchoMismatch => {
            if source.state.response_status.is_none() {
                return Ok(Err(RecoveryDisposition::Inconclusive));
            }
            next.state.stage = GatewayAttemptStage::Observed;
            next.state.observation_match = Some(false);
            next.state.observation_fact = Some(GatewayObservationFact::EchoMismatch);
        }
    }
    next.state.recovery_evidence = Some(link);
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(GatewayAttemptError::InvalidTransition)?;
    if !valid_transition(source, &next)? {
        return Err(GatewayAttemptError::InvalidTransition);
    }
    Ok(Ok(next))
}

/// Inspect the finite permanent allocation set; never infer usage from just
/// the selected read, which may itself have been refused without an allocation.
fn recovery_budget(
    read: &Record<AcquisitionState>,
    read_key: GatewayAttemptKey,
    capacity: &SourceCapacity,
    snapshots: &[Option<Vec<u8>>],
) -> Result<RecoveryBudget, GatewayAttemptError> {
    if snapshots.len()
        != usize::try_from(capacity.attempts).map_err(|_| GatewayAttemptError::Corrupt)?
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    let mut retained_attempts = 0_u64;
    let mut vacant = false;
    for (slot, bytes) in (0..capacity.attempts).zip(snapshots) {
        let Some(bytes) = bytes else {
            vacant = true;
            continue;
        };
        if vacant {
            return Err(GatewayAttemptError::Corrupt);
        }
        let row: capacity::SourceAllocation =
            serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
        row.validate_occupied(&allocation(&read.state.plan, read_key, slot)?, bytes)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        retained_attempts += 1;
    }
    if let Some(slot) = read.state.allocation
        && snapshots
            .get(usize::try_from(slot).map_err(|_| GatewayAttemptError::Corrupt)?)
            .and_then(|bytes| bytes.as_deref())
            != Some(canonical(&allocation(&read.state.plan, read_key, slot)?)?.as_slice())
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(RecoveryBudget {
        retained_attempts,
        maximum_attempts: capacity.attempts,
        maximum_response_bytes: capacity.maximum_bytes,
        retained_response_bytes: retained_attempts
            .checked_mul(capacity.maximum_bytes)
            .ok_or(GatewayAttemptError::Corrupt)?,
        maximum_total_response_bytes: capacity
            .attempts
            .checked_mul(capacity.maximum_bytes)
            .ok_or(GatewayAttemptError::Corrupt)?,
        maximum_transport_seconds: crate::transport::MAX_TRANSPORT_DURATION.as_secs(),
        maximum_total_transport_seconds: capacity
            .attempts
            .checked_mul(crate::transport::MAX_TRANSPORT_DURATION.as_secs())
            .ok_or(GatewayAttemptError::Corrupt)?,
        maximum_evidence_age_seconds: MAX_RECOVERY_EVIDENCE_AGE_SECONDS,
    })
}

impl GatewayAttempts {
    /// Records supported evidence from an already authorized read. It never
    /// re-verifies the expired writer or performs provider/custody I/O. The
    /// deployment clock is sampled inside the source/read/allocation fence.
    pub(crate) async fn refine_recovery(
        &self,
        namespace: &OperatorNamespace,
        source_operation: &LogicalOperationId,
        read_operation: &LogicalOperationId,
        recipe_digest: [u8; 32],
        clock: Arc<crate::QualificationGate>,
    ) -> Result<RecoverySnapshot, GatewayAttemptError> {
        if source_operation == read_operation {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let key = self.key(namespace, source_operation)?;
        let read_key = self.key(namespace, read_operation)?;
        let policy = self.policy.clone();
        let store = Arc::clone(&self.store);
        blocking(move || {
            let bytes = store
                .load(GatewayRecordKind::Attempt, &read_key)?
                .ok_or(GatewayAttemptError::Unavailable)?;
            let read: Record<AcquisitionState> = decode_as(&bytes)?;
            let AcquisitionPlan::Recovery(recovery_plan) = &read.state.plan else {
                return Err(GatewayAttemptError::BindingConflict);
            };
            let binding = read.validate_header()?;
            let capacity = read
                .state
                .plan
                .validate(&binding)
                .map_err(|_| GatewayAttemptError::Corrupt)?;
            if !policy.contains(&binding) || *binding.journal_identity().3 != recipe_digest {
                return Err(GatewayAttemptError::BindingConflict);
            }
            let mut keys = vec![
                (GatewayRecordKind::Attempt, key),
                (GatewayRecordKind::Attempt, read_key),
            ];
            // The bounded lifetime rows, rather than just this read's row,
            // establish retained usage. The adapter's existing writer fence
            // orders them with concurrent admissions and source refinement.
            for slot in 0..capacity.attempts {
                keys.push((
                    GatewayRecordKind::EffectAllocation,
                    capacity::allocation_key(&capacity, slot),
                ));
            }
            let mut result = None;
            let mut unchanged = false;
            let persisted = store.fenced_replace(&keys, &mut |snapshots| {
                if snapshots.len() != keys.len()
                    || snapshots[1].as_deref() != Some(bytes.as_slice())
                {
                    return Err(GatewayAttemptError::Conflict);
                }
                let source = decode(
                    snapshots[0]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Unavailable)?,
                )?;
                if source.binding_canonical != recovery_plan.source_binding
                    || !policy.contains(&source.validate_header()?)
                    || !recovery_plan
                        .matches_target(&source.recovery_target_data()?)
                        .map_err(|_| GatewayAttemptError::Corrupt)?
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                let budget = recovery_budget(&read, read_key, &capacity, &snapshots[2..])?;
                let now = clock
                    .effect_time()
                    .filter(|now| *now <= MAX_JSON_INTEGER)
                    .ok_or(GatewayAttemptError::Unavailable)?;
                let (source, disposition, next) = match refinement(&source, &read, now)? {
                    Ok(next) => (
                        next.snapshot(true)?,
                        RecoveryDisposition::Recorded,
                        Some(encode(&next)?),
                    ),
                    Err(disposition) => (source.snapshot(true)?, disposition, None),
                };
                result = Some(RecoverySnapshot {
                    source,
                    acquisition: read.snapshot()?,
                    disposition,
                    acquisition_received_at: match &read.state.phase {
                        AcquisitionPhase::ResponseRecorded { response } => {
                            Some(response.received_at)
                        }
                        _ => None,
                    },
                    budget,
                });
                if let Some(bytes) = next {
                    Ok(bytes)
                } else {
                    unchanged = true;
                    // Abort the write transaction: an inspection/replay must
                    // not rewrite state or acquire a new journal revision.
                    Err(GatewayAttemptError::Replay)
                }
            });
            match persisted {
                Ok(()) => result.ok_or(GatewayAttemptError::Unavailable),
                Err(GatewayAttemptError::Replay) if unchanged => {
                    result.ok_or(GatewayAttemptError::Unavailable)
                }
                Err(error) => Err(error),
            }
        })
        .await
    }
}
