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
        GatewayRecoveryReport {
            schema: "auths.gateway-recovery/1",
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
            if let Some(slot) = read.state.allocation {
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
                if let Some(slot) = read.state.allocation
                    && snapshots[2].as_deref()
                        != Some(
                            canonical(&allocation(&read.state.plan, read_key, slot)?)?.as_slice(),
                        )
                {
                    return Err(GatewayAttemptError::Corrupt);
                }
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
                });
                match next {
                    Some(bytes) => Ok(bytes),
                    None => {
                        unchanged = true;
                        // Abort the write transaction: an inspection/replay must
                        // not rewrite state or acquire a new journal revision.
                        Err(GatewayAttemptError::Replay)
                    }
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
