//! Publication is an explicit operator action over retained candidate evidence.
//! It changes only the connection row; acquisition facts and charges stay immutable.

use super::{
    AcquisitionPlan, AcquisitionState, ApprovedEffect, Arc, GatewayAttemptError, GatewayAttempts,
    GatewayInsert, GatewayRecordEntry, GatewayRecordKind, LogicalOperationId, OperatorNamespace,
    Record, Serialize, allocation, append_dependencies, blocking, canonical, capacity, decode_as,
    prerequisite_dependencies, select_snapshots, validate_prerequisites,
};

/// Result of an explicit operator publication; neither variant grants I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidatePublication {
    /// The exact predecessor/absence and complete fresh evidence were checked
    /// under the writer fence before the connection commit was acknowledged.
    Published,
    /// The exact candidate is already current. This is a state observation,
    /// not a claim that this invocation published it or refreshed its evidence.
    AlreadyCurrent,
}

struct PublicationTarget {
    plan: crate::effect::CandidatePlan,
    capacity: super::SourceCapacity,
    replacement: Vec<u8>,
    is_first: bool,
    kind: super::PrerequisiteKind,
    connection_key: super::GatewayAttemptKey,
    key: super::GatewayAttemptKey,
}

impl PublicationTarget {
    fn new(
        approved: &ApprovedEffect,
        attempts: &GatewayAttempts,
    ) -> Result<Self, GatewayAttemptError> {
        let binding = approved.effect().binding();
        let target = approved
            .candidate_target()
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        let plan = approved
            .candidate_plan()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let capacity = plan
            .validate(binding)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let replacement = target
            .record()
            .to_canonical_cbor()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let is_first = target.previous().is_none();
        let kind = target.final_kind();
        let connection_key = plan
            .source_key()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let (namespace, operation, _, _) = binding.journal_identity();
        let key = attempts.key(
            &OperatorNamespace::parse(namespace).map_err(|_| GatewayAttemptError::Corrupt)?,
            &LogicalOperationId::parse(operation).map_err(|_| GatewayAttemptError::Corrupt)?,
        )?;
        Ok(Self {
            plan,
            capacity,
            replacement,
            is_first,
            kind,
            connection_key,
            key,
        })
    }
}

type PublicationDecision<'a> =
    dyn FnMut(&[Option<Vec<u8>>]) -> Result<Vec<u8>, GatewayAttemptError> + 'a;

impl GatewayAttempts {
    /// No public/application route may call this as a substitute for operator
    /// publication authority. The native read proof authorizes only its reads.
    pub(crate) async fn publish_candidate(
        &self,
        approved: Arc<ApprovedEffect>,
        validation: crate::entry::EntryValidation,
        authorization_started_at: u64,
    ) -> Result<CandidatePublication, GatewayAttemptError> {
        let binding = approved.effect().binding();
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let PublicationTarget {
            plan,
            capacity,
            replacement,
            is_first,
            kind,
            connection_key,
            key,
        } = PublicationTarget::new(&approved, self)?;
        let store = Arc::clone(&self.store);
        blocking(move || {
            let root_bytes = store
                .load(GatewayRecordKind::Attempt, &key)?
                .ok_or(GatewayAttemptError::Unavailable)?;
            let root: Record<AcquisitionState> = decode_as(&root_bytes)?;
            if root.state.plan != AcquisitionPlan::Candidate(plan.clone())
                || root.validate_header()? != *approved.effect().binding()
            {
                return Err(GatewayAttemptError::BindingConflict);
            }
            // A replay observes current state without refreshing old evidence or
            // giving a second publication any causal attribution.
            if store
                .load(GatewayRecordKind::Connection, &connection_key)?
                .as_deref()
                == Some(replacement.as_slice())
            {
                return Ok(CandidatePublication::AlreadyCurrent);
            }
            let slot = root
                .state
                .allocation
                .ok_or(GatewayAttemptError::InvalidTransition)?;
            let mut keys = vec![
                (GatewayRecordKind::Connection, connection_key),
                (GatewayRecordKind::Attempt, key),
                (
                    GatewayRecordKind::EffectAllocation,
                    capacity::allocation_key(&capacity, slot),
                ),
            ];
            let native_indices = append_dependencies(&mut keys, &validation.dependencies());
            let native_end = keys.len();
            let prerequisites = approved
                .prerequisite_plans()
                .map_err(|_| GatewayAttemptError::Corrupt)?;
            keys.extend(prerequisite_dependencies(key, &prerequisites)?);
            let mut disposition = CandidatePublication::Published;
            let mut decide = |snapshots: &[Option<Vec<u8>>]| {
                if snapshots.len() != keys.len()
                    || snapshots[1].as_deref() != Some(root_bytes.as_slice())
                {
                    return Err(GatewayAttemptError::Conflict);
                }
                if snapshots[0].as_deref() == Some(replacement.as_slice()) {
                    disposition = CandidatePublication::AlreadyCurrent;
                    return Ok(replacement.clone());
                }
                if !plan
                    .source_matches(snapshots[0].as_deref())
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .0
                    || snapshots[2].as_deref()
                        != Some(canonical(&allocation(&root.state.plan, key, slot)?)?.as_slice())
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
                let acquired = validate_prerequisites(
                    key,
                    approved.effect().binding(),
                    &prerequisites,
                    &snapshots[native_end..],
                    now,
                )?;
                let primary = root.response_evidence(kind, now)?;
                validation
                    .validate_candidate_evidence(&approved, &acquired, &primary, now)
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                Ok(replacement.clone())
            };
            if publish_connection(&*store, &keys, &replacement, is_first, &mut decide)? {
                return Ok(CandidatePublication::AlreadyCurrent);
            }
            Ok(disposition)
        })
        .await
    }
}

/// Returns true only when a competing publisher already installed the exact record.
fn publish_connection(
    store: &dyn super::GatewayAttemptStore,
    keys: &[(GatewayRecordKind, super::GatewayAttemptKey)],
    replacement: &[u8],
    is_first: bool,
    decide: &mut PublicationDecision<'_>,
) -> Result<bool, GatewayAttemptError> {
    let connection_key = keys[0].1;
    if is_first {
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::Connection,
            key: connection_key,
            record: replacement.to_vec(),
            expires_at: None,
        };
        // The insertion target itself is held absent by the same fence.
        // Reconstruct that explicit snapshot for the shared decision.
        match store.fenced_insert_all(&[entry], &keys[1..], &mut |snapshots| {
            let mut all = Vec::with_capacity(snapshots.len() + 1);
            all.push(None);
            all.extend_from_slice(snapshots);
            decide(&all)
        })? {
            GatewayInsert::Inserted => {}
            GatewayInsert::Exists { index: 0 } => {
                if store
                    .load(GatewayRecordKind::Connection, &connection_key)?
                    .as_deref()
                    != Some(replacement)
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                return Ok(true);
            }
            GatewayInsert::Exists { .. } => return Err(GatewayAttemptError::Corrupt),
        }
    } else {
        store.fenced_replace(keys, decide)?;
    }
    Ok(false)
}
