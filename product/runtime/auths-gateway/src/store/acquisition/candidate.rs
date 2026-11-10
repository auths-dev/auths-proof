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

/// Read-only, advisory candidate state. Only publication's existing native fence
/// can commit a connection; observing Ready never creates an entry capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateRecoveryState {
    ChecksIncomplete,
    ChecksRefused,
    ReadyForPublication,
    Published,
    Superseded,
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

struct PublicationValidation<'a> {
    approved: &'a ApprovedEffect,
    validation: &'a crate::entry::EntryValidation,
    plan: &'a crate::effect::CandidatePlan,
    root: &'a Record<AcquisitionState>,
    root_bytes: &'a [u8],
    key: super::GatewayAttemptKey,
    kind: super::PrerequisiteKind,
    native_indices: &'a [usize],
    native_end: usize,
    authorization_started_at: u64,
}

impl PublicationValidation<'_> {
    /// The same guards serve advisory inspection and fenced publication.
    /// Inspection never weakens or replaces the latter's snapshot boundary.
    fn check(&self, snapshots: &[Option<Vec<u8>>]) -> Result<(), GatewayAttemptError> {
        if snapshots.len() < self.native_end || snapshots[1].as_deref() != Some(self.root_bytes) {
            return Err(GatewayAttemptError::Conflict);
        }
        let slot = self
            .root
            .state
            .allocation
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        if !self
            .plan
            .source_matches(snapshots[0].as_deref())
            .map_err(|_| GatewayAttemptError::Corrupt)?
            .0
            || snapshots[2].as_deref()
                != Some(canonical(&allocation(&self.root.state.plan, self.key, slot)?)?.as_slice())
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let now = self
            .validation
            .validate(
                self.approved,
                &select_snapshots(snapshots, self.native_indices)?,
                self.authorization_started_at,
            )
            .map_err(|_| GatewayAttemptError::InvalidTransition)?;
        let prerequisites = self
            .approved
            .prerequisite_plans()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let acquired = validate_prerequisites(
            self.key,
            self.approved.effect().binding(),
            &prerequisites,
            &snapshots[self.native_end..],
            now,
        )?;
        let primary = self.root.response_evidence(self.kind, now)?;
        self.validation
            .validate_candidate_evidence(self.approved, &acquired, &primary, now)
            .map_err(|_| GatewayAttemptError::InvalidTransition)
    }
}

impl GatewayAttempts {
    pub(crate) async fn inspect_candidate(
        &self,
        approved: Arc<ApprovedEffect>,
        validation: crate::entry::EntryValidation,
        authorization_started_at: u64,
    ) -> Result<CandidateRecoveryState, GatewayAttemptError> {
        if !self.policy.contains(approved.effect().binding()) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let PublicationTarget {
            plan,
            capacity,
            replacement,
            kind,
            connection_key,
            key,
            ..
        } = PublicationTarget::new(&approved, self)?;
        let store = Arc::clone(&self.store);
        blocking(move || {
            let current = store.load(GatewayRecordKind::Connection, &connection_key)?;
            if current.as_deref() == Some(replacement.as_slice()) {
                return Ok(CandidateRecoveryState::Published);
            }
            if !plan
                .source_matches(current.as_deref())
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .0
            {
                return Ok(CandidateRecoveryState::Superseded);
            }
            let Some(root_bytes) = store.load(GatewayRecordKind::Attempt, &key)? else {
                return Ok(CandidateRecoveryState::ChecksIncomplete);
            };
            let root: Record<AcquisitionState> = decode_as(&root_bytes)?;
            if root.state.plan != AcquisitionPlan::Candidate(plan.clone())
                || root.validate_header()? != *approved.effect().binding()
            {
                return Err(GatewayAttemptError::BindingConflict);
            }
            if matches!(root.state.phase, super::AcquisitionPhase::NotEntered { .. }) {
                return Ok(CandidateRecoveryState::ChecksRefused);
            }
            let Some(slot) = root.state.allocation else {
                return Ok(CandidateRecoveryState::ChecksIncomplete);
            };
            let mut keys = vec![
                (GatewayRecordKind::Connection, connection_key),
                (GatewayRecordKind::Attempt, key),
                (
                    GatewayRecordKind::EffectAllocation,
                    capacity::allocation_key(&capacity, slot),
                ),
            ];
            let native_indices =
                append_dependencies(&mut keys, &validation.dependencies(&approved));
            let native_end = keys.len();
            let prerequisites = approved
                .prerequisite_plans()
                .map_err(|_| GatewayAttemptError::Corrupt)?;
            keys.extend(prerequisite_dependencies(key, &prerequisites)?);
            let snapshots = keys
                .iter()
                .map(|(kind, key)| store.load(*kind, key))
                .collect::<Result<Vec<_>, _>>()?;
            let check = PublicationValidation {
                approved: &approved,
                validation: &validation,
                plan: &plan,
                root: &root,
                root_bytes: &root_bytes,
                key,
                kind,
                native_indices: &native_indices,
                native_end,
                authorization_started_at,
            };
            match check.check(&snapshots) {
                Ok(()) => Ok(CandidateRecoveryState::ReadyForPublication),
                Err(GatewayAttemptError::InvalidTransition) => {
                    Ok(CandidateRecoveryState::ChecksIncomplete)
                }
                Err(error) => Err(error),
            }
        })
        .await
    }

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
            let native_indices =
                append_dependencies(&mut keys, &validation.dependencies(&approved));
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
                PublicationValidation {
                    approved: &approved,
                    validation: &validation,
                    plan: &plan,
                    root: &root,
                    root_bytes: &root_bytes,
                    key,
                    kind,
                    native_indices: &native_indices,
                    native_end,
                    authorization_started_at,
                }
                .check(snapshots)?;
                Ok(replacement.clone())
            };
            crate::admin_fault::boundary("candidate-publication.before-native-commit");
            let already_current =
                publish_connection(&*store, &keys, &replacement, is_first, &mut decide)?;
            crate::admin_fault::boundary("candidate-publication.after-native-ack");
            if already_current {
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
