//! Native final-entry validation over snapshots held by the attempt writer fence.
//! No credential, provider or nested store I/O occurs here. The installed
//! deployment clock retains its explicit platform trust assumptions.

use crate::configuration::SharedConfiguration;
use crate::effect::{ApprovedEffect, EffectPolicy};
use crate::{CompiledRecipe, GatewayAttemptKey, GatewayRecordKind, LoadedConnection};
use auths_connections::ConnectionProfile;
use auths_model::{PrincipalId, TrustedContext};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Exact published connection or unpublished credential candidate. Both are
/// checked against the one current connection row under the writer fence.
pub(crate) enum EntryConnection {
    Installed(Box<LoadedConnection>),
    Candidate(Box<crate::effect::CandidateCredentialTarget>),
}

impl EntryConnection {
    fn record(&self) -> &auths_connections::ConnectionRecord {
        match self {
            Self::Installed(loaded) => loaded.record(),
            Self::Candidate(target) => target.record(),
        }
    }

    fn validate(
        &self,
        approved: &ApprovedEffect,
        bytes: Option<&[u8]>,
        workload: &str,
        profile: &ConnectionProfile,
    ) -> bool {
        match self {
            Self::Installed(loaded) => {
                approved.candidate_target().is_none()
                    && bytes == Some(loaded.private_bytes())
                    && crate::connection::authorizes_entry(loaded.record(), workload, profile)
            }
            Self::Candidate(target) => {
                target.predecessor_matches(bytes)
                    && target.journal_plan().is_ok_and(|plan| {
                        approved.candidate_plan().is_ok_and(|bound| bound == plan)
                    })
                    && target.record().state() != auths_connections::ConnectionState::Revoked
                    && target
                        .record()
                        .allowed_workloads()
                        .iter()
                        .any(|allowed| allowed == workload)
                    && target.record().allowed_profiles().contains(profile)
            }
        }
    }
}

pub(crate) struct InstalledEntry {
    pub(crate) recipe: CompiledRecipe,
    pub(crate) trust: TrustedContext,
    pub(crate) observer: Option<PrincipalId>,
    pub(crate) policy: EffectPolicy,
    pub(crate) configuration: SharedConfiguration,
    pub(crate) connection: EntryConnection,
    pub(crate) connection_key: GatewayAttemptKey,
    pub(crate) qualification: Arc<crate::QualificationGate>,
    pub(crate) workload: String,
    pub(crate) profile: ConnectionProfile,
    pub(crate) started: Instant,
    #[cfg(unix)]
    pub(crate) commissioning: Option<crate::engine::commissioning::EntryAuthority>,
}

pub(crate) enum EntryValidation {
    Installed(Box<InstalledEntry>),
    /// A post-native driver oracle, never available in a production build.
    #[cfg(any(test, feature = "testkit-harness"))]
    Oracle {
        now: u64,
    },
}

impl EntryValidation {
    /// Runs only after exact native authority and acquisition membership have
    /// been validated under the same fence. No signing, custody or provider I/O.
    pub(crate) fn validate_prerequisite_evidence(
        &self,
        approved: &ApprovedEffect,
        pre_entry: &crate::GatewayPreEntry,
        acquired: &[crate::store::PrerequisiteResponse],
        now: u64,
    ) -> Result<(), &'static str> {
        match self {
            Self::Installed(entry) => validate_prerequisite_evidence(
                approved,
                &entry.policy.installation(
                    &entry.recipe,
                    &entry.trust,
                    entry.connection.record(),
                    entry.qualification.policy(),
                    entry.configuration.candidate(),
                ),
                entry.observer.as_ref(),
                pre_entry,
                acquired,
                now,
            ),
            #[cfg(any(test, feature = "testkit-harness"))]
            Self::Oracle { .. } => Ok(()),
        }
    }

    /// Publication is a trusted operator action. Native read evidence still
    /// must satisfy its exact final purpose; HTTP status is not that predicate.
    pub(crate) fn validate_candidate_evidence(
        &self,
        approved: &ApprovedEffect,
        acquired: &[crate::store::PrerequisiteResponse],
        primary: &crate::store::PrerequisiteResponse,
        now: u64,
    ) -> Result<(), &'static str> {
        let invalid = "gateway.entry.prerequisite-evidence";
        let target = approved.candidate_target().ok_or(invalid)?;
        if target.final_kind() != primary.kind
            || primary.observed_at > primary.received_at
            || primary.received_at > now
            || now
                .checked_sub(primary.observed_at)
                .is_none_or(|age| age > crate::effect::MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS)
        {
            return Err(invalid);
        }
        self.validate_prerequisite_evidence(
            approved,
            &crate::GatewayPreEntry::default(),
            acquired,
            now,
        )?;
        match self {
            Self::Installed(entry) => validate_credential_evidence(
                &entry.recipe,
                *target.record().account_commitment(),
                primary,
            ),
            #[cfg(any(test, feature = "testkit-harness"))]
            Self::Oracle { .. } => Ok(()),
        }
    }

    pub(crate) fn dependencies(&self) -> Vec<(GatewayRecordKind, GatewayAttemptKey)> {
        match self {
            Self::Installed(entry) => {
                let mut keys = vec![
                    (GatewayRecordKind::Connection, entry.connection_key),
                    (
                        GatewayRecordKind::EffectConfiguration,
                        entry.configuration.key(),
                    ),
                ];
                #[cfg(unix)]
                if let Some(authority) = &entry.commissioning {
                    keys.push((GatewayRecordKind::CommissioningBudget, authority.budget_key));
                }
                keys
            }
            #[cfg(any(test, feature = "testkit-harness"))]
            Self::Oracle { .. } => Vec::new(),
        }
    }

    /// Samples time after lock acquisition and re-runs native authority and
    /// approval against the exact connection/configuration snapshots.
    pub(crate) fn validate(
        &self,
        approved: &ApprovedEffect,
        snapshots: &[Option<Vec<u8>>],
        evaluated_at: u64,
    ) -> Result<u64, &'static str> {
        match self {
            Self::Installed(entry) => {
                if snapshots.len() != self.dependencies().len() {
                    return Err("gateway.entry.dependencies-unavailable");
                }
                if !entry.connection.validate(
                    approved,
                    snapshots[0].as_deref(),
                    &entry.workload,
                    &entry.profile,
                ) {
                    return Err("gateway.connection.changed");
                }
                let configuration = snapshots[1]
                    .as_deref()
                    .ok_or("gateway.configuration.unavailable")?;
                let qualification = entry
                    .configuration
                    .entry_snapshot(configuration, &entry.qualification)?;
                let now = qualification.now;
                if now < evaluated_at
                    || now > evaluated_at.saturating_add(crate::recipe::ENTRY_DEADLINE_SECONDS)
                    || entry.started.elapsed()
                        > Duration::from_secs(crate::recipe::ENTRY_DEADLINE_SECONDS)
                {
                    return Err("gateway.entry.deadline");
                }
                #[cfg(unix)]
                match &entry.commissioning {
                    Some(authority) => authority.check(
                        &qualification,
                        snapshots
                            .get(2)
                            .and_then(Option::as_deref)
                            .ok_or("gateway.commissioning.registration-missing")?,
                    ),
                    None => qualification.check(),
                }?;
                #[cfg(not(unix))]
                qualification.check()?;
                approved
                    .validate_for_entry(
                        &entry.policy.installation(
                            &entry.recipe,
                            &entry.trust,
                            entry.connection.record(),
                            entry.qualification.policy(),
                            entry.configuration.candidate(),
                        ),
                        now,
                    )
                    .map_err(|_| "gateway.effect.authority-unavailable")?;
                Ok(now)
            }
            #[cfg(any(test, feature = "testkit-harness"))]
            Self::Oracle { now } => {
                if !snapshots.is_empty()
                    || *now < evaluated_at
                    || *now > evaluated_at.saturating_add(crate::recipe::ENTRY_DEADLINE_SECONDS)
                {
                    return Err("test.entry.deadline");
                }
                let key = ed25519_dalek::SigningKey::from_bytes(&[29; 32])
                    .verifying_key()
                    .to_bytes();
                approved
                    .validate_approval(&key, *now)
                    .map_err(|_| "test.entry.approval")?;
                Ok(*now)
            }
        }
    }
}

/// Reuses the recipe's existing response predicates and native selected
/// observation requirements. Inputs are bounded, retained acquisition evidence;
/// callers cannot replace them with a newly fetched or re-timestamped response.
#[allow(
    clippy::too_many_lines,
    reason = "closed prerequisite alternatives preserve distinct existing predicates at one entry gate"
)]
pub(crate) fn validate_prerequisite_evidence(
    approved: &ApprovedEffect,
    installed: &crate::effect::EffectInstallation<'_>,
    observer: Option<&PrincipalId>,
    pre_entry: &crate::GatewayPreEntry,
    acquired: &[crate::store::PrerequisiteResponse],
    now: u64,
) -> Result<(), &'static str> {
    use crate::effect::PrerequisiteKind;
    use auths_gateway_kernel::order::PreEntryResult;
    use sha2::{Digest as _, Sha256};
    let invalid = "gateway.entry.prerequisite-evidence";
    let command = approved.command();
    let plans = approved.prerequisite_plans().map_err(|_| invalid)?;
    if acquired.len() != plans.len() {
        return Err(invalid);
    }
    let mut saw_observations = false;
    let mut saw_basis = false;
    for (plan, evidence) in plans.iter().zip(acquired) {
        if plan.kind().map_err(|_| invalid)? != evidence.kind
            || evidence.observed_at > evidence.received_at
            || evidence.received_at > now
            || now
                .checked_sub(evidence.observed_at)
                .is_none_or(|age| age > crate::effect::MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS)
        {
            return Err(invalid);
        }
        match evidence.kind {
            PrerequisiteKind::Probe
            | PrerequisiteKind::Account
            | PrerequisiteKind::DeniedCapability(_) => {
                validate_credential_evidence(
                    installed.recipe,
                    *installed.connection.account_commitment(),
                    evidence,
                )?;
            }
            PrerequisiteKind::PreEntry => {
                let command = command.ok_or(invalid)?;
                let observer = observer.ok_or(invalid)?;
                let read = command.request.pre_entry_read().ok_or(invalid)?;
                let pointers = installed.recipe.pre_entry_pointers().ok_or(invalid)?;
                let selected = crate::pre_entry::select(
                    &command.requirements,
                    &command.canonical_action,
                    installed.context,
                    Some(observer),
                    read,
                    pointers,
                    |namespace, subject| {
                        crate::engine::resource_covers(installed.context, namespace, subject)
                    },
                )
                .map_err(|_| invalid)?;
                let observations = crate::pre_entry::verify_recorded(
                    observer,
                    read,
                    pointers,
                    evidence.response.usable_body().ok_or(invalid)?,
                    evidence.observed_at,
                    &pre_entry.observations,
                )
                .ok_or(invalid)?;
                if crate::pre_entry::evaluate(&selected, &observations, now)
                    != PreEntryResult::Satisfied
                {
                    return Err(invalid);
                }
                saw_observations = true;
            }
            PrerequisiteKind::RelativeCeiling => {
                let command = command.ok_or(invalid)?;
                let ceiling = installed.recipe.ceiling_check().ok_or(invalid)?;
                let body = evidence.response.usable_body().ok_or(invalid)?;
                let argument = ceiling.argument_value(&command.arguments).ok_or(invalid)?;
                let crate::recipe::CeilingReading::Read {
                    basis,
                    binds_equal: true,
                } = ceiling.read(body, &command.arguments)
                else {
                    return Err(invalid);
                };
                let retained = pre_entry.basis.as_ref().ok_or(invalid)?;
                if !auths_gateway_kernel::ratio::relative_ceiling_admits(
                    argument,
                    basis,
                    ceiling.basis_points,
                ) || retained.value != basis
                    || retained.response_digest != <[u8; 32]>::from(Sha256::digest(body))
                    || retained.read_at != evidence.observed_at
                {
                    return Err(invalid);
                }
                saw_basis = true;
            }
        }
    }
    if saw_observations == pre_entry.observations.is_empty()
        || saw_basis != pre_entry.basis.is_some()
    {
        return Err(invalid);
    }
    Ok(())
}

/// Shared account/capability meaning for mutation and recovery prerequisites.
/// This does not grant entry; the final fence also checks freshness/membership.
pub(crate) fn validate_credential_evidence(
    recipe: &CompiledRecipe,
    account: [u8; 32],
    evidence: &crate::store::PrerequisiteResponse,
) -> Result<(), &'static str> {
    use crate::effect::PrerequisiteKind;
    use auths_gateway_kernel::order::{AccountResult, DeniedResult};
    let invalid = "gateway.entry.prerequisite-evidence";
    let guard = recipe.guard_checks().ok_or(invalid)?;
    let valid = match evidence.kind {
        PrerequisiteKind::Probe => {
            let (pointer, equals) = guard.probe.as_ref().ok_or(invalid)?;
            crate::onboarding::probe_passes(Some(&evidence.response), pointer, equals)
        }
        PrerequisiteKind::Account => {
            let pointer = guard.account_pointer.as_deref().ok_or(invalid)?;
            crate::submit::account_result(Some(&evidence.response), pointer, Some(account))
                == AccountResult::Equal
        }
        PrerequisiteKind::DeniedCapability(index) => {
            let refused = guard
                .denied_refused
                .get(usize::from(index))
                .ok_or(invalid)?;
            crate::submit::denied_result(Some(&evidence.response), refused) == DeniedResult::Refused
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(invalid) }
}
