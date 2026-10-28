//! Native final-entry validation over snapshots held by the attempt writer fence.
//! No credential, provider or nested store I/O occurs here. The installed
//! deployment clock retains its explicit platform trust assumptions.

use crate::configuration::SharedConfiguration;
use crate::effect::{ApprovedEffect, EffectPolicy};
use crate::{CompiledRecipe, GatewayAttemptKey, GatewayRecordKind, LoadedConnection};
use auths_connections::ConnectionProfile;
use auths_model::TrustedContext;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) struct InstalledEntry {
    pub(crate) recipe: CompiledRecipe,
    pub(crate) trust: TrustedContext,
    pub(crate) policy: EffectPolicy,
    pub(crate) configuration: SharedConfiguration,
    pub(crate) connection: LoadedConnection,
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
                let connection = snapshots[0]
                    .as_deref()
                    .ok_or("gateway.connection.unavailable")?;
                if connection != entry.connection.private_bytes() {
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
                if !crate::connection::authorizes_entry(
                    entry.connection.record(),
                    &entry.workload,
                    &entry.profile,
                ) {
                    return Err("gateway.connection.unavailable");
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
