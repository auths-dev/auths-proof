//! Bounded enrollment configuration within the existing gateway writer fence.
//! This owns no operation, usage counter, approval or transport capability.

use super::SharedConfiguration;
use crate::participant_enrollment::{
    EnrollmentInvocation, EnrollmentTree, EnrollmentTreeError, ParentEnrollmentPins,
    ParticipantEnrollmentProofs, RootEnrollmentProofs, root_enrollment_commitment,
};
use crate::{
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayInsert, GatewayRecordEntry,
    GatewayRecordKind, QualificationGate,
};
use auths_model::TrustedContext;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const SCHEMA: &str = "auths.engagement-configuration/1";
const MAX_BYTES: usize = auths_stores::MAX_GATEWAY_RECORD_BYTES;
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// Refusal before publishing enrollment configuration. No error grants entry.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EngagementConfigurationError {
    /// Independently installed root pins are invalid or not self-consistent.
    #[error("invalid engagement installation")]
    Installation,
    /// Native evidence, current ancestry or a requested narrowing was refused.
    #[error("engagement native control refused")]
    Native(#[from] EnrollmentTreeError),
    /// The shared installation, qualification or deployment time is unavailable.
    #[error("engagement configuration is unavailable or changed")]
    Configuration,
    /// Time moved behind already acknowledged configuration history.
    #[error("engagement clock moved behind retained history")]
    ClockRollback,
    /// A finite configuration revision bound was reached.
    #[error("engagement configuration revision exhausted")]
    RevisionExhausted,
    /// Stored state is malformed, noncanonical or for another installation.
    #[error("engagement configuration is corrupt")]
    Corrupt,
    /// Persistence failed or its acknowledgement is ambiguous.
    #[error("engagement configuration store failed")]
    Store(#[from] GatewayAttemptError),
}

impl EngagementConfigurationError {
    /// Stable private/control error class, containing no principal or proof.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Installation => "gateway.engagement.installation",
            Self::Native(_) => "gateway.engagement.native-refused",
            Self::Configuration => "gateway.engagement.configuration-changed",
            Self::ClockRollback => "gateway.engagement.clock-rollback",
            Self::RevisionExhausted => "gateway.engagement.revision-exhausted",
            Self::Corrupt => "gateway.engagement.corrupt",
            Self::Store(_) => "gateway.engagement.store-unavailable",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    root: [u8; 32],
    revision: u64,
    accepted_at: u64,
    tree: String,
}

/// Operator-private retained configuration. This is historical data, never a
/// current authorization, capacity reservation or an execution/delivery permit.
#[derive(Clone, Eq, PartialEq)]
pub struct EngagementConfigurationSnapshot {
    revision: u64,
    accepted_at: u64,
    tree: EnrollmentTree,
}

impl std::fmt::Debug for EngagementConfigurationSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementConfigurationSnapshot { private: [redacted] }")
    }
}

impl EngagementConfigurationSnapshot {
    /// Last acknowledged native configuration revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Clock sample taken inside the common writer fence, not an event timestamp.
    #[must_use]
    pub const fn accepted_at(&self) -> u64 {
        self.accepted_at
    }

    /// Immutable private ancestry for review. New operations must independently
    /// revalidate current native authority and reload this row at final entry.
    #[must_use]
    pub const fn tree(&self) -> &EnrollmentTree {
        &self.tree
    }
}

/// Trusted installation handle for one shared engagement authority. Its row is
/// an `EffectConfiguration` under an independently domain-separated key in the
/// same file/PostgreSQL store as operations. It adds no journal or executor.
///
/// These synchronous methods block on native verification and persistence;
/// async callers must invoke them off the async executor. Root construction is
/// available only through the trusted native installation boundary.
#[derive(Clone)]
pub struct EngagementConfiguration {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    root: ParentEnrollmentPins,
    context: TrustedContext,
    configuration: SharedConfiguration,
    qualification: Arc<QualificationGate>,
}

impl std::fmt::Debug for EngagementConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementConfiguration { private: [redacted] }")
    }
}

fn encode(record: &Record) -> Result<Vec<u8>, EngagementConfigurationError> {
    let bytes = serde_json_canonicalizer::to_vec(record)
        .map_err(|_| EngagementConfigurationError::Corrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(EngagementConfigurationError::Corrupt);
    }
    Ok(bytes)
}

impl EngagementConfiguration {
    pub(crate) fn new(
        store: Arc<dyn GatewayAttemptStore>,
        root: ParentEnrollmentPins,
        context: TrustedContext,
        configuration: SharedConfiguration,
        qualification: Arc<QualificationGate>,
    ) -> Result<Self, EngagementConfigurationError> {
        if !root.active
            || root_enrollment_commitment(&root)
                .map_err(|_| EngagementConfigurationError::Installation)?
                != root.enrollment_commitment
        {
            return Err(EngagementConfigurationError::Installation);
        }
        // Recipe namespaces, worker identity and mutable revisions are absent:
        // independently configured recipe workers must name one authority row.
        let key = super::digest(
            "auths.engagement-configuration-key/1",
            &(
                &root.admission_namespace,
                &root.admission_partition,
                root.engagement_commitment,
            ),
        )
        .map_err(|_| EngagementConfigurationError::Installation)?;
        if key == *configuration.key().as_bytes() {
            return Err(EngagementConfigurationError::Installation);
        }
        Ok(Self {
            store,
            key: GatewayAttemptKey::from_bytes(key),
            root,
            context,
            configuration,
            qualification,
        })
    }

    /// Shared dependency key to be included in the operation's own final fence.
    /// The key is data, never a bearer credential or an admission decision.
    #[must_use]
    pub const fn dependency_key(&self) -> GatewayAttemptKey {
        self.key
    }

    fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(EngagementConfigurationError::Corrupt);
        }
        let record: Record =
            serde_json::from_slice(bytes).map_err(|_| EngagementConfigurationError::Corrupt)?;
        if record.schema != SCHEMA
            || record.root != self.root.enrollment_commitment
            || !(1..=MAX_INTEGER).contains(&record.revision)
            || record.accepted_at > MAX_INTEGER
            || encode(&record)? != bytes
        {
            return Err(EngagementConfigurationError::Corrupt);
        }
        let tree = EnrollmentTree::decode(record.tree.as_bytes(), &self.root)
            .map_err(|_| EngagementConfigurationError::Corrupt)?;
        Ok(EngagementConfigurationSnapshot {
            revision: record.revision,
            accepted_at: record.accepted_at,
            tree,
        })
    }

    fn record(
        &self,
        snapshot: &EngagementConfigurationSnapshot,
    ) -> Result<Vec<u8>, EngagementConfigurationError> {
        let tree = String::from_utf8(
            snapshot
                .tree
                .encode()
                .map_err(|_| EngagementConfigurationError::Corrupt)?,
        )
        .map_err(|_| EngagementConfigurationError::Corrupt)?;
        encode(&Record {
            schema: SCHEMA.to_owned(),
            root: self.root.enrollment_commitment,
            revision: snapshot.revision,
            accepted_at: snapshot.accepted_at,
            tree,
        })
    }

    fn time(
        &self,
        bytes: Option<&[u8]>,
        adding_authority: bool,
    ) -> Result<u64, EngagementConfigurationError> {
        let fenced = self
            .configuration
            .entry_snapshot(
                bytes.ok_or(EngagementConfigurationError::Configuration)?,
                &self.qualification,
            )
            .map_err(|_| EngagementConfigurationError::Configuration)?;
        if adding_authority {
            fenced
                .check()
                .map_err(|_| EngagementConfigurationError::Configuration)?;
        }
        if fenced.now > MAX_INTEGER {
            return Err(EngagementConfigurationError::Configuration);
        }
        Ok(fenced.now)
    }

    /// Reads retained private facts without renewing eligibility or reviving
    /// withdrawn participants. History remains inspectable after expiry.
    ///
    /// # Errors
    /// Refuses absent/unreadable/corrupt state or a different installed root.
    pub fn snapshot(
        &self,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        let bytes = self
            .store
            .load(GatewayRecordKind::EffectConfiguration, &self.key)?
            .ok_or(EngagementConfigurationError::Corrupt)?;
        self.decode(&bytes)
    }

    /// Verifies root control and each resource witness at time sampled under
    /// the common configuration/operation writer fence, then durably inserts
    /// one root. An existing row returns retained facts without reactivation.
    ///
    /// # Errors
    /// Refuses changed installation, native evidence, unavailable time, corrupt
    /// state or failed/ambiguous durability. It never returns an entry permit.
    pub fn bootstrap(
        &self,
        proofs: &RootEnrollmentProofs<'_>,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::EffectConfiguration,
            key: self.key,
            record: b"unpublished native decision".to_vec(),
            expires_at: None,
        };
        let mut refusal = None;
        let mut committed = None;
        let result = self.store.fenced_insert_all(
            &[entry],
            &[(
                GatewayRecordKind::EffectConfiguration,
                self.configuration.key(),
            )],
            &mut |snapshots| {
                let decision = (|| {
                    if snapshots.len() != 1 {
                        return Err(EngagementConfigurationError::Corrupt);
                    }
                    let now = self.time(snapshots[0].as_deref(), true)?;
                    let tree = EnrollmentTree::bootstrap(&self.context, &self.root, now, proofs)?;
                    let next = EngagementConfigurationSnapshot {
                        revision: 1,
                        accepted_at: now,
                        tree,
                    };
                    let bytes = self.record(&next)?;
                    committed = Some(next);
                    Ok(bytes)
                })();
                decision.map_err(|error| {
                    refusal = Some(error);
                    GatewayAttemptError::InvalidTransition
                })
            },
        );
        match result {
            Ok(GatewayInsert::Inserted) => committed.ok_or(EngagementConfigurationError::Corrupt),
            Ok(GatewayInsert::Exists { index: 0 }) => self.snapshot(),
            Ok(GatewayInsert::Exists { .. }) => Err(EngagementConfigurationError::Corrupt),
            Err(error) => Err(refusal.unwrap_or(EngagementConfigurationError::Store(error))),
        }
    }

    fn update(
        &self,
        adding_authority: bool,
        change: impl FnOnce(&mut EnrollmentTree, u64) -> Result<(), EnrollmentTreeError>,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        let keys = [
            (GatewayRecordKind::EffectConfiguration, self.key),
            (
                GatewayRecordKind::EffectConfiguration,
                self.configuration.key(),
            ),
        ];
        let mut refusal = None;
        let mut committed = None;
        let mut change = Some(change);
        let result = self.store.fenced_replace(&keys, &mut |snapshots| {
            let decision = (|| {
                if snapshots.len() != 2 {
                    return Err(EngagementConfigurationError::Corrupt);
                }
                let bytes = snapshots[0]
                    .as_deref()
                    .ok_or(EngagementConfigurationError::Corrupt)?;
                let mut next = self.decode(bytes)?;
                let now = self.time(snapshots[1].as_deref(), adding_authority)?;
                if now < next.accepted_at {
                    return Err(EngagementConfigurationError::ClockRollback);
                }
                let before = next
                    .tree
                    .encode()
                    .map_err(|_| EngagementConfigurationError::Corrupt)?;
                change.take().ok_or(EngagementConfigurationError::Corrupt)?(&mut next.tree, now)?;
                if next
                    .tree
                    .encode()
                    .map_err(|_| EngagementConfigurationError::Corrupt)?
                    != before
                {
                    if next.revision == MAX_INTEGER {
                        return Err(EngagementConfigurationError::RevisionExhausted);
                    }
                    next.revision += 1;
                    next.accepted_at = now;
                }
                let encoded = self.record(&next)?;
                committed = Some(next);
                Ok(encoded)
            })();
            decision.map_err(|error| {
                refusal = Some(error);
                GatewayAttemptError::InvalidTransition
            })
        });
        match result {
            Ok(()) => committed.ok_or(EngagementConfigurationError::Corrupt),
            Err(error) => Err(refusal.unwrap_or(EngagementConfigurationError::Store(error))),
        }
    }

    /// Publishes an exact child only after reloading current ancestry and
    /// rechecking parent, child and resource evidence under the shared fence.
    ///
    /// # Errors
    /// Refuses inactive ancestry, reused identities, widening, stale evidence,
    /// changed configuration, clock rollback and failed/ambiguous persistence.
    pub fn enroll(
        &self,
        parent: [u8; 32],
        proofs: &ParticipantEnrollmentProofs<'_>,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        self.update(true, |tree, now| {
            tree.enroll(&self.context, parent, now, proofs).map(|_| ())
        })
    }

    /// Irreversibly withdraws a subtree using fresh native control authority
    /// under the common writer fence. Provider eligibility is not an additional
    /// withdrawal gate. Current shared configuration, qualification memory and
    /// trusted-time policy still apply; independent operator emergency stop
    /// remains the fallback when those inputs are unavailable.
    ///
    /// # Errors
    /// Refuses another root/subtree, invalid or stale control authority, changed
    /// installation, clock rollback and failed/ambiguous persistence.
    pub fn revoke(
        &self,
        invocation: &EnrollmentInvocation<'_>,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        self.update(false, |tree, now| {
            tree.revoke_authorized(&self.context, now, invocation)
        })
    }
}
