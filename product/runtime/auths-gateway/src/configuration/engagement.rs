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

mod audit;
mod blob;
pub use audit::{
    EngagementAudit, EngagementAuditCheckpoint, EngagementControlEvidence,
    MAX_ENGAGEMENT_CONTROL_BYTES,
};

const SCHEMA: &str = "auths.engagement-configuration/2";
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
    /// Required private original evidence exceeded a finite supported bound.
    #[error("engagement audit evidence limit exceeded")]
    EvidenceLimit,
    /// An acknowledged audit reference has no complete retained evidence.
    #[error("engagement audit evidence is missing")]
    MissingEvidence,
    /// An audit root, context or checkpoint was not independently trusted.
    #[error("engagement audit trusted inputs differ")]
    UntrustedEvidence,
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
            Self::EvidenceLimit => "gateway.engagement.evidence-limit",
            Self::MissingEvidence => "gateway.engagement.evidence-missing",
            Self::UntrustedEvidence => "gateway.engagement.evidence-untrusted",
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
    #[serde(deserialize_with = "audit::deserialize_events")]
    events: Vec<audit::Event>,
}

/// Operator-private retained configuration. This is historical data, never a
/// current authorization, capacity reservation or an execution/delivery permit.
#[derive(Clone, Eq, PartialEq)]
pub struct EngagementConfigurationSnapshot {
    root: [u8; 32],
    revision: u64,
    accepted_at: u64,
    tree: EnrollmentTree,
    events: Vec<audit::Event>,
}

impl std::fmt::Debug for EngagementConfigurationSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngagementConfigurationSnapshot { private: [redacted] }")
    }
}

impl EngagementConfigurationSnapshot {
    /// Checkpoint of exactly these acknowledged private configuration bytes.
    /// Retain it through a trusted channel independently of an audit bundle;
    /// this digest is not a signature, trusted timestamp or rollback detector.
    /// # Errors
    /// Refuses malformed or oversized retained configuration.
    pub fn audit_checkpoint(
        &self,
    ) -> Result<EngagementAuditCheckpoint, EngagementConfigurationError> {
        audit::EngagementAuditCheckpoint::for_record(
            &record_snapshot(self)?,
            self.root,
            self.revision,
        )
    }
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

fn record_snapshot(
    snapshot: &EngagementConfigurationSnapshot,
) -> Result<Vec<u8>, EngagementConfigurationError> {
    audit::validate_history(snapshot)?;
    let tree = String::from_utf8(
        snapshot
            .tree
            .encode()
            .map_err(|_| EngagementConfigurationError::Corrupt)?,
    )
    .map_err(|_| EngagementConfigurationError::Corrupt)?;
    encode(&Record {
        schema: SCHEMA.into(),
        root: snapshot.root,
        revision: snapshot.revision,
        accepted_at: snapshot.accepted_at,
        tree,
        events: snapshot.events.clone(),
    })
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
        let key = *Self::key_for_root(&root)?.as_bytes();
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

    pub(crate) fn key_for_root(
        root: &ParentEnrollmentPins,
    ) -> Result<GatewayAttemptKey, EngagementConfigurationError> {
        let key = super::digest(
            "auths.engagement-configuration-key/1",
            &(
                &root.admission_namespace,
                &root.admission_partition,
                root.engagement_commitment,
            ),
        )
        .map_err(|_| EngagementConfigurationError::Installation)?;
        Ok(GatewayAttemptKey::from_bytes(key))
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
        Self::decode_for_root(&self.root, bytes)
    }

    pub(crate) fn decode_for_root(
        root: &ParentEnrollmentPins,
        bytes: &[u8],
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(EngagementConfigurationError::Corrupt);
        }
        let record: Record =
            serde_json::from_slice(bytes).map_err(|_| EngagementConfigurationError::Corrupt)?;
        if record.schema != SCHEMA
            || record.root != root.enrollment_commitment
            || !(1..=MAX_INTEGER).contains(&record.revision)
            || record.accepted_at > MAX_INTEGER
            || encode(&record)? != bytes
        {
            return Err(EngagementConfigurationError::Corrupt);
        }
        let tree = EnrollmentTree::decode(record.tree.as_bytes(), root)
            .map_err(|_| EngagementConfigurationError::Corrupt)?;
        let snapshot = EngagementConfigurationSnapshot {
            root: record.root,
            revision: record.revision,
            accepted_at: record.accepted_at,
            tree,
            events: record.events,
        };
        audit::validate_history(&snapshot)?;
        Ok(snapshot)
    }

    fn record(
        &self,
        snapshot: &EngagementConfigurationSnapshot,
    ) -> Result<Vec<u8>, EngagementConfigurationError> {
        if snapshot.root != self.root.enrollment_commitment {
            return Err(EngagementConfigurationError::Corrupt);
        }
        record_snapshot(snapshot)
    }

    fn preview_time(&self, adding_authority: bool) -> Result<u64, EngagementConfigurationError> {
        let bytes = self.store.load(
            GatewayRecordKind::EffectConfiguration,
            &self.configuration.key(),
        )?;
        self.time(bytes.as_deref(), adding_authority)
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
        self.bootstrap_evidence(audit::EngagementControlEvidence::root(proofs)?)
    }

    /// Applies owned original evidence through the same native control owner.
    /// This operator handle uses only its independently installed root/context.
    /// It grants no effect/approval authority or provider/disclosure permit.
    /// # Errors
    /// Refuses invalid evidence, current authority or failed/ambiguous storage.
    pub fn apply_control(
        &self,
        evidence: EngagementControlEvidence,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        evidence.to_private_bytes()?;
        if evidence.is_root() {
            self.bootstrap_evidence(evidence)
        } else {
            self.update(evidence.is_enrollment(), evidence)
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one prepared original-evidence publication and final native root fence"
    )]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the control transition owns original evidence through its publication fence"
    )]
    fn bootstrap_evidence(
        &self,
        evidence: EngagementControlEvidence,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        if let Some(bytes) = self
            .store
            .load(GatewayRecordKind::EffectConfiguration, &self.key)?
        {
            return self.decode(&bytes);
        }
        let now = self.preview_time(true)?;
        let tree = evidence.apply(&self.root, &self.context, None, now)?;
        let preview = EngagementConfigurationSnapshot {
            root: self.root.enrollment_commitment,
            revision: 1,
            accepted_at: now,
            tree,
            events: Vec::new(),
        };
        let staged = audit::Staged::prepare(&*self.store, &self.context, &evidence, |staged| {
            let mut preview = preview.clone();
            preview.events.push(staged.event(&preview, None)?);
            audit::validate_history(&preview)
        })?;
        let manifests = staged.entries()?;
        let mut dependencies = vec![(
            GatewayRecordKind::EffectConfiguration,
            self.configuration.key(),
        )];
        dependencies.extend(manifests.iter().map(|entry| (entry.kind, entry.key)));
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::EffectConfiguration,
            key: self.key,
            record: b"unpublished native decision".to_vec(),
            expires_at: None,
        };
        let mut refusal = None;
        let mut committed = None;
        let result = self
            .store
            .fenced_insert_all(&[entry], &dependencies, &mut |snapshots| {
                let decision = (|| {
                    if snapshots.len() != dependencies.len() {
                        return Err(EngagementConfigurationError::Corrupt);
                    }
                    let now = self.time(snapshots[0].as_deref(), true)?;
                    staged.validate(&snapshots[1..])?;
                    let tree = evidence.apply(&self.root, &self.context, None, now)?;
                    let mut next = EngagementConfigurationSnapshot {
                        root: self.root.enrollment_commitment,
                        revision: 1,
                        accepted_at: now,
                        tree,
                        events: Vec::new(),
                    };
                    next.events.push(staged.event(&next, None)?);
                    let bytes = self.record(&next)?;
                    committed = Some(next);
                    Ok(bytes)
                })();
                decision.map_err(|error| {
                    refusal = Some(error);
                    GatewayAttemptError::InvalidTransition
                })
            });
        match result {
            Ok(GatewayInsert::Inserted) => committed.ok_or(EngagementConfigurationError::Corrupt),
            Ok(GatewayInsert::Exists { index: 0 }) => self.snapshot(),
            Ok(GatewayInsert::Exists { .. }) => Err(EngagementConfigurationError::Corrupt),
            Err(error) => Err(refusal.unwrap_or(EngagementConfigurationError::Store(error))),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one control transition keeps evidence preparation separate from its final native publication fence"
    )]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the control transition owns original evidence through its publication fence"
    )]
    fn update(
        &self,
        adding_authority: bool,
        evidence: audit::EngagementControlEvidence,
    ) -> Result<EngagementConfigurationSnapshot, EngagementConfigurationError> {
        let current = self.snapshot()?;
        let now = self.preview_time(adding_authority)?;
        if now < current.accepted_at {
            return Err(EngagementConfigurationError::ClockRollback);
        }
        let tree = evidence.apply(&self.root, &self.context, Some(&current.tree), now)?;
        let staged = if tree == current.tree {
            None
        } else {
            let before = audit::tree_commitment(&current.tree)?;
            let mut preview = current.clone();
            preview.tree = tree;
            preview.revision += 1;
            preview.accepted_at = now;
            Some(audit::Staged::prepare(
                &*self.store,
                &self.context,
                &evidence,
                |staged| {
                    preview.events.push(staged.event(&preview, Some(before))?);
                    audit::validate_history(&preview)
                },
            )?)
        };
        let mut keys = vec![
            (GatewayRecordKind::EffectConfiguration, self.key),
            (
                GatewayRecordKind::EffectConfiguration,
                self.configuration.key(),
            ),
        ];
        if let Some(staged) = &staged {
            keys.extend(staged.entries()?.iter().map(|e| (e.kind, e.key)));
        }
        let mut refusal = None;
        let mut committed = None;
        let result = self.store.fenced_replace(&keys, &mut |snapshots| {
            let decision = (|| {
                if snapshots.len() != keys.len() {
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
                let tree = evidence.apply(&self.root, &self.context, Some(&next.tree), now)?;
                if tree != next.tree {
                    let staged = staged
                        .as_ref()
                        .ok_or(EngagementConfigurationError::Corrupt)?;
                    staged.validate(&snapshots[2..])?;
                    if next.events.len() >= audit::MAX_EVENTS {
                        return Err(EngagementConfigurationError::RevisionExhausted);
                    }
                    let before = audit::tree_commitment(&next.tree)?;
                    next.tree = tree;
                    next.revision += 1;
                    next.accepted_at = now;
                    next.events.push(staged.event(&next, Some(before))?);
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
        self.update(
            true,
            audit::EngagementControlEvidence::enroll(parent, proofs)?,
        )
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
        self.update(
            false,
            audit::EngagementControlEvidence::revoke(*invocation)?,
        )
    }
}
