//! Shared installed configuration and permanent qualification memory.
//!
//! This record participates in the same writer fence as attempts and connection
//! changes. A local manifest or cached qualification bundle cannot replace it.

use crate::{
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayRecordEntry,
    GatewayRecordKind, QualificationGate,
};
use auths_recipe_qualification::{
    MAX_REVOKED_QUALIFICATIONS, MAX_REVOKED_SIGNERS, QualificationId, QualificationSignerId,
    VerifierState,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

const SCHEMA: &str = "auths.effect-configuration/1";
const MAX_BYTES: usize = 131_072;
const MAX_INTEGER: u64 = (1 << 53) - 1;
const UNAVAILABLE: &str = "gateway.configuration.unavailable";
const CHANGED: &str = "gateway.configuration.changed";

/// Bounded union of authenticated revocation memories. Saturation is terminal
/// denial, never truncation followed by authorization with forgotten entries.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationMemory {
    pub(crate) accepted_revocation_sequence: u64,
    pub(crate) accepted_index_issued_at: u64,
    pub(crate) revoked_signers: BTreeSet<QualificationSignerId>,
    pub(crate) revoked_qualifications: BTreeSet<QualificationId>,
    pub(crate) blocked: bool,
}

impl QualificationMemory {
    pub(crate) fn merge(&mut self, state: &VerifierState) {
        self.accepted_revocation_sequence = self
            .accepted_revocation_sequence
            .max(state.accepted_revocation_sequence);
        self.accepted_index_issued_at = self
            .accepted_index_issued_at
            .max(state.accepted_index_issued_at);
        if self.accepted_revocation_sequence > MAX_INTEGER
            || self.accepted_index_issued_at > MAX_INTEGER
        {
            self.blocked = true;
            self.accepted_revocation_sequence = self.accepted_revocation_sequence.min(MAX_INTEGER);
            self.accepted_index_issued_at = self.accepted_index_issued_at.min(MAX_INTEGER);
        }
        for signer in &state.revoked_signers {
            if !self.revoked_signers.contains(signer)
                && self.revoked_signers.len() == MAX_REVOKED_SIGNERS
            {
                self.blocked = true;
                break;
            }
            self.revoked_signers.insert(signer.clone());
        }
        for qualification in &state.revoked_qualifications {
            if !self.revoked_qualifications.contains(qualification)
                && self.revoked_qualifications.len() == MAX_REVOKED_QUALIFICATIONS
            {
                self.blocked = true;
                break;
            }
            self.revoked_qualifications.insert(qualification.clone());
        }
    }

    pub(crate) fn state(&self) -> VerifierState {
        VerifierState {
            accepted_revocation_sequence: self.accepted_revocation_sequence,
            accepted_index_issued_at: self.accepted_index_issued_at,
            revoked_signers: self.revoked_signers.clone(),
            revoked_qualifications: self.revoked_qualifications.clone(),
        }
    }

    fn valid(&self) -> bool {
        self.accepted_revocation_sequence <= MAX_INTEGER
            && self.accepted_index_issued_at <= MAX_INTEGER
            && self.revoked_signers.len() <= MAX_REVOKED_SIGNERS
            && self.revoked_qualifications.len() <= MAX_REVOKED_QUALIFICATIONS
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationSnapshot {
    pub(crate) bundle: Option<[u8; 32]>,
    pub(crate) memory: QualificationMemory,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    installation: [u8; 32],
    revision: u64,
    qualification: QualificationSnapshot,
}

fn encode(record: &Record) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json_canonicalizer::to_vec(record).map_err(|_| UNAVAILABLE)?;
    if bytes.len() > MAX_BYTES {
        return Err(UNAVAILABLE);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<Record, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(UNAVAILABLE);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| UNAVAILABLE)?;
    if record.schema != SCHEMA
        || !(1..=MAX_INTEGER).contains(&record.revision)
        || !record.qualification.memory.valid()
        || encode(&record)? != bytes
    {
        return Err(UNAVAILABLE);
    }
    Ok(record)
}

fn decode(bytes: &[u8], installation: &[u8; 32]) -> Result<Record, &'static str> {
    let record = decode_record(bytes)?;
    if &record.installation != installation {
        return Err(CHANGED);
    }
    Ok(record)
}

pub(crate) fn digest<T: Serialize>(domain: &str, value: &T) -> Result<[u8; 32], &'static str> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|_| UNAVAILABLE)?;
    if bytes.len() > MAX_BYTES {
        return Err(UNAVAILABLE);
    }
    auths_codec::domain_commitment(domain, &bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| UNAVAILABLE)
}

/// Trusted installation owner; not exposed on the application channel.
#[derive(Clone)]
pub(crate) struct SharedConfiguration {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    installation: [u8; 32],
}

impl SharedConfiguration {
    pub(crate) fn new(
        store: Arc<dyn GatewayAttemptStore>,
        key: [u8; 32],
        installation: [u8; 32],
    ) -> Self {
        Self {
            store,
            key: GatewayAttemptKey::from_bytes(key),
            installation,
        }
    }

    pub(crate) fn candidate(&self) -> [u8; 32] {
        self.installation
    }

    /// Only the trusted install/join command may create a missing record.
    pub(crate) fn initialize(&self, gate: &QualificationGate) -> Result<(), &'static str> {
        let record = Record {
            schema: SCHEMA.to_owned(),
            installation: self.installation,
            revision: 1,
            qualification: gate.shared_snapshot(&QualificationMemory::default()),
        };
        match self.store.insert(&GatewayRecordEntry {
            kind: GatewayRecordKind::EffectConfiguration,
            key: self.key,
            record: encode(&record)?,
            expires_at: None,
        }) {
            Ok(()) => Ok(()),
            Err(GatewayAttemptError::Replay) => self.publish(gate),
            Err(_) => Err(UNAVAILABLE),
        }
    }

    /// Publishes already authenticated local inputs under the shared fence.
    /// It merges permanent memory even when the candidate no longer qualifies.
    /// Invalid/unloaded candidates disable entry; they cannot erase revocation.
    pub(crate) fn publish(&self, gate: &QualificationGate) -> Result<(), &'static str> {
        let mut refusal = UNAVAILABLE;
        self.store
            .fenced_replace(
                &[(GatewayRecordKind::EffectConfiguration, self.key)],
                &mut |snapshots| {
                    let current = snapshots[0]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?;
                    let mut record = decode(current, &self.installation).map_err(|code| {
                        refusal = code;
                        GatewayAttemptError::Corrupt
                    })?;
                    let mut next = gate.shared_snapshot(&record.qualification.memory);
                    if next == record.qualification {
                        return Ok(current.to_vec());
                    }
                    if record.revision == MAX_INTEGER {
                        next.memory.blocked = true;
                    } else {
                        record.revision += 1;
                    }
                    record.qualification = next;
                    encode(&record).map_err(|_| GatewayAttemptError::Corrupt)
                },
            )
            .map_err(|_| refusal)
    }

    /// Private operator review token over the current record, including its
    /// revision and remembered revocations. This token grants no authority.
    pub(crate) fn current_revision(&self) -> Result<[u8; 32], &'static str> {
        let bytes = self
            .store
            .load(GatewayRecordKind::EffectConfiguration, &self.key)
            .map_err(|_| UNAVAILABLE)?
            .ok_or(UNAVAILABLE)?;
        let record = decode_record(&bytes)?;
        digest("auths.effect-configuration-revision/1", &record)
    }

    /// Explicit trusted operator activation. A stale review token loses the
    /// CAS; replacing configuration never resets permanent revocation memory.
    pub(crate) fn activate(
        &self,
        expected: [u8; 32],
        gate: &QualificationGate,
    ) -> Result<(), &'static str> {
        self.store
            .fenced_replace(
                &[(GatewayRecordKind::EffectConfiguration, self.key)],
                &mut |snapshots| {
                    let mut record = decode_record(
                        snapshots[0]
                            .as_deref()
                            .ok_or(GatewayAttemptError::Corrupt)?,
                    )
                    .map_err(|_| GatewayAttemptError::Corrupt)?;
                    if digest("auths.effect-configuration-revision/1", &record)
                        .map_err(|_| GatewayAttemptError::Corrupt)?
                        != expected
                    {
                        return Err(GatewayAttemptError::Conflict);
                    }
                    // A saturated record cannot be reactivated by a new configuration.
                    if record.revision == MAX_INTEGER || record.qualification.memory.blocked {
                        return Err(GatewayAttemptError::InvalidTransition);
                    }
                    record.installation = self.installation;
                    record.revision += 1;
                    record.qualification = gate.shared_snapshot(&record.qualification.memory);
                    encode(&record).map_err(|_| GatewayAttemptError::Corrupt)
                },
            )
            .map_err(|_| CHANGED)
    }

    /// Validates an already fenced snapshot; performs no nested store read.
    pub(crate) fn check_snapshot(
        &self,
        bytes: &[u8],
        gate: &QualificationGate,
    ) -> Result<(), &'static str> {
        let record = decode(bytes, &self.installation)?;
        gate.accept_shared(&record.qualification)
    }

    /// Early availability check. Final entry must repeat this against the
    /// snapshot acquired inside its own attempt transaction.
    pub(crate) fn check(&self, gate: &QualificationGate) -> Result<(), &'static str> {
        let bytes = self
            .store
            .load(GatewayRecordKind::EffectConfiguration, &self.key)
            .map_err(|_| UNAVAILABLE)?
            .ok_or(UNAVAILABLE)?;
        self.check_snapshot(&bytes, gate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_testkit::{Backend, TestAttempts, postgres_configured};

    fn gate(state: VerifierState) -> QualificationGate {
        QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(crate::DevelopmentClock),
            state,
        )
    }

    #[test]
    fn native_configuration_fixture_is_current() {
        let policy = crate::effect::fixture_policy().expect("policy");
        let namespace =
            crate::OperatorNamespace::parse("synthetic-configuration").expect("namespace");
        let key = policy.configuration_key(&namespace).expect("key");
        let record = Record {
            schema: SCHEMA.to_owned(),
            installation: [11; 32],
            revision: 1,
            qualification: gate(VerifierState::default())
                .shared_snapshot(&QualificationMemory::default()),
        };
        let canonical = encode(&record).expect("record");
        assert_eq!(decode(&canonical, &[11; 32]).expect("decode").revision, 1);
        assert!(decode(&canonical, &[12; 32]).is_err());
        let mut padded = canonical.clone();
        padded.push(b' ');
        assert!(decode(&padded, &[11; 32]).is_err());
        let fixture = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "auths.effect-configuration-fixture/1",
            "scope": "native configuration encoding and revision identity; no entry claim",
            "key_hex": hex::encode(key),
            "record_canonical": String::from_utf8(canonical).expect("UTF-8"),
            "revision_token_hex": hex::encode(digest("auths.effect-configuration-revision/1", &record).expect("revision")),
        })).expect("fixture");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/gateway/effect-configuration.json");
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, &fixture).expect("write native fixture");
        }
        assert_eq!(std::fs::read(path).expect("fixture"), fixture);
    }

    async fn shared_configuration_conformance(backend: Backend) {
        let store = TestAttempts::open(backend);
        let (first, second) = (store.raw(), store.raw());
        tokio::task::spawn_blocking(move || {
            let key = crate::effect::fixture_policy()
                .expect("policy")
                .configuration_key(
                    &crate::OperatorNamespace::parse("shared-config").expect("namespace"),
                )
                .expect("key");
            let original = SharedConfiguration::new(first, key, [11; 32]);
            let candidate = SharedConfiguration::new(second, key, [12; 32]);
            let old_gate = gate(VerifierState::default());
            assert!(
                original.check(&old_gate).is_err(),
                "application cannot initialize missing state"
            );
            original.initialize(&old_gate).expect("operator install");
            let stale = original.current_revision().expect("revision");
            let signer = QualificationSignerId::parse("synthetic-revoked-signer").expect("signer");
            let revoked = VerifierState {
                accepted_revocation_sequence: 3,
                accepted_index_issued_at: 4,
                revoked_signers: BTreeSet::from([signer.clone()]),
                ..VerifierState::default()
            };
            original
                .publish(&gate(revoked))
                .expect("publish shared memory");
            original.check(&old_gate).expect("adopt shared memory");
            assert!(old_gate.verifier_state().revoked_signers.contains(&signer));
            assert!(
                candidate.initialize(&old_gate).is_err(),
                "joining cannot overwrite a different configuration"
            );
            assert!(
                candidate.activate(stale, &old_gate).is_err(),
                "stale operator review loses CAS"
            );
            candidate
                .activate(
                    original.current_revision().expect("fresh revision"),
                    &old_gate,
                )
                .expect("operator activation");
            assert_eq!(original.check(&old_gate), Err(CHANGED));
            assert_eq!(original.publish(&old_gate), Err(CHANGED));
            let restarted = gate(VerifierState::default());
            candidate.check(&restarted).expect("restarted host");
            assert!(restarted.verifier_state().revoked_signers.contains(&signer));
            assert_eq!(restarted.verifier_state().accepted_revocation_sequence, 3);
            candidate
                .publish(&gate(VerifierState::default()))
                .expect("older empty local memory");
            let retained = gate(VerifierState::default());
            candidate.check(&retained).expect("retained shared memory");
            assert!(retained.verifier_state().revoked_signers.contains(&signer));
            let mut saturated = VerifierState::default();
            saturated.revoked_signers = (0..=MAX_REVOKED_SIGNERS)
                .map(|n| {
                    QualificationSignerId::parse(format!("synthetic-signer-{n}")).expect("signer")
                })
                .collect();
            candidate
                .publish(&gate(saturated))
                .expect("durable saturated denial");
            assert!(candidate.check(&retained).is_err());
            candidate
                .publish(&gate(VerifierState::default()))
                .expect("still saturated");
            assert!(
                candidate.check(&retained).is_err(),
                "publishing cannot forget saturation"
            );
            assert!(
                candidate
                    .activate(candidate.current_revision().expect("revision"), &retained)
                    .is_err(),
                "activation cannot reset permanent memory"
            );
            assert_eq!(
                candidate
                    .store
                    .sweep_expired(u64::MAX / 2, 64)
                    .expect("sweep"),
                0
            );
            assert!(
                candidate.current_revision().is_ok(),
                "configuration never expires"
            );
        })
        .await
        .expect("shared configuration conformance");
    }

    #[tokio::test]
    async fn file_configuration_changes_fence_stale_hosts_and_retain_revocations() {
        shared_configuration_conformance(Backend::File).await;
    }

    #[tokio::test]
    #[ignore = "requires the TLS PostgreSQL fixture"]
    async fn postgres_configuration_changes_fence_stale_hosts_and_retain_revocations() {
        assert!(postgres_configured());
        shared_configuration_conformance(Backend::Postgres).await;
    }
}
