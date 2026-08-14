use crate::profiles::RuntimeFailure;
use auths_production_client::QualifiedProfile;
use postgres::{
    Client, Config, IsolationLevel,
    config::{Host, SslMode},
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use std::{path::Path, str::FromStr as _, sync::Mutex};
use tokio_postgres_rustls::MakeRustlsConnect;

const SCHEMA: &str = include_str!("../sandbox_v1.sql");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingEffect {
    pub(crate) profile: QualifiedProfile,
    pub(crate) authority: [u8; 32],
    pub(crate) action: Vec<u8>,
    pub(crate) created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredReceipt {
    pub(crate) profile: QualifiedProfile,
    pub(crate) completed_at: u64,
    pub(crate) bytes: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

pub(crate) trait SandboxStore: Send + Sync {
    fn claim_use(&self, authority: [u8; 32], maximum: u32) -> Result<(), RuntimeFailure>;
    fn put_pending(&self, reference: &str, pending: &PendingEffect) -> Result<(), RuntimeFailure>;
    fn pending(&self, reference: &str) -> Result<Option<PendingEffect>, RuntimeFailure>;
    fn recovered(&self, reference: &str) -> Result<Option<StoredReceipt>, RuntimeFailure>;
    fn put_receipt(&self, receipt_id: &str, receipt: &StoredReceipt) -> Result<(), RuntimeFailure>;
    fn receipt(&self, receipt_id: &str) -> Result<Option<StoredReceipt>, RuntimeFailure>;
    fn finish_pending(
        &self,
        reference: &str,
        expected: &PendingEffect,
        receipt_id: &str,
        receipt: &StoredReceipt,
    ) -> Result<StoredReceipt, RuntimeFailure>;
    fn ready(&self) -> bool;
}

#[derive(Default)]
pub(crate) struct MemorySandboxStore {
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    uses: std::collections::BTreeMap<[u8; 32], u32>,
    pending: std::collections::BTreeMap<String, PendingEffect>,
    receipts: std::collections::BTreeMap<String, StoredReceipt>,
    recovery: std::collections::BTreeMap<String, String>,
}

impl SandboxStore for MemorySandboxStore {
    fn claim_use(&self, authority: [u8; 32], maximum: u32) -> Result<(), RuntimeFailure> {
        let mut state = self.state.lock().map_err(|_| RuntimeFailure::Unavailable)?;
        let uses = state.uses.entry(authority).or_default();
        if *uses >= maximum {
            return Err(RuntimeFailure::Denied);
        }
        *uses += 1;
        Ok(())
    }

    fn put_pending(&self, reference: &str, pending: &PendingEffect) -> Result<(), RuntimeFailure> {
        let mut state = self.state.lock().map_err(|_| RuntimeFailure::Unavailable)?;
        if state
            .pending
            .insert(reference.into(), pending.clone())
            .is_some()
        {
            return Err(RuntimeFailure::Unavailable);
        }
        Ok(())
    }

    fn pending(&self, reference: &str) -> Result<Option<PendingEffect>, RuntimeFailure> {
        self.state
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)
            .map(|state| state.pending.get(reference).cloned())
    }

    fn recovered(&self, reference: &str) -> Result<Option<StoredReceipt>, RuntimeFailure> {
        self.state
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)
            .map(|state| {
                state
                    .recovery
                    .get(reference)
                    .and_then(|id| state.receipts.get(id))
                    .cloned()
            })
    }

    fn put_receipt(&self, receipt_id: &str, receipt: &StoredReceipt) -> Result<(), RuntimeFailure> {
        self.state
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?
            .receipts
            .insert(receipt_id.into(), receipt.clone());
        Ok(())
    }

    fn receipt(&self, receipt_id: &str) -> Result<Option<StoredReceipt>, RuntimeFailure> {
        self.state
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)
            .map(|state| state.receipts.get(receipt_id).cloned())
    }

    fn finish_pending(
        &self,
        reference: &str,
        expected: &PendingEffect,
        receipt_id: &str,
        receipt: &StoredReceipt,
    ) -> Result<StoredReceipt, RuntimeFailure> {
        let mut state = self.state.lock().map_err(|_| RuntimeFailure::Unavailable)?;
        if let Some(existing) = state
            .recovery
            .get(reference)
            .and_then(|id| state.receipts.get(id))
        {
            return Ok(existing.clone());
        }
        if state.pending.get(reference) != Some(expected) {
            return Err(RuntimeFailure::UnknownWorkflow);
        }
        state.pending.remove(reference);
        state.receipts.insert(receipt_id.into(), receipt.clone());
        state.recovery.insert(reference.into(), receipt_id.into());
        Ok(receipt.clone())
    }

    fn ready(&self) -> bool {
        self.state.lock().is_ok()
    }
}

pub struct PostgresSandboxStore {
    client: Mutex<Client>,
    maximum_records: i64,
}

impl PostgresSandboxStore {
    pub fn connect(
        connection: &str,
        root_certificate: &Path,
        expected_server_name: &str,
        maximum_records: usize,
    ) -> Result<Self, RuntimeFailure> {
        let maximum_records =
            i64::try_from(maximum_records).map_err(|_| RuntimeFailure::Malformed)?;
        let database = Config::from_str(connection).map_err(|_| RuntimeFailure::Malformed)?;
        if database.get_ssl_mode() != SslMode::Require
            || database.get_hosts().len() != 1
            || !matches!(&database.get_hosts()[0], Host::Tcp(host) if host == expected_server_name)
        {
            return Err(RuntimeFailure::Malformed);
        }
        let mut roots = RootCertStore::empty();
        let certificates = CertificateDer::pem_file_iter(root_certificate)
            .map_err(|_| RuntimeFailure::Malformed)?;
        let mut count = 0_usize;
        for certificate in certificates {
            roots
                .add(certificate.map_err(|_| RuntimeFailure::Malformed)?)
                .map_err(|_| RuntimeFailure::Malformed)?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(RuntimeFailure::Malformed);
        }
        let tls = MakeRustlsConnect::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut client = database
            .connect(tls)
            .map_err(|_| RuntimeFailure::Unavailable)?;
        initialize(&mut client)?;
        Ok(Self {
            client: Mutex::new(client),
            maximum_records,
        })
    }
}

impl SandboxStore for PostgresSandboxStore {
    fn claim_use(&self, authority: [u8; 32], maximum: u32) -> Result<(), RuntimeFailure> {
        let maximum = i64::from(maximum);
        let affected = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?
            .query_opt(
                "INSERT INTO auths_sandbox_uses (authority_digest, uses)
                 VALUES ($1, 1)
                 ON CONFLICT (authority_digest) DO UPDATE
                 SET uses = auths_sandbox_uses.uses + 1
                 WHERE auths_sandbox_uses.uses < $2
                 RETURNING uses",
                &[&&authority[..], &maximum],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        affected.map_or(Err(RuntimeFailure::Denied), |_| Ok(()))
    }

    fn put_pending(&self, reference: &str, pending: &PendingEffect) -> Result<(), RuntimeFailure> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        enforce_capacity(&mut transaction, self.maximum_records)?;
        transaction
            .execute(
                "INSERT INTO auths_sandbox_pending
                 (reference, profile, authority_digest, action_bytes, created_at)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &reference,
                    &pending.profile.as_str(),
                    &&pending.authority[..],
                    &pending.action,
                    &i64::try_from(pending.created_at).map_err(|_| RuntimeFailure::Malformed)?,
                ],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| RuntimeFailure::Unavailable)
    }

    fn pending(&self, reference: &str) -> Result<Option<PendingEffect>, RuntimeFailure> {
        let row = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?
            .query_opt(
                "SELECT profile, authority_digest, action_bytes, created_at
                 FROM auths_sandbox_pending WHERE reference = $1",
                &[&reference],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        row.map(decode_pending).transpose()
    }

    fn recovered(&self, reference: &str) -> Result<Option<StoredReceipt>, RuntimeFailure> {
        let row = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?
            .query_opt(
                "SELECT r.profile, r.completed_at, r.receipt_bytes, r.value_bytes
                 FROM auths_sandbox_recovery x
                 JOIN auths_sandbox_receipts r ON r.receipt_id = x.receipt_id
                 WHERE x.reference = $1",
                &[&reference],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        row.map(decode_receipt).transpose()
    }

    fn put_receipt(&self, receipt_id: &str, receipt: &StoredReceipt) -> Result<(), RuntimeFailure> {
        let completed_at =
            i64::try_from(receipt.completed_at).map_err(|_| RuntimeFailure::Malformed)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        enforce_capacity(&mut transaction, self.maximum_records)?;
        transaction
            .execute(
                "INSERT INTO auths_sandbox_receipts
                 (receipt_id, profile, completed_at, receipt_bytes, value_bytes)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (receipt_id) DO NOTHING",
                &[
                    &receipt_id,
                    &receipt.profile.as_str(),
                    &completed_at,
                    &receipt.bytes,
                    &receipt.value,
                ],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| RuntimeFailure::Unavailable)
    }

    fn receipt(&self, receipt_id: &str) -> Result<Option<StoredReceipt>, RuntimeFailure> {
        let row = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?
            .query_opt(
                "SELECT profile, completed_at, receipt_bytes, value_bytes
                 FROM auths_sandbox_receipts WHERE receipt_id = $1",
                &[&receipt_id],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        row.map(decode_receipt).transpose()
    }

    fn finish_pending(
        &self,
        reference: &str,
        expected: &PendingEffect,
        receipt_id: &str,
        receipt: &StoredReceipt,
    ) -> Result<StoredReceipt, RuntimeFailure> {
        let completed_at =
            i64::try_from(receipt.completed_at).map_err(|_| RuntimeFailure::Malformed)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        let pending = transaction
            .query_opt(
                "SELECT profile, authority_digest, action_bytes, created_at
                 FROM auths_sandbox_pending WHERE reference = $1 FOR UPDATE",
                &[&reference],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?
            .map(decode_pending)
            .transpose()?;
        let Some(pending) = pending else {
            let existing = transaction
                .query_opt(
                    "SELECT r.profile, r.completed_at, r.receipt_bytes, r.value_bytes
                     FROM auths_sandbox_recovery x
                     JOIN auths_sandbox_receipts r ON r.receipt_id = x.receipt_id
                     WHERE x.reference = $1",
                    &[&reference],
                )
                .map_err(|_| RuntimeFailure::Unavailable)?
                .map(decode_receipt)
                .transpose()?
                .ok_or(RuntimeFailure::UnknownWorkflow)?;
            transaction
                .commit()
                .map_err(|_| RuntimeFailure::Unavailable)?;
            return Ok(existing);
        };
        if &pending != expected {
            return Err(RuntimeFailure::Denied);
        }
        enforce_capacity(&mut transaction, self.maximum_records)?;
        transaction
            .execute(
                "INSERT INTO auths_sandbox_receipts
                 (receipt_id, profile, completed_at, receipt_bytes, value_bytes)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (receipt_id) DO NOTHING",
                &[
                    &receipt_id,
                    &receipt.profile.as_str(),
                    &completed_at,
                    &receipt.bytes,
                    &receipt.value,
                ],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO auths_sandbox_recovery (reference, receipt_id) VALUES ($1, $2)",
                &[&reference, &receipt_id],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM auths_sandbox_pending WHERE reference = $1",
                &[&reference],
            )
            .map_err(|_| RuntimeFailure::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| RuntimeFailure::Unavailable)?;
        Ok(receipt.clone())
    }

    fn ready(&self) -> bool {
        self.client
            .lock()
            .ok()
            .and_then(|mut client| client.query_one("SELECT 1", &[]).ok())
            .is_some()
    }
}

fn initialize(client: &mut Client) -> Result<(), RuntimeFailure> {
    client
        .query_one("SELECT pg_advisory_lock(4175544858375229441)", &[])
        .map_err(|_| RuntimeFailure::Unavailable)?;
    let result = initialize_locked(client);
    let unlocked = client
        .query_one("SELECT pg_advisory_unlock(4175544858375229441)", &[])
        .and_then(|row| row.try_get::<_, bool>(0))
        .map_err(|_| RuntimeFailure::Unavailable)?;
    if !unlocked {
        return Err(RuntimeFailure::Unavailable);
    }
    result
}

fn initialize_locked(client: &mut Client) -> Result<(), RuntimeFailure> {
    let present: bool = client
        .query_one("SELECT to_regclass('auths_sandbox_meta') IS NOT NULL", &[])
        .and_then(|row| row.try_get(0))
        .map_err(|_| RuntimeFailure::Unavailable)?;
    if !present {
        client
            .batch_execute(SCHEMA)
            .map_err(|_| RuntimeFailure::Unavailable)?;
    }
    let row = client
        .query_one(
            "SELECT schema_version, contract_id FROM auths_sandbox_meta WHERE singleton = TRUE",
            &[],
        )
        .map_err(|_| RuntimeFailure::Unavailable)?;
    let version: i32 = row.try_get(0).map_err(|_| RuntimeFailure::Unavailable)?;
    let contract: String = row.try_get(1).map_err(|_| RuntimeFailure::Unavailable)?;
    if version != 2 || contract != "auths.sandbox.shared-state/2" {
        return Err(RuntimeFailure::Unavailable);
    }
    Ok(())
}

fn enforce_capacity(
    transaction: &mut postgres::Transaction<'_>,
    maximum_records: i64,
) -> Result<(), RuntimeFailure> {
    transaction
        .query_one(
            "SELECT singleton FROM auths_sandbox_meta WHERE singleton = TRUE FOR UPDATE",
            &[],
        )
        .map_err(|_| RuntimeFailure::Unavailable)?;
    let records: i64 = transaction
        .query_one(
            "SELECT (SELECT count(*) FROM auths_sandbox_pending)
                  + (SELECT count(*) FROM auths_sandbox_receipts)",
            &[],
        )
        .and_then(|row| row.try_get(0))
        .map_err(|_| RuntimeFailure::Unavailable)?;
    if records >= maximum_records {
        return Err(RuntimeFailure::Unavailable);
    }
    Ok(())
}

fn decode_pending(row: postgres::Row) -> Result<PendingEffect, RuntimeFailure> {
    let profile: String = row.try_get(0).map_err(|_| RuntimeFailure::Unavailable)?;
    let authority: Vec<u8> = row.try_get(1).map_err(|_| RuntimeFailure::Unavailable)?;
    let action: Vec<u8> = row.try_get(2).map_err(|_| RuntimeFailure::Unavailable)?;
    let created_at: i64 = row.try_get(3).map_err(|_| RuntimeFailure::Unavailable)?;
    Ok(PendingEffect {
        profile: QualifiedProfile::parse(&profile).map_err(|_| RuntimeFailure::Unavailable)?,
        authority: authority
            .try_into()
            .map_err(|_| RuntimeFailure::Unavailable)?,
        action,
        created_at: u64::try_from(created_at).map_err(|_| RuntimeFailure::Unavailable)?,
    })
}

fn decode_receipt(row: postgres::Row) -> Result<StoredReceipt, RuntimeFailure> {
    let profile: String = row.try_get(0).map_err(|_| RuntimeFailure::Unavailable)?;
    let completed_at: i64 = row.try_get(1).map_err(|_| RuntimeFailure::Unavailable)?;
    let bytes: Vec<u8> = row.try_get(2).map_err(|_| RuntimeFailure::Unavailable)?;
    let value: Vec<u8> = row.try_get(3).map_err(|_| RuntimeFailure::Unavailable)?;
    Ok(StoredReceipt {
        profile: QualifiedProfile::parse(&profile).map_err(|_| RuntimeFailure::Unavailable)?,
        completed_at: u64::try_from(completed_at).map_err(|_| RuntimeFailure::Unavailable)?,
        bytes,
        value,
    })
}
