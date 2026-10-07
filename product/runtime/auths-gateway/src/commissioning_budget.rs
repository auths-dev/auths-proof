//! Permanent commissioning consumption on the existing opaque atomic store.
//!
//! This component reserves capacity; it neither leases a credential nor opens
//! the ordinary qualification gate. The authenticated operator creates the
//! record once during fresh setup. Runtime opening never initializes missing
//! state. Before custody, a private commissioning session must persist each
//! returned snapshot as a host-local floor retained independently of database
//! restores. A claimed unit is never refunded, including a crash before lease.

use crate::{
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayInsert, GatewayRecordEntry,
    GatewayRecordKind,
};
use auths_recipe_qualification::{
    CommissioningBinding, CommissioningRefusal, CommissioningRequest, MAX_REVOKED_SIGNERS,
    QualificationSignerId, Sha256Digest, VerifiedCommissioningPermit, VerifierState,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

/// The permanent counter/floor format, separate from qualifications and attempts.
pub const COMMISSIONING_BUDGET_SCHEMA: &str = "auths.gateway-commissioning-budget/1";
/// Fixed record limit checked before decoding store or floor bytes.
pub const MAX_COMMISSIONING_BUDGET_BYTES: usize = 16 * 1024;
/// A claim makes at most this many compare-and-swap attempts under contention.
pub const MAX_COMMISSIONING_CLAIM_RETRIES: usize = 16;

/// A closed refusal before any credential acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommissioningBudgetRefusal {
    /// The signed authority does not satisfy its current runtime check.
    Permit(CommissioningRefusal),
    /// Shared state could not be read or committed.
    Unavailable,
    /// Required permanent registration is absent; runtime never recreates it.
    Missing,
    /// Noncanonical, malformed or inconsistent stored/floor state.
    Corrupt,
    /// A renewal changed the immutable binding or capacity at the run's key.
    BindingMismatch,
    /// Database consumption/time/revocation state is below the retained floor.
    Rollback,
    /// The lifetime ceiling has already been consumed.
    Exhausted,
    /// Bounded contention retries ended; no lease was authorized by this call.
    Contention,
}

impl CommissioningBudgetRefusal {
    /// Stable commissioning code. These are never qualification verdicts.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Permit(CommissioningRefusal::Unavailable) => "gateway.commissioning.unavailable",
            Self::Permit(CommissioningRefusal::Revoked) => "gateway.commissioning.revoked",
            Self::Permit(CommissioningRefusal::RevocationRollback) => {
                "gateway.commissioning.revocation-rollback"
            }
            Self::Permit(CommissioningRefusal::ClockUntrusted) => {
                "gateway.commissioning.clock-untrusted"
            }
            Self::Permit(CommissioningRefusal::RevocationStale) => {
                "gateway.commissioning.revocation-stale"
            }
            Self::Permit(CommissioningRefusal::Expired) => "gateway.commissioning.expired",
            Self::Permit(CommissioningRefusal::BindingMismatch) | Self::BindingMismatch => {
                "gateway.commissioning.binding-mismatch"
            }
            Self::Unavailable => "gateway.commissioning.store-unavailable",
            Self::Missing => "gateway.commissioning.registration-missing",
            Self::Corrupt => "gateway.commissioning.state-corrupt",
            Self::Rollback => "gateway.commissioning.restore-rollback",
            Self::Exhausted => "gateway.commissioning.exhausted",
            Self::Contention => "gateway.commissioning.contention",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    budget_scope_sha256: Sha256Digest,
    budget_binding_sha256: Sha256Digest,
    maximum_credential_leases: u64,
    consumed_credential_leases: u64,
    latest_verifier_time: u64,
    accepted_revocation_sequence: u64,
    revoked_signers: BTreeSet<QualificationSignerId>,
}

/// Validated immutable registration plus its monotone consumption/trust state.
/// This is a storage receipt, never a credential or provider-entry capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissioningBudgetSnapshot {
    record: Record,
    bytes: Vec<u8>,
}

impl CommissioningBudgetSnapshot {
    /// Bytes the private session must durably retain before custody access.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lifetime acquisitions consumed, including claims followed by crashes.
    #[must_use]
    pub const fn consumed_credential_leases(&self) -> u64 {
        self.record.consumed_credential_leases
    }

    /// Immutable signed ceiling at this run/family's stable budget key.
    #[must_use]
    pub const fn maximum_credential_leases(&self) -> u64 {
        self.record.maximum_credential_leases
    }

    /// Restores a floor from canonical bytes for this exact reviewed binding.
    ///
    /// # Errors
    ///
    /// Returns a closed refusal before parsing oversized input, or when the
    /// schema, bounds, canonical form or immutable bindings differ.
    pub fn from_canonical_json(
        bytes: &[u8],
        binding: &CommissioningBinding,
    ) -> Result<Self, CommissioningBudgetRefusal> {
        if bytes.is_empty() || bytes.len() > MAX_COMMISSIONING_BUDGET_BYTES {
            return Err(CommissioningBudgetRefusal::Corrupt);
        }
        let record: Record =
            serde_json::from_slice(bytes).map_err(|_| CommissioningBudgetRefusal::Corrupt)?;
        let snapshot = Self::encode(record)?;
        if snapshot.bytes != bytes {
            return Err(CommissioningBudgetRefusal::Corrupt);
        }
        snapshot.matches(binding)?;
        Ok(snapshot)
    }

    fn encode(record: Record) -> Result<Self, CommissioningBudgetRefusal> {
        if record.schema != COMMISSIONING_BUDGET_SCHEMA
            || !(1..=auths_recipe_qualification::MAX_COMMISSIONING_LEASES)
                .contains(&record.maximum_credential_leases)
            || record.consumed_credential_leases > record.maximum_credential_leases
            || record.accepted_revocation_sequence > (1 << 53) - 1
            || record.latest_verifier_time > 253_402_300_799
            || record.revoked_signers.len() > MAX_REVOKED_SIGNERS
        {
            return Err(CommissioningBudgetRefusal::Corrupt);
        }
        let bytes = serde_json_canonicalizer::to_vec(&record)
            .map_err(|_| CommissioningBudgetRefusal::Corrupt)?;
        if bytes.len() > MAX_COMMISSIONING_BUDGET_BYTES {
            return Err(CommissioningBudgetRefusal::Corrupt);
        }
        Ok(Self { record, bytes })
    }

    fn matches(&self, binding: &CommissioningBinding) -> Result<(), CommissioningBudgetRefusal> {
        if self.record.budget_scope_sha256
            != binding
                .budget_key()
                .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?
            || self.record.budget_binding_sha256
                != binding
                    .budget_binding()
                    .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?
            || self.record.maximum_credential_leases != binding.maximum_credential_leases
        {
            return Err(CommissioningBudgetRefusal::BindingMismatch);
        }
        Ok(())
    }

    fn not_below(&self, floor: &Self) -> bool {
        self.record.budget_scope_sha256 == floor.record.budget_scope_sha256
            && self.record.budget_binding_sha256 == floor.record.budget_binding_sha256
            && self.record.maximum_credential_leases == floor.record.maximum_credential_leases
            && self.record.consumed_credential_leases >= floor.record.consumed_credential_leases
            && self.record.latest_verifier_time >= floor.record.latest_verifier_time
            && self.record.accepted_revocation_sequence >= floor.record.accepted_revocation_sequence
            && self
                .record
                .revoked_signers
                .is_superset(&floor.record.revoked_signers)
    }
}

/// An atomically committed counter/trust update, which the session must persist
/// as its floor before acting on `refusal`. Refused requests consume no unit;
/// authenticated revocations are nevertheless durably remembered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissioningBudgetUpdate {
    snapshot: CommissioningBudgetSnapshot,
    refusal: Option<CommissioningBudgetRefusal>,
}

impl CommissioningBudgetUpdate {
    /// Exact committed snapshot to retain outside database restores.
    #[must_use]
    pub const fn snapshot(&self) -> &CommissioningBudgetSnapshot {
        &self.snapshot
    }

    /// No credential acquisition when present, even though trust was recorded.
    #[must_use]
    pub const fn refusal(&self) -> Option<CommissioningBudgetRefusal> {
        self.refusal
    }
}

/// Capacity for one exact commissioning binding on an existing atomic store.
/// The production operator path must supply its production PostgreSQL backend;
/// development stores may exercise this mechanism without granting authority.
pub struct CommissioningBudget {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    binding: CommissioningBinding,
}

impl CommissioningBudget {
    /// Names the stable run/family key and its immutable reviewed binding.
    ///
    /// # Errors
    ///
    /// Returns [`CommissioningBudgetRefusal::BindingMismatch`] for a binding
    /// outside the shipping permit's production target and finite bounds.
    /// This constructor creates no state and opens no execution authority.
    pub fn new(
        store: Arc<dyn GatewayAttemptStore>,
        binding: CommissioningBinding,
    ) -> Result<Self, CommissioningBudgetRefusal> {
        binding
            .validate()
            .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?;
        let key = GatewayAttemptKey::from_bytes(
            *binding
                .budget_key()
                .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?
                .as_bytes(),
        );
        Ok(Self {
            store,
            key,
            binding,
        })
    }

    /// Registers capacity once during authenticated fresh operator setup.
    /// Existing capacity is checked and returned, never reset or overwritten.
    /// Runtime opening and renewal must use [`Self::load`] instead.
    ///
    /// # Errors
    ///
    /// Returns a store or binding refusal; a failed acknowledgement grants no
    /// capacity or credential capability. Retain the returned initial floor.
    pub fn initialize(&self) -> Result<CommissioningBudgetSnapshot, CommissioningBudgetRefusal> {
        let initial = CommissioningBudgetSnapshot::encode(Record {
            schema: COMMISSIONING_BUDGET_SCHEMA.to_owned(),
            budget_scope_sha256: self
                .binding
                .budget_key()
                .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?,
            budget_binding_sha256: self
                .binding
                .budget_binding()
                .map_err(|_| CommissioningBudgetRefusal::BindingMismatch)?,
            maximum_credential_leases: self.binding.maximum_credential_leases,
            consumed_credential_leases: 0,
            latest_verifier_time: 0,
            accepted_revocation_sequence: 0,
            revoked_signers: BTreeSet::new(),
        })?;
        match self
            .store
            .insert_all(&[GatewayRecordEntry {
                kind: GatewayRecordKind::CommissioningBudget,
                key: self.key,
                record: initial.bytes.clone(),
                expires_at: None,
            }])
            .map_err(store_refusal)?
        {
            GatewayInsert::Inserted => Ok(initial),
            GatewayInsert::Exists { .. } => self.load(),
        }
    }

    /// Reads existing permanent capacity; absence never creates a fresh counter.
    ///
    /// # Errors
    ///
    /// Returns a missing, unavailable, corrupt or changed-binding refusal.
    pub fn load(&self) -> Result<CommissioningBudgetSnapshot, CommissioningBudgetRefusal> {
        let bytes = self
            .store
            .load(GatewayRecordKind::CommissioningBudget, &self.key)
            .map_err(store_refusal)?
            .ok_or(CommissioningBudgetRefusal::Missing)?;
        CommissioningBudgetSnapshot::from_canonical_json(&bytes, &self.binding)
    }

    /// Atomically claims one lifetime unit after current signed authority checks.
    ///
    /// `floor` is this host's independently retained prior snapshot and `state`
    /// includes the installation's prior authenticated revocations. The caller
    /// must durably retain the returned snapshot before custody, including on
    /// a refusal. There is no refund or sweep operation. The normal gateway
    /// proof, action, reservation and attempt checks remain mandatory.
    ///
    /// # Errors
    ///
    /// Returns a store/binding/rollback/contention refusal without authorizing
    /// custody. Signed authority refusals and exhaustion are returned in the
    /// committed update so their revocation memory can be retained.
    pub fn claim(
        &self,
        authority: &VerifiedCommissioningPermit,
        request: &CommissioningRequest<'_>,
        now: u64,
        clock_trusted: bool,
        floor: &CommissioningBudgetSnapshot,
        state: &VerifierState,
    ) -> Result<CommissioningBudgetUpdate, CommissioningBudgetRefusal> {
        let authority_binding = &authority.permit().body().statement.binding;
        floor.matches(&self.binding)?;
        if authority_binding != &self.binding {
            return Err(CommissioningBudgetRefusal::BindingMismatch);
        }
        for _ in 0..MAX_COMMISSIONING_CLAIM_RETRIES {
            let current = self.load()?;
            if !current.not_below(floor) {
                return Err(CommissioningBudgetRefusal::Rollback);
            }
            let mut remembered = state.clone();
            remembered.accepted_revocation_sequence = remembered
                .accepted_revocation_sequence
                .max(current.record.accepted_revocation_sequence);
            remembered
                .revoked_signers
                .extend(current.record.revoked_signers.iter().cloned());
            authority.remember(&mut remembered);
            let mut next = current.record.clone();
            next.accepted_revocation_sequence = remembered.accepted_revocation_sequence;
            next.revoked_signers = remembered.revoked_signers.clone();
            let refusal = authority
                .evaluate(request, now, clock_trusted, &remembered)
                .err()
                .map(CommissioningBudgetRefusal::Permit)
                .or_else(|| {
                    if now < current.record.latest_verifier_time {
                        Some(CommissioningBudgetRefusal::Rollback)
                    } else if current.record.consumed_credential_leases
                        == current.record.maximum_credential_leases
                    {
                        Some(CommissioningBudgetRefusal::Exhausted)
                    } else {
                        None
                    }
                });
            if refusal.is_none() {
                next.consumed_credential_leases += 1;
                next.latest_verifier_time = now;
            }
            let next = CommissioningBudgetSnapshot::encode(next)?;
            match self.store.replace(
                GatewayRecordKind::CommissioningBudget,
                &self.key,
                &current.bytes,
                &next.bytes,
            ) {
                Ok(()) => {
                    return Ok(CommissioningBudgetUpdate {
                        snapshot: next,
                        refusal,
                    });
                }
                Err(GatewayAttemptError::Conflict) => {}
                Err(error) => return Err(store_refusal(error)),
            }
        }
        Err(CommissioningBudgetRefusal::Contention)
    }
}

const fn store_refusal(error: GatewayAttemptError) -> CommissioningBudgetRefusal {
    match error {
        GatewayAttemptError::Conflict => CommissioningBudgetRefusal::Contention,
        GatewayAttemptError::Unavailable => CommissioningBudgetRefusal::Unavailable,
        _ => CommissioningBudgetRefusal::Corrupt,
    }
}

#[cfg(test)]
mod tests;
