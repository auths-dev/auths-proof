//! Secret-free measurements at custody and HTTP execution boundaries.
//!
//! These are process-local diagnostics, never authority or proof of a remote
//! effect. A runner must use snapshots from the same scope, wait for its calls
//! to finish, and independently read back every claimed provider effect.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// One process-local execution measurement, read through the private operator
/// channel. Counts include attempted calls that subsequently fail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayExecutionWitness {
    /// Exactly `auths.gateway-execution-witness/1`.
    pub schema: String,
    /// Fresh random scope for this engine instance. Different scopes must
    /// never be subtracted, including after a process restart.
    pub scope: String,
    /// Actual execution calls to the credential store's lease method.
    pub credential_lease_calls: u64,
    /// Closed write requests passed to the HTTP client's execution method.
    /// This includes ambiguous failures, and does not prove remote receipt.
    pub write_transport_entries: u64,
    /// Read requests passed to the HTTP client's execution method, including
    /// credential probes. These are not provider writes.
    pub read_transport_entries: u64,
}

pub(crate) struct ExecutionWitness {
    scope: String,
    leases: AtomicU64,
    writes: AtomicU64,
    reads: AtomicU64,
}

impl ExecutionWitness {
    pub(crate) fn new() -> Result<Self, getrandom::Error> {
        let mut scope = [0; 16];
        getrandom::fill(&mut scope)?;
        Ok(Self {
            scope: hex::encode(scope),
            leases: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        })
    }

    pub(crate) fn lease(&self) {
        increment(&self.leases);
    }

    pub(crate) fn write(&self) {
        increment(&self.writes);
    }

    pub(crate) fn read(&self) {
        increment(&self.reads);
    }

    pub(crate) fn snapshot(&self) -> GatewayExecutionWitness {
        GatewayExecutionWitness {
            schema: "auths.gateway-execution-witness/1".to_owned(),
            scope: self.scope.clone(),
            credential_lease_calls: self.leases.load(Ordering::SeqCst),
            write_transport_entries: self.writes.load(Ordering::SeqCst),
            read_transport_entries: self.reads.load(Ordering::SeqCst),
        }
    }
}

fn increment(counter: &AtomicU64) {
    // Saturation is explicit: an evidence consumer must refuse saturated
    // snapshots. Wrapping could make a later snapshot appear to precede one.
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        Some(value.saturating_add(1))
    });
}
