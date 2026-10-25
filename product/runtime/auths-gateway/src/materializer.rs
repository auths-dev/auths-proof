//! Operator-installed, post-admission provider credential materialization.
//!
//! The connection store still leases its exact committed source reference.
//! This port turns that source into one short-lived request credential only
//! after a task operation has been durably reserved. Provider-specific grant
//! and scope checks belong in a custody adapter, never in a recipe or action.

use async_trait::async_trait;
use auths_connections::StoredSecretLease;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

/// The kind of already admitted task operation requesting a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRequestKind {
    /// One bounded provider GET for an agent release.
    ReadRelease,
    /// One gateway-owned provider write.
    WriteEffect,
}

/// Closed task and connection facts supplied only by the gateway after an
/// irreversible operation reservation. No field names a provider endpoint,
/// credential source path, token body or materializer implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMaterializationContext {
    pub task_id: String,
    pub operation_id: String,
    pub connection_id: String,
    pub connection_generation: u64,
    pub source_generation: u64,
    pub account_subject: String,
    pub recipe_digest: String,
    pub task_expires_at: u64,
    pub kind: CredentialRequestKind,
}

/// The custody adapter's subject and effective-authority assertion for a
/// deadline-bound bearer. The bearer remains zeroized and has no debug form.
pub struct MaterializedCredential {
    pub lease: StoredSecretLease,
    pub account_subject: String,
    pub effective_authority_digest: [u8; 32],
}

impl fmt::Debug for MaterializedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterializedCredential([REDACTED])")
    }
}

/// Failure has no provider or secret details in public gateway output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("provider credential materialization refused")]
pub struct CredentialMaterializationError;

/// A custody adapter installed by the operator for one exact source family.
/// It must verify source generation, client/audience/scopes, provider subject
/// and provider expiry before returning a bearer; the gateway independently
/// checks the returned subject, authority digest, size and lease deadline.
#[async_trait]
pub trait CredentialMaterializer: Send + Sync {
    /// Materialize only the already admitted operation in `context`.
    async fn materialize(
        &self,
        context: &CredentialMaterializationContext,
        source: &StoredSecretLease,
        deadline: Instant,
    ) -> Result<MaterializedCredential, CredentialMaterializationError>;
}

/// Operator pin for an exact client/audience/scope authority set. A failed
/// materialization never falls back to the source reference as a bearer.
pub struct MaterializerInstallation {
    adapter: Arc<dyn CredentialMaterializer>,
    authority_digest: [u8; 32],
}

impl MaterializerInstallation {
    /// Bind the adapter and one reviewed effective-authority digest.
    #[must_use]
    pub fn new(adapter: Arc<dyn CredentialMaterializer>, authority_digest: [u8; 32]) -> Self {
        Self {
            adapter,
            authority_digest,
        }
    }

    pub(crate) async fn lease(
        &self,
        context: &CredentialMaterializationContext,
        source: &StoredSecretLease,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialMaterializationError> {
        let result = self.adapter.materialize(context, source, deadline).await?;
        if result.account_subject != context.account_subject
            || !bool::from(
                result
                    .effective_authority_digest
                    .ct_eq(&self.authority_digest),
            )
            || result.lease.deadline() > deadline
            || !result
                .lease
                .expose(Instant::now())
                .is_ok_and(|bytes| (1..=65_536).contains(&bytes.len()))
        {
            return Err(CredentialMaterializationError);
        }
        Ok(result.lease)
    }
}

pub(crate) fn task_lease_deadline(
    source: &StoredSecretLease,
    task_expires_at: u64,
) -> Option<Instant> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let remaining = task_expires_at
        .checked_sub(now)
        .filter(|value| *value > 0)?;
    let task_deadline = Instant::now().checked_add(Duration::from_secs(remaining))?;
    Some(source.deadline().min(task_deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    struct CheckedAdapter {
        calls: Mutex<Vec<CredentialMaterializationContext>>,
        subject: String,
        authority: [u8; 32],
        extend_deadline: bool,
        empty_bearer: bool,
    }

    #[async_trait]
    impl CredentialMaterializer for CheckedAdapter {
        async fn materialize(
            &self,
            context: &CredentialMaterializationContext,
            source: &StoredSecretLease,
            deadline: Instant,
        ) -> Result<MaterializedCredential, CredentialMaterializationError> {
            assert_eq!(
                source.expose(Instant::now()).unwrap(),
                b"opaque-source-reference"
            );
            self.calls.lock().unwrap().push(context.clone());
            Ok(MaterializedCredential {
                lease: StoredSecretLease::from_store(
                    Zeroizing::new(if self.empty_bearer {
                        Vec::new()
                    } else {
                        b"fresh-bearer".to_vec()
                    }),
                    if self.extend_deadline {
                        deadline + Duration::from_secs(1)
                    } else {
                        deadline
                    },
                ),
                account_subject: self.subject.clone(),
                effective_authority_digest: self.authority,
            })
        }
    }

    fn context(operation_id: &str) -> CredentialMaterializationContext {
        CredentialMaterializationContext {
            task_id: "task-1".into(),
            operation_id: operation_id.into(),
            connection_id: "connection-1".into(),
            connection_generation: 2,
            source_generation: 1,
            account_subject: "human-subject".into(),
            recipe_digest: "recipe-digest".into(),
            task_expires_at: u64::MAX,
            kind: CredentialRequestKind::WriteEffect,
        }
    }

    #[tokio::test]
    async fn materialization_binds_subject_authority_and_deadline_per_operation() {
        let source = StoredSecretLease::from_store(
            Zeroizing::new(b"opaque-source-reference".to_vec()),
            Instant::now() + Duration::from_secs(30),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let adapter = Arc::new(CheckedAdapter {
            calls: Mutex::new(Vec::new()),
            subject: "human-subject".into(),
            authority: [7; 32],
            extend_deadline: false,
            empty_bearer: false,
        });
        let installation = MaterializerInstallation::new(adapter.clone(), [7; 32]);
        for operation in ["operation-1", "operation-2"] {
            let bearer = installation
                .lease(&context(operation), &source, deadline)
                .await
                .unwrap();
            assert_eq!(bearer.expose(Instant::now()).unwrap(), b"fresh-bearer");
        }
        assert_eq!(
            adapter
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|call| call.operation_id.as_str())
                .collect::<Vec<_>>(),
            ["operation-1", "operation-2"]
        );
        for (subject, authority, extend_deadline, empty_bearer) in [
            ("other-subject", [7; 32], false, false),
            ("human-subject", [8; 32], false, false),
            ("human-subject", [7; 32], true, false),
            ("human-subject", [7; 32], false, true),
        ] {
            let rejected = MaterializerInstallation::new(
                Arc::new(CheckedAdapter {
                    calls: Mutex::new(Vec::new()),
                    subject: subject.into(),
                    authority,
                    extend_deadline,
                    empty_bearer,
                }),
                [7; 32],
            );
            assert!(
                rejected
                    .lease(&context("operation-3"), &source, deadline)
                    .await
                    .is_err()
            );
        }
    }
}
