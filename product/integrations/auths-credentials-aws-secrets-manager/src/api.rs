//! The three service calls the store makes, and nothing else. There is no
//! call that lists, updates, rotates, or moves a staging label.

use async_trait::async_trait;
use std::time::Instant;
use thiserror::Error;
use zeroize::Zeroizing;

/// One secret version as the service returned it.
pub struct FetchedSecret {
    /// The version identifier the service says it returned.
    pub version: String,
    /// The secret bytes.
    pub bytes: Zeroizing<Vec<u8>>,
}

/// Why a service call did not succeed. Nothing here carries a secret, a
/// name, or the service's own message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum SecretsApiError {
    /// A secret with that name already exists.
    #[error("the secret already exists")]
    Exists,
    /// No such secret or version exists.
    #[error("the secret does not exist")]
    NotFound,
    /// The service did not answer in time, refused the caller, or answered
    /// with something that is not a complete, bounded response.
    #[error("the secret service is unavailable")]
    Unavailable,
}

/// The service calls of one deployment.
#[async_trait]
pub trait SecretsApi: Send + Sync {
    /// Creates a secret named `name` whose only version is `version`.
    async fn create(
        &self,
        name: &str,
        version: &str,
        secret: &[u8],
        deadline: Instant,
    ) -> Result<(), SecretsApiError>;

    /// Reads exactly `version` of the secret named `name`.
    async fn get(
        &self,
        name: &str,
        version: &str,
        deadline: Instant,
    ) -> Result<FetchedSecret, SecretsApiError>;

    /// Deletes the secret named `name` at once, with no recovery window.
    async fn delete(&self, name: &str, deadline: Instant) -> Result<(), SecretsApiError>;
}
