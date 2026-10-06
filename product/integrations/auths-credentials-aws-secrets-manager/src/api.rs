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

/// An operator process's separate read and write workload identities.
/// Reads use only `reader`; creates and exact deletes use only `writer`.
/// No failure falls back to the other identity or changes the request.
pub struct AdministrativeSecretsApi<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> AdministrativeSecretsApi<R, W> {
    /// Combines independently configured clients for one reviewed deployment.
    #[must_use]
    pub const fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

#[async_trait]
impl<R: SecretsApi, W: SecretsApi> SecretsApi for AdministrativeSecretsApi<R, W> {
    async fn create(
        &self,
        name: &str,
        version: &str,
        secret: &[u8],
        deadline: Instant,
    ) -> Result<(), SecretsApiError> {
        self.writer.create(name, version, secret, deadline).await
    }

    async fn get(
        &self,
        name: &str,
        version: &str,
        deadline: Instant,
    ) -> Result<FetchedSecret, SecretsApiError> {
        self.reader.get(name, version, deadline).await
    }

    async fn delete(&self, name: &str, deadline: Instant) -> Result<(), SecretsApiError> {
        self.writer.delete(name, deadline).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum Role {
        Reader,
        Writer,
    }

    struct RoleClient {
        role: Role,
        unavailable: bool,
    }

    #[async_trait]
    impl SecretsApi for RoleClient {
        async fn create(
            &self,
            name: &str,
            version: &str,
            secret: &[u8],
            deadline: Instant,
        ) -> Result<(), SecretsApiError> {
            assert_eq!(
                (name, version, secret),
                ("exact-name", "exact-version", b"synthetic-value".as_slice())
            );
            assert!(deadline > Instant::now());
            assert!(matches!(self.role, Role::Writer), "reader cannot create");
            if self.unavailable {
                Err(SecretsApiError::Unavailable)
            } else {
                Ok(())
            }
        }

        async fn get(
            &self,
            name: &str,
            version: &str,
            deadline: Instant,
        ) -> Result<FetchedSecret, SecretsApiError> {
            assert_eq!((name, version), ("exact-name", "exact-version"));
            assert!(deadline > Instant::now());
            assert!(matches!(self.role, Role::Reader), "writer cannot read");
            if self.unavailable {
                Err(SecretsApiError::Unavailable)
            } else {
                Ok(FetchedSecret {
                    version: version.to_owned(),
                    bytes: Zeroizing::new(b"synthetic-value".to_vec()),
                })
            }
        }

        async fn delete(&self, name: &str, deadline: Instant) -> Result<(), SecretsApiError> {
            assert_eq!(name, "exact-name");
            assert!(deadline > Instant::now());
            assert!(matches!(self.role, Role::Writer), "reader cannot delete");
            if self.unavailable {
                Err(SecretsApiError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn operator_administration_uses_separate_permissions_without_fallback() {
        for reader_failed in [false, true] {
            for writer_failed in [false, true] {
                let api = AdministrativeSecretsApi::new(
                    RoleClient {
                        role: Role::Reader,
                        unavailable: reader_failed,
                    },
                    RoleClient {
                        role: Role::Writer,
                        unavailable: writer_failed,
                    },
                );
                let deadline = Instant::now() + std::time::Duration::from_secs(5);
                let write = if writer_failed {
                    Err(SecretsApiError::Unavailable)
                } else {
                    Ok(())
                };
                assert_eq!(
                    api.create("exact-name", "exact-version", b"synthetic-value", deadline)
                        .await,
                    write
                );
                assert_eq!(api.delete("exact-name", deadline).await, write);
                match api.get("exact-name", "exact-version", deadline).await {
                    Ok(secret) => {
                        assert!(!reader_failed);
                        assert_eq!(secret.version, "exact-version");
                        assert_eq!(&*secret.bytes, b"synthetic-value");
                    }
                    Err(error) => {
                        assert!(reader_failed);
                        assert_eq!(error, SecretsApiError::Unavailable);
                    }
                }
            }
        }
    }
}
