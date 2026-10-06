//! The `aws-secrets-manager-v1` provider-secret store.
//!
//! One Secrets Manager secret holds one credential generation in exactly one
//! version. Both the secret's name and its version identifier are derived
//! from what a connection record already seals, so no external location is
//! stored anywhere and a lease reads one exact version without listing.
//!
//! The store is told a connection, generations, and a commitment. It has no
//! input that names a provider, a recipe, an address, a header, or an action.
//!
//! [`SecretsApi`] is the three service calls the store makes. The store's
//! rules are tested against an in-memory implementation of it that can
//! answer wrongly on purpose. [`HttpSecretsApi`] is the network
//! implementation: one attempt per call, bounded by the caller's deadline,
//! signed with short-lived credentials from a [`WorkloadIdentity`]. A static
//! access key is not a workload identity and no source reads one.

#![forbid(unsafe_code)]

mod api;
mod clock;
mod http;
mod identity;
mod names;
mod sigv4;
mod store;

pub use api::{AdministrativeSecretsApi, FetchedSecret, SecretsApi, SecretsApiError};
pub use http::{HttpSecretsApi, InvalidDeployment, Region};
pub use identity::{
    ContainerEndpoint, InstanceMetadata, SessionCredentials, WebIdentity, WorkloadIdentity,
};
pub use names::{
    DeploymentNamespace, InvalidNamespace, SECRET_NAME_DOMAIN, SECRET_VERSION_DOMAIN,
    is_exact_version, secret_name, secret_version,
};
pub use sigv4::{SignedRequest, SigningInput, sign};
pub use store::AwsSecretsManagerStore;
