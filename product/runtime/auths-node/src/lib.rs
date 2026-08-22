#![forbid(unsafe_code)]

pub mod connection_admin;
pub mod generated;
mod journal_executor;
pub mod local_agent;
pub mod local_deployment;
mod preparation_evidence;
pub mod profile_configuration;
mod profile_launch;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
mod qualification_crash;
mod receipt_attestor;
pub mod recovery_handle;
pub mod shutdown;
pub mod workload_authority;

#[cfg(feature = "qualification-failpoints")]
pub use generated::profile_routes::built_in_qualification_local_profiles;
#[cfg(feature = "testkit-agent")]
pub use generated::profile_routes::built_in_testkit_local_profiles;
pub use generated::profile_routes::{built_in_local_profiles, built_in_operation_limits};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub use local_agent::QualificationClientBridgePolicy;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub use local_agent::QualificationCredentialBrokerPolicy;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub use local_agent::QualificationProviderProxyPolicy;
pub use local_agent::{
    ConfiguredWorkloadAuthenticator, LocalAgentFailure, LocalAgentState, PeerCredentials,
    RegisteredLocalProfile, local_agent_app,
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub use local_deployment::bind_qualification_control_plane;
#[cfg(unix)]
pub use local_deployment::load_receipt_trust_anchors;
#[cfg(feature = "testkit-agent")]
pub use local_deployment::provision_testkit_stripe_connection;
#[cfg(unix)]
pub use local_deployment::{
    BoundLocalControlPlane, bind_local_control_plane, serve_local_control_plane,
};
#[cfg(all(unix, feature = "testkit-agent"))]
pub use local_deployment::{BoundTestkitAgent, bind_testkit_agent};
pub use local_deployment::{
    LocalAgentDeploymentConfig, LocalAgentDeploymentError, LocalAgentResources,
};
#[cfg(feature = "testkit-agent")]
pub use receipt_attestor::TestkitReceiptAnchor;
pub use recovery_handle::{RecoveryHandleError, RecoveryHandleSigner, VerifiedRecoveryHandle};
pub use workload_authority::{
    WorkloadAuthority, WorkloadAuthorityError, WorkloadAuthoritySnapshot, pack_workload_authority,
};
