//! Authenticated local IPC agent for generated profile packages.

#![forbid(unsafe_code)]
// Route handlers deliberately mirror the closed local-agent protocol one for
// one; retaining that layout makes authentication and pre-I/O failures easy to
// audit against the wire contract.
#![allow(
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::similar_names
)]

use async_trait::async_trait;
use auths_config::{AgentConfig, ConnectionSelection, WorkloadSelector};
use auths_model::{ProfileId, ProfileRef};
use auths_production_client::{
    ExecuteOperationRequest, LOCAL_AGENT_CONTENT_TYPE, MAX_LOCAL_REQUEST_BYTES,
    MAX_LOCAL_RESPONSE_BYTES, OperationId, PreparationEvidenceRequest, PrepareOperationRequest,
    ProfileAdvertisement, ProfileRoute, RecoverOperationRequest, SessionMode, SessionProfileKey,
    SessionResponse, decode_execute_operation_request, decode_preparation_evidence_request,
    decode_prepare_operation_request, decode_recover_operation_request, decode_session_request,
    encode_session_response,
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use auths_profile_kit::{QualificationAdmissionFaultV1, QualificationClientBridgeBindingV1};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use axum::serve::{IncomingStream, Listener};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use std::path::Component;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use tokio::{io::AsyncReadExt, time::timeout};
use tokio::{net::UnixListener, sync::RwLock};

use crate::{
    journal_executor::JournaledLocalExecutor,
    profile_configuration::ProfileConfigurationSnapshot,
    workload_authority::{WorkloadAuthority, WorkloadAuthorityError, WorkloadAuthoritySnapshot},
};

const MAX_SESSIONS: usize = 4_096;
const MAX_SESSIONS_PER_PRINCIPAL: usize = 64;
const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16_384;
#[cfg(target_os = "linux")]
const MAX_EXECUTABLE_BYTES: u64 = 1_073_741_824;
const SESSION_IDLE: Duration = Duration::from_hours(1);
const SESSION_LIFETIME: Duration = Duration::from_hours(24);

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Authenticated POSIX peer observation associated with one accepted stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerCredentials {
    /// Effective user ID observed by the kernel.
    pub uid: u32,
    /// Effective group ID observed by the kernel.
    pub gid: u32,
    /// Peer process ID when the host exposes it.
    pub pid: Option<u32>,
    /// Protected, phase-selected admission fault. Production listeners never
    /// construct this field.
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub qualification_fault: Option<QualificationAdmissionFaultV1>,
}

#[cfg(unix)]
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, UnixListener>>
    for PeerCredentials
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, UnixListener>) -> Self {
        stream.io().peer_cred().map_or(
            Self {
                uid: u32::MAX,
                gid: u32::MAX,
                pid: None,
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                qualification_fault: None,
            },
            |credentials| Self {
                uid: credentials.uid(),
                gid: credentials.gid(),
                pid: credentials
                    .pid()
                    .and_then(|value| u32::try_from(value).ok()),
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                qualification_fault: None,
            },
        )
    }
}

/// Immutable policy for the qualification-only ClientProxy bridge.
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationClientBridgePolicy {
    reader_uid: u32,
    reader_gid: u32,
    reader_artifact_sha256: String,
    source_context_sha256: String,
}

/// Immutable policy for the qualification-only credential broker.
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationCredentialBrokerPolicy {
    socket: PathBuf,
    reader_uid: u32,
    reader_artifact_sha256: String,
    source_context_sha256: [u8; 32],
}

/// Immutable policy for the qualification-only provider transport proxy.
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationProviderProxyPolicy {
    socket: PathBuf,
    reader_uid: u32,
    reader_artifact_sha256: String,
    source_context_sha256: [u8; 32],
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationCredentialBrokerPolicy {
    /// Constructs one exact protected broker-reader policy.
    pub fn new(
        socket: impl Into<PathBuf>,
        reader_uid: u32,
        reader_artifact_sha256: impl Into<String>,
        source_context_sha256: impl Into<String>,
    ) -> Result<Self, LocalAgentFailure> {
        let socket = socket.into();
        let reader_artifact_sha256 = reader_artifact_sha256.into();
        let source_context_sha256 = source_context_sha256.into();
        let mut decoded_context = [0_u8; 32];
        if !socket.is_absolute()
            || socket
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            || reader_uid == 0
            || reader_uid == u32::MAX
            || !lower_hex_digest(&reader_artifact_sha256)
            || !lower_hex_digest(&source_context_sha256)
            || hex::decode_to_slice(&source_context_sha256, &mut decoded_context).is_err()
        {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        Ok(Self {
            socket,
            reader_uid,
            reader_artifact_sha256,
            source_context_sha256: decoded_context,
        })
    }

    pub(crate) fn socket(&self) -> &std::path::Path {
        &self.socket
    }

    pub(crate) const fn reader_uid(&self) -> u32 {
        self.reader_uid
    }

    pub(crate) fn reader_artifact_sha256(&self) -> &str {
        &self.reader_artifact_sha256
    }

    pub(crate) const fn source_context_sha256(&self) -> &[u8; 32] {
        &self.source_context_sha256
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationProviderProxyPolicy {
    /// Constructs one exact protected ProviderProxy-reader policy.
    pub fn new(
        socket: impl Into<PathBuf>,
        reader_uid: u32,
        reader_artifact_sha256: impl Into<String>,
        source_context_sha256: impl Into<String>,
    ) -> Result<Self, LocalAgentFailure> {
        let socket = socket.into();
        let reader_artifact_sha256 = reader_artifact_sha256.into();
        let source_context_sha256 = source_context_sha256.into();
        let mut decoded_context = [0_u8; 32];
        if !socket.is_absolute()
            || socket
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            || reader_uid == 0
            || reader_uid == u32::MAX
            || !lower_hex_digest(&reader_artifact_sha256)
            || !lower_hex_digest(&source_context_sha256)
            || hex::decode_to_slice(&source_context_sha256, &mut decoded_context).is_err()
        {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        Ok(Self {
            socket,
            reader_uid,
            reader_artifact_sha256,
            source_context_sha256: decoded_context,
        })
    }

    pub(crate) fn socket(&self) -> &std::path::Path {
        &self.socket
    }
    pub(crate) const fn reader_uid(&self) -> u32 {
        self.reader_uid
    }
    pub(crate) fn reader_artifact_sha256(&self) -> &str {
        &self.reader_artifact_sha256
    }
    pub(crate) const fn source_context_sha256(&self) -> &[u8; 32] {
        &self.source_context_sha256
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationClientBridgePolicy {
    /// Constructs one exact protected-reader policy.
    pub fn new(
        reader_uid: u32,
        reader_gid: u32,
        reader_artifact_sha256: impl Into<String>,
        source_context_sha256: impl Into<String>,
    ) -> Result<Self, LocalAgentFailure> {
        let reader_artifact_sha256 = reader_artifact_sha256.into();
        let source_context_sha256 = source_context_sha256.into();
        if reader_uid == 0
            || reader_uid == u32::MAX
            || reader_gid == 0
            || reader_gid == u32::MAX
            || !lower_hex_digest(&reader_artifact_sha256)
            || !lower_hex_digest(&source_context_sha256)
        {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        Ok(Self {
            reader_uid,
            reader_gid,
            reader_artifact_sha256,
            source_context_sha256,
        })
    }

    pub(crate) const fn reader_uid(&self) -> u32 {
        self.reader_uid
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
struct QualificationClientBridgeListener {
    listener: UnixListener,
    policy: QualificationClientBridgePolicy,
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationClientBridgeListener {
    const fn new(listener: UnixListener, policy: QualificationClientBridgePolicy) -> Self {
        Self { listener, policy }
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl Listener for QualificationClientBridgeListener {
    type Io = tokio::net::UnixStream;
    type Addr = PeerCredentials;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((mut stream, _)) = self.listener.accept().await else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            let policy = self.policy.clone();
            let Ok(peer) = qualification_bridge_peer(&mut stream, policy).await else {
                continue;
            };
            return (stream, peer);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(PeerCredentials {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            qualification_fault: None,
        })
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl axum::extract::connect_info::Connected<IncomingStream<'_, QualificationClientBridgeListener>>
    for PeerCredentials
{
    fn connect_info(stream: IncomingStream<'_, QualificationClientBridgeListener>) -> Self {
        *stream.remote_addr()
    }
}

/// Workload identity and least-privilege visibility established from the peer.
#[derive(Clone, Debug)]
pub struct AuthorizedWorkload {
    workload_id: Arc<str>,
    principal: Arc<str>,
    allowed_profiles: Arc<BTreeSet<String>>,
    connections: Arc<Vec<ConnectionSelection>>,
    authority: Arc<WorkloadAuthority>,
    profile_configurations: ProfileConfigurationSnapshot,
}

impl AuthorizedWorkload {
    /// Returns the deployment workload identifier used for connection
    /// authorization. It comes from the authenticated peer mapping.
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    /// Returns the observed principal, never a caller-supplied selector.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Returns the exact configured connection visibility set.
    #[must_use]
    pub fn connections(&self) -> &[ConnectionSelection] {
        &self.connections
    }
    fn permits(&self, profile: &SessionProfileKey) -> bool {
        let Ok(id) = ProfileId::parse(profile.id()) else {
            return false;
        };
        let Ok(authority_profile) = ProfileRef::new(id, profile.version()) else {
            return false;
        };
        self.allowed_profiles
            .contains(&format!("{}/{}", profile.id(), profile.version()))
            && self.authority.permits(&authority_profile)
    }
}

/// Peer-to-workload authentication boundary.
#[async_trait]
pub trait LocalWorkloadAuthenticator: Send + Sync {
    /// Resolves exactly one configured workload from kernel-observed peer facts.
    async fn authenticate(
        &self,
        peer: PeerCredentials,
    ) -> Result<AuthorizedWorkload, LocalAgentFailure>;
}

/// Fixed peer mapping for the separately packaged disposable testkit agent.
///
/// The type exists only under the `testkit-agent` feature. It accepts one
/// exact local UID, one synthetic principal, the Stripe refund profile, and a
/// single non-secret connection alias. Production configuration cannot select
/// or deserialize it.
#[cfg(feature = "testkit-agent")]
#[derive(Clone)]
pub struct TestkitWorkloadAuthenticator {
    uid: u32,
    workload: AuthorizedWorkload,
}

#[cfg(feature = "testkit-agent")]
impl TestkitWorkloadAuthenticator {
    /// Constructs the fixed disposable workload mapping.
    pub fn new(uid: u32, connection_alias: &str) -> Result<Self, LocalAgentFailure> {
        let id = ProfileId::parse("auths.stripe.refund")
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let profile =
            ProfileRef::new(id, 1).map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let connection = ConnectionSelection::new("stripe", connection_alias, true)
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        Ok(Self {
            uid,
            workload: AuthorizedWorkload {
                workload_id: Arc::from("auths-testkit"),
                principal: Arc::from("did:example:auths-testkit"),
                allowed_profiles: Arc::new(BTreeSet::from(["auths.stripe.refund/1".to_owned()])),
                connections: Arc::new(vec![connection]),
                authority: Arc::new(WorkloadAuthority::for_testkit(
                    "did:example:auths-testkit",
                    profile,
                )),
                profile_configurations: ProfileConfigurationSnapshot::default(),
            },
        })
    }
}

#[cfg(feature = "testkit-agent")]
#[async_trait]
impl LocalWorkloadAuthenticator for TestkitWorkloadAuthenticator {
    async fn authenticate(
        &self,
        peer: PeerCredentials,
    ) -> Result<AuthorizedWorkload, LocalAgentFailure> {
        if peer.uid != self.uid {
            return Err(LocalAgentFailure::Unauthenticated);
        }
        Ok(self.workload.clone())
    }
}

/// Strict workload authenticator backed by `auths-config`.
#[derive(Clone)]
pub struct ConfiguredWorkloadAuthenticator {
    state: Arc<std::sync::RwLock<ConfiguredAuthenticatorState>>,
    agent_uid: u32,
    mutable_state_root: Arc<PathBuf>,
    launch_flavor: crate::profile_launch::LaunchFlavor,
}

struct ConfiguredAuthenticatorState {
    config: Arc<AgentConfig>,
    authorities: WorkloadAuthoritySnapshot,
    profile_configurations: ProfileConfigurationSnapshot,
}

impl ConfiguredWorkloadAuthenticator {
    /// Loads all sealed authorities before making the authenticator available.
    ///
    /// # Errors
    ///
    /// Fails atomically if any source or workload binding is unsafe or invalid.
    #[cfg(unix)]
    pub fn load(
        config: AgentConfig,
        agent_uid: u32,
        mutable_state_root: PathBuf,
    ) -> Result<Self, WorkloadAuthorityError> {
        Self::load_for(
            config,
            agent_uid,
            mutable_state_root,
            crate::profile_launch::LaunchFlavor::Production,
        )
    }

    #[cfg(unix)]
    pub(crate) fn load_for(
        config: AgentConfig,
        agent_uid: u32,
        mutable_state_root: PathBuf,
        launch_flavor: crate::profile_launch::LaunchFlavor,
    ) -> Result<Self, WorkloadAuthorityError> {
        let authorities = WorkloadAuthoritySnapshot::load(&config, agent_uid)?;
        let profile_configurations =
            ProfileConfigurationSnapshot::load(&config, agent_uid, &mutable_state_root)
                .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        crate::generated::profile_routes::validate_profile_configurations(
            &profile_configurations,
            launch_flavor,
        )
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        Ok(Self {
            state: Arc::new(std::sync::RwLock::new(ConfiguredAuthenticatorState {
                config: Arc::new(config),
                authorities,
                profile_configurations,
            })),
            agent_uid,
            mutable_state_root: Arc::new(mutable_state_root),
            launch_flavor,
        })
    }

    /// Atomically replaces configuration and all authority artifacts.
    ///
    /// A failed reload leaves the previous validated snapshot active.
    #[cfg(unix)]
    pub fn reload(&self, config: AgentConfig) -> Result<(), WorkloadAuthorityError> {
        let authorities = WorkloadAuthoritySnapshot::load(&config, self.agent_uid)?;
        let profile_configurations =
            ProfileConfigurationSnapshot::load(&config, self.agent_uid, &self.mutable_state_root)
                .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        crate::generated::profile_routes::validate_profile_configurations(
            &profile_configurations,
            self.launch_flavor,
        )
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        let replacement = ConfiguredAuthenticatorState {
            config: Arc::new(config),
            authorities,
            profile_configurations,
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        *state = replacement;
        Ok(())
    }
}

#[async_trait]
impl LocalWorkloadAuthenticator for ConfiguredWorkloadAuthenticator {
    async fn authenticate(
        &self,
        peer: PeerCredentials,
    ) -> Result<AuthorizedWorkload, LocalAgentFailure> {
        let (config, authorities, profile_configurations) = {
            let state = self.state.read().map_err(|_| LocalAgentFailure::Internal)?;
            (
                Arc::clone(&state.config),
                state.authorities.clone(),
                state.profile_configurations.clone(),
            )
        };
        let needs_process = config
            .workloads()
            .iter()
            .any(|workload| match workload.selector() {
                WorkloadSelector::Posix {
                    uid,
                    gid,
                    executable_sha256,
                    linux_cgroup_prefix,
                } => {
                    *uid == peer.uid
                        && gid.is_none_or(|value| value == peer.gid)
                        && (executable_sha256.is_some() || linux_cgroup_prefix.is_some())
                }
                WorkloadSelector::Windows { .. } => false,
            });
        let process = if needs_process {
            let pid = peer.pid.ok_or(LocalAgentFailure::Unauthenticated)?;
            Some(
                tokio::task::spawn_blocking(move || observe_linux_process(pid))
                    .await
                    .map_err(|_| LocalAgentFailure::Unauthenticated)??,
            )
        } else {
            None
        };
        let mut matches = config
            .workloads()
            .iter()
            .filter(|workload| match workload.selector() {
                WorkloadSelector::Posix {
                    uid,
                    gid,
                    executable_sha256,
                    linux_cgroup_prefix,
                } => {
                    *uid == peer.uid
                        && gid.is_none_or(|value| value == peer.gid)
                        && executable_sha256.as_ref().is_none_or(|value| {
                            process
                                .as_ref()
                                .is_some_and(|item| &item.executable_sha256 == value)
                        })
                        && linux_cgroup_prefix.as_ref().is_none_or(|value| {
                            process.as_ref().is_some_and(|item| {
                                item.cgroups.iter().any(|path| path.starts_with(value))
                            })
                        })
                }
                WorkloadSelector::Windows { .. } => false,
            });
        let workload = matches.next().ok_or(LocalAgentFailure::Unauthenticated)?;
        if matches.next().is_some() {
            return Err(LocalAgentFailure::Unauthenticated);
        }
        let authority = authorities
            .get(workload.authority_source())
            .ok_or(LocalAgentFailure::Unauthenticated)?;
        Ok(AuthorizedWorkload {
            workload_id: Arc::from(workload.id()),
            principal: Arc::from(workload.principal()),
            allowed_profiles: Arc::new(workload.allowed_profiles().iter().cloned().collect()),
            connections: Arc::new(workload.connections().to_vec()),
            authority,
            profile_configurations,
        })
    }
}

#[allow(dead_code)]
pub(crate) struct ProcessObservation {
    pub(crate) executable_sha256: String,
    pub(crate) cgroups: Vec<String>,
    pub(crate) effective_uid: u32,
    pub(crate) effective_gid: u32,
    pub(crate) start_time_ticks: u64,
}

#[cfg(target_os = "linux")]
pub(crate) fn observe_linux_process(pid: u32) -> Result<ProcessObservation, LocalAgentFailure> {
    let start_time_ticks = linux_process_start_time(pid)?;
    let mut file = std::fs::File::open(format!("/proc/{pid}/exe"))
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|_| LocalAgentFailure::Unauthenticated)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let cgroup = std::fs::read(format!("/proc/{pid}/cgroup"))
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    if cgroup.len() > 65_536 {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let source = std::str::from_utf8(&cgroup).map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let cgroups = source
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path.to_owned()))
        .collect();
    let (effective_uid, effective_gid) = linux_process_effective_ids(pid)?;
    if linux_process_start_time(pid)? != start_time_ticks {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    Ok(ProcessObservation {
        executable_sha256: hex::encode(digest.finalize()),
        cgroups,
        effective_uid,
        effective_gid,
        start_time_ticks,
    })
}

#[cfg(target_os = "linux")]
fn linux_process_start_time(pid: u32) -> Result<u64, LocalAgentFailure> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_ascii_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or(LocalAgentFailure::Unauthenticated)
}

#[cfg(target_os = "linux")]
fn linux_process_effective_ids(pid: u32) -> Result<(u32, u32), LocalAgentFailure> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let value = |label: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .and_then(|item| item.parse::<u32>().ok())
            .ok_or(LocalAgentFailure::Unauthenticated)
    };
    Ok((value("Uid:")?, value("Gid:")?))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn observe_linux_process(_pid: u32) -> Result<ProcessObservation, LocalAgentFailure> {
    Err(LocalAgentFailure::Unauthenticated)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn qualification_bridge_peer(
    stream: &mut tokio::net::UnixStream,
    policy: QualificationClientBridgePolicy,
) -> Result<PeerCredentials, LocalAgentFailure> {
    let proxy = stream
        .peer_cred()
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let proxy_pid = proxy
        .pid()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LocalAgentFailure::Unauthenticated)?;
    if proxy.uid() != policy.reader_uid || proxy.gid() != policy.reader_gid {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let proxy_process = tokio::task::spawn_blocking(move || observe_linux_process(proxy_pid))
        .await
        .map_err(|_| LocalAgentFailure::Unauthenticated)??;
    if proxy_process.effective_uid != policy.reader_uid
        || proxy_process.effective_gid != policy.reader_gid
        || proxy_process.executable_sha256 != policy.reader_artifact_sha256
    {
        return Err(LocalAgentFailure::Unauthenticated);
    }

    let binding = timeout(Duration::from_secs(30), async {
        let length = stream.read_u32().await?;
        let length = usize::try_from(length)
            .ok()
            .filter(|value| (1..=4_096).contains(value))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid bridge binding")
            })?;
        let mut bytes = vec![0_u8; length];
        stream.read_exact(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    })
    .await
    .map_err(|_| LocalAgentFailure::Unauthenticated)?
    .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let binding = QualificationClientBridgeBindingV1::from_json(&binding)
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    if binding.source_context_sha256 != policy.source_context_sha256 {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let observed_proxy = tokio::task::spawn_blocking(move || observe_linux_process(proxy_pid))
        .await
        .map_err(|_| LocalAgentFailure::Unauthenticated)??;
    if observed_proxy.effective_uid != proxy_process.effective_uid
        || observed_proxy.effective_gid != proxy_process.effective_gid
        || observed_proxy.start_time_ticks != proxy_process.start_time_ticks
        || observed_proxy.executable_sha256 != proxy_process.executable_sha256
    {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let client_pid = binding.client_process_id;
    let client_process = tokio::task::spawn_blocking(move || observe_linux_process(client_pid))
        .await
        .map_err(|_| LocalAgentFailure::Unauthenticated)??;
    if client_process.effective_uid != binding.client_uid
        || client_process.effective_gid != binding.client_gid
        || client_process.start_time_ticks != binding.client_start_time_ticks
        || client_process.executable_sha256 != binding.client_executable_sha256
    {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    Ok(PeerCredentials {
        uid: binding.client_uid,
        gid: binding.client_gid,
        pid: Some(binding.client_process_id),
        qualification_fault: binding.fault,
    })
}

/// One generated static profile route and its negotiated capability.
#[derive(Clone, Debug)]
pub struct RegisteredLocalProfile {
    advertisement: ProfileAdvertisement,
    route: ProfileRoute,
    request_limit: usize,
    preparation_evidence: bool,
}

impl RegisteredLocalProfile {
    /// Constructs a collision-checkable route registration.
    pub(crate) fn new(
        advertisement: ProfileAdvertisement,
        request_limit: usize,
        preparation_evidence: Option<&str>,
    ) -> Result<Self, LocalAgentFailure> {
        if request_limit == 0
            || request_limit > MAX_LOCAL_REQUEST_BYTES
            || preparation_evidence.is_some_and(|value| value != "protected-lease")
        {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        let route = ProfileRoute::new(
            advertisement.profile().id(),
            advertisement.profile().version(),
        )
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        Ok(Self {
            advertisement,
            route,
            request_limit,
            preparation_evidence: preparation_evidence.is_some(),
        })
    }
    /// Returns the immutable profile capability.
    #[must_use]
    pub const fn advertisement(&self) -> &ProfileAdvertisement {
        &self.advertisement
    }
    /// Returns the static collection route.
    #[must_use]
    pub fn collection_route(&self) -> &str {
        self.route.collection()
    }
    fn preparation_evidence_route(&self) -> Option<String> {
        self.preparation_evidence
            .then(|| self.route.preparation_evidence())
    }
}

/// Authenticated call context passed only to Rust-owned profile executors.
#[derive(Clone, Debug)]
pub struct LocalOperationContext {
    /// Deployment workload ID selected from kernel-observed peer facts.
    pub workload_id: Arc<str>,
    /// Observed principal bound to the session and current IPC peer.
    pub principal: Arc<str>,
    /// Exact generated profile key selected by the static route.
    pub profile: SessionProfileKey,
    /// Configured connection visibility for this workload.
    pub connections: Arc<Vec<ConnectionSelection>>,
    /// Sealed deployment authority retained for Rust-owned proof verification.
    pub authority: Arc<WorkloadAuthority>,
    /// Deployment-owned profile configuration selected by exact profile ref.
    pub profile_configuration: Option<Arc<auths_profile_runtime::ProfileConfigurationBinding>>,
    /// Owner-controlled root for profile-owned durable state.
    pub profile_state_root: Arc<PathBuf>,
    /// Protected qualification-only fault selected by ClientProxy from the
    /// immutable phase. It is structurally absent from production builds.
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub qualification_fault: Option<QualificationAdmissionFaultV1>,
}

/// Test-only protocol seam. Production state accepts only the statically
/// composed [`JournaledLocalExecutor`].
#[cfg(test)]
#[async_trait]
trait TestLocalProfileExecutor: Send + Sync {
    /// Acquires one profile-declared preparation-evidence lease.
    async fn preparation_evidence(
        &self,
        _context: LocalOperationContext,
        _request: PreparationEvidenceRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        Err(LocalAgentFailure::NotFound)
    }
    /// Performs effect-free preparation and returns one canonical outcome.
    async fn prepare(
        &self,
        context: LocalOperationContext,
        request: PrepareOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure>;
    /// Advances exactly one already-prepared operation.
    async fn execute(
        &self,
        context: LocalOperationContext,
        request: ExecuteOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure>;
    /// Reconciles exactly one stored operation through its concrete profile.
    async fn recover(
        &self,
        context: LocalOperationContext,
        operation: Option<OperationId>,
        request: RecoverOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure>;
    /// Reads one operation without advancing it.
    async fn status(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure>;
    /// Reads ordered portable receipts for one operation.
    async fn receipts(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure>;
    /// Reads the complete bounded pending set for the principal.
    async fn pending(&self, principal: Arc<str>) -> Result<Vec<u8>, LocalAgentFailure>;
}

enum LocalExecutor {
    Journaled(Arc<JournaledLocalExecutor>),
    #[cfg(test)]
    Test(Arc<dyn TestLocalProfileExecutor>),
}

impl LocalExecutor {
    async fn preparation_evidence(
        &self,
        context: LocalOperationContext,
        request: PreparationEvidenceRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.preparation_evidence(context, request).await,
            #[cfg(test)]
            Self::Test(executor) => executor.preparation_evidence(context, request).await,
        }
    }

    async fn prepare(
        &self,
        context: LocalOperationContext,
        request: PrepareOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.prepare(context, request).await,
            #[cfg(test)]
            Self::Test(executor) => executor.prepare(context, request).await,
        }
    }

    async fn execute(
        &self,
        context: LocalOperationContext,
        request: ExecuteOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.execute(context, request).await,
            #[cfg(test)]
            Self::Test(executor) => executor.execute(context, request).await,
        }
    }

    async fn recover(
        &self,
        context: LocalOperationContext,
        operation: Option<OperationId>,
        request: RecoverOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.recover(context, operation, request).await,
            #[cfg(test)]
            Self::Test(executor) => executor.recover(context, operation, request).await,
        }
    }

    async fn status(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.status(context, operation).await,
            #[cfg(test)]
            Self::Test(executor) => executor.status(context, operation).await,
        }
    }

    async fn receipts(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.receipts(context, operation).await,
            #[cfg(test)]
            Self::Test(executor) => executor.receipts(context, operation).await,
        }
    }

    async fn pending(&self, principal: Arc<str>) -> Result<Vec<u8>, LocalAgentFailure> {
        match self {
            Self::Journaled(executor) => executor.pending(principal).await,
            #[cfg(test)]
            Self::Test(executor) => executor.pending(principal).await,
        }
    }
}

#[derive(Clone)]
struct SessionRecord {
    peer: PeerCredentials,
    workload: AuthorizedWorkload,
    mode: SessionMode,
    created: Instant,
    last_used: Instant,
}

#[derive(Clone)]
struct LocalAgentInner {
    authenticator: Arc<dyn LocalWorkloadAuthenticator>,
    executor: Arc<LocalExecutor>,
    profiles: Arc<Vec<RegisteredLocalProfile>>,
    common_registry_digest: [u8; 32],
    sessions: Arc<RwLock<HashMap<String, SessionRecord>>>,
    profile_state_root: Arc<PathBuf>,
}

/// Complete state for the authenticated local-agent listener.
#[derive(Clone)]
pub struct LocalAgentState {
    inner: Arc<LocalAgentInner>,
}

impl LocalAgentState {
    /// Constructs state and rejects duplicate profile keys or route collisions.
    pub(crate) fn new(
        authenticator: Arc<dyn LocalWorkloadAuthenticator>,
        executor: Arc<JournaledLocalExecutor>,
        profiles: Vec<RegisteredLocalProfile>,
        profile_state_root: Arc<PathBuf>,
    ) -> Result<Self, LocalAgentFailure> {
        Self::new_with_executor(
            authenticator,
            LocalExecutor::Journaled(executor),
            profiles,
            profile_state_root,
        )
    }

    #[cfg(test)]
    fn new_test(
        authenticator: Arc<dyn LocalWorkloadAuthenticator>,
        executor: Arc<dyn TestLocalProfileExecutor>,
        profiles: Vec<RegisteredLocalProfile>,
    ) -> Result<Self, LocalAgentFailure> {
        Self::new_with_executor(
            authenticator,
            LocalExecutor::Test(executor),
            profiles,
            Arc::new(std::env::temp_dir().join("auths-node-tests-profile-state")),
        )
    }

    fn new_with_executor(
        authenticator: Arc<dyn LocalWorkloadAuthenticator>,
        executor: LocalExecutor,
        profiles: Vec<RegisteredLocalProfile>,
        profile_state_root: Arc<PathBuf>,
    ) -> Result<Self, LocalAgentFailure> {
        if profiles.is_empty() || profiles.len() > 256 {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        let mut keys = BTreeSet::new();
        let mut routes = BTreeMap::new();
        let mut previous: Option<&SessionProfileKey> = None;
        for profile in &profiles {
            if previous.is_some_and(|value| value >= profile.advertisement.profile())
                || !keys.insert(profile.advertisement.profile().clone())
                || routes
                    .insert(profile.collection_route().to_owned(), profile.clone())
                    .is_some()
            {
                return Err(LocalAgentFailure::InvalidConfiguration);
            }
            previous = Some(profile.advertisement.profile());
        }
        Ok(Self {
            inner: Arc::new(LocalAgentInner {
                authenticator,
                executor: Arc::new(executor),
                profiles: Arc::new(profiles),
                common_registry_digest: common_registry_digest()?,
                sessions: Arc::new(RwLock::new(HashMap::new())),
                profile_state_root,
            }),
        })
    }
}

/// Closed local-agent boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAgentFailure {
    /// Peer identity did not map to exactly one configured workload.
    Unauthenticated,
    /// Server or generated registration is invalid.
    InvalidConfiguration,
    /// Request framing, route, or canonical body is malformed.
    Malformed,
    /// Request exceeds a common or profile bound.
    Limit,
    /// Profile or operation is not visible to this principal.
    NotFound,
    /// Runtime failed before a valid Auths outcome could be formed.
    Internal,
}

/// Builds the exact static local-agent route family.
pub fn local_agent_app(state: LocalAgentState) -> Router {
    let mut router = Router::new()
        .route("/v1/session", post(create_session))
        .route("/v1/session/{session}", delete(delete_session))
        .route("/v1/operations/pending", get(pending))
        .route("/v1/operations/recover", post(recover_common))
        .route("/v1/operations/{operation}/receipts", get(receipts_common));
    for profile in state.inner.profiles.iter().cloned() {
        let collection = profile.collection_route().to_owned();
        let mut profile_routes = Router::new()
            .route(&collection, post(prepare))
            .route(
                &format!("{collection}/{{operation}}/execute"),
                post(execute),
            )
            .route(
                &format!("{collection}/{{operation}}/recover"),
                post(recover_profile),
            )
            .route(&format!("{collection}/{{operation}}"), get(status_profile))
            .route(
                &format!("{collection}/{{operation}}/receipts"),
                get(receipts_profile),
            );
        if let Some(route) = profile.preparation_evidence_route() {
            profile_routes = profile_routes.route(&route, post(preparation_evidence));
        }
        let profile_routes = profile_routes.layer(Extension(profile));
        router = router.merge(profile_routes);
    }
    router
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_LOCAL_REQUEST_BYTES))
        .with_state(state)
}

/// Serves the router on a POSIX local socket with kernel peer credentials.
#[cfg(unix)]
pub async fn serve_local_agent(
    listener: UnixListener,
    state: LocalAgentState,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        local_agent_app(state).into_make_service_with_connect_info::<PeerCredentials>(),
    )
    .await
}

/// Serves the qualification router only after the protected ClientProxy has
/// authenticated and rebound the original SDK peer for each connection.
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub async fn serve_qualification_client_bridge(
    listener: UnixListener,
    state: LocalAgentState,
    policy: QualificationClientBridgePolicy,
) -> std::io::Result<()> {
    axum::serve(
        QualificationClientBridgeListener::new(listener, policy),
        local_agent_app(state).into_make_service_with_connect_info::<PeerCredentials>(),
    )
    .await
}

async fn create_session(
    State(state): State<LocalAgentState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if validate_request(&uri, &headers, true).is_err() {
        return failure_response(LocalAgentFailure::Malformed);
    }
    let request = match decode_session_request(&body) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    let workload = match state.inner.authenticator.authenticate(peer).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let mode = if request.requested_mode() == SessionMode::Full
        && request.common_registry_digest() == &state.inner.common_registry_digest
    {
        SessionMode::Full
    } else {
        SessionMode::RecoveryOnly
    };
    let profiles = state
        .inner
        .profiles
        .iter()
        .filter(|item| workload.permits(item.advertisement.profile()))
        .map(|item| item.advertisement.clone())
        .collect::<Vec<_>>();
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return failure_response(LocalAgentFailure::Internal);
    }
    let session_id = format!("ses_{}", Base64UrlUnpadded::encode_string(&bytes));
    let now = Instant::now();
    {
        let mut sessions = state.inner.sessions.write().await;
        sessions.retain(|_, record| !expired(record, now));
        let count = sessions
            .values()
            .filter(|record| record.workload.principal() == workload.principal())
            .count();
        if sessions.len() >= MAX_SESSIONS || count >= MAX_SESSIONS_PER_PRINCIPAL {
            return failure_response(LocalAgentFailure::Limit);
        }
        sessions.insert(
            session_id.clone(),
            SessionRecord {
                peer,
                workload: workload.clone(),
                mode,
                created: now,
                last_used: now,
            },
        );
    }
    let response = match SessionResponse::new(
        request.request_id(),
        session_id,
        workload.principal(),
        state.inner.common_registry_digest,
        profiles,
        32,
        mode,
    )
    .and_then(|value| encode_session_response(&value))
    {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Internal),
    };
    binary_response(StatusCode::OK, response)
}

async fn delete_session(
    State(state): State<LocalAgentState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(session): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if validate_request(&uri, &headers, false).is_err() {
        return failure_response(LocalAgentFailure::Malformed);
    }
    let Some(header_session) = session_header(&headers) else {
        return failure_response(LocalAgentFailure::Unauthenticated);
    };
    if header_session != session {
        return failure_response(LocalAgentFailure::Unauthenticated);
    }
    let removed = {
        let mut sessions = state.inner.sessions.write().await;
        sessions
            .get(&session)
            .is_some_and(|record| record.peer == peer)
            .then(|| sessions.remove(&session))
            .flatten()
    };
    if removed.is_none() {
        return failure_response(LocalAgentFailure::Unauthenticated);
    }
    binary_response(StatusCode::OK, canonical_empty_map())
}

async fn prepare(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, true, Some(&profile), true).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let request = match decode_prepare_operation_request(&body, profile.request_limit) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    if request.runtime_contract_digest() != profile.advertisement.runtime_contract_digest() {
        return failure_response(LocalAgentFailure::NotFound);
    }
    runtime_response(
        state
            .inner
            .executor
            .prepare(context(&access, &profile, peer), request)
            .await,
    )
}

async fn preparation_evidence(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !profile.preparation_evidence {
        return failure_response(LocalAgentFailure::NotFound);
    }
    let access = match authorize(&state, peer, &uri, &headers, true, Some(&profile), true).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let request = match decode_preparation_evidence_request(&body, profile.request_limit) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    if request.preparation().runtime_contract_digest()
        != profile.advertisement.runtime_contract_digest()
    {
        return failure_response(LocalAgentFailure::NotFound);
    }
    runtime_response(
        state
            .inner
            .executor
            .preparation_evidence(context(&access, &profile, peer), request)
            .await,
    )
}

async fn execute(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(operation): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, true, Some(&profile), true).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let request = match decode_execute_operation_request(&body) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    if request.operation_id().as_str() != operation {
        return failure_response(LocalAgentFailure::Malformed);
    }
    runtime_response(
        state
            .inner
            .executor
            .execute(context(&access, &profile, peer), request)
            .await,
    )
}

async fn recover_profile(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(operation): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, true, Some(&profile), false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let operation = match OperationId::parse(operation) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    let request = match decode_recover_operation_request(&body) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    runtime_response(
        state
            .inner
            .executor
            .recover(context(&access, &profile, peer), Some(operation), request)
            .await,
    )
}

async fn recover_common(
    State(state): State<LocalAgentState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, true, None, false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let request = match decode_recover_operation_request(&body) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    let context = LocalOperationContext {
        workload_id: access.workload.workload_id.clone(),
        principal: access.workload.principal.clone(),
        profile: SessionProfileKey::new("auths.core.recovery", 1).expect("fixed profile"),
        connections: access.workload.connections.clone(),
        authority: access.workload.authority.clone(),
        profile_configuration: None,
        profile_state_root: Arc::clone(&state.inner.profile_state_root),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        qualification_fault: peer.qualification_fault,
    };
    runtime_response(state.inner.executor.recover(context, None, request).await)
}

async fn status_profile(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(operation): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, false, Some(&profile), false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let operation = match OperationId::parse(operation) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    runtime_response(
        state
            .inner
            .executor
            .status(context(&access, &profile, peer), operation)
            .await,
    )
}

async fn receipts_profile(
    State(state): State<LocalAgentState>,
    Extension(profile): Extension<RegisteredLocalProfile>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(operation): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, false, Some(&profile), false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let operation = match OperationId::parse(operation) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    runtime_response(
        state
            .inner
            .executor
            .receipts(context(&access, &profile, peer), operation)
            .await,
    )
}

async fn receipts_common(
    State(state): State<LocalAgentState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path(operation): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, false, None, false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    let operation = match OperationId::parse(operation) {
        Ok(value) => value,
        Err(_) => return failure_response(LocalAgentFailure::Malformed),
    };
    let context = LocalOperationContext {
        workload_id: access.workload.workload_id.clone(),
        principal: access.workload.principal.clone(),
        profile: SessionProfileKey::new("auths.core.receipts", 1).expect("fixed profile"),
        connections: access.workload.connections.clone(),
        authority: access.workload.authority.clone(),
        profile_configuration: None,
        profile_state_root: Arc::clone(&state.inner.profile_state_root),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        qualification_fault: peer.qualification_fault,
    };
    runtime_response(state.inner.executor.receipts(context, operation).await)
}

async fn pending(
    State(state): State<LocalAgentState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let access = match authorize(&state, peer, &uri, &headers, false, None, false).await {
        Ok(value) => value,
        Err(error) => return failure_response(error),
    };
    runtime_response(
        state
            .inner
            .executor
            .pending(access.workload.principal.clone())
            .await,
    )
}

async fn not_found() -> Response {
    failure_response(LocalAgentFailure::NotFound)
}

struct SessionAccess {
    workload: AuthorizedWorkload,
    profile_state_root: Arc<PathBuf>,
}

async fn authorize(
    state: &LocalAgentState,
    peer: PeerCredentials,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    has_body: bool,
    profile: Option<&RegisteredLocalProfile>,
    effectful: bool,
) -> Result<SessionAccess, LocalAgentFailure> {
    validate_request(uri, headers, has_body)?;
    let id = session_header(headers).ok_or(LocalAgentFailure::Unauthenticated)?;
    let now = Instant::now();
    let mut sessions = state.inner.sessions.write().await;
    let record = sessions
        .get_mut(&id)
        .ok_or(LocalAgentFailure::Unauthenticated)?;
    if expired(record, now) || record.peer != peer {
        sessions.remove(&id);
        return Err(LocalAgentFailure::Unauthenticated);
    }
    if effectful && record.mode != SessionMode::Full {
        return Err(LocalAgentFailure::NotFound);
    }
    if effectful && !record.workload.authority.is_valid_at(unix_seconds_now()?) {
        return Err(LocalAgentFailure::NotFound);
    }
    if let Some(profile) = profile
        && !record.workload.permits(profile.advertisement.profile())
    {
        return Err(LocalAgentFailure::NotFound);
    }
    record.last_used = now;
    Ok(SessionAccess {
        workload: record.workload.clone(),
        profile_state_root: Arc::clone(&state.inner.profile_state_root),
    })
}

fn context(
    access: &SessionAccess,
    profile: &RegisteredLocalProfile,
    peer: PeerCredentials,
) -> LocalOperationContext {
    #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
    let _ = peer;
    let profile_ref = format!(
        "{}/{}",
        profile.advertisement.profile().id(),
        profile.advertisement.profile().version()
    );
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    let principal =
        if peer.qualification_fault == Some(QualificationAdmissionFaultV1::PrincipalSubstitution) {
            Arc::from("did:auths:qualification-substitute")
        } else {
            access.workload.principal.clone()
        };
    #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
    let principal = access.workload.principal.clone();
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    let mut profile_configuration = access.workload.profile_configurations.get(&profile_ref);
    #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
    let profile_configuration = access.workload.profile_configurations.get(&profile_ref);
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    if peer.qualification_fault == Some(QualificationAdmissionFaultV1::ConfigurationMismatch) {
        if let Some(binding) = profile_configuration.as_deref() {
            let mut changed_sha256 = binding.sha256();
            changed_sha256[0] ^= 1;
            profile_configuration = Some(Arc::new(
                auths_profile_runtime::ProfileConfigurationBinding::from_loader(
                    binding.profile_ref().to_owned(),
                    binding.format().to_owned(),
                    Arc::from(binding.canonical_bytes()),
                    changed_sha256,
                    binding.path().to_owned(),
                    binding.maximum_bytes(),
                    binding.file_device(),
                    binding.file_inode(),
                    binding.file_length(),
                    binding.file_modified_nanoseconds(),
                ),
            ));
        }
    }
    LocalOperationContext {
        workload_id: access.workload.workload_id.clone(),
        principal,
        profile: profile.advertisement.profile().clone(),
        connections: access.workload.connections.clone(),
        authority: access.workload.authority.clone(),
        profile_configuration,
        profile_state_root: Arc::clone(&access.profile_state_root),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        qualification_fault: peer.qualification_fault,
    }
}

fn unix_seconds_now() -> Result<i64, LocalAgentFailure> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalAgentFailure::Internal)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| LocalAgentFailure::Internal)
}

fn validate_request(
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    has_body: bool,
) -> Result<(), LocalAgentFailure> {
    if uri.query().is_some()
        || uri.path().contains('%')
        || uri.path().contains("//")
        || uri.path().ends_with('/')
        || uri.path().split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(LocalAgentFailure::Malformed);
    }
    if headers.len() > MAX_HEADERS
        || header_bytes(headers) > MAX_HEADER_BYTES
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::PROXY_AUTHORIZATION)
        || headers.contains_key(header::COOKIE)
        || headers.contains_key(header::TRANSFER_ENCODING)
        || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(LOCAL_AGENT_CONTENT_TYPE)
        || (has_body && headers.get(header::CONTENT_LENGTH).is_none())
    {
        return Err(LocalAgentFailure::Malformed);
    }
    Ok(())
}

fn session_header(headers: &HeaderMap) -> Option<String> {
    let values = headers.get_all("Auths-Session");
    if values.iter().count() != 1 {
        return None;
    }
    let value = values.iter().next()?.to_str().ok()?;
    if !value.starts_with("ses_") || value.len() != 26 {
        return None;
    }
    Some(value.to_owned())
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| {
            name.as_str()
                .len()
                .saturating_add(value.as_bytes().len())
                .saturating_add(4)
        })
        .sum()
}

fn expired(record: &SessionRecord, now: Instant) -> bool {
    now.duration_since(record.last_used) > SESSION_IDLE
        || now.duration_since(record.created) > SESSION_LIFETIME
}

fn runtime_response(result: Result<Vec<u8>, LocalAgentFailure>) -> Response {
    match result {
        Ok(body) if !body.is_empty() && body.len() <= MAX_LOCAL_RESPONSE_BYTES => {
            binary_response(StatusCode::OK, body)
        }
        Ok(_) => failure_response(LocalAgentFailure::Internal),
        Err(error) => failure_response(error),
    }
}

fn failure_response(error: LocalAgentFailure) -> Response {
    let status = match error {
        LocalAgentFailure::Malformed => StatusCode::BAD_REQUEST,
        LocalAgentFailure::Limit => StatusCode::PAYLOAD_TOO_LARGE,
        LocalAgentFailure::NotFound | LocalAgentFailure::Unauthenticated => StatusCode::NOT_FOUND,
        LocalAgentFailure::InvalidConfiguration | LocalAgentFailure::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    binary_response(status, canonical_empty_map())
}

fn canonical_empty_map() -> Vec<u8> {
    vec![0xa0]
}

fn binary_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(LOCAL_AGENT_CONTENT_TYPE),
    );
    response
}

fn common_registry_digest() -> Result<[u8; 32], LocalAgentFailure> {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../../errors/v1/registry.json"))
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    Ok(Sha256::digest(canonical).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::profile_routes::built_in_testkit_local_profiles;
    #[cfg(feature = "qualification-failpoints")]
    use crate::generated::profile_routes::{
        built_in_local_profiles, built_in_qualification_local_profiles,
    };
    use axum::{body::Body, http::Request};
    #[cfg(feature = "qualification-failpoints")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn bridge_fixture() -> (
        QualificationClientBridgePolicy,
        QualificationClientBridgeBindingV1,
    ) {
        let pid = std::process::id();
        let process = observe_linux_process(pid).unwrap();
        let source_context = "a".repeat(64);
        (
            QualificationClientBridgePolicy::new(
                process.effective_uid,
                process.effective_gid,
                process.executable_sha256.clone(),
                source_context.clone(),
            )
            .unwrap(),
            QualificationClientBridgeBindingV1 {
                schema: "auths.qualification-client-bridge-binding/1".into(),
                source_context_sha256: source_context,
                client_uid: process.effective_uid,
                client_gid: process.effective_gid,
                client_process_id: pid,
                client_start_time_ticks: process.start_time_ticks,
                client_executable_sha256: process.executable_sha256,
                fault: None,
            },
        )
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    async fn check_bridge_frame(
        frame: Vec<u8>,
        policy: QualificationClientBridgePolicy,
    ) -> Result<PeerCredentials, LocalAgentFailure> {
        use tokio::io::AsyncWriteExt as _;

        let (mut server, mut client) = tokio::net::UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move {
            client.write_all(&frame).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let result = qualification_bridge_peer(&mut server, policy).await;
        writer.await.unwrap();
        result
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn bridge_frame(binding: &QualificationClientBridgeBindingV1) -> Vec<u8> {
        let body = binding.to_json().unwrap();
        let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    #[tokio::test]
    async fn qualification_bridge_rebinds_only_canonical_live_process_identity() {
        let (policy, binding) = bridge_fixture();
        let peer = check_bridge_frame(bridge_frame(&binding), policy.clone())
            .await
            .unwrap();
        assert_eq!(peer.uid, binding.client_uid);
        assert_eq!(peer.gid, binding.client_gid);
        assert_eq!(peer.pid, Some(binding.client_process_id));
        assert_eq!(peer.qualification_fault, None);

        let mut faulted = binding.clone();
        faulted.fault = Some(QualificationAdmissionFaultV1::StaleEvidence);
        let peer = check_bridge_frame(bridge_frame(&faulted), policy.clone())
            .await
            .unwrap();
        assert_eq!(
            peer.qualification_fault,
            Some(QualificationAdmissionFaultV1::StaleEvidence)
        );

        let mut wrong_context = binding.clone();
        wrong_context.source_context_sha256 = "b".repeat(64);
        assert!(
            check_bridge_frame(bridge_frame(&wrong_context), policy.clone())
                .await
                .is_err()
        );
        let mut wrong_start = binding.clone();
        wrong_start.client_start_time_ticks += 1;
        assert!(
            check_bridge_frame(bridge_frame(&wrong_start), policy.clone())
                .await
                .is_err()
        );
        let mut wrong_executable = binding.clone();
        wrong_executable.client_executable_sha256 = "c".repeat(64);
        assert!(
            check_bridge_frame(bridge_frame(&wrong_executable), policy.clone())
                .await
                .is_err()
        );

        let wrong_reader = QualificationClientBridgePolicy::new(
            binding.client_uid,
            binding.client_gid,
            "d".repeat(64),
            binding.source_context_sha256.clone(),
        )
        .unwrap();
        assert!(
            check_bridge_frame(bridge_frame(&binding), wrong_reader)
                .await
                .is_err()
        );
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    #[tokio::test]
    async fn qualification_bridge_rejects_noncanonical_and_broken_frames() {
        let (policy, binding) = bridge_fixture();
        let mut noncanonical_body = binding.to_json().unwrap();
        noncanonical_body.push(b'\n');
        let mut noncanonical = u32::try_from(noncanonical_body.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        noncanonical.extend_from_slice(&noncanonical_body);
        assert!(
            check_bridge_frame(noncanonical, policy.clone())
                .await
                .is_err()
        );
        assert!(
            check_bridge_frame(4_097_u32.to_be_bytes().to_vec(), policy.clone())
                .await
                .is_err()
        );
        let mut truncated = 32_u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(b"short");
        assert!(check_bridge_frame(truncated, policy).await.is_err());
    }

    #[derive(Clone)]
    struct FixedAuthenticator;
    #[async_trait]
    impl LocalWorkloadAuthenticator for FixedAuthenticator {
        async fn authenticate(
            &self,
            _peer: PeerCredentials,
        ) -> Result<AuthorizedWorkload, LocalAgentFailure> {
            Ok(AuthorizedWorkload {
                workload_id: Arc::from("workload-a"),
                principal: Arc::from("did:example:test"),
                allowed_profiles: Arc::new(
                    ["auths.stripe.refund/1".to_owned()].into_iter().collect(),
                ),
                connections: Arc::new(Vec::new()),
                authority: Arc::new(WorkloadAuthority::for_test(
                    "did:example:test",
                    ProfileRef::new(ProfileId::parse("auths.stripe.refund").unwrap(), 1).unwrap(),
                )),
                profile_configurations: ProfileConfigurationSnapshot::default(),
            })
        }
    }

    struct NoopExecutor;
    #[async_trait]
    impl TestLocalProfileExecutor for NoopExecutor {
        async fn prepare(
            &self,
            _: LocalOperationContext,
            _: PrepareOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::Internal)
        }
        async fn execute(
            &self,
            _: LocalOperationContext,
            _: ExecuteOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::Internal)
        }
        async fn recover(
            &self,
            _: LocalOperationContext,
            _: Option<OperationId>,
            _: RecoverOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::Internal)
        }
        async fn status(
            &self,
            _: LocalOperationContext,
            _: OperationId,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::NotFound)
        }
        async fn receipts(
            &self,
            _: LocalOperationContext,
            _: OperationId,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::NotFound)
        }
        async fn pending(&self, _: Arc<str>) -> Result<Vec<u8>, LocalAgentFailure> {
            Ok(vec![0xa2, 0x01, 0x01, 0x02, 0x80])
        }
    }

    #[cfg(feature = "qualification-failpoints")]
    #[derive(Clone)]
    struct OpentofuAuthenticator;

    #[cfg(feature = "qualification-failpoints")]
    #[async_trait]
    impl LocalWorkloadAuthenticator for OpentofuAuthenticator {
        async fn authenticate(
            &self,
            _peer: PeerCredentials,
        ) -> Result<AuthorizedWorkload, LocalAgentFailure> {
            let profile = ProfileRef::new(
                ProfileId::parse("auths.opentofu.plan-preflight").unwrap(),
                1,
            )
            .unwrap();
            Ok(AuthorizedWorkload {
                workload_id: Arc::from("workload-a"),
                principal: Arc::from("did:example:test"),
                allowed_profiles: Arc::new(
                    ["auths.opentofu.plan-preflight/1".to_owned()]
                        .into_iter()
                        .collect(),
                ),
                connections: Arc::new(Vec::new()),
                authority: Arc::new(WorkloadAuthority::for_test("did:example:test", profile)),
                profile_configurations: ProfileConfigurationSnapshot::default(),
            })
        }
    }

    #[cfg(feature = "qualification-failpoints")]
    struct CountingExecutor(AtomicUsize);

    #[cfg(feature = "qualification-failpoints")]
    #[async_trait]
    impl TestLocalProfileExecutor for CountingExecutor {
        async fn prepare(
            &self,
            _: LocalOperationContext,
            _: PrepareOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(LocalAgentFailure::Internal)
        }
        async fn execute(
            &self,
            _: LocalOperationContext,
            _: ExecuteOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::Internal)
        }
        async fn recover(
            &self,
            _: LocalOperationContext,
            _: Option<OperationId>,
            _: RecoverOperationRequest,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::Internal)
        }
        async fn status(
            &self,
            _: LocalOperationContext,
            _: OperationId,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::NotFound)
        }
        async fn receipts(
            &self,
            _: LocalOperationContext,
            _: OperationId,
        ) -> Result<Vec<u8>, LocalAgentFailure> {
            Err(LocalAgentFailure::NotFound)
        }
        async fn pending(&self, _: Arc<str>) -> Result<Vec<u8>, LocalAgentFailure> {
            Ok(vec![0xa2, 0x01, 0x01, 0x02, 0x80])
        }
    }

    #[tokio::test]
    async fn handshake_is_peer_bound_and_advertises_only_allowed_profiles() {
        let state = LocalAgentState::new_test(
            Arc::new(FixedAuthenticator),
            Arc::new(NoopExecutor),
            built_in_testkit_local_profiles().unwrap(),
        )
        .unwrap();
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(7),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            qualification_fault: None,
        };
        let request = auths_production_client::SessionRequest::new(
            auths_production_client::ClientRequestId::from_bytes([9; 16]),
            "typescript",
            "1.0.0",
            state.inner.common_registry_digest,
            SessionMode::Full,
        )
        .unwrap();
        let body = auths_production_client::encode_session_request(&request).unwrap();
        assert!(decode_session_request(&body).is_ok());
        let http_request = Request::post("/v1/session")
            .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            validate_request(http_request.uri(), http_request.headers(), true),
            Ok(())
        );
        let response = local_agent_app(state)
            .layer(Extension(ConnectInfo(peer)))
            .oneshot(http_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), MAX_LOCAL_RESPONSE_BYTES)
            .await
            .unwrap();
        let decoded = auths_production_client::decode_session_response(&bytes).unwrap();
        assert_eq!(decoded.principal(), "did:example:test");
        assert_eq!(decoded.profiles().len(), 1);
        assert_eq!(decoded.profiles()[0].profile().id(), "auths.stripe.refund");
    }

    #[tokio::test]
    async fn forbidden_bearer_header_is_rejected_before_authentication() {
        let state = LocalAgentState::new_test(
            Arc::new(FixedAuthenticator),
            Arc::new(NoopExecutor),
            built_in_testkit_local_profiles().unwrap(),
        )
        .unwrap();
        let response = local_agent_app(state)
            .layer(Extension(ConnectInfo(PeerCredentials {
                uid: 1,
                gid: 1,
                pid: None,
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                qualification_fault: None,
            })))
            .oneshot(
                Request::post("/v1/session")
                    .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
                    .header(header::CONTENT_LENGTH, 1)
                    .header(header::AUTHORIZATION, "Bearer forbidden")
                    .body(Body::from(vec![0xa0]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "qualification-failpoints")]
    #[tokio::test]
    async fn qualification_roster_dispatches_a_real_profile_while_production_omits_its_route() {
        let profiles = built_in_qualification_local_profiles().unwrap();
        let selected = profiles
            .iter()
            .find(|profile| {
                profile.advertisement().profile().id() == "auths.opentofu.plan-preflight"
            })
            .unwrap();
        let runtime_digest = *selected.advertisement().runtime_contract_digest();
        let executor = Arc::new(CountingExecutor(AtomicUsize::new(0)));
        let state =
            LocalAgentState::new_test(Arc::new(OpentofuAuthenticator), executor.clone(), profiles)
                .unwrap();
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(7),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            qualification_fault: None,
        };
        let session_request = auths_production_client::SessionRequest::new(
            auths_production_client::ClientRequestId::from_bytes([7; 16]),
            "typescript",
            "1.0.0",
            state.inner.common_registry_digest,
            SessionMode::Full,
        )
        .unwrap();
        let session_body =
            auths_production_client::encode_session_request(&session_request).unwrap();
        let session_response = local_agent_app(state.clone())
            .layer(Extension(ConnectInfo(peer)))
            .oneshot(
                Request::post("/v1/session")
                    .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
                    .header(header::CONTENT_LENGTH, session_body.len())
                    .body(Body::from(session_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_bytes =
            axum::body::to_bytes(session_response.into_body(), MAX_LOCAL_RESPONSE_BYTES)
                .await
                .unwrap();
        let session = auths_production_client::decode_session_response(&session_bytes).unwrap();
        assert_eq!(session.profiles().len(), 1);

        let prepare = PrepareOperationRequest::new(
            auths_production_client::ClientRequestId::from_bytes([8; 16]),
            Some("qualification-route-test".to_owned()),
            runtime_digest,
            b"canonical-profile-input".to_vec(),
            None,
            4_194_304,
        )
        .unwrap();
        let prepare_body =
            auths_production_client::encode_prepare_operation_request(&prepare).unwrap();
        let route = "/v1/profiles/opentofu/plan-preflight/1/operations";
        let response = local_agent_app(state)
            .layer(Extension(ConnectInfo(peer)))
            .oneshot(
                Request::post(route)
                    .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
                    .header(header::CONTENT_LENGTH, prepare_body.len())
                    .header("Auths-Session", session.session_id())
                    .body(Body::from(prepare_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(executor.0.load(Ordering::SeqCst), 1);

        let production_profiles = built_in_local_profiles().unwrap();
        assert!(production_profiles.is_empty());
        let production_state = LocalAgentState {
            inner: Arc::new(LocalAgentInner {
                authenticator: Arc::new(OpentofuAuthenticator),
                executor: Arc::new(LocalExecutor::Test(executor.clone())),
                profiles: Arc::new(production_profiles),
                common_registry_digest: common_registry_digest().unwrap(),
                sessions: Arc::new(RwLock::new(HashMap::new())),
                profile_state_root: Arc::new(
                    std::env::temp_dir().join("auths-node-production-route-test"),
                ),
            }),
        };
        let response = local_agent_app(production_state)
            .layer(Extension(ConnectInfo(peer)))
            .oneshot(
                Request::post(route)
                    .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
                    .header(header::CONTENT_LENGTH, prepare_body.len())
                    .body(Body::from(prepare_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.0.load(Ordering::SeqCst), 1);
    }
}
