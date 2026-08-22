//! Deployment assembly for the workload and privileged local-agent sockets.

#![forbid(unsafe_code)]
// Deployment assembly intentionally accepts ownership of its immutable
// resource bundle and keeps all-or-nothing socket binding in one auditable
// unit.
#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::similar_names
)]

#[cfg(feature = "qualification-failpoints")]
use crate::generated::profile_routes::built_in_qualification_local_profiles;
#[cfg(feature = "testkit-agent")]
use crate::generated::profile_routes::built_in_testkit_local_profiles;
#[cfg(any(test, feature = "testkit-agent"))]
use crate::local_agent::LocalAgentFailure;
#[cfg(feature = "testkit-agent")]
use crate::local_agent::TestkitWorkloadAuthenticator;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use crate::local_agent::{
    QualificationClientBridgePolicy, QualificationCredentialBrokerPolicy,
    QualificationProviderProxyPolicy, serve_qualification_client_bridge,
};
use crate::profile_launch::LaunchFlavor;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use crate::qualification_crash::QualificationJournalBoundaryGate;
use crate::{
    connection_admin::{AdminPeerPolicy, ConnectionAdminState, serve_connection_admin},
    generated::profile_routes::{built_in_local_profiles, built_in_operation_limits},
    journal_executor::JournaledLocalExecutor,
    local_agent::{ConfiguredWorkloadAuthenticator, LocalAgentState, serve_local_agent},
    receipt_attestor::ReceiptAttestor,
    recovery_handle::RecoveryHandleSigner,
};
use auths_config::{AgentConfig, ReceiptSigningConfig, ReceiptSigningRole};
#[cfg(feature = "testkit-agent")]
use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
    ConnectionRecord, ConnectionState, ProviderKind, SecretBytes, SemanticId,
};
use auths_connections::{PersistentCredentialStore, RegistryLimits};
use auths_profile_kit::{
    QualificationEvidenceLedgerTrustRegistry, QualificationEvidenceSourceTrustRegistry,
    QualificationObserverTrustRegistry, QualificationTrustIdentity, QualificationTrustRegistry,
    validate_qualification_key_separation,
};
use auths_receipts::{ReceiptTrustAnchor, ReceiptTrustAnchorRole};
use auths_stores::{PersistentConnectionStore, PersistentOperationJournal};
use base64ct::{Base64UrlUnpadded, Encoding as _};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use std::os::unix::fs::MetadataExt as _;
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tokio::net::UnixListener;
use zeroize::Zeroizing;

const QUALIFICATION_ATTESTATION_TRUST: &[u8] =
    include_bytes!("../../../../release/qualification/v1/trust-keys.json");
const QUALIFICATION_OBSERVER_TRUST: &[u8] =
    include_bytes!("../../../../release/qualification/v1/observer-trust-keys.json");
const QUALIFICATION_SOURCE_TRUST: &[u8] =
    include_bytes!("../../../../release/qualification/v1/evidence-source-trust-keys.json");
const QUALIFICATION_LEDGER_TRUST: &[u8] =
    include_bytes!("../../../../release/qualification/v1/evidence-ledger-trust-keys.json");

/// Closed paths, identities, and persistence locations for one local agent.
#[derive(Clone, Debug)]
pub struct LocalAgentDeploymentConfig {
    agent_socket: PathBuf,
    admin_socket: PathBuf,
    connection_store: PathBuf,
    credential_store: PathBuf,
    operation_store: PathBuf,
    recovery_signing_key: PathBuf,
    recovery_key_id: String,
    admin_audit: PathBuf,
    agent_uid: u32,
    admin_uids: BTreeSet<u32>,
    admin_gids: BTreeSet<u32>,
    registry_limits: RegistryLimits,
}

impl LocalAgentDeploymentConfig {
    /// Constructs an exact deployment without environment or TCP fallback.
    ///
    /// Empty admin UID/GID sets mean root-only administration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_socket: impl Into<PathBuf>,
        admin_socket: impl Into<PathBuf>,
        connection_store: impl Into<PathBuf>,
        credential_store: impl Into<PathBuf>,
        operation_store: impl Into<PathBuf>,
        recovery_signing_key: impl Into<PathBuf>,
        recovery_key_id: impl Into<String>,
        admin_audit: impl Into<PathBuf>,
        agent_uid: u32,
        admin_uids: impl IntoIterator<Item = u32>,
        admin_gids: impl IntoIterator<Item = u32>,
        registry_limits: RegistryLimits,
    ) -> Result<Self, LocalAgentDeploymentError> {
        let value = Self {
            agent_socket: agent_socket.into(),
            admin_socket: admin_socket.into(),
            connection_store: connection_store.into(),
            credential_store: credential_store.into(),
            operation_store: operation_store.into(),
            recovery_signing_key: recovery_signing_key.into(),
            recovery_key_id: recovery_key_id.into(),
            admin_audit: admin_audit.into(),
            agent_uid,
            admin_uids: admin_uids.into_iter().collect(),
            admin_gids: admin_gids.into_iter().collect(),
            registry_limits,
        };
        let paths = [
            &value.agent_socket,
            &value.admin_socket,
            &value.connection_store,
            &value.credential_store,
            &value.operation_store,
            &value.recovery_signing_key,
            &value.admin_audit,
        ];
        let distinct = paths
            .iter()
            .map(|path| path.as_path())
            .collect::<BTreeSet<_>>();
        if paths.iter().any(|path| !normalized_absolute(path))
            || distinct.len() != paths.len()
            || !registered_token(&value.recovery_key_id)
        {
            return Err(LocalAgentDeploymentError::InvalidConfiguration);
        }
        Ok(value)
    }

    /// Returns the application-facing local socket path.
    #[must_use]
    pub fn agent_socket(&self) -> &Path {
        &self.agent_socket
    }

    /// Returns the privileged administration socket path.
    #[must_use]
    pub fn admin_socket(&self) -> &Path {
        &self.admin_socket
    }
}

/// Shared persistent connection resources used by administration and profile
/// executors. Credential bytes remain accessible only through store leases.
#[derive(Clone)]
pub struct LocalAgentResources {
    /// Sanitized provider connection registry.
    pub connections: Arc<PersistentConnectionStore>,
    /// Privileged credential-generation store.
    pub credentials: Arc<PersistentCredentialStore>,
    /// Common durable operation journal with exact manifest-derived limits.
    pub operations: Arc<PersistentOperationJournal>,
    /// Deployment-owned signer for principal-bound recovery capabilities.
    pub recovery: Arc<RecoveryHandleSigner>,
    /// Deployment-owned, role-separated portable receipt attestor.
    pub(crate) receipts: Arc<ReceiptAttestor>,
    /// Root beneath which concrete profiles own their separate durable stores.
    pub(crate) profile_state_root: Arc<PathBuf>,
    /// Qualification-only journal boundary gate. This field and its code are
    /// absent from the production binary.
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub(crate) qualification_journal_gate: Option<Arc<QualificationJournalBoundaryGate>>,
}

/// Fully validated local control plane whose two sockets are already bound.
///
/// Constructing this value is the readiness boundary. Holding it keeps both
/// socket paths reserved and scheduled for inode-checked cleanup even if the
/// caller decides not to enter the serve loop.
#[cfg(unix)]
pub struct BoundLocalControlPlane {
    agent_listener: UnixListener,
    admin_listener: UnixListener,
    local_state: LocalAgentState,
    admin_state: ConnectionAdminState,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    qualification_client_bridge: Option<QualificationClientBridgePolicy>,
    _cleanup: (SocketCleanup, SocketCleanup),
}

/// Bound application socket for the explicitly disposable testkit agent.
#[cfg(all(unix, feature = "testkit-agent"))]
pub struct BoundTestkitAgent {
    listener: UnixListener,
    local_state: LocalAgentState,
    _cleanup: SocketCleanup,
}

#[cfg(all(unix, feature = "testkit-agent"))]
impl BoundTestkitAgent {
    /// Serves the already-bound testkit socket until shutdown.
    pub async fn serve(self) -> Result<(), LocalAgentDeploymentError> {
        serve_local_agent(self.listener, self.local_state)
            .await
            .map_err(|_| LocalAgentDeploymentError::Serve)
    }
}

#[cfg(unix)]
impl BoundLocalControlPlane {
    /// Serves both already-bound socket trees until one exits.
    pub async fn serve(self) -> Result<(), LocalAgentDeploymentError> {
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        let agent = async {
            if let Some(policy) = self.qualification_client_bridge {
                serve_qualification_client_bridge(self.agent_listener, self.local_state, policy)
                    .await
            } else {
                serve_local_agent(self.agent_listener, self.local_state).await
            }
        };
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        let agent = serve_local_agent(self.agent_listener, self.local_state);
        tokio::try_join!(
            agent,
            serve_connection_admin(self.admin_listener, self.admin_state),
        )
        .map_err(|_| LocalAgentDeploymentError::Serve)?;
        Ok(())
    }
}

impl LocalAgentResources {
    /// Opens both stores and rejects malformed or unsafe existing state.
    pub fn open(
        config: &LocalAgentDeploymentConfig,
        receipt_config: &ReceiptSigningConfig,
    ) -> Result<Self, LocalAgentDeploymentError> {
        Self::open_with_credential_store(config, receipt_config, &config.credential_store)
    }

    fn open_with_credential_store(
        config: &LocalAgentDeploymentConfig,
        receipt_config: &ReceiptSigningConfig,
        credential_store: &Path,
    ) -> Result<Self, LocalAgentDeploymentError> {
        let signing_seeds = AgentSigningSeeds {
            decision: load_secret_seed(
                Path::new(receipt_config.decision().seed_file()),
                config.agent_uid,
            )?,
            execution: load_secret_seed(
                Path::new(receipt_config.execution().seed_file()),
                config.agent_uid,
            )?,
            recovery: load_secret_seed(&config.recovery_signing_key, config.agent_uid)?,
        };
        Self::open_with_credential_store_and_signing_seeds(
            config,
            receipt_config,
            credential_store,
            signing_seeds,
            None,
        )
    }

    fn open_with_credential_store_and_signing_seeds(
        config: &LocalAgentDeploymentConfig,
        receipt_config: &ReceiptSigningConfig,
        credential_store: &Path,
        signing_seeds: AgentSigningSeeds,
        expected_recovery_public_key_base64url: Option<&str>,
    ) -> Result<Self, LocalAgentDeploymentError> {
        let mutable_state_root = config
            .operation_store
            .parent()
            .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?;
        let profile_state_root = mutable_state_root.join("profiles");
        prepare_profile_state_root(&profile_state_root, config.agent_uid)?;
        let connections =
            PersistentConnectionStore::open(&config.connection_store, config.registry_limits)
                .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let credentials = PersistentCredentialStore::open(credential_store)
            .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let operations = PersistentOperationJournal::open(
            &config.operation_store,
            built_in_operation_limits()
                .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        )
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        if receipt_config.decision().key_id() == config.recovery_key_id
            || receipt_config.execution().key_id() == config.recovery_key_id
        {
            return Err(LocalAgentDeploymentError::InvalidConfiguration);
        }
        let receipts = build_receipt_attestor(receipt_config, &signing_seeds)?;
        let mut recovery_seed = *signing_seeds.recovery.as_bytes();
        let recovery =
            RecoveryHandleSigner::from_seed(config.recovery_key_id.clone(), recovery_seed, [])
                .map_err(|_| LocalAgentDeploymentError::PersistentState);
        recovery_seed.fill(0);
        let recovery = recovery?;
        if expected_recovery_public_key_base64url.is_some_and(|expected| {
            Base64UrlUnpadded::encode_string(&recovery.public_key()) != expected
        }) {
            return Err(LocalAgentDeploymentError::InvalidConfiguration);
        }
        validate_embedded_qualification_key_separation(&receipts, &recovery)?;
        Ok(Self {
            connections: Arc::new(connections),
            credentials: Arc::new(credentials),
            operations: Arc::new(operations),
            recovery: Arc::new(recovery),
            receipts: Arc::new(receipts),
            profile_state_root: Arc::new(profile_state_root),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            qualification_journal_gate: None,
        })
    }

    /// Opens qualification resources with the one bounded journal gate used
    /// by both ordinary and crash qualification runs.
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub fn open_qualification(
        config: &LocalAgentDeploymentConfig,
        receipt_config: &ReceiptSigningConfig,
        signing_directory: &std::fs::File,
        expected_recovery_public_key_base64url: &str,
        gate_output: std::fs::File,
        gate_release: std::fs::File,
        agent_generation: u32,
        failpoint: Option<auths_profile_kit::QualificationFailpoint>,
        control_operation_id: Option<String>,
        controller_nonce_sha256: Option<String>,
        controller_pid: u32,
    ) -> Result<Self, LocalAgentDeploymentError> {
        let credential_store = config
            .operation_store
            .parent()
            .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?
            .join("qualification-agent-credentials.cbor");
        if credential_store == config.credential_store {
            return Err(LocalAgentDeploymentError::InvalidConfiguration);
        }
        let agent_gid = rustix::process::getegid().as_raw();
        let directory_metadata = signing_directory
            .metadata()
            .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.uid() != config.agent_uid
            || directory_metadata.gid() != agent_gid
            || directory_metadata.mode() & 0o777 != 0o700
        {
            return Err(LocalAgentDeploymentError::PersistentState);
        }
        let signing_seeds = AgentSigningSeeds {
            decision: load_secret_seed_at(
                signing_directory,
                "qualification-decision.key",
                config.agent_uid,
                agent_gid,
            )?,
            execution: load_secret_seed_at(
                signing_directory,
                "qualification-execution.key",
                config.agent_uid,
                agent_gid,
            )?,
            recovery: load_secret_seed_at(
                signing_directory,
                "qualification-recovery.key",
                config.agent_uid,
                agent_gid,
            )?,
        };
        let mut resources = Self::open_with_credential_store_and_signing_seeds(
            config,
            receipt_config,
            &credential_store,
            signing_seeds,
            Some(expected_recovery_public_key_base64url),
        )?;
        resources.qualification_journal_gate = Some(Arc::new(
            QualificationJournalBoundaryGate::new(
                gate_output,
                gate_release,
                agent_generation,
                failpoint,
                control_operation_id,
                controller_nonce_sha256,
                controller_pid,
            )
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        ));
        Ok(resources)
    }

    /// Opens the explicitly disposable synthetic testkit with derived receipt
    /// keys. Production assembly cannot call this path without the feature.
    #[cfg(any(test, feature = "testkit-agent"))]
    pub fn open_testkit(
        config: &LocalAgentDeploymentConfig,
    ) -> Result<Self, LocalAgentDeploymentError> {
        let mutable_state_root = config
            .operation_store
            .parent()
            .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?;
        let profile_state_root = mutable_state_root.join("profiles");
        prepare_profile_state_root(&profile_state_root, config.agent_uid)?;
        let connections =
            PersistentConnectionStore::open(&config.connection_store, config.registry_limits)
                .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let credentials = PersistentCredentialStore::open(&config.credential_store)
            .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let operations = PersistentOperationJournal::open(
            &config.operation_store,
            built_in_operation_limits()
                .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        )
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let recovery_seed = load_secret_seed(&config.recovery_signing_key, config.agent_uid)?;
        let receipts =
            ReceiptAttestor::from_root_seed(&config.recovery_key_id, recovery_seed.as_bytes())
                .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        let mut recovery_seed_copy = *recovery_seed.as_bytes();
        let recovery =
            RecoveryHandleSigner::from_seed(config.recovery_key_id.clone(), recovery_seed_copy, [])
                .map_err(|_| LocalAgentDeploymentError::PersistentState);
        recovery_seed_copy.fill(0);
        Ok(Self {
            connections: Arc::new(connections),
            credentials: Arc::new(credentials),
            operations: Arc::new(operations),
            recovery: Arc::new(recovery?),
            receipts: Arc::new(receipts),
            profile_state_root: Arc::new(profile_state_root),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            qualification_journal_gate: None,
        })
    }

    /// Returns the disposable testkit agent's public receipt trust anchors.
    ///
    /// Production deployments distribute trust configuration through their
    /// deployment boundary. This helper exists only for the separately built
    /// synthetic agent so an installed-SDK journey can verify its receipts.
    #[cfg(feature = "testkit-agent")]
    #[must_use]
    pub fn testkit_receipt_anchors(&self) -> [crate::receipt_attestor::TestkitReceiptAnchor; 2] {
        self.receipts.testkit_anchors()
    }
}

fn validate_embedded_qualification_key_separation(
    receipts: &ReceiptAttestor,
    recovery: &RecoveryHandleSigner,
) -> Result<(), LocalAgentDeploymentError> {
    let attestation = QualificationTrustRegistry::from_json(QUALIFICATION_ATTESTATION_TRUST)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let observer = QualificationObserverTrustRegistry::from_json(QUALIFICATION_OBSERVER_TRUST)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let sources = QualificationEvidenceSourceTrustRegistry::from_json(QUALIFICATION_SOURCE_TRUST)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let ledgers = QualificationEvidenceLedgerTrustRegistry::from_json(QUALIFICATION_LEDGER_TRUST)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    validate_agent_signing_key_separation(
        attestation
            .identities()
            .chain(observer.identities())
            .chain(sources.identities())
            .chain(ledgers.identities()),
        receipts.trust_anchors(),
        recovery,
    )
}

fn validate_agent_signing_key_separation<'a>(
    qualification: impl IntoIterator<Item = QualificationTrustIdentity<'a>>,
    receipts: &auths_receipts::ReceiptTrustAnchors,
    recovery: &RecoveryHandleSigner,
) -> Result<(), LocalAgentDeploymentError> {
    let recovery_public = Base64UrlUnpadded::encode_string(&recovery.public_key());
    let mut identities = qualification
        .into_iter()
        .map(|identity| {
            (
                identity.key_id().to_owned(),
                identity.public_key_base64url().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    identities.extend(receipts.anchors().iter().map(|anchor| {
        (
            anchor.key_id().to_owned(),
            anchor.public_key_base64url().to_owned(),
        )
    }));
    identities.push((recovery.key_id().to_owned(), recovery_public));
    validate_qualification_key_separation(
        identities
            .iter()
            .map(|(key_id, public_key)| QualificationTrustIdentity::new(key_id, public_key)),
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)
}

/// Loads only public receipt trust after owner/no-follow validation of the
/// configured current keys. This is the privileged export boundary; no seed
/// bytes leave this function.
#[cfg(unix)]
pub fn load_receipt_trust_anchors(
    config: &ReceiptSigningConfig,
) -> Result<auths_receipts::ReceiptTrustAnchors, LocalAgentDeploymentError> {
    receipt_trust_anchors_from_config(config)
}

#[cfg(unix)]
fn receipt_trust_anchors_from_config(
    config: &ReceiptSigningConfig,
) -> Result<auths_receipts::ReceiptTrustAnchors, LocalAgentDeploymentError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?
        .as_secs();
    if now < config.decision().not_before_unix_seconds()
        || now > config.decision().not_after_unix_seconds()
        || now < config.execution().not_before_unix_seconds()
        || now > config.execution().not_after_unix_seconds()
    {
        return Err(LocalAgentDeploymentError::InvalidConfiguration);
    }
    let mut anchors = config
        .prior()
        .iter()
        .map(|value| {
            let mut public_key = [0_u8; 32];
            Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
                .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
            ReceiptTrustAnchor::new(
                match value.role() {
                    ReceiptSigningRole::Decision => ReceiptTrustAnchorRole::Decision,
                    ReceiptSigningRole::Execution => ReceiptTrustAnchorRole::Execution,
                },
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (role, value) in [
        (ReceiptTrustAnchorRole::Decision, config.decision()),
        (ReceiptTrustAnchorRole::Execution, config.execution()),
    ] {
        let mut public_key = [0_u8; 32];
        Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
        anchors.push(
            ReceiptTrustAnchor::new(
                role,
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        );
    }
    anchors.sort_by(|left, right| {
        (left.role(), left.key_id().as_bytes()).cmp(&(right.role(), right.key_id().as_bytes()))
    });
    auths_receipts::ReceiptTrustAnchors::new(anchors)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)
}

#[cfg(unix)]
fn build_receipt_attestor(
    config: &ReceiptSigningConfig,
    signing_seeds: &AgentSigningSeeds,
) -> Result<ReceiptAttestor, LocalAgentDeploymentError> {
    let expected_anchors = receipt_trust_anchors_from_config(config)?;
    let prior = expected_anchors
        .anchors()
        .iter()
        .filter(|anchor| {
            !matches!(
                (anchor.role(), anchor.key_id()),
                (ReceiptTrustAnchorRole::Decision, key) if key == config.decision().key_id()
            ) && !matches!(
                (anchor.role(), anchor.key_id()),
                (ReceiptTrustAnchorRole::Execution, key) if key == config.execution().key_id()
            )
        })
        .cloned()
        .collect();
    if signing_seeds.decision.as_bytes() == signing_seeds.execution.as_bytes()
        || signing_seeds.recovery.as_bytes() == signing_seeds.decision.as_bytes()
        || signing_seeds.recovery.as_bytes() == signing_seeds.execution.as_bytes()
    {
        return Err(LocalAgentDeploymentError::InvalidConfiguration);
    }
    let receipts = ReceiptAttestor::from_signing_keys(
        config.decision().key_id(),
        config.decision().verification_method(),
        signing_seeds.decision.as_bytes(),
        config.decision().not_before_unix_seconds(),
        config.decision().not_after_unix_seconds(),
        config.execution().key_id(),
        config.execution().verification_method(),
        signing_seeds.execution.as_bytes(),
        config.execution().not_before_unix_seconds(),
        config.execution().not_after_unix_seconds(),
        prior,
    );
    let receipts = receipts.map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if receipts.trust_anchors() != &expected_anchors {
        return Err(LocalAgentDeploymentError::InvalidConfiguration);
    }
    Ok(receipts)
}

struct SecretSeed(Zeroizing<[u8; 32]>);

impl SecretSeed {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

struct AgentSigningSeeds {
    decision: SecretSeed,
    execution: SecretSeed,
    recovery: SecretSeed,
}

/// Binds and serves the application and privileged socket trees together.
///
/// Both listeners are bound before either begins accepting. Authority and
/// administration state are also fully validated first, so startup is
/// all-or-nothing. The concrete executor remains a static Rust-owned vertical.
#[cfg(unix)]
pub fn bind_local_control_plane(
    deployment: LocalAgentDeploymentConfig,
    agent_config: AgentConfig,
    resources: LocalAgentResources,
) -> Result<BoundLocalControlPlane, LocalAgentDeploymentError> {
    bind_local_control_plane_for(
        deployment,
        agent_config,
        resources,
        LaunchFlavor::Production,
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        None,
    )
}

/// Binds the qualification-only control plane with the exact five-profile
/// roster and the one-shot post-decision checkpoint enabled.
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
pub fn bind_qualification_control_plane(
    deployment: LocalAgentDeploymentConfig,
    agent_config: AgentConfig,
    resources: LocalAgentResources,
    client_bridge: QualificationClientBridgePolicy,
    credential_broker: QualificationCredentialBrokerPolicy,
    provider_proxy: QualificationProviderProxyPolicy,
) -> Result<BoundLocalControlPlane, LocalAgentDeploymentError> {
    if client_bridge.reader_uid() == deployment.agent_uid
        || credential_broker.reader_uid() == deployment.agent_uid
        || provider_proxy.reader_uid() == deployment.agent_uid
        || credential_broker.reader_uid() == client_bridge.reader_uid()
        || provider_proxy.reader_uid() == client_bridge.reader_uid()
        || provider_proxy.reader_uid() == credential_broker.reader_uid()
    {
        return Err(LocalAgentDeploymentError::InvalidConfiguration);
    }
    bind_local_control_plane_for(
        deployment,
        agent_config,
        resources,
        LaunchFlavor::Qualification,
        Some((client_bridge, credential_broker, provider_proxy)),
    )
}

#[cfg(unix)]
fn bind_local_control_plane_for(
    deployment: LocalAgentDeploymentConfig,
    agent_config: AgentConfig,
    resources: LocalAgentResources,
    flavor: LaunchFlavor,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    qualification_policy: Option<(
        QualificationClientBridgePolicy,
        QualificationCredentialBrokerPolicy,
        QualificationProviderProxyPolicy,
    )>,
) -> Result<BoundLocalControlPlane, LocalAgentDeploymentError> {
    let mutable_state_root = deployment
        .operation_store
        .parent()
        .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?
        .to_owned();
    let authenticator = ConfiguredWorkloadAuthenticator::load_for(
        agent_config.clone(),
        deployment.agent_uid,
        mutable_state_root,
        flavor,
    )
    .map_err(|_| LocalAgentDeploymentError::Authority)?;
    let executor = JournaledLocalExecutor::new(
        Arc::clone(&resources.operations),
        Arc::clone(&resources.connections),
        Arc::clone(&resources.credentials),
        Arc::clone(&resources.recovery),
        Arc::clone(&resources.receipts),
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    let executor = if flavor == LaunchFlavor::Qualification {
        let (_, credential_broker, provider_proxy) = qualification_policy
            .as_ref()
            .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?;
        executor.with_qualification_mode(
            resources.qualification_journal_gate.clone(),
            credential_broker.clone(),
            provider_proxy.clone(),
        )
    } else {
        executor
    };
    let executor = Arc::new(executor);
    let profiles = match flavor {
        LaunchFlavor::Production => built_in_local_profiles(),
        #[cfg(feature = "qualification-failpoints")]
        LaunchFlavor::Qualification => built_in_qualification_local_profiles(),
        #[cfg(any(test, feature = "testkit-agent"))]
        LaunchFlavor::Testkit => Err(LocalAgentFailure::InvalidConfiguration),
    }
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let local_state = LocalAgentState::new(
        Arc::new(authenticator),
        executor,
        profiles,
        Arc::clone(&resources.profile_state_root),
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let peer_policy = AdminPeerPolicy::new(deployment.admin_uids, deployment.admin_gids)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let admin_state = ConnectionAdminState::new(
        peer_policy,
        agent_config,
        Arc::clone(&resources.connections),
        Arc::clone(&resources.credentials),
        deployment.admin_audit,
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let (agent_listener, agent_cleanup) =
        bind_socket(&deployment.agent_socket, deployment.agent_uid, 0o660)?;
    let (admin_listener, admin_cleanup) =
        bind_socket(&deployment.admin_socket, deployment.agent_uid, 0o600)?;
    Ok(BoundLocalControlPlane {
        agent_listener,
        admin_listener,
        local_state,
        admin_state,
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        qualification_client_bridge: qualification_policy
            .map(|(client_bridge, _, _)| client_bridge),
        _cleanup: (agent_cleanup, admin_cleanup),
    })
}

/// Binds a single application socket backed by the static Stripe testkit
/// vertical. No administration socket, runtime callback, or production
/// provider adapter is installed.
#[cfg(all(unix, feature = "testkit-agent"))]
pub fn bind_testkit_agent(
    deployment: &LocalAgentDeploymentConfig,
    resources: &LocalAgentResources,
    connection_alias: &str,
) -> Result<BoundTestkitAgent, LocalAgentDeploymentError> {
    let (listener, cleanup) = bind_socket(&deployment.agent_socket, deployment.agent_uid, 0o600)?;
    let authenticator = TestkitWorkloadAuthenticator::new(deployment.agent_uid, connection_alias)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let executor = Arc::new(
        JournaledLocalExecutor::new_testkit_stripe(
            Arc::clone(&resources.operations),
            Arc::clone(&resources.connections),
            Arc::clone(&resources.credentials),
            Arc::clone(&resources.recovery),
            Arc::clone(&resources.receipts),
        )
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
    );
    let profiles = built_in_testkit_local_profiles()
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?
        .into_iter()
        .filter(|profile| {
            profile.advertisement().profile().id() == "auths.stripe.refund"
                && profile.advertisement().profile().version() == 1
        })
        .collect::<Vec<_>>();
    if profiles.len() != 1 {
        return Err(LocalAgentDeploymentError::InvalidConfiguration);
    }
    let local_state = LocalAgentState::new(
        Arc::new(authenticator),
        executor,
        profiles,
        Arc::clone(&resources.profile_state_root),
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    Ok(BoundTestkitAgent {
        listener,
        local_state,
        _cleanup: cleanup,
    })
}

/// Installs or validates the one persistent synthetic Stripe connection used
/// by the disposable testkit agent.
#[cfg(feature = "testkit-agent")]
pub async fn provision_testkit_stripe_connection(
    resources: &LocalAgentResources,
    connection_alias: &str,
) -> Result<(), LocalAgentDeploymentError> {
    let provider = ProviderKind::parse("stripe")
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let alias = ConnectionAlias::parse(connection_alias)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let descriptor = br#"{"accountId":"acct_test_primary","allowedScopes":["stripe.refunds.write/1"],"apiVersion":"2025-08-27","livemode":false,"schema":"auths.stripe.connection-descriptor/1"}"#.to_vec();
    let validated =
        auths_stripe::connection::StripeConnectionDescriptor::from_canonical_bytes(&descriptor)
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    if let Some(existing) = resources
        .connections
        .load(&provider, &alias)
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?
    {
        if existing.descriptor() != descriptor
            || existing.state() != ConnectionState::Active
            || existing.allowed_workloads() != ["auths-testkit"]
            || existing.allowed_profiles().len() != 1
            || existing.allowed_profiles()[0].id().as_str() != "auths.stripe.refund"
            || existing.allowed_profiles()[0].version() != 1
            || resources
                .credentials
                .retained_commitment(existing.connection_id(), existing.generation())
                .map_err(|_| LocalAgentDeploymentError::PersistentState)?
                .as_bytes()
                != existing.credential_reference_commitment()
        {
            return Err(LocalAgentDeploymentError::PersistentState);
        }
        return Ok(());
    }

    let connection_id =
        ConnectionId::generate().map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let generation =
        std::num::NonZeroU64::new(1).ok_or(LocalAgentDeploymentError::InvalidConfiguration)?;
    let secret = SecretBytes::new(b"sk_test_auths_testkit_credential".to_vec())
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    let credential = resources
        .credentials
        .install(&connection_id, generation, secret)
        .await
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?
        .as_secs();
    let record = ConnectionRecord::new(
        provider,
        alias,
        connection_id.clone(),
        SemanticId::parse("auths.stripe.connection/1")
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        SemanticId::parse("auths.stripe.connection-descriptor/1")
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        descriptor,
        validated.account_commitment(),
        *credential.as_bytes(),
        generation,
        ConnectionState::Active,
        vec!["auths-testkit".into()],
        vec![
            ConnectionProfile::new(
                SemanticId::parse("auths.stripe.refund")
                    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
                1,
            )
            .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?,
        ],
        now,
        now,
        None,
    )
    .map_err(|_| LocalAgentDeploymentError::InvalidConfiguration)?;
    if resources
        .connections
        .insert_with_defaults(record, &["auths-testkit".into()])
        .is_err()
    {
        let _ = resources
            .credentials
            .revoke(&connection_id, generation)
            .await;
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    Ok(())
}

/// Binds and serves the application and privileged socket trees together.
#[cfg(unix)]
pub async fn serve_local_control_plane(
    deployment: LocalAgentDeploymentConfig,
    agent_config: AgentConfig,
    resources: LocalAgentResources,
) -> Result<(), LocalAgentDeploymentError> {
    bind_local_control_plane(deployment, agent_config, resources)?
        .serve()
        .await
}

/// Closed local deployment startup/serve failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalAgentDeploymentError {
    /// A path, identity, limit, or route registration is invalid.
    #[error("invalid local-agent deployment configuration")]
    InvalidConfiguration,
    /// Existing connection or credential state is unsafe or malformed.
    #[error("invalid local-agent persistent state")]
    PersistentState,
    /// One or more sealed workload authority artifacts failed validation.
    #[error("invalid local-agent workload authority")]
    Authority,
    /// A local socket cannot be bound safely.
    #[error("local-agent socket is unavailable or unsafe")]
    Socket,
    /// One of the local servers stopped unexpectedly.
    #[error("local-agent server failed")]
    Serve,
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && path.as_os_str().as_encoded_bytes().len() <= 1_024
        && !path
            .components()
            .any(|item| matches!(item, Component::CurDir | Component::ParentDir))
}

fn registered_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
fn load_secret_seed(path: &Path, agent_uid: u32) -> Result<SecretSeed, LocalAgentDeploymentError> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::{
        io::Read as _,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    let parent_path = path
        .parent()
        .filter(|parent| parent.is_absolute())
        .ok_or(LocalAgentDeploymentError::PersistentState)?;
    let name = path
        .file_name()
        .ok_or(LocalAgentDeploymentError::PersistentState)?;
    let root = fs::File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?,
    );
    let mut parent = root;
    for component in parent_path.components() {
        let Component::Normal(component) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(LocalAgentDeploymentError::PersistentState);
        };
        parent = fs::File::from(
            openat(
                &parent,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| LocalAgentDeploymentError::PersistentState)?,
        );
    }
    let parent_before = parent
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if !parent_before.file_type().is_dir()
        || (parent_before.uid() != 0 && parent_before.uid() != agent_uid)
        || parent_before.permissions().mode() & 0o077 != 0
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let mut file = fs::File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if !before.file_type().is_file()
        || before.len() != 32
        || before.nlink() != 1
        || (before.uid() != 0 && before.uid() != agent_uid)
        || before.permissions().mode() & 0o077 != 0
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let opened = &before;
    if !opened.file_type().is_file()
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.nlink() != before.nlink()
        || opened.uid() != before.uid()
        || opened.mode() != before.mode()
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let mut seed = SecretSeed(Zeroizing::new([0_u8; 32]));
    file.read_exact(seed.0.as_mut())
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?
        != 0
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let after = file
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let named_after = fs::File::from(
        openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?,
    )
    .metadata()
    .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let parent_after = parent
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.mtime() != opened.mtime()
        || after.mtime_nsec() != opened.mtime_nsec()
        || named_after.dev() != opened.dev()
        || named_after.ino() != opened.ino()
        || parent_after.dev() != parent_before.dev()
        || parent_after.ino() != parent_before.ino()
        || parent_after.uid() != parent_before.uid()
        || parent_after.mode() != parent_before.mode()
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    Ok(seed)
}

#[cfg(not(unix))]
fn load_secret_seed(
    _path: &Path,
    _agent_uid: u32,
) -> Result<SecretSeed, LocalAgentDeploymentError> {
    Err(LocalAgentDeploymentError::InvalidConfiguration)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn load_secret_seed_at(
    parent: &std::fs::File,
    name: &str,
    agent_uid: u32,
    agent_gid: u32,
) -> Result<SecretSeed, LocalAgentDeploymentError> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::io::Read as _;

    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let mut file = std::fs::File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if !before.file_type().is_file()
        || before.len() != 32
        || before.nlink() != 1
        || before.uid() != agent_uid
        || before.gid() != agent_gid
        || before.mode() & 0o777 != 0o600
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let mut seed = SecretSeed(Zeroizing::new([0_u8; 32]));
    file.read_exact(seed.0.as_mut())
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?
        != 0
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    let after = file
        .metadata()
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    let named = std::fs::File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?,
    )
    .metadata()
    .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || after.dev() != named.dev()
        || after.ino() != named.ino()
        || after.len() != named.len()
        || after.uid() != named.uid()
        || after.gid() != named.gid()
        || after.mode() != named.mode()
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    Ok(seed)
}

#[cfg(unix)]
struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn prepare_profile_state_root(
    path: &Path,
    agent_uid: u32,
) -> Result<(), LocalAgentDeploymentError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.exists() {
        fs::create_dir(path).map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
        fs::File::open(
            path.parent()
                .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?,
        )
        .and_then(|value| value.sync_all())
        .map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| LocalAgentDeploymentError::PersistentState)?;
    if !metadata.file_type().is_dir()
        || (metadata.uid() != 0 && metadata.uid() != agent_uid)
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LocalAgentDeploymentError::PersistentState);
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_profile_state_root(
    _path: &Path,
    _agent_uid: u32,
) -> Result<(), LocalAgentDeploymentError> {
    Err(LocalAgentDeploymentError::InvalidConfiguration)
}

#[cfg(unix)]
fn bind_socket(
    path: &Path,
    agent_uid: u32,
    mode: u32,
) -> Result<(UnixListener, SocketCleanup), LocalAgentDeploymentError> {
    use std::os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixStream as StdUnixStream,
    };

    let parent = path
        .parent()
        .ok_or(LocalAgentDeploymentError::InvalidConfiguration)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| LocalAgentDeploymentError::Socket)?;
    let parent_owner = parent_metadata.uid();
    if !parent_metadata.file_type().is_dir()
        || (parent_owner != 0 && parent_owner != agent_uid)
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(LocalAgentDeploymentError::Socket);
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        let owner = metadata.uid();
        if !metadata.file_type().is_socket()
            || (owner != 0 && owner != agent_uid)
            || metadata.permissions().mode() & 0o002 != 0
            || StdUnixStream::connect(path).is_ok()
        {
            return Err(LocalAgentDeploymentError::Socket);
        }
        std::fs::remove_file(path).map_err(|_| LocalAgentDeploymentError::Socket)?;
    }
    let listener = UnixListener::bind(path).map_err(|_| LocalAgentDeploymentError::Socket)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| LocalAgentDeploymentError::Socket)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| LocalAgentDeploymentError::Socket)?;
    if !metadata.file_type().is_socket() {
        return Err(LocalAgentDeploymentError::Socket);
    }
    let cleanup = SocketCleanup {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    Ok((listener, cleanup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_lifecycle::{OperationIdV1, OperationProfileV1};
    use ed25519_dalek::SigningKey;
    use std::{
        fs,
        num::NonZeroUsize,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };
    use tempfile::tempdir;

    #[test]
    fn deployment_paths_are_closed_and_distinct() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let limits = RegistryLimits {
            maximum_records: NonZeroUsize::new(8).unwrap(),
            maximum_encoded_bytes: NonZeroUsize::new(1_048_576).unwrap(),
        };
        let config = LocalAgentDeploymentConfig::new(
            directory.path().join("agent.sock"),
            directory.path().join("admin.sock"),
            directory.path().join("connections.cbor"),
            directory.path().join("credentials.cbor"),
            directory.path().join("operations.cbor"),
            directory.path().join("recovery.key"),
            "recovery-v1",
            directory.path().join("audit.jsonl"),
            1_000,
            [],
            [],
            limits,
        )
        .unwrap();
        assert_eq!(config.agent_socket(), directory.path().join("agent.sock"));
        assert!(
            LocalAgentDeploymentConfig::new(
                directory.path().join("agent.sock"),
                directory.path().join("agent.sock"),
                directory.path().join("connections.cbor"),
                directory.path().join("credentials.cbor"),
                directory.path().join("operations.cbor"),
                directory.path().join("recovery.key"),
                "recovery-v1",
                directory.path().join("audit.jsonl"),
                1_000,
                [],
                [],
                limits,
            )
            .is_err()
        );
    }

    #[test]
    fn resources_open_owner_only_recovery_key_and_manifest_limited_journal() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // `tempdir` may report a platform alias such as `/var` whose first
        // component is a symlink. Production seed loading deliberately walks
        // every component with `NOFOLLOW`, so exercise the canonical directory
        // rather than weakening that invariant for the test harness.
        let directory_path = fs::canonicalize(directory.path()).unwrap();
        let recovery_key = directory_path.join("recovery.key");
        fs::write(&recovery_key, [7_u8; 32]).unwrap();
        fs::set_permissions(&recovery_key, fs::Permissions::from_mode(0o600)).unwrap();
        let limits = RegistryLimits {
            maximum_records: NonZeroUsize::new(8).unwrap(),
            maximum_encoded_bytes: NonZeroUsize::new(1_048_576).unwrap(),
        };
        let config = LocalAgentDeploymentConfig::new(
            directory_path.join("agent.sock"),
            directory_path.join("admin.sock"),
            directory_path.join("connections.cbor"),
            directory_path.join("credentials.cbor"),
            directory_path.join("operations.cbor"),
            recovery_key,
            "recovery-v1",
            directory_path.join("audit.jsonl"),
            fs::metadata(&directory_path).unwrap().uid(),
            [],
            [],
            limits,
        )
        .unwrap();
        let resources = LocalAgentResources::open_testkit(&config).unwrap();
        let profile = OperationProfileV1::new(
            "auths.stripe.refund",
            1,
            auths_stripe::generated::profile_routes::REFUNDS_CREATE_RUNTIME_DIGEST,
        )
        .unwrap();
        let handle = resources
            .recovery
            .issue(
                &OperationIdV1::from_random_bytes([3; 16]).unwrap(),
                &profile,
                "did:example:workload",
                1,
                None,
            )
            .unwrap();
        assert!(!handle.is_empty());
        assert!(
            resources
                .operations
                .pending("did:example:workload")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn production_agent_rejects_qualification_key_id_or_public_key_reuse() {
        let decision = SigningKey::from_bytes(&[21_u8; 32]);
        let execution = SigningKey::from_bytes(&[22_u8; 32]);
        let receipt_anchors = auths_receipts::ReceiptTrustAnchors::new(vec![
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Decision,
                "receipt-decision",
                "did:key:receipt-decision",
                decision.verifying_key().to_bytes(),
                1,
                100,
            )
            .unwrap(),
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Execution,
                "receipt-execution",
                "did:key:receipt-execution",
                execution.verifying_key().to_bytes(),
                1,
                100,
            )
            .unwrap(),
        ])
        .unwrap();
        let recovery = RecoveryHandleSigner::from_seed("recovery", [23_u8; 32], []).unwrap();
        let distinct = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[24_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        assert!(
            validate_agent_signing_key_separation(
                [QualificationTrustIdentity::new("qualification", &distinct)],
                &receipt_anchors,
                &recovery,
            )
            .is_ok()
        );
        assert!(
            validate_agent_signing_key_separation(
                [QualificationTrustIdentity::new(
                    "receipt-decision",
                    &distinct
                )],
                &receipt_anchors,
                &recovery,
            )
            .is_err()
        );
        let receipt_public = Base64UrlUnpadded::encode_string(decision.verifying_key().as_bytes());
        assert!(
            validate_agent_signing_key_separation(
                [QualificationTrustIdentity::new(
                    "qualification-other-id",
                    &receipt_public,
                )],
                &receipt_anchors,
                &recovery,
            )
            .is_err()
        );
    }
}
