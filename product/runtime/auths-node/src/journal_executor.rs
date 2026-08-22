//! Durable local-agent orchestration over static Rust-owned profile bridges.

#![forbid(unsafe_code)]
// The executor spells out the durable state machine rather than hiding its
// domain-sensitive transitions behind callbacks. These targeted allowances
// preserve that explicit audit surface without weakening correctness lints.
#![allow(
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::unused_async,
    clippy::unused_self
)]

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use crate::local_agent::{
    ProcessObservation, QualificationCredentialBrokerPolicy, QualificationProviderProxyPolicy,
    observe_linux_process,
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use crate::qualification_crash::QualificationBoundaryClaim;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use crate::qualification_crash::QualificationJournalBoundaryGate;
use crate::{
    generated::profile_routes::{RegisteredProfile, RegisteredProvider},
    local_agent::{LocalAgentFailure, LocalOperationContext},
    preparation_evidence::{
        LeaseBinding, PreparationEvidenceLeaseStore, preparation_evidence_intent_commitment,
    },
    profile_launch::LaunchFlavor,
    receipt_attestor::ReceiptAttestor,
    recovery_handle::RecoveryHandleSigner,
};
#[cfg(test)]
use async_trait::async_trait;
use auths_connections::{
    ConnectionAlias, ConnectionBinding, ConnectionProfile, ConnectionRecord, CredentialScope,
    PersistentCredentialStore, ProviderCredentialLease, ProviderKind, SemanticId,
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use auths_connections::{
    QualificationCredentialLeaseRequest, QualificationProviderCallKind,
    QualificationProviderCallRequest, QualificationProviderCallResponse,
};
use auths_errors::{
    CauseCategory, EffectState, EnteredBoundaries, ErrorEnvelope, ErrorEnvelopeInput,
    RecommendedAction, RetryClass,
};
use auths_lifecycle::{
    ClientRequestIdV1, ConnectionBindingCommitmentsV1, OperationEffectV1, OperationIdV1,
    OperationProfileV1, OperationProjectionV1, OperationStateV1, PreparationBindingV1,
};
#[cfg(test)]
use auths_model::{ProfileId, ProfileRef};
use auths_production_client::{
    ClientRequestId, ExecuteOperationRequest, LocalOperationCompletion, LocalOperationOutcome,
    LocalPendingOperation, LocalReceiptEntry, OperationId, PreparationEvidenceRequest,
    PrepareOperationRequest, RecoverOperationRequest, SessionProfileKey,
    encode_local_operation_outcome, encode_pending_operations, encode_preparation_evidence_lease,
    encode_preparation_evidence_outcome, encode_receipt_entries, local_idempotency_commitment,
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use auths_profile_kit::QualificationAdmissionFaultV1;
#[cfg(feature = "testkit-agent")]
use auths_profile_runtime::ProfileOperationContext;
use auths_profile_runtime::{
    ProfileConclusion, ProfileConnectionRequirement as BridgeConnectionRequirement,
    ProfileDecisionReceiptFacts, ProfileExecutionReceiptFacts, ProfileObservation,
    ProfilePreEntryRecheck, ProfilePreparation, ProfilePreparationKind, ProfileReceiptInspection,
    ProfileRuntimeError as ProfileBridgeError, SealedProfileCall,
};
use auths_receipts::{DecisionClass, ExecutionOutcome};
#[cfg(test)]
use auths_receipts::{
    ProfileReceiptClaim, ProfileReceiptClaimPhase, encode_profile_receipt_claims,
};
use auths_stores::{
    JournalCompletionV1, JournalDecisionClassV1, JournalExecutionOutcomeV1, JournalRecordV1,
    JournalStatusV1, OperationMutationV1, PersistentConnectionStore, PersistentOperationJournal,
    PreparationIdentityLookup, PrepareJournalResult, generate_operation_id,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::{
    ops::Deref,
    sync::{Arc, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    time::{Instant as TokioInstant, timeout_at},
};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use zeroize::Zeroizing;

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const MAX_QUALIFICATION_CREDENTIAL_REQUEST_BYTES: usize = 16_384;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const MAX_QUALIFICATION_CREDENTIAL_BYTES: usize = 65_536;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const MAX_QUALIFICATION_PROVIDER_CALL_BYTES: usize = 260 * 1_024 * 1_024;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const MAX_QUALIFICATION_FRAME_BYTES: usize = MAX_QUALIFICATION_PROVIDER_CALL_BYTES;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const QUALIFICATION_CREDENTIAL_IO_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const QUALIFICATION_CREDENTIAL_ACQUIRE: u8 = 0;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
const QUALIFICATION_CREDENTIAL_CLOSE_RETRY: u8 = 1;

enum RuntimeCredentialLease {
    Local(ProviderCredentialLease),
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    Brokered {
        credential_capability: Zeroizing<[u8; 32]>,
        lease_sha256: [u8; 32],
        transport: QualificationCredentialTransport,
    },
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
enum QualificationCredentialCloseReadError {
    Ambiguous,
    Fatal,
}

impl RuntimeCredentialLease {
    const fn local(credential: ProviderCredentialLease) -> Self {
        Self::Local(credential)
    }

    // The brokered variant exists only in the Linux qualification build; keep
    // one cross-profile accessor so call sites cannot bypass that boundary.
    #[allow(clippy::unnecessary_wraps)]
    const fn credential(&self) -> Option<&ProviderCredentialLease> {
        match self {
            Self::Local(credential) => Some(credential),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            Self::Brokered { .. } => None,
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    const fn qualification_lease_sha256(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Brokered { lease_sha256, .. } => Some(lease_sha256),
            Self::Local(_) => None,
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn qualification_credential_capability(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Brokered {
                credential_capability,
                ..
            } => Some(credential_capability),
            Self::Local(_) => None,
        }
    }

    async fn close(self) -> Result<(), LocalAgentFailure> {
        match self {
            Self::Local(_) => Ok(()),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            Self::Brokered { transport, .. } => transport.close().await,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
struct QualificationCredentialTransport {
    stream: UnixStream,
    request: Vec<u8>,
    peer_pid: u32,
    peer: ProcessObservation,
    policy: QualificationCredentialBrokerPolicy,
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationCredentialTransport {
    async fn close(mut self) -> Result<(), LocalAgentFailure> {
        let deadline = TokioInstant::now() + QUALIFICATION_CREDENTIAL_IO_TIMEOUT;
        verify_credential_broker_peer(self.peer_pid, &self.peer, &self.policy)?;
        if write_qualification_frame(&mut self.stream, &[1], deadline)
            .await
            .is_err()
        {
            return retry_qualification_credential_close(&self.policy, &self.request, deadline)
                .await;
        }
        match read_qualification_close_ack(&mut self.stream, deadline).await {
            Ok(()) => {
                verify_credential_broker_peer(self.peer_pid, &self.peer, &self.policy)?;
                Ok(())
            }
            Err(QualificationCredentialCloseReadError::Fatal) => Err(LocalAgentFailure::Internal),
            Err(QualificationCredentialCloseReadError::Ambiguous) => {
                retry_qualification_credential_close(&self.policy, &self.request, deadline).await
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn read_qualification_close_ack(
    stream: &mut UnixStream,
    deadline: TokioInstant,
) -> Result<(), QualificationCredentialCloseReadError> {
    let mut length = [0_u8; 4];
    timeout_at(deadline, stream.read_exact(&mut length))
        .await
        .map_err(|_| QualificationCredentialCloseReadError::Ambiguous)?
        .map_err(|_| QualificationCredentialCloseReadError::Ambiguous)?;
    if u32::from_be_bytes(length) != 1 {
        return Err(QualificationCredentialCloseReadError::Fatal);
    }
    let mut acknowledgement = [0_u8; 1];
    timeout_at(deadline, stream.read_exact(&mut acknowledgement))
        .await
        .map_err(|_| QualificationCredentialCloseReadError::Ambiguous)?
        .map_err(|_| QualificationCredentialCloseReadError::Ambiguous)?;
    if acknowledgement != [1] {
        return Err(QualificationCredentialCloseReadError::Fatal);
    }
    let mut trailing = [0_u8; 1];
    match timeout_at(deadline, stream.read(&mut trailing)).await {
        Ok(Ok(0)) => Ok(()),
        Ok(Ok(_)) => Err(QualificationCredentialCloseReadError::Fatal),
        Ok(Err(_)) | Err(_) => Err(QualificationCredentialCloseReadError::Ambiguous),
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn retry_qualification_credential_close(
    policy: &QualificationCredentialBrokerPolicy,
    request: &[u8],
    deadline: TokioInstant,
) -> Result<(), LocalAgentFailure> {
    loop {
        if TokioInstant::now() >= deadline {
            return Err(LocalAgentFailure::Internal);
        }
        let (mut stream, peer_pid, peer) = match connect_qualification_credential_broker(
            policy,
            request,
            QUALIFICATION_CREDENTIAL_CLOSE_RETRY,
            deadline,
        )
        .await
        {
            Ok(connection) => connection,
            Err(LocalAgentFailure::Unauthenticated) => {
                return Err(LocalAgentFailure::Unauthenticated);
            }
            Err(_) => continue,
        };
        match read_qualification_close_ack(&mut stream, deadline).await {
            Ok(()) => {
                return verify_credential_broker_peer(peer_pid, &peer, policy);
            }
            Err(QualificationCredentialCloseReadError::Fatal) => {
                return Err(LocalAgentFailure::Internal);
            }
            Err(QualificationCredentialCloseReadError::Ambiguous) => {}
        }
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn verify_credential_broker_peer(
    pid: u32,
    retained: &ProcessObservation,
    policy: &QualificationCredentialBrokerPolicy,
) -> Result<(), LocalAgentFailure> {
    let current = observe_linux_process(pid)?;
    if current.start_time_ticks != retained.start_time_ticks
        || current.effective_uid != retained.effective_uid
        || current.effective_gid != retained.effective_gid
        || current.executable_sha256 != retained.executable_sha256
        || current.effective_uid != policy.reader_uid()
        || current.executable_sha256 != policy.reader_artifact_sha256()
    {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn write_qualification_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: TokioInstant,
) -> Result<(), LocalAgentFailure> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_FRAME_BYTES {
        return Err(LocalAgentFailure::Internal);
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| LocalAgentFailure::Internal)?
        .to_be_bytes();
    timeout_at(deadline, async {
        stream.write_all(&length).await?;
        stream.write_all(bytes).await
    })
    .await
    .map_err(|_| LocalAgentFailure::Internal)?
    .map_err(|_| LocalAgentFailure::Internal)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn read_qualification_frame(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: TokioInstant,
) -> Result<Zeroizing<Vec<u8>>, LocalAgentFailure> {
    let mut length = [0_u8; 4];
    timeout_at(deadline, stream.read_exact(&mut length))
        .await
        .map_err(|_| LocalAgentFailure::Internal)?
        .map_err(|_| LocalAgentFailure::Internal)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| LocalAgentFailure::Internal)?;
    if length == 0 || length > maximum {
        return Err(LocalAgentFailure::Internal);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    timeout_at(deadline, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| LocalAgentFailure::Internal)?
        .map_err(|_| LocalAgentFailure::Internal)?;
    Ok(bytes)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn connect_qualification_credential_broker(
    policy: &QualificationCredentialBrokerPolicy,
    request: &[u8],
    mode: u8,
    deadline: TokioInstant,
) -> Result<(UnixStream, u32, ProcessObservation), LocalAgentFailure> {
    let mut stream = timeout_at(deadline, UnixStream::connect(policy.socket()))
        .await
        .map_err(|_| LocalAgentFailure::NotFound)?
        .map_err(|_| LocalAgentFailure::NotFound)?;
    let peer_credentials = stream
        .peer_cred()
        .map_err(|_| LocalAgentFailure::Unauthenticated)?;
    let peer_pid = peer_credentials
        .pid()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LocalAgentFailure::Unauthenticated)?;
    if peer_credentials.uid() != policy.reader_uid() {
        return Err(LocalAgentFailure::Unauthenticated);
    }
    let peer = observe_linux_process(peer_pid)?;
    verify_credential_broker_peer(peer_pid, &peer, policy)?;
    let mut framed_request = Vec::with_capacity(request.len() + 1);
    framed_request.push(mode);
    framed_request.extend_from_slice(request);
    write_qualification_frame(&mut stream, &framed_request, deadline).await?;
    Ok((stream, peer_pid, peer))
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn lease_from_qualification_credential_broker(
    policy: QualificationCredentialBrokerPolicy,
    request: QualificationCredentialLeaseRequest,
) -> Result<RuntimeCredentialLease, LocalAgentFailure> {
    let lease_sha256 = request
        .lease_sha256()
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    let request = request
        .to_cbor()
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    if request.len() > MAX_QUALIFICATION_CREDENTIAL_REQUEST_BYTES {
        return Err(LocalAgentFailure::InvalidConfiguration);
    }
    let deadline = TokioInstant::now() + QUALIFICATION_CREDENTIAL_IO_TIMEOUT;
    let (mut stream, peer_pid, peer) = connect_qualification_credential_broker(
        &policy,
        &request,
        QUALIFICATION_CREDENTIAL_ACQUIRE,
        deadline,
    )
    .await?;
    let bytes =
        read_qualification_frame(&mut stream, MAX_QUALIFICATION_CREDENTIAL_BYTES, deadline).await?;
    verify_credential_broker_peer(peer_pid, &peer, &policy)?;
    if bytes.len() != 33 || bytes[0] != 1 {
        return Err(LocalAgentFailure::Internal);
    }
    let credential_capability = Zeroizing::new(
        bytes[1..]
            .try_into()
            .map_err(|_| LocalAgentFailure::Internal)?,
    );
    Ok(RuntimeCredentialLease::Brokered {
        credential_capability,
        lease_sha256,
        transport: QualificationCredentialTransport {
            stream,
            request,
            peer_pid,
            peer,
            policy,
        },
    })
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn call_qualification_provider_proxy(
    policy: &QualificationProviderProxyPolicy,
    request: QualificationProviderCallRequest,
) -> Result<QualificationProviderCallResponse, ProfileBridgeError> {
    let request = request.to_cbor().map_err(|_| ProfileBridgeError::Invalid)?;
    let deadline = TokioInstant::now() + QUALIFICATION_CREDENTIAL_IO_TIMEOUT;
    loop {
        if TokioInstant::now() >= deadline {
            return Err(ProfileBridgeError::Invalid);
        }
        match call_qualification_provider_proxy_once(policy, &request, deadline).await {
            Ok(response) => return Ok(response),
            Err(QualificationProviderProxyTransportError::Fatal) => {
                return Err(ProfileBridgeError::Invalid);
            }
            Err(QualificationProviderProxyTransportError::Ambiguous) => {}
        }
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn qualification_provider_call_request(
    policy: &QualificationProviderProxyPolicy,
    record: &JournalRecordV1,
    kind: QualificationProviderCallKind,
    credential: &RuntimeCredentialLease,
    command: &[u8],
    profile_state: &[u8],
    configuration: Option<&auths_profile_runtime::ProfileConfigurationBinding>,
    now_unix_seconds: u64,
) -> Result<QualificationProviderCallRequest, LocalAgentFailure> {
    let profile = record.binding().profile();
    let connection_generation = record
        .binding()
        .connection()
        .map(auths_lifecycle::ConnectionBindingCommitmentsV1::generation)
        .ok_or(LocalAgentFailure::InvalidConfiguration)?;
    let credential_capability = credential
        .qualification_credential_capability()
        .copied()
        .ok_or(LocalAgentFailure::InvalidConfiguration)?;
    let credential_lease_sha256 = credential
        .qualification_lease_sha256()
        .copied()
        .ok_or(LocalAgentFailure::InvalidConfiguration)?;
    QualificationProviderCallRequest::new(
        *policy.source_context_sha256(),
        record.operation_id().as_str(),
        profile.id(),
        profile.version(),
        connection_generation,
        kind,
        credential_lease_sha256,
        command.to_vec(),
        profile_state.to_vec(),
        Zeroizing::new(credential_capability),
        configuration
            .map(auths_profile_runtime::ProfileConfigurationBinding::format)
            .map(str::to_owned),
        configuration
            .map(auths_profile_runtime::ProfileConfigurationBinding::canonical_bytes)
            .map(ToOwned::to_owned),
        now_unix_seconds,
    )
    .map_err(|()| LocalAgentFailure::InvalidConfiguration)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
#[derive(Clone, Copy)]
enum QualificationProviderProxyTransportError {
    Ambiguous,
    Fatal,
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn call_qualification_provider_proxy_once(
    policy: &QualificationProviderProxyPolicy,
    request: &[u8],
    deadline: TokioInstant,
) -> Result<QualificationProviderCallResponse, QualificationProviderProxyTransportError> {
    let mut stream = timeout_at(deadline, UnixStream::connect(policy.socket()))
        .await
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?;
    let credentials = stream
        .peer_cred()
        .map_err(|_| QualificationProviderProxyTransportError::Fatal)?;
    let peer_pid = credentials
        .pid()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(QualificationProviderProxyTransportError::Fatal)?;
    if credentials.uid() != policy.reader_uid() {
        return Err(QualificationProviderProxyTransportError::Fatal);
    }
    let peer = observe_linux_process(peer_pid)
        .map_err(|_| QualificationProviderProxyTransportError::Fatal)?;
    if peer.effective_uid != policy.reader_uid()
        || peer.executable_sha256 != policy.reader_artifact_sha256()
    {
        return Err(QualificationProviderProxyTransportError::Fatal);
    }
    write_qualification_frame(&mut stream, request, deadline)
        .await
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?;
    let response = read_qualification_provider_proxy_frame(&mut stream, deadline).await?;
    verify_provider_proxy_peer(peer_pid, &peer, policy)
        .map_err(|_| QualificationProviderProxyTransportError::Fatal)?;
    QualificationProviderCallResponse::from_cbor(&response)
        .map_err(|_| QualificationProviderProxyTransportError::Fatal)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
async fn read_qualification_provider_proxy_frame(
    stream: &mut UnixStream,
    deadline: TokioInstant,
) -> Result<Zeroizing<Vec<u8>>, QualificationProviderProxyTransportError> {
    let mut length = [0_u8; 4];
    timeout_at(deadline, stream.read_exact(&mut length))
        .await
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| QualificationProviderProxyTransportError::Fatal)?;
    if length == 0 || length > MAX_QUALIFICATION_PROVIDER_CALL_BYTES {
        return Err(QualificationProviderProxyTransportError::Fatal);
    }
    let mut response = Zeroizing::new(vec![0_u8; length]);
    timeout_at(deadline, stream.read_exact(&mut response))
        .await
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?
        .map_err(|_| QualificationProviderProxyTransportError::Ambiguous)?;
    Ok(response)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn verify_provider_proxy_peer(
    pid: u32,
    retained: &ProcessObservation,
    policy: &QualificationProviderProxyPolicy,
) -> Result<(), ProfileBridgeError> {
    let current = observe_linux_process(pid).map_err(|_| ProfileBridgeError::Invalid)?;
    if current.start_time_ticks != retained.start_time_ticks
        || current.effective_uid != retained.effective_uid
        || current.effective_gid != retained.effective_gid
        || current.executable_sha256 != retained.executable_sha256
        || current.effective_uid != policy.reader_uid()
        || current.executable_sha256 != policy.reader_artifact_sha256()
    {
        return Err(ProfileBridgeError::Invalid);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
trait QualificationProviderCallResponseExt {
    fn into_runtime(self, operation_id: &OperationIdV1) -> Result<Vec<u8>, ProfileBridgeError>;
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
impl QualificationProviderCallResponseExt for QualificationProviderCallResponse {
    fn into_runtime(self, operation_id: &OperationIdV1) -> Result<Vec<u8>, ProfileBridgeError> {
        match self {
            Self::Success(value) => Ok(value),
            Self::PreEntry(issue) => Err(ProfileBridgeError::PreEntry(issue)),
            Self::PreEntryPending => Err(ProfileBridgeError::PreEntryPending),
            Self::Possible(issue) => Err(ProfileBridgeError::Possible(issue)),
            Self::PossibleWithProfileState {
                issue,
                profile_state,
            } => Err(ProfileBridgeError::PossibleWithProfileState {
                issue,
                profile_state,
            }),
            Self::PostEntryTimeout => Err(ProfileBridgeError::Possible(
                common_issue(CommonIssue::OutcomeUnknown, Some(operation_id))
                    .map_err(|_| ProfileBridgeError::Invalid)?,
            )),
            Self::NotApplied => Err(ProfileBridgeError::Invalid),
            Self::Invalid => Err(ProfileBridgeError::Invalid),
        }
    }
}

/// Test-only profile seam. Production dispatch is the generated closed
/// [`RegisteredProfile`] enum and cannot install callbacks at runtime.
#[cfg(test)]
#[async_trait]
trait TestStaticLocalProfileBridge: Send + Sync {
    fn profile(&self) -> OperationProfileV1;
    fn connection_requirement(&self) -> Option<BridgeConnectionRequirement>;
    fn prepare(
        &self,
        context: &LocalOperationContext,
        workflow_id: &str,
        profile_input: &[u8],
        connection: Option<&ConnectionBinding>,
        preparation_evidence: Option<&[u8]>,
        now_unix_seconds: u64,
    ) -> Result<ProfilePreparation, ProfileBridgeError>;

    async fn seal_provider_call(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        now_unix_seconds: u64,
    ) -> Result<SealedProfileCall, ProfileBridgeError>;

    fn recheck_pre_entry(
        &self,
        _context: &LocalOperationContext,
        record: &JournalRecordV1,
        _now_unix_seconds: u64,
    ) -> Result<ProfilePreEntryRecheck, ProfileBridgeError> {
        Ok(ProfilePreEntryRecheck {
            profile_state: record.profile_state().to_vec(),
        })
    }

    fn release_pre_entry(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
    ) -> Result<(), ProfileBridgeError>;

    async fn call_provider(
        &self,
        context: &LocalOperationContext,
        call: &SealedProfileCall,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, ProfileBridgeError>;

    fn observe_provider_result(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        provider_result: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ProfileObservation, ProfileBridgeError>;

    async fn reconcile(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
    ) -> Result<ProfileObservation, ProfileBridgeError>;

    fn build_decision_receipt_claims(
        &self,
        facts: ProfileDecisionReceiptFacts<'_>,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        test_receipt_claims(
            facts.binding.profile(),
            ProfileReceiptClaimPhase::Decision,
            "test.profile-state",
            facts.profile_state,
        )
    }

    fn build_execution_receipt_claims(
        &self,
        facts: ProfileExecutionReceiptFacts<'_>,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        test_receipt_claims(
            facts.binding.profile(),
            ProfileReceiptClaimPhase::Execution,
            "test.sealed-command",
            facts.sealed_command,
        )
    }

    fn inspect_receipt_claims(
        &self,
        inspection: ProfileReceiptInspection<'_>,
    ) -> Result<(), ProfileBridgeError> {
        if self.build_decision_receipt_claims(inspection.facts.decision_facts())?
            != inspection.decision_claims
        {
            return Err(ProfileBridgeError::Invalid);
        }
        match (
            inspection.facts.execution_facts(),
            inspection.execution_claims,
        ) {
            (None, None) => Ok(()),
            (Some(facts), Some(actual))
                if self.build_execution_receipt_claims(facts)?.as_slice() == actual =>
            {
                Ok(())
            }
            _ => Err(ProfileBridgeError::Invalid),
        }
    }
}

#[cfg(test)]
fn test_receipt_claims(
    profile: &OperationProfileV1,
    phase: ProfileReceiptClaimPhase,
    id: &'static str,
    bytes: &[u8],
) -> Result<Vec<u8>, ProfileBridgeError> {
    let profile = ProfileRef::new(
        ProfileId::parse(profile.id()).map_err(|_| ProfileBridgeError::Invalid)?,
        profile.version(),
    )
    .map_err(|_| ProfileBridgeError::Invalid)?;
    encode_profile_receipt_claims(
        &profile,
        phase,
        &[ProfileReceiptClaim::new(id, Sha256::digest(bytes).into())
            .map_err(|_| ProfileBridgeError::Invalid)?],
    )
    .map_err(|_| ProfileBridgeError::Invalid)
}

#[derive(Clone)]
enum ProfileRuntime {
    BuiltIn {
        profile: RegisteredProfile,
        mode: RuntimeMode,
    },
    #[cfg(test)]
    Test(Arc<dyn TestStaticLocalProfileBridge>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeMode {
    Production,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    Qualification,
    #[cfg(feature = "testkit-agent")]
    TestkitStripe,
}

enum GatedPreparationRecord {
    Record(JournalRecordV1),
    ReceiptIntegrityFailed(JournalRecordV1),
    IntentConflict(JournalRecordV1),
}

struct ReceiptIntegrityTruth {
    state: OperationStateV1,
    issue: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
    progress: Option<Vec<u8>>,
    completion: Option<JournalCompletionV1>,
    profile_state: Vec<u8>,
}

impl ReceiptIntegrityTruth {
    fn recovery(issue: Vec<u8>, progress: Option<Vec<u8>>, profile_state: Vec<u8>) -> Self {
        Self {
            state: OperationStateV1::RecoveryRequired,
            issue: Some(issue),
            value: None,
            progress,
            completion: None,
            profile_state,
        }
    }

    fn terminal(
        state: OperationStateV1,
        issue: Option<Vec<u8>>,
        value: Option<Vec<u8>>,
        completion: JournalCompletionV1,
        profile_state: Vec<u8>,
    ) -> Self {
        Self {
            state,
            issue,
            value,
            progress: None,
            completion: Some(completion),
            profile_state,
        }
    }
}

impl ProfileRuntime {
    fn preparation_evidence_kind(&self) -> Option<&'static str> {
        match self {
            Self::BuiltIn { profile, .. } => profile.preparation_evidence_kind(),
            #[cfg(test)]
            Self::Test(_) => None,
        }
    }

    fn authorize_preparation_evidence(
        &self,
        context: &LocalOperationContext,
        workflow_id: &str,
        profile_input: &[u8],
        connection: Option<&ConnectionBinding>,
        now_unix_seconds: u64,
    ) -> Result<[u8; 32], ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe {
                    return testkit_preparation_evidence_commitment(
                        context,
                        workflow_id,
                        profile_input,
                        connection,
                    );
                }
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                profile.authorize_preparation_evidence(
                    context,
                    workflow_id,
                    profile_input,
                    connection,
                    now_unix_seconds,
                )
            }
            #[cfg(test)]
            Self::Test(_) => Err(ProfileBridgeError::Invalid),
        }
    }

    fn acquire_preparation_evidence(
        &self,
        context: &LocalOperationContext,
        workflow_id: &str,
        profile_input: &[u8],
        connection: Option<&ConnectionBinding>,
        authority_action_commitment: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<auths_profile_runtime::PreparationEvidenceAcquisition, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe {
                    let expected = testkit_preparation_evidence_commitment(
                        context,
                        workflow_id,
                        profile_input,
                        connection,
                    )?;
                    if expected != authority_action_commitment {
                        return Err(ProfileBridgeError::Invalid);
                    }
                    return Ok(auths_profile_runtime::PreparationEvidenceAcquisition {
                        bytes: vec![0xa0],
                        authority_action_commitment,
                    });
                }
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                profile.acquire_preparation_evidence(
                    context,
                    workflow_id,
                    profile_input,
                    connection,
                    authority_action_commitment,
                    now_unix_seconds,
                )
            }
            #[cfg(test)]
            Self::Test(_) => Err(ProfileBridgeError::Invalid),
        }
    }

    fn profile(&self) -> Result<OperationProfileV1, LocalAgentFailure> {
        match self {
            Self::BuiltIn { profile, .. } => profile.profile(),
            #[cfg(test)]
            Self::Test(profile) => Ok(profile.profile()),
        }
    }

    fn connection_requirement(&self) -> Option<BridgeConnectionRequirement> {
        match self {
            Self::BuiltIn { profile, .. } => profile.connection_requirement(),
            #[cfg(test)]
            Self::Test(profile) => profile.connection_requirement(),
        }
    }

    fn build_decision_receipt_claims(
        &self,
        facts: ProfileDecisionReceiptFacts<'_>,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => profile.build_decision_receipt_claims(facts),
            #[cfg(test)]
            Self::Test(profile) => profile.build_decision_receipt_claims(facts),
        }
    }

    fn build_execution_receipt_claims(
        &self,
        facts: ProfileExecutionReceiptFacts<'_>,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => profile.build_execution_receipt_claims(facts),
            #[cfg(test)]
            Self::Test(profile) => profile.build_execution_receipt_claims(facts),
        }
    }

    fn inspect_receipt_claims(
        &self,
        inspection: ProfileReceiptInspection<'_>,
    ) -> Result<(), ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => profile.inspect_receipt_claims(inspection),
            #[cfg(test)]
            Self::Test(profile) => profile.inspect_receipt_claims(inspection),
        }
    }

    fn revalidate_configuration(
        &self,
        context: &LocalOperationContext,
    ) -> Result<(), LocalAgentFailure> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    return Ok(());
                }
                profile.revalidate_configuration(context)
            }
            #[cfg(test)]
            Self::Test(_) => Ok(()),
        }
    }

    fn release_pre_entry(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
    ) -> Result<(), ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    let identity = profile.profile().map_err(|_| ProfileBridgeError::Invalid)?;
                    return auths_stripe::local_agent::refunds_create_release_pre_entry_testkit(
                        auths_profile_runtime::ReleaseProfileCallInput {
                            context: operation_context(&identity, context),
                            record,
                        },
                    );
                }
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                profile.release_pre_entry(context, record)
            }
            #[cfg(test)]
            Self::Test(profile) => profile.release_pre_entry(context, record),
        }
    }

    fn prepare(
        &self,
        context: &LocalOperationContext,
        workflow_id: &str,
        profile_input: &[u8],
        connection: Option<&ConnectionBinding>,
        preparation_evidence: Option<&[u8]>,
        now_unix_seconds: u64,
    ) -> Result<ProfilePreparation, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    let identity = profile.profile().map_err(|_| ProfileBridgeError::Invalid)?;
                    return auths_stripe::local_agent::refunds_create_prepare_testkit(
                        auths_profile_runtime::PrepareProfileInput {
                            context: operation_context(&identity, context),
                            workflow_id,
                            profile_input,
                            connection,
                            preparation_evidence,
                            now_unix_seconds,
                        },
                    );
                }
                profile.prepare(
                    context,
                    workflow_id,
                    profile_input,
                    connection,
                    preparation_evidence,
                    now_unix_seconds,
                )
            }
            #[cfg(test)]
            Self::Test(profile) => profile.prepare(
                context,
                workflow_id,
                profile_input,
                connection,
                preparation_evidence,
                now_unix_seconds,
            ),
        }
    }

    async fn seal_provider_call(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        now_unix_seconds: u64,
    ) -> Result<SealedProfileCall, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    let identity = profile.profile().map_err(|_| ProfileBridgeError::Invalid)?;
                    return auths_stripe::local_agent::refunds_create_seal_provider_call_testkit(
                        auths_profile_runtime::SealProfileCallInput {
                            context: operation_context(&identity, context),
                            record,
                            now_unix_seconds,
                        },
                    );
                }
                profile
                    .seal_provider_call(context, record, now_unix_seconds)
                    .await
            }
            #[cfg(test)]
            Self::Test(profile) => {
                profile
                    .seal_provider_call(context, record, now_unix_seconds)
                    .await
            }
        }
    }

    fn recheck_pre_entry(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        now_unix_seconds: u64,
    ) -> Result<ProfilePreEntryRecheck, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    return Ok(ProfilePreEntryRecheck {
                        profile_state: record.profile_state().to_vec(),
                    });
                }
                profile.recheck_pre_entry(context, record, now_unix_seconds)
            }
            #[cfg(test)]
            Self::Test(profile) => profile.recheck_pre_entry(context, record, now_unix_seconds),
        }
    }

    async fn call_provider(
        &self,
        context: &LocalOperationContext,
        call: &SealedProfileCall,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    let identity = profile.profile().map_err(|_| ProfileBridgeError::Invalid)?;
                    return auths_stripe::local_agent::refunds_create_call_provider_testkit(
                        auths_profile_runtime::CallProviderInput {
                            context: operation_context(&identity, context),
                            call,
                            credential,
                            now_unix_seconds,
                        },
                    );
                }
                profile
                    .call_provider(context, call, credential, now_unix_seconds)
                    .await
            }
            #[cfg(test)]
            Self::Test(profile) => {
                profile
                    .call_provider(context, call, credential, now_unix_seconds)
                    .await
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn finalize_qualification_provider_result(
        &self,
        context: &LocalOperationContext,
        call: &SealedProfileCall,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
        result: Result<Vec<u8>, ProfileBridgeError>,
    ) -> Result<Vec<u8>, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => profile.finalize_qualification_provider_result(
                context,
                call,
                credential,
                now_unix_seconds,
                result,
            ),
            #[cfg(test)]
            Self::Test(_) => result,
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn finalize_qualification_reconcile_result(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        now_unix_seconds: u64,
        result: QualificationProviderCallResponse,
    ) -> Result<ProfileObservation, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => profile.finalize_qualification_reconcile_result(
                context,
                record,
                now_unix_seconds,
                result,
            ),
            #[cfg(test)]
            Self::Test(_) => Err(ProfileBridgeError::Invalid),
        }
    }

    fn observe_provider_result(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        provider_result: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ProfileObservation, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, .. } => {
                profile.observe_provider_result(context, record, provider_result, now_unix_seconds)
            }
            #[cfg(test)]
            Self::Test(profile) => {
                profile.observe_provider_result(context, record, provider_result, now_unix_seconds)
            }
        }
    }

    async fn reconcile(
        &self,
        context: &LocalOperationContext,
        record: &JournalRecordV1,
        credential: Option<&ProviderCredentialLease>,
        now_unix_seconds: u64,
    ) -> Result<ProfileObservation, ProfileBridgeError> {
        match self {
            Self::BuiltIn { profile, mode } => {
                #[cfg(not(feature = "testkit-agent"))]
                let _ = mode;
                #[cfg(feature = "testkit-agent")]
                if *mode == RuntimeMode::TestkitStripe
                    && *profile == RegisteredProfile::StripeRefundsCreate
                {
                    let identity = profile.profile().map_err(|_| ProfileBridgeError::Invalid)?;
                    return auths_stripe::local_agent::refunds_create_reconcile_testkit(
                        auths_profile_runtime::ReconcileProfileInput {
                            context: operation_context(&identity, context),
                            record,
                            credential,
                            now_unix_seconds,
                        },
                    );
                }
                profile
                    .reconcile(context, record, credential, now_unix_seconds)
                    .await
            }
            #[cfg(test)]
            Self::Test(profile) => {
                profile
                    .reconcile(context, record, credential, now_unix_seconds)
                    .await
            }
        }
    }
}

#[cfg(feature = "testkit-agent")]
fn operation_context<'a>(
    profile: &'a OperationProfileV1,
    context: &'a LocalOperationContext,
) -> ProfileOperationContext<'a> {
    ProfileOperationContext::new(
        context.workload_id.as_ref(),
        context.principal.as_ref(),
        profile,
        context.authority.proof_bytes(),
        context.authority.trusted_context_bytes(),
        context.authority.artifact_commitment(),
        context.profile_configuration.as_deref(),
        &context.profile_state_root,
    )
}

/// Thin qualification-only gate around the existing journal. All production
/// builds dereference directly to the unchanged persistent journal; the
/// qualification build intercepts only transactions that extend the private
/// store-owned boundary roster.
struct ExecutorJournal {
    inner: Arc<PersistentOperationJournal>,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    gate: Option<Arc<QualificationJournalBoundaryGate>>,
}

impl ExecutorJournal {
    fn new(inner: Arc<PersistentOperationJournal>) -> Self {
        Self {
            inner,
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            gate: None,
        }
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn set_gate(&mut self, gate: Option<Arc<QualificationJournalBoundaryGate>>) {
        self.gate = gate;
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn boundary_count(&self) -> Result<usize, auths_stores::OperationJournalError> {
        self.inner.qualification_boundary_count()
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn checkpoint_after_reservation(&self) -> Result<(), LocalAgentFailure> {
        self.gate
            .as_ref()
            .ok_or(LocalAgentFailure::Internal)?
            .checkpoint_after_reservation()
            .map_err(|()| LocalAgentFailure::Internal)
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn finish_boundary_transaction<T>(
        &self,
        reservation: QualificationBoundaryClaim<'_>,
        before: usize,
        result: Result<T, auths_stores::OperationJournalError>,
    ) -> Result<T, auths_stores::OperationJournalError> {
        let value = result?;
        if self.boundary_count()? > before {
            reservation
                .flush_and_wait()
                .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
        }
        Ok(value)
    }

    fn prepare(
        &self,
        record: JournalRecordV1,
        now_unix_seconds: u64,
    ) -> Result<PrepareJournalResult, auths_stores::OperationJournalError> {
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        {
            let claim = self
                .gate
                .as_ref()
                .ok_or(auths_stores::OperationJournalError::Unavailable)?
                .claim()
                .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
            let result = self.inner.prepare(record, now_unix_seconds);
            if let Ok(PrepareJournalResult::Created(created)) = &result {
                claim
                    .acknowledge_and_wait(created)
                    .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
            } else {
                claim.cancel();
            }
            return result;
        }
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        self.inner.prepare(record, now_unix_seconds)
    }

    fn mutate_operation(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        expected_revision: u64,
        mutation: OperationMutationV1,
        now_unix_seconds: u64,
    ) -> Result<JournalRecordV1, auths_stores::OperationJournalError> {
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        {
            let reservation = self
                .gate
                .as_ref()
                .ok_or(auths_stores::OperationJournalError::Unavailable)?
                .reserve()
                .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
            let before = self.boundary_count()?;
            return self.finish_boundary_transaction(
                reservation,
                before,
                self.inner.mutate_operation(
                    principal,
                    operation_id,
                    expected_revision,
                    mutation,
                    now_unix_seconds,
                ),
            );
        }
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        self.inner.mutate_operation(
            principal,
            operation_id,
            expected_revision,
            mutation,
            now_unix_seconds,
        )
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn record_preparation_replay_for_qualification(
        &self,
        operation_id: &OperationIdV1,
        candidate: &PreparationBindingV1,
    ) -> Result<JournalRecordV1, auths_stores::OperationJournalError> {
        let reservation = self
            .gate
            .as_ref()
            .ok_or(auths_stores::OperationJournalError::Unavailable)?
            .reserve()
            .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
        let before = self.boundary_count()?;
        self.finish_boundary_transaction(
            reservation,
            before,
            self.inner
                .record_preparation_replay_for_qualification(operation_id, candidate),
        )
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn record_status_for_qualification(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        request_id: ClientRequestIdV1,
    ) -> Result<JournalRecordV1, auths_stores::OperationJournalError> {
        let reservation = self
            .gate
            .as_ref()
            .ok_or(auths_stores::OperationJournalError::Unavailable)?
            .reserve()
            .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
        let before = self.boundary_count()?;
        self.finish_boundary_transaction(
            reservation,
            before,
            self.inner
                .record_status_for_qualification(principal, operation_id, request_id),
        )
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    fn record_recovery_for_qualification(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        request_id: ClientRequestIdV1,
        completion: Option<JournalCompletionV1>,
    ) -> Result<JournalRecordV1, auths_stores::OperationJournalError> {
        let reservation = self
            .gate
            .as_ref()
            .ok_or(auths_stores::OperationJournalError::Unavailable)?
            .reserve()
            .map_err(|()| auths_stores::OperationJournalError::Unavailable)?;
        let before = self.boundary_count()?;
        self.finish_boundary_transaction(
            reservation,
            before,
            self.inner.record_recovery_for_qualification(
                principal,
                operation_id,
                request_id,
                completion,
            ),
        )
    }
}

impl Deref for ExecutorJournal {
    type Target = PersistentOperationJournal;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Common journal executor over a build-time static profile roster.
pub(crate) struct JournaledLocalExecutor {
    journal: ExecutorJournal,
    connections: Arc<PersistentConnectionStore>,
    credentials: Arc<PersistentCredentialStore>,
    recovery: Arc<RecoveryHandleSigner>,
    receipts: Arc<ReceiptAttestor>,
    operation_gates: tokio::sync::Mutex<BTreeMap<OperationIdV1, Weak<tokio::sync::Mutex<()>>>>,
    preparation_evidence_gates: tokio::sync::Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
    preparation_evidence_maintenance: tokio::sync::Mutex<()>,
    mode: RuntimeMode,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    credential_broker: Option<QualificationCredentialBrokerPolicy>,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    provider_proxy: Option<QualificationProviderProxyPolicy>,
    #[cfg(test)]
    test_profiles: BTreeMap<(String, u16), Arc<dyn TestStaticLocalProfileBridge>>,
}

impl JournaledLocalExecutor {
    /// Constructs the executor over the build-generated closed profile roster.
    pub(crate) fn new(
        journal: Arc<PersistentOperationJournal>,
        connections: Arc<PersistentConnectionStore>,
        credentials: Arc<PersistentCredentialStore>,
        recovery: Arc<RecoveryHandleSigner>,
        receipts: Arc<ReceiptAttestor>,
    ) -> Result<Self, LocalAgentFailure> {
        if RegisteredProfile::ALL.is_empty() || RegisteredProfile::ALL.len() > 256 {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        Ok(Self {
            journal: ExecutorJournal::new(journal),
            connections,
            credentials,
            recovery,
            receipts,
            operation_gates: tokio::sync::Mutex::new(BTreeMap::new()),
            preparation_evidence_gates: tokio::sync::Mutex::new(BTreeMap::new()),
            preparation_evidence_maintenance: tokio::sync::Mutex::new(()),
            mode: RuntimeMode::Production,
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            credential_broker: None,
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            provider_proxy: None,
            #[cfg(test)]
            test_profiles: BTreeMap::new(),
        })
    }

    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    pub(crate) fn with_qualification_mode(
        mut self,
        gate: Option<Arc<QualificationJournalBoundaryGate>>,
        credential_broker: QualificationCredentialBrokerPolicy,
        provider_proxy: QualificationProviderProxyPolicy,
    ) -> Self {
        self.journal.set_gate(gate);
        self.mode = RuntimeMode::Qualification;
        self.credential_broker = Some(credential_broker);
        self.provider_proxy = Some(provider_proxy);
        self
    }

    /// Constructs the statically linked disposable Stripe testkit executor.
    /// No callback or runtime-loaded provider code is admitted.
    #[cfg(feature = "testkit-agent")]
    pub(crate) fn new_testkit_stripe(
        journal: Arc<PersistentOperationJournal>,
        connections: Arc<PersistentConnectionStore>,
        credentials: Arc<PersistentCredentialStore>,
        recovery: Arc<RecoveryHandleSigner>,
        receipts: Arc<ReceiptAttestor>,
    ) -> Result<Self, LocalAgentFailure> {
        let mut value = Self::new(journal, connections, credentials, recovery, receipts)?;
        value.mode = RuntimeMode::TestkitStripe;
        Ok(value)
    }

    #[cfg(test)]
    fn new_for_tests(
        journal: Arc<PersistentOperationJournal>,
        connections: Arc<PersistentConnectionStore>,
        credentials: Arc<PersistentCredentialStore>,
        recovery: Arc<RecoveryHandleSigner>,
        receipts: Arc<ReceiptAttestor>,
        profiles: impl IntoIterator<Item = Arc<dyn TestStaticLocalProfileBridge>>,
    ) -> Result<Self, LocalAgentFailure> {
        let mut executor = Self::new(journal, connections, credentials, recovery, receipts)?;
        for profile in profiles {
            let identity = profile.profile();
            let key = (identity.id().to_owned(), identity.version());
            if executor.test_profiles.insert(key, profile).is_some() {
                return Err(LocalAgentFailure::InvalidConfiguration);
            }
        }
        if executor.test_profiles.is_empty() {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        Ok(executor)
    }

    fn bridge(&self, profile: &SessionProfileKey) -> Result<ProfileRuntime, LocalAgentFailure> {
        #[cfg(test)]
        if let Some(profile) = self
            .test_profiles
            .get(&(profile.id().to_owned(), profile.version()))
        {
            return Ok(ProfileRuntime::Test(Arc::clone(profile)));
        }
        let flavor = match self.mode {
            RuntimeMode::Production => LaunchFlavor::Production,
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            RuntimeMode::Qualification => LaunchFlavor::Qualification,
            #[cfg(feature = "testkit-agent")]
            RuntimeMode::TestkitStripe => LaunchFlavor::Testkit,
        };
        RegisteredProfile::parse(profile.id(), profile.version(), flavor)
            .map(|profile| ProfileRuntime::BuiltIn {
                profile,
                mode: self.mode,
            })
            .ok_or(LocalAgentFailure::NotFound)
    }

    fn bridge_for_operation_profile(
        &self,
        profile: &OperationProfileV1,
    ) -> Result<ProfileRuntime, LocalAgentFailure> {
        #[cfg(test)]
        if let Some(test_profile) = self
            .test_profiles
            .get(&(profile.id().to_owned(), profile.version()))
        {
            let runtime = ProfileRuntime::Test(Arc::clone(test_profile));
            if runtime.profile()? != *profile {
                return Err(LocalAgentFailure::Internal);
            }
            return Ok(runtime);
        }
        let flavor = match self.mode {
            RuntimeMode::Production => LaunchFlavor::Production,
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            RuntimeMode::Qualification => LaunchFlavor::Qualification,
            #[cfg(feature = "testkit-agent")]
            RuntimeMode::TestkitStripe => LaunchFlavor::Testkit,
        };
        let registered = RegisteredProfile::parse(profile.id(), profile.version(), flavor)
            .ok_or(LocalAgentFailure::NotFound)?;
        let runtime = ProfileRuntime::BuiltIn {
            profile: registered,
            mode: self.mode,
        };
        // A persisted operation is bound to the exact generated runtime
        // contract, not merely a reusable profile name/version.  Refuse to
        // reinterpret or resume old bytes under changed profile code.
        if runtime.profile()? != *profile {
            return Err(LocalAgentFailure::Internal);
        }
        Ok(runtime)
    }

    async fn operation_gate(&self, operation: &OperationIdV1) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.operation_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() != 0);
        if let Some(gate) = gates.get(operation).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(operation.clone(), Arc::downgrade(&gate));
        gate
    }

    async fn preparation_evidence_gate_set(
        &self,
        context: &LocalOperationContext,
        profile: &OperationProfileV1,
        request: &PrepareOperationRequest,
    ) -> Vec<Arc<tokio::sync::Mutex<()>>> {
        let mut identities = Vec::with_capacity(2);
        for (kind, value) in [
            ("request", request.request_id().as_bytes().as_slice()),
            (
                "idempotency",
                request.idempotency_key().unwrap_or("").as_bytes(),
            ),
        ] {
            if kind == "idempotency" && value.is_empty() {
                continue;
            }
            let mut digest = Sha256::new();
            digest.update(b"AUTHS-PREPARATION-EVIDENCE-GATE\0\x01");
            digest.update(kind.as_bytes());
            digest.update((context.principal.len() as u64).to_be_bytes());
            digest.update(context.principal.as_bytes());
            digest.update((profile.id().len() as u64).to_be_bytes());
            digest.update(profile.id().as_bytes());
            digest.update(profile.version().to_be_bytes());
            digest.update(profile.runtime_contract_digest());
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
            identities.push(hex::encode(digest.finalize()));
        }
        identities.sort();
        identities.dedup();
        let mut gates = self.preparation_evidence_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() != 0);
        identities
            .into_iter()
            .map(|identity| {
                if let Some(gate) = gates.get(&identity).and_then(Weak::upgrade) {
                    return gate;
                }
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                gates.insert(identity, Arc::downgrade(&gate));
                gate
            })
            .collect()
    }

    fn resolve_connection(
        &self,
        context: &LocalOperationContext,
        requirement: Option<BridgeConnectionRequirement>,
        requested_alias: Option<&str>,
    ) -> Result<Option<ConnectionBinding>, LocalAgentFailure> {
        let Some(requirement) = requirement else {
            return if requested_alias.is_none() {
                Ok(None)
            } else {
                Err(LocalAgentFailure::NotFound)
            };
        };
        let selected = match requested_alias {
            Some(alias) => context
                .connections
                .iter()
                .find(|item| item.provider() == requirement.provider_kind && item.alias() == alias)
                .map(|item| item.alias()),
            None => {
                let mut defaults = context.connections.iter().filter(|item| {
                    item.provider() == requirement.provider_kind && item.is_default()
                });
                let selected = defaults.next().map(|item| item.alias());
                if defaults.next().is_some() {
                    return Err(LocalAgentFailure::InvalidConfiguration);
                }
                selected
            }
        }
        .ok_or(LocalAgentFailure::NotFound)?;
        let provider = ProviderKind::parse(requirement.provider_kind)
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let alias = ConnectionAlias::parse(selected)
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let profile = ConnectionProfile::new(
            SemanticId::parse(context.profile.id())
                .map_err(|_| LocalAgentFailure::InvalidConfiguration)?,
            context.profile.version(),
        )
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let binding = self
            .connections
            .resolve(&provider, Some(&alias), &context.workload_id, &profile)
            .map_err(|_| LocalAgentFailure::NotFound)?;
        if binding.contract().as_str() != requirement.contract
            || binding.descriptor_schema().as_str() != requirement.descriptor_schema
        {
            return Err(LocalAgentFailure::NotFound);
        }
        Ok(Some(binding))
    }

    async fn lease_connection(
        &self,
        context: &LocalOperationContext,
        operation_id: &OperationIdV1,
        requirement: Option<BridgeConnectionRequirement>,
        recorded: Option<&ConnectionBindingCommitmentsV1>,
    ) -> Result<(Option<ConnectionBinding>, Option<RuntimeCredentialLease>), LocalAgentFailure>
    {
        let Some(requirement) = requirement else {
            return if recorded.is_none() {
                Ok((None, None))
            } else {
                Err(LocalAgentFailure::Internal)
            };
        };
        let recorded = recorded.ok_or(LocalAgentFailure::Internal)?;
        let binding = self
            .resolve_connection(context, Some(requirement), Some(recorded.alias()))?
            .ok_or(LocalAgentFailure::Internal)?;
        if binding.connection_id().as_str() != recorded.connection_id()
            || binding.generation().get() != recorded.generation()
            || binding.descriptor_commitment() != recorded.descriptor_commitment()
            || binding.account_commitment() != recorded.account_commitment()
        {
            return Err(LocalAgentFailure::NotFound);
        }
        let profile = ConnectionProfile::new(
            SemanticId::parse(context.profile.id())
                .map_err(|_| LocalAgentFailure::InvalidConfiguration)?,
            context.profile.version(),
        )
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let record = self
            .connections
            .reread_before_lease(&binding, &context.workload_id, &profile)
            .map_err(|_| LocalAgentFailure::NotFound)?;
        let lease = self
            .lease_validated_record(context, operation_id, requirement, &record, &binding)
            .await?;
        Ok((Some(binding), Some(lease)))
    }

    /// Loads the exact retained generation named by an unresolved operation.
    ///
    /// Unlike ordinary resolution this does not require the current alias to
    /// be active or at the same generation. It does require immutable
    /// connection identity, descriptor, and account commitments to match the
    /// operation. If an emergency revocation removed the retained credential,
    /// callers preserve `possible` and return an operator-actionable recovery
    /// result instead of claiming non-effect.
    async fn lease_connection_for_recovery(
        &self,
        context: &LocalOperationContext,
        operation_id: &OperationIdV1,
        requirement: Option<BridgeConnectionRequirement>,
        recorded: Option<&ConnectionBindingCommitmentsV1>,
    ) -> Result<(Option<ConnectionBinding>, Option<RuntimeCredentialLease>), LocalAgentFailure>
    {
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        let _ = (context, operation_id);
        let Some(requirement) = requirement else {
            return if recorded.is_none() {
                Ok((None, None))
            } else {
                Err(LocalAgentFailure::Internal)
            };
        };
        let recorded = recorded.ok_or(LocalAgentFailure::Internal)?;
        let provider = ProviderKind::parse(requirement.provider_kind)
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let alias =
            ConnectionAlias::parse(recorded.alias()).map_err(|_| LocalAgentFailure::Internal)?;
        let current = self
            .connections
            .load(&provider, &alias)
            .map_err(|_| LocalAgentFailure::NotFound)?
            .ok_or(LocalAgentFailure::NotFound)?;
        if current.connection_id().as_str() != recorded.connection_id()
            || current.contract().as_str() != requirement.contract
            || current.descriptor_schema().as_str() != requirement.descriptor_schema
            || current.descriptor_commitment() != recorded.descriptor_commitment()
            || current.account_commitment() != recorded.account_commitment()
        {
            return Err(LocalAgentFailure::NotFound);
        }
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        if self.mode == RuntimeMode::Qualification {
            let policy = self
                .credential_broker
                .clone()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let request = QualificationCredentialLeaseRequest::new(
                *policy.source_context_sha256(),
                operation_id.as_str(),
                context.workload_id.as_ref(),
                context.profile.id(),
                context.profile.version(),
                requirement.provider_kind,
                recorded.alias(),
                recorded.connection_id(),
                recorded.generation(),
                *recorded.descriptor_commitment(),
                *recorded.account_commitment(),
                requirement.contract,
                requirement.descriptor_schema,
                requirement.credential_scope,
            )
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
            let lease = lease_from_qualification_credential_broker(policy, request).await?;
            return Ok((None, Some(lease)));
        }
        let generation =
            std::num::NonZeroU64::new(recorded.generation()).ok_or(LocalAgentFailure::Internal)?;
        let credential_commitment = self
            .credentials
            .retained_commitment(current.connection_id(), generation)
            .map_err(|_| LocalAgentFailure::NotFound)?;
        let binding = current
            .binding_for_recovery(generation, credential_commitment)
            .map_err(|_| LocalAgentFailure::NotFound)?;
        let lease = self
            .lease_validated_record(context, operation_id, requirement, &current, &binding)
            .await?;
        Ok((Some(binding), Some(lease)))
    }

    async fn lease_validated_record(
        &self,
        context: &LocalOperationContext,
        operation_id: &OperationIdV1,
        requirement: BridgeConnectionRequirement,
        record: &ConnectionRecord,
        binding: &ConnectionBinding,
    ) -> Result<RuntimeCredentialLease, LocalAgentFailure> {
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        let _ = (context, operation_id);
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        if self.mode == RuntimeMode::Qualification {
            let policy = self
                .credential_broker
                .clone()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let request = QualificationCredentialLeaseRequest::new(
                *policy.source_context_sha256(),
                operation_id.as_str(),
                context.workload_id.as_ref(),
                context.profile.id(),
                context.profile.version(),
                requirement.provider_kind,
                binding.alias().as_str(),
                binding.connection_id().as_str(),
                binding.generation().get(),
                *binding.descriptor_commitment(),
                *binding.account_commitment(),
                requirement.contract,
                requirement.descriptor_schema,
                requirement.credential_scope,
            )
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
            return lease_from_qualification_credential_broker(policy, request).await;
        }
        let scope = CredentialScope::parse(requirement.credential_scope)
            .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let provider = RegisteredProvider::parse(requirement.provider_kind)
            .ok_or(LocalAgentFailure::InvalidConfiguration)?;
        provider
            .lease_credential(
                record.descriptor(),
                binding,
                &scope,
                self.credentials.as_ref(),
                deadline,
            )
            .await
            .map(RuntimeCredentialLease::local)
            .map_err(|_| LocalAgentFailure::NotFound)
    }

    /// Advances a provider call from either the ordinary ready checkpoint or
    /// an interrupted, durably proven pre-entry checkpoint.
    ///
    /// The latter path is recovery, not blind retry: `MarkProviderEntered` is
    /// durably ordered before the only provider call, so an
    /// `executing/not-applied` record proves that no prior call began.
    async fn advance_provider_call(
        &self,
        context: &LocalOperationContext,
        bridge: &ProfileRuntime,
        record: JournalRecordV1,
        recovering_pre_entry: bool,
        now: u64,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        let operation_id = record.operation_id().clone();
        let sealed_command = record
            .sealed_command()
            .ok_or(LocalAgentFailure::Internal)?
            .to_vec();
        let mut executing = if recovering_pre_entry {
            record
        } else {
            match self.journal.mutate_operation(
                &context.principal,
                &operation_id,
                record.revision(),
                OperationMutationV1::BeginExecution {
                    profile_state: record.profile_state().to_vec(),
                    sealed_command,
                },
                now,
            ) {
                Ok(value) => value,
                Err(auths_stores::OperationJournalError::Conflict) => {
                    let current = self.status_record(&context.principal, &operation_id)?;
                    if current.projection().state() != OperationStateV1::Executing
                        && current.projection().effect() == OperationEffectV1::NotApplied
                    {
                        // Sealing may already have created a domain
                        // reservation/claim. If this BeginExecution CAS loses
                        // to a non-executing terminal/recovery transition,
                        // release by operation ID so the unpersisted command
                        // cannot orphan that capability.
                        bridge
                            .release_pre_entry(context, &record)
                            .map_err(|_| LocalAgentFailure::Internal)?;
                    }
                    return Ok(current);
                }
                Err(error) => return Err(map_journal(error)),
            }
        };
        if !executing.pre_entry_rechecked() {
            let rechecked = match bridge.recheck_pre_entry(context, &executing, now) {
                Ok(value) if !value.profile_state.is_empty() => value,
                Ok(_)
                | Err(
                    ProfileBridgeError::Invalid
                    | ProfileBridgeError::Possible(_)
                    | ProfileBridgeError::PossibleWithProfileState { .. },
                ) => {
                    return Err(LocalAgentFailure::Internal);
                }
                Err(ProfileBridgeError::PreEntryPending) => return Ok(executing),
                Err(ProfileBridgeError::PreEntry(issue)) => {
                    bridge
                        .release_pre_entry(context, &executing)
                        .map_err(|_| LocalAgentFailure::Internal)?;
                    return self
                        .journal
                        .mutate_operation(
                            &context.principal,
                            &operation_id,
                            executing.revision(),
                            OperationMutationV1::ConcludePreEntry {
                                state: OperationStateV1::NotApplied,
                                issue,
                                profile_state: executing.profile_state().to_vec(),
                            },
                            unix_seconds()?,
                        )
                        .map_err(map_journal);
                }
            };
            let rechecked_at = unix_seconds()?;
            executing = self
                .journal
                .mutate_operation(
                    &context.principal,
                    &operation_id,
                    executing.revision(),
                    OperationMutationV1::RecordPreEntryRecheck {
                        profile_state: rechecked.profile_state,
                    },
                    rechecked_at,
                )
                .map_err(map_journal)?;
        }
        let call = SealedProfileCall {
            command: executing
                .sealed_command()
                .ok_or(LocalAgentFailure::Internal)?
                .to_vec(),
            profile_state: executing.profile_state().to_vec(),
        };
        if bridge.revalidate_configuration(context).is_err() {
            bridge
                .release_pre_entry(context, &executing)
                .map_err(|_| LocalAgentFailure::Internal)?;
            return self
                .journal
                .mutate_operation(
                    &context.principal,
                    &operation_id,
                    executing.revision(),
                    OperationMutationV1::ConcludePreEntry {
                        state: OperationStateV1::Unavailable,
                        issue: common_issue(
                            CommonIssue::InvalidConfiguration,
                            Some(&operation_id),
                        )?,
                        profile_state: executing.profile_state().to_vec(),
                    },
                    unix_seconds()?,
                )
                .map_err(map_journal);
        }
        let lease = if recovering_pre_entry {
            self.lease_connection_for_recovery(
                context,
                &operation_id,
                bridge.connection_requirement(),
                executing.binding().connection(),
            )
            .await
        } else {
            self.lease_connection(
                context,
                &operation_id,
                bridge.connection_requirement(),
                executing.binding().connection(),
            )
            .await
        };
        let (_binding, credential) = match lease {
            Ok(value) => value,
            Err(_) => {
                bridge
                    .release_pre_entry(context, &executing)
                    .map_err(|_| LocalAgentFailure::Internal)?;
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        executing.revision(),
                        OperationMutationV1::ConcludePreEntry {
                            state: OperationStateV1::Unavailable,
                            issue: common_issue(
                                CommonIssue::CredentialUnavailable,
                                Some(&operation_id),
                            )?,
                            profile_state: executing.profile_state().to_vec(),
                        },
                        unix_seconds()?,
                    )
                    .map_err(map_journal);
            }
        };
        let entered_at = unix_seconds()?;
        let entered = self
            .journal
            .mutate_operation(
                &context.principal,
                &operation_id,
                executing.revision(),
                OperationMutationV1::MarkProviderEntered,
                entered_at,
            )
            .map_err(map_journal)?;
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        let provider_result = if self.mode == RuntimeMode::Qualification {
            let policy = self
                .provider_proxy
                .as_ref()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let credential = credential
                .as_ref()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let request = qualification_provider_call_request(
                policy,
                &entered,
                QualificationProviderCallKind::Execute,
                credential,
                &call.command,
                &call.profile_state,
                context.profile_configuration.as_deref(),
                entered_at,
            )?;
            let result = call_qualification_provider_proxy(policy, request)
                .await
                .and_then(|response| response.into_runtime(&operation_id));
            bridge.finalize_qualification_provider_result(context, &call, None, entered_at, result)
        } else {
            bridge
                .call_provider(
                    context,
                    &call,
                    credential
                        .as_ref()
                        .and_then(RuntimeCredentialLease::credential),
                    entered_at,
                )
                .await
        };
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        let provider_result = bridge
            .call_provider(
                context,
                &call,
                credential
                    .as_ref()
                    .and_then(RuntimeCredentialLease::credential),
                entered_at,
            )
            .await;
        if let Some(credential) = credential {
            if provider_result
                .as_ref()
                .is_ok_and(|value| !value.is_empty())
            {
                credential.close().await?;
            } else {
                drop(credential);
            }
        }
        let observed_at = unix_seconds()?;
        let provider_result = match provider_result {
            Ok(value) if !value.is_empty() => value,
            Ok(_) | Err(ProfileBridgeError::Invalid | ProfileBridgeError::PreEntryPending) => {
                let issue = common_issue(CommonIssue::OutcomeUnknown, Some(&operation_id))?;
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &entered,
                    ExecutionOutcome::Indeterminate,
                    None,
                    ReceiptIntegrityTruth::recovery(
                        issue.clone(),
                        None,
                        call.profile_state.clone(),
                    ),
                    observed_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        receipt_record.revision(),
                        OperationMutationV1::RequireRecovery {
                            issue,
                            progress: None,
                            profile_state: call.profile_state,
                        },
                        observed_at,
                    )
                    .map_err(map_journal);
            }
            Err(ProfileBridgeError::Possible(issue)) => {
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &entered,
                    ExecutionOutcome::Indeterminate,
                    None,
                    ReceiptIntegrityTruth::recovery(
                        issue.clone(),
                        None,
                        call.profile_state.clone(),
                    ),
                    observed_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        receipt_record.revision(),
                        OperationMutationV1::RequireRecovery {
                            issue,
                            progress: None,
                            profile_state: call.profile_state,
                        },
                        observed_at,
                    )
                    .map_err(map_journal);
            }
            Err(ProfileBridgeError::PossibleWithProfileState {
                issue,
                profile_state,
            }) if !profile_state.is_empty() => {
                let uncertain = self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        entered.revision(),
                        OperationMutationV1::RecordProviderUncertaintyState {
                            profile_state: profile_state.clone(),
                        },
                        observed_at,
                    )
                    .map_err(map_journal)?;
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &uncertain,
                    ExecutionOutcome::Indeterminate,
                    None,
                    ReceiptIntegrityTruth::recovery(issue.clone(), None, profile_state.clone()),
                    observed_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        receipt_record.revision(),
                        OperationMutationV1::RequireRecovery {
                            issue,
                            progress: None,
                            profile_state,
                        },
                        observed_at,
                    )
                    .map_err(map_journal);
            }
            Err(ProfileBridgeError::PossibleWithProfileState { .. }) => {
                return Err(LocalAgentFailure::Internal);
            }
            Err(ProfileBridgeError::PreEntry(_)) => {
                // Once provider entry is durable, even a provider adapter that
                // labels its own failure "pre-entry" cannot strengthen the
                // effect claim. Preserve possible effect for recovery.
                let issue = common_issue(CommonIssue::OutcomeUnknown, Some(&operation_id))?;
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &entered,
                    ExecutionOutcome::Indeterminate,
                    None,
                    ReceiptIntegrityTruth::recovery(
                        issue.clone(),
                        None,
                        call.profile_state.clone(),
                    ),
                    observed_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        receipt_record.revision(),
                        OperationMutationV1::RequireRecovery {
                            issue,
                            progress: None,
                            profile_state: call.profile_state,
                        },
                        observed_at,
                    )
                    .map_err(map_journal);
            }
        };
        let durable_result = self
            .journal
            .mutate_operation(
                &context.principal,
                &operation_id,
                entered.revision(),
                OperationMutationV1::RecordProviderResult {
                    bytes: provider_result.clone(),
                },
                observed_at,
            )
            .map_err(map_journal)?;
        self.observe_durable_provider_result(
            context,
            bridge,
            durable_result,
            provider_result,
            false,
            observed_at,
        )
        .await
    }

    async fn observe_durable_provider_result(
        &self,
        context: &LocalOperationContext,
        bridge: &ProfileRuntime,
        record: JournalRecordV1,
        provider_result: Vec<u8>,
        reconciled: bool,
        now: u64,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        let operation_id = record.operation_id().clone();
        let observation =
            match bridge.observe_provider_result(context, &record, &provider_result, now) {
                Ok(value) => value,
                Err(ProfileBridgeError::Possible(issue)) => ProfileObservation {
                    bytes: provider_result,
                    conclusion: ProfileConclusion::RecoveryRequired {
                        issue,
                        progress: None,
                        profile_state: record.profile_state().to_vec(),
                    },
                },
                Err(
                    ProfileBridgeError::PreEntry(_)
                    | ProfileBridgeError::PreEntryPending
                    | ProfileBridgeError::PossibleWithProfileState { .. }
                    | ProfileBridgeError::Invalid,
                ) => ProfileObservation {
                    bytes: provider_result,
                    conclusion: ProfileConclusion::RecoveryRequired {
                        issue: common_issue(CommonIssue::OutcomeUnknown, Some(&operation_id))?,
                        progress: None,
                        profile_state: record.profile_state().to_vec(),
                    },
                },
            };
        self.apply_observation(context, record, observation, reconciled)
            .await
    }

    fn profile_from_context(
        context: &LocalOperationContext,
        runtime_digest: [u8; 32],
    ) -> Result<OperationProfileV1, LocalAgentFailure> {
        OperationProfileV1::new(
            context.profile.id(),
            context.profile.version(),
            runtime_digest,
        )
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)
    }

    fn status_record(
        &self,
        principal: &str,
        operation: &OperationIdV1,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        match self
            .journal
            .status(principal, operation)
            .map_err(map_journal)?
        {
            Some(JournalStatusV1::Record(record)) => Ok(record),
            Some(JournalStatusV1::Tombstone(_)) | None => Err(LocalAgentFailure::NotFound),
        }
    }

    fn encode_preparation_replay(
        &self,
        record: &JournalRecordV1,
        request_id: ClientRequestId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        #[cfg(feature = "qualification-failpoints")]
        let record = self
            .journal
            .record_preparation_replay_for_qualification(
                record.operation_id(),
                &PreparationBindingV1::new(
                    record.binding().principal(),
                    record.binding().profile().clone(),
                    ClientRequestIdV1::from_bytes(*request_id.as_bytes()),
                    record.binding().idempotency_commitment().copied(),
                    *record.binding().canonical_input_commitment(),
                    record.binding().preparation_evidence_commitment().copied(),
                    record
                        .binding()
                        .preparation_evidence_intent_commitment()
                        .copied(),
                    record.binding().connection().cloned(),
                    *record.binding().canonical_action_commitment(),
                    *record.binding().authority_commitment(),
                    *record.binding().configuration_commitment(),
                )
                .map_err(|_| LocalAgentFailure::Internal)?,
            )
            .map_err(map_journal)?;
        #[cfg(feature = "qualification-failpoints")]
        let record = &record;
        self.encode_record_for_request(
            record,
            record
                .projection()
                .is_terminal()
                .then_some(LocalOperationCompletion::Replayed),
            Some(request_id),
        )
    }

    fn encode_record(
        &self,
        record: &JournalRecordV1,
        completion_override: Option<LocalOperationCompletion>,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        self.encode_record_for_request(record, completion_override, None)
    }

    fn encode_conflict_for_record(
        &self,
        original: &JournalRecordV1,
        request_id: ClientRequestId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        if original.receipt_integrity_failed() || self.verify_receipts_for_record(original).is_err()
        {
            return Self::encode_receipt_integrity_failure(original, Some(request_id));
        }
        encode_local_operation_outcome(&LocalOperationOutcome::Conflict {
            request_id,
            operation_id: protocol_operation_id(original.operation_id())?,
            issue: common_issue(
                CommonIssue::IdempotencyConflict,
                Some(original.operation_id()),
            )?,
            recovery_handle: original.recovery_handle().to_vec(),
            receipts: receipt_bytes(original),
            connection_alias: connection_alias(original),
        })
        .map_err(|_| LocalAgentFailure::Internal)
    }

    fn encode_record_for_request(
        &self,
        record: &JournalRecordV1,
        completion_override: Option<LocalOperationCompletion>,
        request_id: Option<ClientRequestId>,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        if record.receipt_integrity_failed() || self.verify_receipts_for_record(record).is_err() {
            return Self::encode_receipt_integrity_failure(record, request_id);
        }
        encode_local_operation_outcome(&outcome_from_record(
            record,
            completion_override,
            request_id,
        )?)
        .map_err(|_| LocalAgentFailure::Internal)
    }

    fn encode_status_projection(
        &self,
        principal: &str,
        record: &JournalRecordV1,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        #[cfg(not(feature = "qualification-failpoints"))]
        let _ = principal;
        let bytes = self.encode_record(record, None)?;
        #[cfg(feature = "qualification-failpoints")]
        self.journal
            .record_status_for_qualification(
                principal,
                record.operation_id(),
                record.binding().request_id(),
            )
            .map_err(map_journal)?;
        Ok(bytes)
    }

    fn encode_recovery_projection(
        &self,
        principal: &str,
        record: &JournalRecordV1,
        completion_override: Option<LocalOperationCompletion>,
        request_id: ClientRequestId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        #[cfg(not(feature = "qualification-failpoints"))]
        let _ = principal;
        let bytes =
            self.encode_record_for_request(record, completion_override, Some(request_id))?;
        #[cfg(feature = "qualification-failpoints")]
        self.journal
            .record_recovery_for_qualification(
                principal,
                record.operation_id(),
                ClientRequestIdV1::from_bytes(*request_id.as_bytes()),
                completion_override.map(|completion| match completion {
                    LocalOperationCompletion::Fresh => JournalCompletionV1::Fresh,
                    LocalOperationCompletion::Replayed => JournalCompletionV1::Replayed,
                    LocalOperationCompletion::Reconciled => JournalCompletionV1::Reconciled,
                }),
            )
            .map_err(map_journal)?;
        Ok(bytes)
    }

    fn encode_receipt_integrity_failure(
        record: &JournalRecordV1,
        request_id: Option<ClientRequestId>,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let request_id = request_id.unwrap_or_else(|| {
            ClientRequestId::from_bytes(*record.binding().request_id().as_bytes())
        });
        encode_local_operation_outcome(&LocalOperationOutcome::ReceiptIntegrityFailed {
            request_id,
            operation_id: protocol_operation_id(record.operation_id())?,
            issue: terminal_receipt_integrity_issue(record)?,
            state: state_text(record.projection().state()).to_owned(),
            effect: effect_text(record.projection().effect()).to_owned(),
            terminal: record.projection().is_terminal(),
            connection_alias: connection_alias(record),
        })
        .map_err(|_| LocalAgentFailure::Internal)
    }

    async fn apply_observation(
        &self,
        context: &LocalOperationContext,
        record: JournalRecordV1,
        observation: ProfileObservation,
        reconciled: bool,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        // A crash may occur after the observation is durable but before the
        // terminal conclusion. Re-observing the already durable provider
        // result must finish that same transition without appending a second
        // observation or calling the provider again.
        let observed = if record
            .observations()
            .last()
            .is_some_and(|bytes| bytes.as_slice() == observation.bytes.as_slice())
        {
            record
        } else {
            self.journal
                .mutate_operation(
                    &context.principal,
                    record.operation_id(),
                    record.revision(),
                    OperationMutationV1::RecordObservation {
                        bytes: observation.bytes,
                    },
                    unix_seconds()?,
                )
                .map_err(map_journal)?
        };
        let receipt_at = unix_seconds()?;
        let (receipt_record, mutation) = match observation.conclusion {
            ProfileConclusion::Completed {
                value,
                profile_state,
            } => {
                let completion = if reconciled {
                    JournalCompletionV1::Reconciled
                } else {
                    JournalCompletionV1::Fresh
                };
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &observed,
                    ExecutionOutcome::Succeeded,
                    Some(&value),
                    ReceiptIntegrityTruth::terminal(
                        OperationStateV1::Completed,
                        None,
                        Some(value.clone()),
                        completion,
                        profile_state.clone(),
                    ),
                    receipt_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                (
                    receipt_record,
                    OperationMutationV1::Conclude {
                        state: OperationStateV1::Completed,
                        issue: None,
                        value: Some(value),
                        completion,
                        profile_state,
                    },
                )
            }
            ProfileConclusion::Partial {
                value,
                issue,
                profile_state,
            } => {
                let completion = if reconciled {
                    JournalCompletionV1::Reconciled
                } else {
                    JournalCompletionV1::Fresh
                };
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &observed,
                    ExecutionOutcome::Succeeded,
                    Some(&value),
                    ReceiptIntegrityTruth::terminal(
                        OperationStateV1::Partial,
                        Some(issue.clone()),
                        Some(value.clone()),
                        completion,
                        profile_state.clone(),
                    ),
                    receipt_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                (
                    receipt_record,
                    OperationMutationV1::Conclude {
                        state: OperationStateV1::Partial,
                        issue: Some(issue),
                        value: Some(value),
                        completion,
                        profile_state,
                    },
                )
            }
            ProfileConclusion::NotApplied {
                issue,
                profile_state,
            } => {
                let completion = if reconciled {
                    JournalCompletionV1::Reconciled
                } else {
                    JournalCompletionV1::Fresh
                };
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &observed,
                    ExecutionOutcome::Failed,
                    observed.provider_result(),
                    ReceiptIntegrityTruth::terminal(
                        OperationStateV1::NotApplied,
                        Some(issue.clone()),
                        None,
                        completion,
                        profile_state.clone(),
                    ),
                    receipt_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                (
                    receipt_record,
                    OperationMutationV1::Conclude {
                        state: OperationStateV1::NotApplied,
                        issue: Some(issue),
                        value: None,
                        completion,
                        profile_state,
                    },
                )
            }
            ProfileConclusion::RecoveryRequired {
                issue,
                progress,
                profile_state,
            } => {
                let receipt_record = self.persist_execution_receipt_or_quarantine(
                    &context.principal,
                    &observed,
                    ExecutionOutcome::Indeterminate,
                    observed.provider_result(),
                    ReceiptIntegrityTruth::recovery(
                        issue.clone(),
                        progress.clone(),
                        profile_state.clone(),
                    ),
                    receipt_at,
                )?;
                if receipt_record.receipt_integrity_failed() {
                    return Ok(receipt_record);
                }
                (
                    receipt_record,
                    OperationMutationV1::RequireRecovery {
                        issue,
                        progress,
                        profile_state,
                    },
                )
            }
        };
        self.journal
            .mutate_operation(
                &context.principal,
                receipt_record.operation_id(),
                receipt_record.revision(),
                mutation,
                unix_seconds()?,
            )
            .map_err(map_journal)
    }

    fn persist_execution_receipt_or_quarantine(
        &self,
        principal: &str,
        record: &JournalRecordV1,
        outcome: ExecutionOutcome,
        result: Option<&[u8]>,
        truth: ReceiptIntegrityTruth,
        now: u64,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        match self.persist_execution_receipt(principal, record, outcome, result, now) {
            Ok(record) => Ok(record),
            Err(_) if record.provider_entered() && !record.receipt_integrity_failed() => self
                .journal
                .mutate_operation(
                    principal,
                    record.operation_id(),
                    record.revision(),
                    OperationMutationV1::QuarantineReceiptIntegrity {
                        state: truth.state,
                        issue: truth.issue,
                        value: truth.value,
                        progress: truth.progress,
                        completion: truth.completion,
                        profile_state: truth.profile_state,
                    },
                    now,
                )
                .map_err(map_journal),
            Err(error) => Err(error),
        }
    }

    fn persist_execution_receipt(
        &self,
        principal: &str,
        record: &JournalRecordV1,
        outcome: ExecutionOutcome,
        result: Option<&[u8]>,
        now: u64,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        let journal_outcome = match outcome {
            ExecutionOutcome::Succeeded => JournalExecutionOutcomeV1::Succeeded,
            ExecutionOutcome::Failed => JournalExecutionOutcomeV1::Failed,
            ExecutionOutcome::Indeterminate => JournalExecutionOutcomeV1::Indeterminate,
        };
        let result_commitment = result.map(|bytes| Sha256::digest(bytes).into());
        if let Some(existing) = record.execution_outcome() {
            // A linked indeterminate receipt is immutable evidence of the
            // original response-loss boundary.  Reconciliation may later
            // prove the terminal effect, but it must reuse that exact receipt
            // rather than replacing it with a newly signed success/failure.
            if existing == JournalExecutionOutcomeV1::Indeterminate
                && record.projection().state() == OperationStateV1::RecoveryRequired
            {
                return Ok(record.clone());
            }
            return if existing == journal_outcome
                && record.receipts().len() == 2
                && record.execution_result_commitment().copied() == result_commitment
            {
                Ok(record.clone())
            } else {
                Err(LocalAgentFailure::Internal)
            };
        }
        let decision = record
            .receipts()
            .first()
            .ok_or(LocalAgentFailure::Internal)?;
        let command = record.sealed_command().ok_or(LocalAgentFailure::Internal)?;
        let bridge = self.bridge_for_operation_profile(record.binding().profile())?;
        let execution_profile_claims = bridge
            .build_execution_receipt_claims(
                ProfileExecutionReceiptFacts::at_mint(record).ok_or(LocalAgentFailure::Internal)?,
            )
            .map_err(|_error| LocalAgentFailure::Internal)?;
        let execution = self
            .receipts
            .execution(
                decision,
                record.operation_id(),
                command,
                outcome,
                result,
                now,
                &execution_profile_claims,
            )
            .map_err(|_| LocalAgentFailure::Internal)?;
        self.journal
            .mutate_operation(
                principal,
                record.operation_id(),
                record.revision(),
                OperationMutationV1::RecordExecutionReceipt {
                    receipt: execution,
                    outcome: journal_outcome,
                    result_commitment,
                },
                now,
            )
            .map_err(map_journal)
    }

    fn verify_receipts_for_record(
        &self,
        record: &JournalRecordV1,
    ) -> Result<(), LocalAgentFailure> {
        let bridge = self.bridge_for_operation_profile(record.binding().profile())?;
        let decision_claims = bridge
            .build_decision_receipt_claims(ProfileDecisionReceiptFacts::from_record(record))
            .map_err(|_| LocalAgentFailure::Internal)?;
        let execution_claims = match record.execution_outcome() {
            Some(_) => Some(
                bridge
                    .build_execution_receipt_claims(
                        ProfileExecutionReceiptFacts::from_record(record)
                            .ok_or(LocalAgentFailure::Internal)?,
                    )
                    .map_err(|_| LocalAgentFailure::Internal)?,
            ),
            None => None,
        };
        let (actual_decision, actual_execution) = self
            .receipts
            .verify_for_record(record, &decision_claims, execution_claims.as_deref())
            .map_err(|_| LocalAgentFailure::Internal)?;
        let facts = auths_profile_runtime::ProfileReceiptInspectionFactsV1::from_record(record);
        bridge
            .inspect_receipt_claims(ProfileReceiptInspection {
                facts: &facts,
                decision_claims: &actual_decision,
                execution_claims: actual_execution.as_deref(),
            })
            .map_err(|_| LocalAgentFailure::Internal)
    }
}

impl JournaledLocalExecutor {
    pub(crate) async fn preparation_evidence(
        &self,
        context: LocalOperationContext,
        request: PreparationEvidenceRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let request = request.preparation();
        let bridge = self.bridge(&context.profile)?;
        let profile = bridge.profile()?;
        if bridge.preparation_evidence_kind() != Some("protected-lease")
            || request.runtime_contract_digest() != profile.runtime_contract_digest()
            || request.preparation_evidence_handle().is_some()
        {
            return Err(LocalAgentFailure::NotFound);
        }
        let gates = self
            .preparation_evidence_gate_set(&context, &profile, request)
            .await;
        let mut gate_guards = Vec::with_capacity(gates.len());
        for gate in gates {
            gate_guards.push(gate.lock_owned().await);
        }
        let authorized_at = unix_seconds()?;
        let identity = self
            .journal
            .preparation_identity(
                &context.principal,
                &profile,
                ClientRequestIdV1::from_bytes(*request.request_id().as_bytes()),
                request.idempotency_key().map(local_idempotency_commitment),
                authorized_at,
            )
            .map_err(map_journal)?;
        let idempotency_replay = match identity {
            PreparationIdentityLookup::Absent => None,
            PreparationIdentityLookup::Existing(JournalStatusV1::Record(record)) => {
                if record.binding().request_id()
                    == ClientRequestIdV1::from_bytes(*request.request_id().as_bytes())
                {
                    let operation_id = record.operation_id().clone();
                    let inner = match self
                        .gated_prepared_record(
                            &context,
                            &bridge,
                            &operation_id,
                            authorized_at,
                            Some(request),
                        )
                        .await?
                    {
                        GatedPreparationRecord::Record(current) => {
                            self.encode_preparation_replay(&current, request.request_id())?
                        }
                        GatedPreparationRecord::ReceiptIntegrityFailed(current) => {
                            Self::encode_receipt_integrity_failure(
                                &current,
                                Some(request.request_id()),
                            )?
                        }
                        GatedPreparationRecord::IntentConflict(current) => {
                            self.encode_conflict_for_record(&current, request.request_id())?
                        }
                    };
                    return encode_preparation_evidence_outcome(request.request_id(), &inner)
                        .map_err(|_| LocalAgentFailure::Internal);
                }
                Some(record)
            }
            PreparationIdentityLookup::Existing(JournalStatusV1::Tombstone(_)) => {
                return Err(LocalAgentFailure::Internal);
            }
            PreparationIdentityLookup::Conflict {
                original_operation_id,
            } => {
                let original = self.status_record(&context.principal, &original_operation_id)?;
                let inner = self.encode_conflict_for_record(&original, request.request_id())?;
                return encode_preparation_evidence_outcome(request.request_id(), &inner)
                    .map_err(|_| LocalAgentFailure::Internal);
            }
        };
        // Mutable connection state and deployment authorization are consulted
        // only for a genuinely new admission. A retained operation remains
        // replayable after its original connection is disabled or rotated.
        let connection = match self.resolve_connection(
            &context,
            bridge.connection_requirement(),
            request.connection_alias(),
        ) {
            Ok(value) => value,
            Err(error) => {
                if let Some(original) = idempotency_replay.as_ref() {
                    let inner = self.encode_conflict_for_record(original, request.request_id())?;
                    return encode_preparation_evidence_outcome(request.request_id(), &inner)
                        .map_err(|_| LocalAgentFailure::Internal);
                }
                return Err(error);
            }
        };
        let connection = connection.as_ref().ok_or(LocalAgentFailure::NotFound)?;
        let configuration_sha256 = context.profile_configuration.as_deref().map_or(
            [0; 32],
            auths_profile_runtime::ProfileConfigurationBinding::sha256,
        );
        let workflow_id = workflow_identity(&context, &profile, request);
        let authority_sha256 = match bridge.authorize_preparation_evidence(
            &context,
            &workflow_id,
            request.profile_input(),
            Some(connection),
            authorized_at,
        ) {
            Ok(value) => value,
            Err(_) => {
                if let Some(original) = idempotency_replay.as_ref() {
                    let inner = self.encode_conflict_for_record(original, request.request_id())?;
                    return encode_preparation_evidence_outcome(request.request_id(), &inner)
                        .map_err(|_| LocalAgentFailure::Internal);
                }
                return Err(LocalAgentFailure::NotFound);
            }
        };
        let binding = LeaseBinding {
            principal: &context.principal,
            profile: &profile,
            workflow_id: &workflow_id,
            request,
            connection,
            configuration_sha256,
            authority_sha256,
            authority_artifact_sha256: context.authority.artifact_commitment(),
        };
        let intent_sha256 = preparation_evidence_intent_commitment(&binding);
        if let Some(original) = idempotency_replay {
            let inner = if original.binding().preparation_evidence_intent_commitment()
                == Some(&intent_sha256)
                && preparation_request_matches_binding(&context, request, original.binding())
            {
                match self
                    .gated_prepared_record(
                        &context,
                        &bridge,
                        original.operation_id(),
                        authorized_at,
                        Some(request),
                    )
                    .await?
                {
                    GatedPreparationRecord::Record(current) => {
                        self.encode_preparation_replay(&current, request.request_id())?
                    }
                    GatedPreparationRecord::ReceiptIntegrityFailed(current) => {
                        Self::encode_receipt_integrity_failure(
                            &current,
                            Some(request.request_id()),
                        )?
                    }
                    GatedPreparationRecord::IntentConflict(current) => {
                        self.encode_conflict_for_record(&current, request.request_id())?
                    }
                }
            } else {
                self.encode_conflict_for_record(&original, request.request_id())?
            };
            return encode_preparation_evidence_outcome(request.request_id(), &inner)
                .map_err(|_| LocalAgentFailure::Internal);
        }
        let (store, existing) = {
            let _maintenance = self.preparation_evidence_maintenance.lock().await;
            let store = PreparationEvidenceLeaseStore::open(&context.profile_state_root)
                .map_err(|()| LocalAgentFailure::Internal)?;
            let existing = store
                .lookup(&binding, authorized_at)
                .map_err(|()| LocalAgentFailure::Internal)?;
            (store, existing)
        };
        if let Some(existing) = existing {
            return encode_preparation_evidence_lease(&existing)
                .map_err(|_| LocalAgentFailure::Internal);
        }
        let acquired = bridge
            .acquire_preparation_evidence(
                &context,
                &workflow_id,
                request.profile_input(),
                Some(connection),
                authority_sha256,
                authorized_at,
            )
            .map_err(|_| LocalAgentFailure::NotFound)?;
        if acquired.authority_action_commitment != authority_sha256 {
            return Err(LocalAgentFailure::Internal);
        }
        let accepted_at = unix_seconds()?;
        let lease = {
            let _maintenance = self.preparation_evidence_maintenance.lock().await;
            store.issue(&binding, &acquired.bytes, accepted_at)
        }
        .map_err(|()| LocalAgentFailure::Internal)?;
        encode_preparation_evidence_lease(&lease).map_err(|_| LocalAgentFailure::Internal)
    }

    pub(crate) async fn prepare(
        &self,
        context: LocalOperationContext,
        request: PrepareOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let mut now = unix_seconds()?;
        let bridge = self.bridge(&context.profile)?;
        let bridge_profile = bridge.profile()?;
        if request.runtime_contract_digest() != bridge_profile.runtime_contract_digest() {
            return Err(LocalAgentFailure::NotFound);
        }
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        if context.qualification_fault == Some(QualificationAdmissionFaultV1::ConfigurationMismatch)
            && context.profile_configuration.is_none()
        {
            return Err(LocalAgentFailure::InvalidConfiguration);
        }
        let gates = self
            .preparation_evidence_gate_set(&context, &bridge_profile, &request)
            .await;
        let mut gate_guards = Vec::with_capacity(gates.len());
        for gate in gates {
            gate_guards.push(gate.lock_owned().await);
        }
        let identity = self
            .journal
            .preparation_identity(
                &context.principal,
                &bridge_profile,
                ClientRequestIdV1::from_bytes(*request.request_id().as_bytes()),
                request.idempotency_key().map(local_idempotency_commitment),
                now,
            )
            .map_err(map_journal)?;
        let idempotency_replay = match identity {
            PreparationIdentityLookup::Absent => None,
            PreparationIdentityLookup::Existing(JournalStatusV1::Record(record)) => {
                if record.binding().request_id()
                    == ClientRequestIdV1::from_bytes(*request.request_id().as_bytes())
                {
                    return match self
                        .gated_prepared_record(
                            &context,
                            &bridge,
                            record.operation_id(),
                            now,
                            Some(&request),
                        )
                        .await?
                    {
                        GatedPreparationRecord::Record(current) => {
                            self.encode_preparation_replay(&current, request.request_id())
                        }
                        GatedPreparationRecord::ReceiptIntegrityFailed(current) => {
                            Self::encode_receipt_integrity_failure(
                                &current,
                                Some(request.request_id()),
                            )
                        }
                        GatedPreparationRecord::IntentConflict(current) => {
                            self.encode_conflict_for_record(&current, request.request_id())
                        }
                    };
                }
                Some(record)
            }
            PreparationIdentityLookup::Existing(JournalStatusV1::Tombstone(_)) => {
                return Err(LocalAgentFailure::Internal);
            }
            PreparationIdentityLookup::Conflict {
                original_operation_id,
            } => {
                let original = self.status_record(&context.principal, &original_operation_id)?;
                return self.encode_conflict_for_record(&original, request.request_id());
            }
        };
        // A genuinely new admission, or a fresh request ID presenting an
        // existing idempotency key, must evaluate current mutable commitments.
        // The latter can replay only when the journal's full preparation
        // commitment still matches; drift becomes a typed conflict.
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        if context.qualification_fault
            == Some(QualificationAdmissionFaultV1::ConnectionSubstitution)
        {
            let substitute = if request.connection_alias() == Some("qualification-substitute-a") {
                "qualification-substitute-b"
            } else {
                "qualification-substitute-a"
            };
            match self.resolve_connection(
                &context,
                bridge.connection_requirement(),
                Some(substitute),
            ) {
                Err(LocalAgentFailure::NotFound) | Ok(None) => {
                    return encode_qualification_admission_unavailable(
                        &request,
                        CommonIssue::ConnectionUnavailable,
                    );
                }
                Ok(Some(_)) => return Err(LocalAgentFailure::InvalidConfiguration),
                Err(error) => return Err(error),
            }
        }
        let connection = match self.resolve_connection(
            &context,
            bridge.connection_requirement(),
            request.connection_alias(),
        ) {
            Ok(value) => value,
            Err(LocalAgentFailure::NotFound) => {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                return encode_local_operation_outcome(&LocalOperationOutcome::Unavailable {
                    request_id: request.request_id(),
                    operation_id: None,
                    issue: common_issue(CommonIssue::ConnectionUnavailable, None)?,
                    receipts: Vec::new(),
                    connection_alias: request.connection_alias().map(str::to_owned),
                })
                .map_err(|_| LocalAgentFailure::Internal);
            }
            Err(error) => return Err(error),
        };
        let workflow_id = workflow_identity(&context, &bridge_profile, &request);
        let preparation_evidence = match (
            bridge.preparation_evidence_kind(),
            request.preparation_evidence_handle(),
        ) {
            (None, None) => None,
            (Some("protected-lease"), Some(handle)) => {
                let connection = connection.as_ref().ok_or(LocalAgentFailure::NotFound)?;
                let configuration_sha256 = context.profile_configuration.as_deref().map_or(
                    [0; 32],
                    auths_profile_runtime::ProfileConfigurationBinding::sha256,
                );
                let authority_sha256 = match bridge.authorize_preparation_evidence(
                    &context,
                    &workflow_id,
                    request.profile_input(),
                    Some(connection),
                    now,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        if let Some(original) = idempotency_replay.as_ref() {
                            return self.encode_conflict_for_record(original, request.request_id());
                        }
                        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                        if let Some(issue) = qualification_admission_issue(&context) {
                            return encode_qualification_admission_unavailable(&request, issue);
                        }
                        return Err(LocalAgentFailure::NotFound);
                    }
                };
                let binding = LeaseBinding {
                    principal: &context.principal,
                    profile: &bridge_profile,
                    workflow_id: &workflow_id,
                    request: &request,
                    connection,
                    configuration_sha256,
                    authority_sha256,
                    authority_artifact_sha256: context.authority.artifact_commitment(),
                };
                let resolved = {
                    let _maintenance = self.preparation_evidence_maintenance.lock().await;
                    let store =
                        match PreparationEvidenceLeaseStore::open(&context.profile_state_root) {
                            Ok(value) => value,
                            Err(()) => {
                                if let Some(original) = idempotency_replay.as_ref() {
                                    return self.encode_conflict_for_record(
                                        original,
                                        request.request_id(),
                                    );
                                }
                                return Err(LocalAgentFailure::Internal);
                            }
                        };
                    store.resolve(&binding, handle, now)
                };
                let resolved = match resolved {
                    Ok(value) => value,
                    Err(()) => {
                        if let Some(original) = idempotency_replay.as_ref() {
                            return self.encode_conflict_for_record(original, request.request_id());
                        }
                        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                        if let Some(issue) = qualification_admission_issue(&context) {
                            return encode_qualification_admission_unavailable(&request, issue);
                        }
                        return Err(LocalAgentFailure::NotFound);
                    }
                };
                Some(resolved)
            }
            _ => {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                return Err(LocalAgentFailure::Malformed);
            }
        };
        now = unix_seconds()?;
        if let Some(evidence) = preparation_evidence.as_ref() {
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            match context.qualification_fault {
                Some(QualificationAdmissionFaultV1::EvidenceFreshnessEdge) => {
                    now = evidence.expires_at_unix_seconds.saturating_sub(1);
                }
                Some(QualificationAdmissionFaultV1::StaleEvidence) => {
                    now = evidence.expires_at_unix_seconds;
                }
                _ => {}
            }
            if evidence.expires_at_unix_seconds <= now {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                if let Some(issue) = qualification_admission_issue(&context) {
                    return encode_qualification_admission_unavailable(&request, issue);
                }
                return Err(LocalAgentFailure::NotFound);
            }
            let connection = connection.as_ref().ok_or(LocalAgentFailure::NotFound)?;
            let refreshed_authority = match bridge.authorize_preparation_evidence(
                &context,
                &workflow_id,
                request.profile_input(),
                Some(connection),
                now,
            ) {
                Ok(value) => value,
                Err(_) => {
                    if let Some(original) = idempotency_replay.as_ref() {
                        return self.encode_conflict_for_record(original, request.request_id());
                    }
                    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                    if let Some(issue) = qualification_admission_issue(&context) {
                        return encode_qualification_admission_unavailable(&request, issue);
                    }
                    return Err(LocalAgentFailure::NotFound);
                }
            };
            if refreshed_authority != evidence.authority_sha256 {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                if let Some(issue) = qualification_admission_issue(&context) {
                    return encode_qualification_admission_unavailable(&request, issue);
                }
                return Err(LocalAgentFailure::NotFound);
            }
        }
        let prepared = match bridge.prepare(
            &context,
            &workflow_id,
            request.profile_input(),
            connection.as_ref(),
            preparation_evidence
                .as_ref()
                .map(|value| value.bytes.as_slice()),
            now,
        ) {
            Ok(value) => value,
            Err(ProfileBridgeError::PreEntry(issue)) => {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                return encode_local_operation_outcome(&LocalOperationOutcome::Unavailable {
                    request_id: request.request_id(),
                    operation_id: None,
                    issue,
                    receipts: Vec::new(),
                    connection_alias: connection
                        .as_ref()
                        .map(|value| value.alias().as_str().to_owned()),
                })
                .map_err(|_| LocalAgentFailure::Internal);
            }
            Err(
                ProfileBridgeError::Possible(_)
                | ProfileBridgeError::PossibleWithProfileState { .. }
                | ProfileBridgeError::PreEntryPending
                | ProfileBridgeError::Invalid,
            ) => {
                if let Some(original) = idempotency_replay.as_ref() {
                    return self.encode_conflict_for_record(original, request.request_id());
                }
                return Err(LocalAgentFailure::Internal);
            }
        };
        // Every receipt and journal timestamp uses the trusted clock sampled
        // after the protected preflight and pure preparation phases.
        now = unix_seconds()?;
        let profile = Self::profile_from_context(&context, *request.runtime_contract_digest())?;
        let connection_commitments = connection
            .as_ref()
            .map(connection_commitments)
            .transpose()?;
        let binding = PreparationBindingV1::new(
            context.principal.as_ref(),
            profile.clone(),
            ClientRequestIdV1::from_bytes(*request.request_id().as_bytes()),
            request.idempotency_key().map(local_idempotency_commitment),
            prepared.canonical_input_commitment,
            preparation_evidence.as_ref().map(|value| value.commitment),
            preparation_evidence
                .as_ref()
                .map(|value| value.intent_sha256),
            connection_commitments,
            prepared.canonical_action_commitment,
            context.authority.artifact_commitment(),
            prepared.configuration_commitment,
        )
        .map_err(|_| LocalAgentFailure::Internal)?;
        if Sha256::digest(&prepared.canonical_action).as_slice()
            != prepared.canonical_action_commitment
        {
            return Err(LocalAgentFailure::Internal);
        }
        if let Some(original) = idempotency_replay.as_ref() {
            if binding.idempotency_replay_commitment()
                != original.binding().idempotency_replay_commitment()
            {
                return self.encode_conflict_for_record(original, request.request_id());
            }
            // Full current commitments match the retained logical operation.
            // Return it before minting another receipt, operation ID, or
            // recovery handle: replay is a read of durable truth, not a new
            // signing/admission attempt.
            return match self
                .gated_prepared_record(
                    &context,
                    &bridge,
                    original.operation_id(),
                    now,
                    Some(&request),
                )
                .await?
            {
                GatedPreparationRecord::Record(current) => {
                    self.encode_preparation_replay(&current, request.request_id())
                }
                GatedPreparationRecord::ReceiptIntegrityFailed(current) => {
                    Self::encode_receipt_integrity_failure(&current, Some(request.request_id()))
                }
                GatedPreparationRecord::IntentConflict(current) => {
                    self.encode_conflict_for_record(&current, request.request_id())
                }
            };
        }
        let decision_class = match &prepared.kind {
            ProfilePreparationKind::Ready => DecisionClass::Authorized,
            ProfilePreparationKind::Denied { .. } => DecisionClass::Denied,
            ProfilePreparationKind::Unavailable { .. } => DecisionClass::Indeterminate,
        };
        let decision_context = receipt_context(&context, &binding);
        let receipt_action_commitment =
            auths_codec::domain_commitment("auths.profile-action.v2", &prepared.canonical_action)
                .map_err(|_| LocalAgentFailure::Internal)?;
        let receipt_context_commitment =
            auths_codec::domain_commitment("auths.profile-context.v2", &decision_context)
                .map_err(|_| LocalAgentFailure::Internal)?;
        let journal_decision_class = match decision_class {
            DecisionClass::Authorized => JournalDecisionClassV1::Authorized,
            DecisionClass::Denied => JournalDecisionClassV1::Denied,
            DecisionClass::Indeterminate => JournalDecisionClassV1::Indeterminate,
        };
        let decision_profile_claims = bridge
            .build_decision_receipt_claims(ProfileDecisionReceiptFacts {
                binding: &binding,
                decision_class: journal_decision_class,
                receipt_action_commitment: *receipt_action_commitment.as_bytes(),
                receipt_context_commitment: *receipt_context_commitment.as_bytes(),
                profile_state: &prepared.profile_state,
            })
            .map_err(|_| LocalAgentFailure::Internal)?;
        let decision_receipt = self
            .receipts
            .decision(
                &profile,
                context.authority.proof_bytes(),
                &prepared.canonical_action,
                &decision_context,
                decision_class,
                prepared.decision_reason.clone(),
                now,
                &decision_profile_claims,
            )
            .map_err(|_| LocalAgentFailure::Internal)?;
        let operation_id = generate_operation_id().map_err(map_journal)?;
        let recovery_handle = self
            .recovery
            .issue(&operation_id, &profile, &context.principal, now, None)
            .map_err(|_| LocalAgentFailure::Internal)?;
        let (projection, issue) = match prepared.kind {
            ProfilePreparationKind::Ready => (
                OperationProjectionV1::new(
                    OperationStateV1::Ready,
                    OperationEffectV1::NotApplied,
                    false,
                ),
                None,
            ),
            ProfilePreparationKind::Denied { issue } => (
                OperationProjectionV1::new(
                    OperationStateV1::Denied,
                    OperationEffectV1::NotApplied,
                    true,
                ),
                Some(issue),
            ),
            ProfilePreparationKind::Unavailable { issue } => (
                OperationProjectionV1::new(
                    OperationStateV1::Unavailable,
                    OperationEffectV1::NotApplied,
                    true,
                ),
                Some(issue),
            ),
        };
        let record = JournalRecordV1::prepared(
            operation_id,
            binding,
            journal_decision_class,
            *receipt_action_commitment.as_bytes(),
            *receipt_context_commitment.as_bytes(),
            projection.map_err(|_| LocalAgentFailure::Internal)?,
            now,
            recovery_handle,
            issue,
            prepared.profile_state,
            vec![decision_receipt],
        )
        .map_err(map_journal)?;
        match self.journal.prepare(record, now) {
            Ok(PrepareJournalResult::Created(record)) => {
                match self
                    .gated_prepared_record(&context, &bridge, record.operation_id(), now, None)
                    .await?
                {
                    GatedPreparationRecord::Record(record) => {
                        self.encode_record_for_request(&record, None, Some(request.request_id()))
                    }
                    GatedPreparationRecord::ReceiptIntegrityFailed(record) => {
                        Self::encode_receipt_integrity_failure(&record, Some(request.request_id()))
                    }
                    GatedPreparationRecord::IntentConflict(_) => Err(LocalAgentFailure::Internal),
                }
            }
            Ok(PrepareJournalResult::Replayed(record)) => {
                match self
                    .gated_prepared_record(&context, &bridge, record.operation_id(), now, None)
                    .await?
                {
                    GatedPreparationRecord::Record(record) => self.encode_record_for_request(
                        &record,
                        record
                            .projection()
                            .is_terminal()
                            .then_some(LocalOperationCompletion::Replayed),
                        Some(request.request_id()),
                    ),
                    GatedPreparationRecord::ReceiptIntegrityFailed(record) => {
                        Self::encode_receipt_integrity_failure(&record, Some(request.request_id()))
                    }
                    GatedPreparationRecord::IntentConflict(_) => Err(LocalAgentFailure::Internal),
                }
            }
            Ok(PrepareJournalResult::Conflict {
                original_operation_id,
            }) => {
                let original = self.status_record(&context.principal, &original_operation_id)?;
                if original.receipt_integrity_failed()
                    || self.verify_receipts_for_record(&original).is_err()
                {
                    return Self::encode_receipt_integrity_failure(
                        &original,
                        Some(request.request_id()),
                    );
                }
                encode_local_operation_outcome(&LocalOperationOutcome::Conflict {
                    request_id: request.request_id(),
                    operation_id: protocol_operation_id(original.operation_id())?,
                    issue: common_issue(
                        CommonIssue::IdempotencyConflict,
                        Some(original.operation_id()),
                    )?,
                    recovery_handle: original.recovery_handle().to_vec(),
                    receipts: receipt_bytes(&original),
                    connection_alias: connection_alias(&original),
                })
                .map_err(|_| LocalAgentFailure::Internal)
            }
            Ok(PrepareJournalResult::ReplayedTombstone(_)) => Err(LocalAgentFailure::NotFound),
            Err(auths_stores::OperationJournalError::Capacity) => {
                encode_local_operation_outcome(&LocalOperationOutcome::Unavailable {
                    request_id: request.request_id(),
                    operation_id: None,
                    issue: common_issue(CommonIssue::AdmissionExhausted, None)?,
                    receipts: Vec::new(),
                    connection_alias: request.connection_alias().map(str::to_owned),
                })
                .map_err(|_| LocalAgentFailure::Internal)
            }
            Err(error) => Err(map_journal(error)),
        }
    }

    async fn gated_prepared_record(
        &self,
        context: &LocalOperationContext,
        bridge: &ProfileRuntime,
        operation_id: &OperationIdV1,
        now: u64,
        expected_request: Option<&PrepareOperationRequest>,
    ) -> Result<GatedPreparationRecord, LocalAgentFailure> {
        let operation_gate = self.operation_gate(operation_id).await;
        let _operation_guard = operation_gate.lock().await;
        let current = self.status_record(&context.principal, operation_id)?;
        ensure_profile(context, &current)?;
        if expected_request.is_some_and(|request| {
            !preparation_request_matches_binding(context, request, current.binding())
        }) {
            return Ok(GatedPreparationRecord::IntentConflict(current));
        }
        if current.receipt_integrity_failed() || self.verify_receipts_for_record(&current).is_err()
        {
            return Ok(GatedPreparationRecord::ReceiptIntegrityFailed(current));
        }
        self.seal_pre_entry_after_prepare(context, bridge, current, now)
            .await
            .map(GatedPreparationRecord::Record)
    }

    pub(crate) async fn execute(
        &self,
        context: LocalOperationContext,
        request: ExecuteOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let now = unix_seconds()?;
        let response_request_id = request.request_id();
        let operation_id = journal_operation_id(request.operation_id())?;
        // Reject unknown IDs before allocating a coordination gate. Reload
        // after acquiring the gate because another accepted request may have
        // advanced the record in between.
        self.status_record(&context.principal, &operation_id)?;
        let gate = self.operation_gate(&operation_id).await;
        let _guard = gate.lock().await;
        let record = self.status_record(&context.principal, &operation_id)?;
        ensure_profile(&context, &record)?;
        if record.receipt_integrity_failed() || self.verify_receipts_for_record(&record).is_err() {
            return Self::encode_receipt_integrity_failure(&record, Some(response_request_id));
        }
        if record.binding().preparation_commitment() != request.preparation_commitment() {
            return self.encode_record_for_request(&record, None, Some(response_request_id));
        }
        if record.projection().is_terminal() {
            return self.encode_record_for_request(
                &record,
                Some(LocalOperationCompletion::Replayed),
                Some(response_request_id),
            );
        }
        let recovering_pre_entry = record.projection().state() == OperationStateV1::Executing
            && record.projection().effect() == OperationEffectV1::NotApplied;
        if record.projection().state() != OperationStateV1::Ready && !recovering_pre_entry {
            return self.encode_record_for_request(&record, None, Some(response_request_id));
        }
        let bridge = self.bridge(&context.profile)?;
        let terminal = self
            .advance_provider_call(&context, &bridge, record, recovering_pre_entry, now)
            .await?;
        self.encode_record_for_request(&terminal, None, Some(response_request_id))
    }

    async fn seal_pre_entry_after_prepare(
        &self,
        context: &LocalOperationContext,
        bridge: &ProfileRuntime,
        record: JournalRecordV1,
        now: u64,
    ) -> Result<JournalRecordV1, LocalAgentFailure> {
        if record.projection().state() != OperationStateV1::Ready
            || record.sealed_command().is_some()
        {
            return Ok(record);
        }
        let operation_id = record.operation_id().clone();
        let sealed_result = bridge.seal_provider_call(context, &record, now).await;
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        self.journal.checkpoint_after_reservation()?;
        let sealed = match sealed_result {
            Ok(value) if !value.profile_state.is_empty() && !value.command.is_empty() => value,
            Ok(_)
            | Err(
                ProfileBridgeError::Invalid
                | ProfileBridgeError::Possible(_)
                | ProfileBridgeError::PossibleWithProfileState { .. }
                | ProfileBridgeError::PreEntryPending,
            ) => {
                // A domain sealer may have acquired its durable reservation
                // before a later canonicalization/serialization step failed.
                // The command never reached the common journal, so every
                // unsuccessful seal path must invoke the idempotent
                // by-operation release hook before returning.
                bridge
                    .release_pre_entry(context, &record)
                    .map_err(|_| LocalAgentFailure::Internal)?;
                return Err(LocalAgentFailure::Internal);
            }
            Err(ProfileBridgeError::PreEntry(issue)) => {
                bridge
                    .release_pre_entry(context, &record)
                    .map_err(|_| LocalAgentFailure::Internal)?;
                return self
                    .journal
                    .mutate_operation(
                        &context.principal,
                        &operation_id,
                        record.revision(),
                        OperationMutationV1::ConcludePreEntry {
                            state: OperationStateV1::NotApplied,
                            issue,
                            profile_state: record.profile_state().to_vec(),
                        },
                        unix_seconds()?,
                    )
                    .map_err(map_journal);
            }
        };
        let persisted_at = unix_seconds()?;
        match self.journal.mutate_operation(
            &context.principal,
            &operation_id,
            record.revision(),
            OperationMutationV1::SealPreEntry {
                profile_state: sealed.profile_state,
                sealed_command: sealed.command,
            },
            persisted_at,
        ) {
            Ok(value) => Ok(value),
            Err(auths_stores::OperationJournalError::Conflict) => {
                let current = self.status_record(&context.principal, &operation_id)?;
                if current.projection().state() != OperationStateV1::Ready
                    || current.sealed_command().is_none()
                {
                    bridge
                        .release_pre_entry(context, &record)
                        .map_err(|_| LocalAgentFailure::Internal)?;
                }
                Ok(current)
            }
            Err(error) => {
                bridge
                    .release_pre_entry(context, &record)
                    .map_err(|_| LocalAgentFailure::Internal)?;
                Err(map_journal(error))
            }
        }
    }

    pub(crate) async fn recover(
        &self,
        context: LocalOperationContext,
        operation: Option<OperationId>,
        request: RecoverOperationRequest,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let now = unix_seconds()?;
        let response_request_id = request.request_id();
        let verified = self
            .recovery
            .verify(request.recovery_handle(), &context.principal, now)
            .map_err(|_| LocalAgentFailure::NotFound)?;
        if operation
            .as_ref()
            .is_some_and(|value| value.as_str() != verified.operation_id().as_str())
        {
            return Err(LocalAgentFailure::NotFound);
        }
        self.status_record(&context.principal, verified.operation_id())?;
        let gate = self.operation_gate(verified.operation_id()).await;
        let _guard = gate.lock().await;
        let record = self.status_record(&context.principal, verified.operation_id())?;
        if record.binding().profile() != verified.profile()
            || (context.profile.id() != "auths.core.recovery"
                && (context.profile.id() != record.binding().profile().id()
                    || context.profile.version() != record.binding().profile().version()))
        {
            return Err(LocalAgentFailure::NotFound);
        }
        if record.receipt_integrity_failed() || self.verify_receipts_for_record(&record).is_err() {
            return self.encode_recovery_projection(
                &context.principal,
                &record,
                None,
                response_request_id,
            );
        }
        if record.projection().is_terminal() {
            return self.encode_recovery_projection(
                &context.principal,
                &record,
                Some(LocalOperationCompletion::Replayed),
                response_request_id,
            );
        }
        let bridge_key = SessionProfileKey::new(
            record.binding().profile().id(),
            record.binding().profile().version(),
        )
        .map_err(|_| LocalAgentFailure::Internal)?;
        let bridge = self.bridge(&bridge_key)?;
        let profile_context = LocalOperationContext {
            profile: bridge_key,
            ..context
        };
        if matches!(
            record.projection().state(),
            OperationStateV1::Ready | OperationStateV1::Executing
        ) && record.projection().effect() == OperationEffectV1::NotApplied
        {
            // Recovery is never an effect-creation API.  A durable pre-entry
            // checkpoint proves that the provider was not called, so release
            // the accepted operation instead of resuming the original call.
            // This is what makes caller cancellation after prepare safe: a
            // recovery request can establish non-application without ever
            // becoming a second execute request.
            // The hook is deliberately idempotent for Ready as well as
            // Executing. A domain reservation/claim can become durable while
            // sealing, immediately before the common BeginExecution CAS. If
            // the process dies in that gap, the Ready journal record has no
            // sealed command/token, so the concrete profile store releases by
            // the immutable operation ID instead.
            bridge
                .release_pre_entry(&profile_context, &record)
                .map_err(|_| LocalAgentFailure::Internal)?;
            let updated = self
                .journal
                .mutate_operation(
                    &profile_context.principal,
                    record.operation_id(),
                    record.revision(),
                    OperationMutationV1::ConcludePreEntry {
                        state: OperationStateV1::NotApplied,
                        issue: common_issue(CommonIssue::TimedOut, Some(record.operation_id()))?,
                        profile_state: record.profile_state().to_vec(),
                    },
                    unix_seconds()?,
                )
                .map_err(map_journal)?;
            return self.encode_recovery_projection(
                &profile_context.principal,
                &updated,
                None,
                response_request_id,
            );
        }
        let record = if record.projection().state() == OperationStateV1::Executing
            && record.projection().effect() == OperationEffectV1::Possible
        {
            if let Some(provider_result) = record.provider_result().map(<[u8]>::to_vec) {
                let observed_at = unix_seconds()?;
                let updated = self
                    .observe_durable_provider_result(
                        &profile_context,
                        &bridge,
                        record,
                        provider_result,
                        true,
                        observed_at,
                    )
                    .await?;
                return self.encode_recovery_projection(
                    &profile_context.principal,
                    &updated,
                    None,
                    response_request_id,
                );
            }
            let integrity_issue =
                common_issue(CommonIssue::OutcomeUnknown, Some(record.operation_id()))?;
            let receipt_record = self.persist_execution_receipt_or_quarantine(
                &profile_context.principal,
                &record,
                ExecutionOutcome::Indeterminate,
                record.provider_result(),
                ReceiptIntegrityTruth::recovery(
                    integrity_issue.clone(),
                    record.profile_progress().map(<[u8]>::to_vec),
                    record.profile_state().to_vec(),
                ),
                unix_seconds()?,
            )?;
            if receipt_record.receipt_integrity_failed() {
                return self.encode_recovery_projection(
                    &profile_context.principal,
                    &receipt_record,
                    None,
                    response_request_id,
                );
            }
            self.journal
                .mutate_operation(
                    &profile_context.principal,
                    receipt_record.operation_id(),
                    receipt_record.revision(),
                    OperationMutationV1::RequireRecovery {
                        issue: integrity_issue,
                        progress: receipt_record.profile_progress().map(<[u8]>::to_vec),
                        profile_state: receipt_record.profile_state().to_vec(),
                    },
                    unix_seconds()?,
                )
                .map_err(map_journal)?
        } else if record.projection().state() == OperationStateV1::RecoveryRequired {
            record
        } else {
            return self.encode_recovery_projection(
                &profile_context.principal,
                &record,
                None,
                response_request_id,
            );
        };
        let (_binding, credential) = self
            .lease_connection_for_recovery(
                &profile_context,
                record.operation_id(),
                bridge.connection_requirement(),
                record.binding().connection(),
            )
            .await
            .unwrap_or((None, None));
        if bridge.connection_requirement().is_some() && credential.is_none() {
            let issue = common_issue(
                CommonIssue::RecoveryUnavailable,
                Some(record.operation_id()),
            )?;
            let updated = self
                .journal
                .mutate_operation(
                    &profile_context.principal,
                    record.operation_id(),
                    record.revision(),
                    OperationMutationV1::RequireRecovery {
                        issue,
                        progress: record.profile_progress().map(<[u8]>::to_vec),
                        profile_state: record.profile_state().to_vec(),
                    },
                    unix_seconds()?,
                )
                .map_err(map_journal)?;
            return self.encode_recovery_projection(
                &profile_context.principal,
                &updated,
                None,
                response_request_id,
            );
        }
        let reconciliation_at = unix_seconds()?;
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        let observation = if self.mode == RuntimeMode::Qualification {
            let policy = self
                .provider_proxy
                .as_ref()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let credential = credential
                .as_ref()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let command = record
                .sealed_command()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?;
            let request = qualification_provider_call_request(
                policy,
                &record,
                QualificationProviderCallKind::Reconcile,
                credential,
                command,
                record.profile_state(),
                profile_context.profile_configuration.as_deref(),
                reconciliation_at,
            )?;
            match call_qualification_provider_proxy(policy, request).await {
                Ok(QualificationProviderCallResponse::PostEntryTimeout) => {
                    Err(ProfileBridgeError::Possible(common_issue(
                        CommonIssue::OutcomeUnknown,
                        Some(record.operation_id()),
                    )?))
                }
                Ok(result) => bridge.finalize_qualification_reconcile_result(
                    &profile_context,
                    &record,
                    reconciliation_at,
                    result,
                ),
                Err(error) => Err(error),
            }
        } else {
            bridge
                .reconcile(
                    &profile_context,
                    &record,
                    credential
                        .as_ref()
                        .and_then(RuntimeCredentialLease::credential),
                    reconciliation_at,
                )
                .await
        };
        #[cfg(not(all(target_os = "linux", feature = "qualification-failpoints")))]
        let observation = bridge
            .reconcile(
                &profile_context,
                &record,
                credential
                    .as_ref()
                    .and_then(RuntimeCredentialLease::credential),
                reconciliation_at,
            )
            .await;
        let observation = match observation {
            Ok(value) => value,
            Err(ProfileBridgeError::Possible(issue)) => ProfileObservation {
                bytes: issue.clone(),
                conclusion: ProfileConclusion::RecoveryRequired {
                    issue,
                    progress: record.profile_progress().map(<[u8]>::to_vec),
                    profile_state: record.profile_state().to_vec(),
                },
            },
            Err(
                ProfileBridgeError::PreEntry(_)
                | ProfileBridgeError::PreEntryPending
                | ProfileBridgeError::PossibleWithProfileState { .. }
                | ProfileBridgeError::Invalid,
            ) => {
                let issue = common_issue(
                    CommonIssue::RecoveryUnavailable,
                    Some(record.operation_id()),
                )?;
                ProfileObservation {
                    bytes: issue.clone(),
                    conclusion: ProfileConclusion::RecoveryRequired {
                        issue,
                        progress: record.profile_progress().map(<[u8]>::to_vec),
                        profile_state: record.profile_state().to_vec(),
                    },
                }
            }
        };
        if let Some(credential) = credential {
            if matches!(
                &observation.conclusion,
                ProfileConclusion::RecoveryRequired { .. }
            ) {
                drop(credential);
            } else {
                credential.close().await?;
            }
        }
        let updated = self
            .apply_observation(&profile_context, record, observation, true)
            .await?;
        self.encode_recovery_projection(
            &profile_context.principal,
            &updated,
            None,
            response_request_id,
        )
    }

    pub(crate) async fn status(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let operation = journal_operation_id(&operation)?;
        let record = self.status_record(&context.principal, &operation)?;
        if context.profile.id() != "auths.core.receipts" {
            ensure_profile(&context, &record)?;
        }
        self.encode_status_projection(&context.principal, &record)
    }

    pub(crate) async fn receipts(
        &self,
        context: LocalOperationContext,
        operation: OperationId,
    ) -> Result<Vec<u8>, LocalAgentFailure> {
        let operation = journal_operation_id(&operation)?;
        let record = self.status_record(&context.principal, &operation)?;
        if context.profile.id() != "auths.core.receipts" {
            ensure_profile(&context, &record)?;
        }
        if record.receipt_integrity_failed() || self.verify_receipts_for_record(&record).is_err() {
            // Receipt export shares the ordinary registered outcome envelope:
            // callers receive a typed recovery-required integrity failure and
            // never receive the quarantined receipt bytes.
            return Self::encode_receipt_integrity_failure(&record, None);
        }
        let entries = record
            .receipts()
            .iter()
            .map(|value| LocalReceiptEntry {
                receipt_id: value.receipt_id().to_owned(),
                bytes: value.bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        encode_receipt_entries(&protocol_operation_id(record.operation_id())?, &entries)
            .map_err(|_| LocalAgentFailure::Internal)
    }

    pub(crate) async fn pending(&self, principal: Arc<str>) -> Result<Vec<u8>, LocalAgentFailure> {
        let records = self.journal.pending(&principal).map_err(map_journal)?;
        let values = records
            .iter()
            .map(|record| {
                Ok(LocalPendingOperation {
                    operation_id: protocol_operation_id(record.operation_id())?,
                    profile_id: record.binding().profile().id().to_owned(),
                    profile_version: record.binding().profile().version(),
                    state: state_text(record.projection().state()).to_owned(),
                    effect: effect_text(record.projection().effect()).to_owned(),
                    updated_at_unix_seconds: record.updated_at_unix_seconds(),
                    receipt_ids: record
                        .receipts()
                        .iter()
                        .map(|value| value.receipt_id().to_owned())
                        .collect(),
                    recovery_handle: record.recovery_handle().to_vec(),
                    connection_alias: connection_alias(record),
                })
            })
            .collect::<Result<Vec<_>, LocalAgentFailure>>()?;
        encode_pending_operations(&values).map_err(|_| LocalAgentFailure::Internal)
    }
}

fn outcome_from_record(
    record: &JournalRecordV1,
    completion_override: Option<LocalOperationCompletion>,
    request_id_override: Option<ClientRequestId>,
) -> Result<LocalOperationOutcome, LocalAgentFailure> {
    let request_id = request_id_override
        .unwrap_or_else(|| ClientRequestId::from_bytes(*record.binding().request_id().as_bytes()));
    let operation_id = protocol_operation_id(record.operation_id())?;
    let alias = connection_alias(record);
    let receipts = receipt_bytes(record);
    let receipt_ids = record
        .receipts()
        .iter()
        .map(|value| value.receipt_id().to_owned())
        .collect::<Vec<_>>();
    match record.projection().state() {
        OperationStateV1::Preparing => Ok(LocalOperationOutcome::InProgress {
            request_id,
            operation_id,
            state: "preparing".into(),
            effect: effect_text(record.projection().effect()).into(),
            receipt_ids,
            recovery_handle: record.recovery_handle().to_vec(),
            connection_alias: alias,
        }),
        OperationStateV1::Ready => Ok(LocalOperationOutcome::Ready {
            request_id,
            operation_id,
            preparation_commitment: *record.binding().preparation_commitment(),
            decision_receipt: receipts
                .first()
                .cloned()
                .ok_or(LocalAgentFailure::Internal)?,
            recovery_handle: record.recovery_handle().to_vec(),
            connection_alias: alias,
        }),
        OperationStateV1::Executing => Ok(LocalOperationOutcome::InProgress {
            request_id,
            operation_id,
            state: "executing".into(),
            effect: effect_text(record.projection().effect()).into(),
            receipt_ids,
            recovery_handle: record.recovery_handle().to_vec(),
            connection_alias: alias,
        }),
        OperationStateV1::Denied => Ok(LocalOperationOutcome::Denied {
            request_id,
            operation_id,
            issue: required_issue(record)?,
            decision_receipt: receipts
                .first()
                .cloned()
                .ok_or(LocalAgentFailure::Internal)?,
            connection_alias: alias,
        }),
        OperationStateV1::Unavailable => Ok(LocalOperationOutcome::Unavailable {
            request_id,
            operation_id: Some(operation_id),
            issue: required_issue(record)?,
            receipts,
            connection_alias: alias,
        }),
        OperationStateV1::RecoveryRequired => Ok(LocalOperationOutcome::RecoveryRequired {
            request_id,
            operation_id,
            issue: required_issue(record)?,
            recovery_handle: record.recovery_handle().to_vec(),
            receipts,
            progress: record.profile_progress().map(<[u8]>::to_vec),
            connection_alias: alias,
        }),
        OperationStateV1::Completed => Ok(LocalOperationOutcome::Completed {
            request_id,
            operation_id,
            value: record
                .profile_value()
                .map(<[u8]>::to_vec)
                .ok_or(LocalAgentFailure::Internal)?,
            receipts,
            completion: completion_override.unwrap_or(completion(record)?),
            connection_alias: alias,
        }),
        OperationStateV1::Partial => Ok(LocalOperationOutcome::Partial {
            request_id,
            operation_id,
            value: record
                .profile_value()
                .map(<[u8]>::to_vec)
                .ok_or(LocalAgentFailure::Internal)?,
            issue: required_issue(record)?,
            receipts,
            completion: completion_override.unwrap_or(completion(record)?),
            connection_alias: alias,
        }),
        OperationStateV1::NotApplied => Ok(LocalOperationOutcome::NotApplied {
            request_id,
            operation_id,
            issue: required_issue(record)?,
            receipts,
            completion: completion_override.unwrap_or(completion(record)?),
            connection_alias: alias,
        }),
    }
}

fn completion(record: &JournalRecordV1) -> Result<LocalOperationCompletion, LocalAgentFailure> {
    match record.completion() {
        Some(JournalCompletionV1::Fresh) => Ok(LocalOperationCompletion::Fresh),
        Some(JournalCompletionV1::Replayed) => Ok(LocalOperationCompletion::Replayed),
        Some(JournalCompletionV1::Reconciled) => Ok(LocalOperationCompletion::Reconciled),
        None => Err(LocalAgentFailure::Internal),
    }
}

fn receipt_bytes(record: &JournalRecordV1) -> Vec<Vec<u8>> {
    record
        .receipts()
        .iter()
        .map(|value| value.bytes().to_vec())
        .collect()
}

fn required_issue(record: &JournalRecordV1) -> Result<Vec<u8>, LocalAgentFailure> {
    record
        .issue()
        .map(<[u8]>::to_vec)
        .ok_or(LocalAgentFailure::Internal)
}

fn connection_alias(record: &JournalRecordV1) -> Option<String> {
    record
        .binding()
        .connection()
        .map(|value| value.alias().to_owned())
}

fn connection_commitments(
    binding: &ConnectionBinding,
) -> Result<ConnectionBindingCommitmentsV1, LocalAgentFailure> {
    ConnectionBindingCommitmentsV1::new(
        binding.alias().as_str(),
        binding.connection_id().as_str(),
        binding.generation().get(),
        *binding.descriptor_commitment(),
        *binding.account_commitment(),
    )
    .map_err(|_| LocalAgentFailure::Internal)
}

fn ensure_profile(
    context: &LocalOperationContext,
    record: &JournalRecordV1,
) -> Result<(), LocalAgentFailure> {
    if context.profile.id() != record.binding().profile().id()
        || context.profile.version() != record.binding().profile().version()
    {
        return Err(LocalAgentFailure::NotFound);
    }
    Ok(())
}

/// Compares only immutable caller-supplied preparation facts. Mutable
/// deployment dependencies (the current connection generation and profile
/// configuration) deliberately do not participate: once an operation owns a
/// request/idempotency identity, later disablement or rotation must not hide
/// its durable truth.
fn preparation_request_matches_binding(
    context: &LocalOperationContext,
    request: &PrepareOperationRequest,
    binding: &PreparationBindingV1,
) -> bool {
    let input_commitment: [u8; 32] = Sha256::digest(request.profile_input()).into();
    let requested_idempotency = request.idempotency_key().map(local_idempotency_commitment);
    binding.principal() == context.principal.as_ref()
        && binding.profile().id() == context.profile.id()
        && binding.profile().version() == context.profile.version()
        && binding.profile().runtime_contract_digest() == request.runtime_contract_digest()
        && binding.idempotency_commitment().copied() == requested_idempotency
        && binding.canonical_input_commitment() == &input_commitment
        && request.connection_alias().is_none_or(|alias| {
            binding
                .connection()
                .is_some_and(|connection| connection.alias() == alias)
        })
        && binding.authority_commitment() == &context.authority.artifact_commitment()
}

fn workflow_identity(
    context: &LocalOperationContext,
    profile: &OperationProfileV1,
    request: &PrepareOperationRequest,
) -> String {
    let request_commitment = request.idempotency_key().map_or_else(
        || {
            let mut digest = Sha256::new();
            digest.update(b"AUTHS-WORKFLOW-REQUEST\x00\x01");
            digest.update(request.request_id().as_bytes());
            digest.finalize().into()
        },
        local_idempotency_commitment,
    );
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-WORKFLOW-IDENTITY\x00\x01");
    digest.update((context.principal.len() as u64).to_be_bytes());
    digest.update(context.principal.as_bytes());
    digest.update((profile.id().len() as u64).to_be_bytes());
    digest.update(profile.id().as_bytes());
    digest.update(profile.version().to_be_bytes());
    digest.update(profile.runtime_contract_digest());
    digest.update(request_commitment);
    format!("wf_{}", hex::encode(digest.finalize()))
}

#[cfg(feature = "testkit-agent")]
fn testkit_preparation_evidence_commitment(
    context: &LocalOperationContext,
    workflow_id: &str,
    profile_input: &[u8],
    connection: Option<&ConnectionBinding>,
) -> Result<[u8; 32], ProfileBridgeError> {
    let connection = connection.ok_or(ProfileBridgeError::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-TESTKIT-PREPARATION-EVIDENCE\0\x01");
    for value in [
        context.principal.as_bytes(),
        context.profile.id().as_bytes(),
        workflow_id.as_bytes(),
        profile_input,
        connection.connection_id().as_str().as_bytes(),
        connection.descriptor_commitment(),
        connection.account_commitment(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    Ok(digest.finalize().into())
}

fn receipt_context(context: &LocalOperationContext, binding: &PreparationBindingV1) -> Vec<u8> {
    let trusted = context.authority.trusted_context_bytes();
    let mut output = Vec::with_capacity(trusted.len().saturating_add(256));
    output.extend_from_slice(b"AUTHS-LOCAL-RECEIPT-CONTEXT\x00\x01");
    output.extend_from_slice(&(trusted.len() as u64).to_be_bytes());
    output.extend_from_slice(trusted);
    output.extend_from_slice(binding.authority_commitment());
    output.extend_from_slice(binding.configuration_commitment());
    output.extend_from_slice(binding.preparation_commitment());
    if let Some(connection) = binding.connection() {
        output.push(1);
        output.extend_from_slice(connection.connection_id().as_bytes());
        output.push(0);
        output.extend_from_slice(&connection.generation().to_be_bytes());
        output.extend_from_slice(connection.descriptor_commitment());
        output.extend_from_slice(connection.account_commitment());
    } else {
        output.push(0);
    }
    output
}

fn protocol_operation_id(value: &OperationIdV1) -> Result<OperationId, LocalAgentFailure> {
    OperationId::parse(value.as_str()).map_err(|_| LocalAgentFailure::Internal)
}

fn journal_operation_id(value: &OperationId) -> Result<OperationIdV1, LocalAgentFailure> {
    OperationIdV1::parse(value.as_str()).map_err(|_| LocalAgentFailure::Malformed)
}

fn unix_seconds() -> Result<u64, LocalAgentFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| LocalAgentFailure::Internal)
}

fn state_text(value: OperationStateV1) -> &'static str {
    match value {
        OperationStateV1::Preparing => "preparing",
        OperationStateV1::Denied => "denied",
        OperationStateV1::Unavailable => "unavailable",
        OperationStateV1::Ready => "ready",
        OperationStateV1::Executing => "executing",
        OperationStateV1::RecoveryRequired => "recovery-required",
        OperationStateV1::Completed => "completed",
        OperationStateV1::Partial => "partial",
        OperationStateV1::NotApplied => "not-applied",
    }
}

fn effect_text(value: OperationEffectV1) -> &'static str {
    match value {
        OperationEffectV1::NotApplied => "not-applied",
        OperationEffectV1::Possible => "possible",
        OperationEffectV1::Applied => "applied",
    }
}

fn map_journal(error: auths_stores::OperationJournalError) -> LocalAgentFailure {
    match error {
        auths_stores::OperationJournalError::NotFound => LocalAgentFailure::NotFound,
        auths_stores::OperationJournalError::Capacity => LocalAgentFailure::Limit,
        auths_stores::OperationJournalError::InvalidRecord
        | auths_stores::OperationJournalError::InvalidTransition
        | auths_stores::OperationJournalError::Conflict
        | auths_stores::OperationJournalError::InvalidState
        | auths_stores::OperationJournalError::Unavailable => LocalAgentFailure::Internal,
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn qualification_admission_issue(context: &LocalOperationContext) -> Option<CommonIssue> {
    match context.qualification_fault {
        Some(QualificationAdmissionFaultV1::ConfigurationMismatch) => {
            Some(CommonIssue::InvalidConfiguration)
        }
        Some(QualificationAdmissionFaultV1::PrincipalSubstitution) => {
            Some(CommonIssue::UnauthenticatedPrincipal)
        }
        Some(QualificationAdmissionFaultV1::StaleEvidence) => {
            Some(CommonIssue::AuthorizationIndeterminate)
        }
        Some(
            QualificationAdmissionFaultV1::ConnectionSubstitution
            | QualificationAdmissionFaultV1::EvidenceFreshnessEdge,
        )
        | None => None,
    }
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn encode_qualification_admission_unavailable(
    request: &PrepareOperationRequest,
    issue: CommonIssue,
) -> Result<Vec<u8>, LocalAgentFailure> {
    encode_local_operation_outcome(&LocalOperationOutcome::Unavailable {
        request_id: request.request_id(),
        operation_id: None,
        issue: common_issue(issue, None)?,
        receipts: Vec::new(),
        connection_alias: request.connection_alias().map(str::to_owned),
    })
    .map_err(|_| LocalAgentFailure::Internal)
}

enum CommonIssue {
    InvalidConfiguration,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    AuthorizationIndeterminate,
    #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
    UnauthenticatedPrincipal,
    ConnectionUnavailable,
    CredentialUnavailable,
    AdmissionExhausted,
    IdempotencyConflict,
    OutcomeUnknown,
    RecoveryUnavailable,
    TimedOut,
}

fn common_issue(
    kind: CommonIssue,
    operation_id: Option<&OperationIdV1>,
) -> Result<Vec<u8>, LocalAgentFailure> {
    let (
        code,
        operation,
        stage,
        summary,
        retry,
        effect,
        recommended_action,
        entered,
        execution_reference,
        causes,
    ) = match kind {
        CommonIssue::InvalidConfiguration => (
            "core.invalid-configuration",
            "create",
            "configuration",
            "The deployment-owned profile configuration changed before provider entry.",
            RetryClass::Never,
            EffectState::NotApplied,
            RecommendedAction::CorrectConfiguration,
            boundaries(false, false, false),
            None,
            vec![CauseCategory::CorruptState],
        ),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        CommonIssue::AuthorizationIndeterminate => (
            "core.authorization-indeterminate",
            "verify",
            "authorization",
            "A required authorization fact was unavailable before any effect.",
            RetryClass::Conditional,
            EffectState::NotApplied,
            RecommendedAction::SatisfyCondition,
            boundaries(false, false, false),
            None,
            vec![CauseCategory::Unavailable],
        ),
        #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
        CommonIssue::UnauthenticatedPrincipal => (
            "core.unauthenticated-principal",
            "create",
            "authentication",
            "The request principal could not be authenticated before any effect.",
            RetryClass::Never,
            EffectState::NotApplied,
            RecommendedAction::CorrectInput,
            boundaries(false, false, false),
            None,
            vec![CauseCategory::Unavailable],
        ),
        CommonIssue::ConnectionUnavailable => (
            "connection.unavailable",
            "execute",
            "connection-resolution",
            "No authorized active provider connection is available.",
            RetryClass::Never,
            EffectState::NotApplied,
            RecommendedAction::CorrectConfiguration,
            boundaries(false, false, false),
            None,
            vec![CauseCategory::Unavailable],
        ),
        CommonIssue::CredentialUnavailable => (
            "connection.credential-unavailable",
            "execute",
            "credential",
            "The bound credential is unavailable before provider entry.",
            RetryClass::Safe,
            EffectState::NotApplied,
            RecommendedAction::RetryExecution,
            boundaries(true, true, false),
            operation_id.map(|value| value.as_str().to_owned()),
            vec![CauseCategory::Unavailable],
        ),
        CommonIssue::AdmissionExhausted => (
            "operation.admission-exhausted",
            "execute",
            "admission",
            "Operation admission capacity is exhausted before provider entry.",
            RetryClass::Conditional,
            EffectState::NotApplied,
            RecommendedAction::RetryExecution,
            boundaries(false, false, false),
            None,
            vec![CauseCategory::LimitExceeded],
        ),
        CommonIssue::IdempotencyConflict => (
            "operation.idempotency-conflict",
            "execute",
            "reservation",
            "The idempotency key is bound to a different operation commitment.",
            RetryClass::Unknown,
            EffectState::Possible,
            RecommendedAction::ResumeAndReconcile,
            boundaries(true, true, true),
            operation_id.map(|value| value.as_str().to_owned()),
            vec![CauseCategory::Conflict],
        ),
        CommonIssue::OutcomeUnknown => (
            "operation.outcome-unknown",
            "execute",
            "provider",
            "The provider may have applied the operation; recover it instead of retrying.",
            RetryClass::Unknown,
            EffectState::Possible,
            RecommendedAction::ResumeAndReconcile,
            boundaries(true, true, true),
            operation_id.map(|value| value.as_str().to_owned()),
            vec![CauseCategory::Unknown],
        ),
        CommonIssue::RecoveryUnavailable => (
            "operation.recovery-unavailable",
            "recover",
            "reconciliation",
            "Recovery could not establish the existing operation effect.",
            RetryClass::Unknown,
            EffectState::Possible,
            RecommendedAction::ResumeAndReconcile,
            boundaries(true, true, true),
            operation_id.map(|value| value.as_str().to_owned()),
            vec![CauseCategory::Unavailable],
        ),
        CommonIssue::TimedOut => (
            "operation.timed-out",
            "execute",
            "pre-provider",
            "The accepted operation was released before provider entry.",
            RetryClass::Safe,
            EffectState::NotApplied,
            RecommendedAction::RetryExecution,
            boundaries(true, false, false),
            operation_id.map(|value| value.as_str().to_owned()),
            vec![CauseCategory::Timeout],
        ),
    };
    ErrorEnvelope::parse(ErrorEnvelopeInput {
        code: code.into(),
        operation: operation.into(),
        stage: stage.into(),
        summary: summary.into(),
        correlation_id: operation_id.map_or_else(
            || "local-agent".to_owned(),
            |value| value.as_str().to_owned(),
        ),
        retry,
        effect,
        entered,
        recommended_action,
        execution_reference,
        decision_reference: None,
        receipt_reference: None,
        causes,
    })
    .and_then(|value| value.to_canonical_cbor())
    .map_err(|_| LocalAgentFailure::Internal)
}

fn terminal_receipt_integrity_issue(
    record: &JournalRecordV1,
) -> Result<Vec<u8>, LocalAgentFailure> {
    let operation_id = record.operation_id().as_str().to_owned();
    let effect = match record.projection().effect() {
        OperationEffectV1::NotApplied => EffectState::NotApplied,
        OperationEffectV1::Possible => EffectState::Possible,
        OperationEffectV1::Applied => EffectState::Applied,
    };
    let verified_reference = |receipt: &auths_stores::JournalReceiptV1| {
        auths_receipts::portable_receipt_id(receipt.bytes())
            .ok()
            .filter(|computed| computed == receipt.receipt_id())
    };
    let decision_reference = record.receipts().first().and_then(verified_reference);
    let receipt_reference = (effect != EffectState::NotApplied)
        .then(|| record.receipts().get(1).and_then(verified_reference))
        .flatten();
    ErrorEnvelope::parse(ErrorEnvelopeInput {
        code: "core.terminal-receipt-integrity-failed".into(),
        operation: "resume".into(),
        stage: "receipt".into(),
        summary: "The retained terminal receipt does not match durable operation truth.".into(),
        correlation_id: operation_id.clone(),
        retry: RetryClass::Never,
        effect,
        entered: boundaries(true, record.provider_entered(), record.provider_entered()),
        recommended_action: RecommendedAction::ContactSupport,
        execution_reference: Some(operation_id),
        decision_reference,
        receipt_reference,
        causes: vec![CauseCategory::CorruptState],
    })
    .and_then(|value| value.to_canonical_cbor())
    .map_err(|_| LocalAgentFailure::Internal)
}

const fn boundaries(state: bool, credential: bool, provider: bool) -> EnteredBoundaries {
    EnteredBoundaries {
        approval: state,
        signer: state,
        state,
        credential,
        provider,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_connections::{
        ConnectionCredentialStore as _, ConnectionId, ConnectionState,
        ProviderConnectionAdapter as _, RegistryLimits, SecretBytes,
    };
    use auths_model::{ProfileId, ProfileRef};
    use auths_stores::OperationJournalLimitsV1;
    use minicbor::Decoder;
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tempfile::tempdir;

    const PROFILE_ID: &str = "auths.opentofu.saved-plan-apply";
    const PROFILE_VERSION: u16 = 1;
    const RUNTIME_DIGEST: [u8; 32] =
        auths_opentofu::generated::profile_routes::SAVED_PLANS_APPLY_RUNTIME_DIGEST;

    struct SyntheticBridge {
        provider_calls: AtomicUsize,
        pre_entry_releases: AtomicUsize,
        fail_execution_claims: AtomicBool,
        fail_seal_after_reservation: AtomicBool,
        observation_kind: AtomicUsize,
        fail_first_call: bool,
        requires_connection: bool,
        deny_seal: bool,
        block_provider_call: AtomicBool,
        provider_call_started: tokio::sync::Notify,
        continue_provider_call: tokio::sync::Notify,
    }

    impl SyntheticBridge {
        fn new(fail_first_call: bool, requires_connection: bool, deny_seal: bool) -> Self {
            Self {
                provider_calls: AtomicUsize::new(0),
                pre_entry_releases: AtomicUsize::new(0),
                fail_execution_claims: AtomicBool::new(false),
                fail_seal_after_reservation: AtomicBool::new(false),
                observation_kind: AtomicUsize::new(0),
                fail_first_call,
                requires_connection,
                deny_seal,
                block_provider_call: AtomicBool::new(false),
                provider_call_started: tokio::sync::Notify::new(),
                continue_provider_call: tokio::sync::Notify::new(),
            }
        }

        fn completed_observation(&self, reconciled: bool) -> ProfileObservation {
            if !reconciled {
                match self.observation_kind.load(Ordering::SeqCst) {
                    1 => {
                        return ProfileObservation {
                            bytes: b"provider-observation-partial".to_vec(),
                            conclusion: ProfileConclusion::Partial {
                                value: b"canonical-partial".to_vec(),
                                issue: vec![0xa0],
                                profile_state: b"partial-state".to_vec(),
                            },
                        };
                    }
                    2 => {
                        return ProfileObservation {
                            bytes: b"provider-observation-not-applied".to_vec(),
                            conclusion: ProfileConclusion::NotApplied {
                                issue: vec![0xa0],
                                profile_state: b"not-applied-state".to_vec(),
                            },
                        };
                    }
                    3 => {
                        return ProfileObservation {
                            bytes: b"provider-observation-indeterminate".to_vec(),
                            conclusion: ProfileConclusion::RecoveryRequired {
                                issue: vec![0xa0],
                                progress: Some(b"recovery-progress".to_vec()),
                                profile_state: b"recovery-state".to_vec(),
                            },
                        };
                    }
                    _ => {}
                }
            }
            ProfileObservation {
                bytes: if reconciled {
                    b"reconciled-observation".to_vec()
                } else {
                    b"provider-observation".to_vec()
                },
                conclusion: ProfileConclusion::Completed {
                    value: b"canonical-success".to_vec(),
                    profile_state: if reconciled {
                        b"reconciled-state".to_vec()
                    } else {
                        b"completed-state".to_vec()
                    },
                },
            }
        }
    }

    #[async_trait]
    impl TestStaticLocalProfileBridge for SyntheticBridge {
        fn profile(&self) -> OperationProfileV1 {
            OperationProfileV1::new(PROFILE_ID, PROFILE_VERSION, RUNTIME_DIGEST).unwrap()
        }

        fn connection_requirement(&self) -> Option<BridgeConnectionRequirement> {
            self.requires_connection
                .then_some(BridgeConnectionRequirement {
                    provider_kind: "stripe",
                    contract: "auths.stripe.connection/1",
                    descriptor_schema: "auths.stripe.connection-descriptor/1",
                    credential_scope: "stripe.refunds.write/1",
                })
        }

        fn build_execution_receipt_claims(
            &self,
            facts: ProfileExecutionReceiptFacts<'_>,
        ) -> Result<Vec<u8>, ProfileBridgeError> {
            if self.fail_execution_claims.load(Ordering::SeqCst) {
                return Err(ProfileBridgeError::Invalid);
            }
            test_receipt_claims(
                facts.binding.profile(),
                ProfileReceiptClaimPhase::Execution,
                "test.sealed-command",
                facts.sealed_command,
            )
        }

        fn prepare(
            &self,
            _context: &LocalOperationContext,
            _workflow_id: &str,
            profile_input: &[u8],
            connection: Option<&ConnectionBinding>,
            _preparation_evidence: Option<&[u8]>,
            _now_unix_seconds: u64,
        ) -> Result<ProfilePreparation, ProfileBridgeError> {
            assert_eq!(connection.is_some(), self.requires_connection);
            let commitment: [u8; 32] = Sha256::digest(profile_input).into();
            Ok(ProfilePreparation {
                canonical_input_commitment: commitment,
                canonical_action_commitment: commitment,
                configuration_commitment: [9; 32],
                canonical_action: profile_input.to_vec(),
                decision_reason: "test.authorized".into(),
                profile_state: b"prepared-state".to_vec(),
                kind: ProfilePreparationKind::Ready,
            })
        }

        async fn seal_provider_call(
            &self,
            _context: &LocalOperationContext,
            record: &JournalRecordV1,
            _now_unix_seconds: u64,
        ) -> Result<SealedProfileCall, ProfileBridgeError> {
            if self.deny_seal {
                return Err(ProfileBridgeError::PreEntry(vec![3]));
            }
            if self.fail_seal_after_reservation.load(Ordering::SeqCst) {
                return Err(ProfileBridgeError::Invalid);
            }
            assert!(matches!(
                record.profile_state(),
                b"prepared-state" | b"command-state"
            ));
            Ok(SealedProfileCall {
                command: b"sealed-command".to_vec(),
                profile_state: b"command-state".to_vec(),
            })
        }

        fn release_pre_entry(
            &self,
            _context: &LocalOperationContext,
            record: &JournalRecordV1,
        ) -> Result<(), ProfileBridgeError> {
            assert_eq!(record.projection().effect(), OperationEffectV1::NotApplied);
            if record.sealed_command().is_some()
                || self.fail_seal_after_reservation.load(Ordering::SeqCst)
            {
                self.pre_entry_releases.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }

        async fn call_provider(
            &self,
            _context: &LocalOperationContext,
            call: &SealedProfileCall,
            credential: Option<&ProviderCredentialLease>,
            _now_unix_seconds: u64,
        ) -> Result<Vec<u8>, ProfileBridgeError> {
            assert_eq!(credential.is_some(), self.requires_connection);
            assert_eq!(call.command, b"sealed-command");
            if self.block_provider_call.load(Ordering::SeqCst) {
                self.provider_call_started.notify_one();
                self.continue_provider_call.notified().await;
            }
            let attempt = self.provider_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_first_call && attempt == 0 {
                return Err(ProfileBridgeError::PossibleWithProfileState {
                    issue: vec![3],
                    profile_state: b"outcome-unknown-state".to_vec(),
                });
            }
            Ok(b"provider-result".to_vec())
        }

        fn observe_provider_result(
            &self,
            _context: &LocalOperationContext,
            record: &JournalRecordV1,
            provider_result: &[u8],
            _now_unix_seconds: u64,
        ) -> Result<ProfileObservation, ProfileBridgeError> {
            assert_eq!(provider_result, b"provider-result");
            assert_eq!(record.provider_result(), Some(provider_result));
            Ok(self.completed_observation(false))
        }

        async fn reconcile(
            &self,
            _context: &LocalOperationContext,
            record: &JournalRecordV1,
            credential: Option<&ProviderCredentialLease>,
            _now_unix_seconds: u64,
        ) -> Result<ProfileObservation, ProfileBridgeError> {
            assert_eq!(credential.is_some(), self.requires_connection);
            assert_eq!(
                record.projection().state(),
                OperationStateV1::RecoveryRequired
            );
            Ok(self.completed_observation(true))
        }
    }

    struct Fixture {
        executor: JournaledLocalExecutor,
        journal: Arc<PersistentOperationJournal>,
        connections: Arc<PersistentConnectionStore>,
        credentials: Arc<PersistentCredentialStore>,
        bridge: Arc<SyntheticBridge>,
        context: LocalOperationContext,
    }

    fn fixture_at(directory: &std::path::Path, fail_first_call: bool) -> Fixture {
        fixture_at_with_connection(directory, fail_first_call, false)
    }

    fn fixture_at_with_connection(
        directory: &std::path::Path,
        fail_first_call: bool,
        requires_connection: bool,
    ) -> Fixture {
        fixture_at_with_options(directory, fail_first_call, requires_connection, false)
    }

    fn fixture_at_with_options(
        directory: &std::path::Path,
        fail_first_call: bool,
        requires_connection: bool,
        deny_seal: bool,
    ) -> Fixture {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let profile = OperationProfileV1::new(PROFILE_ID, PROFILE_VERSION, RUNTIME_DIGEST).unwrap();
        let limits = OperationJournalLimitsV1::new(
            120,
            16,
            8,
            256 * 1024 * 1024,
            100_000,
            2_592_000,
            2_592_000,
            4,
            65_536,
            262_144,
        )
        .unwrap();
        let journal = Arc::new(
            PersistentOperationJournal::open(
                directory.join("operations.cbor"),
                [(profile, limits)],
            )
            .unwrap(),
        );
        let connections = Arc::new(
            PersistentConnectionStore::open(
                directory.join("connections.cbor"),
                RegistryLimits {
                    maximum_records: NonZeroUsize::new(8).unwrap(),
                    maximum_encoded_bytes: NonZeroUsize::new(1_048_576).unwrap(),
                },
            )
            .unwrap(),
        );
        let credentials =
            Arc::new(PersistentCredentialStore::open(directory.join("credentials.cbor")).unwrap());
        let recovery =
            Arc::new(RecoveryHandleSigner::from_seed("test-recovery", [7; 32], []).unwrap());
        let receipts =
            Arc::new(ReceiptAttestor::from_root_seed("test-recovery", &[7; 32]).unwrap());
        let bridge = Arc::new(SyntheticBridge::new(
            fail_first_call,
            requires_connection,
            deny_seal,
        ));
        let dynamic: Arc<dyn TestStaticLocalProfileBridge> = bridge.clone();
        let executor = JournaledLocalExecutor::new_for_tests(
            Arc::clone(&journal),
            Arc::clone(&connections),
            Arc::clone(&credentials),
            recovery,
            receipts,
            [dynamic],
        )
        .unwrap();
        let profile_ref =
            ProfileRef::new(ProfileId::parse(PROFILE_ID).unwrap(), PROFILE_VERSION).unwrap();
        let connections_config = if requires_connection {
            let config = auths_config::AgentConfig::from_toml(
                r#"
[agent]
authority_root = "/var/lib/auths/authorities"

[agent.receipt_signing.decision]
algorithm = "Ed25519"
key_id = "decision-2026-01"
verification_method = "did:key:auths-receipt-decision#decision-2026-01"
public_key_base64url = "1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"
seed_file = "/var/lib/auths/receipt-decision.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.receipt_signing.execution]
algorithm = "Ed25519"
key_id = "execution-2026-01"
verification_method = "did:key:auths-receipt-execution#execution-2026-01"
public_key_base64url = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"
seed_file = "/var/lib/auths/receipt-execution.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.authority_sources.test-authority]
kind = "sealed-file-v1"
path = "/var/lib/auths/authorities/test.cbor"

[[agent.workloads]]
id = "test-workload"
principal = "did:example:test-workload"
authority_source = "test-authority"
allowed_profiles = ["auths.opentofu.saved-plan-apply/1"]
connections = [{ provider = "stripe", alias = "billing", default = true }]

[agent.workloads.selector]
kind = "posix"
uid = 10001
"#,
                auths_config::AgentPlatform::Linux,
            )
            .unwrap();
            config.workloads()[0].connections().to_vec()
        } else {
            Vec::new()
        };
        let context = LocalOperationContext {
            workload_id: Arc::from("test-workload"),
            principal: Arc::from("did:example:test-workload"),
            profile: SessionProfileKey::new(PROFILE_ID, PROFILE_VERSION).unwrap(),
            connections: Arc::new(connections_config),
            authority: Arc::new(crate::WorkloadAuthority::for_test(
                "did:example:test-workload",
                profile_ref,
            )),
            profile_configuration: None,
            profile_state_root: Arc::new(directory.join("profile-state")),
            #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
            qualification_fault: None,
        };
        Fixture {
            executor,
            journal,
            connections,
            credentials,
            bridge,
            context,
        }
    }

    fn fixture(fail_first_call: bool) -> (tempfile::TempDir, Fixture) {
        let directory = tempdir().unwrap();
        let value = fixture_at(directory.path(), fail_first_call);
        (directory, value)
    }

    fn request_id(byte: u8) -> ClientRequestId {
        ClientRequestId::from_bytes([byte; 16])
    }

    fn prepare_request() -> PrepareOperationRequest {
        PrepareOperationRequest::new(
            request_id(1),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"canonical-input".to_vec(),
            None,
            1024,
        )
        .unwrap()
    }

    #[test]
    fn workflow_identity_is_stable_only_within_the_exact_principal_and_profile_scope() {
        let (_directory, fixture) = fixture(false);
        let profile = OperationProfileV1::new(PROFILE_ID, PROFILE_VERSION, RUNTIME_DIGEST).unwrap();
        let first = prepare_request();
        let replay = PrepareOperationRequest::new(
            request_id(9),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"different-request-body".to_vec(),
            None,
            1024,
        )
        .unwrap();
        assert_eq!(
            workflow_identity(&fixture.context, &profile, &first),
            workflow_identity(&fixture.context, &profile, &replay)
        );

        let mut other_principal = fixture.context.clone();
        other_principal.principal = Arc::from("did:example:other-workload");
        assert_ne!(
            workflow_identity(&fixture.context, &profile, &first),
            workflow_identity(&other_principal, &profile, &first)
        );
        let other_profile =
            OperationProfileV1::new("auths.example.other", PROFILE_VERSION, RUNTIME_DIGEST)
                .unwrap();
        assert_ne!(
            workflow_identity(&fixture.context, &profile, &first),
            workflow_identity(&fixture.context, &other_profile, &first)
        );

        let without_key = |byte| {
            PrepareOperationRequest::new(
                request_id(byte),
                None,
                RUNTIME_DIGEST,
                b"canonical-input".to_vec(),
                None,
                1024,
            )
            .unwrap()
        };
        assert_ne!(
            workflow_identity(&fixture.context, &profile, &without_key(1)),
            workflow_identity(&fixture.context, &profile, &without_key(2))
        );
        assert!(!workflow_identity(&fixture.context, &profile, &first).contains("test-operation"));
    }

    fn ready_fields(bytes: &[u8]) -> (OperationId, [u8; 32], Vec<u8>) {
        let mut decoder = Decoder::new(bytes);
        assert_eq!(decoder.map().unwrap(), Some(8));
        let mut operation = None;
        let mut commitment = None;
        let mut recovery = None;
        for _ in 0..8 {
            match decoder.u8().unwrap() {
                4 => operation = Some(OperationId::parse(decoder.str().unwrap()).unwrap()),
                5 => {
                    let bytes = decoder.bytes().unwrap();
                    commitment = Some(<[u8; 32]>::try_from(bytes).unwrap());
                }
                7 => recovery = Some(decoder.bytes().unwrap().to_vec()),
                _ => decoder.skip().unwrap(),
            }
        }
        (operation.unwrap(), commitment.unwrap(), recovery.unwrap())
    }

    fn outcome_kind(bytes: &[u8]) -> String {
        let mut decoder = Decoder::new(bytes);
        let length = decoder.map().unwrap().unwrap();
        for _ in 0..length {
            let key = decoder.u8().unwrap();
            if key == 2 {
                return decoder.str().unwrap().to_owned();
            }
            decoder.skip().unwrap();
        }
        panic!("outcome kind missing")
    }

    fn outcome_request_id(bytes: &[u8]) -> [u8; 16] {
        let mut decoder = Decoder::new(bytes);
        let length = decoder.map().unwrap().unwrap();
        for _ in 0..length {
            let key = decoder.u8().unwrap();
            if key == 3 {
                return <[u8; 16]>::try_from(decoder.bytes().unwrap()).unwrap();
            }
            decoder.skip().unwrap();
        }
        panic!("outcome request ID missing")
    }

    fn receipt_integrity_truth(bytes: &[u8]) -> (String, String, bool) {
        let mut decoder = Decoder::new(bytes);
        assert_eq!(decoder.map().unwrap(), Some(9));
        let mut state = None;
        let mut effect = None;
        let mut terminal = None;
        for _ in 0..9 {
            match decoder.u8().unwrap() {
                6 => state = Some(decoder.str().unwrap().to_owned()),
                7 => effect = Some(decoder.str().unwrap().to_owned()),
                8 => terminal = Some(decoder.bool().unwrap()),
                _ => decoder.skip().unwrap(),
            }
        }
        (state.unwrap(), effect.unwrap(), terminal.unwrap())
    }

    #[tokio::test]
    async fn provider_result_and_observation_are_distinct_durable_checkpoints() {
        let (_directory, fixture) = fixture(false);
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&ready), "ready");
        let (operation, commitment, _recovery) = ready_fields(&ready);
        let result = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&result), "completed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
        let stored = fixture
            .journal
            .status(
                fixture.context.principal.as_ref(),
                &OperationIdV1::parse(operation.as_str()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let JournalStatusV1::Record(stored) = stored else {
            panic!("terminal full record unexpectedly compacted")
        };
        assert_eq!(
            stored.provider_result(),
            Some(b"provider-result".as_slice())
        );
        assert_eq!(stored.observations(), &[b"provider-observation".to_vec()]);
        assert_eq!(stored.projection().state(), OperationStateV1::Completed);

        let replay = fixture
            .executor
            .execute(
                fixture.context,
                ExecuteOperationRequest::new(request_id(3), operation, commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "completed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn receipt_claim_failure_quarantines_without_changing_provider_truth() {
        let cases = [
            (0, OperationStateV1::Completed, "applied", true),
            (1, OperationStateV1::Partial, "applied", true),
            (2, OperationStateV1::NotApplied, "not-applied", true),
            (3, OperationStateV1::RecoveryRequired, "possible", false),
        ];
        for (kind, state, effect, terminal) in cases {
            let directory = tempdir().unwrap();
            let fixture = fixture_at(directory.path(), false);
            fixture
                .bridge
                .observation_kind
                .store(kind, Ordering::SeqCst);
            let ready = fixture
                .executor
                .prepare(fixture.context.clone(), prepare_request())
                .await
                .unwrap();
            let (operation, commitment, recovery) = ready_fields(&ready);
            fixture
                .bridge
                .fail_execution_claims
                .store(true, Ordering::SeqCst);
            let same_turn = fixture
                .executor
                .execute(
                    fixture.context.clone(),
                    ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("receipt-integrity case {kind} failed to execute: {error:?}")
                });
            assert_eq!(outcome_kind(&same_turn), "receipt-integrity-failed");
            assert_eq!(
                receipt_integrity_truth(&same_turn),
                (state_text(state).into(), effect.into(), terminal)
            );
            assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
            let stored = record(&fixture, &operation);
            assert!(stored.receipt_integrity_failed());
            assert_eq!(stored.projection().state(), state);
            assert_eq!(stored.projection().is_terminal(), terminal);

            let replay = fixture
                .executor
                .execute(
                    fixture.context.clone(),
                    ExecuteOperationRequest::new(request_id(3), operation.clone(), commitment),
                )
                .await
                .unwrap();
            assert_eq!(outcome_kind(&replay), "receipt-integrity-failed");
            let status = fixture
                .executor
                .status(fixture.context.clone(), operation.clone())
                .await
                .unwrap();
            assert_eq!(outcome_kind(&status), "receipt-integrity-failed");
            let recovered = fixture
                .executor
                .recover(
                    fixture.context.clone(),
                    Some(operation.clone()),
                    RecoverOperationRequest::new(request_id(4), recovery.clone()).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(outcome_kind(&recovered), "receipt-integrity-failed");
            let exported = fixture
                .executor
                .receipts(fixture.context.clone(), operation.clone())
                .await
                .unwrap();
            assert_eq!(outcome_kind(&exported), "receipt-integrity-failed");
            assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

            drop(fixture);
            let reopened = fixture_at(directory.path(), false);
            let status = reopened
                .executor
                .status(reopened.context.clone(), operation.clone())
                .await
                .unwrap();
            assert_eq!(outcome_kind(&status), "receipt-integrity-failed");
            assert_eq!(
                receipt_integrity_truth(&status),
                (state_text(state).into(), effect.into(), terminal)
            );
            let exported = reopened
                .executor
                .receipts(reopened.context.clone(), operation)
                .await
                .unwrap();
            assert_eq!(outcome_kind(&exported), "receipt-integrity-failed");
            assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn caller_idempotency_replays_terminal_without_another_provider_call() {
        let (_directory, fixture) = fixture(false);
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, _recovery) = ready_fields(&ready);
        let completed = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation, commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&completed), "completed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

        let replay_request = PrepareOperationRequest::new(
            request_id(3),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"canonical-input".to_vec(),
            None,
            1024,
        )
        .unwrap();
        let replay = fixture
            .executor
            .prepare(fixture.context.clone(), replay_request)
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "completed");
        assert_eq!(outcome_request_id(&replay), [3; 16]);
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

        let changed_request = PrepareOperationRequest::new(
            request_id(4),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"changed-input".to_vec(),
            None,
            1024,
        )
        .unwrap();
        let conflict = fixture
            .executor
            .prepare(fixture.context, changed_request)
            .await
            .unwrap();
        assert_eq!(outcome_kind(&conflict), "conflict");
        assert_eq!(outcome_request_id(&conflict), [4; 16]);
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalid_decision_receipt_fails_before_provider_entry() {
        let (_directory, fixture) = fixture(false);
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, _recovery) = ready_fields(&ready);
        let bridge: Arc<dyn TestStaticLocalProfileBridge> = fixture.bridge.clone();
        let executor = JournaledLocalExecutor::new_for_tests(
            Arc::clone(&fixture.journal),
            Arc::clone(&fixture.connections),
            Arc::clone(&fixture.credentials),
            Arc::clone(&fixture.executor.recovery),
            Arc::new(ReceiptAttestor::from_root_seed("wrong-receipts", &[8; 32]).unwrap()),
            [bridge],
        )
        .unwrap();

        let outcome = executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&outcome), "receipt-integrity-failed");
        assert_eq!(
            receipt_integrity_truth(&outcome),
            ("ready".into(), "not-applied".into(), false)
        );
        let replay = executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(3), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "receipt-integrity-failed");
        let status = executor
            .status(fixture.context.clone(), operation.clone())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&status), "receipt-integrity-failed");
        let exported = executor
            .receipts(fixture.context.clone(), operation)
            .await
            .unwrap();
        assert_eq!(outcome_kind(&exported), "receipt-integrity-failed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execute_and_recover_are_serialized_across_the_provider_call() {
        let (_directory, fixture) = fixture(false);
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, recovery) = ready_fields(&ready);
        fixture
            .bridge
            .block_provider_call
            .store(true, Ordering::SeqCst);

        let execute_operation = operation.clone();
        let execute = fixture.executor.execute(
            fixture.context.clone(),
            ExecuteOperationRequest::new(request_id(2), execute_operation, commitment),
        );
        let concurrent_recovery = async {
            fixture.bridge.provider_call_started.notified().await;
            let recovery = fixture.executor.recover(
                fixture.context.clone(),
                Some(operation),
                RecoverOperationRequest::new(request_id(3), recovery).unwrap(),
            );
            tokio::pin!(recovery);
            tokio::select! {
                value = &mut recovery => panic!("recovery crossed an active provider call: {value:?}"),
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
            fixture
                .bridge
                .block_provider_call
                .store(false, Ordering::SeqCst);
            fixture.bridge.continue_provider_call.notify_one();
            recovery.await.unwrap()
        };
        let (executed, recovered) = tokio::join!(execute, concurrent_recovery);
        assert_eq!(outcome_kind(&executed.unwrap()), "completed");
        assert_eq!(outcome_kind(&recovered), "completed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn recovery_advances_possible_state_without_a_second_provider_call() {
        let (_directory, fixture) = fixture(true);
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, recovery) = ready_fields(&ready);
        let unknown = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&unknown), "recovery-required");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

        let uncertain = record(&fixture, &operation);
        assert_eq!(uncertain.profile_state(), b"outcome-unknown-state");
        assert_eq!(
            uncertain
                .execution_receipt_basis()
                .expect("indeterminate receipt basis")
                .profile_state(),
            b"outcome-unknown-state"
        );

        let recovered = fixture
            .executor
            .recover(
                fixture.context.clone(),
                Some(operation.clone()),
                RecoverOperationRequest::new(request_id(3), recovery).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&recovered), "completed");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

        let stored = fixture
            .journal
            .status(
                fixture.context.principal.as_ref(),
                &OperationIdV1::parse(operation.as_str()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let JournalStatusV1::Record(stored) = stored else {
            panic!("recovered full record unexpectedly compacted")
        };
        assert_eq!(stored.provider_result(), None);
        assert_eq!(stored.observations(), &[b"reconciled-observation".to_vec()]);
        assert_eq!(stored.completion(), Some(JournalCompletionV1::Reconciled));
    }

    fn record(fixture: &Fixture, operation: &OperationId) -> JournalRecordV1 {
        let status = fixture
            .journal
            .status(
                fixture.context.principal.as_ref(),
                &OperationIdV1::parse(operation.as_str()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let JournalStatusV1::Record(record) = status else {
            panic!("checkpoint unexpectedly compacted")
        };
        record
    }

    fn mutate(
        fixture: &Fixture,
        record: &JournalRecordV1,
        mutation: OperationMutationV1,
    ) -> JournalRecordV1 {
        fixture
            .journal
            .mutate_operation(
                fixture.context.principal.as_ref(),
                record.operation_id(),
                record.revision(),
                mutation,
                record.updated_at_unix_seconds(),
            )
            .unwrap()
    }

    fn begin_execution(fixture: &Fixture, record: &JournalRecordV1) -> JournalRecordV1 {
        mutate(
            fixture,
            record,
            OperationMutationV1::BeginExecution {
                profile_state: record.profile_state().to_vec(),
                sealed_command: record.sealed_command().unwrap().to_vec(),
            },
        )
    }

    fn mark_provider_entered(fixture: &Fixture, record: &JournalRecordV1) -> JournalRecordV1 {
        let executing = begin_execution(fixture, record);
        let rechecked = mutate(
            fixture,
            &executing,
            OperationMutationV1::RecordPreEntryRecheck {
                profile_state: executing.profile_state().to_vec(),
            },
        );
        mutate(
            fixture,
            &rechecked,
            OperationMutationV1::MarkProviderEntered,
        )
    }

    async fn prepared_checkpoint(fixture: &Fixture) -> (OperationId, Vec<u8>, JournalRecordV1) {
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, _commitment, recovery) = ready_fields(&ready);
        let record = record(fixture, &operation);
        (operation, recovery, record)
    }

    async fn recover_after_reopen(
        directory: &std::path::Path,
        operation: OperationId,
        recovery: Vec<u8>,
        expected_kind: &str,
    ) -> Fixture {
        let reopened = fixture_at(directory, false);
        let outcome = reopened
            .executor
            .recover(
                reopened.context.clone(),
                Some(operation),
                RecoverOperationRequest::new(request_id(9), recovery).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&outcome), expected_kind);
        reopened
    }

    async fn install_stripe_connection(fixture: &Fixture) -> ConnectionRecord {
        let descriptor =
            include_bytes!("../../../integrations/auths-stripe/fixtures/connection/v1/valid.json")
                .strip_suffix(b"\n")
                .unwrap_or(include_bytes!(
                    "../../../integrations/auths-stripe/fixtures/connection/v1/valid.json"
                ))
                .to_vec();
        let adapter = auths_stripe::connection::StripeConnectionAdapter::new();
        let validated = adapter.validate_descriptor(&descriptor).unwrap();
        let generation = NonZeroU64::new(1).unwrap();
        let connection_id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let credential_commitment = fixture
            .credentials
            .install(
                &connection_id,
                generation,
                SecretBytes::new(b"rk_test_initial_recovery_secret".to_vec()).unwrap(),
            )
            .await
            .unwrap();
        let record = ConnectionRecord::new(
            ProviderKind::parse("stripe").unwrap(),
            ConnectionAlias::parse("billing").unwrap(),
            connection_id,
            SemanticId::parse("auths.stripe.connection/1").unwrap(),
            SemanticId::parse("auths.stripe.connection-descriptor/1").unwrap(),
            descriptor,
            *validated.account_commitment(),
            *credential_commitment.as_bytes(),
            generation,
            ConnectionState::Active,
            vec!["test-workload".to_owned()],
            vec![
                ConnectionProfile::new(SemanticId::parse(PROFILE_ID).unwrap(), PROFILE_VERSION)
                    .unwrap(),
            ],
            10,
            10,
            None,
        )
        .unwrap();
        fixture.connections.insert(record.clone()).unwrap();
        record
    }

    async fn possible_connected_operation(
        fixture: &Fixture,
    ) -> (OperationId, Vec<u8>, ConnectionRecord) {
        let connection = install_stripe_connection(fixture).await;
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, recovery) = ready_fields(&ready);
        let unknown = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&unknown), "recovery-required");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
        (operation, recovery, connection)
    }

    #[tokio::test]
    async fn seal_denial_happens_before_any_credential_lease() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_options(directory.path(), false, true, true);
        install_stripe_connection(&fixture).await;
        let denied = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&denied), "not-applied");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_seal_releases_before_an_exact_ready_retry() {
        let (_directory, fixture) = fixture(false);
        fixture
            .bridge
            .fail_seal_after_reservation
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            fixture
                .executor
                .prepare(fixture.context.clone(), prepare_request())
                .await,
            Err(LocalAgentFailure::Internal)
        ));
        assert_eq!(fixture.bridge.pre_entry_releases.load(Ordering::SeqCst), 1);

        fixture
            .bridge
            .fail_seal_after_reservation
            .store(false, Ordering::SeqCst);
        let replay = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "ready");
        assert_eq!(fixture.bridge.pre_entry_releases.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn credential_failure_releases_profile_state_before_concluding_pre_entry() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_options(directory.path(), false, true, false);
        let connection = install_stripe_connection(&fixture).await;
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, _recovery) = ready_fields(&ready);
        fixture
            .credentials
            .revoke(connection.connection_id(), connection.generation())
            .await
            .unwrap();

        let unavailable = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(18), operation, commitment),
            )
            .await
            .unwrap();

        assert_eq!(outcome_kind(&unavailable), "unavailable");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.bridge.pre_entry_releases.load(Ordering::SeqCst), 1);
    }

    async fn recover_connected_after_reopen(
        directory: &std::path::Path,
        operation: OperationId,
        recovery: Vec<u8>,
    ) -> (Fixture, Vec<u8>) {
        let reopened = fixture_at_with_connection(directory, false, true);
        let outcome = reopened
            .executor
            .recover(
                reopened.context.clone(),
                Some(operation),
                RecoverOperationRequest::new(request_id(9), recovery).unwrap(),
            )
            .await
            .unwrap();
        (reopened, outcome)
    }

    #[tokio::test]
    async fn restart_before_provider_entry_releases_without_provider_call() {
        let (directory, fixture) = fixture(false);
        let (operation, recovery, ready) = prepared_checkpoint(&fixture).await;
        let _executing = begin_execution(&fixture, &ready);
        drop(fixture);

        let reopened =
            recover_after_reopen(directory.path(), operation, recovery, "not-applied").await;
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopened.bridge.pre_entry_releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn restart_after_provider_entry_reconciles_without_provider_retry() {
        let (directory, fixture) = fixture(false);
        let (operation, recovery, ready) = prepared_checkpoint(&fixture).await;
        let _entered = mark_provider_entered(&fixture, &ready);
        drop(fixture);

        let reopened =
            recover_after_reopen(directory.path(), operation, recovery, "completed").await;
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn restart_after_durable_provider_result_observes_without_provider_retry() {
        let (directory, fixture) = fixture(false);
        let (operation, recovery, ready) = prepared_checkpoint(&fixture).await;
        let entered = mark_provider_entered(&fixture, &ready);
        let _result = mutate(
            &fixture,
            &entered,
            OperationMutationV1::RecordProviderResult {
                bytes: b"provider-result".to_vec(),
            },
        );
        drop(fixture);

        let reopened =
            recover_after_reopen(directory.path(), operation, recovery, "completed").await;
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn restart_after_durable_observation_does_not_duplicate_it() {
        let (directory, fixture) = fixture(false);
        let (operation, recovery, ready) = prepared_checkpoint(&fixture).await;
        let entered = mark_provider_entered(&fixture, &ready);
        let result = mutate(
            &fixture,
            &entered,
            OperationMutationV1::RecordProviderResult {
                bytes: b"provider-result".to_vec(),
            },
        );
        let _observed = mutate(
            &fixture,
            &result,
            OperationMutationV1::RecordObservation {
                bytes: b"provider-observation".to_vec(),
            },
        );
        drop(fixture);

        let reopened =
            recover_after_reopen(directory.path(), operation.clone(), recovery, "completed").await;
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            record(&reopened, &operation).observations(),
            &[b"provider-observation".to_vec()]
        );
    }

    #[tokio::test]
    async fn restart_after_execution_receipt_reuses_the_exact_pair() {
        let (directory, fixture) = fixture(false);
        let (operation, recovery, ready) = prepared_checkpoint(&fixture).await;
        let entered = mark_provider_entered(&fixture, &ready);
        let result = mutate(
            &fixture,
            &entered,
            OperationMutationV1::RecordProviderResult {
                bytes: b"provider-result".to_vec(),
            },
        );
        let observed = mutate(
            &fixture,
            &result,
            OperationMutationV1::RecordObservation {
                bytes: b"provider-observation".to_vec(),
            },
        );
        let receipted = fixture
            .executor
            .persist_execution_receipt(
                fixture.context.principal.as_ref(),
                &observed,
                ExecutionOutcome::Succeeded,
                Some(b"canonical-success"),
                observed.updated_at_unix_seconds(),
            )
            .unwrap();
        let retained_ids = receipted
            .receipts()
            .iter()
            .map(|receipt| receipt.receipt_id().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(retained_ids.len(), 2);
        assert_eq!(receipted.projection().state(), OperationStateV1::Executing);
        drop(fixture);

        let reopened =
            recover_after_reopen(directory.path(), operation.clone(), recovery, "completed").await;
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
        let terminal = record(&reopened, &operation);
        assert_eq!(terminal.completion(), Some(JournalCompletionV1::Reconciled));
        assert_eq!(
            terminal
                .receipts()
                .iter()
                .map(|receipt| receipt.receipt_id().to_owned())
                .collect::<Vec<_>>(),
            retained_ids
        );
    }

    #[tokio::test]
    async fn disabled_connection_retains_prior_generation_for_crash_recovery() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_connection(directory.path(), true, true);
        let (operation, recovery, connection) = possible_connected_operation(&fixture).await;
        let next_generation = NonZeroU64::new(connection.generation().get() + 1).unwrap();
        let next_commitment = fixture
            .credentials
            .advance_generation(
                connection.connection_id(),
                connection.generation(),
                next_generation,
            )
            .unwrap();
        fixture
            .connections
            .transition_state(
                connection.provider_kind(),
                connection.alias(),
                connection.generation(),
                ConnectionState::Disabled,
                *next_commitment.as_bytes(),
                11,
            )
            .unwrap();
        drop(fixture);

        let (reopened, outcome) =
            recover_connected_after_reopen(directory.path(), operation, recovery).await;
        assert_eq!(outcome_kind(&outcome), "completed");
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_ready_replay_precedes_current_connection_disable() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_options(directory.path(), false, true, false);
        let connection = install_stripe_connection(&fixture).await;
        let first = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&first), "ready");

        let next_generation = NonZeroU64::new(connection.generation().get() + 1).unwrap();
        let next_commitment = fixture
            .credentials
            .advance_generation(
                connection.connection_id(),
                connection.generation(),
                next_generation,
            )
            .unwrap();
        fixture
            .connections
            .transition_state(
                connection.provider_kind(),
                connection.alias(),
                connection.generation(),
                ConnectionState::Disabled,
                *next_commitment.as_bytes(),
                11,
            )
            .unwrap();

        let replay = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "ready");
        assert_eq!(ready_fields(&replay).0, ready_fields(&first).0);
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_terminal_replay_precedes_current_connection_rotation() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_options(directory.path(), false, true, false);
        let connection = install_stripe_connection(&fixture).await;
        let ready = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        let (operation, commitment, _recovery) = ready_fields(&ready);
        let completed = fixture
            .executor
            .execute(
                fixture.context.clone(),
                ExecuteOperationRequest::new(request_id(2), operation.clone(), commitment),
            )
            .await
            .unwrap();
        assert_eq!(outcome_kind(&completed), "completed");

        let fresh_exact = PrepareOperationRequest::new(
            request_id(8),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"canonical-input".to_vec(),
            None,
            1024,
        )
        .unwrap();
        let exact_replay = fixture
            .executor
            .prepare(fixture.context.clone(), fresh_exact)
            .await
            .unwrap();
        assert_eq!(outcome_kind(&exact_replay), "completed");
        assert_eq!(outcome_request_id(&exact_replay), [8; 16]);
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);

        let next_generation = NonZeroU64::new(connection.generation().get() + 1).unwrap();
        let next_commitment = fixture
            .credentials
            .replace(
                connection.connection_id(),
                connection.generation(),
                next_generation,
                SecretBytes::new(b"rk_test_rotated_replay_secret".to_vec()).unwrap(),
            )
            .await
            .unwrap();
        let replacement = connection
            .rotated(
                connection.descriptor().to_vec(),
                *connection.account_commitment(),
                *next_commitment.as_bytes(),
                11,
            )
            .unwrap();
        fixture
            .connections
            .replace(connection.generation(), replacement)
            .unwrap();

        let replay = fixture
            .executor
            .prepare(fixture.context.clone(), prepare_request())
            .await
            .unwrap();
        assert_eq!(outcome_kind(&replay), "completed");

        let fresh_request = PrepareOperationRequest::new(
            request_id(9),
            Some("test-operation".to_owned()),
            RUNTIME_DIGEST,
            b"canonical-input".to_vec(),
            None,
            1024,
        )
        .unwrap();
        let conflict = fixture
            .executor
            .prepare(fixture.context.clone(), fresh_request)
            .await
            .unwrap();
        assert_eq!(outcome_kind(&conflict), "conflict");
        assert_eq!(fixture.bridge.provider_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rotated_connection_retains_prior_generation_for_crash_recovery() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_connection(directory.path(), true, true);
        let (operation, recovery, connection) = possible_connected_operation(&fixture).await;
        let next_generation = NonZeroU64::new(connection.generation().get() + 1).unwrap();
        let next_commitment = fixture
            .credentials
            .replace(
                connection.connection_id(),
                connection.generation(),
                next_generation,
                SecretBytes::new(b"rk_test_rotated_recovery_secret".to_vec()).unwrap(),
            )
            .await
            .unwrap();
        let replacement = connection
            .rotated(
                connection.descriptor().to_vec(),
                *connection.account_commitment(),
                *next_commitment.as_bytes(),
                11,
            )
            .unwrap();
        fixture
            .connections
            .replace(connection.generation(), replacement)
            .unwrap();
        drop(fixture);

        let (reopened, outcome) =
            recover_connected_after_reopen(directory.path(), operation, recovery).await;
        assert_eq!(outcome_kind(&outcome), "completed");
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn emergency_revocation_preserves_possible_recovery_state() {
        let directory = tempdir().unwrap();
        let fixture = fixture_at_with_connection(directory.path(), true, true);
        let (operation, recovery, connection) = possible_connected_operation(&fixture).await;
        let next_generation = NonZeroU64::new(connection.generation().get() + 1).unwrap();
        let next_commitment = fixture
            .credentials
            .advance_generation(
                connection.connection_id(),
                connection.generation(),
                next_generation,
            )
            .unwrap();
        fixture
            .connections
            .transition_state(
                connection.provider_kind(),
                connection.alias(),
                connection.generation(),
                ConnectionState::Revoked,
                *next_commitment.as_bytes(),
                11,
            )
            .unwrap();
        fixture
            .credentials
            .revoke(connection.connection_id(), connection.generation())
            .await
            .unwrap();
        fixture
            .credentials
            .revoke(connection.connection_id(), next_generation)
            .await
            .unwrap();
        drop(fixture);

        let (reopened, outcome) =
            recover_connected_after_reopen(directory.path(), operation.clone(), recovery).await;
        assert_eq!(outcome_kind(&outcome), "recovery-required");
        assert_eq!(reopened.bridge.provider_calls.load(Ordering::SeqCst), 0);
        let stored = record(&reopened, &operation);
        assert_eq!(stored.projection().effect(), OperationEffectV1::Possible);
        assert_eq!(
            stored.projection().state(),
            OperationStateV1::RecoveryRequired
        );
    }
}
