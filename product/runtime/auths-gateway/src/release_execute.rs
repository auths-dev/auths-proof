//! Credential-owning read-release order for one installed task and recipe.
//! The operator still needs to expose this through an installed read command.

use super::{
    GatewayEngine, SharedConnection, TaskWriteSession, authorizes_entry, submit, wall_clock_seconds,
};
use crate::release_channel::{AuthenticatedReleaseChannel, UnixAgentReleaseChannel};
use crate::release_commitment::ReleaseCommitmentKey;
use crate::release_state::FileReleaseTaskLedger;
use crate::release_verify::{VerifiedReleaseRequest, verify_release_request};
use crate::task_activation::{ApprovedAgentTask, TaskActivationPins};
use crate::transport::GatewayHttpTransport;
use crate::{
    CompiledReleaseRecipe, GatewayConnectionDescriptor, GenerationFloor, LoadedConnection,
    QualificationGate,
};
use auths_connections::ConnectionCredentialStore;
use auths_connections::{ConnectionAlias, ProviderKind};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Secret-free status of one signed read action. A spent provider call and an
/// agent-visible release are distinct even when either later step fails.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ManagedReleaseResult {
    NotEntered {
        code: &'static str,
    },
    ProviderUnavailable {
        status: Option<u16>,
    },
    NoRelease {
        code: &'static str,
    },
    DeliveryUnknown,
    AgentAcknowledged {
        released_bytes: u64,
        commitment_key_version: u32,
        content_commitment: String,
    },
}

/// Read inputs installed by the operator beside the write task. A separate
/// qualification gate belongs to the exact read recipe; the write gate must
/// not be reused merely because the task has a write installation.
pub struct TaskReadOperatorInputs {
    pub recipe: CompiledReleaseRecipe,
    pub provider: ProviderKind,
    pub alias: ConnectionAlias,
    pub generation_floor: GenerationFloor,
    pub qualification: Arc<QualificationGate>,
    pub commitment_key: ReleaseCommitmentKey,
    pub channel_socket: PathBuf,
    pub channel_name: String,
    pub agent_identity_packet: Vec<u8>,
}

/// One operator-owned read path joined to the same activated task journal as
/// the installed write path. It owns no provider credential; the gateway
/// leases from its custody store under the distinct read connection record.
pub struct TaskReadSession<'s, 'e> {
    task: &'s TaskWriteSession<'e>,
    recipe: CompiledReleaseRecipe,
    connection: SharedConnection,
    qualification: Arc<QualificationGate>,
    commitment_key: ReleaseCommitmentKey,
    channel: UnixAgentReleaseChannel,
}

impl<'e> TaskWriteSession<'e> {
    /// Bind an operator-installed read recipe, recipient and connection to
    /// this task's immutable pins. No agent-supplied value can widen them.
    ///
    /// # Errors
    /// Refuses an unlisted recipe or a changed recipient before any provider
    /// call. The exact connection ID, generation and subject are checked
    /// again against the signed scope at read admission.
    pub fn read_session<'s>(
        &'s self,
        inputs: TaskReadOperatorInputs,
    ) -> Result<TaskReadSession<'s, 'e>, &'static str> {
        if !self.pins.permits_read_recipe(&inputs.recipe.digest_hex()) {
            return Err("gateway.release.recipe-not-installed");
        }
        if inputs.channel_name != self.pins.delivery_channel
            || hex::encode(Sha256::digest(&inputs.agent_identity_packet))
                != self.pins.agent_key_fingerprint
        {
            return Err("gateway.release.recipient-not-installed");
        }
        let channel = UnixAgentReleaseChannel::new(
            inputs.channel_socket,
            inputs.channel_name,
            inputs.agent_identity_packet,
        )
        .map_err(|_| "gateway.release.invalid-channel")?;
        Ok(TaskReadSession {
            task: self,
            recipe: inputs.recipe,
            connection: SharedConnection::new(
                self.engine.attempts.store(),
                inputs.provider,
                inputs.alias,
            )
            .with_generation_floor(inputs.generation_floor),
            qualification: inputs.qualification,
            commitment_key: inputs.commitment_key,
            channel,
        })
    }
}

impl TaskReadSession<'_, '_> {
    /// Execute one native-verified read against the already activated task.
    /// The returned status contains no provider body or credential.
    pub async fn read(
        &self,
        task_id: &str,
        agent_proof: &[u8],
        agent_action: &[u8],
    ) -> ManagedReleaseResult {
        self.task
            .engine
            .execute_managed_read(ManagedReadSubmission {
                task_id,
                agent_proof,
                agent_action,
                pins: &self.task.pins,
                recipe: &self.recipe,
                read_connection: &self.connection,
                read_credentials: &self.task.engine.credentials,
                read_qualification: &self.qualification,
                ledger: &self.task.ledger,
                commitment_key: &self.commitment_key,
                channel: &self.channel,
            })
            .await
    }
}

/// All authority and custody inputs come from operator-owned installation,
/// not the agent's action body. The action chooses only its signed scope.
pub(crate) struct ManagedReadSubmission<'a> {
    pub(crate) task_id: &'a str,
    pub(crate) agent_proof: &'a [u8],
    pub(crate) agent_action: &'a [u8],
    pub(crate) pins: &'a TaskActivationPins,
    pub(crate) recipe: &'a CompiledReleaseRecipe,
    pub(crate) read_connection: &'a SharedConnection,
    pub(crate) read_credentials: &'a Arc<dyn ConnectionCredentialStore>,
    /// Qualification for this exact read recipe and connection. The engine's
    /// own gate belongs to its installed write recipe and cannot substitute.
    pub(crate) read_qualification: &'a QualificationGate,
    pub(crate) ledger: &'a FileReleaseTaskLedger,
    pub(crate) commitment_key: &'a ReleaseCommitmentKey,
    pub(crate) channel: &'a UnixAgentReleaseChannel,
}

struct PreparedRead {
    task: ApprovedAgentTask,
    verified: VerifiedReleaseRequest,
    loaded: LoadedConnection,
    connection_subject: String,
    transport: GatewayHttpTransport,
    channel: AuthenticatedReleaseChannel,
}

#[derive(Clone, Copy)]
enum ReadFailure {
    /// The reserved call was withheld before provider transport entry.
    Refused(&'static str),
    /// Transport may have entered, or the complete provider result could not
    /// be projected. The operation ID remains spent in either case.
    ProviderUnavailable(Option<u16>),
}

impl GatewayEngine {
    /// Read one provider source and deliver its bounded projection only after
    /// native admission, connection checks, durable accounting, and agent
    /// channel authentication. No path retries a claimed operation ID.
    pub(crate) async fn execute_managed_read(
        &self,
        submission: ManagedReadSubmission<'_>,
    ) -> ManagedReleaseResult {
        let Some(now) = wall_clock_seconds() else {
            return ManagedReleaseResult::NotEntered {
                code: "gateway.verify.clock-unavailable",
            };
        };
        let prepared = match self.prepare_managed_read(&submission, now).await {
            Ok(prepared) => prepared,
            Err(result) => return result,
        };
        let request = prepared.verified.request();
        let operation_id = request.operation_id().as_str();
        let connection = prepared.loaded.record();
        let Some(reservation_time) = wall_clock_seconds() else {
            return not_entered("gateway.verify.clock-unavailable");
        };
        if submission
            .ledger
            .reserve_verified_request(
                &prepared.verified,
                connection.connection_id().as_str(),
                connection.generation().get(),
                &prepared.connection_subject,
                reservation_time,
            )
            .is_err()
        {
            return ManagedReleaseResult::NotEntered {
                code: "gateway.release.task-admission",
            };
        }
        let content = match self.fetch_projected(&submission, &prepared).await {
            Ok(content) => content,
            Err(failure) => return record_read_failure(&submission, operation_id, failure),
        };
        if !unchanged(submission.read_connection, &prepared.loaded).await
            || submission.read_qualification.check().is_err()
        {
            return refuse_release(
                &submission,
                operation_id,
                "gateway.release.connection-changed",
            );
        }
        let Some(release_time) = wall_clock_seconds() else {
            return refuse_release(
                &submission,
                operation_id,
                "gateway.verify.clock-unavailable",
            );
        };
        if submission
            .ledger
            .enter_release(
                submission.task_id,
                operation_id,
                &content,
                submission.commitment_key,
                release_time,
            )
            .is_err()
        {
            return refuse_release(&submission, operation_id, "gateway.release.release-refused");
        }
        let evidence = match prepared
            .channel
            .deliver(
                &prepared.task,
                operation_id,
                request.resource_handle(),
                &content,
                submission.commitment_key,
            )
            .await
        {
            Ok(evidence) => evidence,
            Err(_) => return ManagedReleaseResult::DeliveryUnknown,
        };
        if submission.ledger.acknowledge(&evidence).is_err() {
            return ManagedReleaseResult::DeliveryUnknown;
        }
        ManagedReleaseResult::AgentAcknowledged {
            released_bytes: evidence.released_bytes,
            commitment_key_version: evidence.commitment_key_version,
            content_commitment: evidence.content_commitment,
        }
    }

    async fn prepare_managed_read(
        &self,
        submission: &ManagedReadSubmission<'_>,
        now: u64,
    ) -> Result<PreparedRead, ManagedReleaseResult> {
        let state = submission
            .ledger
            .load(submission.task_id)
            .map_err(|_| not_entered("gateway.release.task-state"))?
            .ok_or_else(|| not_entered("gateway.release.task-not-activated"))?;
        let task = state
            .activated_task(submission.pins, now)
            .map_err(|_| not_entered("gateway.release.task-inactive"))?;
        let verified = verify_release_request(
            submission.recipe,
            &self.trusted_context,
            now,
            submission.agent_proof,
            submission.agent_action,
        )
        .map_err(|_| not_entered("gateway.release.native-proof"))?;
        let request = verified.request();
        if request.task_id() != submission.task_id {
            return Err(not_entered("gateway.release.task-binding"));
        }
        let digest = submission.recipe.digest_hex();
        let scope = task
            .task_policy()
            .resources
            .into_iter()
            .find(|scope| {
                scope.handle == request.resource_handle() && scope.recipe_digest == digest
            })
            .ok_or_else(|| not_entered("gateway.release.scope"))?;
        let loaded = submission
            .read_connection
            .load()
            .await
            .map_err(|_| not_entered("gateway.release.connection-unavailable"))?
            .ok_or_else(|| not_entered("gateway.release.connection-unavailable"))?;
        let record = loaded.record();
        if !authorizes_entry(record, &self.workload_id, &self.profile)
            || record.connection_id().as_str() != scope.connection_id
            || record.generation().get() != scope.connection_generation
            || record.account_commitment() != &submit::account_commitment(&scope.connection_subject)
        {
            return Err(not_entered("gateway.release.connection-binding"));
        }
        let descriptor =
            GatewayConnectionDescriptor::from_release_record(record, submission.recipe)
                .map_err(|_| not_entered("gateway.release.recipe-binding"))?;
        submission
            .read_qualification
            .check()
            .map_err(|_| not_entered("gateway.release.unqualified"))?;
        #[cfg(feature = "loopback-provider")]
        let transport = if let Some(port) = self.loopback_port {
            GatewayHttpTransport::prepare_release_loopback(
                submission.recipe,
                descriptor.credential(),
                port,
            )
        } else {
            GatewayHttpTransport::prepare_release(submission.recipe, descriptor.credential())
        };
        #[cfg(not(feature = "loopback-provider"))]
        let transport =
            GatewayHttpTransport::prepare_release(submission.recipe, descriptor.credential());
        let transport = transport
            .map_err(|_| not_entered("gateway.release.transport-preparation"))?
            .with_witness(Arc::clone(&self.execution_witness));
        let channel = submission
            .channel
            .authenticate(&task, request.operation_id().as_str())
            .await
            .map_err(|_| not_entered("gateway.release.agent-channel"))?;
        Ok(PreparedRead {
            task,
            verified,
            loaded,
            connection_subject: scope.connection_subject,
            transport,
            channel,
        })
    }

    async fn fetch_projected(
        &self,
        submission: &ManagedReadSubmission<'_>,
        prepared: &PreparedRead,
    ) -> Result<Zeroizing<Vec<u8>>, ReadFailure> {
        if !unchanged(submission.read_connection, &prepared.loaded).await
            || submission.read_qualification.check().is_err()
        {
            return Err(ReadFailure::Refused("gateway.release.connection-changed"));
        }
        self.execution_witness.lease();
        let lease = submission
            .read_credentials
            .lease_secret(
                &prepared.loaded.record().credential_binding(),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .map_err(|_| ReadFailure::Refused("gateway.release.credential-unavailable"))?;
        if !unchanged(submission.read_connection, &prepared.loaded).await
            || submission.read_qualification.check().is_err()
        {
            return Err(ReadFailure::Refused("gateway.release.connection-changed"));
        }
        let response = prepared
            .transport
            .release_read(prepared.verified.request(), &lease)
            .await
            .ok_or(ReadFailure::ProviderUnavailable(None))?;
        let Some(content_type) = response.content_type.as_deref() else {
            return Err(ReadFailure::ProviderUnavailable(Some(response.status)));
        };
        let body = Zeroizing::new(response.body);
        submission
            .recipe
            .project(response.status, content_type, &body)
            .map(Zeroizing::new)
            .map_err(|_| ReadFailure::ProviderUnavailable(Some(response.status)))
    }
}

fn record_read_failure(
    submission: &ManagedReadSubmission<'_>,
    operation_id: &str,
    failure: ReadFailure,
) -> ManagedReleaseResult {
    match failure {
        ReadFailure::Refused(code) => refuse_release(submission, operation_id, code),
        ReadFailure::ProviderUnavailable(status) => {
            if submission
                .ledger
                .provider_unavailable(submission.task_id, operation_id)
                .is_ok()
            {
                ManagedReleaseResult::ProviderUnavailable { status }
            } else {
                ManagedReleaseResult::DeliveryUnknown
            }
        }
    }
}

async fn unchanged(connection: &SharedConnection, loaded: &LoadedConnection) -> bool {
    matches!(connection.load().await, Ok(Some(current)) if current.unchanged(loaded))
}

fn not_entered(code: &'static str) -> ManagedReleaseResult {
    ManagedReleaseResult::NotEntered { code }
}

fn refuse_release(
    submission: &ManagedReadSubmission<'_>,
    operation_id: &str,
    code: &'static str,
) -> ManagedReleaseResult {
    if submission
        .ledger
        .release_refused(submission.task_id, operation_id)
        .is_ok()
    {
        ManagedReleaseResult::NoRelease { code }
    } else {
        ManagedReleaseResult::DeliveryUnknown
    }
}

#[cfg(all(test, feature = "loopback-provider"))]
mod tests {
    use super::*;
    use crate::GatewayObserver;
    use crate::engine::tests::administration;
    use crate::harness::{self, Signer};
    use crate::release_state::ReleaseStage;
    use crate::release_verify::tests::{arguments, exact_grant, recipe};
    use crate::task_activation::{
        AgentTaskDescriptor, ApprovedAgentTask, TaskReadScope, TaskWriteVerb,
    };
    use crate::task_write::TaskWriteBinding;
    use auths_connections::ConnectionRecord;
    use auths_identity_raw_key::RawKeyIdentityMethod;
    use ed25519_dalek::Signer as _;
    use serde_json::json;
    use std::{
        os::unix::fs::PermissionsExt as _,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, UnixListener},
    };

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one installed-style fixture spans task, native proof, credential, provider and agent channel"
    )]
    async fn managed_read_joins_native_task_provider_and_registered_agent() {
        let mut installation = administration::installation(8).await;
        let engine = &mut installation.first.engine;
        let read_recipe = recipe();
        let provider = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("provider");
        engine.loopback_port = Some(provider.local_addr().expect("address").port());
        let now = wall_clock_seconds().expect("clock");
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        engine.trusted_context =
            harness::context(&root, observer.principal(), None, now).expect("read trust");
        let loaded = engine
            .connection
            .load()
            .await
            .expect("load")
            .expect("connection");
        let old = loaded.record();
        let subject = "acct_TESTPLATFORM1";
        let descriptor =
            GatewayConnectionDescriptor::approve_release(&read_recipe, "Authorization")
                .expect("descriptor")
                .to_bytes()
                .expect("descriptor bytes");
        let bound = ConnectionRecord::new(
            old.provider_kind().clone(),
            old.alias().clone(),
            old.connection_id().clone(),
            old.contract().clone(),
            old.descriptor_schema().clone(),
            descriptor,
            submit::account_commitment(subject),
            *old.credential_reference_commitment(),
            old.generation(),
            old.state(),
            old.allowed_workloads().to_vec(),
            old.allowed_profiles().to_vec(),
            old.created_at_unix_seconds(),
            old.updated_at_unix_seconds(),
            old.revoked_at_unix_seconds(),
        )
        .expect("subject-bound connection");
        engine
            .connection
            .replace(&loaded, &bound)
            .await
            .expect("replace");

        let identity = RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            agent.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("identity")
        .into_public_identity();
        let identity = identity.to_descriptor().expect("descriptor");
        let packet = identity.encode().expect("packet");
        let read_scope = json!({"handle": harness::RECORD,
            "recipe_digest": read_recipe.digest_hex(),
            "connection_id": bound.connection_id().as_str(),
            "connection_generation": bound.generation().get(),
            "connection_subject": subject});
        let pins = TaskActivationPins {
            company_id: "atlas".to_owned(),
            human_principal: root.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: hex::encode(Sha256::digest(&packet)),
            connection_id: bound.connection_id().as_str().to_owned(),
            connection_generation: bound.generation().get(),
            connection_subject: subject.to_owned(),
            permitted_read_scopes: vec![
                serde_json::from_value::<TaskReadScope>(read_scope.clone()).expect("scope"),
            ],
            delivery_channel: "agent-channel".to_owned(),
            operator_policy_digest: "b".repeat(64),
            allow_bounded_writes: false,
        };
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/2", "task_id": "task-1", "company_id": "atlas",
            "human_principal": root.principal.as_str(), "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": pins.agent_key_fingerprint,
            "connection_id": bound.connection_id().as_str(),
            "connection_generation": bound.generation().get(), "connection_subject": subject,
            "read_scopes": [read_scope], "write_scopes": [],
            "delivery_channel": "agent-channel", "not_before": now - 10,
            "expires_at": now + 600, "max_provider_calls": 1,
            "max_releases": 1, "max_release_bytes": 64, "max_writes": 0,
            "write_approval_mode": "exact", "operator_policy_digest": "b".repeat(64),
            "purpose": "Read one test record"
        }))
        .expect("card");
        let canonical = serde_json_canonicalizer::to_vec(&card).expect("card canonical");
        let commitment =
            auths_codec::domain_commitment("auths.agent-task.v2", &canonical).expect("commitment");
        let approved = ApprovedAgentTask::from_test_card(card, *commitment.as_bytes());
        let directory = tempfile::tempdir().expect("state root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("state mode");
        let ledger_root = directory.path().join("task-state");
        std::fs::create_dir(&ledger_root).expect("ledger directory");
        std::fs::set_permissions(&ledger_root, std::fs::Permissions::from_mode(0o700))
            .expect("ledger mode");
        let ledger = FileReleaseTaskLedger::open(
            std::fs::canonicalize(ledger_root).expect("canonical ledger root"),
        )
        .expect("ledger");
        let floor_root = directory.path().join("read-floor");
        std::fs::create_dir(&floor_root).expect("read floor directory");
        std::fs::set_permissions(&floor_root, std::fs::Permissions::from_mode(0o700))
            .expect("read floor mode");
        let read_floor = GenerationFloor::new(floor_root);
        read_floor.initialize(&bound).expect("read floor");
        ledger.initialize(&approved).expect("activate");
        let mut action_arguments = arguments(&read_recipe, agent.principal.as_str());
        action_arguments.insert(
            "task_commitment".to_owned(),
            json!(hex::encode(commitment.as_bytes())),
        );
        let grant = exact_grant(&root, &agent, &action_arguments, now);
        let signed = crate::observed_tests::submission_for(
            &root,
            &agent,
            &grant,
            &action_arguments,
            &[],
            harness::SERVICE,
            harness::TOOL,
            now,
        );

        let socket = std::fs::canonicalize(directory.path())
            .expect("canonical")
            .join("agent.sock");
        let listener = UnixListener::bind(&socket).expect("agent socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode");
        let channel = UnixAgentReleaseChannel::new(
            socket.clone(),
            "agent-channel".to_owned(),
            packet.clone(),
        )
        .expect("channel");
        let unqualified_read = QualificationGate::unconfigured();
        let refused = engine
            .execute_managed_read(ManagedReadSubmission {
                task_id: "task-1",
                agent_proof: &signed.proof,
                agent_action: &signed.action,
                pins: &pins,
                recipe: &read_recipe,
                read_connection: &engine.connection,
                read_credentials: &engine.credentials,
                read_qualification: &unqualified_read,
                ledger: &ledger,
                commitment_key: &ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32]))
                    .expect("key"),
                channel: &channel,
            })
            .await;
        assert!(matches!(
            refused,
            ManagedReleaseResult::NotEntered {
                code: "gateway.release.unqualified"
            }
        ));
        assert_eq!(
            ledger
                .load("task-1")
                .expect("ledger")
                .expect("task")
                .counts(),
            (0, 0, 0)
        );
        let mut altered_action = signed.action.clone();
        let last = altered_action.last_mut().expect("action byte");
        *last ^= 1;
        let refused = engine
            .execute_managed_read(ManagedReadSubmission {
                task_id: "task-1",
                agent_proof: &signed.proof,
                agent_action: &altered_action,
                pins: &pins,
                recipe: &read_recipe,
                read_connection: &engine.connection,
                read_credentials: &engine.credentials,
                read_qualification: &engine.qualification,
                ledger: &ledger,
                commitment_key: &ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32]))
                    .expect("key"),
                channel: &channel,
            })
            .await;
        assert!(matches!(
            refused,
            ManagedReleaseResult::NotEntered {
                code: "gateway.release.native-proof"
            }
        ));
        assert_eq!(
            ledger
                .load("task-1")
                .expect("ledger")
                .expect("task")
                .counts(),
            (0, 0, 0)
        );
        let authenticated = Arc::new(AtomicBool::new(false));
        let agent_ready = Arc::clone(&authenticated);
        let agent_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept agent");
            let length = stream.read_u32().await.expect("challenge length") as usize;
            let mut challenge = vec![0; length];
            stream.read_exact(&mut challenge).await.expect("challenge");
            let preimage = identity
                .signing_preimage("default-signing", &challenge)
                .expect("challenge preimage");
            let signature = agent.key.sign(&preimage).to_bytes();
            agent_ready.store(true, Ordering::SeqCst);
            stream.write_u32(64).await.expect("signature length");
            stream.write_all(&signature).await.expect("signature");
            let length = stream.read_u32().await.expect("content length") as usize;
            let mut content = vec![0; length];
            stream.read_exact(&mut content).await.expect("content");
            let length = stream.read_u32().await.expect("ack length") as usize;
            let mut message = vec![0; length];
            stream.read_exact(&mut message).await.expect("ack message");
            let preimage = identity
                .signing_preimage("default-signing", &message)
                .expect("ack preimage");
            let signature = agent.key.sign(&preimage).to_bytes();
            stream.write_u32(64).await.expect("ack signature length");
            stream.write_all(&signature).await.expect("ack signature");
            content
        });
        let provider_ready = Arc::clone(&authenticated);
        let provider_server = tokio::spawn(async move {
            let (mut stream, _) = provider.accept().await.expect("provider accept");
            assert!(
                provider_ready.load(Ordering::SeqCst),
                "provider call preceded agent authentication"
            );
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).await.expect("request");
            let request = std::str::from_utf8(&request[..size]).expect("request text");
            assert!(request.starts_with("GET /v0/"));
            assert!(
                request.contains("Authorization: Bearer pat-initial")
                    || request.contains("authorization: Bearer pat-initial")
            );
            let body = br#"{"fields":{"DemoStatus":"Ready"}}"#;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.expect("headers");
            stream.write_all(body).await.expect("body");
        });
        let task_session = TaskWriteSession {
            engine,
            pins,
            binding: TaskWriteBinding {
                resource_field: "record_id".to_owned(),
                verb: TaskWriteVerb::Edit,
                connection_id: bound.connection_id().as_str().to_owned(),
                connection_generation: bound.generation().get(),
                connection_subject: subject.to_owned(),
            },
            ledger,
        };
        let read_session = task_session
            .read_session(TaskReadOperatorInputs {
                recipe: read_recipe,
                provider: bound.provider_kind().clone(),
                alias: bound.alias().clone(),
                generation_floor: read_floor,
                qualification: Arc::clone(&engine.qualification),
                commitment_key: ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32]))
                    .expect("key"),
                channel_socket: socket,
                channel_name: "agent-channel".to_owned(),
                agent_identity_packet: packet,
            })
            .expect("installed read session");
        let result = read_session
            .read("task-1", &signed.proof, &signed.action)
            .await;
        assert!(
            matches!(
                result,
                ManagedReleaseResult::AgentAcknowledged {
                    released_bytes: 5,
                    ..
                }
            ),
            "{result:?}"
        );
        assert_eq!(agent_server.await.expect("agent"), b"Ready");
        provider_server.await.expect("provider");
        let state = task_session
            .ledger
            .load("task-1")
            .expect("ledger")
            .expect("task");
        assert_eq!(state.counts(), (1, 1, 5));
        assert_eq!(state.stage("read-1"), Some(ReleaseStage::AgentAcknowledged));
        let status = serde_json::to_value(task_session.status("task-1").expect("task status"))
            .expect("redacted status");
        assert_eq!(status["reads"][0]["stage"], "agent-acknowledged");
        assert_eq!(status["released_bytes"], 5);
        let public = status.to_string();
        assert!(!public.contains(subject));
        assert!(!public.contains("content_commitment"));
        assert!(!public.contains("pat-initial"));
        task_session.revoke("task-1").expect("durable revocation");
        assert_eq!(
            serde_json::to_value(task_session.status("task-1").expect("revoked status"))
                .expect("redacted status")["revoked"],
            true
        );
        assert_eq!(
            read_session
                .read("task-1", &signed.proof, &signed.action)
                .await,
            ManagedReleaseResult::NotEntered {
                code: "gateway.release.task-inactive"
            }
        );
    }
}
