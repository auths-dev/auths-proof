//! Target V1 end-to-end MCP fixtures and transport conformance.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_author::prepare_action;
use auths_codec::{
    action_id, body_digest, encode_bundle, encode_canonical_action, encode_verifier_context,
    evidence_id, plan_id,
};
use auths_did_keri::DidKeriMethod;
use auths_did_key::DidKeyMethod;
use auths_model::{
    AcceptedRegistries, ActionEnvelope, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    AssuranceQuantifier, AssuranceRequirement, AudienceSet, AuthorizationPlan, BundleHeader,
    CanonicalAction, Challenge, ChannelBindingId, CompositionRequirement, ControlBinding,
    CriticalExtensions, EvidenceId, EvidenceObject, EvidenceTypeId, GrantStatusSnapshot, MediaType,
    ParticipantRole, Permission, PermissionSet, PrincipalMethodId, PrincipalStatusSnapshot,
    ProfilePolicyId, ProofBundle, ProofRef, RegistryManifestId, ResourceMatcherId, SignatureBytes,
    SignatureDescriptor, SignatureSuiteId, StatementRef, StatusPolicy, StatusSnapshotId, Timestamp,
    TrustAnchor, TrustAnchorId, ValidityWindow, VerificationMethod, VerifierConfigurationId,
    VerifierContext, VerifierLimits,
};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_proof_exchange_iroh::{
    ALPN_V1, IrohChannelConfig, IrohClientChannel, IrohServerChannel, PathObservation,
};
use auths_proof_exchange_memory::channel_pair;
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, ChallengeNonce, ChannelBindingPolicy,
    ExchangeOutcome, PeerObservation, RefusalKind, VerdictDecision,
};
use auths_proof_exchange_port::{ClientProofChannel, ProofExchangeService, serve_one};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_receipts::{ReceiptSigner, decode_attested_decision, decode_attested_execution};
use auths_runtime::{
    AuthsKernel, ChallengeSource, ChallengeSourceError, Clock, ExecutableAction,
    InMemoryChallengeLedger, McpAuthorizationService, McpExecutionDependencies,
    McpRequestStateDependencies, McpRuntimeDependencies, McpServiceConfig, McpToolExecutor,
    NoBudgetLedger, ReceiptAttestationError, ReceiptAttestor, ReceiptSink, ReceiptStoreError,
};
use auths_sdk::{RequestContext, Verifier};
use auths_signature::{ED25519_V1, Ed25519Suite, P256Sha256Suite};
use ed25519_dalek::{Signer as _, SigningKey};
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use serde_json::{Map, Value};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

const ROOT_SEED: [u8; 32] = [101; 32];
const RECEIPT_SEED: [u8; 32] = [102; 32];
pub const DEMO_NOW: u64 = 1_800_000_000;
pub const DEMO_CHALLENGE: ChallengeNonce = ChallengeNonce::new([0xc4; 32]);

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

struct FixedChallengeSource(ChallengeNonce);

impl ChallengeSource for FixedChallengeSource {
    fn generate(&self) -> Result<ChallengeNonce, ChallengeSourceError> {
        Ok(self.0)
    }
}

struct DemoReceiptAttestor {
    key: SigningKey,
    signer: ReceiptSigner,
}

impl DemoReceiptAttestor {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&RECEIPT_SEED),
            signer: ReceiptSigner::new(
                auths_model::PrincipalId::parse("did:key:auths-demo-verifier").unwrap(),
                VerificationMethod::parse("did:key:auths-demo-verifier#receipt").unwrap(),
                SignatureSuiteId::parse(ED25519_V1).unwrap(),
            ),
        }
    }
}

impl ReceiptAttestor for DemoReceiptAttestor {
    fn signer(&self) -> ReceiptSigner {
        self.signer.clone()
    }

    fn sign(&self, signing_preimage: &[u8]) -> Result<SignatureBytes, ReceiptAttestationError> {
        SignatureBytes::new(self.key.sign(signing_preimage).to_bytes().to_vec())
            .map_err(|_| ReceiptAttestationError)
    }
}

struct StaticReportExecutor {
    expected_challenge: ChallengeNonce,
    executions: AtomicUsize,
}

impl StaticReportExecutor {
    fn new(expected_challenge: ChallengeNonce) -> Self {
        Self {
            expected_challenge,
            executions: AtomicUsize::new(0),
        }
    }

    fn count(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl McpToolExecutor for StaticReportExecutor {
    async fn execute(
        &self,
        action: ExecutableAction<auths_profile_mcp::McpCommand>,
    ) -> Result<Vec<u8>, String> {
        let command = action.command();
        if command.name() != "read_report"
            || command.arguments().get("name") != Some(&Value::String("q3".into()))
            || action.lease().challenge() != self.expected_challenge
        {
            return Err("verified report command is outside the demo policy".into());
        }
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(br#"{"name":"q3","status":"approved"}"#.to_vec())
    }
}

#[derive(Default)]
struct MemoryReceiptSink {
    decisions: Mutex<std::collections::BTreeMap<auths_model::ReceiptId, Vec<u8>>>,
    executions: Mutex<std::collections::BTreeMap<auths_model::ReceiptId, Vec<u8>>>,
}

impl MemoryReceiptSink {
    fn counts(&self) -> (usize, usize) {
        (
            self.decisions.lock().expect("decision lock").len(),
            self.executions.lock().expect("execution lock").len(),
        )
    }

    fn assert_canonical(&self) {
        for bytes in self.decisions.lock().expect("decision lock").values() {
            decode_attested_decision(bytes).expect("canonical attested decision receipt");
        }
        for bytes in self.executions.lock().expect("execution lock").values() {
            decode_attested_execution(bytes).expect("canonical attested execution receipt");
        }
    }
}

impl ReceiptSink for MemoryReceiptSink {
    fn store_decision(
        &self,
        id: auths_model::ReceiptId,
        bytes: Vec<u8>,
    ) -> Result<(), ReceiptStoreError> {
        self.decisions
            .lock()
            .map_err(|_| ReceiptStoreError)?
            .insert(id, bytes);
        Ok(())
    }

    fn store_execution(
        &self,
        id: auths_model::ReceiptId,
        bytes: Vec<u8>,
    ) -> Result<(), ReceiptStoreError> {
        self.executions
            .lock()
            .map_err(|_| ReceiptStoreError)?
            .insert(id, bytes);
        Ok(())
    }
}

pub struct DemoResult {
    pub response: ActionResponse,
    pub proof_bytes: usize,
    pub total_micros: u64,
    pub path: &'static str,
    pub executor_invocations: usize,
    pub decision_receipts: usize,
    pub execution_receipts: usize,
}

/// Canonical fixture material shared by the native and browser live labs.
pub struct DemoFixtureBytes {
    /// Canonical MCP request bytes accepted by the application profile.
    pub body: Vec<u8>,
    /// Canonical action bytes passed to the portable verifier.
    pub canonical_action: Vec<u8>,
    /// Canonical proof bundle.
    pub proof: Vec<u8>,
    /// Trusted context whose required configuration matches the demo engine.
    pub context: Vec<u8>,
    /// Display-safe root principal for the proof graph.
    pub root_principal: String,
}

struct DemoFixture {
    body: Vec<u8>,
    canonical_action: Vec<u8>,
    proof: Vec<u8>,
    context: VerifierContext,
    root_principal: String,
}

/// Builds the exact deterministic body, proof, and root used by the demos.
///
/// # Panics
///
/// Panics if the repository-owned fixture cannot be constructed or encoded.
#[must_use]
pub fn demo_fixture_bytes() -> DemoFixtureBytes {
    demo_fixture_bytes_for_challenge(*DEMO_CHALLENGE.as_bytes())
}

/// Builds canonical demo material bound to a caller-provided challenge.
///
/// This is used by the public live service so the browser verifies the exact
/// short-lived proof that the native runtime will later consume.
///
/// # Panics
///
/// Panics if the repository-owned fixture cannot be constructed or encoded.
#[must_use]
pub fn demo_fixture_bytes_for_challenge(nonce: [u8; 32]) -> DemoFixtureBytes {
    let fixture = build_fixture(ChallengeNonce::new(nonce), None);
    DemoFixtureBytes {
        body: fixture.body,
        canonical_action: fixture.canonical_action,
        proof: fixture.proof,
        context: encode_verifier_context(&fixture.context).expect("fixed demo context"),
        root_principal: fixture.root_principal,
    }
}

/// Runs the target authorization flow over the semantic reference transport.
///
/// # Panics
///
/// Panics if a repository-owned fixture, transport step, receipt, or task
/// assertion fails.
pub async fn run_memory_demo() -> DemoResult {
    let fixture = build_fixture(DEMO_CHALLENGE, None);
    let (service, executor, receipts) = demo_service(
        fixture.context,
        ChannelBindingPolicy::RequireAuthenticatedPeer,
        None,
    );
    let (mut client, mut server) = channel_pair(
        PeerObservation::ServerAuthenticated,
        PeerObservation::AuthenticatedOpaque {
            kind: "memory-demo".into(),
            identifier: vec![1],
        },
    );
    let server_service = service.clone();
    let server_task = tokio::spawn(async move {
        serve_one(&mut server, server_service.as_ref())
            .await
            .expect("memory exchange");
    });
    let started = Instant::now();
    let challenge = client.receive_challenge().await.expect("challenge");
    let request =
        ActionSubmission::new(fixture.body, fixture.proof.clone(), &challenge).expect("submission");
    let response = client.submit_action(request).await.expect("response");
    server_task.await.expect("server task");
    let receipt_counts = receipts.counts();
    assert_eq!(receipt_counts, (1, 1));
    receipts.assert_canonical();
    DemoResult {
        response,
        proof_bytes: fixture.proof.len(),
        total_micros: micros(started.elapsed()),
        path: "in-memory",
        executor_invocations: executor.count(),
        decision_receipts: receipt_counts.0,
        execution_receipts: receipt_counts.1,
    }
}

/// Runs the same target flow over a local authenticated Iroh path.
///
/// # Panics
///
/// Panics if endpoint setup, transport I/O, a repository-owned fixture, or a
/// conformance assertion fails.
pub async fn run_iroh_demo() -> DemoResult {
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_V1.to_vec()])
        .bind()
        .await
        .expect("server endpoint");
    let client_endpoint = Endpoint::bind(presets::N0).await.expect("client endpoint");
    let server_addr = direct_addr(&server_endpoint);
    let fixture = build_fixture(DEMO_CHALLENGE, None);
    let (service, executor, receipts) = demo_service(
        fixture.context,
        ChannelBindingPolicy::RequireAuthenticatedPeer,
        None,
    );
    let server_service = service.clone();
    let server_endpoint_task = server_endpoint.clone();
    let config = IrohChannelConfig::default();
    let server_task = tokio::spawn(async move {
        let mut server = IrohServerChannel::accept(&server_endpoint_task, config)
            .await
            .expect("Iroh accept");
        serve_one(&mut server, server_service.as_ref())
            .await
            .expect("Iroh exchange");
    });
    let started = Instant::now();
    let mut client = IrohClientChannel::connect(&client_endpoint, server_addr, config)
        .await
        .expect("Iroh connect");
    assert_eq!(client.path_observation(), PathObservation::Direct);
    let challenge = client.receive_challenge().await.expect("challenge");
    let request =
        ActionSubmission::new(fixture.body, fixture.proof.clone(), &challenge).expect("submission");
    let response = client.submit_action(request).await.expect("response");
    server_task.await.expect("server task");
    client_endpoint.close().await;
    server_endpoint.close().await;
    let receipt_counts = receipts.counts();
    assert_eq!(receipt_counts, (1, 1));
    receipts.assert_canonical();
    DemoResult {
        response,
        proof_bytes: fixture.proof.len(),
        total_micros: micros(started.elapsed()),
        path: "Iroh direct",
        executor_invocations: executor.count(),
        decision_receipts: receipt_counts.0,
        execution_receipts: receipt_counts.1,
    }
}

/// Native replay experiment output for the browser live-lab snapshot.
pub struct ReplayDemoResult {
    /// First request, which must execute.
    pub first: ActionResponse,
    /// Identical second request, which must be rejected as consumed.
    pub replay: ActionResponse,
    /// Total safe-executor invocations across both requests.
    pub executor_invocations: usize,
    /// Total persisted decision receipts.
    pub decision_receipts: usize,
    /// Total persisted execution receipts.
    pub execution_receipts: usize,
}

/// A single real Auths runtime session used by the interactive live service.
///
/// Each instance owns an issued challenge, its signed proof, the atomic
/// challenge ledger, the safe executor, and receipt storage. Reusing the
/// instance for a second submission exercises the runtime replay gate.
pub struct DemoRuntimeSession {
    service: Arc<McpAuthorizationService>,
    executor: Arc<StaticReportExecutor>,
    receipts: Arc<MemoryReceiptSink>,
    challenge: ActionChallenge,
    request: ActionSubmission,
}

/// Result of one submission to a [`DemoRuntimeSession`].
pub struct DemoRuntimeSubmission {
    /// The real exchange-layer response returned by the runtime.
    pub response: ActionResponse,
    /// Total safe-executor invocations in this session.
    pub executor_invocations: usize,
    /// Total persisted signed decision receipts in this session.
    pub decision_receipts: usize,
    /// Total persisted signed execution receipts in this session.
    pub execution_receipts: usize,
}

impl DemoRuntimeSession {
    /// Creates a runtime session around a caller-provided cryptographic nonce.
    ///
    /// # Panics
    ///
    /// Panics if repository-owned fixtures or runtime setup violate the demo
    /// contract.
    pub async fn new(nonce: [u8; 32]) -> Self {
        let expected = ChallengeNonce::new(nonce);
        let fixture = build_fixture(expected, None);
        let (service, executor, receipts) = demo_service_with_challenge(
            fixture.context,
            ChannelBindingPolicy::None,
            None,
            expected,
        );
        let challenge = service
            .issue_challenge(&PeerObservation::Unauthenticated)
            .await
            .expect("live demo challenge");
        assert_eq!(challenge.challenge(), expected);
        let request =
            ActionSubmission::new(fixture.body, fixture.proof, &challenge).expect("submission");
        Self {
            service,
            executor,
            receipts,
            challenge,
            request,
        }
    }

    /// Submits the exact same proof-carrying action to this session.
    ///
    /// The first call executes once. Every later call is rejected by the
    /// runtime's consumed-challenge gate.
    pub async fn execute(&self) -> DemoRuntimeSubmission {
        let response = self
            .service
            .handle_action(
                &PeerObservation::Unauthenticated,
                &self.challenge,
                self.request.clone(),
            )
            .await;
        let (decision_receipts, execution_receipts) = self.receipts.counts();
        self.receipts.assert_canonical();
        DemoRuntimeSubmission {
            response,
            executor_invocations: self.executor.count(),
            decision_receipts,
            execution_receipts,
        }
    }
}

/// Runs the deterministic native replay experiment.
///
/// # Panics
///
/// Panics if the repository-owned fixture, runtime, replay gate, or receipt
/// sink violates its deterministic demo contract.
#[must_use]
pub async fn run_replay_demo() -> ReplayDemoResult {
    let session = DemoRuntimeSession::new(*DEMO_CHALLENGE.as_bytes()).await;
    let first = session.execute().await;
    let replay = session.execute().await;
    ReplayDemoResult {
        first: first.response,
        replay: replay.response,
        executor_invocations: replay.executor_invocations,
        decision_receipts: replay.decision_receipts,
        execution_receipts: replay.execution_receipts,
    }
}

/// Executes deterministic target replay, receipt, and negative assertions
/// without opening operating-system sockets.
///
/// # Panics
///
/// Panics if any target conformance assertion fails.
pub async fn assert_target_conformance() {
    let memory = run_memory_demo().await;
    assert!(matches!(
        memory.response.outcome(),
        ExchangeOutcome::Completed { .. }
    ));

    replay_is_consumed_before_second_execution().await;
    concurrent_duplicate_executes_exactly_once().await;
    authenticated_transport_does_not_upgrade_bad_proof().await;
    signed_permission_must_match_tool().await;
}

/// Asserts that Iroh produces the same semantic outcome and request ID as the
/// socket-free reference transport.
///
/// # Panics
///
/// Panics if either transport fails or their semantic results differ.
pub async fn assert_iroh_target_conformance() {
    let memory = run_memory_demo().await;
    let iroh = run_iroh_demo().await;
    assert_eq!(memory.response.outcome(), iroh.response.outcome());
    assert_eq!(memory.response.request_id(), iroh.response.request_id());
}

async fn replay_is_consumed_before_second_execution() {
    let replay = run_replay_demo().await;
    assert!(matches!(
        replay.first.outcome(),
        ExchangeOutcome::Completed { .. }
    ));
    assert!(matches!(
        replay.replay.outcome(),
        ExchangeOutcome::Refused {
            kind: RefusalKind::ConsumedChallenge,
            ..
        }
    ));
    assert_eq!(replay.executor_invocations, 1);
    assert_eq!(
        (replay.decision_receipts, replay.execution_receipts),
        (1, 1)
    );
}

async fn concurrent_duplicate_executes_exactly_once() {
    let fixture = build_fixture(DEMO_CHALLENGE, None);
    let (service, executor, receipts) =
        demo_service(fixture.context, ChannelBindingPolicy::None, None);
    let challenge = service
        .issue_challenge(&PeerObservation::Unauthenticated)
        .await
        .expect("challenge");
    let request = ActionSubmission::new(fixture.body, fixture.proof, &challenge).unwrap();
    let left_service = service.clone();
    let right_service = service.clone();
    let left_request = request.clone();
    let left_challenge = challenge.clone();
    let right_challenge = challenge.clone();
    let left = tokio::spawn(async move {
        left_service
            .handle_action(
                &PeerObservation::Unauthenticated,
                &left_challenge,
                left_request,
            )
            .await
    });
    let right = tokio::spawn(async move {
        right_service
            .handle_action(&PeerObservation::Unauthenticated, &right_challenge, request)
            .await
    });
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|response| matches!(response.outcome(), ExchangeOutcome::Completed { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|response| matches!(
                response.outcome(),
                ExchangeOutcome::Refused {
                    kind: RefusalKind::ConsumedChallenge,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(executor.count(), 1);
    assert_eq!(receipts.counts(), (1, 1));
}

async fn authenticated_transport_does_not_upgrade_bad_proof() {
    let fixture = build_fixture(DEMO_CHALLENGE, None);
    let (service, executor, receipts) = demo_service(
        fixture.context,
        ChannelBindingPolicy::RequireAuthenticatedPeer,
        None,
    );
    let challenge = service
        .issue_challenge(&PeerObservation::IrohEndpoint([9; 32]))
        .await
        .unwrap();
    let mut proof = fixture.proof;
    let last = proof.len() - 1;
    proof[last] ^= 1;
    let request = ActionSubmission::new(fixture.body, proof, &challenge).unwrap();
    let response = service
        .handle_action(&PeerObservation::IrohEndpoint([9; 32]), &challenge, request)
        .await;
    assert!(matches!(
        response.outcome(),
        ExchangeOutcome::Refused {
            kind: RefusalKind::AuthsVerdict,
            verdict: Some(summary),
            ..
        } if summary.decision() != VerdictDecision::Authorized
    ));
    assert_eq!(executor.count(), 0);
    assert_eq!(receipts.counts(), (1, 0));
}

async fn signed_permission_must_match_tool() {
    let wrong = Permission::new(
        auths_model::CapabilityId::parse("tools/call").unwrap(),
        auths_model::ResourceId::parse("mcp://reports/tools/delete_report").unwrap(),
    );
    let fixture = build_fixture(DEMO_CHALLENGE, Some(wrong));
    let (service, executor, receipts) =
        demo_service(fixture.context, ChannelBindingPolicy::None, None);
    let challenge = service
        .issue_challenge(&PeerObservation::Unauthenticated)
        .await
        .unwrap();
    let request = ActionSubmission::new(fixture.body, fixture.proof, &challenge).unwrap();
    let response = service
        .handle_action(&PeerObservation::Unauthenticated, &challenge, request)
        .await;
    assert!(matches!(
        response.outcome(),
        ExchangeOutcome::Refused {
            kind: RefusalKind::AuthsVerdict,
            ..
        }
    ));
    assert_eq!(executor.count(), 0);
    assert_eq!(receipts.counts(), (1, 0));
}

fn demo_call() -> McpToolCall {
    McpToolCall::new(
        "reports",
        "read_report",
        Map::from_iter([("name".into(), Value::String("q3".into()))]),
    )
    .expect("fixed call")
}

fn demo_service(
    context: VerifierContext,
    channel_policy: ChannelBindingPolicy,
    local_endpoint: Option<[u8; 32]>,
) -> (
    Arc<McpAuthorizationService>,
    Arc<StaticReportExecutor>,
    Arc<MemoryReceiptSink>,
) {
    demo_service_with_challenge(context, channel_policy, local_endpoint, DEMO_CHALLENGE)
}

fn demo_service_with_challenge(
    context: VerifierContext,
    channel_policy: ChannelBindingPolicy,
    local_endpoint: Option<[u8; 32]>,
    challenge: ChallengeNonce,
) -> (
    Arc<McpAuthorizationService>,
    Arc<StaticReportExecutor>,
    Arc<MemoryReceiptSink>,
) {
    let kernel =
        AuthsKernel::new(context, demo_principal_methods(), demo_signature_suites()).unwrap();
    let executor = Arc::new(StaticReportExecutor::new(challenge));
    let receipts = Arc::new(MemoryReceiptSink::default());
    let service = McpAuthorizationService::new(
        McpServiceConfig::new(
            "reports",
            30,
            256 * 1024,
            2 * 1024 * 1024,
            channel_policy,
            local_endpoint,
        )
        .unwrap(),
        McpRuntimeDependencies::new(
            McpRequestStateDependencies::new(
                Arc::new(FixedClock(DEMO_NOW)),
                Arc::new(FixedChallengeSource(challenge)),
                Arc::new(InMemoryChallengeLedger::new(64).unwrap()),
                Arc::new(NoBudgetLedger),
            ),
            McpExecutionDependencies::new(
                receipts.clone(),
                Arc::new(DemoReceiptAttestor::new()),
                Arc::new(kernel),
                executor.clone(),
            ),
        ),
    )
    .unwrap();
    (Arc::new(service), executor, receipts)
}

fn demo_principal_methods() -> Vec<Box<dyn auths_ports::PrincipalMethod + Send + Sync>> {
    vec![
        Box::new(RawKeyMethod::new().unwrap()),
        Box::new(DidKeyMethod::new().unwrap()),
        Box::new(DidKeriMethod::new().unwrap()),
    ]
}

fn demo_signature_suites() -> Vec<Box<dyn auths_ports::SignatureSuite + Send + Sync>> {
    vec![
        Box::new(Ed25519Suite::new().unwrap()),
        Box::new(P256Sha256Suite::new().unwrap()),
    ]
}

fn demo_configuration_id() -> VerifierConfigurationId {
    let methods = demo_principal_methods();
    let suites = demo_signature_suites();
    let method_refs: Vec<&dyn auths_ports::PrincipalMethod> = methods
        .iter()
        .map(|method| method.as_ref() as &dyn auths_ports::PrincipalMethod)
        .collect();
    let suite_refs: Vec<&dyn auths_ports::SignatureSuite> = suites
        .iter()
        .map(|suite| suite.as_ref() as &dyn auths_ports::SignatureSuite)
        .collect();
    auths_registries::ImmutableRegistries::new(&method_refs, &suite_refs)
        .unwrap()
        .configuration_id()
}

/// Real Auths proof material for one exact application-owned canonical action.
pub struct ExactActionFixture {
    pub verifier: Verifier,
    pub proof: Vec<u8>,
    pub request: RequestContext,
    pub principal: String,
}

/// Builds a self-contained raw-key authorization for one exact product action.
///
/// This helper keeps vertical demos focused on their product boundary while
/// still exercising the production Auths authoring, codec, verifier, and SDK.
///
/// # Panics
///
/// Panics only when repository-owned fixture constants violate the Auths model.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture spells out every signed and trusted Auths object"
)]
pub fn exact_action_fixture(
    canonical: &CanonicalAction,
    audience: &str,
    now: u64,
    challenge: [u8; 32],
) -> ExactActionFixture {
    let audience = auths_model::Audience::parse(audience).expect("valid demo audience");
    let signing = SigningKey::from_bytes(&ROOT_SEED);
    let raw = RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )
    .expect("fixed raw key");
    let principal = raw.principal().expect("fixed principal");
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(RAW_KEY_V1).unwrap(),
        VerificationMethod::parse(principal.as_str()).unwrap(),
        SignatureSuiteId::parse(ED25519_V1).unwrap(),
    );
    let proof_ref = ProofRef::new([0xa1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let validity =
        ValidityWindow::new(Timestamp::new(now - 60), Timestamp::new(now + 600)).unwrap();
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience.clone(),
        Challenge::new(challenge),
        validity,
        principal.clone(),
        None,
        plan_id(&plan).unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let signing_request = prepare_action(envelope, descriptor).expect("action signing request");
    let signature = SignatureBytes::new(
        signing
            .sign(signing_request.signing_preimage())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let action = signing_request.complete(signature);
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        EvidenceTypeId::parse(RAW_KEY_V1).unwrap(),
        MediaType::parse(RAW_KEY_MEDIA_TYPE).unwrap(),
        raw.encode(),
    )
    .unwrap();
    let evidence = EvidenceObject::new(
        evidence_id(&unaddressed).unwrap(),
        unaddressed.evidence_type().clone(),
        unaddressed.media_type().clone(),
        unaddressed.bytes().to_vec(),
    )
    .unwrap();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).unwrap()),
        vec![evidence.id()],
    )
    .unwrap();
    let proof = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .unwrap();
    let assurance_policy = AssurancePolicy::new(
        AssurancePolicyId::parse("raw-key-baseline").unwrap(),
        vec![AssuranceRequirement::new(
            ParticipantRole::Actor,
            AssuranceQuantifier::Every,
            AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
            None,
        )],
    )
    .unwrap();
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(principal.as_str()).unwrap(),
        principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![canonical.profile().clone()],
        PermissionSet::new(vec![canonical.permission().clone()]).unwrap(),
        vec![canonical.permission().resource().clone()],
        AudienceSet::new(vec![audience.clone()]).unwrap(),
        validity,
        canonical.requested_budget().cloned(),
        1,
        assurance_policy.id().clone(),
        StatusPolicy::ExpiryOnly,
    )
    .unwrap();
    let budget_algebras = canonical
        .requested_budget()
        .map(|budget| budget.algebra().clone())
        .into_iter()
        .collect();
    let registries = AcceptedRegistries::new(
        RegistryManifestId::new([0x33; 32]),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![SignatureSuiteId::parse(ED25519_V1).unwrap()],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).unwrap()],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").unwrap(),
            AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse("uri-namespace-v1").unwrap()],
        budget_algebras,
        Vec::new(),
        vec![canonical.profile().clone()],
        vec![ProfilePolicyId::parse("exact-v1").unwrap()],
    )
    .unwrap();
    let context = VerifierContext::new(
        demo_configuration_id(),
        CompositionRequirement::exact(plan_id(proof.plan()).unwrap()),
        vec![anchor],
        registries,
        audience.clone(),
        Challenge::new(challenge),
        Timestamp::new(now),
        assurance_policy,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x44; 32]),
            Timestamp::new(now - 300),
            Timestamp::new(now + 600),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x55; 32]),
            Timestamp::new(now - 300),
            Timestamp::new(now + 600),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        ResourceMatcherId::parse("uri-namespace-v1").unwrap(),
        ProfilePolicyId::parse("exact-v1").unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        VerifierLimits::default(),
    )
    .unwrap();
    ExactActionFixture {
        verifier: Verifier::self_contained(context).unwrap(),
        proof: encode_bundle(&proof).unwrap(),
        request: RequestContext::new(audience.as_str(), challenge, now).unwrap(),
        principal: principal.as_str().into(),
    }
}

#[allow(clippy::too_many_lines)]
fn build_fixture(challenge: ChallengeNonce, signed_permission: Option<Permission>) -> DemoFixture {
    let call = demo_call();
    let body = call.canonical_bytes().expect("canonical MCP call");
    let canonical = McpProfile
        .canonicalize(&body)
        .expect("profile canonicalization");
    let canonical_action = encode_canonical_action(&canonical).expect("canonical action");
    let permission = signed_permission.unwrap_or_else(|| canonical.permission().clone());
    let signing = SigningKey::from_bytes(&ROOT_SEED);
    let raw = RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )
    .expect("fixed raw key");
    let principal = raw.principal().expect("fixed principal");
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(RAW_KEY_V1).unwrap(),
        VerificationMethod::parse(principal.as_str()).unwrap(),
        SignatureSuiteId::parse(ED25519_V1).unwrap(),
    );
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        permission.clone(),
        None,
        call.audience().unwrap(),
        Challenge::new(*challenge.as_bytes()),
        ValidityWindow::new(Timestamp::new(DEMO_NOW - 10), Timestamp::new(DEMO_NOW + 20)).unwrap(),
        principal.clone(),
        None,
        plan_id(&plan).unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let request = prepare_action(envelope, descriptor).expect("action signing request");
    let signature =
        SignatureBytes::new(signing.sign(request.signing_preimage()).to_bytes().to_vec()).unwrap();
    let action = request.complete(signature);
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        EvidenceTypeId::parse(RAW_KEY_V1).unwrap(),
        MediaType::parse(RAW_KEY_MEDIA_TYPE).unwrap(),
        raw.encode(),
    )
    .unwrap();
    let evidence = EvidenceObject::new(
        evidence_id(&unaddressed).unwrap(),
        unaddressed.evidence_type().clone(),
        unaddressed.media_type().clone(),
        unaddressed.bytes().to_vec(),
    )
    .unwrap();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).unwrap()),
        vec![evidence.id()],
    )
    .unwrap();
    let proof = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .unwrap();
    let assurance_policy = AssurancePolicy::new(
        AssurancePolicyId::parse("raw-key-baseline").unwrap(),
        vec![AssuranceRequirement::new(
            ParticipantRole::Actor,
            AssuranceQuantifier::Every,
            AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
            None,
        )],
    )
    .unwrap();
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(principal.as_str()).unwrap(),
        principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![canonical.profile().clone()],
        PermissionSet::new(vec![permission]).unwrap(),
        vec![auths_model::ResourceId::parse("mcp://reports").unwrap()],
        AudienceSet::new(vec![call.audience().unwrap()]).unwrap(),
        ValidityWindow::new(
            Timestamp::new(DEMO_NOW - 300),
            Timestamp::new(DEMO_NOW + 300),
        )
        .unwrap(),
        None,
        1,
        assurance_policy.id().clone(),
        StatusPolicy::ExpiryOnly,
    )
    .unwrap();
    let registries = AcceptedRegistries::new(
        RegistryManifestId::new([0x33; 32]),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![SignatureSuiteId::parse(ED25519_V1).unwrap()],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).unwrap()],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").unwrap(),
            AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse("uri-namespace-v1").unwrap()],
        Vec::new(),
        Vec::new(),
        vec![canonical.profile().clone()],
        vec![ProfilePolicyId::parse("exact-v1").unwrap()],
    )
    .unwrap();
    let context = VerifierContext::new(
        demo_configuration_id(),
        CompositionRequirement::exact(plan_id(proof.plan()).unwrap()),
        vec![anchor],
        registries,
        call.audience().unwrap(),
        Challenge::new(*challenge.as_bytes()),
        Timestamp::new(DEMO_NOW),
        assurance_policy,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x44; 32]),
            Timestamp::new(DEMO_NOW - 300),
            Timestamp::new(DEMO_NOW + 300),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x55; 32]),
            Timestamp::new(DEMO_NOW - 300),
            Timestamp::new(DEMO_NOW + 300),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        ResourceMatcherId::parse("uri-namespace-v1").unwrap(),
        ProfilePolicyId::parse("exact-v1").unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        VerifierLimits::default(),
    )
    .unwrap();
    DemoFixture {
        body,
        canonical_action,
        proof: encode_bundle(&proof).unwrap(),
        context,
        root_principal: principal.as_str().into(),
    }
}

fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
    let address = endpoint.addr();
    let direct = address.ip_addrs().next().copied().expect("direct address");
    EndpointAddr::new(endpoint.id()).with_ip_addr(direct)
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn target_flow_is_transport_independent_and_replay_safe() {
        assert_target_conformance().await;
    }

    #[tokio::test]
    #[ignore = "requires local UDP sockets"]
    async fn iroh_matches_the_reference_transport() {
        assert_iroh_target_conformance().await;
    }
}
