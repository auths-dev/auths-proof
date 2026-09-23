//! Hosted-style end-to-end tests of gateway-observed preconditions.
//!
//! Each test signs a real grant and MCP action, verifies it natively with the
//! gateway's own registries and `mcp-arguments-v1` policy at an explicit
//! gateway clock, and then follows the engine's post-verification dispatch
//! against a counting provider. The provider counts write entries, read-only
//! observations, and credential leases; a lease is taken only after
//! verification and a durable claim, exactly as in the engine.

use crate::engine::{
    GatewayObserveResult, GatewaySubmitResult, execute_claimed, gateway_verifier_configuration,
    not_entered, observe_outcome, observe_read_back, reobserve, replay_refused, reserve_bound,
    verify_command,
};
use crate::observer::{OUTCOME_SCHEMA, READ_BACK_SCHEMA, operation_subject};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::transport::{GatewayTransportError, ProviderPort, WriteTransportOutcome};
use crate::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, GatewayAttemptError,
    GatewayObserver, LogicalOperationId, OperatorNamespace,
};
use auths_codec::{
    action_id, action_signing_preimage, attachment_digest, body_digest, domain_commitment,
    encode_bundle, encode_canonical_action, encode_observation_requirements,
    encode_signed_observation, evidence_id, grant_id, grant_signing_preimage,
    observation_signing_preimage, plan_id,
};
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy,
    AssurancePolicyId, AttachmentDescriptor, Audience, AudienceSet, AuthorizationPlan,
    BundleHeader, CanonicalAction, Challenge, ChannelBindingId, CompositionRequirement,
    ConditionTest, Confidentiality, ControlBinding, CriticalExtension, CriticalExtensions,
    DetachedAttachment, DispositionId, EvidenceId, EvidenceObject, EvidenceTypeId, ExtensionId,
    FactName, FactText, FactValue, GrantStatement, GrantStatusSnapshot, MediaType, MemberValues,
    OBSERVATION_MEDIA_TYPE, ObservationCondition, ObservationFact, ObservationFacts,
    ObservationRequirement, ObservationRequirements, ObservationSchemaId, ObservationStatement,
    ObservationSubject, ObserverAnchor, ObserverAnchorId, Opacity, PermissionSet, Presence,
    PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId, ProofBundle,
    ProofRef, ResourceId, ResourceMatcherId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, SignedAction, SignedGrant, SignedObservation,
    StatementRef, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId,
    TrustedContext, ValidityWindow, VerificationMethod, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use auths_registries::{ImmutableRegistries, OBSERVATION_REQUIREMENT_EXTENSION_V1};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "bounds_tests.rs"]
mod bounds_tests;

const NOW: u64 = 1_790_000_000;
const SERVICE: &str = "gateway-observer-test";
const TOOL: &str = "set_status_v1";
const NAMESPACE: &str = "observer-demo";
const ORIGIN: &str = "https://api.airtable.com";
const RECORD: &str = "recTEST0000000001";
const OTHER_RECORD: &str = "recTEST0000000002";
const ANCHOR: &str = "gateway-observer";
const ASSURANCE: &str = "gateway-observer-test-v1";

/// Raw-key Ed25519 principal used for the root, the agent, and forgeries.
struct Signer {
    key: SigningKey,
    raw: RawKeyDescriptor,
    principal: PrincipalId,
}

impl Signer {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .expect("raw key");
        let principal = raw.principal().expect("principal");
        Self {
            key,
            raw,
            principal,
        }
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        )
    }

    fn evidence(&self) -> EvidenceObject {
        let object = |id| {
            EvidenceObject::new(
                id,
                EvidenceTypeId::parse(RAW_KEY_V1).expect("type"),
                MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("media"),
                self.raw.encode(),
            )
            .expect("evidence")
        };
        object(evidence_id(&object(EvidenceId::new([0; 32]))).expect("evidence ID"))
    }

    fn sign(&self, preimage: &[u8]) -> SignatureBytes {
        SignatureBytes::new(self.key.sign(preimage).to_bytes().to_vec()).expect("signature")
    }
}

fn window(from: u64, until: u64) -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(from), Timestamp::new(until)).expect("window")
}

fn audience() -> Audience {
    Audience::parse(&format!("mcp://{SERVICE}")).expect("audience")
}

fn call(arguments: &Map<String, Value>) -> McpToolCall {
    McpToolCall::new(SERVICE, TOOL, arguments.clone()).expect("call")
}

fn name(value: &str) -> FactName {
    FactName::parse(value).expect("fact name")
}

fn text(value: &str) -> FactValue {
    FactValue::Text(FactText::new(value).expect("text"))
}

fn read_back_subject(record: &str) -> String {
    format!("{ORIGIN}/v0/appTEST0000000001/tblTEST0000000001/{record}#/fields/DemoStatus")
}

fn namespace() -> OperatorNamespace {
    OperatorNamespace::parse(NAMESPACE).expect("namespace")
}

fn step_subject(operation: &str) -> String {
    operation_subject(
        &namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
    )
}

/// Compiles a recipe for `extra` profile fields and its precondition block.
fn recipe(extra: &Value, preconditions: &Value) -> CompiledRecipe {
    let mut fields = json!({
        "operation_id": {"kind": "string", "minimum": 1, "maximum": 128},
        "operator_namespace": {"type": "enum", "variants": [NAMESPACE]},
        "recipe_digest": {"kind": "string", "minimum": 64, "maximum": 64},
        "record_id": {"kind": "string", "minimum": 17, "maximum": 43},
        "replacement": {"type": "enum", "variants": ["Approved", "Pending"]}
    });
    for (key, value) in extra.as_object().expect("extra fields") {
        fields[key] = value.clone();
    }
    let schema = json!({"kind": "object", "fields": fields});
    let digest = hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&schema).expect("canonical schema"),
    ));
    let lock = json!({
        "command_schema": schema, "generator_format": 2, "profile": "gateway-observer-test",
        "schema": "auths.self-hosted-profile-lock/1", "schema_digest": digest,
        "service": SERVICE, "tool": TOOL, "version": 1
    });
    let path = json!([
        {"kind": "fixed", "value": "v0"},
        {"kind": "fixed", "value": "appTEST0000000001"},
        {"kind": "fixed", "value": "tblTEST0000000001"},
        {"kind": "field", "name": "record_id"}
    ]);
    let source = json!({
        "schema": "auths.gateway-recipe-source/1", "profile_schema_digest": digest,
        "service": SERVICE, "tool": TOOL, "operator_namespace": NAMESPACE,
        "credential": {"kind": "bearer"}, "origin": ORIGIN,
        "write": {"method": "PATCH", "path": path, "body": {"kind": "json", "value": {
            "kind": "object", "fields": {"fields": {"kind": "object", "fields": {
                "DemoStatus": {"kind": "field", "name": "replacement"}}}}}}},
        "observation": {"path": path, "json_pointer": "/fields/DemoStatus",
            "expected_field": "replacement", "maximum_response_bytes": 16384},
        "echo": {"write": "/fields/auths_echo", "observe": "/fields/auths_echo"},
        "preconditions": preconditions
    });
    CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        &serde_json::to_vec(&lock).expect("lock"),
    )
    .expect("test recipe compiles")
}

fn update_recipe() -> CompiledRecipe {
    recipe(
        &json!({
            "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
            "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
        }),
        &json!({"read_back_subject": "record_uri", "verified": ["expected"]}),
    )
}

fn chained_recipe() -> CompiledRecipe {
    recipe(
        &json!({
            "depends_on": {"kind": "string", "minimum": 1, "maximum": 256},
            "depends_on_commitment": {"kind": "string", "minimum": 64, "maximum": 64}
        }),
        &json!({"verified": ["depends_on", "depends_on_commitment"]}),
    )
}

fn observer_anchor(observer: &PrincipalId) -> ObserverAnchor {
    ObserverAnchor::new(
        ObserverAnchorId::parse(ANCHOR).expect("observer anchor ID"),
        observer.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        vec![
            ObservationSchemaId::parse(READ_BACK_SCHEMA).expect("schema"),
            ObservationSchemaId::parse(OUTCOME_SCHEMA).expect("schema"),
        ],
        vec![
            ResourceId::parse(&format!("{ORIGIN}/")).expect("namespace"),
            ResourceId::parse(&format!("auths-gateway://{NAMESPACE}/operations/"))
                .expect("namespace"),
        ],
        window(NOW - 86_400, NOW + 86_400),
    )
    .expect("observer anchor")
}

fn accepted_registries() -> AcceptedRegistries {
    AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        vec![
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
            SignatureSuiteId::parse("p256-sha256-v1").expect("suite"),
        ],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).expect("evidence type")],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").expect("claim"),
            AssuranceClaimId::parse("self-certifying-identifier").expect("claim"),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse("uri-namespace-v1").expect("matcher")],
        Vec::new(),
        vec![
            ExtensionId::parse(auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1)
                .expect("extension"),
            ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1).expect("extension"),
        ],
        vec![call(&Map::new()).profile_ref().expect("profile")],
        vec![ProfilePolicyId::parse(crate::MCP_ARGUMENTS_V1).expect("policy")],
    )
    .expect("registries")
}

/// Trust pinned to `root`, with one observer anchor for `observer`.
fn context(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
) -> TrustedContext {
    context_with_depth(root, observer, configuration, 1)
}

/// Trust pinned to `root` that permits `depth` delegation edges.
fn context_with_depth(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    depth: u16,
) -> TrustedContext {
    context_with(
        &[root],
        observer,
        configuration,
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        depth,
    )
}

/// Trust pinned to every root in `roots` under one composition requirement.
fn context_with(
    roots: &[&Signer],
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    composition: CompositionRequirement,
    depth: u16,
) -> TrustedContext {
    let configuration = configuration.map_or_else(
        || gateway_verifier_configuration().expect("configuration"),
        auths_model::VerifierConfigurationId::new,
    );
    let assurance = AssurancePolicyId::parse(ASSURANCE).expect("assurance");
    let anchors = roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            TrustAnchor::new(
                TrustAnchorId::parse(&format!("root-{index}")).expect("anchor ID"),
                root.principal.clone(),
                vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
                vec![call(&Map::new()).profile_ref().expect("profile")],
                PermissionSet::new(vec![call(&Map::new()).permission().expect("permission")])
                    .expect("permissions"),
                vec![ResourceId::parse(&format!("mcp://{SERVICE}/")).expect("namespace")],
                AudienceSet::new(vec![audience()]).expect("audiences"),
                window(NOW - 86_400, NOW + 86_400),
                None,
                depth,
                assurance.clone(),
                StatusPolicy::ExpiryOnly,
            )
            .expect("trust anchor")
        })
        .collect();
    TrustedContext::new(
        configuration,
        composition,
        anchors,
        accepted_registries(),
        audience(),
        Challenge::new([0; 32]),
        Timestamp::new(NOW),
        AssurancePolicy::new(assurance, Vec::new()).expect("assurance policy"),
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x63; 32]),
            Timestamp::new(NOW - 86_400),
            Timestamp::new(NOW + 86_400),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal status"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x64; 32]),
            Timestamp::new(NOW - 86_400),
            Timestamp::new(NOW + 86_400),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant status"),
        ResourceMatcherId::parse("uri-namespace-v1").expect("matcher"),
        ProfilePolicyId::parse(crate::MCP_ARGUMENTS_V1).expect("policy"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        VerifierLimits::default(),
    )
    .expect("context")
    .with_observer_anchors(vec![observer_anchor(observer)])
    .expect("observer anchors")
}

fn read_back_requirement() -> ObservationRequirement {
    ObservationRequirement::new(
        ObserverAnchorId::parse(ANCHOR).expect("anchor"),
        ObservationSchemaId::parse(READ_BACK_SCHEMA).expect("schema"),
        ObservationSubject::ActionFact(name("record_uri")),
        60,
        vec![ObservationCondition::new(
            name("value"),
            ConditionTest::EqAction(name("expected")),
        )],
    )
    .expect("requirement")
}

fn outcome_requirement() -> ObservationRequirement {
    ObservationRequirement::new(
        ObserverAnchorId::parse(ANCHOR).expect("anchor"),
        ObservationSchemaId::parse(OUTCOME_SCHEMA).expect("schema"),
        ObservationSubject::ActionFact(name("depends_on")),
        3_600,
        vec![
            ObservationCondition::new(
                name("stage"),
                ConditionTest::Member(
                    MemberValues::new(vec![text("observed-by-provider")]).expect("members"),
                ),
            ),
            ObservationCondition::new(
                name("commitment"),
                ConditionTest::EqAction(name("depends_on_commitment")),
            ),
        ],
    )
    .expect("requirement")
}

fn grant(
    root: &Signer,
    agent: &Signer,
    requirement: Option<ObservationRequirement>,
) -> SignedGrant {
    let extensions = requirement.map_or_else(CriticalExtensions::empty, |requirement| {
        let bytes = encode_observation_requirements(
            &ObservationRequirements::new(vec![requirement]).expect("requirements"),
        )
        .expect("requirement bytes");
        CriticalExtensions::new(vec![
            CriticalExtension::new(
                ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1).expect("extension"),
                bytes,
            )
            .expect("extension"),
        ])
        .expect("extensions")
    });
    let statement = GrantStatement::new(
        root.principal.clone(),
        agent.principal.clone(),
        call(&Map::new()).profile_ref().expect("profile"),
        PermissionSet::new(vec![call(&Map::new()).permission().expect("permission")])
            .expect("permissions"),
        window(NOW - 3_600, NOW + 86_400),
        AudienceSet::new(vec![audience()]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        extensions,
    );
    let descriptor = root.descriptor();
    let signature = root.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
    SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
}

/// One signed submission: proof bytes, canonical action bytes, commitment.
struct Submission {
    proof: Vec<u8>,
    action: Vec<u8>,
    commitment: [u8; 32],
}

fn attachments(observations: &[Vec<u8>]) -> (Vec<AttachmentDescriptor>, Vec<DetachedAttachment>) {
    let mut descriptors = Vec::new();
    let mut detached = Vec::new();
    for bytes in observations {
        let digest = attachment_digest(bytes);
        descriptors.push(AttachmentDescriptor::new(
            digest,
            MediaType::parse(OBSERVATION_MEDIA_TYPE).expect("media type"),
            u64::try_from(bytes.len()).expect("length"),
            DispositionId::parse("authorization-input").expect("disposition"),
            Confidentiality::Plain,
            Presence::Required,
            Opacity::MustBeInspectable,
        ));
        detached.push(DetachedAttachment::new(digest, bytes.clone()).expect("attachment"));
    }
    descriptors.sort();
    (descriptors, detached)
}

fn sign_action(agent: &Signer, envelope: ActionEnvelope) -> SignedAction {
    let descriptor = agent.descriptor();
    let signature = agent.sign(&action_signing_preimage(&envelope, &descriptor).expect("preimage"));
    SignedAction::new(envelope, SignatureEnvelope::new(descriptor, signature))
}

fn envelope(
    agent: &Signer,
    canonical: &CanonicalAction,
    grant: &SignedGrant,
    plan: &AuthorizationPlan,
    proof_ref: ProofRef,
    descriptors: Vec<AttachmentDescriptor>,
) -> ActionEnvelope {
    ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        None,
        audience(),
        Challenge::new([0; 32]),
        window(NOW - 3_600, NOW + 3_600),
        agent.principal.clone(),
        Some(grant_id(grant.statement()).expect("grant ID")),
        plan_id(plan).expect("plan ID"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        descriptors,
        CriticalExtensions::empty(),
    )
}

fn submission(
    root: &Signer,
    agent: &Signer,
    grant: &SignedGrant,
    arguments: &Map<String, Value>,
    observations: &[Vec<u8>],
) -> Submission {
    let bytes = call(arguments).canonical_bytes().expect("canonical call");
    let (descriptors, detached) = attachments(observations);
    let canonical: CanonicalAction = McpProfile
        .canonicalize(&bytes)
        .expect("canonical action")
        .with_detached_attachments(detached)
        .expect("attachments");
    let proof_ref = ProofRef::new([0x0b; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let action = sign_action(
        agent,
        envelope(
            agent,
            &canonical,
            grant,
            &plan,
            proof_ref,
            descriptors.clone(),
        ),
    );
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
            vec![root.evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![agent.evidence().id()],
        )
        .expect("action binding"),
    ];
    let mut evidence = vec![root.evidence(), agent.evidence()];
    evidence.sort_by_key(EvidenceObject::id);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant.clone()],
        vec![action],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        descriptors,
        Some(canonical.body().to_vec()),
    )
    .expect("bundle");
    let action = encode_canonical_action(&canonical).expect("action bytes");
    let commitment = *domain_commitment("auths.canonical-action.v1", &action)
        .expect("commitment")
        .as_bytes();
    Submission {
        proof: encode_bundle(&bundle).expect("proof bytes"),
        action,
        commitment,
    }
}

/// A read-back statement signed by `signer` while naming `claimed` as its
/// observer: an agent forging, or an agent observing for itself.
fn forged_read_back(signer: &Signer, claimed: &PrincipalId, record: &str, value: &str) -> Vec<u8> {
    let statement = ObservationStatement::new(
        claimed.clone(),
        ObservationSchemaId::parse(READ_BACK_SCHEMA).expect("schema"),
        ResourceId::parse(&read_back_subject(record)).expect("subject"),
        Timestamp::new(NOW),
        ObservationFacts::new(vec![ObservationFact::new(name("value"), text(value))])
            .expect("facts"),
    );
    let descriptor = signer.descriptor();
    let signature =
        signer.sign(&observation_signing_preimage(&statement, &descriptor).expect("preimage"));
    encode_signed_observation(
        &SignedObservation::new(
            statement,
            SignatureEnvelope::new(descriptor, signature),
            vec![signer.evidence()],
        )
        .expect("observation"),
    )
    .expect("observation bytes")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivery {
    Respond,
    TimeoutAfterApplying,
}

/// Synthetic provider that counts every write entry, read, and lease.
struct CountingProvider {
    delivery: Mutex<Delivery>,
    records: Mutex<Map<String, Value>>,
    writes: AtomicUsize,
    reads: AtomicUsize,
    leases: AtomicUsize,
}

impl CountingProvider {
    fn new() -> Self {
        let mut records = Map::new();
        for record in [RECORD, OTHER_RECORD] {
            records.insert(record.to_owned(), json!({"DemoStatus": "Pending"}));
        }
        Self {
            delivery: Mutex::new(Delivery::Respond),
            records: Mutex::new(records),
            writes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            leases: AtomicUsize::new(0),
        }
    }

    fn set_delivery(&self, delivery: Delivery) {
        *self.delivery.lock().expect("delivery") = delivery;
    }

    /// Another party with write access changes the record.
    fn overwrite(&self, record: &str, status: &str) {
        self.records.lock().expect("records")[record]["DemoStatus"] = json!(status);
    }

    fn record_of(url: &str) -> String {
        url.rsplit('/').next().expect("record segment").to_owned()
    }

    fn counts(&self) -> (usize, usize, usize) {
        (
            self.writes.load(Ordering::SeqCst),
            self.reads.load(Ordering::SeqCst),
            self.leases.load(Ordering::SeqCst),
        )
    }
}

impl ProviderPort for CountingProvider {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(request.body())
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let update = body["fields"].as_object().cloned().unwrap_or_default();
        let record = Self::record_of(request.url());
        self.records.lock().expect("records")[&record]
            .as_object_mut()
            .expect("record fields")
            .extend(update);
        Ok(match *self.delivery.lock().expect("delivery") {
            Delivery::Respond => WriteTransportOutcome::ResponseRecorded {
                status: 200,
                digest: [4; 32],
            },
            Delivery::TimeoutAfterApplying => WriteTransportOutcome::Unknown,
        })
    }

    async fn read_back(&self, request: &ClosedObservationRequest) -> Option<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let record = Self::record_of(request.url());
        let fields = self.records.lock().expect("records")[&record].clone();
        serde_json::to_vec(&json!({"id": record, "fields": fields})).ok()
    }
}

struct Harness {
    recipe: CompiledRecipe,
    context: TrustedContext,
    store: TestAttempts,
    provider: CountingProvider,
    observer: GatewayObserver,
    root: Signer,
    agent: Signer,
}

impl Harness {
    fn open(recipe: CompiledRecipe, backend: Backend) -> Self {
        let root = Signer::new(0x11);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = context(&root, observer.principal(), None);
        Self::with(recipe, context, observer, root, Signer::new(0x22), backend)
    }

    fn with(
        recipe: CompiledRecipe,
        context: TrustedContext,
        observer: GatewayObserver,
        root: Signer,
        agent: Signer,
        backend: Backend,
    ) -> Self {
        Self {
            recipe,
            context,
            store: TestAttempts::open(backend),
            provider: CountingProvider::new(),
            observer,
            root,
            agent,
        }
    }

    fn arguments(&self, operation: &str, record: &str, extra: &Value) -> Map<String, Value> {
        let mut arguments = json!({
            "operation_id": operation,
            "operator_namespace": NAMESPACE,
            "recipe_digest": self.recipe.digest_hex(),
            "record_id": record,
            "replacement": "Approved"
        })
        .as_object()
        .expect("object")
        .clone();
        arguments.extend(extra.as_object().expect("extra").clone());
        arguments
    }

    fn sign(
        &self,
        requirement: Option<ObservationRequirement>,
        arguments: &Map<String, Value>,
        observations: &[Vec<u8>],
    ) -> Submission {
        let grant = grant(&self.root, &self.agent, requirement);
        submission(&self.root, &self.agent, &grant, arguments, observations)
    }

    /// Mirrors the engine: verify, claim, lease, then enter the provider.
    async fn submit(&self, submission: &Submission, now: u64) -> GatewaySubmitResult {
        let (request, bound) = match verify_command(
            &self.recipe,
            &self.context,
            now,
            &submission.proof,
            &submission.action,
        ) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let attempts = self.store.attempts();
        match attempts.claim(&request, *self.recipe.digest()).await {
            Ok(claim) => {
                let claim = match reserve_bound(attempts, bound.as_ref(), &request, claim).await {
                    Ok(value) => value,
                    Err(result) => return result,
                };
                self.provider.leases.fetch_add(1, Ordering::SeqCst);
                execute_claimed(claim, &request, &self.provider).await
            }
            Err(GatewayAttemptError::Replay) => {
                match attempts
                    .resume_observable(&request, *self.recipe.digest())
                    .await
                {
                    Ok(Some(attempt)) => {
                        self.provider.leases.fetch_add(1, Ordering::SeqCst);
                        reobserve(attempt, &request, &self.provider).await
                    }
                    _ => replay_refused(),
                }
            }
            Err(_) => not_entered("gateway.attempt.unavailable"),
        }
    }

    async fn read_back(&self, record: &str, at: u64) -> Vec<u8> {
        let arguments = json!({"record_id": record})
            .as_object()
            .expect("object")
            .clone();
        let target = self.recipe.read_back_target(&arguments).expect("target");
        self.provider.leases.fetch_add(1, Ordering::SeqCst);
        signed_bytes(observe_read_back(&target, &self.observer, &self.provider, || Some(at)).await)
    }

    async fn outcome(&self, operation: &str, at: u64) -> GatewayObserveResult {
        observe_outcome(
            self.store.attempts(),
            &namespace(),
            &self.observer,
            operation,
            at,
        )
        .await
    }
}

fn signed_bytes(result: GatewayObserveResult) -> Vec<u8> {
    let GatewayObserveResult::Signed {
        observation_b64,
        media_type,
        ..
    } = result
    else {
        panic!("expected a signed observation, got {result:?}");
    };
    assert_eq!(media_type, OBSERVATION_MEDIA_TYPE);
    Base64UrlUnpadded::decode_vec(&observation_b64).expect("base64")
}

fn stage_of(bytes: &[u8]) -> String {
    let decoded =
        auths_codec::decode_signed_observation(bytes, &VerifierLimits::default()).expect("decode");
    let stage = decoded
        .statement()
        .facts()
        .as_slice()
        .iter()
        .find(|fact| fact.name().as_str() == "stage")
        .map(|fact| fact.value().clone());
    match stage {
        Some(FactValue::Text(text)) => text.as_str().to_owned(),
        other => panic!("no stage fact: {other:?}"),
    }
}

fn indeterminate(code: &str) -> GatewaySubmitResult {
    GatewaySubmitResult::Indeterminate {
        code: code.to_owned(),
    }
}

fn denied(code: &str) -> GatewaySubmitResult {
    GatewaySubmitResult::Denied {
        code: code.to_owned(),
    }
}

fn update_extra(record: &str, expected: &str) -> Value {
    json!({"expected": expected, "record_uri": read_back_subject(record)})
}

async fn fresh_matching_read_back_authorizes_the_replacement_write(backend: Backend) {
    let harness = Harness::open(update_recipe(), backend);
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("update-1", RECORD, &update_extra(RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    let result = harness.submit(&signed, NOW + 60).await;
    assert!(
        matches!(
            result,
            GatewaySubmitResult::ObservedByProvider {
                status: Some(200),
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(
        harness.provider.counts(),
        (1, 2, 2),
        "one write; the pre-read and the post-write read-back"
    );
}

async fn stale_changed_or_missing_expected_is_refused_before_credential_access(backend: Backend) {
    let cases = [
        (
            "stale-by-one-second",
            NOW + 61,
            "Pending",
            true,
            indeterminate("observation-missing"),
        ),
        (
            "changed-value",
            NOW + 30,
            "Approved",
            true,
            denied("observation-condition-false"),
        ),
        (
            "missing-observation",
            NOW + 30,
            "Pending",
            false,
            indeterminate("observation-missing"),
        ),
    ];
    for (id, at, expected, attach, outcome) in cases {
        let harness = Harness::open(update_recipe(), backend);
        let observation = harness.read_back(RECORD, NOW).await;
        let arguments = harness.arguments(id, RECORD, &update_extra(RECORD, expected));
        let attached = if attach {
            vec![observation]
        } else {
            Vec::new()
        };
        let signed = harness.sign(Some(read_back_requirement()), &arguments, &attached);
        assert_eq!(harness.submit(&signed, at).await, outcome, "{id}");
        assert_eq!(
            harness.provider.counts(),
            (0, 1, 1),
            "{id}: only the pre-read touched the provider; no write and no write-path lease"
        );
        let operation = LogicalOperationId::parse(id).expect("operation");
        assert_eq!(
            harness
                .store
                .attempts()
                .read(&namespace(), &operation)
                .await
                .expect("read"),
            None,
            "{id}: a refused action consumes no logical operation"
        );
    }
}

async fn read_back_of_another_record_cannot_license_this_write(backend: Backend) {
    let harness = Harness::open(update_recipe(), backend);
    harness.provider.overwrite(RECORD, "Approved");
    let observation = harness.read_back(OTHER_RECORD, NOW).await;
    let arguments = harness.arguments("swap", RECORD, &update_extra(OTHER_RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    assert_eq!(
        harness.submit(&signed, NOW + 1).await,
        not_entered("gateway.recipe.precondition-subject-mismatch")
    );
    assert_eq!(harness.provider.counts(), (0, 1, 1));
}

async fn replaced_in_between_is_authorized_inside_the_documented_window(backend: Backend) {
    let harness = Harness::open(update_recipe(), backend);
    let observation = harness.read_back(RECORD, NOW).await;
    harness.provider.overwrite(RECORD, "Approved");
    let arguments = harness.arguments("window", RECORD, &update_extra(RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    let result = harness.submit(&signed, NOW + 5).await;
    assert!(
        matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
        "the fact held at observed_at, not at execution: {result:?}"
    );
    assert_eq!(harness.provider.counts().0, 1);
}

async fn chained_step_is_refused_until_the_previous_step_is_provider_bound(backend: Backend) {
    let harness = Harness::open(chained_recipe(), backend);
    let first = harness.sign(
        None,
        &harness.arguments(
            "step-1",
            RECORD,
            &json!({"depends_on": step_subject("genesis"), "depends_on_commitment": "0".repeat(64)}),
        ),
        &[],
    );
    let second = |observations: &[Vec<u8>], commitment: &str| {
        harness.sign(
            Some(outcome_requirement()),
            &harness.arguments(
                "step-2",
                OTHER_RECORD,
                &json!({"depends_on": step_subject("step-1"), "depends_on_commitment": commitment}),
            ),
            observations,
        )
    };
    let commitment = hex::encode(first.commitment);
    assert_eq!(
        harness.outcome("step-1", NOW).await,
        GatewayObserveResult::Refused {
            code: "gateway.observer.operation-unknown".to_owned()
        }
    );
    assert_eq!(
        harness.submit(&second(&[], &commitment), NOW).await,
        indeterminate("observation-missing")
    );
    harness
        .provider
        .set_delivery(Delivery::TimeoutAfterApplying);
    assert_eq!(
        harness.submit(&first, NOW + 1).await,
        GatewaySubmitResult::Unknown
    );
    let unknown = signed_bytes(harness.outcome("step-1", NOW + 10).await);
    assert_eq!(stage_of(&unknown), "unknown");
    assert_eq!(
        harness
            .submit(&second(&[unknown], &commitment), NOW + 20)
            .await,
        denied("observation-condition-false")
    );
    assert_eq!(
        harness.provider.counts().0,
        1,
        "step 2 has not entered the provider"
    );
    harness.provider.set_delivery(Delivery::Respond);
    assert!(matches!(
        harness.submit(&first, NOW + 30).await,
        GatewaySubmitResult::ObservedByProvider { status: None, .. }
    ));
    let bound = signed_bytes(harness.outcome("step-1", NOW + 40).await);
    assert_eq!(stage_of(&bound), "observed-by-provider");
    assert_eq!(
        harness
            .submit(
                &second(std::slice::from_ref(&bound), &"1".repeat(64)),
                NOW + 50
            )
            .await,
        denied("observation-condition-false"),
        "an outcome for a different commitment does not satisfy step 2"
    );
    assert!(matches!(
        harness
            .submit(&second(&[bound], &commitment), NOW + 50)
            .await,
        GatewaySubmitResult::ObservedByProvider {
            status: Some(200),
            ..
        }
    ));
    assert_eq!(harness.provider.counts().0, 2, "one entry per step");
}

async fn self_signed_or_forged_observations_never_satisfy(backend: Backend) {
    let harness = Harness::open(update_recipe(), backend);
    let arguments = harness.arguments("forged", RECORD, &update_extra(RECORD, "Pending"));
    for observation in [
        forged_read_back(&harness.agent, &harness.agent.principal, RECORD, "Pending"),
        forged_read_back(
            &harness.agent,
            harness.observer.principal(),
            RECORD,
            "Pending",
        ),
    ] {
        let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
        assert_eq!(
            harness.submit(&signed, NOW + 1).await,
            indeterminate("observation-missing")
        );
    }
    assert_eq!(harness.provider.counts(), (0, 0, 0));
}

async fn observer_in_the_authority_chain_is_refused(backend: Backend) {
    let root = Signer::new(0x11);
    let agent = Signer::new(0x22);
    let context = context(&root, &agent.principal, None);
    let harness = Harness::with(
        update_recipe(),
        context,
        GatewayObserver::from_test_seed(0x33),
        root,
        agent,
        backend,
    );
    let observation = forged_read_back(&harness.agent, &harness.agent.principal, RECORD, "Pending");
    let arguments = harness.arguments("self-observer", RECORD, &update_extra(RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    assert_eq!(
        harness.submit(&signed, NOW + 1).await,
        denied("observer-in-authority-chain")
    );
    assert_eq!(harness.provider.counts(), (0, 0, 0));
}

async fn action_fact_policy_is_bound_into_the_pinned_configuration(backend: Backend) {
    let raw_key = auths_raw_key::RawKeyMethod::new().expect("raw key");
    let did_key = auths_did_key::DidKeyMethod::new().expect("did:key");
    let did_keri = auths_did_keri::DidKeriMethod::new().expect("did:keri");
    let ed25519 = auths_signature::Ed25519Suite::new().expect("ed25519");
    let p256 = auths_signature::P256Sha256Suite::new().expect("p256");
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let without_policy = *ImmutableRegistries::new(&methods, &suites)
        .expect("registries")
        .configuration_id()
        .as_bytes();
    assert_ne!(
        &without_policy,
        gateway_verifier_configuration()
            .expect("configuration")
            .as_bytes()
    );
    let root = Signer::new(0x11);
    let observer = GatewayObserver::from_test_seed(0x33);
    let context = context(&root, observer.principal(), Some(without_policy));
    let harness = Harness::with(
        update_recipe(),
        context,
        observer,
        root,
        Signer::new(0x22),
        backend,
    );
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("unpinned", RECORD, &update_extra(RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    assert_eq!(
        harness.submit(&signed, NOW + 1).await,
        denied("verifier-configuration-mismatch")
    );
    assert_eq!(harness.provider.counts().0, 0);
}

/// A threshold proof: one branch per index in `signing`, each a grant from
/// `roots[index]` to `agent` and an action under it, combined in a `k`-of-n
/// plan. A root may own more than one branch. The trust, not the plan, sets
/// how many distinct roots must authorize.
fn threshold_submission(
    roots: &[&Signer],
    signing: &[usize],
    k: u16,
    agent: &Signer,
    arguments: &Map<String, Value>,
) -> Submission {
    let bytes = call(arguments).canonical_bytes().expect("canonical call");
    let canonical: CanonicalAction = McpProfile.canonicalize(&bytes).expect("canonical action");
    let proof_ref = |index: usize| ProofRef::new([0x40 + u8::try_from(index).expect("index"); 32]);
    let plan = match signing {
        [only] => AuthorizationPlan::proof(proof_ref(*only)),
        _ => AuthorizationPlan::k_of_n(
            k,
            signing
                .iter()
                .map(|index| AuthorizationPlan::proof(proof_ref(*index)))
                .collect(),
        )
        .expect("threshold plan"),
    };
    let mut grants = Vec::new();
    let mut actions = Vec::new();
    let mut bindings = Vec::new();
    let mut evidence = vec![agent.evidence()];
    for &index in signing {
        let root = roots[index];
        let signed = grant(root, agent, None);
        let action = sign_action(
            agent,
            envelope(
                agent,
                &canonical,
                &signed,
                &plan,
                proof_ref(index),
                Vec::new(),
            ),
        );
        if !grants.contains(&signed) {
            bindings.push(
                ControlBinding::new(
                    StatementRef::Grant(grant_id(signed.statement()).expect("grant ID")),
                    vec![root.evidence().id()],
                )
                .expect("grant binding"),
            );
            grants.push(signed);
        }
        bindings.push(
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![agent.evidence().id()],
            )
            .expect("action binding"),
        );
        if !evidence.contains(&root.evidence()) {
            evidence.push(root.evidence());
        }
        actions.push(action);
    }
    evidence.sort_by_key(EvidenceObject::id);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        actions,
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("bundle");
    let action = encode_canonical_action(&canonical).expect("action bytes");
    let commitment = *domain_commitment("auths.canonical-action.v1", &action)
        .expect("commitment")
        .as_bytes();
    Submission {
        proof: encode_bundle(&bundle).expect("proof bytes"),
        action,
        commitment,
    }
}

/// A 2-of-3 root: three trust anchors and a composition requirement of two
/// authorized branches from two distinct roots. Two roots signing through
/// the kernel's `KOfN` plan authorize; one root, even with two branches, is
/// refused before any claim or credential lease.
async fn two_of_three_root_authorizes_only_with_two_distinct_roots(backend: Backend) {
    let roots = [Signer::new(0x51), Signer::new(0x52), Signer::new(0x53)];
    let roots: Vec<&Signer> = roots.iter().collect();
    let observer = GatewayObserver::from_test_seed(0x33);
    let context = context_with(
        &roots,
        observer.principal(),
        None,
        CompositionRequirement::new(None, 2, 1, 2).expect("2-of-3 composition"),
        1,
    );
    let harness = Harness::with(
        update_recipe(),
        context,
        observer,
        Signer::new(0x51),
        Signer::new(0x22),
        backend,
    );
    let submit = |operation: &str, branches: &[&Signer], signing: &[usize]| {
        let arguments = harness.arguments(
            operation,
            RECORD,
            &json!({"expected": "Pending", "record_uri": read_back_subject(RECORD)}),
        );
        threshold_submission(branches, signing, 2, &harness.agent, &arguments)
    };
    let one_root_twice = [roots[0], roots[0], roots[1]];
    for (operation, branches, signing) in [
        ("one-root", &roots[..], vec![1]),
        ("one-root-two-branches", &one_root_twice[..], vec![0, 1]),
    ] {
        let result = harness
            .submit(&submit(operation, branches, &signing), NOW)
            .await;
        assert_eq!(
            result,
            denied("composition-requirement-not-met"),
            "{operation}"
        );
    }
    assert_eq!(harness.provider.counts(), (0, 0, 0));
    for (operation, signing) in [("roots-0-1", [0, 1]), ("roots-1-2", [1, 2])] {
        let result = harness
            .submit(&submit(operation, &roots, &signing), NOW)
            .await;
        assert!(
            matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
            "{operation}: {result:?}"
        );
    }
    assert_eq!(
        harness.provider.counts().0,
        2,
        "one entry per authorized operation"
    );
}

/// Root, operator, and observer principals must not overlap.
#[test]
fn production_principals_must_be_separate() {
    use crate::{PrincipalSeparationError as E, check_principal_separation as check};
    let root = Signer::new(0x11);
    let operator = Signer::new(0x44);
    let observer = GatewayObserver::from_test_seed(0x33);
    let trust = context(&root, observer.principal(), None);
    assert_eq!(
        check(&trust, &operator.principal, Some(observer.principal())),
        Ok(())
    );
    assert_eq!(
        check(&trust, &root.principal, Some(observer.principal())),
        Err(E::OperatorIsRoot)
    );
    assert_eq!(
        check(&trust, observer.principal(), Some(observer.principal())),
        Err(E::OperatorIsObserver)
    );
    let operator_observes = context(&root, &operator.principal, None);
    assert_eq!(
        check(&operator_observes, &operator.principal, None),
        Err(E::OperatorIsObserver)
    );
    let root_observes = context(&root, &root.principal, None);
    assert_eq!(
        check(&root_observes, &operator.principal, None),
        Err(E::ObserverIsRoot)
    );
    let unanchored = GatewayObserver::from_test_seed(0x77);
    assert_eq!(
        check(&trust, &operator.principal, Some(unanchored.principal())),
        Err(E::ObserverNotAnchored)
    );
    for (error, code) in [
        (E::OperatorIsRoot, "gateway.trust.operator-is-root"),
        (E::OperatorIsObserver, "gateway.trust.operator-is-observer"),
        (E::ObserverIsRoot, "gateway.trust.observer-is-root"),
        (
            E::ObserverNotAnchored,
            "gateway.trust.observer-not-anchored",
        ),
    ] {
        assert_eq!(error.code(), code);
    }
}

/// A KMS-held observer through the AWS KMS reference adapter over a mock
/// KMS API. No live KMS and no credentials are involved.
mod mock_custody {
    use auths_custody_aws_kms::{
        AwsKmsApi, AwsKmsFailure, AwsKmsKeyDescription, AwsKmsKeySpec, AwsKmsKeyUsage,
        AwsKmsMessageType, AwsKmsSignOutput, AwsKmsSigningAlgorithm,
    };
    use auths_custody_pkcs11::{
        Pkcs11Api, Pkcs11Failure, Pkcs11KeyDescription, Pkcs11SecretProvider, Pkcs11Selector,
        Pkcs11SignOutput, SecretPin,
    };
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use p256::pkcs8::EncodePublicKey as _;

    pub(super) const ARN: &str = "arn:aws:kms:eu-west-2:123456789012:key/observer";

    pub(super) struct Kms(pub(super) SigningKey);

    impl AwsKmsApi for Kms {
        fn describe_key(&self, _: &str) -> Result<AwsKmsKeyDescription, AwsKmsFailure> {
            Ok(AwsKmsKeyDescription {
                key_arn: ARN.to_owned(),
                region: "eu-west-2".to_owned(),
                account: "123456789012".to_owned(),
                key_spec: AwsKmsKeySpec::EccNistP256,
                key_usage: AwsKmsKeyUsage::SignVerify,
                enabled: true,
                pending_deletion: false,
                algorithms: vec![AwsKmsSigningAlgorithm::EcdsaSha256],
            })
        }

        fn get_public_key(&self, _: &str) -> Result<Vec<u8>, AwsKmsFailure> {
            p256::PublicKey::from(self.0.verifying_key())
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|_| AwsKmsFailure::InvalidResponse)
        }

        fn sign(
            &self,
            _: &str,
            message: &[u8],
            algorithm: AwsKmsSigningAlgorithm,
            _: AwsKmsMessageType,
        ) -> Result<AwsKmsSignOutput, AwsKmsFailure> {
            let signature: Signature = self.0.sign(message);
            Ok(AwsKmsSignOutput {
                key_arn: ARN.to_owned(),
                algorithm,
                signature_der: signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_der()
                    .as_bytes()
                    .to_vec(),
            })
        }
    }

    pub(super) struct Token(pub(super) SigningKey);

    impl Pkcs11Api for Token {
        fn inspect(
            &self,
            _: &Pkcs11Selector<'_>,
            _: &SecretPin,
        ) -> Result<Pkcs11KeyDescription, Pkcs11Failure> {
            Ok(Pkcs11KeyDescription {
                public_key_sec1: self
                    .0
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                p256: true,
                sign: true,
                enabled: true,
            })
        }

        fn sign_sha256(
            &self,
            _: &Pkcs11Selector<'_>,
            _: &SecretPin,
            message: &[u8],
        ) -> Result<Pkcs11SignOutput, Pkcs11Failure> {
            let signature: Signature = self.0.sign(message);
            Ok(Pkcs11SignOutput {
                signature: signature.normalize_s().unwrap_or(signature).to_vec(),
            })
        }
    }

    pub(super) struct Pin;

    impl Pkcs11SecretProvider for Pin {
        fn acquire(&self) -> Result<SecretPin, Pkcs11Failure> {
            SecretPin::parse(b"test-only-pin".to_vec()).map_err(|_| Pkcs11Failure::WrongPin)
        }
    }
}

fn kms_observer() -> GatewayObserver {
    use auths_custody_aws_kms::{
        AwsAccountId, AwsKmsConfiguration, AwsKmsP256Adapter, AwsRegion, SecretKeyArn,
    };
    let adapter = AwsKmsP256Adapter::connect(
        mock_custody::Kms(p256::ecdsa::SigningKey::from_slice(&[0x61; 32]).expect("key")),
        AwsKmsConfiguration::new(
            SecretKeyArn::parse(mock_custody::ARN.to_owned()).expect("ARN"),
            AwsRegion::parse("eu-west-2").expect("region"),
            AwsAccountId::parse("123456789012").expect("account"),
        ),
        auths_custody::CustodyPrincipalForm::RawKeyV1,
    )
    .expect("KMS adapter");
    let identity = adapter.identity().clone();
    GatewayObserver::from_custody(
        auths_custody::CustodyKey::new(Box::new(adapter), identity).expect("custody key"),
    )
    .expect("custody observer")
}

fn pkcs11_observer() -> GatewayObserver {
    use auths_custody_pkcs11::{
        Pkcs11Configuration, Pkcs11ObjectId, Pkcs11P256Adapter, Pkcs11TokenId,
    };
    let adapter = Pkcs11P256Adapter::connect(
        mock_custody::Token(p256::ecdsa::SigningKey::from_slice(&[0x62; 32]).expect("key")),
        mock_custody::Pin,
        Pkcs11Configuration::new(
            std::path::PathBuf::from("/opt/softhsm/lib/softhsm2.so"),
            Pkcs11TokenId::parse("auths-observer").expect("token"),
            Pkcs11ObjectId::parse(vec![7]).expect("object"),
            2,
            std::time::Duration::from_secs(2),
        )
        .expect("configuration"),
        auths_custody::CustodyPrincipalForm::RawKeyV1,
    )
    .expect("PKCS#11 adapter");
    let identity = adapter.identity().clone();
    GatewayObserver::from_custody(
        auths_custody::CustodyKey::new(Box::new(adapter), identity).expect("custody key"),
    )
    .expect("custody observer")
}

/// KMS- and PKCS#11-held observers satisfy the same observation
/// requirements as the software observer, through the kernel, and report
/// their custody kind.
async fn custody_held_observers_satisfy_requirements(backend: Backend) {
    for (observer, custody) in [(kms_observer(), "kms"), (pkcs11_observer(), "pkcs11")] {
        assert_eq!(observer.custody().label(), custody);
        let root = Signer::new(0x11);
        let context = context(&root, observer.principal(), None);
        let harness = Harness::with(
            update_recipe(),
            context,
            observer,
            root,
            Signer::new(0x22),
            backend,
        );
        let observation = harness.read_back(RECORD, NOW).await;
        let arguments = harness.arguments("custody", RECORD, &update_extra(RECORD, "Pending"));
        let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
        let result = harness.submit(&signed, NOW + 1).await;
        assert!(
            matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
            "{custody}: {result:?}"
        );
        assert_eq!(harness.provider.counts().0, 1, "{custody}");
    }
}

/// Every custody conformance case, driven through the gateway observer:
/// only a correct provider response yields an observation, and that
/// observation authorizes through the kernel; every other case signs
/// nothing and reports the custody boundary's stable code.
#[tokio::test]
async fn custody_observer_passes_custody_conformance() {
    use auths_custody::conformance::{ConformanceExpectation, ConformanceSigner, cases};
    use auths_custody::{CustodyKind, CustodyPrincipalForm, KeyLifecycleState};
    for (case, expected) in cases() {
        if expected == ConformanceExpectation::Startup {
            continue;
        }
        let (key, probe) = ConformanceSigner::key(
            CustodyPrincipalForm::RawKeyV1,
            CustodyKind::Kms,
            KeyLifecycleState::ActiveCurrent,
            case,
        );
        let observer = GatewayObserver::from_custody(key).expect("observer");
        let root = Signer::new(0x11);
        let context = context(&root, observer.principal(), None);
        let harness = Harness::with(
            update_recipe(),
            context,
            observer,
            root,
            Signer::new(0x22),
            Backend::File,
        );
        let target = harness
            .recipe
            .read_back_target(json!({"record_id": RECORD}).as_object().expect("object"))
            .expect("target");
        let result =
            observe_read_back(&target, &harness.observer, &harness.provider, || Some(NOW)).await;
        assert_eq!(probe.calls(), 1, "{case:?}");
        match expected {
            ConformanceExpectation::Signed => {
                let observation = signed_bytes(result);
                let arguments =
                    harness.arguments("conformance", RECORD, &update_extra(RECORD, "Pending"));
                let signed =
                    harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
                assert!(
                    matches!(
                        harness.submit(&signed, NOW + 1).await,
                        GatewaySubmitResult::ObservedByProvider { .. }
                    ),
                    "{case:?}"
                );
            }
            ConformanceExpectation::Refused(error) => {
                assert_eq!(
                    result,
                    GatewayObserveResult::Refused {
                        code: error.stable_code().to_owned()
                    },
                    "{case:?}"
                );
                assert_eq!(harness.provider.counts().0, 0, "{case:?}");
            }
            ConformanceExpectation::Startup => unreachable!(),
        }
    }
}

/// A custody observer whose key is not ready or active never reaches its
/// provider and signs nothing.
#[tokio::test]
async fn custody_observer_lifecycle_gates_the_provider() {
    use auths_custody::conformance::{ConformanceSigner, LIFECYCLE_CASES};
    use auths_custody::{CustodyConformanceCase, CustodyKind, CustodyPrincipalForm};
    for (lifecycle, permitted) in LIFECYCLE_CASES {
        let (key, probe) = ConformanceSigner::key(
            CustodyPrincipalForm::RawKeyV1,
            CustodyKind::Pkcs11,
            *lifecycle,
            CustodyConformanceCase::Valid,
        );
        let observer = GatewayObserver::from_custody(key).expect("observer");
        let result = observe_read_back(
            &update_recipe()
                .read_back_target(json!({"record_id": RECORD}).as_object().expect("object"))
                .expect("target"),
            &observer,
            &CountingProvider::new(),
            || Some(NOW),
        )
        .await;
        assert_eq!(
            matches!(result, GatewayObserveResult::Signed { .. }),
            *permitted,
            "{lifecycle:?}"
        );
        if !permitted {
            assert_eq!(
                result,
                GatewayObserveResult::Refused {
                    code: "custody.lifecycle-not-permitted".to_owned()
                }
            );
        }
        assert_eq!(probe.calls(), usize::from(*permitted), "{lifecycle:?}");
    }
}

/// A `did:key` custody key cannot be a gateway observer: observer anchors
/// accept `raw-key-v1` only.
#[test]
fn custody_observer_requires_a_raw_key_principal() {
    use auths_custody::conformance::ConformanceSigner;
    use auths_custody::{
        CustodyConformanceCase, CustodyKind, CustodyPrincipalForm, KeyLifecycleState,
    };
    let (key, _) = ConformanceSigner::key(
        CustodyPrincipalForm::DidKeyV1,
        CustodyKind::Kms,
        KeyLifecycleState::ActiveCurrent,
        CustodyConformanceCase::Valid,
    );
    assert_eq!(
        GatewayObserver::from_custody(key).err(),
        Some(crate::GatewayObserverError::Identity)
    );
}

/// Runs every hostile observation-conditioned case against the single-host
/// file store and, with the TLS fixture, the qualified multi-host store.
macro_rules! on_both_stores {
    ($($case:ident),* $(,)?) => {
        mod file_store {
            use super::Backend;
            $(
                #[tokio::test]
                async fn $case() {
                    super::$case(Backend::File).await;
                }
            )*
        }

        mod postgres_store {
            use super::{Backend, postgres_configured};
            $(
                #[tokio::test]
                #[ignore = "needs the TLS PostgreSQL fixture"]
                async fn $case() {
                    assert!(postgres_configured(), "TLS PostgreSQL environment slots are required");
                    super::$case(Backend::Postgres).await;
                }
            )*
        }
    };
}

on_both_stores!(
    fresh_matching_read_back_authorizes_the_replacement_write,
    stale_changed_or_missing_expected_is_refused_before_credential_access,
    read_back_of_another_record_cannot_license_this_write,
    replaced_in_between_is_authorized_inside_the_documented_window,
    chained_step_is_refused_until_the_previous_step_is_provider_bound,
    self_signed_or_forged_observations_never_satisfy,
    observer_in_the_authority_chain_is_refused,
    action_fact_policy_is_bound_into_the_pinned_configuration,
    two_of_three_root_authorizes_only_with_two_distinct_roots,
    custody_held_observers_satisfy_requirements,
);
