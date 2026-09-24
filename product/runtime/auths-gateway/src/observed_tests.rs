//! Hosted-style end-to-end tests of gateway-observed preconditions.
//!
//! Each test signs a real grant and MCP action, verifies it natively with the
//! gateway's own registries and `mcp-arguments-v1` policy at an explicit
//! gateway clock, and then follows the engine's post-verification dispatch
//! against the counting provider of [`crate::harness`]. The provider counts
//! write entries, read-only observations, and credential leases; a lease is
//! taken only after verification and a durable claim, exactly as in the
//! engine.

use crate::engine::{
    GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult,
    gateway_verifier_configuration, not_entered, observe_outcome,
};
use crate::harness::{
    self as h, ANCHOR, ASSURANCE, Delivery, NAMESPACE, OTHER_RECORD, RECORD, Signer,
    read_back_subject,
};
use crate::observer::{OUTCOME_SCHEMA, READ_BACK_SCHEMA, operation_subject};
use crate::{CompiledRecipe, GatewayObserver, LogicalOperationId, OperatorNamespace};
use auths_codec::{
    action_id, action_signing_preimage, attachment_digest, body_digest, domain_commitment,
    encode_bundle, encode_canonical_action, encode_signed_observation, grant_id,
    grant_signing_preimage, observation_signing_preimage, plan_id,
};
use auths_model::{
    ActionConstraint, ActionEnvelope, AssurancePolicyId, AttachmentDescriptor, Audience,
    AudienceSet, AuthorizationPlan, BundleHeader, CanonicalAction, Challenge, ChannelBindingId,
    ConditionTest, Confidentiality, ControlBinding, CriticalExtension, CriticalExtensions,
    DetachedAttachment, DispositionId, EvidenceObject, ExtensionId, FactName, FactValue,
    GrantStatement, MediaType, MemberValues, OBSERVATION_MEDIA_TYPE, ObservationCondition,
    ObservationFact, ObservationFacts, ObservationRequirement, ObservationSchemaId,
    ObservationStatement, ObservationSubject, ObserverAnchorId, Opacity, PermissionSet, Presence,
    PrincipalId, ProofBundle, ProofRef, ResourceId, SignatureEnvelope, SignedAction, SignedGrant,
    SignedObservation, StatementRef, StatusPolicy, Timestamp, TrustedContext, ValidityWindow,
    VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_registries::ImmutableRegistries;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::{Map, Value, json};
use std::ops::Deref;

#[path = "bounds_tests.rs"]
mod bounds_tests;

const NOW: u64 = 1_790_000_000;

fn window(from: u64, until: u64) -> ValidityWindow {
    h::window(from, until).expect("window")
}

fn audience() -> Audience {
    h::audience().expect("audience")
}

fn call(arguments: &Map<String, Value>) -> McpToolCall {
    h::call(arguments).expect("call")
}

fn name(value: &str) -> FactName {
    h::name(value).expect("fact name")
}

fn text(value: &str) -> FactValue {
    h::text(value).expect("text")
}

fn namespace() -> OperatorNamespace {
    h::namespace().expect("namespace")
}

fn signer(seed: u8) -> Signer {
    Signer::new(seed)
}

fn recipe(extra: &Value, preconditions: &Value) -> CompiledRecipe {
    h::recipe(extra, preconditions).expect("test recipe compiles")
}

fn update_recipe() -> CompiledRecipe {
    h::update_recipe().expect("update recipe")
}

fn context(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
) -> TrustedContext {
    h::context(root, observer, configuration, NOW).expect("context")
}

fn read_back_requirement() -> ObservationRequirement {
    h::read_back_requirement().expect("requirement")
}

fn grant(
    root: &Signer,
    agent: &Signer,
    requirement: Option<ObservationRequirement>,
) -> SignedGrant {
    h::grant(root, &agent.principal, requirement, NOW).expect("grant")
}

fn step_subject(operation: &str) -> String {
    operation_subject(
        &namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
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

fn context_with_depth(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    depth: u16,
) -> TrustedContext {
    h::context_with_depth(root, observer, configuration, NOW, depth).expect("context")
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

/// The shared harness with a test-held agent key.
struct Harness {
    core: h::Harness,
    root: Signer,
    agent: Signer,
    _temp: tempfile::TempDir,
}

impl Deref for Harness {
    type Target = h::Harness;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl Harness {
    fn open(recipe: CompiledRecipe) -> Self {
        let root = signer(h::ROOT_SEED);
        let observer = GatewayObserver::from_test_seed(h::OBSERVER_SEED);
        let context = context(&root, observer.principal(), None);
        Self::with(recipe, context, observer, root, signer(0x22))
    }

    fn with(
        recipe: CompiledRecipe,
        context: TrustedContext,
        observer: GatewayObserver,
        root: Signer,
        agent: Signer,
    ) -> Self {
        let temp = tempfile::tempdir().expect("temp directory");
        let state = std::fs::canonicalize(temp.path()).expect("canonical temp");
        Self {
            core: h::Harness::with(recipe, context, observer, &state).expect("harness"),
            root,
            agent,
            _temp: temp,
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

    async fn submit(&self, submission: &Submission, now: u64) -> GatewaySubmitResult {
        self.core
            .submit(&submission.proof, &submission.action, now)
            .await
    }

    async fn read_back(&self, record: &str, at: u64) -> Vec<u8> {
        let arguments = json!({"record_id": record})
            .as_object()
            .expect("object")
            .clone();
        signed_bytes(
            self.core
                .observe(&GatewayObserveRequest::ReadBack { arguments }, at)
                .await,
        )
    }

    fn outcome(&self, operation: &str, at: u64) -> GatewayObserveResult {
        observe_outcome(&self.store, &namespace(), &self.observer, operation, at)
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

#[tokio::test]
async fn fresh_matching_read_back_authorizes_the_replacement_write() {
    let harness = Harness::open(update_recipe());
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

#[tokio::test]
async fn stale_changed_or_missing_expected_is_refused_before_credential_access() {
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
        let harness = Harness::open(update_recipe());
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
            harness.store.read(&namespace(), &operation).expect("read"),
            None,
            "{id}: a refused action consumes no logical operation"
        );
    }
}

#[tokio::test]
async fn read_back_of_another_record_cannot_license_this_write() {
    let harness = Harness::open(update_recipe());
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

#[tokio::test]
async fn replaced_in_between_is_authorized_inside_the_documented_window() {
    let harness = Harness::open(update_recipe());
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

#[tokio::test]
async fn chained_step_is_refused_until_the_previous_step_is_provider_bound() {
    let harness = Harness::open(chained_recipe());
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
        harness.outcome("step-1", NOW),
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
    let unknown = signed_bytes(harness.outcome("step-1", NOW + 10));
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
    let bound = signed_bytes(harness.outcome("step-1", NOW + 40));
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

#[tokio::test]
async fn self_signed_or_forged_observations_never_satisfy() {
    let harness = Harness::open(update_recipe());
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

#[tokio::test]
async fn observer_in_the_authority_chain_is_refused() {
    let root = signer(0x11);
    let agent = signer(0x22);
    let context = context(&root, &agent.principal, None);
    let harness = Harness::with(
        update_recipe(),
        context,
        GatewayObserver::from_test_seed(0x33),
        root,
        agent,
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

#[tokio::test]
async fn action_fact_policy_is_bound_into_the_pinned_configuration() {
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
    let root = signer(0x11);
    let observer = GatewayObserver::from_test_seed(0x33);
    let context = context(&root, observer.principal(), Some(without_policy));
    let harness = Harness::with(update_recipe(), context, observer, root, signer(0x22));
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("unpinned", RECORD, &update_extra(RECORD, "Pending"));
    let signed = harness.sign(Some(read_back_requirement()), &arguments, &[observation]);
    assert_eq!(
        harness.submit(&signed, NOW + 1).await,
        denied("verifier-configuration-mismatch")
    );
    assert_eq!(harness.provider.counts().0, 0);
}

/// Authors exactly as the SDKs do: `prepare_profile_action` at `evaluated`
/// with `validity_seconds` (the native default when `None`), observations
/// attached before signing, and the proof assembled by the shared builder.
fn sdk_submission(
    harness: &Harness,
    grant: SignedGrant,
    arguments: &Map<String, Value>,
    observations: &[Vec<u8>],
    evaluated: u64,
    validity_seconds: Option<u64>,
) -> Submission {
    let canonical = McpProfile
        .canonicalize(&call(arguments).canonical_bytes().expect("canonical call"))
        .expect("canonical action");
    let prepared = auths_author::prepare_profile_action(
        canonical,
        audience(),
        harness.agent.principal.clone(),
        &grant,
        [0; 32],
        evaluated,
        validity_seconds,
    )
    .expect("prepared");
    let offered: Vec<(&str, &[u8])> = observations
        .iter()
        .map(|bytes| (OBSERVATION_MEDIA_TYPE, bytes.as_slice()))
        .collect();
    let prepared = auths_author::attach_observations(prepared, &offered).expect("attached");
    let action = sign_action(&harness.agent, prepared.envelope().clone());
    let mut builder = auths_author::WorkflowProofBuilder::new();
    let index = builder.push_grant(grant).expect("grant");
    builder
        .bind_grant_evidence(index, harness.root.evidence())
        .expect("grant evidence");
    builder
        .bind_action_evidence(harness.agent.evidence())
        .expect("action evidence");
    let proof = builder
        .finish(&action, prepared.canonical(), &harness.context)
        .expect("proof");
    let action = encode_canonical_action(prepared.canonical()).expect("action bytes");
    let commitment = *domain_commitment("auths.canonical-action.v1", &action)
        .expect("commitment")
        .as_bytes();
    Submission {
        proof: encode_bundle(proof.proof()).expect("proof bytes"),
        action,
        commitment,
    }
}

fn requirement_grant(harness: &Harness, from: u64, until: u64) -> SignedGrant {
    h::grant_within(
        &harness.root,
        &harness.agent.principal,
        Some(read_back_requirement()),
        window(from, until),
    )
    .expect("grant")
}

#[tokio::test]
async fn sdk_action_window_admits_a_later_gateway_clock_and_replay_stays_refused() {
    let harness = Harness::open(update_recipe());
    let long = || requirement_grant(&harness, NOW - 3_600, NOW + 86_400);
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("window-30", RECORD, &update_extra(RECORD, "Pending"));
    let within = sdk_submission(
        &harness,
        long(),
        &arguments,
        std::slice::from_ref(&observation),
        NOW,
        None,
    );
    assert!(
        matches!(
            harness.submit(&within, NOW + 5).await,
            GatewaySubmitResult::ObservedByProvider {
                status: Some(200),
                ..
            }
        ),
        "the default window covers a gateway clock 5 s later"
    );
    assert_eq!(harness.provider.counts().0, 1);
    assert_eq!(
        harness.submit(&within, NOW + 10).await,
        crate::engine::replay_refused(),
        "the durable claim refuses the same action again inside its window"
    );
    let later = NOW + 3_600;
    let reauthored = sdk_submission(
        &harness,
        long(),
        &harness.arguments("window-30", RECORD, &update_extra(RECORD, "Approved")),
        &[harness.read_back(RECORD, later).await],
        later,
        None,
    );
    assert_eq!(
        harness.submit(&reauthored, later + 5).await,
        crate::engine::replay_refused(),
        "and a fresh action for the same logical operation after the window"
    );
    assert_eq!(harness.provider.counts().0, 1);

    let other = harness.read_back(OTHER_RECORD, NOW).await;
    let arguments = harness.arguments(
        "window-1",
        OTHER_RECORD,
        &update_extra(OTHER_RECORD, "Pending"),
    );
    let leases = harness.provider.counts().2;
    let narrow = sdk_submission(&harness, long(), &arguments, &[other], NOW, Some(1));
    assert_eq!(
        harness.submit(&narrow, NOW + 5).await,
        denied("action-outside-validity"),
        "a 1 s window has closed 5 s later"
    );
    assert_eq!(
        harness.submit(&narrow, NOW - 1).await,
        denied("action-outside-validity"),
        "an action is never valid before its evaluation time"
    );
    assert_eq!(harness.provider.counts().0, 1);
    assert_eq!(
        harness.provider.counts().2,
        leases,
        "denied before any lease"
    );
}

#[tokio::test]
async fn sdk_action_window_is_cut_to_the_grant_expiry() {
    let harness = Harness::open(update_recipe());
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("near-expiry", RECORD, &update_extra(RECORD, "Pending"));
    let near = sdk_submission(
        &harness,
        requirement_grant(&harness, NOW - 3_600, NOW + 10),
        &arguments,
        std::slice::from_ref(&observation),
        NOW,
        None,
    );
    assert!(
        matches!(
            harness.submit(&near, NOW + 5).await,
            GatewaySubmitResult::ObservedByProvider { .. }
        ),
        "a grant expiring 10 s later still authorizes the cut [t, t+10] window"
    );
    let arguments = harness.arguments("expired", RECORD, &update_extra(RECORD, "Approved"));
    let expired = sdk_submission(
        &harness,
        requirement_grant(&harness, NOW - 3_600, NOW - 1),
        &arguments,
        &[harness.read_back(RECORD, NOW).await],
        NOW,
        None,
    );
    let writes = harness.provider.counts().0;
    assert!(
        matches!(
            harness.submit(&expired, NOW).await,
            GatewaySubmitResult::Denied { .. }
        ),
        "an expired grant keeps the instant window and is denied"
    );
    assert_eq!(harness.provider.counts().0, writes);
}

#[tokio::test]
async fn a_longer_action_window_never_extends_observation_freshness() {
    let harness = Harness::open(update_recipe());
    let observation = harness.read_back(RECORD, NOW).await;
    let arguments = harness.arguments("long-window", RECORD, &update_extra(RECORD, "Pending"));
    let long = sdk_submission(
        &harness,
        requirement_grant(&harness, NOW - 3_600, NOW + 86_400),
        &arguments,
        &[observation],
        NOW + 50,
        Some(300),
    );
    assert_eq!(
        harness.submit(&long, NOW + 61).await,
        indeterminate("observation-missing"),
        "max_age is judged at the gateway's evaluation time"
    );
    assert_eq!(harness.provider.counts(), (0, 1, 1));
}
