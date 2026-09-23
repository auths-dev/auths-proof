//! Approval-quorum hostile cases: "2 of 3 managers approve before the agent
//! acts", driven through the gateway's native verification and a counting
//! provider.
//!
//! The installed trust anchors exactly three managers and requires two
//! authorized branches from two distinct actors. Every proof, action, and the
//! trusted context are read from `bindings/fixtures/gateway/approval-quorum.json`;
//! the drive test signs nothing. The fixture test regenerates the file from
//! fixed seeds and requires it to be byte-identical, so the Python and
//! TypeScript SDKs can check their own authoring against the same bytes.

use crate::engine::{
    GatewaySubmitResult, execute_claimed, gateway_verifier_configuration, not_entered,
    replay_refused, reserve_bound, verify_command,
};
use crate::transport::{GatewayTransportError, ProviderPort, WriteTransportOutcome};
use crate::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, FileGatewayAttemptStore,
    GatewayAttemptError,
};
use auths_approval_quorum::{QuorumApproval, QuorumApprover, QuorumProposal, quorum_requirement};
use auths_codec::{
    action_signing_preimage, body_digest, encode_bundle, encode_canonical_action,
    encode_verifier_context, evidence_id, plan_id,
};
use auths_model::{
    AcceptedRegistries, ActionEnvelope, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    AssuranceQuantifier, AssuranceRequirement, Audience, AudienceSet, AuthorizationPlan,
    BundleHeader, CanonicalAction, Challenge, ChannelBindingId, ControlBinding, CriticalExtensions,
    EvidenceId, EvidenceObject, EvidenceTypeId, GrantStatusSnapshot, MediaType, ParticipantRole,
    PermissionSet, PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId,
    ProofBundle, ProofRef, ResourceId, ResourceMatcherId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, SignedAction, StatementRef, StatusPolicy,
    StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId, TrustedContext, ValidityWindow,
    VerificationMethod, VerifierLimits,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../bindings/fixtures/gateway/approval-quorum.json"
);
const FIXTURE: &str = include_str!("../../../../bindings/fixtures/gateway/approval-quorum.json");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");

const SCHEMA: &str = "auths.gateway-approval-quorum/1";
const NOW: u64 = 1_790_000_000;
const NOT_BEFORE: u64 = NOW - 600;
const EXPIRES_AT: u64 = NOW + 3_000;
const CHALLENGE: [u8; 32] = [0x51; 32];
const REQUIRED: u16 = 2;
const RECORD: &str = "recQUORUM00000001";
const ASSURANCE: &str = "approval-quorum-test-v1";

/// Fixed test seeds: three members and one principal outside the quorum.
const MEMBERS: [(&str, u8); 4] = [
    ("manager-a", 0xa1),
    ("manager-b", 0xb2),
    ("manager-c", 0xc3),
    ("outsider", 0xd4),
];

struct Member {
    name: &'static str,
    seed: u8,
    key: SigningKey,
    raw: RawKeyDescriptor,
    principal: PrincipalId,
}

impl Member {
    fn named(name: &str) -> Self {
        let (name, seed) = *MEMBERS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .expect("fixture member");
        let key = SigningKey::from_bytes(&[seed; 32]);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .expect("raw key");
        let principal = raw.principal().expect("principal");
        Self {
            name,
            seed,
            key,
            raw,
            principal,
        }
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

    fn sign(&self, envelope: &ActionEnvelope) -> SignedAction {
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        );
        let preimage = action_signing_preimage(envelope, &descriptor).expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        SignedAction::new(
            envelope.clone(),
            SignatureEnvelope::new(descriptor, signature),
        )
    }

    fn approve(&self, envelope: &ActionEnvelope) -> QuorumApproval {
        QuorumApproval::new(self.sign(envelope), Vec::new(), vec![self.evidence()])
            .expect("approval")
    }
}

fn recipe() -> CompiledRecipe {
    CompiledRecipe::compile(RECIPE, LOCK).expect("airtable fixture recipe compiles")
}

fn arguments(recipe: &CompiledRecipe, operation: &str) -> Map<String, Value> {
    json!({
        "operation_id": operation,
        "operator_namespace": recipe.namespace().as_str(),
        "recipe_digest": recipe.digest_hex(),
        "record_id": RECORD,
        "replacement": "Approved"
    })
    .as_object()
    .expect("object")
    .clone()
}

fn call(recipe: &CompiledRecipe, operation: &str) -> McpToolCall {
    McpToolCall::new(
        "airtable-gateway-demo",
        "set_demo_status_v1",
        arguments(recipe, operation),
    )
    .expect("call")
}

fn canonical(recipe: &CompiledRecipe, operation: &str) -> (CanonicalAction, Audience) {
    let call = call(recipe, operation);
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().expect("canonical call"))
        .expect("canonical action");
    (canonical, call.audience().expect("audience"))
}

fn validity() -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(NOT_BEFORE), Timestamp::new(EXPIRES_AT)).expect("window")
}

fn proposal(
    recipe: &CompiledRecipe,
    operation: &str,
    required: u16,
    names: &[&str],
) -> QuorumProposal {
    let (canonical, audience) = canonical(recipe, operation);
    let approvers: Vec<_> = names
        .iter()
        .map(|name| QuorumApprover::new(Member::named(name).principal, None).expect("approver"))
        .collect();
    QuorumProposal::new(
        canonical,
        &audience,
        CHALLENGE,
        validity(),
        required,
        &approvers,
    )
    .expect("proposal")
}

/// The operator's installation: each manager is a depth-zero anchor for the
/// one MCP tool, and two distinct approving actors are required.
fn trusted_context(recipe: &CompiledRecipe) -> TrustedContext {
    let call = call(recipe, "trust");
    let profile = call.profile_ref().expect("profile");
    let permission = call.permission().expect("permission");
    let audience = call.audience().expect("audience");
    let assurance = AssurancePolicyId::parse(ASSURANCE).expect("assurance");
    let anchors = MEMBERS[..3]
        .iter()
        .map(|(name, _)| {
            let member = Member::named(name);
            TrustAnchor::new(
                TrustAnchorId::parse(name).expect("anchor ID"),
                member.principal.clone(),
                vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
                vec![profile.clone()],
                PermissionSet::new(vec![permission.clone()]).expect("permissions"),
                vec![ResourceId::parse("mcp://airtable-gateway-demo/").expect("namespace")],
                AudienceSet::new(vec![audience.clone()]).expect("audiences"),
                ValidityWindow::new(Timestamp::new(NOW - 86_400), Timestamp::new(NOW + 86_400))
                    .expect("anchor window"),
                None,
                0,
                assurance.clone(),
                StatusPolicy::ExpiryOnly,
            )
            .expect("trust anchor")
        })
        .collect();
    let registries = AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        vec![SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite")],
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
        Vec::new(),
        vec![profile],
        vec![ProfilePolicyId::parse(crate::MCP_ARGUMENTS_V1).expect("policy")],
    )
    .expect("registries");
    TrustedContext::new(
        gateway_verifier_configuration().expect("configuration"),
        quorum_requirement(REQUIRED, 1).expect("composition"),
        anchors,
        registries,
        audience,
        Challenge::new(CHALLENGE),
        Timestamp::new(NOW),
        AssurancePolicy::new(assurance, Vec::new()).expect("assurance policy"),
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x71; 32]),
            Timestamp::new(NOW - 86_400),
            Timestamp::new(NOW + 86_400),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal status"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x72; 32]),
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
}

/// The same quorum as an SDK trusted-context template under the packaged
/// verifier configuration, so the Python and TypeScript verifiers decide the
/// same vectors the gateway decides.
fn sdk_trusted_context(recipe: &CompiledRecipe) -> TrustedContext {
    let call = call(recipe, "trust");
    let profile = call.profile_ref().expect("profile");
    let audience = call.audience().expect("audience");
    let raw_key = auths_raw_key::RawKeyMethod::new().expect("raw key");
    let did_key = auths_did_key::DidKeyMethod::new().expect("did:key");
    let did_keri = auths_did_keri::DidKeriMethod::new().expect("did:keri");
    let ed25519 = auths_signature::Ed25519Suite::new().expect("ed25519");
    let p256 = auths_signature::P256Sha256Suite::new().expect("p256");
    let methods: [&dyn auths_ports::PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let configuration = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .expect("packaged registries")
        .configuration_id();
    let anchors = MEMBERS[..3]
        .iter()
        .map(|(name, _)| {
            TrustAnchor::new(
                TrustAnchorId::parse(name).expect("anchor ID"),
                Member::named(name).principal,
                vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
                vec![profile.clone()],
                PermissionSet::new(vec![call.permission().expect("permission")])
                    .expect("permissions"),
                vec![ResourceId::parse(audience.as_str()).expect("namespace")],
                AudienceSet::new(vec![audience.clone()]).expect("audiences"),
                ValidityWindow::new(Timestamp::new(NOW - 86_400), Timestamp::new(NOW + 86_400))
                    .expect("anchor window"),
                None,
                0,
                AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
                StatusPolicy::ExpiryOnly,
            )
            .expect("trust anchor")
        })
        .collect();
    let claim = |value| AssuranceClaimId::parse(value).expect("claim");
    let assurance = AssurancePolicy::new(
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                claim("self-certifying-identifier"),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                claim("self-certifying-identifier"),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                claim("offline-verifiable"),
                None,
            ),
        ],
    )
    .expect("assurance policy");
    auths_sdk::TrustedContextBuilder::new(
        configuration,
        quorum_requirement(REQUIRED, 1).expect("composition"),
        anchors,
        assurance,
    )
    .expect("builder")
    .declare_budget_free_profile(profile)
    .accept_evidence_type(EvidenceTypeId::parse(RAW_KEY_V1).expect("evidence type"))
    .build()
    .expect("SDK template")
}

/// Hand-built bundle for shapes the SDK refuses to author: `signers` sign the
/// leaves in order, and `leaves` may exceed the signers to leave one absent.
fn hand_bundle(
    recipe: &CompiledRecipe,
    operation: &str,
    required: u16,
    leaves: usize,
    signers: &[&Member],
) -> ProofBundle {
    let (canonical, audience) = canonical(recipe, operation);
    let references: Vec<_> = (0..leaves)
        .map(|index| ProofRef::new([u8::try_from(index + 1).expect("small"); 32]))
        .collect();
    let plan = AuthorizationPlan::k_of_n(
        required,
        references
            .iter()
            .copied()
            .map(AuthorizationPlan::proof)
            .collect(),
    )
    .expect("plan");
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let mut evidence = Vec::new();
    let mut bindings = Vec::new();
    let actions: Vec<_> = signers
        .iter()
        .zip(&references)
        .map(|(member, reference)| {
            let action = member.sign(&ActionEnvelope::new(
                canonical.profile().clone(),
                canonical.media_type().clone(),
                body_digest(canonical.body()),
                canonical.permission().clone(),
                None,
                audience.clone(),
                Challenge::new(CHALLENGE),
                validity(),
                member.principal.clone(),
                None,
                plan_identifier,
                ChannelBindingId::parse("none-v1").expect("channel"),
                *reference,
                Vec::new(),
                CriticalExtensions::empty(),
            ));
            let object = member.evidence();
            bindings.push(
                ControlBinding::new(
                    StatementRef::Action(
                        auths_codec::action_id(action.envelope()).expect("action ID"),
                    ),
                    vec![object.id()],
                )
                .expect("binding"),
            );
            if !evidence.contains(&object) {
                evidence.push(object);
            }
            action
        })
        .collect();
    evidence.sort_by_key(EvidenceObject::id);
    ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        actions,
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("hand-built bundle")
}

fn sdk_bundle(
    recipe: &CompiledRecipe,
    operation: &str,
    required: u16,
    names: &[&str],
) -> ProofBundle {
    let quorum = proposal(recipe, operation, required, names);
    let approvals: Vec<_> = quorum
        .envelopes()
        .iter()
        .zip(names)
        .map(|(envelope, name)| Member::named(name).approve(envelope))
        .collect();
    quorum.assemble(&approvals).expect("assembled quorum")
}

struct Case {
    id: &'static str,
    authoring: &'static str,
    required: u16,
    approvers: &'static [&'static str],
    decision: &'static str,
    code: &'static str,
    provider_entries: usize,
}

const CASES: [Case; 7] = [
    Case {
        id: "two-of-three-managers",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "manager-b"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
    Case {
        id: "one-of-three-managers",
        authoring: "sdk",
        required: 1,
        approvers: &["manager-a"],
        decision: "denied",
        code: "composition-requirement-not-met",
        provider_entries: 0,
    },
    Case {
        id: "one-of-two-listed-approvals-absent",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a"],
        decision: "denied",
        code: "missing-reference",
        provider_entries: 0,
    },
    Case {
        id: "duplicate-signer",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a", "manager-a"],
        decision: "denied",
        code: "composition-requirement-not-met",
        provider_entries: 0,
    },
    Case {
        id: "outsider-does-not-count",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "outsider"],
        decision: "denied",
        code: "untrusted-root",
        provider_entries: 0,
    },
    Case {
        id: "outsider-beside-two-managers",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "manager-b", "outsider"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
    Case {
        id: "three-of-three-managers",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "manager-b", "manager-c"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
];

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn unb64(value: &Value) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value.as_str().expect("base64 string")).expect("base64")
}

fn generate() -> String {
    let recipe = recipe();
    let context = trusted_context(&recipe);
    let cases: Vec<Value> = CASES
        .iter()
        .map(|case| {
            let bundle = if case.authoring == "sdk" {
                sdk_bundle(&recipe, case.id, case.required, case.approvers)
            } else {
                let signers: Vec<_> = case
                    .approvers
                    .iter()
                    .map(|name| Member::named(name))
                    .collect();
                let refs: Vec<_> = signers.iter().collect();
                hand_bundle(&recipe, case.id, case.required, case.required.into(), &refs)
            };
            let (canonical, _) = canonical(&recipe, case.id);
            json!({
                "id": case.id,
                "authoring": case.authoring,
                "required": case.required,
                "approvers": case.approvers,
                "arguments_json": String::from_utf8(
                    serde_json_canonicalizer::to_vec(&arguments(&recipe, case.id)).expect("json")
                ).expect("utf-8"),
                "action_b64": b64(&encode_canonical_action(&canonical).expect("action")),
                "proof_b64": b64(&encode_bundle(&bundle).expect("proof")),
                "decision": case.decision,
                "code": case.code,
                "provider_entries": case.provider_entries,
            })
        })
        .collect();
    let members: Vec<Value> = MEMBERS
        .iter()
        .map(|(name, _)| {
            let member = Member::named(name);
            json!({
                "name": member.name,
                "seed_byte": member.seed,
                "principal": member.principal.as_str(),
                "evidence_b64": b64(&member.raw.encode()),
                "member": member.name != "outsider",
            })
        })
        .collect();
    let document = json!({
        "schema": SCHEMA,
        "service": "airtable-gateway-demo",
        "tool": "set_demo_status_v1",
        "evaluation_time": NOW,
        "not_before": NOT_BEFORE,
        "expires_at": EXPIRES_AT,
        "challenge_hex": hex::encode(CHALLENGE),
        "required": REQUIRED,
        "members": members,
        "trusted_context_b64": b64(&encode_verifier_context(&context).expect("context")),
        "sdk_trusted_context_b64": b64(
            &encode_verifier_context(&sdk_trusted_context(&recipe)).expect("SDK context")
        ),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&document).expect("fixture JSON");
    text.push('\n');
    text
}

#[test]
fn approval_quorum_fixture_is_current() {
    let generated = generate();
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(FIXTURE_PATH, &generated).expect("write fixture");
        return;
    }
    assert!(
        generated == FIXTURE,
        "approval-quorum fixture is stale; rerun with AUTHS_UPDATE_FIXTURES=1"
    );
}

/// Counts every provider write entry and every credential lease.
struct CountingProvider {
    writes: AtomicUsize,
    leases: AtomicUsize,
}

impl ProviderPort for CountingProvider {
    async fn write(
        &self,
        _: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(WriteTransportOutcome::ResponseRecorded {
            status: 200,
            digest: [4; 32],
        })
    }

    async fn read_back(&self, _: &ClosedObservationRequest) -> Option<Vec<u8>> {
        None
    }
}

impl CountingProvider {
    fn counts(&self) -> (usize, usize) {
        (
            self.writes.load(Ordering::SeqCst),
            self.leases.load(Ordering::SeqCst),
        )
    }
}

/// Mirrors the engine: verify, claim, reserve any bound, lease, then enter
/// the provider.
async fn submit(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    store: &FileGatewayAttemptStore,
    provider: &CountingProvider,
    proof: &[u8],
    action: &[u8],
) -> GatewaySubmitResult {
    let (request, bound) = match verify_command(recipe, context, NOW, proof, action) {
        Ok(value) => value,
        Err(result) => return result,
    };
    match store.claim(&request, *recipe.digest()) {
        Ok(claim) => {
            let claim = match reserve_bound(store, bound.as_ref(), &request, claim) {
                Ok(claim) => claim,
                Err(result) => return result,
            };
            provider.leases.fetch_add(1, Ordering::SeqCst);
            execute_claimed(claim, &request, provider).await
        }
        Err(GatewayAttemptError::Replay) => replay_refused(),
        Err(_) => not_entered("gateway.attempt.unavailable"),
    }
}

fn decision_of(result: &GatewaySubmitResult) -> (&'static str, String) {
    match result {
        GatewaySubmitResult::Denied { code } => ("denied", code.clone()),
        GatewaySubmitResult::Indeterminate { code } => ("indeterminate", code.clone()),
        GatewaySubmitResult::NotEntered { code } => ("not-entered", code.clone()),
        _ => ("authorized", String::new()),
    }
}

#[tokio::test]
async fn approval_quorum_hostile_cases_admit_only_a_two_manager_quorum() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    assert_eq!(fixture["schema"], SCHEMA);
    let recipe = recipe();
    let context = auths_codec::decode_verifier_context(&unb64(&fixture["trusted_context_b64"]))
        .expect("installed trust");
    let temp = tempfile::tempdir().expect("temp directory");
    let store = FileGatewayAttemptStore::open(
        std::fs::canonicalize(temp.path())
            .expect("canonical temp")
            .join("attempts"),
    )
    .expect("store");
    let provider = CountingProvider {
        writes: AtomicUsize::new(0),
        leases: AtomicUsize::new(0),
    };
    let mut expected_entries = 0;
    let mut unauthorized_entries = 0;
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), CASES.len());
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let before = provider.counts();
        let result = submit(
            &recipe,
            &context,
            &store,
            &provider,
            &unb64(&case["proof_b64"]),
            &unb64(&case["action_b64"]),
        )
        .await;
        let after = provider.counts();
        let (entries, leases) = (after.0 - before.0, after.1 - before.1);
        let (decision, code) = decision_of(&result);
        assert_eq!(decision, case["decision"], "{id}: {result:?}");
        assert_eq!(code, case["code"], "{id}");
        let expected =
            usize::try_from(case["provider_entries"].as_u64().expect("entries")).expect("entries");
        assert_eq!(entries, expected, "{id}: provider entries");
        if decision == "authorized" {
            assert!(
                matches!(
                    result,
                    GatewaySubmitResult::ResponseRecorded { status: 200 }
                ),
                "{id}: {result:?}"
            );
            assert_eq!(leases, 1, "{id}: one lease for one entry");
            unauthorized_entries += entries.saturating_sub(1);
        } else {
            assert_eq!(leases, 0, "{id}: refused before any credential lease");
            unauthorized_entries += entries;
        }
        expected_entries += expected;
    }
    assert_eq!(provider.counts().0, expected_entries);
    assert_eq!(unauthorized_entries, 0);

    let replay = &cases[0];
    let result = submit(
        &recipe,
        &context,
        &store,
        &provider,
        &unb64(&replay["proof_b64"]),
        &unb64(&replay["action_b64"]),
    )
    .await;
    assert_eq!(result, replay_refused(), "an authorized quorum is one-use");
    assert_eq!(provider.counts().0, expected_entries);
}

#[test]
fn a_proof_carried_plan_cannot_lower_the_installed_threshold() {
    let recipe = recipe();
    let context = trusted_context(&recipe);
    let action = encode_canonical_action(&canonical(&recipe, "lowered").0).expect("action");
    let manager = Member::named("manager-a");
    for bundle in [
        hand_bundle(&recipe, "lowered", 1, 1, &[&manager]),
        hand_bundle(
            &recipe,
            "lowered",
            1,
            2,
            &[&manager, &Member::named("outsider")],
        ),
    ] {
        let proof = encode_bundle(&bundle).expect("proof");
        let result = verify_command(&recipe, &context, NOW, &proof, &action)
            .expect_err("a single manager never authorizes");
        assert!(
            matches!(result, GatewaySubmitResult::Denied { .. }),
            "{result:?}"
        );
    }
}
