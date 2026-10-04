//! Approval-quorum hostile cases: "any 2 of 3 managers approve before the
//! agent acts", driven through the gateway's native verification and a
//! counting provider.
//!
//! The installed trust anchors the agent for one MCP tool, names three
//! managers as approvers, and requires approvals from any two of them. The
//! agent signs the action; each manager signs an approval of the exact action
//! bound to the installed requirement. Submissions run through the shared
//! `Harness`, which verifies, claims, reserves, leases, and enters the
//! counting provider in the engine's order. Every proof, action, and the
//! trusted context are read from `bindings/fixtures/gateway/approval-quorum.json`;
//! the drive test signs nothing. The fixture test regenerates the file from
//! fixed seeds and requires it to be byte-identical, so the Python and
//! TypeScript SDKs can check their own authoring against the same bytes.

use crate::engine::{GatewaySubmitResult, gateway_verifier_configuration, verify_command};
use crate::harness::{self, Harness};
use crate::{CompiledRecipe, GatewayObserver};
use auths_approval_quorum::{
    ApprovalCode, DEFAULT_QUORUM_VALIDITY_SECONDS, QuorumAction, QuorumActor, QuorumProposal,
    RegisteredProfile, collect, open_request, requests,
};
use auths_codec::{
    action_signing_preimage, approval_signing_preimage, encode_bundle, encode_canonical_action,
    encode_verifier_context, evidence_id,
};
use auths_model::{
    AcceptedRegistries, ActionEnvelope, ApprovalRequirement, ApprovalStatement, ApproverAnchor,
    AssuranceClaimId, AssurancePolicy, AssurancePolicyId, AssuranceQuantifier,
    AssuranceRequirement, Audience, AudienceSet, CanonicalAction, Challenge, ChannelBindingId,
    CompositionRequirement, EvidenceId, EvidenceObject, EvidenceTypeId, GrantStatusSnapshot,
    MediaType, ParticipantRole, PermissionSet, PrincipalId, PrincipalMethodId,
    PrincipalStatusSnapshot, ProfilePolicyId, ProofBundle, ResourceId, ResourceMatcherId,
    SignatureBytes, SignatureDescriptor, SignatureEnvelope, SignatureSuiteId, SignedAction,
    SignedApproval, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId,
    TrustedContext, ValidityWindow, VerificationMethod, VerifierLimits,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../bindings/fixtures/gateway/approval-quorum.json"
);
const FIXTURE: &str = include_str!("../../../../bindings/fixtures/gateway/approval-quorum.json");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");

const SCHEMA: &str = "auths.gateway-approval-quorum/2";
const NOW: u64 = 1_790_000_000;
/// Approvals are authored this long before the gateway verifies them, inside
/// the default quorum validity.
const AUTHORED_AT: u64 = NOW - 10;
const CHALLENGE: [u8; 32] = [0x51; 32];
const REQUIRED: u16 = 2;
const ASSURANCE: &str = "approval-quorum-test-v1";

/// Fixed test seeds: the agent, three managers, and one principal outside
/// the installation.
const MEMBERS: [(&str, u8); 5] = [
    ("agent", 0x11),
    ("manager-a", 0xa1),
    ("manager-b", 0xb2),
    ("manager-c", 0xc3),
    ("outsider", 0xd4),
];
const MANAGERS: [&str; 3] = ["manager-a", "manager-b", "manager-c"];

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

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        )
    }

    fn sign(&self, envelope: &ActionEnvelope) -> QuorumAction {
        let descriptor = self.descriptor();
        let preimage = action_signing_preimage(envelope, &descriptor).expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        QuorumAction::new(
            SignedAction::new(
                envelope.clone(),
                SignatureEnvelope::new(descriptor, signature),
            ),
            Vec::new(),
            vec![self.evidence()],
        )
        .expect("action")
    }

    /// Signs `template` with this member as approver, whether or not the
    /// proposal lists it.
    fn approve(&self, quorum: &QuorumProposal, template: &ApprovalStatement) -> SignedApproval {
        let statement = ApprovalStatement::new(
            self.principal.clone(),
            template.requirement(),
            template.media_type().clone(),
            template.body_digest(),
            template.permission().clone(),
            template.requested_budget().cloned(),
            template.attributes(),
            template.audience().clone(),
            template.challenge(),
            template.validity(),
        );
        let descriptor = self.descriptor();
        let preimage =
            approval_signing_preimage(&statement, &descriptor, quorum.canonical().profile())
                .expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        SignedApproval::new(
            statement,
            SignatureEnvelope::new(descriptor, signature),
            vec![self.evidence()],
        )
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
        "record_id": harness::RECORD,
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
    ValidityWindow::new(
        Timestamp::new(AUTHORED_AT),
        Timestamp::new(AUTHORED_AT + DEFAULT_QUORUM_VALIDITY_SECONDS),
    )
    .expect("window")
}

fn manager_principals() -> Vec<PrincipalId> {
    MANAGERS
        .iter()
        .map(|name| Member::named(name).principal)
        .collect()
}

fn proposal(recipe: &CompiledRecipe, operation: &str, required: u16) -> QuorumProposal {
    let (canonical, audience) = canonical(recipe, operation);
    QuorumProposal::new(
        canonical,
        &audience,
        CHALLENGE,
        AUTHORED_AT,
        None,
        required,
        &manager_principals(),
        &QuorumActor::new(Member::named("agent").principal, None).expect("actor"),
    )
    .expect("proposal")
}

fn requirement() -> ApprovalRequirement {
    ApprovalRequirement::new(manager_principals(), REQUIRED).expect("requirement")
}

fn approver_anchors() -> Vec<ApproverAnchor> {
    MANAGERS
        .iter()
        .map(|name| {
            ApproverAnchor::new(
                Member::named(name).principal,
                vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
                ValidityWindow::new(Timestamp::new(NOW - 86_400), Timestamp::new(NOW + 86_400))
                    .expect("approver window"),
                StatusPolicy::ExpiryOnly,
            )
            .expect("approver anchor")
        })
        .collect()
}

fn agent_anchor(recipe: &CompiledRecipe, namespace: &str) -> TrustAnchor {
    let call = call(recipe, "trust");
    TrustAnchor::new(
        TrustAnchorId::parse("agent").expect("anchor ID"),
        Member::named("agent").principal,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        vec![call.profile_ref().expect("profile")],
        PermissionSet::new(vec![call.permission().expect("permission")]).expect("permissions"),
        vec![ResourceId::parse(namespace).expect("namespace")],
        AudienceSet::new(vec![call.audience().expect("audience")]).expect("audiences"),
        ValidityWindow::new(Timestamp::new(NOW - 86_400), Timestamp::new(NOW + 86_400))
            .expect("anchor window"),
        None,
        0,
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        StatusPolicy::ExpiryOnly,
    )
    .expect("trust anchor")
}

/// The operator's installation: the agent is a depth-zero anchor for the one
/// MCP tool, and any two of the three managers must approve.
fn trusted_context(recipe: &CompiledRecipe) -> TrustedContext {
    let call = call(recipe, "trust");
    let profile = call.profile_ref().expect("profile");
    let audience = call.audience().expect("audience");
    let assurance = AssurancePolicyId::parse(ASSURANCE).expect("assurance");
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
        vec![ProfilePolicyId::parse(auths_profile_mcp::MCP_ARGUMENTS_V1).expect("policy")],
    )
    .expect("registries");
    TrustedContext::new(
        gateway_verifier_configuration().expect("configuration"),
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        vec![agent_anchor(recipe, "mcp://airtable-gateway-demo/")],
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
        ProfilePolicyId::parse(auths_profile_mcp::MCP_ARGUMENTS_V1).expect("policy"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        VerifierLimits::default(),
    )
    .expect("context")
    .with_approvals(approver_anchors(), vec![requirement()])
    .expect("approvals")
}

/// The same installation as an SDK trusted-context template under the
/// packaged verifier configuration, so the Python and TypeScript verifiers
/// decide the same vectors the gateway decides.
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
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        vec![agent_anchor(recipe, audience.as_str())],
        assurance,
    )
    .expect("builder")
    .with_approvals(approver_anchors(), vec![requirement()])
    .expect("approvals")
    .declare_budget_free_profile(profile)
    .accept_evidence_type(EvidenceTypeId::parse(RAW_KEY_V1).expect("evidence type"))
    .build()
    .expect("SDK template")
}

#[test]
fn the_action_and_every_statement_share_the_default_window() {
    let quorum = proposal(&recipe(), "window", REQUIRED);
    assert_eq!(quorum.envelope().validity(), validity());
    assert!(
        quorum
            .statements()
            .iter()
            .all(|statement| statement.validity() == validity())
    );
}

/// The agent's action with approvals by `names`. The SDK assembles when the
/// names are distinct listed managers at the threshold; otherwise the bundle
/// carries exactly the approvals named, which the SDK refuses to assemble.
fn bundle(recipe: &CompiledRecipe, operation: &str, required: u16, names: &[&str]) -> ProofBundle {
    let quorum = proposal(recipe, operation, required);
    let action = Member::named("agent").sign(quorum.envelope());
    let template = &quorum.statements()[0];
    let approvals: Vec<_> = names
        .iter()
        .map(|name| Member::named(name).approve(&quorum, template))
        .collect();
    quorum.assemble(&action, &approvals).unwrap_or_else(|_| {
        let full: Vec<_> = MANAGERS[..usize::from(required)]
            .iter()
            .map(|name| Member::named(name).approve(&quorum, template))
            .collect();
        quorum
            .assemble(&action, &full)
            .expect("assembled quorum")
            .with_approvals(approvals)
            .expect("hand-chosen approvals")
    })
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

const CASES: [Case; 10] = [
    Case {
        id: "managers-a-and-b",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "manager-b"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
    Case {
        id: "managers-a-and-c",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-a", "manager-c"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
    Case {
        id: "managers-b-and-c",
        authoring: "sdk",
        required: 2,
        approvers: &["manager-b", "manager-c"],
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
    Case {
        id: "one-of-three-managers",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a"],
        decision: "denied",
        code: "approval-threshold-not-met",
        provider_entries: 0,
    },
    Case {
        id: "no-approvals",
        authoring: "hand",
        required: 2,
        approvers: &[],
        decision: "denied",
        code: "approval-threshold-not-met",
        provider_entries: 0,
    },
    Case {
        id: "duplicate-approval",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a", "manager-a"],
        decision: "denied",
        code: "approval-threshold-not-met",
        provider_entries: 0,
    },
    Case {
        id: "outsider-does-not-count",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a", "outsider"],
        decision: "denied",
        code: "approval-threshold-not-met",
        provider_entries: 0,
    },
    Case {
        id: "outsider-beside-two-managers",
        authoring: "hand",
        required: 2,
        approvers: &["manager-a", "manager-b", "outsider"],
        decision: "authorized",
        code: "",
        provider_entries: 1,
    },
    Case {
        id: "approvals-for-a-lowered-threshold",
        authoring: "sdk",
        required: 1,
        approvers: &["manager-a"],
        decision: "denied",
        code: "approval-threshold-not-met",
        provider_entries: 0,
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
            let bundle = bundle(&recipe, case.id, case.required, case.approvers);
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
            let role = match member.name {
                "agent" => "actor",
                "outsider" => "outsider",
                _ => "approver",
            };
            json!({
                "name": member.name,
                "seed_byte": member.seed,
                "principal": member.principal.as_str(),
                "evidence_b64": b64(&member.raw.encode()),
                "role": role,
            })
        })
        .collect();
    let document = json!({
        "schema": SCHEMA,
        "service": "airtable-gateway-demo",
        "tool": "set_demo_status_v1",
        "evaluation_time": NOW,
        "authored_at": AUTHORED_AT,
        "validity_seconds": DEFAULT_QUORUM_VALIDITY_SECONDS,
        "challenge_hex": hex::encode(CHALLENGE),
        "required": REQUIRED,
        "approvers": MANAGERS,
        "actor": "agent",
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

fn decision_of(result: &GatewaySubmitResult) -> (&'static str, String) {
    match result {
        GatewaySubmitResult::Denied { code } => ("denied", code.clone()),
        GatewaySubmitResult::Indeterminate { code } => ("indeterminate", code.clone()),
        GatewaySubmitResult::NotEntered { code } => ("not-entered", code.clone()),
        _ => ("authorized", String::new()),
    }
}

#[tokio::test]
async fn approval_quorum_hostile_cases_admit_only_two_distinct_managers() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    assert_eq!(fixture["schema"], SCHEMA);
    let recipe = recipe();
    let context = auths_codec::decode_verifier_context(&unb64(&fixture["trusted_context_b64"]))
        .expect("installed trust");
    let temp = tempfile::tempdir().expect("temp directory");
    let harness = Harness::with(
        recipe,
        context,
        GatewayObserver::from_test_seed(harness::OBSERVER_SEED),
        &std::fs::canonicalize(temp.path()).expect("canonical temp"),
    )
    .expect("harness");
    let counts = || {
        let (writes, _, leases) = harness.provider.counts();
        (writes, leases)
    };
    let mut expected_entries = 0;
    let mut unauthorized_entries = 0;
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), CASES.len());
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let before = counts();
        let result = harness
            .submit(&unb64(&case["proof_b64"]), &unb64(&case["action_b64"]), NOW)
            .await;
        let after = counts();
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
                    GatewaySubmitResult::ObservedByProvider {
                        status: Some(200),
                        ..
                    }
                ),
                "{id}: {result:?}"
            );
            assert_eq!(
                leases, 2,
                "{id}: one lease for the entry and one for its read-back"
            );
            unauthorized_entries += entries.saturating_sub(1);
        } else {
            assert_eq!(leases, 0, "{id}: refused before any credential lease");
            unauthorized_entries += entries;
        }
        expected_entries += expected;
    }
    assert_eq!(counts().0, expected_entries);
    assert_eq!(unauthorized_entries, 0);

    let replay = &cases[0];
    let result = harness
        .submit(
            &unb64(&replay["proof_b64"]),
            &unb64(&replay["action_b64"]),
            NOW,
        )
        .await;
    assert!(
        !matches!(result, GatewaySubmitResult::ResponseRecorded { .. }),
        "an authorized quorum is one-use: {result:?}"
    );
    assert_eq!(counts().0, expected_entries, "a replay never writes again");
}

fn two_of_three_submission() -> (Vec<u8>, Vec<u8>) {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    let case = fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == "managers-a-and-b")
        .expect("two-of-three case");
    (unb64(&case["proof_b64"]), unb64(&case["action_b64"]))
}

fn fresh_harness(state: &std::path::Path) -> Harness {
    let recipe = recipe();
    let context = trusted_context(&recipe);
    Harness::with(
        recipe,
        context,
        GatewayObserver::from_test_seed(harness::OBSERVER_SEED),
        &std::fs::canonicalize(state).expect("canonical temp"),
    )
    .expect("harness")
}

#[tokio::test]
async fn a_quorum_still_authorizes_23_hours_after_approval_and_only_once() {
    let temp = tempfile::tempdir().expect("temp directory");
    let harness = fresh_harness(temp.path());
    let (proof, action) = two_of_three_submission();
    let later = AUTHORED_AT + 23 * 3_600;
    let result = harness.submit(&proof, &action, later).await;
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
    let (writes, _, leases) = harness.provider.counts();
    assert_eq!((writes, leases), (1, 2));
    let replay = harness.submit(&proof, &action, later + 60).await;
    assert!(
        !matches!(replay, GatewaySubmitResult::ResponseRecorded { .. }),
        "{replay:?}"
    );
    assert_eq!(
        harness.provider.counts().0,
        1,
        "the durable claim refuses a second entry"
    );
}

#[tokio::test]
async fn a_quorum_after_its_window_is_refused_before_any_lease() {
    let temp = tempfile::tempdir().expect("temp directory");
    let harness = fresh_harness(temp.path());
    let (proof, action) = two_of_three_submission();
    let result = harness
        .submit(
            &proof,
            &action,
            AUTHORED_AT + DEFAULT_QUORUM_VALIDITY_SECONDS + 1,
        )
        .await;
    assert_eq!(
        result,
        GatewaySubmitResult::Denied {
            code: "action-outside-validity".to_owned()
        }
    );
    assert_eq!(harness.provider.counts(), (0, 0, 0));
}

/// The quorum assembled from remote responses: the agent sends a request to
/// every manager, the managers in `names` open theirs (carried as text) and
/// answer on their own, and the collector assembles with the agent's action.
/// It must be byte-identical to the in-process quorum.
fn remote_bundle(
    recipe: &CompiledRecipe,
    operation: &str,
    names: &[&str],
    decline: &[&str],
) -> Result<ProofBundle, ApprovalCode> {
    let quorum = proposal(recipe, operation, REQUIRED);
    let action = Member::named("agent").sign(quorum.envelope());
    let mcp = RegisteredProfile::new(
        call(recipe, operation).profile_ref().expect("profile"),
        McpProfile,
    );
    let mut responses = Vec::new();
    for request in requests(&quorum)? {
        let Some(name) = names
            .iter()
            .find(|name| Member::named(name).principal == *request.approver())
        else {
            continue;
        };
        let member = Member::named(name);
        let text = request.to_text()?;
        let reviewed = open_request(text.as_bytes(), &[&mcp], AUTHORED_AT + 60)?;
        let response = if decline.contains(name) {
            let pending = reviewed.prepare_decline(&member.principal, member.descriptor(), NOW)?;
            let signature = member.key.sign(pending.signing_preimage()).to_bytes();
            pending.complete(&signature, vec![member.evidence()])?
        } else {
            let pending = reviewed.prepare_approval(&member.principal, member.descriptor())?;
            let signature = member
                .key
                .sign(pending.signing().signing_preimage())
                .to_bytes();
            pending.complete(&signature, vec![member.evidence()])?
        };
        responses.push(response.to_text()?);
    }
    collect(&quorum, &responses)?.assemble(&action)
}

#[tokio::test]
async fn remote_approvals_from_any_two_managers_authorize() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    let recipe = recipe();
    let temp = tempfile::tempdir().expect("temp directory");
    let harness = fresh_harness(temp.path());
    let mut entries = 0;
    for case in CASES
        .iter()
        .filter(|case| case.authoring == "sdk" && case.required == REQUIRED)
    {
        let vector = fixture["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|vector| vector["id"] == case.id)
            .expect("vector");
        let bundle = remote_bundle(&recipe, case.id, case.approvers, &[])
            .expect("the threshold of managers approved");
        let proof = encode_bundle(&bundle).expect("proof");
        assert_eq!(
            proof,
            unb64(&vector["proof_b64"]),
            "{}: remote and in-process quorums are the same bytes",
            case.id
        );
        let before = harness.provider.counts();
        let result = harness
            .submit(&proof, &unb64(&vector["action_b64"]), NOW)
            .await;
        let after = harness.provider.counts();
        let (decision, code) = decision_of(&result);
        assert_eq!(
            (decision, code.as_str()),
            (case.decision, case.code),
            "{}",
            case.id
        );
        assert_eq!(after.0 - before.0, case.provider_entries, "{}", case.id);
        assert_eq!(after.2 - before.2, 2 * case.provider_entries, "{}", case.id);
        entries += case.provider_entries;
    }
    assert!(
        remote_bundle(
            &recipe,
            "remote-one-decline",
            &["manager-a", "manager-b", "manager-c"],
            &["manager-b"],
        )
        .is_ok(),
        "one declined manager still leaves two approvals"
    );
    assert_eq!(
        remote_bundle(
            &recipe,
            "remote-two-declines",
            &["manager-a", "manager-b", "manager-c"],
            &["manager-b", "manager-c"],
        )
        .err(),
        Some(ApprovalCode::Incomplete),
        "two declined managers leave nothing to submit"
    );
    assert_eq!(
        remote_bundle(&recipe, "remote-one-answer", &["manager-c"], &[]).err(),
        Some(ApprovalCode::Incomplete),
        "one answer is not a quorum"
    );
    assert_eq!(harness.provider.counts().0, entries);
}

#[test]
fn a_proof_cannot_lower_the_installed_threshold() {
    let recipe = recipe();
    let context = trusted_context(&recipe);
    let action = encode_canonical_action(&canonical(&recipe, "lowered").0).expect("action");
    for bundle in [
        bundle(&recipe, "lowered", 1, &["manager-a"]),
        bundle(&recipe, "lowered", 1, &["manager-a", "outsider"]),
    ] {
        let proof = encode_bundle(&bundle).expect("proof");
        let result = verify_command(&recipe, &context, NOW, &proof, &action)
            .expect_err("a single manager never authorizes");
        assert_eq!(
            result,
            GatewaySubmitResult::Denied {
                code: "approval-threshold-not-met".to_owned()
            }
        );
    }
}
