//! Remote approval corpus: `bindings/fixtures/approval/remote-approval.json`.
//!
//! `remote_approval_fixture_is_current` regenerates the corpus from fixed
//! seeds and requires it to be byte-identical; the Python and TypeScript SDKs
//! replay the same file. Every refusal vector is checked against the code it
//! records while it is generated, and replayed from the committed bytes by
//! `every_fixture_vector_replays`.

use super::*;
use crate::{DEFAULT_QUORUM_VALIDITY_SECONDS, MAX_APPROVERS, QuorumActor};
use auths_codec::{
    action_signing_preimage, encode_bundle, encode_signed_action, encode_signed_grant,
    grant_signing_preimage,
};
use auths_model::{
    ActionConstraint, AssurancePolicyId, Audience, AudienceSet, CapabilityId, CriticalExtensions,
    Permission, PermissionSet, ProfileId, ResourceId, SignatureEnvelope, SignedAction, SignedGrant,
    StatusPolicy, Timestamp, ValidityWindow,
};
use auths_profile_mcp::{McpProfile, McpToolCall, PROFILE_ID, PROFILE_VERSION};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../bindings/fixtures/approval/remote-approval.json"
);
const FIXTURE: &str = include_str!("../../../../bindings/fixtures/approval/remote-approval.json");

const SCHEMA: &str = "auths.approval-fixtures/1";
const SERVICE: &str = "payments";
const TOOL: &str = "refund_v1";
const EVALUATION_TIME: u64 = 1_790_000_000;
const OPENED_AT: u64 = EVALUATION_TIME + 60;
const DECIDED_AT: u64 = EVALUATION_TIME + 120;
const CHALLENGE: [u8; 32] = [0x62; 32];
const REQUIRED: u16 = 2;
const SHOWN_AMOUNT: u64 = 1_500;
const SIGNED_AMOUNT: u64 = 150_000;

/// Fixed test seeds: the requester, three managers, the agent's grant issuer,
/// and one principal outside the proposal.
const MEMBERS: [(&str, u8); 6] = [
    ("agent", 0x11),
    ("manager-a", 0xc3),
    ("manager-b", 0xa1),
    ("manager-c", 0xb2),
    ("root", 0x01),
    ("outsider", 0xd4),
];
/// The listed approvers by name, in the ascending principal order the
/// requirement fixes; `proposal` checks the order.
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

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        )
    }

    fn evidence(&self) -> EvidenceObject {
        address_evidence(
            EvidenceTypeId::parse(RAW_KEY_V1).expect("type"),
            MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("media"),
            self.raw.encode(),
        )
        .expect("evidence")
    }

    fn sign(&self, preimage: &[u8]) -> Vec<u8> {
        self.key.sign(preimage).to_bytes().to_vec()
    }

    fn json(&self) -> Value {
        let evidence = self.evidence();
        json!({
            "name": self.name,
            "seed_byte": self.seed,
            "principal": self.principal.as_str(),
            "evidence_type": evidence.evidence_type().as_str(),
            "evidence_media_type": evidence.media_type().as_str(),
            "evidence_b64": b64(evidence.bytes()),
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn arguments(amount: u64) -> Map<String, Value> {
    json!({"amount": amount, "payment_intent": "pi_fixture_0001"})
        .as_object()
        .expect("object")
        .clone()
}

fn mcp_profile() -> ProfileRef {
    ProfileRef::new(
        ProfileId::parse(PROFILE_ID).expect("profile"),
        PROFILE_VERSION,
    )
    .expect("profile")
}

fn open(input: &[u8], registry: &str, now: u64) -> Result<ReviewedRequest, ApprovalCode> {
    let mcp = RegisteredProfile::new(mcp_profile(), McpProfile);
    let profiles: Vec<&dyn ReviewProfile> = match registry {
        "mcp" => vec![&mcp],
        _ => Vec::new(),
    };
    open_request(input, &profiles, now)
}

fn proposal(amount: u64) -> QuorumProposal {
    let call = McpToolCall::new(SERVICE, TOOL, arguments(amount)).expect("call");
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().expect("bytes"))
        .expect("canonical");
    let approvers: Vec<_> = MANAGERS
        .iter()
        .map(|name| Member::named(name).principal)
        .collect();
    let grant = agent_grant();
    let quorum = QuorumProposal::new(
        canonical,
        &call.audience().expect("audience"),
        CHALLENGE,
        EVALUATION_TIME,
        None,
        REQUIRED,
        &approvers,
        &QuorumActor::new(Member::named("agent").principal, Some(&grant.0)).expect("actor"),
    )
    .expect("proposal");
    assert_eq!(
        quorum.approvers(),
        approvers,
        "managers are listed in order"
    );
    quorum
}

/// The agent's signed action for `quorum`, with its grant chain.
fn agent_action(quorum: &QuorumProposal) -> QuorumAction {
    let agent = Member::named("agent");
    let descriptor = agent.descriptor();
    let preimage = action_signing_preimage(quorum.envelope(), &descriptor).expect("preimage");
    let signature = SignatureBytes::new(agent.sign(&preimage)).expect("signature");
    QuorumAction::new(
        SignedAction::new(
            quorum.envelope().clone(),
            SignatureEnvelope::new(descriptor, signature),
        ),
        vec![agent_grant()],
        vec![agent.evidence()],
    )
    .expect("action")
}

fn agent_grant() -> (SignedGrant, Vec<EvidenceObject>) {
    let root = Member::named("root");
    let agent = Member::named("agent");
    let audience = Audience::parse(&format!("mcp://{SERVICE}")).expect("audience");
    let statement = auths_model::GrantStatement::new(
        root.principal.clone(),
        agent.principal,
        mcp_profile(),
        PermissionSet::new(vec![Permission::new(
            CapabilityId::parse("tools/call").expect("capability"),
            ResourceId::parse(&format!("mcp://{SERVICE}/tools/{TOOL}")).expect("resource"),
        )])
        .expect("permissions"),
        ValidityWindow::new(
            Timestamp::new(EVALUATION_TIME - 300),
            Timestamp::new(EVALUATION_TIME + 30 * 86_400),
        )
        .expect("validity"),
        AudienceSet::new(vec![audience]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("raw-key-baseline").expect("assurance"),
        CriticalExtensions::empty(),
    );
    let descriptor = root.descriptor();
    let preimage = grant_signing_preimage(&statement, &descriptor).expect("preimage");
    let signature = SignatureBytes::new(root.sign(&preimage)).expect("signature");
    (
        SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature)),
        vec![root.evidence()],
    )
}

fn approve(reviewed: &ReviewedRequest, member: &Member) -> ApprovalResponse {
    let pending = reviewed
        .prepare_approval(&member.principal, member.descriptor())
        .expect("addressed");
    assert_eq!(
        pending.display(),
        reviewed.fields(),
        "custody shows the review"
    );
    assert_eq!(pending.expires_at(), reviewed.window().expires_at());
    assert!(pending.signing().request_id().starts_with("approval:"));
    let signature = member.sign(pending.signing().signing_preimage());
    pending
        .complete(&signature, vec![member.evidence()])
        .expect("response")
}

fn decline(reviewed: &ReviewedRequest, member: &Member) -> ApprovalResponse {
    let pending = reviewed
        .prepare_decline(&member.principal, member.descriptor(), DECIDED_AT)
        .expect("addressed");
    assert_eq!(pending.display(), reviewed.fields());
    let signature = member.sign(pending.signing_preimage());
    pending
        .complete(&signature, vec![member.evidence()])
        .expect("response")
}

fn reencode(request: &ApprovalRequest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    write_request(&mut encoder, request).expect("encode");
    encoder.into_writer()
}

fn rekeyed(mut request: ApprovalRequest) -> ApprovalRequest {
    request.request_id = request_id(
        &request.canonical_action,
        &request.statement,
        &request.approver,
    )
    .expect("request ID");
    request
}

fn review_json(reviewed: &ReviewedRequest) -> Value {
    json!({
        "title": reviewed.title(),
        "fields": reviewed.fields(),
        "display_digest_hex": reviewed.display_digest_hex(),
        "requester": reviewed.requester().as_str(),
        "approvers": reviewed.approvers().iter().map(PrincipalId::as_str).collect::<Vec<_>>(),
        "required": reviewed.required(),
        "approver": reviewed.approver().as_str(),
        "window": [reviewed.window().not_before(), reviewed.window().expires_at()],
        "request_id_hex": hex(&reviewed.request_id()),
    })
}

struct OpenCase {
    name: &'static str,
    input: Vec<u8>,
    text: bool,
    now: u64,
    registry: &'static str,
    expect: Option<ApprovalCode>,
}

impl OpenCase {
    fn bytes(name: &'static str, input: Vec<u8>, expect: Option<ApprovalCode>) -> Self {
        Self {
            name,
            input,
            text: false,
            now: OPENED_AT,
            registry: "mcp",
            expect,
        }
    }

    fn text(name: &'static str, input: String, expect: Option<ApprovalCode>) -> Self {
        Self {
            text: true,
            ..Self::bytes(name, input.into_bytes(), expect)
        }
    }

    fn at(self, now: u64) -> Self {
        Self { now, ..self }
    }

    fn json(&self) -> Value {
        let result = open(&self.input, self.registry, self.now);
        assert_eq!(result.as_ref().err().copied(), self.expect, "{}", self.name);
        let mut value = json!({
            "name": self.name,
            "now": self.now,
            "profiles": self.registry,
            "expect": self.expect.map(ApprovalCode::as_str),
        });
        if self.text {
            value["input_text"] = json!(core::str::from_utf8(&self.input).expect("text"));
        } else {
            value["input_b64"] = json!(b64(&self.input));
        }
        if let Ok(reviewed) = result {
            value["review"] = review_json(&reviewed);
        }
        value
    }
}

#[allow(clippy::too_many_lines)]
fn open_vectors(issued: &[ApprovalRequest], other: &[ApprovalRequest]) -> Vec<Value> {
    use ApprovalCode as Code;
    let encoded: Vec<Vec<u8>> = issued
        .iter()
        .map(|request| request.encode().expect("encode"))
        .collect();
    let window = issued[0].window;
    let base = issued[1].clone();
    let outsider = Member::named("outsider").principal;
    let with = |edit: &dyn Fn(&mut ApprovalRequest)| {
        let mut request = base.clone();
        edit(&mut request);
        request
    };

    let mut unknown_key = encoded[1].clone();
    unknown_key[0] = 0xaa;
    unknown_key.extend_from_slice(&[0x09, 0x61, b'x']);

    let canonical = reencode(&base);
    let at = canonical
        .windows(2)
        .rposition(|pair| pair == [0x05, 0x02])
        .expect("required field");
    let mut non_minimal = canonical[..at].to_vec();
    non_minimal.extend_from_slice(&[0x05, 0x19, 0x00, 0x02]);
    non_minimal.extend_from_slice(&canonical[at + 2..]);

    let mut oversized = encoded[1].clone();
    oversized.resize(MAX_APPROVAL_MESSAGE_BYTES + 1, 0);

    let crowded = with(&|request| {
        request.approvers = (0..=MAX_APPROVERS)
            .map(|index| {
                let byte = u8::try_from(index).expect("index");
                PrincipalId::parse(&format!("key:sha256:{}", b64(&[byte; 32]))).expect("principal")
            })
            .collect();
    });
    let mut shows_less = other[1].clone();
    shows_less.canonical_action = base.canonical_action.clone();
    let shows_more = with(&|request| request.canonical_action = other[1].canonical_action.clone());
    let manager_a = issued[0].approver.clone();
    let manager_c = issued[2].approver.clone();

    let cases = [
        OpenCase::bytes("addressed-to-manager-a", encoded[0].clone(), None),
        OpenCase::bytes("addressed-to-manager-b", encoded[1].clone(), None),
        OpenCase::bytes("addressed-to-manager-c", encoded[2].clone(), None),
        OpenCase::text(
            "printable-form-with-surrounding-whitespace",
            format!("  {}\n", base.to_text().expect("text")),
            None,
        ),
        OpenCase::bytes("opened-at-the-last-second", encoded[1].clone(), None)
            .at(window.expires_at),
        OpenCase::bytes("garbage", vec![0xff, 0x00], Some(Code::Malformed)),
        OpenCase::bytes("empty", Vec::new(), Some(Code::Malformed)),
        OpenCase::bytes("unknown-key", unknown_key, Some(Code::Malformed)),
        OpenCase::bytes("non-minimal-integer", non_minimal, Some(Code::Malformed)),
        OpenCase::text(
            "printable-form-bad-base64",
            format!("{APPROVAL_REQUEST_TEXT_PREFIX}!!!!"),
            Some(Code::Malformed),
        ),
        OpenCase::text(
            "printable-form-with-padding",
            format!("{}=", base.to_text().expect("text")),
            Some(Code::Malformed),
        ),
        OpenCase::text(
            "response-prefix",
            format!("{APPROVAL_RESPONSE_TEXT_PREFIX}{}", b64(&encoded[1])),
            Some(Code::Malformed),
        ),
        OpenCase::bytes("over-the-byte-limit", oversized, Some(Code::Oversized)),
        OpenCase::bytes(
            "seventeen-approvers",
            reencode(&crowded),
            Some(Code::Oversized),
        ),
        OpenCase::bytes(
            "shows-15.00-signs-1500.00",
            reencode(&rekeyed(shows_less)),
            Some(Code::ActionMismatch),
        ),
        OpenCase::bytes(
            "shows-1500.00-signs-15.00",
            reencode(&rekeyed(shows_more)),
            Some(Code::ActionMismatch),
        ),
        OpenCase::bytes(
            "threshold-lowered",
            reencode(&rekeyed(with(&|request| request.required = 1))),
            Some(Code::RequirementMismatch),
        ),
        OpenCase::bytes(
            "approver-replaced",
            reencode(&rekeyed(with(&|request| {
                request.approvers[2] = outsider.clone();
            }))),
            Some(Code::RequirementMismatch),
        ),
        OpenCase::bytes(
            "approver-listed-twice",
            reencode(&rekeyed(with(&|request| {
                request.approvers[2] = manager_a.clone();
            }))),
            Some(Code::RequirementMismatch),
        ),
        OpenCase::bytes(
            "requester-listed-as-approver",
            reencode(&rekeyed(with(&|request| {
                request.requester = manager_c.clone();
            }))),
            Some(Code::RequirementMismatch),
        ),
        OpenCase::bytes(
            "addressed-to-another-approver",
            reencode(&rekeyed(with(&|request| {
                request.approver = manager_c.clone();
            }))),
            Some(Code::NotAddressed),
        ),
        OpenCase::bytes(
            "request-id-edited",
            reencode(&with(&|request| request.request_id[0] ^= 1)),
            Some(Code::RequestIdMismatch),
        ),
        OpenCase::bytes(
            "before-the-window",
            encoded[1].clone(),
            Some(Code::OutsideWindow),
        )
        .at(window.not_before - 1),
        OpenCase::bytes(
            "after-the-window",
            encoded[1].clone(),
            Some(Code::OutsideWindow),
        )
        .at(window.expires_at + 1),
        OpenCase::bytes(
            "window-differs-from-statement",
            reencode(&with(&|request| request.window.expires_at += 1)),
            Some(Code::OutsideWindow),
        ),
        OpenCase {
            registry: "none",
            ..OpenCase::bytes(
                "no-registered-profile",
                encoded[1].clone(),
                Some(Code::ProfileUnregistered),
            )
        },
    ];
    cases.iter().map(OpenCase::json).collect()
}

fn status_json(status: &ApproverStatus, approver: &str) -> Value {
    match status {
        ApproverStatus::Pending => json!({"approver": approver, "status": "pending"}),
        ApproverStatus::Approved => json!({"approver": approver, "status": "approved"}),
        ApproverStatus::Declined(decline) => json!({
            "approver": approver,
            "status": "declined",
            "decided_at": decline.decided_at(),
        }),
        ApproverStatus::Rejected(code) => json!({
            "approver": approver,
            "status": "rejected",
            "code": code.as_str(),
        }),
    }
}

/// A collection case: its name, the responses, and the in-process proof it
/// must reproduce when it assembles.
type CollectionCase<'a> = (&'a str, Vec<Vec<u8>>, Option<Vec<u8>>);

fn collection_json(shown: &QuorumProposal, action: &QuorumAction, inputs: &[Vec<u8>]) -> Value {
    let collection = collect(shown, inputs).expect("collects");
    let mut value = json!({
        "responses_b64": inputs.iter().map(|bytes| b64(bytes)).collect::<Vec<_>>(),
        "statuses": collection
            .statuses()
            .iter()
            .zip(MANAGERS)
            .map(|(status, approver)| status_json(status, approver))
            .collect::<Vec<_>>(),
        "approved": collection.approved(),
        "unattributed": collection
            .unattributed()
            .iter()
            .map(|(index, code)| json!([index, code.as_str()]))
            .collect::<Vec<_>>(),
    });
    match collection.assemble(action) {
        Ok(bundle) => value["proof_b64"] = json!(b64(&encode_bundle(&bundle).expect("bytes"))),
        Err(code) => value["assemble_code"] = json!(code.as_str()),
    }
    value
}

#[allow(clippy::too_many_lines)]
fn generate() -> String {
    let members: Vec<Member> = MEMBERS
        .iter()
        .map(|(name, _)| Member::named(name))
        .collect();
    let [manager_a, manager_b, manager_c, outsider] = [1, 2, 3, 5].map(|index| &members[index]);

    let shown = proposal(SHOWN_AMOUNT);
    let signed = proposal(SIGNED_AMOUNT);
    let issued = requests(&shown).expect("requests");
    let other = requests(&signed).expect("requests");
    let opened = open_vectors(&issued, &other);
    let action = agent_action(&shown);
    let stray_action = agent_action(&signed);

    let reviewed: Vec<ReviewedRequest> = issued
        .iter()
        .map(|request| open(&request.encode().expect("encode"), "mcp", OPENED_AT).expect("opens"))
        .collect();
    assert_eq!(
        reviewed[0]
            .prepare_approval(&outsider.principal, outsider.descriptor())
            .err(),
        Some(ApprovalCode::NotAddressed)
    );
    assert_eq!(
        reviewed[0]
            .prepare_decline(&manager_b.principal, manager_b.descriptor(), DECIDED_AT)
            .err(),
        Some(ApprovalCode::NotAddressed)
    );

    let approve_a = approve(&reviewed[0], manager_a);
    let approve_b = approve(&reviewed[1], manager_b);
    let approve_c = approve(&reviewed[2], manager_c);
    let decline_b = decline(&reviewed[1], manager_b);
    let decline_c = decline(&reviewed[2], manager_c);
    let forged_statement = {
        let pending = reviewed[1]
            .prepare_approval(&manager_b.principal, manager_a.descriptor())
            .expect("pending");
        let signature = manager_a.sign(pending.signing().signing_preimage());
        ApprovalResponse {
            request_id: issued[0].request_id,
            approver: manager_a.principal.clone(),
            body: ResponseBody::Approve(
                pending
                    .signing
                    .complete(
                        SignatureBytes::new(signature).expect("signature"),
                        vec![manager_a.evidence()],
                    )
                    .expect("approval"),
            ),
        }
    };
    let other_opened = open(&other[0].encode().expect("encode"), "mcp", OPENED_AT).expect("opens");
    let other_proposal = approve(&other_opened, manager_a);
    let mut wrong_approver = approve_a.clone();
    wrong_approver.approver = manager_b.principal.clone();

    let responses: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "approve-manager-a",
            approve_a.encode().expect("encode"),
            "manager-a",
            "approver",
        ),
        (
            "approve-manager-b",
            approve_b.encode().expect("encode"),
            "manager-b",
            "approver",
        ),
        (
            "approve-manager-c",
            approve_c.encode().expect("encode"),
            "manager-c",
            "approver",
        ),
        (
            "decline-manager-b",
            decline_b.encode().expect("encode"),
            "manager-b",
            "approver",
        ),
        (
            "decline-manager-c",
            decline_c.encode().expect("encode"),
            "manager-c",
            "approver",
        ),
        (
            "signed-for-another-statement",
            forged_statement.encode().expect("encode"),
            "manager-a",
            "attacker",
        ),
        (
            "signed-for-another-proposal",
            other_proposal.encode().expect("encode"),
            "manager-a",
            "attacker",
        ),
        (
            "names-another-approver",
            wrong_approver.encode().expect("encode"),
            "manager-a",
            "attacker",
        ),
        ("garbage", vec![0xa0], "", "attacker"),
    ];
    let response = |name: &str| {
        responses
            .iter()
            .find(|(candidate, ..)| *candidate == name)
            .map(|(_, bytes, ..)| bytes.clone())
            .expect("response")
    };
    for (name, bytes, ..) in &responses {
        if *name != "garbage" {
            let decoded = decode_response(bytes).expect("decodes");
            assert_eq!(&decoded.encode().expect("encode"), bytes);
            let text = decoded.to_text().expect("text");
            assert_eq!(decode_response(text.as_bytes()).expect("text"), decoded);
        }
    }

    let approval = |response: &ApprovalResponse| match response.body() {
        ResponseBody::Approve(approval) => approval.clone(),
        ResponseBody::Decline(_) => panic!("not an approval"),
    };
    let in_process = |pair: [&ApprovalResponse; 2]| {
        encode_bundle(
            &shown
                .assemble(&action, &pair.map(approval))
                .expect("in-process bundle"),
        )
        .expect("bytes")
    };

    let collections: Vec<CollectionCase<'_>> = vec![
        (
            "managers-a-and-b-approved",
            vec![response("approve-manager-a"), response("approve-manager-b")],
            Some(in_process([&approve_a, &approve_b])),
        ),
        (
            "managers-a-and-c-approved",
            vec![response("approve-manager-a"), response("approve-manager-c")],
            Some(in_process([&approve_a, &approve_c])),
        ),
        (
            "managers-b-and-c-approved",
            vec![response("approve-manager-c"), response("approve-manager-b")],
            Some(in_process([&approve_b, &approve_c])),
        ),
        (
            "every-manager-approved",
            vec![
                response("approve-manager-a"),
                response("approve-manager-b"),
                response("approve-manager-c"),
            ],
            None,
        ),
        (
            "arrival-order-and-form-do-not-matter",
            vec![
                response("approve-manager-b"),
                approve_a.to_text().expect("text").into_bytes(),
            ],
            Some(in_process([&approve_a, &approve_b])),
        ),
        (
            "one-approved-two-pending",
            vec![response("approve-manager-a")],
            None,
        ),
        (
            "one-declined-two-approved",
            vec![
                response("approve-manager-a"),
                response("decline-manager-b"),
                response("approve-manager-c"),
            ],
            Some(in_process([&approve_a, &approve_c])),
        ),
        (
            "two-declined",
            vec![
                response("approve-manager-a"),
                response("decline-manager-b"),
                response("decline-manager-c"),
            ],
            None,
        ),
        (
            "second-response-from-one-approver",
            vec![
                response("approve-manager-a"),
                response("approve-manager-b"),
                response("approve-manager-a"),
            ],
            None,
        ),
        (
            "approve-then-decline",
            vec![
                response("approve-manager-a"),
                response("approve-manager-b"),
                response("decline-manager-b"),
            ],
            None,
        ),
        (
            "signed-for-another-statement",
            vec![
                response("signed-for-another-statement"),
                response("approve-manager-b"),
            ],
            None,
        ),
        (
            "names-another-approver",
            vec![
                response("names-another-approver"),
                response("approve-manager-b"),
            ],
            None,
        ),
        (
            "unattributable-responses-do-not-count",
            vec![
                response("approve-manager-a"),
                response("signed-for-another-proposal"),
                response("garbage"),
                response("approve-manager-c"),
            ],
            Some(in_process([&approve_a, &approve_c])),
        ),
    ];
    let mut collected: Vec<Value> = collections
        .iter()
        .map(|(name, inputs, expected)| {
            let mut value = collection_json(&shown, &action, inputs);
            if let Some(expected) = expected {
                assert_eq!(
                    value["proof_b64"].as_str(),
                    Some(b64(expected).as_str()),
                    "{name}: remote and in-process assembly agree"
                );
            }
            value["name"] = json!(name);
            value
        })
        .collect();
    let mut stray = collection_json(
        &shown,
        &stray_action,
        &[response("approve-manager-a"), response("approve-manager-b")],
    );
    assert_eq!(
        stray["assemble_code"].as_str(),
        Some(ApprovalCode::ActionMismatch.as_str())
    );
    stray["name"] = json!("actor-signed-another-action");
    stray["action"] = json!("attacker");
    collected.push(stray);

    let grant = agent_grant();
    let evidence_json = |object: &EvidenceObject| {
        json!({
            "evidence_type": object.evidence_type().as_str(),
            "evidence_media_type": object.media_type().as_str(),
            "evidence_b64": b64(object.bytes()),
        })
    };
    let action_json = |action: &QuorumAction| {
        json!({
            "signed_action_b64": b64(&encode_signed_action(action.action()).expect("action")),
            "evidence": action.action_evidence.iter().map(evidence_json).collect::<Vec<_>>(),
        })
    };
    let fixture = json!({
        "schema": SCHEMA,
        "codes": ApprovalCode::ALL.iter().map(|code| code.as_str()).collect::<Vec<_>>(),
        "service": SERVICE,
        "tool": TOOL,
        "arguments": arguments(SHOWN_AMOUNT),
        "attacker_arguments": arguments(SIGNED_AMOUNT),
        "evaluation_time": EVALUATION_TIME,
        "validity_seconds": DEFAULT_QUORUM_VALIDITY_SECONDS,
        "challenge_hex": hex(&CHALLENGE),
        "required": REQUIRED,
        "approvers": MANAGERS,
        "requester": "agent",
        "requirement_id_hex": hex(shown.requirement_id().as_bytes()),
        "opened_at": OPENED_AT,
        "decided_at": DECIDED_AT,
        "members": members.iter().map(Member::json).collect::<Vec<_>>(),
        "agent_grant": {
            "signed_grant_b64": b64(&encode_signed_grant(&grant.0).expect("grant")),
            "evidence": grant.1.iter().map(evidence_json).collect::<Vec<_>>(),
        },
        "agent_action": action_json(&action),
        "attacker_action": action_json(&stray_action),
        "requests": issued.iter().zip(MANAGERS).map(|(request, approver)| json!({
            "approver": approver,
            "request_id_hex": hex(&request.request_id),
            "request_b64": b64(&request.encode().expect("encode")),
            "request_text": request.to_text().expect("text"),
        })).collect::<Vec<_>>(),
        "open": opened,
        "responses": responses.iter().map(|(name, bytes, approver, origin)| json!({
            "name": name,
            "approver": approver,
            "origin": origin,
            "response_b64": b64(bytes),
        })).collect::<Vec<_>>(),
        "collect": collected,
    });
    let mut text = serde_json::to_string_pretty(&fixture).expect("json");
    text.push('\n');
    text
}

#[test]
fn remote_approval_fixture_is_current() {
    let generated = generate();
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        let path = std::path::Path::new(FIXTURE_PATH);
        std::fs::create_dir_all(path.parent().expect("fixture directory"))
            .expect("create fixture directory");
        std::fs::write(path, &generated).expect("write fixture");
        return;
    }
    assert!(
        generated == FIXTURE,
        "remote approval fixture is stale; rerun with AUTHS_UPDATE_FIXTURES=1"
    );
}

fn bytes_of(value: &Value) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value.as_str().expect("base64")).expect("base64")
}

#[test]
fn every_fixture_vector_replays() {
    let corpus: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    let mut seen = std::collections::BTreeSet::new();
    for case in corpus["open"].as_array().expect("open cases") {
        let input = case.get("input_text").map_or_else(
            || bytes_of(&case["input_b64"]),
            |text| text.as_str().expect("text").as_bytes().to_vec(),
        );
        let result = open(
            &input,
            case["profiles"].as_str().expect("profiles"),
            case["now"].as_u64().expect("now"),
        );
        match (result, case["expect"].as_str()) {
            (Ok(reviewed), None) => assert_eq!(review_json(&reviewed), case["review"]),
            (Err(code), Some(expected)) => {
                assert_eq!(code.as_str(), expected, "{}", case["name"]);
                seen.insert(expected.to_owned());
            }
            (other, expected) => panic!("{}: {other:?} != {expected:?}", case["name"]),
        }
    }
    let shown = proposal(SHOWN_AMOUNT);
    let action = agent_action(&shown);
    let stray_action = agent_action(&proposal(SIGNED_AMOUNT));
    for case in corpus["collect"].as_array().expect("collect cases") {
        let inputs: Vec<Vec<u8>> = case["responses_b64"]
            .as_array()
            .expect("responses")
            .iter()
            .map(bytes_of)
            .collect();
        let chosen = if case.get("action").is_some() {
            &stray_action
        } else {
            &action
        };
        let mut replayed = collection_json(&shown, chosen, &inputs);
        replayed["name"] = case["name"].clone();
        if let Some(origin) = case.get("action") {
            replayed["action"] = origin.clone();
        }
        assert_eq!(&replayed, case, "{}", case["name"]);
        for status in collect(&shown, &inputs).expect("collects").statuses() {
            if let ApproverStatus::Rejected(code) = status {
                seen.insert(code.as_str().to_owned());
            }
        }
        for [_, code] in case["unattributed"]
            .as_array()
            .expect("unattributed")
            .iter()
            .map(|pair| {
                let pair = pair.as_array().expect("pair");
                [pair[0].clone(), pair[1].clone()]
            })
        {
            seen.insert(code.as_str().expect("code").to_owned());
        }
        if let Some(code) = case["assemble_code"].as_str() {
            seen.insert(code.to_owned());
        }
    }
    let every: std::collections::BTreeSet<String> = ApprovalCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect();
    assert_eq!(seen, every, "the corpus exercises every stable code");
}

#[test]
fn requests_are_deterministic_and_round_trip() {
    let shown = proposal(SHOWN_AMOUNT);
    let first = requests(&shown).expect("requests");
    assert_eq!(first, requests(&shown).expect("requests"));
    assert_eq!(first.len(), MANAGERS.len());
    for (request, statement) in first.iter().zip(shown.statements()) {
        assert_eq!(request.approver(), statement.approver());
        let bytes = request.encode().expect("encode");
        assert_eq!(decode_request(&bytes).expect("decode"), *request);
        let text = request.to_text().expect("text");
        assert!(text.starts_with(APPROVAL_REQUEST_TEXT_PREFIX));
        assert_eq!(decode_request(text.as_bytes()).expect("decode"), *request);
    }
}

#[test]
fn a_decline_signs_the_domain_separated_preimage() {
    let shown = proposal(SHOWN_AMOUNT);
    let manager = Member::named("manager-b");
    let request = requests(&shown).expect("requests")[1]
        .encode()
        .expect("encode");
    let reviewed = open(&request, "mcp", OPENED_AT).expect("opens");
    let pending = reviewed
        .prepare_decline(&manager.principal, manager.descriptor(), DECIDED_AT)
        .expect("pending");
    let mut expected = Sha256::new();
    expected.update(b"auths.approval-decline/2\0");
    expected.update(reviewed.request_id());
    expected.update(DECIDED_AT.to_be_bytes());
    assert_eq!(
        pending.signing_preimage(),
        &<[u8; 32]>::from(expected.finalize())
    );
    assert!(
        pending
            .custody_request_id()
            .starts_with("approval-decline:")
    );
    assert_eq!(pending.expires_at(), reviewed.window().expires_at());
}

#[test]
fn an_approval_signs_the_profile_bound_statement() {
    let shown = proposal(SHOWN_AMOUNT);
    let manager = Member::named("manager-a");
    let request = requests(&shown).expect("requests")[0]
        .encode()
        .expect("encode");
    let reviewed = open(&request, "mcp", OPENED_AT).expect("opens");
    assert_eq!(reviewed.statement(), &shown.statements()[0]);
    let pending = reviewed
        .prepare_approval(&manager.principal, manager.descriptor())
        .expect("pending");
    assert_eq!(
        pending.signing().signing_preimage(),
        auths_codec::approval_signing_preimage(
            &shown.statements()[0],
            &manager.descriptor(),
            shown.canonical().profile(),
        )
        .expect("preimage")
    );
}
