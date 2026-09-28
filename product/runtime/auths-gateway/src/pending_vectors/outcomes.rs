//! Signed outcome `/2` vectors: for each stage and fact combination, the
//! canonical observation signed by a fixed test observer and its expected
//! facts, plus refused vectors that break the presence rule, the schema, or
//! the signer.
//!
//! Digest facts are fixed test bytes derived from their labels; they are not
//! recomputed from a store, because these vectors pin the signed encoding
//! and the presence rule, not a gateway run.
//!
//! Each verdict case attaches one vector's exact observation bytes to an
//! action whose grant requires `member("stage", ["observed-by-provider"])`
//! of that outcome, under a trusted context pinned to the packaged verifier
//! configuration, with the decision the native verifier reaches. The Python
//! (native) and TypeScript (WASM) verifiers must reach the same decision on
//! every case.

use super::{NOW, load, require_current};
use crate::GatewayObserver;
use crate::harness::{self as h, Signer};
use auths_model::{
    AssuranceClaimId, AssurancePolicy, AssurancePolicyId, AssuranceQuantifier,
    AssuranceRequirement, AudienceSet, Challenge, CompositionRequirement, ConditionTest,
    EvidenceTypeId, ExtensionId, FactBytes, FactName, FactText, FactValue, MemberValues,
    ObservationCondition, ObservationFact, ObservationRequirement, ObservationSchemaId,
    ObservationSubject, ObserverAnchor, ObserverAnchorId, ParticipantRole, PermissionSet,
    PrincipalMethodId, ResourceId, StatusPolicy, Timestamp, TrustAnchor, TrustAnchorId,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

pub(super) const FILE: &str = "outcome-v2.json";
const SCHEMA: &str = "auths.gateway-outcome-vectors/1";
const OUTCOME_V2: &str = "auths.gateway-outcome/2";
const OBSERVER_SEED: u8 = 0x5a;
const OTHER_SEED: u8 = 0x5b;
const OBSERVED_AT: u64 = NOW + 5;

#[derive(Clone, Copy)]
enum Fact {
    Text(&'static str),
    Uint(u64),
    /// Thirty-two test bytes derived from the label.
    Digest(&'static str),
    /// The lowercase hex of the test bytes derived from the label.
    DigestHex(&'static str),
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(format!("auths.gateway-outcome-vector/{label}")).into()
}

fn fact_value(fact: Fact) -> FactValue {
    match fact {
        Fact::Text(value) => FactValue::Text(FactText::new(value).expect("text fact")),
        Fact::Uint(value) => FactValue::Uint(value),
        Fact::Digest(label) => {
            FactValue::Bytes(FactBytes::new(digest(label).to_vec()).expect("bytes fact"))
        }
        Fact::DigestHex(label) => {
            FactValue::Text(FactText::new(&hex::encode(digest(label))).expect("text fact"))
        }
    }
}

fn fact_json(fact: Fact) -> Value {
    match fact {
        Fact::Text(value) => json!({"text": value}),
        Fact::Uint(value) => json!({"uint": value}),
        Fact::Digest(label) => json!({"bytes_hex": hex::encode(digest(label))}),
        Fact::DigestHex(label) => json!({"text": hex::encode(digest(label))}),
    }
}

const COMMITMENT: Fact = Fact::DigestHex("commitment");
const RECIPE: Fact = Fact::DigestHex("recipe");
const EVALUATED: Fact = Fact::Uint(NOW);

/// Named facts of one outcome.
type Facts = Vec<(&'static str, Fact)>;

/// An accepted vector: `(id, namespace, facts)`.
type Accepted = (&'static str, &'static str, Facts);

/// A refused vector: `(id, schema, signer seed, facts)`.
type Refused = (&'static str, &'static str, u8, Facts);

/// The facts every outcome carries, then `extra`.
fn facts(stage: &'static str, extra: &[(&'static str, Fact)]) -> Facts {
    let mut facts = vec![
        ("commitment", COMMITMENT),
        ("stage", Fact::Text(stage)),
        ("evaluated-at", EVALUATED),
        ("recipe-digest", RECIPE),
    ];
    facts.extend_from_slice(extra);
    facts
}

const COUNTERS: (&str, Fact) = ("counters-digest", Fact::Digest("counters"));
const HTTP_200: (&str, Fact) = ("http-status", Fact::Uint(200));
const RESPONSE: (&str, Fact) = ("response-digest", Fact::Digest("response"));
const BASIS: (&str, Fact) = ("relative-basis", Fact::Uint(1001));
const BASIS_DIGEST: (&str, Fact) = ("relative-basis-digest", Fact::Digest("basis-response"));
const EVIDENCE: (&str, Fact) = ("evidence-digest", Fact::Digest("evidence"));
const PRE_ENTRY: (&str, Fact) = ("pre-entry-digest", Fact::Digest("pre-entry"));

fn refusal(code: &'static str) -> (&'static str, Fact) {
    ("refusal", Fact::Text(code))
}

fn not_entered_and_unknown() -> Vec<Accepted> {
    vec![
        (
            "not-entered-exhausted",
            "stripe-refunds",
            facts("not-entered", &[refusal("gateway.policy.window-exhausted")]),
        ),
        (
            "not-entered-after-claim",
            "stripe-refunds",
            facts(
                "not-entered",
                &[COUNTERS, refusal("gateway.credential.account-mismatch")],
            ),
        ),
        (
            "not-entered-relative-ceiling-above",
            "stripe-refunds",
            facts(
                "not-entered",
                &[
                    COUNTERS,
                    refusal("gateway.relative-ceiling.above"),
                    BASIS,
                    BASIS_DIGEST,
                ],
            ),
        ),
        (
            "not-entered-pre-entry-condition-false",
            "airtable-demo",
            facts(
                "not-entered",
                &[PRE_ENTRY, refusal("gateway.pre-entry.condition-false")],
            ),
        ),
        (
            "unknown",
            "stripe-refunds",
            facts("unknown", &[COUNTERS, BASIS, BASIS_DIGEST]),
        ),
        (
            "unknown-without-counters",
            "airtable-demo",
            facts("unknown", &[]),
        ),
    ]
}

fn recorded_and_observed() -> Vec<Accepted> {
    vec![
        (
            "response-recorded",
            "stripe-refunds",
            facts(
                "response-recorded",
                &[COUNTERS, HTTP_200, RESPONSE, BASIS, BASIS_DIGEST],
            ),
        ),
        (
            "response-recorded-provider-rejected",
            "stripe-refunds",
            facts(
                "response-recorded",
                &[
                    COUNTERS,
                    ("http-status", Fact::Uint(400)),
                    RESPONSE,
                    BASIS,
                    BASIS_DIGEST,
                ],
            ),
        ),
        (
            "observed-match",
            "airtable-demo",
            facts(
                "observed",
                &[HTTP_200, RESPONSE, ("observation", Fact::Text("match"))],
            ),
        ),
        (
            "observed-mismatch",
            "airtable-demo",
            facts(
                "observed",
                &[HTTP_200, RESPONSE, ("observation", Fact::Text("mismatch"))],
            ),
        ),
        (
            "observed-echo-mismatch",
            "airtable-demo",
            facts(
                "observed",
                &[
                    HTTP_200,
                    RESPONSE,
                    ("observation", Fact::Text("echo-mismatch")),
                ],
            ),
        ),
        (
            "observed-by-provider-after-response",
            "stripe-refunds",
            facts(
                "observed-by-provider",
                &[COUNTERS, HTTP_200, RESPONSE, EVIDENCE, BASIS, BASIS_DIGEST],
            ),
        ),
        (
            "observed-by-provider-after-unknown",
            "airtable-demo",
            facts("observed-by-provider", &[EVIDENCE]),
        ),
        (
            "observed-by-provider-with-pre-entry",
            "airtable-demo",
            facts(
                "observed-by-provider",
                &[HTTP_200, RESPONSE, EVIDENCE, PRE_ENTRY],
            ),
        ),
    ]
}

fn refused() -> Vec<Refused> {
    let recorded = |extra: &[(&'static str, Fact)]| facts("response-recorded", extra);
    vec![
        (
            "outcome-v1-schema",
            "auths.gateway-outcome/1",
            OBSERVER_SEED,
            recorded(&[HTTP_200, RESPONSE]),
        ),
        (
            "http-status-without-response-digest",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[HTTP_200]),
        ),
        (
            "refusal-on-response-recorded",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[HTTP_200, RESPONSE, refusal("gateway.transport.not-entered")]),
        ),
        (
            "not-entered-without-refusal",
            OUTCOME_V2,
            OBSERVER_SEED,
            facts("not-entered", &[]),
        ),
        (
            "observation-on-response-recorded",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[HTTP_200, RESPONSE, ("observation", Fact::Text("match"))]),
        ),
        (
            "observed-without-observation",
            OUTCOME_V2,
            OBSERVER_SEED,
            facts("observed", &[HTTP_200, RESPONSE]),
        ),
        (
            "evidence-digest-on-observed",
            OUTCOME_V2,
            OBSERVER_SEED,
            facts(
                "observed",
                &[
                    HTTP_200,
                    RESPONSE,
                    ("observation", Fact::Text("match")),
                    EVIDENCE,
                ],
            ),
        ),
        (
            "relative-basis-2-pow-53",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[
                HTTP_200,
                RESPONSE,
                ("relative-basis", Fact::Uint(1 << 53)),
                BASIS_DIGEST,
            ]),
        ),
        (
            "relative-basis-digest-without-basis",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[HTTP_200, RESPONSE, BASIS_DIGEST]),
        ),
        (
            "http-status-99",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[("http-status", Fact::Uint(99)), RESPONSE]),
        ),
        (
            "stage-attempting",
            OUTCOME_V2,
            OBSERVER_SEED,
            facts("attempting", &[]),
        ),
        (
            "unregistered-fact",
            OUTCOME_V2,
            OBSERVER_SEED,
            recorded(&[
                HTTP_200,
                RESPONSE,
                ("provider-status", Fact::Text("succeeded")),
            ]),
        ),
        (
            "other-signer",
            OUTCOME_V2,
            OTHER_SEED,
            recorded(&[HTTP_200, RESPONSE]),
        ),
    ]
}

fn signed(
    seed: u8,
    schema: &str,
    namespace: &str,
    id: &str,
    facts: &[(&'static str, Fact)],
) -> Value {
    let observer = GatewayObserver::from_test_seed(seed);
    let subject = format!("auths-gateway://{namespace}/operations/{id}");
    let observation_facts = facts
        .iter()
        .map(|(name, fact)| {
            ObservationFact::new(FactName::parse(name).expect("fact name"), fact_value(*fact))
        })
        .collect();
    let signed = observer
        .sign(schema, &subject, OBSERVED_AT, observation_facts)
        .expect("signed outcome");
    let mut expected = Map::new();
    for (name, fact) in facts {
        expected.insert((*name).to_owned(), fact_json(*fact));
    }
    json!({
        "id": id,
        "schema": schema,
        "subject": subject,
        "facts": expected,
        "observation_b64": Base64::encode_string(signed.bytes()),
    })
}

const ROOT_SEED: u8 = 0x11;
const AGENT_SEED: u8 = 0x22;
/// The verifier's clock for every verdict case: one second after signing.
const VERDICT_AT: u64 = OBSERVED_AT + 1;

/// The packaged verifier configuration the Python and TypeScript SDKs
/// verify under.
fn packaged_registries<R>(use_registries: impl FnOnce(&ImmutableRegistries<'_>) -> R) -> R {
    let raw_key = auths_raw_key::RawKeyMethod::new().expect("raw key");
    let did_key = auths_did_key::DidKeyMethod::new().expect("did:key");
    let did_keri = auths_did_keri::DidKeriMethod::new().expect("did:keri");
    let ed25519 = auths_signature::Ed25519Suite::new().expect("ed25519");
    let p256 = auths_signature::P256Sha256Suite::new().expect("p256");
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).expect("packaged registries");
    use_registries(&registries)
}

/// Trust compiled as the SDKs compile it, pinned to the packaged
/// configuration and bound to the verdict clock, whose observer anchor for
/// the vector observer covers both vector namespaces.
fn verdict_context(root: &Signer, observer: &GatewayObserver) -> Vec<u8> {
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "the method path cannot name the registries' own lifetime"
    )]
    let configuration = packaged_registries(|registries| registries.configuration_id());
    let unbound = h::call(&serde_json::Map::new()).expect("call");
    let assurance = AssurancePolicyId::parse(h::ASSURANCE).expect("assurance");
    let trust = TrustAnchor::new(
        TrustAnchorId::parse("root").expect("anchor ID"),
        root.principal.clone(),
        vec![PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1).expect("method")],
        vec![unbound.profile_ref().expect("profile")],
        PermissionSet::new(vec![unbound.permission().expect("permission")]).expect("permissions"),
        vec![ResourceId::parse(&format!("mcp://{}/", h::SERVICE)).expect("namespace")],
        AudienceSet::new(vec![h::audience().expect("audience")]).expect("audiences"),
        h::window(NOW - 86_400, NOW + 86_400).expect("window"),
        None,
        1,
        assurance.clone(),
        StatusPolicy::ExpiryOnly,
    )
    .expect("trust anchor");
    let anchor = ObserverAnchor::new(
        ObserverAnchorId::parse(h::ANCHOR).expect("anchor ID"),
        observer.principal().clone(),
        vec![PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1).expect("method")],
        vec![ObservationSchemaId::parse(OUTCOME_V2).expect("schema")],
        ["stripe-refunds", "airtable-demo"]
            .iter()
            .map(|namespace| {
                ResourceId::parse(&format!("auths-gateway://{namespace}/operations/"))
                    .expect("namespace")
            })
            .collect(),
        h::window(NOW - 86_400, NOW + 86_400).expect("window"),
    )
    .expect("observer anchor");
    let template = auths_sdk::TrustedContextBuilder::new(
        configuration,
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        vec![trust],
        AssurancePolicy::new(
            assurance,
            [ParticipantRole::Root, ParticipantRole::Actor]
                .into_iter()
                .flat_map(|role| {
                    ["self-certifying-identifier", "offline-verifiable"]
                        .into_iter()
                        .map(move |claim| {
                            AssuranceRequirement::new(
                                role,
                                AssuranceQuantifier::Every,
                                AssuranceClaimId::parse(claim).expect("claim"),
                                None,
                            )
                        })
                })
                .collect(),
        )
        .expect("assurance policy"),
    )
    .expect("builder")
    .accept_evidence_type(EvidenceTypeId::parse(auths_raw_key::RAW_KEY_V1).expect("evidence"))
    .accept_critical_extension(
        ExtensionId::parse(auths_registries::OBSERVATION_REQUIREMENT_EXTENSION_V1)
            .expect("extension"),
    )
    .build()
    .expect("SDK template")
    .with_observer_anchors(vec![anchor])
    .expect("observer anchors");
    let context = template
        .for_request(
            h::audience().expect("audience"),
            Challenge::new([0; 32]),
            Timestamp::new(VERDICT_AT),
        )
        .expect("bound context");
    auths_codec::encode_verifier_context(&context).expect("context bytes")
}

/// The grant requirement every verdict case carries: the outcome of
/// `subject`, at most an hour old, in stage `observed-by-provider`.
fn stage_requirement(subject: &str) -> ObservationRequirement {
    ObservationRequirement::new(
        ObserverAnchorId::parse(h::ANCHOR).expect("anchor"),
        ObservationSchemaId::parse(OUTCOME_V2).expect("schema"),
        ObservationSubject::Resource(ResourceId::parse(subject).expect("subject")),
        3_600,
        vec![ObservationCondition::new(
            FactName::parse("stage").expect("fact name"),
            ConditionTest::Member(
                MemberValues::new(vec![FactValue::Text(
                    FactText::new("observed-by-provider").expect("text"),
                )])
                .expect("members"),
            ),
        )],
    )
    .expect("requirement")
}

/// One verdict case over the vector `entry`: its exact observation bytes
/// attached to an action whose grant requires its subject's outcome in stage
/// `observed-by-provider`.
fn verdict(entry: &Value, context: &[u8], root: &Signer, agent: &Signer) -> Value {
    let id = entry["id"].as_str().expect("id");
    let subject = entry["subject"].as_str().expect("subject");
    let observation =
        Base64::decode_vec(entry["observation_b64"].as_str().expect("bytes")).expect("base64");
    let grant = h::grant(
        root,
        &agent.principal,
        Some(stage_requirement(subject)),
        NOW,
    )
    .expect("grant");
    let arguments = json!({"operation_id": format!("verdict-{id}")})
        .as_object()
        .expect("arguments")
        .clone();
    let submission =
        crate::observed_tests::submission(root, agent, &grant, &arguments, &[observation]);
    let (decision, code) = packaged_registries(|registries| {
        let sealed = auths_verifier::verify_v1_sealed(
            &submission.proof,
            &submission.action,
            context,
            registries,
        )
        .expect("verifiable input");
        let decision = match sealed.portable().decision() {
            auths_model::VerificationDecision::Authorized => "authorized",
            auths_model::VerificationDecision::Denied => "denied",
            auths_model::VerificationDecision::Indeterminate => "indeterminate",
        };
        (decision, sealed.portable().code().code().to_owned())
    });
    json!({
        "id": id,
        "proof_b64": Base64UrlUnpadded::encode_string(&submission.proof),
        "action_b64": Base64UrlUnpadded::encode_string(&submission.action),
        "decision": decision,
        "code": code,
    })
}

fn document() -> Value {
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let accepted: Vec<Value> = [not_entered_and_unknown(), recorded_and_observed()]
        .concat()
        .iter()
        .map(|(id, namespace, facts)| signed(OBSERVER_SEED, OUTCOME_V2, namespace, id, facts))
        .collect();
    let refused: Vec<Value> = refused()
        .iter()
        .map(|(id, schema, seed, facts)| {
            let mut entry = signed(*seed, schema, "stripe-refunds", id, facts);
            entry["code"] = json!("audit.outcome-invalid");
            entry
        })
        .collect();
    let root = Signer::new(ROOT_SEED);
    let agent = Signer::new(AGENT_SEED);
    let context = verdict_context(&root, &observer);
    let verdicts: Vec<Value> = accepted
        .iter()
        .chain(refused.iter().filter(|entry| {
            matches!(
                entry["id"].as_str(),
                Some("other-signer" | "outcome-v1-schema")
            )
        }))
        .map(|entry| verdict(entry, &context, &root, &agent))
        .collect();
    json!({
        "schema": SCHEMA,
        "outcome_schema": OUTCOME_V2,
        "observer": {"seed_byte": OBSERVER_SEED, "principal": observer.principal().as_str()},
        "observed_at": OBSERVED_AT,
        "accepted": accepted,
        "refused": refused,
        "verdict_trusted_context_b64": Base64UrlUnpadded::encode_string(&context),
        "verdicts": verdicts,
    })
}

#[test]
fn outcome_v2_vectors_are_current() {
    require_current(FILE, &document());
}

fn pinned_observer(vectors: &Value) -> auths_model::PrincipalId {
    auths_model::PrincipalId::parse(
        vectors["observer"]["principal"]
            .as_str()
            .expect("principal"),
    )
    .expect("observer")
}

/// The outcome verifier accepts every accepted vector with exactly its
/// expected facts, and refuses every refused vector with its code.
#[test]
fn outcome_verifier_accepts_every_vector_with_its_facts_and_refuses_the_rest() {
    let vectors = load(FILE);
    let observer = pinned_observer(&vectors);
    let accepted = vectors["accepted"].as_array().expect("accepted");
    assert!(!accepted.is_empty());
    for entry in accepted {
        let bytes =
            Base64::decode_vec(entry["observation_b64"].as_str().expect("bytes")).expect("base64");
        let verified = crate::observer::verify_outcome(&bytes, &observer)
            .unwrap_or_else(|code| panic!("{}: {code}", entry["id"]));
        assert_eq!(verified.subject, entry["subject"], "{}", entry["id"]);
        assert_eq!(verified.observed_at, OBSERVED_AT);
        let facts = crate::observer::outcome_record_json(&verified.record);
        assert_eq!(Value::Object(facts), entry["facts"], "{}", entry["id"]);
        let signed = crate::observer::OutcomeRecord::facts(&verified.record).expect("facts");
        let resigned = GatewayObserver::from_test_seed(OBSERVER_SEED)
            .sign(OUTCOME_V2, &verified.subject, OBSERVED_AT, signed)
            .expect("re-signed");
        assert_eq!(resigned.bytes(), bytes.as_slice(), "{}", entry["id"]);
    }
    for entry in vectors["refused"].as_array().expect("refused") {
        let bytes =
            Base64::decode_vec(entry["observation_b64"].as_str().expect("bytes")).expect("base64");
        assert_eq!(
            crate::observer::verify_outcome(&bytes, &observer).err(),
            entry["code"].as_str(),
            "{}",
            entry["id"]
        );
    }
}

/// Every verdict case is authorized exactly when its outcome is signed by
/// the anchored observer in stage `observed-by-provider`.
#[test]
fn outcome_verdicts_follow_the_stage_condition() {
    let vectors = load(FILE);
    let accepted = vectors["accepted"].as_array().expect("accepted");
    let verdicts = vectors["verdicts"].as_array().expect("verdicts");
    assert_eq!(verdicts.len(), accepted.len() + 2);
    for case in verdicts {
        let id = case["id"].as_str().expect("id");
        let provider_bound = accepted.iter().any(|entry| {
            entry["id"] == id && entry["facts"]["stage"]["text"] == "observed-by-provider"
        });
        assert_eq!(
            case["decision"] == "authorized",
            provider_bound,
            "{id}: {case}"
        );
    }
}
