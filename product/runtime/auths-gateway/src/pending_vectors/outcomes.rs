//! Signed outcome `/2` vectors: for each stage and fact combination, the
//! canonical observation signed by a fixed test observer and its expected
//! facts, plus refused vectors that break the presence rule, the schema, or
//! the signer.
//!
//! Digest facts are fixed test bytes derived from their labels; they are not
//! recomputed from a store, because these vectors pin the signed encoding
//! and the presence rule, not a gateway run.

use super::{NOW, load, require_current};
use crate::GatewayObserver;
use auths_model::{FactBytes, FactName, FactText, FactValue, ObservationFact};
use base64ct::{Base64, Encoding as _};
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
    json!({
        "schema": SCHEMA,
        "outcome_schema": OUTCOME_V2,
        "observer": {"seed_byte": OBSERVER_SEED, "principal": observer.principal().as_str()},
        "observed_at": OBSERVED_AT,
        "accepted": accepted,
        "refused": refused,
    })
}

#[test]
fn outcome_v2_vectors_are_current() {
    require_current(FILE, &document());
}

/// Today's outcome verifier reads only `/1`, so it refuses every outcome
/// `/2` vector that the revised verifier must accept.
#[test]
fn current_outcome_verifier_refuses_every_outcome_v2() {
    let vectors = load(FILE);
    let observer = auths_model::PrincipalId::parse(
        vectors["observer"]["principal"]
            .as_str()
            .expect("principal"),
    )
    .expect("observer");
    let accepted = vectors["accepted"].as_array().expect("accepted");
    assert!(!accepted.is_empty());
    for entry in accepted {
        let bytes =
            Base64::decode_vec(entry["observation_b64"].as_str().expect("bytes")).expect("base64");
        assert_eq!(
            crate::observer::verify_outcome(&bytes, &observer),
            Err("audit.outcome-invalid"),
            "{}",
            entry["id"]
        );
    }
}
