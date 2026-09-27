//! One spend limit: count and sum cases for evaluator `/2` and policy `/2`,
//! run through both stores.
//!
//! Grants form chains from the root's grant to the actor's. Each grant's
//! policy is given as members and as its canonical CBOR. Submissions run in
//! order, each with a fresh logical operation ID, and every refused
//! submission leases nothing and enters nothing. Slot tables list the
//! counters of the case's subjects after the last submission, zero included.

use super::{NOW, keys, load, recipes, require_current};
use minicbor::Encoder;
use serde_json::{Value, json};

pub(super) const FILE: &str = "bounds-aggregate.json";
const SCHEMA: &str = "auths.gateway-bounds-aggregate/1";
const EVALUATOR_V2: &str = "auths.gateway.argument-ceiling-window-count/2";
const POLICY_V2: &str = "auths.gateway.argument-ceiling-policy/2";
const EVALUATOR_V1: &str = "auths.gateway.argument-ceiling-window-count/1";
const POLICY_V1: &str = "auths.gateway.argument-ceiling-policy/1";
const WINDOW: u64 = 86_400;
const WINDOW_INDEX: u64 = NOW / WINDOW;
const WINDOW_END: u64 = (WINDOW_INDEX + 1) * WINDOW;
const ACCOUNT_1: &str = "acct_TESTACCOUNT01";
const ACCOUNT_2: &str = "acct_TESTACCOUNT02";

/// Named principals and their fixed Ed25519 seed bytes.
const PRINCIPALS: [(&str, u8); 4] = [
    ("root", 0x61),
    ("parent", 0x62),
    ("child-a", 0x63),
    ("child-b", 0x64),
];

#[derive(Clone, Copy)]
struct Policy {
    ceiling: u64,
    count: u64,
    sum: Option<u64>,
    partition: Option<(&'static str, &'static [&'static str])>,
    scope: Option<(&'static str, &'static [&'static str])>,
}

const fn count(ceiling: u64, count: u64) -> Policy {
    Policy {
        ceiling,
        count,
        sum: None,
        partition: None,
        scope: None,
    }
}

const USD: &[&str] = &["usd"];
const EUR_USD: &[&str] = &["eur", "usd"];

const fn sum(ceiling: u64, count: u64, limit: u64, values: &'static [&'static str]) -> Policy {
    Policy {
        ceiling,
        count,
        sum: Some(limit),
        partition: Some(("currency", values)),
        scope: None,
    }
}

fn values_cbor(encoder: &mut Encoder<Vec<u8>>, argument: &str, values: &[&str]) {
    encoder
        .map(2)
        .expect("map")
        .u8(0)
        .expect("key")
        .str(argument)
        .expect("argument");
    encoder
        .u8(1)
        .expect("key")
        .array(values.len() as u64)
        .expect("array");
    for value in values {
        encoder.str(value).expect("value");
    }
}

/// Canonical CBOR of policy `/2`: members 0–3 as in `/1`, then the optional
/// sum limit, partition, and scope under keys 4, 5, and 6.
fn policy_cbor(policy: &Policy) -> Vec<u8> {
    let members = 4
        + u64::from(policy.sum.is_some())
        + u64::from(policy.partition.is_some())
        + u64::from(policy.scope.is_some());
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(members).expect("map");
    encoder.u8(0).expect("key").str("amount").expect("argument");
    encoder
        .u8(1)
        .expect("key")
        .u64(policy.ceiling)
        .expect("ceiling");
    encoder.u8(2).expect("key").u64(WINDOW).expect("window");
    encoder
        .u8(3)
        .expect("key")
        .u64(policy.count)
        .expect("count");
    if let Some(limit) = policy.sum {
        encoder.u8(4).expect("key").u64(limit).expect("sum");
    }
    if let Some((argument, values)) = policy.partition {
        encoder.u8(5).expect("key");
        values_cbor(&mut encoder, argument, values);
    }
    if let Some((argument, values)) = policy.scope {
        encoder.u8(6).expect("key");
        values_cbor(&mut encoder, argument, values);
    }
    encoder.into_writer()
}

fn policy_json(policy: &Policy) -> Value {
    let mut members = json!({"argument": "amount", "ceiling": policy.ceiling, "window_seconds": WINDOW,
        "max_count": policy.count});
    if let Some(limit) = policy.sum {
        members["sum_limit"] = json!(limit);
    }
    if let Some((argument, values)) = policy.partition {
        members["partition"] = json!({"argument": argument, "values": values});
    }
    if let Some((argument, values)) = policy.scope {
        members["scope"] = json!({"argument": argument, "values": values});
    }
    members
}

fn grant_with(
    id: &str,
    subject: &str,
    parent: Option<(&str, &str)>,
    policy: Option<&Policy>,
    identities: (&str, &str),
) -> Value {
    let (issuer, parent) = parent.map_or(("root", None), |(issuer, grant)| (issuer, Some(grant)));
    let mut grant = json!({"id": id, "issuer": issuer, "subject": subject, "parent": parent});
    if let Some(policy) = policy {
        grant["evaluator"] = json!(identities.0);
        grant["policy_type"] = json!(identities.1);
        grant["policy"] = policy_json(policy);
        grant["policy_cbor_hex"] = json!(hex::encode(policy_cbor(policy)));
    } else {
        grant["policy"] = Value::Null;
    }
    grant
}

/// A grant to `subject`, from the root or, under `parent`, from that grant's
/// subject.
fn grant(id: &str, subject: &str, parent: Option<(&str, &str)>, policy: &Policy) -> Value {
    grant_with(id, subject, parent, Some(policy), (EVALUATOR_V2, POLICY_V2))
}

fn submission(grant: &str, arguments: Value, at: u64, code: Option<&str>, stored: bool) -> Value {
    let mut entry = json!({"grant": grant, "at": at});
    entry["arguments"] = arguments;
    entry["decision"] = json!(if code.is_some() {
        "not-entered"
    } else {
        "entered"
    });
    entry["code"] = json!(code);
    entry["stored"] = json!(stored);
    entry
}

fn amount(value: u64) -> Value {
    json!({"amount": value})
}

fn in_currency(value: u64, currency: &str) -> Value {
    let intent = if currency == "eur" {
        "pi_TEST0000000002"
    } else {
        "pi_TEST0000000001"
    };
    json!({"amount": value, "currency": currency, "payment_intent": intent})
}

fn entered(grant: &str, arguments: Value) -> Value {
    submission(grant, arguments, NOW, None, true)
}

fn exhausted(grant: &str, arguments: Value, code: &str) -> Value {
    submission(grant, arguments, NOW, Some(code), true)
}

fn refused(grant: &str, arguments: Value, code: &str) -> Value {
    submission(grant, arguments, NOW, Some(code), false)
}

fn count_slots(entries: &[(&str, u64)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(subject, slots)| json!({"subject": subject, "window_index": WINDOW_INDEX, "slots": slots}))
            .collect(),
    )
}

fn sum_slots(entries: &[(&str, Option<&str>, u64)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(subject, partition, cumulative)| {
                json!({"subject": subject, "partition": partition, "window_index": WINDOW_INDEX,
                    "cumulative": cumulative})
            })
            .collect(),
    )
}

fn case(
    id: &str,
    recipe: &str,
    grants: Vec<Value>,
    submissions: Vec<Value>,
    slots: (Value, Value),
) -> Value {
    let entries = submissions
        .iter()
        .filter(|submission| submission["decision"] == "entered")
        .count();
    let mut case = json!({"id": id, "recipe": recipe});
    case["grants"] = Value::Array(grants);
    case["submissions"] = Value::Array(submissions);
    case["count_slots"] = slots.0;
    case["sum_slots"] = slots.1;
    case["provider_entries"] = json!(entries);
    case
}

const EXHAUSTED: &str = "gateway.policy.window-exhausted";
const SUM_EXHAUSTED: &str = "gateway.policy.sum-exhausted";
const EXPANDED: &str = "gateway.policy.expanded";
const SUM_REQUIRED: &str = "gateway.policy.sum-required";

fn parent(policy: &Policy) -> Value {
    grant("g-parent", "parent", None, policy)
}

fn child(id: &str, subject: &str, policy: &Policy) -> Value {
    grant(id, subject, Some(("parent", "g-parent")), policy)
}

fn delegation_count_cases() -> Vec<Value> {
    let none = json!([]);
    vec![
        case(
            "siblings-exceed-parent-count",
            "stripe-plain",
            vec![
                parent(&count(1000, 2)),
                child("g-a", "child-a", &count(1000, 2)),
                child("g-b", "child-b", &count(1000, 2)),
            ],
            vec![
                entered("g-a", amount(100)),
                entered("g-b", amount(100)),
                exhausted("g-a", amount(100), EXHAUSTED),
            ],
            (
                count_slots(&[("parent", 2), ("child-a", 1), ("child-b", 1)]),
                none.clone(),
            ),
        ),
        case(
            "parent-and-child-share-counter",
            "stripe-plain",
            vec![
                parent(&count(1000, 2)),
                child("g-a", "child-a", &count(1000, 5)),
            ],
            vec![
                entered("g-parent", amount(100)),
                entered("g-a", amount(100)),
                exhausted("g-parent", amount(100), EXHAUSTED),
            ],
            (count_slots(&[("parent", 2), ("child-a", 1)]), none.clone()),
        ),
        case(
            "self-delegation-other-method",
            "stripe-plain",
            vec![
                parent(&count(1000, 1)),
                child("g-self", "parent-did-key", &count(1000, 5)),
            ],
            vec![
                entered("g-self", amount(100)),
                exhausted("g-self", amount(100), EXHAUSTED),
                exhausted("g-parent", amount(100), EXHAUSTED),
            ],
            (
                count_slots(&[("parent", 1), ("parent-did-key", 1)]),
                none.clone(),
            ),
        ),
        case(
            "exhausted-ancestor-consumes-no-descendant-slot",
            "stripe-plain",
            vec![
                parent(&count(1000, 1)),
                child("g-a", "child-a", &count(1000, 5)),
            ],
            vec![
                entered("g-parent", amount(100)),
                exhausted("g-a", amount(100), EXHAUSTED),
            ],
            (count_slots(&[("parent", 1), ("child-a", 0)]), none),
        ),
    ]
}

fn window_and_registry_cases() -> Vec<Value> {
    let none = json!([]);
    vec![
        case(
            "burst-across-window-boundary",
            "stripe-plain",
            vec![parent(&count(1000, 2))],
            vec![
                submission("g-parent", amount(100), WINDOW_END - 2, None, true),
                submission("g-parent", amount(100), WINDOW_END - 1, None, true),
                submission("g-parent", amount(100), WINDOW_END, None, true),
                submission("g-parent", amount(100), WINDOW_END + 1, None, true),
                submission(
                    "g-parent",
                    amount(100),
                    WINDOW_END + 2,
                    Some(EXHAUSTED),
                    true,
                ),
            ],
            (
                json!([{"subject": "parent", "window_index": WINDOW_INDEX, "slots": 2},
                {"subject": "parent", "window_index": WINDOW_INDEX + 1, "slots": 2}]),
                none.clone(),
            ),
        ),
        case(
            "evaluator-v1-refused",
            "stripe-plain",
            vec![grant_with(
                "g-parent",
                "parent",
                None,
                Some(&count(1000, 2)),
                (EVALUATOR_V1, POLICY_V2),
            )],
            vec![refused(
                "g-parent",
                amount(100),
                "gateway.policy.evaluator-unregistered",
            )],
            (count_slots(&[("parent", 0)]), none.clone()),
        ),
        case(
            "policy-type-v1-refused",
            "stripe-plain",
            vec![grant_with(
                "g-parent",
                "parent",
                None,
                Some(&count(1000, 2)),
                (EVALUATOR_V2, POLICY_V1),
            )],
            vec![refused(
                "g-parent",
                amount(100),
                "gateway.policy.evaluator-mismatch",
            )],
            (count_slots(&[("parent", 0)]), none),
        ),
    ]
}

/// A chain of `links` bounded grants from the root through `agent-01` to
/// `agent-<links>`.
fn long_chain(id: &str, links: usize, code: Option<&str>) -> Value {
    let grants: Vec<Value> = (1..=links)
        .map(|index| {
            let parent = (index > 1).then(|| {
                (
                    format!("agent-{:02}", index - 1),
                    format!("g-{:02}", index - 1),
                )
            });
            grant(
                &format!("g-{index:02}"),
                &format!("agent-{index:02}"),
                parent
                    .as_ref()
                    .map(|(issuer, grant)| (issuer.as_str(), grant.as_str())),
                &count(1000, 5),
            )
        })
        .collect();
    let terminal = format!("g-{links:02}");
    let (submission, slots) = match code {
        Some(code) => (refused(&terminal, amount(100), code), 0),
        None => (entered(&terminal, amount(100)), 1),
    };
    let subjects: Vec<String> = (1..=links)
        .map(|index| format!("agent-{index:02}"))
        .collect();
    let table: Vec<(&str, u64)> = subjects
        .iter()
        .map(|subject| (subject.as_str(), slots))
        .collect();
    case(
        id,
        "stripe-plain",
        grants,
        vec![submission],
        (count_slots(&table), json!([])),
    )
}

fn race_and_audit_cases() -> Vec<Value> {
    let parent = grant("g-parent", "parent", None, &count(1000, 3));
    let mut count_race = case(
        "race-last-count-slots",
        "stripe-plain",
        vec![parent],
        vec![entered("g-parent", amount(100))],
        (count_slots(&[("parent", 3)]), json!([])),
    );
    count_race["race"] = json!({"store": "postgresql", "processes": 2,
        "concurrent": [{"process": 0, "grant": "g-parent", "arguments": amount(100)},
            {"process": 0, "grant": "g-parent", "arguments": amount(100)},
            {"process": 1, "grant": "g-parent", "arguments": amount(100)},
            {"process": 1, "grant": "g-parent", "arguments": amount(100)}],
        "admitted": 2, "refused": {"count": 2, "code": EXHAUSTED}});
    count_race["provider_entries"] = json!(3);
    let sum_parent = grant("g-parent", "parent", None, &sum(1000, 20, 1000, USD));
    let mut sum_race = case(
        "race-last-sum-units",
        "stripe-platform",
        vec![sum_parent],
        vec![entered("g-parent", in_currency(800, "usd"))],
        (
            count_slots(&[("parent", 3)]),
            sum_slots(&[("parent", Some("usd"), 1000)]),
        ),
    );
    sum_race["race"] = json!({"store": "postgresql", "processes": 2,
        "concurrent": [{"process": 0, "grant": "g-parent", "arguments": in_currency(100, "usd")},
            {"process": 0, "grant": "g-parent", "arguments": in_currency(100, "usd")},
            {"process": 1, "grant": "g-parent", "arguments": in_currency(100, "usd")},
            {"process": 1, "grant": "g-parent", "arguments": in_currency(100, "usd")}],
        "admitted": 2, "refused": {"count": 2, "code": SUM_EXHAUSTED}});
    sum_race["provider_entries"] = json!(3);
    let audit = |id: &str, counter: &str, entries: Value, verdicts: Value| {
        json!({"id": id, "audit": {"counter": counter, "entries": entries, "verdicts": verdicts,
            "orders": "every permutation of the entries yields the same verdicts"}})
    };
    let verified = |id: &str| json!({"id": id, "status": "verified", "code": null});
    let inconsistent =
        |id: &str, code: &str| json!({"id": id, "status": "inconsistent", "code": code});
    vec![
        count_race,
        sum_race,
        audit(
            "audit-count-capacity-three-and-one",
            "count",
            json!([{"id": "e1", "capacity": 3}, {"id": "e2", "capacity": 1}, {"id": "e3", "capacity": 1}]),
            json!([
                verified("e1"),
                inconsistent("e2", "audit.bound-exceeded"),
                inconsistent("e3", "audit.bound-exceeded")
            ]),
        ),
        audit(
            "audit-count-valid-every-order",
            "count",
            json!([{"id": "e1", "capacity": 3}, {"id": "e2", "capacity": 3}, {"id": "e3", "capacity": 1}]),
            json!([verified("e1"), verified("e2"), verified("e3")]),
        ),
        audit(
            "audit-sum-exceeded",
            "sum",
            json!([{"id": "e1", "capacity": 500, "argument": 400}, {"id": "e2", "capacity": 500, "argument": 300}]),
            json!([
                inconsistent("e1", "audit.sum-exceeded"),
                inconsistent("e2", "audit.sum-exceeded")
            ]),
        ),
        audit(
            "audit-sum-valid-every-order",
            "sum",
            json!([{"id": "e1", "capacity": 1000, "argument": 400}, {"id": "e2", "capacity": 600, "argument": 300},
                {"id": "e3", "capacity": 1000, "argument": 300}]),
            json!([verified("e1"), verified("e2"), verified("e3")]),
        ),
    ]
}

fn sum_cases() -> Vec<Value> {
    let usd = |value| in_currency(value, "usd");
    vec![
        case(
            "siblings-exceed-parent-sum",
            "stripe-platform",
            vec![
                parent(&sum(1000, 10, 1000, USD)),
                child("g-a", "child-a", &sum(1000, 10, 800, USD)),
                child("g-b", "child-b", &sum(1000, 10, 800, USD)),
            ],
            vec![
                entered("g-a", usd(600)),
                exhausted("g-b", usd(500), SUM_EXHAUSTED),
            ],
            (
                count_slots(&[("parent", 1), ("child-a", 1), ("child-b", 0)]),
                sum_slots(&[
                    ("parent", Some("usd"), 600),
                    ("child-a", Some("usd"), 600),
                    ("child-b", Some("usd"), 0),
                ]),
            ),
        ),
        case(
            "sum-argument-equals-remaining",
            "stripe-platform",
            vec![parent(&sum(1000, 10, 1000, USD))],
            vec![
                entered("g-parent", usd(400)),
                exhausted("g-parent", usd(601), SUM_EXHAUSTED),
                entered("g-parent", usd(600)),
            ],
            (
                count_slots(&[("parent", 2)]),
                sum_slots(&[("parent", Some("usd"), 1000)]),
            ),
        ),
        case(
            "partition-values-counted-separately",
            "stripe-platform",
            vec![parent(&sum(1000, 10, 1000, EUR_USD))],
            vec![
                entered("g-parent", usd(1000)),
                entered("g-parent", in_currency(1000, "eur")),
            ],
            (
                count_slots(&[("parent", 2)]),
                sum_slots(&[("parent", Some("eur"), 1000), ("parent", Some("usd"), 1000)]),
            ),
        ),
        case(
            "partition-value-not-listed",
            "stripe-platform",
            vec![parent(&sum(1000, 10, 1000, EUR_USD))],
            vec![refused(
                "g-parent",
                in_currency(100, "gbp"),
                "gateway.policy.partition-denied",
            )],
            (count_slots(&[("parent", 0)]), sum_slots(&[])),
        ),
        case(
            "exhausted-ancestor-sum-consumes-no-descendant-slot",
            "stripe-platform",
            vec![
                parent(&sum(1000, 10, 500, USD)),
                child("g-a", "child-a", &sum(1000, 10, 500, USD)),
            ],
            vec![
                entered("g-parent", usd(500)),
                exhausted("g-a", usd(100), SUM_EXHAUSTED),
            ],
            (
                count_slots(&[("parent", 1), ("child-a", 0)]),
                sum_slots(&[("parent", Some("usd"), 500), ("child-a", Some("usd"), 0)]),
            ),
        ),
        case(
            "argument-above-smallest-sum-limit",
            "stripe-platform",
            vec![
                parent(&sum(1000, 10, 1000, USD)),
                child("g-a", "child-a", &sum(1000, 10, 300, USD)),
            ],
            vec![refused("g-a", usd(301), "gateway.policy.above-sum-limit")],
            (
                count_slots(&[("parent", 0), ("child-a", 0)]),
                sum_slots(&[("parent", Some("usd"), 0), ("child-a", Some("usd"), 0)]),
            ),
        ),
    ]
}

fn unpartitioned(limit: u64) -> Policy {
    Policy {
        sum: Some(limit),
        ..count(1000, 10)
    }
}

fn zero_slots() -> (Value, Value) {
    (count_slots(&[("parent", 0), ("child-a", 0)]), json!([]))
}

fn tightening_cases() -> Vec<Value> {
    let by = |argument, values| Policy {
        partition: Some((argument, values)),
        ..unpartitioned(1000)
    };
    let scoped = |accounts| Policy {
        scope: Some(("connect_account", accounts)),
        ..sum(1000, 10, 1000, USD)
    };
    let stripe_arguments = json!({"amount": 100, "currency": "usd", "payment_intent": "pi_TEST0000000001",
        "connect_account": ACCOUNT_1});
    let usd = |value| in_currency(value, "usd");
    vec![
        case(
            "child-drops-parent-sum",
            "stripe-plain",
            vec![
                parent(&unpartitioned(1000)),
                child("g-a", "child-a", &count(1000, 10)),
            ],
            vec![refused("g-a", amount(100), EXPANDED)],
            zero_slots(),
        ),
        case(
            "child-changes-partition",
            "stripe-plain",
            vec![
                parent(&by("payment_intent", &["pi_TEST0000000001"])),
                child("g-a", "child-a", &by("operation_id", &["refund-1"])),
            ],
            vec![refused("g-a", amount(100), EXPANDED)],
            zero_slots(),
        ),
        case(
            "child-widens-partition-list",
            "stripe-platform",
            vec![
                parent(&sum(1000, 10, 1000, USD)),
                child("g-a", "child-a", &sum(1000, 10, 1000, EUR_USD)),
            ],
            vec![refused("g-a", usd(100), EXPANDED)],
            zero_slots(),
        ),
        case(
            "child-widens-scope-list",
            "stripe",
            vec![
                parent(&scoped(&[ACCOUNT_1])),
                child("g-a", "child-a", &scoped(&[ACCOUNT_1, ACCOUNT_2])),
            ],
            vec![refused("g-a", stripe_arguments, EXPANDED)],
            zero_slots(),
        ),
        case(
            "child-raises-sum-limit",
            "stripe-platform",
            vec![
                parent(&sum(1000, 10, 1000, USD)),
                child("g-a", "child-a", &sum(1000, 10, 2000, USD)),
            ],
            vec![refused("g-a", usd(100), EXPANDED)],
            zero_slots(),
        ),
        case(
            "child-adds-sum-under-parent-without",
            "stripe-plain",
            vec![
                parent(&count(1000, 10)),
                child("g-a", "child-a", &unpartitioned(500)),
            ],
            vec![entered("g-a", amount(100))],
            (
                count_slots(&[("parent", 1), ("child-a", 1)]),
                sum_slots(&[("child-a", None, 100)]),
            ),
        ),
    ]
}

fn requirement_cases() -> Vec<Value> {
    let usd = |value| in_currency(value, "usd");
    vec![
        case(
            "sum-required-unbounded-action",
            "stripe-platform",
            vec![grant_with(
                "g-parent",
                "parent",
                None,
                None,
                (EVALUATOR_V2, POLICY_V2),
            )],
            vec![refused("g-parent", usd(100), SUM_REQUIRED)],
            (count_slots(&[("parent", 0)]), json!([])),
        ),
        case(
            "sum-required-link-lacks-sum",
            "stripe-platform",
            vec![
                parent(&count(1000, 10)),
                child("g-a", "child-a", &sum(1000, 10, 500, USD)),
            ],
            vec![refused("g-a", usd(100), SUM_REQUIRED)],
            zero_slots(),
        ),
        case(
            "sum-required-partition-absent",
            "stripe-platform",
            vec![parent(&unpartitioned(1000))],
            vec![refused("g-parent", usd(100), SUM_REQUIRED)],
            (count_slots(&[("parent", 0)]), json!([])),
        ),
    ]
}

fn principals() -> Value {
    let mut table = serde_json::Map::new();
    let mut add = |name: &str, seed: u8, method: &str| {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let entry = if method == "did-key-v1" {
            let principal = keys::did_key(keys::ED25519_MULTICODEC, &key);
            json!({"seed_byte": seed, "method": method, "multibase": keys::multibase(&principal)})
        } else {
            let principal = auths_raw_key::RawKeyDescriptor::new(
                auths_raw_key::RawKeyType::Ed25519,
                key.to_vec(),
            )
            .expect("raw key")
            .principal()
            .expect("principal");
            json!({"seed_byte": seed, "method": method, "principal": principal.as_str()})
        };
        table.insert(name.to_owned(), entry);
    };
    for (name, seed) in PRINCIPALS {
        add(name, seed, "raw-key-v1");
    }
    add("parent-did-key", 0x62, "did-key-v1");
    for index in 1..=17_u8 {
        add(&format!("agent-{index:02}"), 0x70 + index, "raw-key-v1");
    }
    Value::Object(table)
}

fn document() -> Value {
    let cases: Vec<Value> = [
        delegation_count_cases(),
        window_and_registry_cases(),
        vec![
            long_chain("sixteen-links-admitted", 16, None),
            long_chain(
                "seventeen-links-refused",
                17,
                Some("gateway.policy.too-many-bounds"),
            ),
        ],
        sum_cases(),
        tightening_cases(),
        requirement_cases(),
        race_and_audit_cases(),
    ]
    .concat();
    json!({
        "schema": SCHEMA,
        "evaluator": EVALUATOR_V2,
        "policy_type": POLICY_V2,
        "stores": ["file", "postgresql"],
        "recipes": recipes::FILE,
        "window_seconds": WINDOW,
        "evaluated_at": NOW,
        "window_index": WINDOW_INDEX,
        "window_end": WINDOW_END,
        "principals": principals(),
        "did_key_principal": "did:key:<multibase>",
        "operation_ids": "<case id>-<submission index>, counting from 0",
        "default_arguments": {
            "stripe-plain": {"payment_intent": "pi_TEST0000000001"},
            "stripe-platform": {"payment_intent": "pi_TEST0000000001", "currency": "usd"},
            "stripe": {"payment_intent": "pi_TEST0000000001", "currency": "usd", "connect_account": ACCOUNT_1}
        },
        "provider": {
            "answers": "the defaults of attempt-scenarios-v3.json for recipe stripe",
            "payment_intents": [
                {"id": "pi_TEST0000000001", "currency": "usd", "amount_received": 1_000_000},
                {"id": "pi_TEST0000000002", "currency": "eur", "amount_received": 1_000_000}
            ]
        },
        "cases": cases,
    })
}

#[test]
fn bounds_aggregate_vectors_are_current() {
    require_current(FILE, &document());
}

/// Today's registry holds only evaluator `/1` over policy `/1`, and today's
/// policy decoder refuses every policy that carries a sum, partition, or
/// scope member.
#[test]
fn current_registry_and_decoder_lack_evaluator_v2() {
    let vectors = load(FILE);
    let registrations = crate::gateway_evaluator_registrations().expect("registry");
    let evaluators: Vec<&str> = registrations
        .iter()
        .map(|registration| registration.evaluator_semantic_id.as_str())
        .collect();
    let policies: Vec<&str> = registrations
        .iter()
        .map(|registration| registration.policy_type.as_str())
        .collect();
    assert_eq!(evaluators, [EVALUATOR_V1]);
    assert_eq!(policies, [POLICY_V1]);
    assert_eq!(vectors["evaluator"], EVALUATOR_V2);
    let mut extended = 0;
    for case in vectors["cases"].as_array().expect("cases") {
        for grant in case["grants"].as_array().into_iter().flatten() {
            let Some(bytes) = grant["policy_cbor_hex"].as_str() else {
                continue;
            };
            let bytes = hex::decode(bytes).expect("hex");
            let members = grant["policy"].as_object().expect("policy").len();
            if members > 4 {
                extended += 1;
                assert!(
                    crate::ArgumentCeilingPolicy::decode(&bytes).is_err(),
                    "{}",
                    case["id"]
                );
            }
        }
    }
    assert!(extended > 0);
}
