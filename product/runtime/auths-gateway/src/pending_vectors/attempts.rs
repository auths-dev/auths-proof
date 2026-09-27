//! Attempt scenarios for attempt record `/3`: the pre-entry re-read, the
//! relative ceiling, the lease-time account and denied reads, account-scope
//! headers, the retention rule, the entry deadline, and response-locator
//! recovery.
//!
//! Each case names a base of the recipe `/2` corpus, the provider double's
//! answers where they differ from the defaults, the stored stages in order
//! (empty when nothing is stored), the refusal code, and the lease, read, and
//! write counts. The nineteen `/1` scenarios stay in `attempt-scenarios.json`
//! until attempt record `/2` is retired, when they move here unchanged.

use super::{NOW, load, recipes, require_current};
use crate::{CompiledRecipe, FileGatewayAttemptStore, GatewayAttempts};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) const FILE: &str = "attempt-scenarios-v3.json";
const SCHEMA: &str = "auths.gateway-attempt-scenarios/3";
const ATTEMPT_SCHEMA: &str = "auths.gateway-attempt/3";
const STRIPE_VERSION: &str = "2025-03-31.basil";
const ACCOUNT: &str = "acct_TESTACCOUNT01";
const PLATFORM: &str = "acct_TESTPLATFORM1";
const INTENT: &str = "pi_TEST0000000001";
const REFUND: &str = "re_TEST0000000001";
const AIRTABLE_ORIGIN: &str = "https://api.airtable.com";
const RECORD_PATH: &str = "/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001";

/// A provider answer with no provider headers.
fn answer(status: u16, body: Value) -> Value {
    let mut answer = json!({"status": status, "headers": {}});
    answer["body"] = body;
    answer
}

/// A Stripe answer carrying the pinned `Stripe-Version` header.
fn stripe_answer(status: u16, body: Value) -> Value {
    let mut answer = answer(status, body);
    answer["headers"]["Stripe-Version"] = json!(STRIPE_VERSION);
    answer
}

fn responses(entries: Vec<(String, Value)>) -> Value {
    Value::Object(entries.into_iter().collect::<Map<String, Value>>())
}

/// The Stripe double when every check passes: the installed account, both
/// denied reads refused, and a `PaymentIntent` whose half, rounded down, is
/// 500.
fn stripe_defaults() -> Value {
    let refund = json!({"id": REFUND, "amount": "<written amount>",
        "metadata": {"auths_echo": "<written echo>"}});
    let mut defaults = json!({
        "account_label": PLATFORM,
        "validity_seconds": 3600,
        "arguments": {"operation_id": "refund-1", "payment_intent": INTENT, "amount": 500,
            "currency": "usd", "connect_account": ACCOUNT},
        "grant_policy": {"argument": "amount", "ceiling": 100_000, "window_seconds": 86_400,
            "max_count": 10, "sum_limit": 100_000,
            "partition": {"argument": "currency", "values": ["usd"]},
            "scope": {"argument": "connect_account", "values": [ACCOUNT]}}
    });
    defaults["responses"] = responses(vec![
        (
            "GET /v1/account".into(),
            stripe_answer(200, json!({"id": PLATFORM, "object": "account"})),
        ),
        ("GET /v1/customers".into(), stripe_answer(403, Value::Null)),
        ("GET /v1/payouts".into(), stripe_answer(403, Value::Null)),
        (
            format!("GET /v1/payment_intents/{INTENT}"),
            stripe_answer(
                200,
                json!({"id": INTENT, "amount_received": 1001, "currency": "usd"}),
            ),
        ),
        (
            "POST /v1/refunds".into(),
            stripe_answer(200, refund.clone()),
        ),
        (
            format!("GET /v1/refunds/{REFUND}"),
            stripe_answer(200, refund),
        ),
    ]);
    defaults
}

/// The Airtable double and grant for the pre-entry recipe: the agent attaches
/// a fresh gateway read-back of `Pending`, and the grant requires the
/// re-read value to equal the verified `expected` argument.
fn pre_entry_defaults() -> Value {
    let mut defaults = json!({
        "validity_seconds": 3600,
        "arguments": {"operation_id": "update-1", "record_id": "recTEST0000000001",
            "replacement": "Approved", "expected": "Pending",
            "record_uri": format!("{AIRTABLE_ORIGIN}{RECORD_PATH}#/fields/DemoStatus")},
        "grant_requirement": {"schema": "auths.gateway-readback/1",
            "subject": {"action_fact": "record_uri"},
            "conditions": [{"eq-action": ["value", "expected"]}], "maximum_age_seconds": 300},
        "attached_read_back": {"value": "Pending", "observed_at": NOW - 10},
        "observer_provisioned": true
    });
    defaults["responses"] = responses(vec![
        (
            format!("GET {RECORD_PATH}"),
            answer(200, json!({"fields": {"DemoStatus": "Pending"}})),
        ),
        (
            format!("PATCH {RECORD_PATH}"),
            answer(200, json!({"fields": {"DemoStatus": "Approved"}})),
        ),
    ]);
    defaults
}

struct Counts {
    leases: u64,
    credential_reads: u64,
    action_reads: u64,
    writes: u64,
}

const fn counts(leases: u64, credential_reads: u64, action_reads: u64, writes: u64) -> Counts {
    Counts {
        leases,
        credential_reads,
        action_reads,
        writes,
    }
}

fn scenario(
    id: &str,
    recipe: &str,
    setup: Value,
    stages: &[&str],
    code: Option<&str>,
    counts: &Counts,
) -> Value {
    let mut case = json!({"id": id, "recipe": recipe});
    case["setup"] = setup;
    case["stages"] = json!(stages);
    case["code"] = json!(code);
    case["leases"] = json!(counts.leases);
    case["credential_reads"] = json!(counts.credential_reads);
    case["action_reads"] = json!(counts.action_reads);
    case["provider_entries"] = json!(counts.writes);
    case
}

/// A setup that overrides one Stripe answer.
fn response(key: &str, status: u16, body: Value) -> Value {
    let mut setup = json!({"responses": {}});
    setup["responses"][key] = stripe_answer(status, body);
    setup
}

/// A setup that overrides one answer with no provider headers: an Airtable
/// answer, or a Stripe answer that omits its version header.
fn plain_response(key: &str, status: u16, body: Value) -> Value {
    let mut setup = json!({"responses": {}});
    setup["responses"][key] = answer(status, body);
    setup
}

const FULL: [&str; 4] = [
    "attempting",
    "attempting",
    "response-recorded",
    "observed-by-provider",
];
const REFUSED_AFTER_BASIS: [&str; 2] = ["attempting", "not-entered"];

fn relative_ceiling_cases() -> Vec<Value> {
    let intent = format!("GET /v1/payment_intents/{INTENT}");
    let unavailable = Some("gateway.relative-ceiling.unavailable");
    let mut above = scenario(
        "relative-ceiling-above",
        "stripe",
        json!({"arguments": {"amount": 501}}),
        &REFUSED_AFTER_BASIS,
        Some("gateway.relative-ceiling.above"),
        &counts(1, 3, 1, 0),
    );
    above["basis"] = json!(1001);
    let mut boundary = scenario(
        "relative-ceiling-exact-boundary",
        "stripe",
        json!({}),
        &FULL,
        None,
        &counts(2, 6, 2, 1),
    );
    boundary["basis"] = json!(1001);
    let mut mismatch = scenario(
        "relative-binding-mismatch",
        "stripe",
        response(
            &intent,
            200,
            json!({"id": INTENT, "amount_received": 1001, "currency": "eur"}),
        ),
        &REFUSED_AFTER_BASIS,
        Some("gateway.relative-ceiling.binding-mismatch"),
        &counts(1, 3, 1, 0),
    );
    mismatch["basis"] = json!(1001);
    let version = plain_response(
        &intent,
        200,
        json!({"id": INTENT, "amount_received": 1001, "currency": "usd"}),
    );
    vec![
        above,
        boundary,
        scenario(
            "relative-basis-unavailable",
            "stripe",
            response(&intent, 200, json!({"id": INTENT, "currency": "usd"})),
            &REFUSED_AFTER_BASIS,
            unavailable,
            &counts(1, 3, 1, 0),
        ),
        scenario(
            "relative-basis-not-an-integer",
            "stripe",
            response(
                &intent,
                200,
                json!({"id": INTENT, "amount_received": 1001.5, "currency": "usd"}),
            ),
            &REFUSED_AFTER_BASIS,
            unavailable,
            &counts(1, 3, 1, 0),
        ),
        scenario(
            "relative-basis-version-mismatch",
            "stripe",
            version,
            &REFUSED_AFTER_BASIS,
            unavailable,
            &counts(1, 3, 1, 0),
        ),
        mismatch,
    ]
}

fn credential_cases() -> Vec<Value> {
    let refused = ["attempting", "not-entered"];
    let version = plain_response("GET /v1/customers", 403, Value::Null);
    vec![
        scenario(
            "credential-mode-guard-at-lease",
            "stripe",
            json!({"leased_secret_prefix": "sk_test_"}),
            &refused,
            Some("gateway.credential.mode-guard"),
            &counts(1, 0, 0, 0),
        ),
        scenario(
            "account-substituted-at-lease",
            "stripe",
            response(
                "GET /v1/account",
                200,
                json!({"id": "acct_TESTOTHER0001", "object": "account"}),
            ),
            &refused,
            Some("gateway.credential.account-mismatch"),
            &counts(1, 1, 0, 0),
        ),
        scenario(
            "account-unavailable-at-lease",
            "stripe",
            response("GET /v1/account", 500, Value::Null),
            &refused,
            Some("gateway.credential.account-unavailable"),
            &counts(1, 1, 0, 0),
        ),
        scenario(
            "denied-read-answered",
            "stripe",
            response("GET /v1/customers", 200, json!({"data": []})),
            &refused,
            Some("gateway.credential.capability-excess"),
            &counts(1, 2, 0, 0),
        ),
        scenario(
            "denied-read-unexpected-status",
            "stripe",
            response("GET /v1/payouts", 404, Value::Null),
            &refused,
            Some("gateway.credential.capability-unavailable"),
            &counts(1, 3, 0, 0),
        ),
        scenario(
            "denied-read-version-mismatch",
            "stripe",
            version,
            &refused,
            Some("gateway.credential.capability-unavailable"),
            &counts(1, 2, 0, 0),
        ),
    ]
}

fn stripe_request(method: &str, path: &str, account: bool, key: bool) -> Value {
    json!({"method": method, "path": path, "stripe_version": STRIPE_VERSION,
        "stripe_account": if account { json!(ACCOUNT) } else { Value::Null },
        "idempotency_key": key, "credential": true})
}

fn account_scope_cases() -> Vec<Value> {
    let none: [&str; 0] = [];
    let before = counts(0, 0, 0, 0);
    let scope = |values: &[&str]| json!({"grant_policy": {"scope": {"argument": "connect_account", "values": values}}});
    let unbound = json!({"grant_policy": {"scope": null}});
    let mut invalid = scope(&["acct-TESTACCOUNT01"]);
    invalid["arguments"] = json!({"connect_account": "acct-TESTACCOUNT01"});
    let mut outside = scope(&[ACCOUNT]);
    outside["arguments"] = json!({"connect_account": "acct_TESTACCOUNT02"});
    let mut only_action = scenario(
        "account-scope-only-on-action-requests",
        "stripe",
        json!({}),
        &FULL,
        None,
        &counts(2, 6, 2, 1),
    );
    let credential_reads = |requests: &mut Vec<Value>| {
        for path in ["/v1/account", "/v1/customers", "/v1/payouts"] {
            requests.push(stripe_request("GET", path, false, false));
        }
    };
    let mut requests = Vec::new();
    credential_reads(&mut requests);
    requests.push(stripe_request(
        "GET",
        &format!("/v1/payment_intents/{INTENT}"),
        true,
        false,
    ));
    requests.push(stripe_request("POST", "/v1/refunds", true, true));
    credential_reads(&mut requests);
    requests.push(stripe_request(
        "GET",
        &format!("/v1/refunds/{REFUND}"),
        true,
        false,
    ));
    only_action["requests"] = Value::Array(requests);
    vec![
        scenario(
            "account-scope-outside-grant",
            "stripe",
            outside,
            &none,
            Some("gateway.policy.scope-denied"),
            &before,
        ),
        scenario(
            "account-scope-unbound",
            "stripe",
            unbound,
            &none,
            Some("gateway.account-scope.unbound"),
            &before,
        ),
        scenario(
            "account-scope-invalid-value",
            "stripe",
            invalid,
            &none,
            Some("gateway.account-scope.invalid-value"),
            &before,
        ),
        only_action,
    ]
}

fn pre_entry_cases() -> Vec<Value> {
    let none: [&str; 0] = [];
    let record = format!("GET {RECORD_PATH}");
    let mut replaced = scenario(
        "pre-entry-replaced-after-observation",
        "airtable-pre-entry",
        plain_response(&record, 200, json!({"fields": {"DemoStatus": "Approved"}})),
        &["attempting", "not-entered"],
        Some("gateway.pre-entry.condition-false"),
        &counts(1, 0, 1, 0),
    );
    replaced["pre_entry_observations"] = json!(1);
    let mut matching = scenario(
        "pre-entry-still-matches",
        "airtable-pre-entry",
        json!({}),
        &FULL,
        None,
        &counts(2, 0, 2, 1),
    );
    matching["pre_entry_observations"] = json!(1);
    vec![
        replaced,
        matching,
        scenario(
            "pre-entry-unavailable",
            "airtable-pre-entry",
            plain_response(&record, 404, Value::Null),
            &["attempting", "not-entered"],
            Some("gateway.pre-entry.unavailable"),
            &counts(1, 0, 1, 0),
        ),
        scenario(
            "pre-entry-requirement-missing",
            "airtable-pre-entry",
            json!({"grant_requirement": null}),
            &none,
            Some("gateway.pre-entry.requirement-missing"),
            &counts(0, 0, 0, 0),
        ),
        scenario(
            "pre-entry-observer-unavailable",
            "airtable-pre-entry",
            json!({"observer_provisioned": false}),
            &none,
            Some("gateway.pre-entry.observer-unavailable"),
            &counts(0, 0, 0, 0),
        ),
    ]
}

fn entry_and_recovery_cases() -> Vec<Value> {
    let none: [&str; 0] = [];
    let refused_at_entry = ["attempting", "attempting", "not-entered"];
    vec![
        scenario(
            "idempotency-window-exceeds-retention",
            "stripe",
            json!({"validity_seconds": 86_400}),
            &none,
            Some("gateway.idempotency.window-exceeds-retention"),
            &counts(0, 0, 0, 0),
        ),
        scenario(
            "idempotency-window-at-retention",
            "stripe",
            json!({"validity_seconds": 86_340}),
            &FULL,
            None,
            &counts(2, 6, 2, 1),
        ),
        scenario(
            "entry-deadline-exceeded",
            "stripe",
            json!({"gateway_clock_advance": {"after_step": 10, "seconds": 61}}),
            &refused_at_entry,
            Some("gateway.attempt.entry-deadline"),
            &counts(1, 3, 1, 0),
        ),
        scenario(
            "transport-not-entered",
            "stripe",
            json!({"write_transport": "refused-before-send"}),
            &refused_at_entry,
            Some("gateway.transport.not-entered"),
            &counts(1, 3, 1, 0),
        ),
        scenario(
            "response-locator-unknown-stays-unknown",
            "stripe",
            json!({"write_transport": "timeout-after-send", "replay": "fresh-proof"}),
            &["attempting", "attempting", "unknown"],
            None,
            &counts(1, 3, 1, 1),
        ),
        scenario(
            "linked-attempting-reobserved",
            "airtable",
            json!({"crash": "after-write-before-response", "replay": "fresh-proof"}),
            &["attempting", "observed-by-provider"],
            None,
            &counts(2, 0, 1, 1),
        ),
    ]
}

fn document() -> Value {
    let cases: Vec<Value> = [
        pre_entry_cases(),
        relative_ceiling_cases(),
        credential_cases(),
        account_scope_cases(),
        entry_and_recovery_cases(),
    ]
    .concat();
    json!({
        "schema": SCHEMA,
        "attempt_schema": ATTEMPT_SCHEMA,
        "recipes": recipes::FILE,
        "evaluated_at": NOW,
        "defaults": {"stripe": stripe_defaults(), "airtable-pre-entry": pre_entry_defaults(),
            "airtable": {"validity_seconds": 3600, "arguments": {"operation_id": "update-1",
                "record_id": "recTEST0000000001", "replacement": "Approved"}}},
        "cases": cases,
    })
}

#[test]
fn attempt_scenarios_v3_are_current() {
    require_current(FILE, &document());
}

/// Today's store writes attempt record `/2`, and today's compiler refuses the
/// recipe of every scenario, so none of these scenarios can run.
#[tokio::test]
async fn current_store_and_compiler_cannot_run_attempt_scenarios_v3() {
    let scenarios = load(FILE);
    assert_eq!(scenarios["attempt_schema"], ATTEMPT_SCHEMA);
    let corpus = load(recipes::FILE);
    for case in scenarios["cases"].as_array().expect("cases") {
        let base = &corpus["bases"][case["recipe"].as_str().expect("recipe")];
        let refused = CompiledRecipe::compile(
            &serde_json::to_vec(&base["recipe"]).expect("recipe"),
            &serde_json::to_vec(&base["lock"]).expect("lock"),
        )
        .expect_err("revised recipe");
        assert_eq!(
            refused.code(),
            "gateway.recipe.invalid-source",
            "{}",
            case["id"]
        );
    }
    let recipe = CompiledRecipe::compile(
        include_bytes!("../../../../../bindings/fixtures/gateway/github/recipe.json"),
        include_bytes!("../../../../../bindings/fixtures/gateway/github/profile.lock.json"),
    )
    .expect("current github fixture");
    let mut arguments = Map::new();
    arguments.insert("operation_id".into(), json!("issue-1"));
    arguments.insert("title".into(), json!("Exact"));
    arguments.insert("body".into(), json!("One issue"));
    arguments.insert(
        "operator_namespace".into(),
        json!(recipe.namespace().as_str()),
    );
    arguments.insert("recipe_digest".into(), json!(recipe.digest_hex()));
    let request = recipe
        .closed_request_from_arguments(&arguments, [7; 32])
        .expect("request");
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical")
        .join("attempts");
    let store = GatewayAttempts::new(Arc::new(
        FileGatewayAttemptStore::open(&root).expect("store"),
    ));
    store
        .claim(&request, *recipe.digest())
        .await
        .expect("claim");
    let mut schemas = Vec::new();
    for entry in std::fs::read_dir(&root).expect("store directory") {
        let path = entry.expect("entry").path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("claim-"))
        {
            let record: Value = serde_json::from_slice(&std::fs::read(&path).expect("record"))
                .expect("JSON record");
            schemas.push(record["schema"].as_str().expect("schema").to_owned());
        }
    }
    assert_eq!(schemas, ["auths.gateway-attempt/2"]);
}
