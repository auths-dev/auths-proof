//! Recipe source `/2`: valid bases with the recovery class each compiles to,
//! and hostile cases for every construct the revision adds.
//!
//! The bases are derived from the committed `/1` fixtures and the north-star
//! example, so a change to either makes this fixture stale. Each hostile case
//! is one base plus mutations that break exactly one compile rule; no case
//! depends on the order in which the compiler checks its rules.

use super::{apply_mutation, load, require_current};
use crate::CompiledRecipe;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub(super) const FILE: &str = "hostile-recipes-v2.json";
const SCHEMA: &str = "auths.gateway-hostile-recipes/2";
const SOURCE_V2: &str = "auths.gateway-recipe-source/2";
const STRIPE_VERSION: &str = "2025-03-31.basil";

const AIRTABLE: &[u8] =
    include_bytes!("../../../../../bindings/fixtures/gateway/airtable/recipe.json");
const AIRTABLE_LOCK: &[u8] =
    include_bytes!("../../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TODOIST: &[u8] =
    include_bytes!("../../../../../bindings/fixtures/gateway/todoist/recipe.json");
const TODOIST_LOCK: &[u8] =
    include_bytes!("../../../../../bindings/fixtures/gateway/todoist/profile.lock.json");
const GITHUB: &[u8] = include_bytes!("../../../../../bindings/fixtures/gateway/github/recipe.json");
const GITHUB_LOCK: &[u8] =
    include_bytes!("../../../../../bindings/fixtures/gateway/github/profile.lock.json");
const STRIPE: &[u8] = include_bytes!("../../../../../examples/stripe-refund-approval/recipe.json");
const STRIPE_LOCK: &[u8] =
    include_bytes!("../../../../../examples/stripe-refund-approval/profile.lock.json");

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("committed JSON")
}

/// Adds `extra` fields to a committed lock and recomputes its schema digest
/// exactly as the profile generator does.
fn derive_lock(bytes: &[u8], extra: &Value) -> Value {
    let mut lock = parse(bytes);
    for (name, schema) in extra.as_object().expect("extra fields") {
        lock["command_schema"]["fields"][name] = schema.clone();
    }
    let canonical = serde_json_canonicalizer::to_vec(&lock["command_schema"]).expect("schema");
    lock["schema_digest"] = Value::String(hex::encode(Sha256::digest(canonical)));
    lock
}

fn stripe_lock() -> Value {
    derive_lock(
        STRIPE_LOCK,
        &json!({
            "connect_account": {"kind": "string", "minimum": 13, "maximum": 64},
            "currency": {"kind": "string", "minimum": 3, "maximum": 3}
        }),
    )
}

/// The platform-account form: no `Stripe-Account` header and no
/// `connect_account` field.
fn stripe_platform_lock() -> Value {
    derive_lock(
        STRIPE_LOCK,
        &json!({"currency": {"kind": "string", "minimum": 3, "maximum": 3}}),
    )
}

fn airtable_pre_entry_lock() -> Value {
    derive_lock(
        AIRTABLE_LOCK,
        &json!({
            "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
            "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
        }),
    )
}

/// A committed `/1` recipe under the `/2` schema, with its echo placement in
/// the `/2` object form.
fn revised(bytes: &[u8]) -> Value {
    let mut recipe = parse(bytes);
    recipe["schema"] = json!(SOURCE_V2);
    if let Some(pointer) = recipe.pointer("/echo/write").and_then(Value::as_str) {
        let pointer = pointer.to_owned();
        recipe["echo"]["write"] = json!({"kind": "json-pointer", "pointer": pointer});
    }
    recipe
}

fn fixed(values: &[&str]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| json!({"kind": "fixed", "value": value}))
            .collect(),
    )
}

fn stripe_plain() -> Value {
    let mut recipe = revised(STRIPE);
    let write = recipe["write"].as_object_mut().expect("write");
    write
        .remove("idempotency_key")
        .expect("north-star key flag");
    write.insert(
        "idempotency".into(),
        json!({"kind": "derived-header", "retention_seconds": 86_400}),
    );
    recipe
}

/// The north-star recipe with every capability the revision adds.
fn stripe(lock: &Value) -> Value {
    json!({
        "schema": SOURCE_V2,
        "profile_schema_digest": lock["schema_digest"],
        "service": "stripe-refunds",
        "tool": "create_refund_v1",
        "operator_namespace": "stripe-refunds",
        "credential": {"kind": "bearer", "guard": {
            "prefixes": ["rk_test_"],
            "probe": {"path": fixed(&["v1", "balance"]), "json_pointer": "/livemode",
                "equals": false, "maximum_response_bytes": 16_384},
            "account": {"path": fixed(&["v1", "account"]), "json_pointer": "/id",
                "maximum_response_bytes": 65_536},
            "denied_reads": [
                {"method": "GET", "path": fixed(&["v1", "customers"]), "refused_status": [403]},
                {"method": "GET", "path": fixed(&["v1", "payouts"]), "refused_status": [403]}
            ]
        }},
        "origin": "https://api.stripe.com",
        "provider_headers": {"Stripe-Version": STRIPE_VERSION},
        "account_scope": {"header": "Stripe-Account", "field": "connect_account"},
        "bounds": {"sum": {"argument": "amount", "partition": "currency"}},
        "relative_ceiling": {
            "argument": "amount",
            "basis_points": 5000,
            "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "payment_intents"},
                {"kind": "field", "name": "payment_intent"}],
            "json_pointer": "/amount_received",
            "bind": [{"pointer": "/currency", "field": "currency"}],
            "maximum_response_bytes": 65_536
        },
        "write": {
            "method": "POST",
            "path": fixed(&["v1", "refunds"]),
            "body": {"kind": "form", "fields": {
                "payment_intent": {"kind": "field", "name": "payment_intent"},
                "amount": {"kind": "field", "name": "amount"}
            }},
            "idempotency": {"kind": "derived-header", "retention_seconds": 86_400}
        },
        "observation": {
            "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "refunds"},
                {"kind": "response-field", "pointer": "/id", "max_bytes": 255}],
            "json_pointer": "/amount",
            "expected_field": "amount",
            "maximum_response_bytes": 16_384
        },
        "echo": {"write": {"kind": "form-field", "name": "metadata[auths_echo]"},
            "observe": "/metadata/auths_echo"}
    })
}

fn stripe_platform(lock: &Value) -> Value {
    let mut recipe = stripe(lock);
    recipe
        .as_object_mut()
        .expect("recipe")
        .remove("account_scope")
        .expect("account scope");
    recipe
}

fn airtable_pre_entry(lock: &Value) -> Value {
    let mut recipe = revised(AIRTABLE);
    recipe["profile_schema_digest"] = lock["schema_digest"].clone();
    recipe["preconditions"] = json!({"read_back_subject": "record_uri", "verified": ["expected"]});
    recipe["pre_entry"] = json!({
        "path": recipe["write"]["path"].clone(),
        "pointers": ["/fields/DemoStatus"],
        "maximum_response_bytes": 16_384
    });
    recipe
}

fn todoist_operation_id() -> Value {
    let mut recipe = revised(TODOIST);
    recipe["write"]["idempotency"] = json!({
        "kind": "operation-id-field",
        "location": {"form_field": "commands", "pointer": "/0/uuid"},
        "retention_seconds": 3600
    });
    recipe
}

fn github_response_locator() -> Value {
    let mut recipe = revised(GITHUB);
    let mut path = recipe["write"]["path"].clone();
    path.as_array_mut()
        .expect("path")
        .push(json!({"kind": "response-field", "pointer": "/number", "max_bytes": 20}));
    recipe["observation"] = json!({
        "path": path,
        "json_pointer": "/title",
        "expected_field": "title",
        "maximum_response_bytes": 65_536
    });
    recipe
}

/// The recovery capability a recipe's declarations determine.
fn recovery(
    locator: Option<&str>,
    echo: bool,
    idempotency: Option<(&str, u64)>,
    pre_entry: bool,
) -> Value {
    let observation = locator.unwrap_or("none");
    let link = if echo { observation } else { "none" };
    let class = match (locator, echo) {
        (Some("verified-locator"), true) => "linked",
        (Some(_), true) => "linked-after-response",
        (Some(_), false) => "observed",
        (None, _) => "recorded",
    };
    let reentry = idempotency.map_or_else(
        || json!({"deduplication": "none"}),
        |(kind, retention)| {
            json!({"deduplication": "declared", "kind": kind, "retention_seconds": retention})
        },
    );
    json!({
        "schema": "auths.gateway-recovery-capability/1",
        "class": class,
        "state_observation": observation,
        "provider_link": link,
        "unknown_resolution": if class == "linked" { "gateway-reobservation" } else { "none" },
        "lost_claim_reentry": reentry,
        "pre_entry_reread": pre_entry,
        "write_is_conditional": false
    })
}

/// The revised recipe digest: SHA-256 over the `/2` domain, a NUL byte, and
/// the RFC 8785 serialization of the source.
fn recipe_digest(recipe: &Value) -> String {
    let mut preimage = b"auths.gateway-compiled-recipe/2\0".to_vec();
    preimage.extend(serde_json_canonicalizer::to_vec(recipe).expect("canonical source"));
    hex::encode(Sha256::digest(preimage))
}

fn bases() -> Value {
    let stripe_lock = stripe_lock();
    let platform_lock = stripe_platform_lock();
    let pre_entry_lock = airtable_pre_entry_lock();
    let base = |recipe: Value, lock: Value, recovery: Value| json!({"recipe": recipe, "lock": lock, "recovery": recovery});
    let verified = Some("verified-locator");
    let response = Some("response-locator");
    let mut bases = json!({
        "airtable": base(revised(AIRTABLE), parse(AIRTABLE_LOCK), recovery(verified, true, None, false)),
        "airtable-pre-entry": base(airtable_pre_entry(&pre_entry_lock), pre_entry_lock,
            recovery(verified, true, None, true)),
        "todoist": base(revised(TODOIST), parse(TODOIST_LOCK), recovery(None, false, None, false)),
        "todoist-operation-id": base(todoist_operation_id(), parse(TODOIST_LOCK),
            recovery(None, false, Some(("operation-id-field", 3600)), false)),
        "github": base(revised(GITHUB), parse(GITHUB_LOCK), recovery(None, false, None, false)),
        "github-response-locator": base(github_response_locator(), parse(GITHUB_LOCK),
            recovery(response, false, None, false)),
        "stripe-plain": base(stripe_plain(), parse(STRIPE_LOCK),
            recovery(None, false, Some(("derived-header", 86_400)), false)),
        "stripe": base(stripe(&stripe_lock), stripe_lock,
            recovery(response, true, Some(("derived-header", 86_400)), false)),
        "stripe-platform": base(stripe_platform(&platform_lock), platform_lock,
            recovery(response, true, Some(("derived-header", 86_400)), false)),
    });
    bases["todoist-operation-id"]["note"] =
        json!("retention_seconds is a fixture value, not a statement of the provider's retention");
    for base in bases.as_object_mut().expect("bases").values_mut() {
        base["digest"] = json!(recipe_digest(&base["recipe"]));
    }
    bases
}

fn mutation(op: &str, pointer: &str, value: Option<Value>) -> Value {
    let mut mutation = json!({"op": op, "pointer": pointer});
    if let Some(value) = value {
        mutation["value"] = value;
    }
    mutation
}

fn set(pointer: &str, value: Value) -> Value {
    mutation("set", pointer, Some(value))
}

fn append(pointer: &str, value: Value) -> Value {
    mutation("append", pointer, Some(value))
}

fn remove(pointer: &str) -> Value {
    mutation("remove", pointer, None)
}

fn case(id: &str, base: &str, code: &str, mutations: Vec<Value>) -> Value {
    let mut case = json!({"id": id, "base": base});
    case["mutations"] = Value::Array(mutations);
    case["code"] = json!(code);
    case
}

fn field(name: &str) -> Value {
    json!({"kind": "field", "name": name})
}

fn schema_and_credential_cases() -> Vec<Value> {
    let credential = "gateway.recipe.invalid-credential";
    let header = |name: &str| {
        set(
            "/credential",
            json!({"kind": "header-api-key", "header": name}),
        )
    };
    vec![
        case(
            "schema-v1-refused",
            "github",
            "gateway.recipe.invalid-source",
            vec![set("/schema", json!("auths.gateway-recipe-source/1"))],
        ),
        case(
            "credential-header-is-stripe-version",
            "todoist",
            credential,
            vec![header("Stripe-Version")],
        ),
        case(
            "credential-header-is-github-version",
            "todoist",
            credential,
            vec![header("X-GitHub-Api-Version")],
        ),
        case(
            "credential-header-is-stripe-account",
            "todoist",
            credential,
            vec![header("Stripe-Account")],
        ),
    ]
}

fn guard_cases() -> Vec<Value> {
    let code = "gateway.recipe.invalid-credential-guard";
    let guard = |id: &str, pointer: &str, value: Value| {
        case(
            id,
            "stripe",
            code,
            vec![set(&format!("/credential/guard/{pointer}"), value)],
        )
    };
    vec![
        guard("guard-prefixes-empty", "prefixes", json!([])),
        guard(
            "guard-prefixes-five",
            "prefixes",
            json!(["rk_test_", "rk_a_", "rk_b_", "rk_c_", "rk_d_"]),
        ),
        guard(
            "guard-prefix-duplicate",
            "prefixes",
            json!(["rk_test_", "rk_test_"]),
        ),
        guard("guard-prefix-empty-string", "prefixes", json!([""])),
        guard("guard-prefix-33-bytes", "prefixes", json!(["r".repeat(33)])),
        guard("guard-prefix-space", "prefixes", json!(["rk test_"])),
        guard(
            "guard-prefix-non-ascii",
            "prefixes",
            json!(["rk_t\u{e9}st_"]),
        ),
        guard(
            "probe-field-segment",
            "probe/path",
            json!([{"kind": "fixed", "value": "v1"}, field("payment_intent")]),
        ),
        guard("probe-path-empty", "probe/path", json!([])),
        guard("probe-path-17-segments", "probe/path", fixed(&["v1"; 17])),
        guard(
            "probe-pointer-not-a-pointer",
            "probe/json_pointer",
            json!("livemode"),
        ),
        guard("probe-equals-object", "probe/equals", json!({})),
        guard("probe-equals-null", "probe/equals", Value::Null),
        guard(
            "probe-equals-integer-2-pow-53",
            "probe/equals",
            json!(9_007_199_254_740_992_u64),
        ),
        guard(
            "probe-equals-string-257-bytes",
            "probe/equals",
            json!("x".repeat(257)),
        ),
        guard(
            "probe-response-bound-zero",
            "probe/maximum_response_bytes",
            json!(0),
        ),
        guard(
            "probe-response-bound-65537",
            "probe/maximum_response_bytes",
            json!(65_537),
        ),
        guard(
            "account-field-segment",
            "account/path",
            json!([field("payment_intent")]),
        ),
        guard(
            "account-pointer-not-a-pointer",
            "account/json_pointer",
            json!("id"),
        ),
        guard(
            "account-response-bound-65537",
            "account/maximum_response_bytes",
            json!(65_537),
        ),
    ]
}

fn denied_read_cases() -> Vec<Value> {
    let code = "gateway.recipe.invalid-credential-guard";
    let read = |id: &str, pointer: &str, value: Value| {
        case(
            id,
            "stripe",
            code,
            vec![set(
                &format!("/credential/guard/denied_reads/{pointer}"),
                value,
            )],
        )
    };
    let entry = |path: &str| json!({"method": "GET", "path": fixed(&["v1", path]), "refused_status": [403]});
    vec![
        read("denied-read-post", "0/method", json!("POST")),
        read(
            "denied-read-field-segment",
            "0/path",
            json!([{"kind": "fixed", "value": "v1"}, field("payment_intent")]),
        ),
        read("denied-read-status-429", "0/refused_status", json!([429])),
        read("denied-read-status-408", "0/refused_status", json!([408])),
        read("denied-read-status-200", "0/refused_status", json!([200])),
        read("denied-read-status-500", "0/refused_status", json!([500])),
        read(
            "denied-read-status-duplicate",
            "0/refused_status",
            json!([403, 403]),
        ),
        read(
            "denied-read-four-statuses",
            "0/refused_status",
            json!([401, 403, 404, 405]),
        ),
        read("denied-read-no-status", "0/refused_status", json!([])),
        read(
            "denied-read-duplicate-path",
            "1/path",
            fixed(&["v1", "customers"]),
        ),
        read(
            "denied-read-probe-path",
            "0/path",
            fixed(&["v1", "balance"]),
        ),
        read(
            "denied-read-account-path",
            "0/path",
            fixed(&["v1", "account"]),
        ),
        read(
            "denied-read-write-path",
            "0/path",
            fixed(&["v1", "refunds"]),
        ),
        case(
            "denied-reads-empty",
            "stripe",
            code,
            vec![set("/credential/guard/denied_reads", json!([]))],
        ),
        case(
            "denied-reads-five",
            "stripe",
            code,
            vec![set(
                "/credential/guard/denied_reads",
                json!([
                    entry("customers"),
                    entry("payouts"),
                    entry("charges"),
                    entry("transfers"),
                    entry("invoices")
                ]),
            )],
        ),
    ]
}

fn header_and_scope_cases() -> Vec<Value> {
    let header = "gateway.recipe.invalid-provider-header";
    let scope = "gateway.recipe.invalid-account-scope";
    let headers =
        |id: &str, value: Value| case(id, "stripe", header, vec![set("/provider_headers", value)]);
    let version = |id: &str, value: &str| headers(id, json!({"Stripe-Version": value}));
    let body_connect = set(
        "/write/body/fields/connect_account",
        field("connect_account"),
    );
    vec![
        headers(
            "provider-header-stripe-account",
            json!({"Stripe-Version": STRIPE_VERSION, "Stripe-Account": "acct_TESTACCOUNT01"}),
        ),
        headers(
            "provider-header-unregistered",
            json!({"Stripe-Version": STRIPE_VERSION, "X-Api-Version": "1"}),
        ),
        headers(
            "provider-header-idempotency-key",
            json!({"Idempotency-Key": "fixed"}),
        ),
        headers(
            "provider-header-authorization",
            json!({"Authorization": "Bearer fixed"}),
        ),
        version("stripe-version-first-byte-letter", "v2025-03-31"),
        version("stripe-version-9-bytes", "2025-03-3"),
        version("stripe-version-65-bytes", &format!("2{}", "a".repeat(64))),
        version("stripe-version-underscore", "2025-03-31_basil"),
        version("stripe-version-line-break", "2025-03-31\r\nX-Injected: 1"),
        case(
            "github-version-not-a-date",
            "github",
            header,
            vec![set(
                "/provider_headers",
                json!({"X-GitHub-Api-Version": "2022/11/28"}),
            )],
        ),
        case(
            "github-version-11-bytes",
            "github",
            header,
            vec![set(
                "/provider_headers",
                json!({"X-GitHub-Api-Version": "2022-11-280"}),
            )],
        ),
        case(
            "account-scope-unregistered-header",
            "stripe",
            scope,
            vec![set("/account_scope/header", json!("X-Account"))],
        ),
        case(
            "account-scope-version-header",
            "stripe",
            scope,
            vec![set("/account_scope/header", json!("Stripe-Version"))],
        ),
        case(
            "account-scope-field-absent",
            "stripe",
            scope,
            vec![
                set("/account_scope/field", json!("missing")),
                body_connect.clone(),
            ],
        ),
        case(
            "account-scope-field-integer",
            "stripe",
            scope,
            vec![
                set("/account_scope/field", json!("amount")),
                body_connect.clone(),
            ],
        ),
        case(
            "account-scope-field-in-body",
            "stripe",
            scope,
            vec![body_connect],
        ),
        case(
            "account-scope-field-in-path",
            "stripe",
            scope,
            vec![append("/write/path", field("connect_account"))],
        ),
        case(
            "account-scope-removed",
            "stripe",
            "gateway.recipe.unsafe-template",
            vec![remove("/account_scope")],
        ),
    ]
}

fn bounds_cases() -> Vec<Value> {
    let bounds = "gateway.recipe.invalid-bounds";
    let sum = |id: &str, member: &str, value: &str| {
        case(
            id,
            "stripe",
            bounds,
            vec![set(&format!("/bounds/sum/{member}"), json!(value))],
        )
    };
    vec![
        sum("bounds-sum-argument-string", "argument", "payment_intent"),
        sum("bounds-sum-argument-absent", "argument", "missing"),
        sum("bounds-sum-partition-is-argument", "partition", "amount"),
        sum("bounds-sum-partition-absent", "partition", "missing"),
        case(
            "unbound-partition",
            "stripe",
            "gateway.recipe.unbound-partition",
            vec![
                set("/relative_ceiling/bind", json!([])),
                append("/relative_ceiling/path", field("currency")),
            ],
        ),
    ]
}

const CEILING: &str = "gateway.recipe.invalid-relative-ceiling";

fn ceiling_case(id: &str, code: &str, member: &str, value: Value) -> Value {
    case(
        id,
        "stripe",
        code,
        vec![set(&format!("/relative_ceiling/{member}"), value)],
    )
}

fn bind(pointer: &str, name: &str) -> Value {
    json!({"pointer": pointer, "field": name})
}

fn ceiling_cases() -> Vec<Value> {
    vec![
        ceiling_case(
            "relative-ceiling-basis-points-0",
            CEILING,
            "basis_points",
            json!(0),
        ),
        ceiling_case(
            "relative-ceiling-basis-points-10001",
            CEILING,
            "basis_points",
            json!(10_001),
        ),
        ceiling_case(
            "relative-ceiling-argument-string",
            CEILING,
            "argument",
            json!("payment_intent"),
        ),
        ceiling_case(
            "relative-ceiling-argument-absent",
            CEILING,
            "argument",
            json!("missing"),
        ),
        ceiling_case(
            "relative-ceiling-subtract-is-pointer",
            CEILING,
            "subtract_pointer",
            json!("/amount_received"),
        ),
        ceiling_case(
            "relative-ceiling-pointer-not-a-pointer",
            CEILING,
            "json_pointer",
            json!("amount_received"),
        ),
    ]
}

fn ceiling_bind_cases() -> Vec<Value> {
    let currency = bind("/currency", "currency");
    vec![
        ceiling_case(
            "relative-ceiling-three-binds",
            CEILING,
            "bind",
            json!([
                currency.clone(),
                bind("/customer", "connect_account"),
                bind("/description", "payment_intent")
            ]),
        ),
        ceiling_case(
            "relative-ceiling-bind-duplicate-pointer",
            CEILING,
            "bind",
            json!([currency.clone(), bind("/currency", "connect_account")]),
        ),
        ceiling_case(
            "relative-ceiling-bind-argument",
            CEILING,
            "bind",
            json!([currency.clone(), bind("/amount", "amount")]),
        ),
        ceiling_case(
            "relative-ceiling-bind-absent-field",
            CEILING,
            "bind",
            json!([currency, bind("/metadata/x", "missing")]),
        ),
        ceiling_case(
            "relative-ceiling-bind-not-a-pointer",
            CEILING,
            "bind",
            json!([bind("currency", "currency")]),
        ),
    ]
}

fn ceiling_limit_cases() -> Vec<Value> {
    let unsafe_path = "gateway.recipe.unsafe-path";
    vec![
        ceiling_case(
            "relative-ceiling-response-bound-zero",
            CEILING,
            "maximum_response_bytes",
            json!(0),
        ),
        ceiling_case(
            "relative-ceiling-response-bound-65537",
            CEILING,
            "maximum_response_bytes",
            json!(65_537),
        ),
        ceiling_case(
            "relative-ceiling-path-traversal",
            unsafe_path,
            "path/1/value",
            json!(".."),
        ),
        case(
            "relative-ceiling-path-integer-field",
            "stripe",
            unsafe_path,
            vec![append("/relative_ceiling/path", field("amount"))],
        ),
    ]
}

fn response_field(pointer: &str, max: u64) -> Value {
    json!({"kind": "response-field", "pointer": pointer, "max_bytes": max})
}

fn write_cases() -> Vec<Value> {
    let idempotency = "gateway.recipe.invalid-idempotency";
    let location = |value: Value| {
        set(
            "/write/idempotency",
            json!({"kind": "operation-id-field", "location": value, "retention_seconds": 3600}),
        )
    };
    vec![
        case(
            "write-path-response-field",
            "stripe",
            "gateway.recipe.response-locator-conflict",
            vec![append("/write/path", response_field("/id", 255))],
        ),
        case(
            "idempotency-v1-flag",
            "stripe-plain",
            "gateway.recipe.invalid-source",
            vec![
                remove("/write/idempotency"),
                set("/write/idempotency_key", json!(true)),
            ],
        ),
        case(
            "idempotency-retention-zero",
            "stripe-plain",
            idempotency,
            vec![set("/write/idempotency/retention_seconds", json!(0))],
        ),
        case(
            "idempotency-retention-2592001",
            "stripe-plain",
            idempotency,
            vec![set(
                "/write/idempotency/retention_seconds",
                json!(2_592_001),
            )],
        ),
        case(
            "operation-id-field-names-temp-id",
            "todoist",
            idempotency,
            vec![location(
                json!({"form_field": "commands", "pointer": "/0/temp_id"}),
            )],
        ),
        case(
            "operation-id-field-json-location-on-form",
            "todoist",
            idempotency,
            vec![location(json!({"json_pointer": "/0/uuid"}))],
        ),
        case(
            "operation-id-field-absent-form-field",
            "todoist",
            idempotency,
            vec![location(
                json!({"form_field": "missing", "pointer": "/0/uuid"}),
            )],
        ),
        case(
            "operation-id-field-form-location-on-json",
            "github",
            idempotency,
            vec![location(json!({"form_field": "title"}))],
        ),
    ]
}

fn observation_cases() -> Vec<Value> {
    let locator = "gateway.recipe.response-locator-conflict";
    vec![
        case(
            "observation-three-response-fields",
            "stripe",
            locator,
            vec![set(
                "/observation/path",
                json!([
                    {"kind": "fixed", "value": "v1"}, response_field("/id", 255),
                    response_field("/charge", 255), response_field("/object", 255)
                ]),
            )],
        ),
        case(
            "response-field-max-bytes-zero",
            "stripe",
            locator,
            vec![set("/observation/path/2/max_bytes", json!(0))],
        ),
        case(
            "response-field-max-bytes-256",
            "stripe",
            locator,
            vec![set("/observation/path/2/max_bytes", json!(256))],
        ),
        case(
            "response-field-not-a-pointer",
            "stripe",
            locator,
            vec![set("/observation/path/2/pointer", json!("id"))],
        ),
        case(
            "read-back-subject-with-response-locator",
            "airtable-pre-entry",
            "gateway.recipe.precondition-conflict",
            vec![append("/observation/path", response_field("/id", 64))],
        ),
    ]
}

fn echo_cases() -> Vec<Value> {
    let echo = "gateway.recipe.echo-conflict";
    let form_echo = |id: &str, name: &str| {
        case(
            id,
            "stripe",
            echo,
            vec![set(
                "/echo/write",
                json!({"kind": "form-field", "name": name}),
            )],
        )
    };
    let mut sixteen = serde_json::Map::new();
    sixteen.insert("payment_intent".into(), field("payment_intent"));
    sixteen.insert("amount".into(), field("amount"));
    for index in 1..=14 {
        sixteen.insert(
            format!("f{index:02}"),
            json!({"kind": "string", "value": "x"}),
        );
    }
    vec![
        case(
            "echo-v1-string-form",
            "airtable",
            "gateway.recipe.invalid-source",
            vec![set("/echo/write", json!("/fields/auths_echo"))],
        ),
        case(
            "form-echo-on-json-body",
            "airtable",
            echo,
            vec![set(
                "/echo/write",
                json!({"kind": "form-field", "name": "auths_echo"}),
            )],
        ),
        case(
            "json-echo-on-form-body",
            "stripe",
            echo,
            vec![set(
                "/echo/write",
                json!({"kind": "json-pointer", "pointer": "/metadata/auths_echo"}),
            )],
        ),
        form_echo("form-echo-existing-field", "amount"),
        form_echo("form-echo-name-space", "metadata[auths echo]"),
        form_echo("form-echo-two-brackets", "metadata[a][b]"),
        form_echo("form-echo-empty-bracket", "metadata[]"),
        form_echo("form-echo-leading-underscore", "_auths_echo"),
        form_echo("form-echo-65-byte-name", &"a".repeat(65)),
        case(
            "form-echo-seventeenth-field",
            "stripe",
            echo,
            vec![set("/write/body/fields", Value::Object(sixteen))],
        ),
        case(
            "form-echo-author-placed",
            "stripe",
            echo,
            vec![set(
                "/write/body/fields/metadata[auths_echo]",
                json!({"kind": "echo"}),
            )],
        ),
    ]
}

fn pre_entry_cases() -> Vec<Value> {
    let pre_entry = "gateway.recipe.invalid-pre-entry";
    let pointers = |value: Value| set("/pre_entry/pointers", value);
    vec![
        case(
            "pre-entry-no-pointers",
            "airtable-pre-entry",
            pre_entry,
            vec![pointers(json!([]))],
        ),
        case(
            "pre-entry-five-pointers",
            "airtable-pre-entry",
            pre_entry,
            vec![pointers(json!([
                "/fields/A",
                "/fields/B",
                "/fields/C",
                "/fields/D",
                "/fields/E"
            ]))],
        ),
        case(
            "pre-entry-duplicate-pointer",
            "airtable-pre-entry",
            pre_entry,
            vec![pointers(json!([
                "/fields/DemoStatus",
                "/fields/DemoStatus"
            ]))],
        ),
        case(
            "pre-entry-not-a-pointer",
            "airtable-pre-entry",
            pre_entry,
            vec![pointers(json!(["fields/DemoStatus"]))],
        ),
        case(
            "pre-entry-response-bound-65537",
            "airtable-pre-entry",
            pre_entry,
            vec![set("/pre_entry/maximum_response_bytes", json!(65_537))],
        ),
        case(
            "pre-entry-path-traversal",
            "airtable-pre-entry",
            "gateway.recipe.unsafe-path",
            vec![set("/pre_entry/path/1/value", json!(".."))],
        ),
    ]
}

fn document() -> Value {
    let cases: Vec<Value> = [
        schema_and_credential_cases(),
        guard_cases(),
        denied_read_cases(),
        header_and_scope_cases(),
        bounds_cases(),
        ceiling_cases(),
        ceiling_bind_cases(),
        ceiling_limit_cases(),
        write_cases(),
        observation_cases(),
        echo_cases(),
        pre_entry_cases(),
    ]
    .concat();
    json!({"schema": SCHEMA, "source_schema": SOURCE_V2, "bases": bases(), "cases": cases})
}

#[test]
fn recipe_v2_corpus_is_current() {
    require_current(FILE, &document());
}

fn compile(recipe: &Value, lock: &Value) -> Result<CompiledRecipe, crate::GatewayRecipeError> {
    CompiledRecipe::compile(
        &serde_json::to_vec(recipe).expect("recipe"),
        &serde_json::to_vec(lock).expect("lock"),
    )
}

/// Today's compiler reads only `/1`: every base is refused before any revised
/// construct is examined, so no hostile case can reach the rule it targets.
/// The one case that restores `/1` compiles, although `/2` refuses it.
#[test]
fn current_compiler_refuses_every_revised_recipe() {
    let corpus = load(FILE);
    let invalid = "gateway.recipe.invalid-source";
    let bases = corpus["bases"].as_object().expect("bases");
    for (id, base) in bases {
        let error = compile(&base["recipe"], &base["lock"]).expect_err(id);
        assert_eq!(error.code(), invalid, "base {id}");
    }
    let mut ids = std::collections::BTreeSet::new();
    for case in corpus["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        assert!(ids.insert(id), "duplicate case {id}");
        let base = &bases[case["base"].as_str().expect("base")];
        let mut recipe = base["recipe"].clone();
        for mutation in case["mutations"].as_array().expect("mutations") {
            apply_mutation(&mut recipe, mutation);
        }
        match compile(&recipe, &base["lock"]) {
            Ok(_) => assert_eq!(id, "schema-v1-refused"),
            Err(error) => assert_eq!(error.code(), invalid, "case {id}"),
        }
    }
}
