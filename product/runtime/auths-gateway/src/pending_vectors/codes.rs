//! The gateway code inventory for the revision: every code it adds or whose
//! meaning it changes, and every existing code a pending vector expects,
//! each with its owner, stage, status, implementing epic, and a fixture case
//! that produces it.
//!
//! `case` is null where no fixture of this change can produce the code: the
//! operator plane, installation, echo verification, and the audit's
//! counter-set, pre-entry, and relative-ceiling checks, each of which unit
//! tests in its owning module drive instead.
//!
//! Every epic of the revision is implemented, so the inventory is closed in
//! both directions: every listed code exists in the crate and every named
//! case produces it; every code a fixture expects is listed; and every code
//! of a family the revision introduced whole is listed.

use super::{
    attempts, bounds, crate_defines_code, crate_sources, load, outcomes, recipes, require_current,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) const FILE: &str = "codes.json";
const SCHEMA: &str = "auths.gateway-codes/1";

/// One row per code: code, owner, stage, status, epic (`-` for an existing
/// code), and the producing case as `<fixture letter>:<case id>` (`-` when
/// none exists yet). The fixture letters are R for the recipe corpus, A for
/// the attempt scenarios, B for the bounds cases, and O for the outcomes.
const ROWS: &[&str] = &[
    "gateway.recipe.echo-conflict GatewayRecipeError compile existing - R:form-echo-existing-field",
    "gateway.recipe.invalid-account-scope GatewayRecipeError compile new 2 R:account-scope-unregistered-header",
    "gateway.recipe.invalid-bounds GatewayRecipeError compile new 2 R:bounds-sum-argument-string",
    "gateway.recipe.invalid-credential GatewayRecipeError compile existing - R:credential-header-is-stripe-version",
    "gateway.recipe.invalid-credential-guard GatewayRecipeError compile new 2 R:denied-read-post",
    "gateway.recipe.invalid-idempotency GatewayRecipeError compile new 2 R:idempotency-retention-zero",
    "gateway.recipe.invalid-pre-entry GatewayRecipeError compile new 2 R:pre-entry-no-pointers",
    "gateway.recipe.invalid-provider-header GatewayRecipeError compile new 2 R:provider-header-stripe-account",
    "gateway.recipe.invalid-relative-ceiling GatewayRecipeError compile new 2 R:relative-ceiling-basis-points-0",
    "gateway.recipe.invalid-source GatewayRecipeError compile existing - R:schema-v1-refused",
    "gateway.recipe.precondition-conflict GatewayRecipeError compile existing - R:read-back-subject-with-response-locator",
    "gateway.recipe.response-locator-conflict GatewayRecipeError compile new 2 R:write-path-response-field",
    "gateway.recipe.unbound-partition GatewayRecipeError compile new 2 R:unbound-partition",
    "gateway.recipe.unsafe-path GatewayRecipeError compile existing - R:relative-ceiling-path-traversal",
    "gateway.recipe.unsafe-template GatewayRecipeError compile existing - R:account-scope-removed",
    "gateway.account-scope.invalid-value engine before-claim new 4 A:account-scope-invalid-value",
    "gateway.account-scope.unbound engine before-claim new 4 A:account-scope-unbound",
    "gateway.attempt.entry-deadline engine recorded new 3 A:entry-deadline-exceeded",
    "gateway.connection.changed engine recorded changed 5 -",
    "gateway.connection.credential-generation-missing engine before-claim new 5 -",
    "gateway.credential.account-mismatch engine recorded new 3 A:account-substituted-at-lease",
    "gateway.credential.account-unavailable engine recorded new 3 A:account-unavailable-at-lease",
    "gateway.credential.capability-excess engine recorded new 3 A:denied-read-answered",
    "gateway.credential.capability-unavailable engine recorded new 3 A:denied-read-unexpected-status",
    "gateway.credential.mode-guard engine recorded new 3 A:credential-mode-guard-at-lease",
    "gateway.credential.unavailable engine recorded changed 3 -",
    "gateway.idempotency.window-exceeds-retention engine before-claim new 3 A:idempotency-window-exceeds-retention",
    "gateway.policy.above-sum-limit engine before-claim new 4 B:argument-above-smallest-sum-limit",
    "gateway.policy.count-unavailable ReserveRefusal before-claim changed 4 -",
    "gateway.policy.evaluator-mismatch engine before-claim existing - B:policy-type-v1-refused",
    "gateway.policy.evaluator-unregistered engine before-claim existing - B:evaluator-v1-refused",
    "gateway.policy.expanded engine before-claim existing - B:child-raises-sum-limit",
    "gateway.policy.partition-denied engine before-claim new 4 B:partition-value-not-listed",
    "gateway.policy.scope-denied engine before-claim new 4 A:account-scope-outside-grant",
    "gateway.policy.sum-exhausted ReserveRefusal recorded new 4 B:siblings-exceed-parent-sum",
    "gateway.policy.sum-required engine before-claim new 4 B:sum-required-unbounded-action",
    "gateway.policy.too-many-bounds engine before-claim new 4 B:seventeen-links-refused",
    "gateway.policy.window-exhausted ReserveRefusal recorded changed 4 B:siblings-exceed-parent-count",
    "gateway.pre-entry.condition-false engine recorded new 3 A:pre-entry-replaced-after-observation",
    "gateway.pre-entry.observer-unavailable engine before-claim new 3 A:pre-entry-observer-unavailable",
    "gateway.pre-entry.requirement-missing engine before-claim new 3 A:pre-entry-requirement-missing",
    "gateway.pre-entry.unavailable engine recorded new 3 A:pre-entry-unavailable",
    "gateway.relative-ceiling.above engine recorded new 3 A:relative-ceiling-above",
    "gateway.relative-ceiling.binding-mismatch engine recorded new 3 A:relative-binding-mismatch",
    "gateway.relative-ceiling.unavailable engine recorded new 3 A:relative-basis-unavailable",
    "gateway.transport.not-entered engine recorded new 3 A:transport-not-entered",
    "gateway.trust.key-aliased install install-and-serve new 5 -",
    "gateway.trust.observer-key-in-authority-chain engine before-claim new 5 -",
    "gateway.observer.credential-guard observer observe new 3 -",
    "gateway.admin.credential-account admin admin new 3 -",
    "gateway.admin.credential-capability admin admin new 3 -",
    "gateway.admin.credential-guard admin admin new 3 -",
    "gateway.admin.credential-probe admin admin new 3 -",
    "gateway.admin.generation-conflict admin admin new 5 -",
    "gateway.admin.peer-refused admin admin existing - -",
    "gateway.admin.reobserved admin admin new 5 -",
    "gateway.admin.status admin admin new 5 -",
    "gateway.install.connection-exists install install new 5 -",
    "gateway.install.credential-account install install new 3 -",
    "gateway.install.credential-capability install install new 3 -",
    "gateway.install.credential-guard install install new 3 -",
    "gateway.install.credential-probe install install new 3 -",
    "gateway.install.join-commitment-mismatch install install new 5 -",
    "gateway.install.join-record-missing install install new 5 -",
    "gateway.install.operator-attestation-invalid install install new 5 -",
    "gateway.install.operator-attestation-required install install new 5 -",
    "gateway.reobserve.not-observable admin admin new 5 -",
    "gateway.serve.accept-failed serve serve existing - -",
    "gateway.serve.descriptor-limit serve serve new 5 -",
    "audit.bound-exceeded audit audit new 4 B:audit-count-capacity-three-and-one",
    "audit.counters-mismatch audit audit new 6 -",
    "audit.outcome-invalid audit audit existing - O:outcome-v1-schema",
    "audit.pre-entry-invalid audit audit new 6 -",
    "audit.pre-entry-missing audit audit new 6 -",
    "audit.pre-entry-unsatisfied audit audit new 6 -",
    "audit.relative-ceiling-exceeded audit audit new 6 -",
    "audit.relative-ceiling-missing audit audit new 6 -",
    "audit.sum-exceeded audit audit new 4 B:audit-sum-exceeded",
    "gateway.echo-verify.absent echo-verify echo-verify new 6 -",
    "gateway.echo-verify.action-invalid echo-verify echo-verify new 6 -",
    "gateway.echo-verify.match echo-verify echo-verify new 6 -",
    "gateway.echo-verify.mismatch echo-verify echo-verify new 6 -",
    "gateway.echo-verify.pointer-invalid echo-verify echo-verify new 6 -",
    "gateway.echo-verify.record-invalid echo-verify echo-verify new 6 -",
];

fn fixture(letter: &str) -> &'static str {
    match letter {
        "R" => recipes::FILE,
        "A" => attempts::FILE,
        "B" => bounds::FILE,
        "O" => outcomes::FILE,
        _ => panic!("unknown fixture letter {letter}"),
    }
}

fn row(text: &str) -> Value {
    let fields: Vec<&str> = text.split(' ').collect();
    let [code, owner, stage, status, epic, case] = fields[..] else {
        panic!("malformed row {text}");
    };
    let epic = (epic != "-").then(|| epic.parse::<u8>().expect("epic"));
    let case = case
        .split_once(':')
        .map(|(letter, id)| json!({"fixture": fixture(letter), "id": id}));
    json!({"code": code, "owner": owner, "stage": stage, "status": status, "epic": epic, "case": case})
}

fn document() -> Value {
    let mut rows: Vec<&str> = ROWS.to_vec();
    rows.sort_unstable();
    json!({"schema": SCHEMA, "codes": rows.into_iter().map(row).collect::<Vec<_>>()})
}

#[test]
fn code_inventory_is_current() {
    require_current(FILE, &document());
}

/// Every string under a `code` key anywhere in `value`.
fn expected_codes(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, member) in object {
                if let ("code", Value::String(code)) = (key.as_str(), member) {
                    found.insert(code.clone());
                }
                expected_codes(member, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| expected_codes(item, found)),
        _ => {}
    }
}

/// Code families the revision introduced whole: every code under one of
/// these prefixes that the crate defines must be in the inventory.
const REVISION_FAMILIES: &[&str] = &[
    "gateway.account-scope.",
    "gateway.echo-verify.",
    "gateway.pre-entry.",
    "gateway.relative-ceiling.",
];

/// Every string literal in `text` that starts with `prefix` and continues
/// with code characters.
fn literals_with_prefix(text: &str, prefix: &str) -> BTreeSet<String> {
    let quoted = format!("\"{prefix}");
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(index) = rest.find(&quoted) {
        let tail = &rest[index + 1..];
        let end = tail
            .find(|character: char| {
                !(character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '.' | '-'))
            })
            .unwrap_or(tail.len());
        if tail[end..].starts_with('"') {
            found.insert(tail[..end].to_owned());
        }
        rest = &tail[end..];
    }
    found
}

/// Every listed code exists in the crate and every named case produces it;
/// every code a vector expects is listed; and every code the crate defines
/// in a family the revision introduced whole is listed.
#[test]
fn gateway_codes_inventory_is_closed() {
    let inventory = load(FILE);
    let sources = crate_sources();
    let mut listed = BTreeSet::new();
    for entry in inventory["codes"].as_array().expect("codes") {
        let code = entry["code"].as_str().expect("code");
        assert!(listed.insert(code.to_owned()), "duplicate {code}");
        assert!(crate_defines_code(&sources, code), "{code} is missing");
        if let Some(case) = entry["case"].as_object() {
            let fixture = load(case["fixture"].as_str().expect("fixture"));
            let cases = fixture
                .get("cases")
                .or_else(|| fixture.get("refused"))
                .and_then(Value::as_array)
                .expect("cases");
            let found = cases
                .iter()
                .find(|candidate| candidate["id"] == case["id"])
                .expect("named case");
            let mut produced = BTreeSet::new();
            expected_codes(found, &mut produced);
            assert!(
                produced.contains(code),
                "{code} is not produced by {}",
                case["id"]
            );
        }
    }
    let mut expected = BTreeSet::new();
    for name in [recipes::FILE, attempts::FILE, bounds::FILE, outcomes::FILE] {
        let mut fixture = load(name);
        // Verdict cases carry the native verifier's codes, not gateway codes.
        if let Some(object) = fixture.as_object_mut() {
            object.remove("verdicts");
        }
        expected_codes(&fixture, &mut expected);
    }
    let missing: Vec<_> = expected.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "codes without an inventory entry: {missing:?}"
    );
    let mut defined = BTreeSet::new();
    for (_, text) in &sources {
        for prefix in REVISION_FAMILIES {
            defined.extend(literals_with_prefix(text, prefix));
        }
    }
    let unlisted: Vec<_> = defined.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "revision codes the inventory does not list: {unlisted:?}"
    );
}
