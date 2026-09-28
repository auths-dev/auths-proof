//! Request construction on the fixture recipes and arbitrary arguments:
//! construction never panics; an accepted URL stays in the recipe's origin
//! with no query or fragment and the recipe's segment count; the body stays
//! in its bound; the echo token and key match their derivations; and an
//! account-scope header appears exactly when declared, carrying the
//! verified value.
//!
//! Input: one byte selecting a fixture recipe, then a JSON object of
//! arguments. The namespace and recipe digest are always the recipe's own,
//! so construction reaches past the identity check.

#![no_main]

use auths_gateway::{CompiledRecipe, LogicalOperationId, echo_token, fuzzing, idempotency_key};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;

const MAX_BODY_BYTES: usize = 16 * 1024;

const FIXTURES: [(&[u8], &[u8]); 3] = [
    (
        include_bytes!("../../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    ),
    (
        include_bytes!("../../../../../bindings/fixtures/gateway/github/recipe.json"),
        include_bytes!("../../../../../bindings/fixtures/gateway/github/profile.lock.json"),
    ),
    (
        include_bytes!("../../../../../bindings/fixtures/gateway/todoist/recipe.json"),
        include_bytes!("../../../../../bindings/fixtures/gateway/todoist/profile.lock.json"),
    ),
];

fn recipes() -> &'static [Option<CompiledRecipe>] {
    static RECIPES: OnceLock<Vec<Option<CompiledRecipe>>> = OnceLock::new();
    RECIPES.get_or_init(|| {
        FIXTURES
            .iter()
            .map(|(source, lock)| CompiledRecipe::compile(source, lock).ok())
            .collect()
    })
}

/// The origin and the number of path segments of the recipe's write.
fn write_shape(source: &[u8]) -> Option<(String, usize)> {
    let value: Value = serde_json::from_slice(source).ok()?;
    let origin = value
        .get("origin")?
        .as_str()?
        .trim_end_matches('/')
        .to_owned();
    let segments = value.pointer("/write/path")?.as_array()?.len();
    Some((origin, segments))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let index = usize::from(selector) % FIXTURES.len();
    let Some(Some(recipe)) = recipes().get(index) else {
        return;
    };
    let Ok(Value::Object(mut arguments)) = serde_json::from_slice::<Value>(rest) else {
        return;
    };
    arguments.insert(
        "operator_namespace".to_owned(),
        Value::String(recipe.namespace().as_str().to_owned()),
    );
    arguments.insert(
        "recipe_digest".to_owned(),
        Value::String(recipe.digest_hex()),
    );
    let commitment: [u8; 32] = Sha256::digest(rest).into();
    let Ok(request) = fuzzing::closed_request(recipe, &arguments, commitment) else {
        return;
    };
    let Some((origin, segments)) = write_shape(FIXTURES[index].0) else {
        panic!("a fixture recipe has an origin and a write path");
    };
    let url = request.url();
    let Some(path) = url.strip_prefix(&origin) else {
        panic!("the write left the recipe origin: {url}");
    };
    assert!(
        !url.contains('?') && !url.contains('#'),
        "query or fragment in {url}"
    );
    assert_eq!(
        path.split('/').skip(1).count(),
        segments,
        "segment count of {url}"
    );
    assert!(request.body().len() <= MAX_BODY_BYTES);
    let operation = arguments
        .get("operation_id")
        .and_then(Value::as_str)
        .and_then(|value| LogicalOperationId::parse(value).ok());
    let Some(operation) = operation else {
        panic!("an accepted request has a valid operation ID");
    };
    if let Some(token) = request.echo_token() {
        assert_eq!(
            token,
            echo_token(recipe.namespace(), &operation, &commitment)
        );
    }
    if let Some(key) = request.idempotency_key() {
        assert_eq!(key, idempotency_key(recipe.namespace(), &operation));
    }
    let scoped = scope_headers(request.headers(), recipe, &arguments);
    assert!(scoped, "account-scope header in {url}");
});

/// An account-scope header is present exactly when the recipe declares a
/// scope field, and then carries that field's verified value.
fn scope_headers(
    headers: &[auths_gateway::RequestHeader],
    recipe: &CompiledRecipe,
    arguments: &Map<String, Value>,
) -> bool {
    let scoped: Vec<_> = headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case("Stripe-Account"))
        .collect();
    match fuzzing::account_scope_field(recipe) {
        None => scoped.is_empty(),
        Some(field) => {
            scoped.len() == 1
                && arguments.get(&field).and_then(Value::as_str) == Some(scoped[0].value())
        }
    }
}
