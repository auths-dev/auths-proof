//! The committed seeds reach past each target's first refusal, so a short
//! campaign exercises the rules each target checks rather than only its
//! parser's front door.

use auths_gateway::{CompiledRecipe, GatewayAttemptStage, fuzzing};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{fs, path::PathBuf};

const TARGETS: [&str; 5] = [
    "target_gateway_recipe",
    "target_gateway_request",
    "target_gateway_attempt",
    "target_gateway_outcome",
    "target_gateway_app_frame",
];

fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target);
    let mut found: Vec<_> = fs::read_dir(&directory)
        .expect("committed corpus")
        .map(|entry| {
            let path = entry.expect("corpus entry").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("seed name")
                .to_owned();
            (name, fs::read(&path).expect("seed bytes"))
        })
        .collect();
    found.sort();
    found
}

fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let length = usize::try_from(u32::from_be_bytes(
        data[..4].try_into().expect("length prefix"),
    ))
    .expect("length");
    (&data[4..4 + length], &data[4 + length..])
}

#[test]
fn every_target_has_committed_seeds() {
    for target in TARGETS {
        assert!(!seeds(target).is_empty(), "{target} has no seeds");
    }
}

#[test]
fn recipe_seeds_compile() {
    for (name, data) in seeds("target_gateway_recipe") {
        let (source, lock) = split(&data);
        assert!(CompiledRecipe::compile(source, lock).is_ok(), "{name}");
    }
}

#[test]
fn request_seeds_build_a_closed_request() {
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../bindings/fixtures/gateway");
    let recipes: Vec<CompiledRecipe> = ["airtable", "github", "todoist"]
        .iter()
        .map(|service| {
            CompiledRecipe::compile(
                &fs::read(fixtures.join(service).join("recipe.json")).expect("recipe"),
                &fs::read(fixtures.join(service).join("profile.lock.json")).expect("lock"),
            )
            .expect("fixture recipe")
        })
        .collect();
    for (name, data) in seeds("target_gateway_request") {
        let recipe = &recipes[usize::from(data[0]) % recipes.len()];
        let Value::Object(mut arguments) = serde_json::from_slice(&data[1..]).expect("arguments")
        else {
            panic!("{name} is not an object");
        };
        arguments.insert(
            "operator_namespace".to_owned(),
            Value::String(recipe.namespace().as_str().to_owned()),
        );
        arguments.insert(
            "recipe_digest".to_owned(),
            Value::String(recipe.digest_hex()),
        );
        let commitment: [u8; 32] = Sha256::digest(&data[1..]).into();
        assert!(
            fuzzing::closed_request(recipe, &arguments, commitment).is_ok(),
            "{name}"
        );
    }
}

#[test]
fn attempt_seeds_are_records_and_valid_transitions() {
    for (name, data) in seeds("target_gateway_attempt") {
        if name.starts_with("transition-") {
            let (old, new) = split(&data);
            assert_eq!(
                fuzzing::attempt_stage(old),
                Some(GatewayAttemptStage::Attempting),
                "{name}"
            );
            assert_eq!(fuzzing::attempt_transition(old, new), Some(true), "{name}");
        } else {
            assert!(fuzzing::attempt_stage(&data).is_some(), "{name}");
        }
    }
}

#[test]
fn outcome_seeds_verify_or_are_refused_as_named() {
    let observer = fuzzing::test_observer(0x5a);
    for (name, data) in seeds("target_gateway_outcome") {
        let verified = fuzzing::verify_outcome(&data, &observer);
        assert_eq!(verified.is_some(), name != "outcome-v1-schema", "{name}");
    }
}

#[cfg(unix)]
#[test]
fn frame_seeds_parse_as_their_closed_schemas() {
    for (name, data) in seeds("target_gateway_app_frame") {
        let parsed = fuzzing::app_frame_kind(&data).is_some()
            || auths_gateway::admin::parse_admin_request(&data).is_ok();
        assert!(parsed, "{name}");
    }
}
