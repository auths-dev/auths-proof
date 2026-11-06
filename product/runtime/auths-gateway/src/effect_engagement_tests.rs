//! Real native enrollment and effect compilation, separate from operation entry.
use super::*;
use crate::effect::{EffectBindingError, EngagementPolicy};
use std::sync::Arc;

#[path = "effect_engagement_admission_tests.rs"]
mod admission_tests;

#[path = "effect_engagement_information_tests.rs"]
mod information_tests;

#[path = "effect_engagement_prerequisite_tests.rs"]
mod prerequisite_tests;

#[path = "effect_created_resource_tests.rs"]
mod created_resource_tests;

#[cfg(unix)]
#[path = "effect_engagement_delivery_tests.rs"]
mod delivery_tests;

#[cfg(unix)]
#[path = "effect_engagement_control_tests.rs"]
mod control_tests;

fn approve(effect: crate::effect::BoundEffect) -> crate::effect::ApprovedEffect {
    let key = SigningKey::from_bytes(&[29; 32]);
    let request = effect.approval_request(NOW, NOW + 60).unwrap();
    let signature = key.sign(&request.signing_message().unwrap()).to_bytes();
    effect
        .approve(
            request.with_signature(signature),
            &key.verifying_key().to_bytes(),
            NOW,
        )
        .unwrap()
}

fn fixture() -> (
    CompiledRecipe,
    ConnectionRecord,
    crate::participant_enrollment::ParentEnrollmentPins,
    crate::participant_enrollment::EnrollmentTree,
    auths_model::TrustedContext,
    crate::observed_tests::Submission,
) {
    let recipe = recipe(&json!({}), &Value::Null);
    let connection = connection(&recipe);
    let args = json!({"operation_id": "engagement-mutation", "operator_namespace": NAMESPACE,
        "recipe_digest": recipe.digest_hex(), "record_id": RECORD, "replacement": "Approved"});
    let native = crate::participant_enrollment::tests::effect_scope_fixture(
        &recipe,
        &connection,
        args.as_object().unwrap(),
    );
    (
        recipe,
        connection,
        native.root,
        native.tree,
        native.context,
        native.action,
    )
}

fn policy(
    root: crate::participant_enrollment::ParentEnrollmentPins,
    executor: &str,
) -> EffectPolicy {
    EffectPolicy::new(
        "recipe-partition".to_owned(),
        1,
        SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
    )
    .unwrap()
    .with_engagement(EngagementPolicy::new(root, executor.to_owned()).unwrap())
    .unwrap()
}

#[test]
fn native_scoped_effect_requires_exact_installed_root_tree_and_connection() {
    let (recipe, connection, root, tree, trust, action) = fixture();
    let policy = policy(root.clone(), "gateway");
    let installed = policy.installation(
        &recipe,
        &trust,
        &connection,
        crate::QualificationPolicy::Optional,
        [12; 32],
    );
    assert!(compile_mutation_effect(&installed, NOW, &action.proof, &action.action).is_err());
    let installed = installed.with_enrollment(Some(&tree));
    let effect = compile_mutation_effect(&installed, NOW, &action.proof, &action.action).unwrap();
    let binding =
        serde_json::from_slice::<Value>(&effect.binding().to_private_bytes().unwrap()).unwrap();
    assert_eq!(binding["scope"]["kind"], "engagement");
    assert_eq!(
        binding["scope"]["bound"]["ancestors"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(binding["scope"]["bound"]["executor"], "gateway");
    let approved = approve(effect);
    approved.validate_for_entry(&installed, NOW).unwrap();
    for which in ["root", "child"] {
        let mut current = tree.clone();
        let id: [u8; 32] = if which == "root" {
            root.enrollment_commitment
        } else {
            serde_json::from_value(binding["scope"]["bound"]["ancestors"][1]["enrollment"].clone())
                .unwrap()
        };
        current.revoke(id).unwrap();
        assert!(
            approved
                .validate_for_entry(
                    &policy
                        .installation(
                            &recipe,
                            &trust,
                            &connection,
                            crate::QualificationPolicy::Optional,
                            [12; 32]
                        )
                        .with_enrollment(Some(&current)),
                    NOW
                )
                .is_err()
        );
    }
    let mut changed = root.clone();
    changed.scopes[0].connection_binding[0] ^= 1;
    changed.enrollment_commitment =
        crate::participant_enrollment::root_enrollment_commitment(&changed).unwrap();
    let changed = policy_for_changed_root(changed);
    assert!(
        compile_mutation_effect(
            &changed
                .installation(
                    &recipe,
                    &trust,
                    &connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32]
                )
                .with_enrollment(Some(&tree)),
            NOW,
            &action.proof,
            &action.action
        )
        .is_err()
    );
    assert!(approved.validate_for_entry(&installed, NOW + 900).is_err());
}

fn policy_for_changed_root(
    root: crate::participant_enrollment::ParentEnrollmentPins,
) -> EffectPolicy {
    policy(root, "gateway")
}

#[test]
fn exact_scope_review_binds_executor_and_ancestry_with_shared_ancestor_keys() {
    let (recipe, connection, root, tree, trust, action) = fixture();
    let original = policy(root.clone(), "executor-a");
    let other = policy(root, "executor-b");
    let make = |policy: &EffectPolicy| {
        compile_mutation_effect(
            &policy
                .installation(
                    &recipe,
                    &trust,
                    &connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32],
                )
                .with_enrollment(Some(&tree)),
            NOW,
            &action.proof,
            &action.action,
        )
        .unwrap()
    };
    let a = make(&original);
    let b = make(&other);
    assert_ne!(a.binding().id(), b.binding().id());
    let private_a: Value =
        serde_json::from_slice(&a.binding().to_private_bytes().unwrap()).unwrap();
    let private_b: Value =
        serde_json::from_slice(&b.binding().to_private_bytes().unwrap()).unwrap();
    assert_eq!(private_a["reservations"], private_b["reservations"]);
    assert_eq!(private_a["reservations"].as_array().unwrap().len(), 2);
    assert_eq!(
        private_a["reservations"][0]["window"]["kind"],
        "engagement-lifetime"
    );
    let review = a.private_review().unwrap().to_private_bytes().unwrap();
    assert!(std::str::from_utf8(&review).unwrap().contains("executor-a"));
    let approved = approve(a);
    assert!(
        approved
            .validate_for_entry(
                &other
                    .installation(
                        &recipe,
                        &trust,
                        &connection,
                        crate::QualificationPolicy::Optional,
                        [12; 32]
                    )
                    .with_enrollment(Some(&tree)),
                NOW
            )
            .is_err()
    );
}

#[test]
fn decoded_scope_cannot_omit_ancestor_charges_or_invent_a_wider_ancestry() {
    let (recipe, connection, root, tree, trust, action) = fixture();
    let policy = policy(root, "gateway");
    let effect = compile_mutation_effect(
        &policy
            .installation(
                &recipe,
                &trust,
                &connection,
                crate::QualificationPolicy::Optional,
                [12; 32],
            )
            .with_enrollment(Some(&tree)),
        NOW,
        &action.proof,
        &action.action,
    )
    .unwrap();
    let bytes = effect.binding().to_private_bytes().unwrap();
    assert_eq!(
        &EffectBinding::from_private_bytes(&bytes).unwrap(),
        effect.binding()
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    for case in 0..12 {
        let mut changed = value.clone();
        match case {
            0 => {
                changed["reservations"].as_array_mut().unwrap().pop();
            }
            1 => changed["reservations"][0]["ceiling"] = json!(100),
            2 => changed["reservations"][0]["amount"] = json!(0),
            3 => changed["scope"]["bound"]["ancestors"][1]["ceilings"]["writes"] = json!(2),
            4 => {
                changed["scope"]["bound"]["ancestors"][1]["principal"] =
                    changed["scope"]["bound"]["ancestors"][0]["principal"].clone();
            }
            5 => changed["scope"]["bound"]["ancestors"][1]["expires_at"] = json!(NOW + 1000),
            6 => changed["scope"]["bound"]["authority_epoch"] = json!(0),
            7 => changed["scope"]["kind"] = json!("task"),
            8 => changed["scope"] = json!({"kind":"unscoped"}),
            9 => {
                changed["scope"]["bound"]["ancestors"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("capacity_enrollment");
            }
            10 => {
                changed["scope"]["bound"]["ancestors"][0]["capacity_enrollment"] =
                    json!(vec![0; 32]);
            }
            _ => {
                changed["scope"]["bound"]["ancestors"][1]["capacity_enrollment"] =
                    changed["scope"]["bound"]["ancestors"][0]["capacity_enrollment"].clone();
            }
        }
        let encoded = serde_json_canonicalizer::to_vec(&changed).unwrap();
        assert!(
            EffectBinding::from_private_bytes(&encoded).is_err(),
            "case {case}"
        );
    }
    let mut old = value;
    old["schema"] = json!("auths.bound-effect/3");
    assert_eq!(
        EffectBinding::from_private_bytes(&serde_json_canonicalizer::to_vec(&old).unwrap()),
        Err(EffectBindingError::Unsupported)
    );
}

#[test]
fn native_engagement_effect_fixture_is_current() {
    decoded_scope_cannot_omit_ancestor_charges_or_invent_a_wider_ancestry();
    let (recipe, connection, root, tree, trust, action) = fixture();
    let policy = policy(root.clone(), "gateway");
    let effect = compile_mutation_effect(
        &policy
            .installation(
                &recipe,
                &trust,
                &connection,
                crate::QualificationPolicy::Optional,
                [12; 32],
            )
            .with_enrollment(Some(&tree)),
        NOW,
        &action.proof,
        &action.action,
    )
    .unwrap();
    let private_review = serde_json::from_slice::<Value>(
        &effect.private_review().unwrap().to_private_bytes().unwrap(),
    )
    .unwrap();
    let binding: Value =
        serde_json::from_slice(&effect.binding().to_private_bytes().unwrap()).unwrap();
    let document = json!({"schema":"auths.engagement-effect-vectors/1", "generated_by":"native_engagement_effect_fixture_is_current",
        "claims":["native-root-activation", "native-parent-child-resource-enrollment", "native-scoped-mutation-compilation", "exact-ancestry-and-planned-charge-review"],
        "not_established":["atomic-ancestor-admission", "provider-entry", "information-flow-compilation", "independent-enrollment-proof-history", "installed-containment"],
        "root":root, "policy": serde_json::from_slice::<Value>(&policy.to_private_bytes().unwrap()).unwrap(),
        "tree": serde_json::from_slice::<Value>(&tree.encode().unwrap()).unwrap(),
        "proof_hex": hex::encode(&action.proof), "action_hex": hex::encode(&action.action),
        "effect":binding, "private_review": private_review});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/effect.json");
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn acting_child_cannot_supply_its_own_exact_human_approval() {
    let (recipe, connection, root, tree, trust, action) = fixture();
    for (seed, allowed) in [(0x44, false), (0x22, true)] {
        let policy = EffectPolicy::new(
            "recipe-partition".to_owned(),
            1,
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
        .with_engagement(EngagementPolicy::new(root.clone(), "gateway".to_owned()).unwrap())
        .unwrap();
        let result = compile_mutation_effect(
            &policy
                .installation(
                    &recipe,
                    &trust,
                    &connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32],
                )
                .with_enrollment(Some(&tree)),
            NOW,
            &action.proof,
            &action.action,
        );
        assert_eq!(result.is_ok(), allowed);
    }
}

/// Snapshot-level composition only; actual lock/process schedules belong to
/// the shared adapter admission tests, not this unit case.
#[tokio::test]
async fn entry_snapshots_revalidate_current_enrollment() {
    let setup = admission_tests::Setup::with_recipe(
        crate::store_testkit::Backend::File,
        recipe(&json!({}), &Value::Null),
        [1; 32],
    )
    .await;
    let approved = approve(
        compile_mutation_effect(
            &setup
                .policy
                .installation(
                    &setup.recipe,
                    &setup.native.context,
                    &setup.connection,
                    crate::QualificationPolicy::Optional,
                    [12; 32],
                )
                .with_enrollment(Some(&setup.native.tree)),
            NOW,
            &setup.native.action.proof,
            &setup.native.action.action,
        )
        .unwrap(),
    );
    let validation = setup.validation();
    let dependencies = validation.dependencies(&approved);
    assert_eq!(dependencies.len(), 3);
    assert_eq!(
        dependencies[2],
        (
            crate::GatewayRecordKind::EffectConfiguration,
            setup.controller.dependency_key()
        )
    );
    // Use the current native control owner and retained history, rather than
    // reconstructing a private record format independently in this test.
    let mut snapshots: Vec<_> = dependencies
        .iter()
        .map(|(kind, key)| setup.store.load(*kind, key).unwrap())
        .collect();
    assert_eq!(validation.validate(&approved, &snapshots, NOW), Ok(NOW));
    let current = snapshots[2].clone().unwrap();
    setup
        .controller
        .apply_control(setup.native.withdrawal_evidence(0x44))
        .unwrap();
    snapshots[2] = setup
        .store
        .load(dependencies[2].0, &dependencies[2].1)
        .unwrap();
    assert_eq!(
        validation.validate(&approved, &snapshots, NOW),
        Err("gateway.effect.authority-unavailable")
    );
    // A structurally consistent snapshot accepted beyond the current clock
    // must fail the entry time fence. This is not a historical proof replay.
    let mut future: Value = serde_json::from_slice(&current).unwrap();
    future["accepted_at"] = json!(NOW + 1);
    future["events"].as_array_mut().unwrap().last_mut().unwrap()["accepted_at"] = json!(NOW + 1);
    snapshots[2] = Some(serde_json_canonicalizer::to_vec(&future).unwrap());
    assert_eq!(
        validation.validate(&approved, &snapshots, NOW),
        Err("gateway.engagement.clock-rollback")
    );
    snapshots[2] = None;
    assert_eq!(
        validation.validate(&approved, &snapshots, NOW),
        Err("gateway.engagement.state-unavailable")
    );
}

#[path = "effect_instance_recovery_tests.rs"]
mod instance_recovery_tests;
