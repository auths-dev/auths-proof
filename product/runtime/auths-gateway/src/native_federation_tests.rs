//! ADR0021: real native mixed-method owner proofs and coordinated process
//! histories. All keys/clock/provider are explicit public test fixtures.
use super::*;
use auths_model::{AcceptedRegistries, TrustAnchor, TrustedContext};

fn context_with(
    original: &TrustedContext,
    anchors: Vec<TrustAnchor>,
    registries: AcceptedRegistries,
) -> TrustedContext {
    TrustedContext::new(
        original.configuration(),
        original.composition(),
        anchors,
        registries,
        original.expected_audience().clone(),
        original.expected_challenge(),
        original.evaluation_time(),
        original.assurance_policy().clone(),
        original.principal_status_snapshot().clone(),
        original.grant_status_snapshot().clone(),
        original.resource_matcher().clone(),
        original.profile_policy().clone(),
        original.channel_policy().clone(),
        original.limits().clone(),
    )
    .unwrap()
    .with_observer_anchors(original.observer_anchors().to_vec())
    .unwrap()
}
fn owner_method(anchor: &TrustAnchor, methods: Vec<auths_model::PrincipalMethodId>) -> TrustAnchor {
    TrustAnchor::new(
        anchor.id().clone(),
        anchor.principal().clone(),
        methods,
        anchor.profiles().to_vec(),
        anchor.permissions().clone(),
        anchor.resource_namespaces().to_vec(),
        anchor.audiences().clone(),
        anchor.validity(),
        anchor.budget_ceiling().cloned(),
        anchor.max_delegation_depth(),
        anchor.assurance_policy().clone(),
        anchor.status_policy().clone(),
    )
    .unwrap()
}
fn substituted_proof(
    action: &crate::observed_tests::Submission,
    corrupt_signature: bool,
) -> Vec<u8> {
    use auths_model::{ProofBundle, SignatureBytes, SignatureEnvelope, SignedGrant};
    let bundle =
        auths_codec::decode_bundle(&action.proof, &auths_model::VerifierLimits::default()).unwrap();
    let mut grants = bundle.grants().to_vec();
    let mut evidence = bundle.evidence().to_vec();
    if corrupt_signature {
        let first = &grants[0];
        let mut signature = first.signature().signature().as_slice().to_vec();
        signature[0] ^= 1;
        grants[0] = SignedGrant::new(
            first.statement().clone(),
            SignatureEnvelope::new(
                first.signature().descriptor().clone(),
                SignatureBytes::new(signature).unwrap(),
            ),
        );
    } else {
        evidence.clear();
    }
    auths_codec::encode_bundle(
        &ProofBundle::new(
            bundle.header().clone(),
            grants,
            bundle.actions().to_vec(),
            bundle.plan().clone(),
            evidence,
            bundle.bindings().to_vec(),
            bundle.principal_status().to_vec(),
            bundle.grant_status().to_vec(),
            bundle.attachments().to_vec(),
            bundle.canonical_body().map(<[u8]>::to_vec),
        )
        .unwrap()
        .with_approvals(bundle.approvals().to_vec())
        .unwrap(),
    )
    .unwrap()
}

#[allow(
    clippy::too_many_lines,
    reason = "one complete positive and refusal corpus over independent native issuer paths"
)]
fn trust_boundaries(backend: Backend) -> Value {
    let case = Case::new(backend, true);
    let (_, actions, recipes, records) = native(&case.input);
    let control = crate::harness::Signer::new(0x11);
    let owners = [
        crate::harness::Signer::new(0x12),
        crate::harness::Signer::did_key(0x13),
    ];
    let context = &case.native.context;
    assert_eq!(context.trust_anchors().len(), 3);
    let principals: BTreeSet<_> = context
        .trust_anchors()
        .iter()
        .map(|a| a.principal().as_str())
        .collect();
    assert_eq!(principals.len(), 3);
    assert!(principals.contains(owners[1].principal.as_str()));
    assert_ne!(control.principal, owners[0].principal);
    let compile = |index: usize,
                   trust: &TrustedContext,
                   proof: &[u8],
                   action: &[u8],
                   tree: &crate::participant_enrollment::EnrollmentTree| {
        let policy = policy(case.native.root.clone(), index);
        crate::effect::compile_mutation_effect(
            &policy
                .installation(
                    &recipes[index],
                    trust,
                    &records[index],
                    crate::QualificationPolicy::Optional,
                    case.engines[index]
                        .effect_configuration_candidate()
                        .unwrap(),
                )
                .with_enrollment(Some(tree)),
            NOW,
            proof,
            action,
        )
    };
    let mut refusal_names = Vec::new();
    // Owner A is a genuine accepted issuer, and its independently signed proof
    // authorizes the very same B command in the offline verifier. Only B's
    // pinned enrolled suffix makes it ineligible for B's protected installation.
    let parent = crate::harness::Signer::new(0x22);
    let child = crate::harness::Signer::new(0x55);
    let audience = crate::participant_enrollment::resource_audience(
        &case.native.root.engagement_commitment,
        case.native.root.partition_generation,
        &recipes[1].digest_hex(),
    )
    .unwrap();
    let foreign_parent = crate::participant_enrollment::tests::grant_for_audiences(
        &owners[0],
        &parent,
        recipes[1].service(),
        &[recipes[1].review().tool()],
        None,
        1,
        vec![audience.clone()],
    );
    let foreign_child = crate::participant_enrollment::tests::grant_for_audiences(
        &parent,
        &child,
        recipes[1].service(),
        &[recipes[1].review().tool()],
        Some(auths_codec::grant_id(foreign_parent.statement()).unwrap()),
        0,
        vec![audience.clone()],
    );
    let foreign = crate::participant_enrollment::tests::chained(
        &[&owners[0], &parent, &child],
        &[&foreign_parent, &foreign_child],
        recipes[1].service(),
        recipes[1].review().tool(),
        &arguments(&recipes[1], 1),
    );
    let request_context = context
        .for_request(
            audience,
            context.expected_challenge(),
            auths_model::Timestamp::new(NOW),
        )
        .unwrap();
    assert!(
        crate::engine::verify_detailed(
            &recipes[1],
            &request_context,
            NOW,
            &foreign.proof,
            &foreign.action
        )
        .is_ok()
    );
    assert!(
        compile(
            1,
            context,
            &foreign.proof,
            &foreign.action,
            &case.native.tree
        )
        .is_err()
    );
    refusal_names.push("accepted-foreign-owner-cannot-replace-pinned-resource-path".into());
    for index in 0..2 {
        assert!(
            compile(
                index,
                context,
                &actions[index].proof,
                &actions[index].action,
                &case.native.tree
            )
            .is_ok()
        );
        let without = context_with(
            context,
            context
                .trust_anchors()
                .iter()
                .filter(|anchor| anchor.principal() != &owners[index].principal)
                .cloned()
                .collect(),
            context.accepted_registries().clone(),
        );
        assert!(
            compile(
                index,
                &without,
                &actions[index].proof,
                &actions[index].action,
                &case.native.tree
            )
            .is_err()
        );
        refusal_names.push(format!("missing-resource-owner-{index}"));
        let other = 1 - index;
        assert!(
            compile(
                other,
                context,
                &actions[index].proof,
                &actions[index].action,
                &case.native.tree
            )
            .is_err()
        );
        refusal_names.push(format!("foreign-resource-{index}"));
        for (name, signature) in [
            ("invalid-native-signature", true),
            ("missing-control-evidence", false),
        ] {
            let invalid = substituted_proof(&actions[index], signature);
            assert!(
                compile(
                    index,
                    context,
                    &invalid,
                    &actions[index].action,
                    &case.native.tree
                )
                .is_err()
            );
            refusal_names.push(format!("{name}-{index}"));
        }
    }
    let no_control = context_with(
        context,
        context
            .trust_anchors()
            .iter()
            .filter(|a| a.principal() != &control.principal)
            .cloned()
            .collect(),
        context.accepted_registries().clone(),
    );
    // A resource proof can still be valid without this control issuer, but it
    // cannot bootstrap the exact root's separate activation authority.
    assert!(case.native.bootstrap_with_context(&no_control).is_err());
    refusal_names.push("resource-trust-does-not-activate-control-root".into());
    let wrong_method = context_with(
        context,
        context
            .trust_anchors()
            .iter()
            .map(|anchor| {
                if anchor.principal() == &owners[1].principal {
                    owner_method(
                        anchor,
                        vec![
                            auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)
                                .unwrap(),
                        ],
                    )
                } else {
                    anchor.clone()
                }
            })
            .collect(),
        context.accepted_registries().clone(),
    );
    assert!(
        compile(
            1,
            &wrong_method,
            &actions[1].proof,
            &actions[1].action,
            &case.native.tree
        )
        .is_err()
    );
    refusal_names.push("owner-method-not-accepted".into());
    let mut unapproved = case.native.root.clone();
    unapproved.engagement_commitment = [0xFE; 32];
    unapproved.enrollment_commitment =
        crate::participant_enrollment::root_enrollment_commitment(&unapproved).unwrap();
    assert!(
        crate::participant_enrollment::EnrollmentTree::decode(
            &case.native.tree.encode().unwrap(),
            &unapproved
        )
        .is_err()
    );
    refusal_names.push("unapproved-root-installation".into());
    assert!(crate::principals_overlap(
        &crate::harness::Signer::new(0x13).principal,
        &owners[1].principal
    ));
    assert_eq!(case.provider.count(), 0);
    assert_eq!(case.allocated_rows(), 0);
    case.save_approvals();
    let positive = case.replay(1);
    assert!(matches!(
        positive,
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    assert_eq!(case.provider.count(), 1);
    assert_eq!(case.allocated_rows(), 2);
    assert!(matches!(
        case.replay(1),
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    assert_eq!(case.provider.count(), 1);
    json!({"case":"independently-pinned-mixed-method-owners","issuer_keys":3,
        "methods":[auths_raw_key::RAW_KEY_V1,auths_did_key::DID_KEY_V1],"native_refusals":refusal_names,
        "negative_cases_provider_calls":0,"negative_cases_allocations":0,"native_positive_provider_writes":1,
        "native_positive_allocated_ancestor_rows":2,"replay_new_writes":0,"raw_did_aliases_overlap":true,
        "not_established":["independent-human-administration","global-key-revocation","offline-escrow"]})
}
fn federation_corpus(backend: Backend) -> Value {
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for index in 0..7 {
        match std::panic::catch_unwind(|| match index {
            0 => trust_boundaries(backend),
            1 => race(backend, true),
            2 => independent_engagement(backend, true),
            _ => ordered(backend, index >= 5, index % 2 == 0, true),
        }) {
            Ok(value) => cases.push(value),
            Err(_) => failures.push(index),
        }
    }
    assert!(
        failures.is_empty(),
        "native federation failures: {failures:?}"
    );
    assert_eq!(cases.len(), 7);
    json!({"schema":"auths.coordinated-federation-vectors/1","adapter":backend.label(),"cases":cases,
        "scope":"three distinct fixed-fixture issuer keys, maintained raw-key/did:key adapters, native proof and exact approval, two resource installations, shared adapter fences and real HTTP effects across independent processes",
        "unsupported":["disconnected-escrow","independent-cloned-admission-stores","automatic-trust-rollover"],
        "not_established":["source-free-key-containment","live-provider-qualification","human-presence","independent-operator-consent","power-loss-durability","native-records-qualification","whole-store-rollback-detection","full-AP073-acceptance"]})
}
#[test]
fn native_file_coordinated_federation_fixture_is_current() {
    let bytes = serde_json::to_vec_pretty(&federation_corpus(Backend::File)).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/federation.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
#[ignore = "requires TLS PostgreSQL; the configured hosted selector must execute"]
fn postgres_native_coordinated_federation_matrix() {
    assert!(postgres_configured());
    federation_corpus(Backend::Postgres);
}
