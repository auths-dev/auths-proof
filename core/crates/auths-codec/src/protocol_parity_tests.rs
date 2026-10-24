//! Whole-object parity against the frozen pre-refactor production algorithms.

extern crate std;

use crate::{protocol_reference as former, *};
use alloc::vec::Vec;
use auths_model::VerifierLimits;
use proptest::prelude::*;
use std::{fs, path::{Path, PathBuf}};

fn compare_approval_signing(
    statement: &auths_model::ApprovalStatement,
    descriptor: &auths_model::SignatureDescriptor,
) {
    for (identifier, version) in [("test-parity", 1), ("other-parity", 1), ("test-parity", u16::MAX)] {
        let profile = auths_model::ProfileRef::new(
            auths_model::ProfileId::parse(identifier).unwrap(), version).unwrap();
        assert_eq!(approval_signing_preimage(statement, descriptor, &profile),
            former::approval_signing_preimage(statement, descriptor, &profile));
    }
}

#[test]
fn recursive_plan_variants_preserve_frozen_bytes_and_ids() {
    use auths_model::{AuthorizationPlan as Plan, ProofRef};
    let leaf = |identifier| Plan::proof(ProofRef::new([identifier; 32]));
    let nested = Plan::all_of(alloc::vec![
        leaf(1),
        Plan::any_of(alloc::vec![
            leaf(2),
            Plan::k_of_n(1, alloc::vec![leaf(3), leaf(4)]).unwrap(),
        ]).unwrap(),
    ]).unwrap();
    for plan in [
        leaf(0),
        Plan::all_of(alloc::vec![leaf(2), leaf(1)]).unwrap(),
        Plan::any_of(alloc::vec![leaf(2), leaf(1)]).unwrap(),
        Plan::k_of_n(1, alloc::vec![leaf(2), leaf(1)]).unwrap(),
        Plan::k_of_n(2, alloc::vec![leaf(2), leaf(1)]).unwrap(),
        nested,
    ] {
        assert_eq!(encode_authorization_plan(&plan), former::encode_authorization_plan(&plan));
        assert_eq!(plan_id(&plan), former::plan_id(&plan));
    }
}

#[test]
fn observation_requirement_variants_preserve_frozen_bytes_and_ids() {
    use auths_model::{
        ConditionTest, FactBytes, FactName, FactText, FactValue, MemberValues,
        ObservationCondition, ObservationRequirement, ObservationRequirements,
        ObservationSchemaId, ObservationSubject, ObserverAnchorId, ResourceId, UintRange,
    };
    let name = |value| FactName::parse(value).unwrap();
    let values = alloc::vec![
        FactValue::Uint(0),
        FactValue::Bytes(FactBytes::new(alloc::vec![0, 255]).unwrap()),
        FactValue::Text(FactText::new("quoted \"value\" / λ".into()).unwrap()),
    ];
    let tests = alloc::vec![
        ConditionTest::EqLiteral(values[0].clone()),
        ConditionTest::EqLiteral(values[1].clone()),
        ConditionTest::EqLiteral(values[2].clone()),
        ConditionTest::EqAction(name("action-value")),
        ConditionTest::UintRange(UintRange::new(0, u64::MAX).unwrap()),
        ConditionTest::UintRange(UintRange::new(7, 7).unwrap()),
        ConditionTest::Member(MemberValues::new(values).unwrap()),
    ];
    for subject in [
        ObservationSubject::Resource(ResourceId::parse("test:resource").unwrap()),
        ObservationSubject::ActionFact(name("subject-value")),
    ] {
        for test in &tests {
            let requirement = ObservationRequirement::new(
                ObserverAnchorId::parse("test:observer").unwrap(),
                ObservationSchemaId::parse("test:schema").unwrap(),
                subject.clone(),
                86_400,
                alloc::vec![ObservationCondition::new(name("observed-value"), test.clone())],
            ).unwrap();
            assert_eq!(encode_observation_requirement(&requirement), former::encode_observation_requirement(&requirement));
            assert_eq!(observation_requirement_id(&requirement), former::observation_requirement_id(&requirement));
            let requirements = ObservationRequirements::new(alloc::vec![requirement]).unwrap();
            let encoded = encode_observation_requirements(&requirements).unwrap();
            assert_eq!(encoded, former::encode_observation_requirements(&requirements).unwrap());
            assert_eq!(decode_observation_requirements(&encoded).unwrap(), requirements);
        }
    }
}

#[test]
fn approval_requirement_boundaries_preserve_frozen_bytes_and_ids() {
    use auths_model::{ApprovalRequirement, PrincipalId};
    for count in [1, 2, 16] {
        let approvers: Vec<_> = (0..count).map(|position| {
            PrincipalId::parse(alloc::format!("test:approver-{position:02}")).unwrap()
        }).collect();
        for threshold in [1, u16::try_from(count).unwrap()] {
            let requirement = ApprovalRequirement::new(approvers.clone(), threshold).unwrap();
            assert_eq!(encode_approval_requirement(&requirement), former::encode_approval_requirement(&requirement));
            assert_eq!(approval_requirement_id(&requirement), former::approval_requirement_id(&requirement));
        }
    }
}

#[test]
fn approval_canonical_carrier_round_trips_exactly() {
    use auths_model::{ApprovalRequirement, ApprovalRequirements, PrincipalId};
    let first = ApprovalRequirement::new(
        alloc::vec![PrincipalId::parse("test:approver-a").unwrap()], 1).unwrap();
    let second = ApprovalRequirement::new(
        alloc::vec![PrincipalId::parse("test:approver-b").unwrap()], 1).unwrap();
    let seed = alloc::vec![first, second];
    let canonical: Vec<_> = crate::approval::sorted_approval_requirements(&seed).unwrap()
        .into_iter().map(|(_, requirement)| requirement.clone()).collect();
    let mut opposite = canonical.clone();
    opposite.reverse();
    let original = ApprovalRequirements::new(opposite).unwrap();
    let normalized = ApprovalRequirements::new(canonical).unwrap();
    assert_ne!(original, normalized);
    let canonical = crate::CanonicalApprovalRequirements::new(original.clone()).unwrap();
    assert_eq!(canonical.as_value(), &normalized);
    let encoded = crate::encode_approval_requirements(&canonical).unwrap();
    assert_eq!(encoded, former::encode_approval_requirements(&original).unwrap());
    assert_eq!(encoded, former::encode_approval_requirements(&normalized).unwrap());
    let decoded = crate::decode_approval_requirements(&encoded).unwrap();
    assert_eq!(decoded, canonical);
    assert_eq!(decoded.as_value(), &normalized);
    assert_ne!(decoded.as_value(), &original);
    let rebuilt = crate::CanonicalApprovalRequirements::new(canonical.into_value()).unwrap();
    assert_eq!(rebuilt, decoded);
}

macro_rules! compare_limited {
    ($input:expr, $limits:expr, $($decode:ident => $encode:ident),+ $(,)?) => {$ (
        let actual = crate::$decode($input, $limits);
        let expected = former::$decode($input, $limits);
        assert_eq!(actual, expected, "{}: input={:?}, limits={:?}", stringify!($decode), $input, $limits);
        if let Ok(value) = actual {
            assert_eq!(crate::$encode(&value), former::$encode(&value), "{}", stringify!($encode));
        }
    )+};
}

macro_rules! compare_unlimited {
    ($input:expr, $($decode:ident => $encode:ident),+ $(,)?) => {$ (
        let actual = crate::$decode($input);
        let expected = former::$decode($input);
        assert_eq!(actual, expected, "{}: input={:?}", stringify!($decode), $input);
        if let Ok(value) = actual {
            assert_eq!(crate::$encode(&value), former::$encode(&value), "{}", stringify!($encode));
        }
    )+};
}

macro_rules! compare_canonical_limited {
    ($input:expr, $limits:expr, $($decode:ident => $encode:ident),+ $(,)?) => {$ (
        let actual = crate::$decode($input, $limits);
        let expected = former::$decode($input, $limits);
        assert_eq!(actual.as_ref().map(|value| value.as_value()), expected.as_ref(),
            "{}: input={:?}, limits={:?}", stringify!($decode), $input, $limits);
        if let Ok(value) = actual {
            assert_eq!(crate::$encode(&value), former::$encode(value.as_value()), "{}", stringify!($encode));
        }
    )+};
}

macro_rules! compare_canonical_unlimited {
    ($input:expr, $($decode:ident => $encode:ident),+ $(,)?) => {$ (
        let actual = crate::$decode($input);
        let expected = former::$decode($input);
        assert_eq!(actual.as_ref().map(|value| value.as_value()), expected.as_ref(),
            "{}: input={:?}", stringify!($decode), $input);
        if let Ok(value) = actual {
            assert_eq!(crate::$encode(&value), former::$encode(value.as_value()), "{}", stringify!($encode));
        }
    )+};
}

fn compare(input: &[u8], limits: &VerifierLimits) {
    compare_limited!(input, limits,
        decode_canonical_action => encode_canonical_action,
        decode_grant_statement => encode_grant_statement,
        decode_signed_grant => encode_signed_grant,
        decode_action_envelope => encode_action_envelope,
        decode_signed_action => encode_signed_action,
        decode_principal_status_statement => encode_principal_status_statement,
        decode_signed_principal_status => encode_signed_principal_status,
        decode_grant_status_statement => encode_grant_status_statement,
        decode_signed_grant_status => encode_signed_grant_status,
    );
    compare_unlimited!(input,
        decode_observation_requirements => encode_observation_requirements,
        decode_approval_statement => encode_approval_statement,
    );
    compare_canonical_limited!(input, limits,
        decode_bundle => encode_bundle,
        decode_principal_status_snapshot => encode_principal_status_snapshot,
        decode_grant_status_snapshot => encode_grant_status_snapshot,
        decode_signed_approval => encode_signed_approval,
        decode_signed_observation => encode_signed_observation,
    );
    compare_canonical_unlimited!(input,
        decode_verifier_context => encode_verifier_context,
        decode_approval_requirements => encode_approval_requirements,
        decode_verification_result => encode_verification_result,
        decode_bounded_policy_commitment => encode_bounded_policy_commitment,
    );
    if let Ok(observation) = decode_signed_observation(input, limits) {
        let statement = observation.statement();
        let descriptor = observation.signature().descriptor();
        assert_eq!(encode_observation_statement(statement), former::encode_observation_statement(statement));
        assert_eq!(encode_observation_signing_input(statement, descriptor), former::encode_observation_signing_input(statement, descriptor));
        assert_eq!(observation_signing_preimage(statement, descriptor), former::observation_signing_preimage(statement, descriptor));
    }
    if let Ok(approval) = decode_signed_approval(input, limits) {
        let statement = approval.statement();
        let descriptor = approval.signature().descriptor();
        assert_eq!(encode_approval_signing_input(statement, descriptor), former::encode_approval_signing_input(statement, descriptor));
        compare_approval_signing(statement, descriptor);
    }
}

fn compare_nested(bundle: &auths_model::ProofBundle) {
    assert_eq!(encode_authorization_plan(bundle.plan()), former::encode_authorization_plan(bundle.plan()));
    assert_eq!(plan_id(bundle.plan()), former::plan_id(bundle.plan()));
    assert_eq!(proof_digest(bundle), former::proof_digest(bundle));
    for grant in bundle.grants() {
        let statement = grant.statement();
        let descriptor = grant.signature().descriptor();
        assert_eq!(encode_signed_grant(grant), former::encode_signed_grant(grant));
        assert_eq!(encode_grant_statement(statement), former::encode_grant_statement(statement));
        assert_eq!(encode_grant_signing_input(statement, descriptor), former::encode_grant_signing_input(statement, descriptor));
        assert_eq!(grant_signing_preimage(statement, descriptor), former::grant_signing_preimage(statement, descriptor));
        assert_eq!(grant_id(statement), former::grant_id(statement));
        for extension in statement.extensions().as_slice() {
            compare(extension.bytes(), &VerifierLimits::default());
        }
    }
    for action in bundle.actions() {
        let envelope = action.envelope();
        let descriptor = action.signature().descriptor();
        assert_eq!(encode_signed_action(action), former::encode_signed_action(action));
        assert_eq!(encode_action_envelope(envelope), former::encode_action_envelope(envelope));
        assert_eq!(encode_action_signing_input(envelope, descriptor), former::encode_action_signing_input(envelope, descriptor));
        assert_eq!(action_signing_preimage(envelope, descriptor), former::action_signing_preimage(envelope, descriptor));
        assert_eq!(action_id(envelope), former::action_id(envelope));
    }
    for status in bundle.principal_status() {
        let statement = status.statement();
        let descriptor = status.signature().descriptor();
        assert_eq!(encode_signed_principal_status(status), former::encode_signed_principal_status(status));
        assert_eq!(encode_principal_status_signing_input(statement, descriptor), former::encode_principal_status_signing_input(statement, descriptor));
        assert_eq!(principal_status_signing_preimage(statement, descriptor), former::principal_status_signing_preimage(statement, descriptor));
        assert_eq!(principal_status_id(statement), former::principal_status_id(statement));
    }
    for status in bundle.grant_status() {
        let statement = status.statement();
        let descriptor = status.signature().descriptor();
        assert_eq!(encode_signed_grant_status(status), former::encode_signed_grant_status(status));
        assert_eq!(encode_grant_status_signing_input(statement, descriptor), former::encode_grant_status_signing_input(statement, descriptor));
        assert_eq!(grant_status_signing_preimage(statement, descriptor), former::grant_status_signing_preimage(statement, descriptor));
        assert_eq!(grant_status_id(statement), former::grant_status_id(statement));
    }
    for approval in bundle.approvals() {
        let statement = approval.statement();
        let descriptor = approval.signature().descriptor();
        let canonical = CanonicalSignedApproval::new(approval.clone()).unwrap();
        assert_eq!(encode_signed_approval(&canonical), former::encode_signed_approval(approval));
        assert_eq!(encode_approval_signing_input(statement, descriptor), former::encode_approval_signing_input(statement, descriptor));
        compare_approval_signing(statement, descriptor);
        assert_eq!(approval_digest(approval), former::approval_digest(approval));
    }
    for object in bundle.evidence() {
        assert_eq!(evidence_id(object), former::evidence_id(object));
    }
}

fn fixture_files(root: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(root).unwrap().map(Result::unwrap).collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            fixture_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "cbor") {
            files.push(path);
        }
    }
}

fn corpus() -> Vec<PathBuf> {
    let mut files = Vec::new();
    fixture_files(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1"), &mut files);
    assert!(!files.is_empty(), "canonical fixture corpus must be present");
    files
}

#[test]
fn canonical_objects_and_signing_wrappers_match_frozen_source() {
    for path in corpus() {
        let input = fs::read(&path).unwrap();
        compare(&input, &VerifierLimits::default());
        if let Ok(bundle) = decode_bundle(&input, &VerifierLimits::default()) {
            compare_nested(&bundle);
        }
        if let Ok(action) = decode_canonical_action(&input, &VerifierLimits::default()) {
            for attachment in action.detached_attachments() {
                compare(attachment.bytes(), &VerifierLimits::default());
            }
        }
        if let Ok(context) = decode_verifier_context(&input) {
            assert_eq!(context_digest(&context), former::context_digest(&context));
            assert_eq!(context_digest_and_size(&context).unwrap(), (
                former::context_digest(&context).unwrap(),
                former::encode_verifier_context(&context).unwrap().len(),
            ));
        }
        if let Ok(result) = decode_verification_result(&input) {
            assert_eq!(verification_result_digest(&result), former::verification_result_digest(&result));
        }
    }
}

#[test]
fn malformed_and_truncated_corpus_preserves_typed_error_precedence() {
    let limits = VerifierLimits::default();
    for path in corpus() {
        let input = fs::read(&path).unwrap();
        // Each object is tested with missing heads/tails, noncanonical trailing
        // data and mutations throughout its bytes, including nested schemas.
        for end in [0, 1, 2, 8, input.len() / 2, input.len().saturating_sub(1)] {
            compare(&input[..end.min(input.len())], &limits);
        }
        let mut trailing = input.clone();
        trailing.push(0);
        compare(&trailing, &limits);
        for part in 0..16 {
            if input.is_empty() {
                break;
            }
            let index = part * (input.len() - 1) / 15;
            for mask in [1, 0x80, 0xff] {
                let mut mutated = input.clone();
                mutated[index] ^= mask;
                compare(&mutated, &limits);
            }
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_and_deployment_refusals_match_frozen_source(
        input in proptest::collection::vec(any::<u8>(), 0..1024),
        action_limit in 0usize..1024,
    ) {
        compare(&input, &VerifierLimits::default());
        // A valid reduced limit exercises preparse refusals. A zero limit,
        // where the model refuses it, is covered by explicit malformed limits
        // in the existing source cases rather than treated as valid here.
        if let Ok(limits) = VerifierLimits::default().with_limit(auths_model::LimitKind::ActionBytes, action_limit) {
            compare(&input, &limits);
        }
    }
}
