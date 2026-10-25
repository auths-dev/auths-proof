//! Frozen pre-cutover constructor algorithms and source-scan regressions.
//! Synthetic signature bytes below test representation only, not authenticity.

use crate::*;
use alloc::{format, vec, vec::Vec};
use core::cell::Cell;

fn words(alphabet: u8, maximum: u32, mut visit: impl FnMut(Vec<u8>)) {
    for length in 0..=maximum {
        for mut code in 0..usize::from(alphabet).pow(length) {
            let mut values = Vec::new();
            for _ in 0..length {
                values.push((code % usize::from(alphabet)) as u8);
                code /= usize::from(alphabet);
            }
            visit(values);
        }
    }
}

fn original_set<const MAX: usize>(mut values: Vec<u8>) -> Result<Vec<u8>, BoundError> {
    if values.is_empty() {
        return Err(BoundError::Empty);
    }
    if values.len() > MAX {
        return Err(BoundError::AboveMaximum);
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BoundError::Duplicate);
    }
    Ok(values)
}

fn original_approvers(
    mut values: Vec<PrincipalId>,
    threshold: u16,
) -> Result<Vec<PrincipalId>, ModelError> {
    values.sort();
    if values.is_empty()
        || values.len() > MAX_APPROVERS_PER_REQUIREMENT
        || values.windows(2).any(|pair| pair[0] == pair[1])
        || threshold == 0
        || usize::from(threshold) > values.len()
    {
        Err(ModelError::InvalidApprovalRequirement)
    } else {
        Ok(values)
    }
}

fn original_typed_set<T: Ord, const MAX: usize>(mut values: Vec<T>) -> Result<Vec<T>, BoundError> {
    if values.is_empty() {
        return Err(BoundError::Empty);
    }
    if values.len() > MAX {
        return Err(BoundError::AboveMaximum);
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BoundError::Duplicate);
    }
    Ok(values)
}

fn original_extensions(
    mut values: Vec<CriticalExtension>,
) -> Result<Vec<CriticalExtension>, ModelError> {
    if values.len() > HARD_MAX_EXTENSIONS {
        return Err(ModelError::InvalidExtension);
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
        return Err(ModelError::DuplicateExtension);
    }
    Ok(values)
}

fn original_facts(mut values: Vec<ObservationFact>) -> Result<Vec<ObservationFact>, ModelError> {
    if values.is_empty() || values.len() > MAX_OBSERVATION_FACTS {
        return Err(ModelError::InvalidObservation);
    }
    values.sort_by(|left, right| left.name().cmp(right.name()));
    if values.windows(2).any(|pair| pair[0].name() == pair[1].name()) {
        return Err(ModelError::InvalidObservation);
    }
    Ok(values)
}

fn original_evidence(
    mut values: Vec<EvidenceObject>,
    error: ModelError,
) -> Result<Vec<EvidenceObject>, ModelError> {
    if values.len() > 4 {
        return Err(error);
    }
    values.sort_by_key(EvidenceObject::id);
    if values.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
        return Err(error);
    }
    Ok(values)
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::parse(&format!("test:principal-{tag:03}")).unwrap()
}

fn fact(tag: u8, amount: u64) -> ObservationFact {
    ObservationFact::new(FactName::parse(&format!("fact-{tag:03}")).unwrap(), FactValue::Uint(amount))
}

fn evidence(tag: u8, body: u8) -> EvidenceObject {
    EvidenceObject::new(
        EvidenceId::new([tag; 32]),
        EvidenceTypeId::parse("test-evidence").unwrap(),
        MediaType::parse("application/octet-stream").unwrap(),
        vec![body],
    )
    .unwrap()
}

fn signature() -> SignatureEnvelope {
    SignatureEnvelope::new(
        SignatureDescriptor::new(
            PrincipalMethodId::parse("test-method").unwrap(),
            VerificationMethod::parse("test:key").unwrap(),
            SignatureSuiteId::parse("test-suite").unwrap(),
        ),
        SignatureBytes::new(vec![7]).unwrap(),
    )
}

fn window() -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(3), Timestamp::new(5)).unwrap()
}

fn approval_statement() -> ApprovalStatement {
    ApprovalStatement::new(
        principal(1),
        ApprovalRequirementId::new([2; 32]),
        MediaType::parse("application/json").unwrap(),
        Digest::new([3; 32]),
        Permission::new(CapabilityId::parse("write").unwrap(), ResourceId::parse("test:resource").unwrap()),
        None,
        None,
        Audience::parse("test:audience").unwrap(),
        Challenge::new([4; 32]),
        window(),
    )
}

fn observation_statement() -> ObservationStatement {
    ObservationStatement::new(
        principal(2),
        ObservationSchemaId::parse("test-schema").unwrap(),
        ResourceId::parse("test:resource").unwrap(),
        Timestamp::new(4),
        ObservationFacts::new(vec![fact(0, 7)]).unwrap(),
    )
}

#[test]
fn explicit_scans_match_prior_adjacent_and_prefix_semantics() {
    words(3, 7, |values| {
        assert_eq!(collection_scan::adjacent_equal(&values), values.windows(2).any(|pair| pair[0] == pair[1]));
        let original = values.iter().enumerate().any(|(index, value)| values[..index].contains(value));
        assert_eq!(collection_scan::has_duplicates(&values), original);
        for end in 0..=values.len() + 2 {
            for target in 0..=3 {
                assert_eq!(collection_scan::prefix_contains(&values, &target, end), values[..end.min(values.len())].contains(&target));
            }
        }
        assert_eq!(collection_scan::prefix_contains(&values, &4, usize::MAX), values.contains(&4));
        assert_eq!(BoundedSet::<u8, 3>::new(values.clone()).map(BoundedSet::into_vec), original_set::<3>(values));
    });
}

#[test]
fn scans_stop_after_first_match_and_visit_no_unchecked_pair() {
    struct Counted<'a>(u8, &'a Cell<usize>);
    impl PartialEq for Counted<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.1.set(self.1.get() + 1);
            self.0 == other.0
        }
    }
    for (tags, adjacent, adjacent_calls, duplicate, duplicate_calls) in [
        (vec![], false, 0, false, 0),
        (vec![0], false, 0, false, 0),
        (vec![0, 0, 1], true, 1, true, 1),
        (vec![0, 1, 0, 2], false, 3, true, 2),
        (vec![0, 1, 2, 3], false, 3, false, 6),
    ] {
        let calls = Cell::new(0);
        let values: Vec<_> = tags.into_iter().map(|tag| Counted(tag, &calls)).collect();
        assert_eq!(collection_scan::adjacent_equal(&values), adjacent);
        assert_eq!(calls.get(), adjacent_calls);
        calls.set(0);
        assert_eq!(collection_scan::has_duplicates(&values), duplicate);
        assert_eq!(calls.get(), duplicate_calls);
    }
}

#[test]
fn approval_threshold_and_error_precedence_match_prior_constructor() {
    words(3, 6, |tags| {
        let values: Vec<_> = tags.into_iter().map(principal).collect();
        for threshold in 0..=7 {
            let actual = ApprovalRequirement::new(values.clone(), threshold).map(|requirement| {
                assert_eq!(requirement.threshold(), threshold);
                requirement.approvers().to_vec()
            });
            assert_eq!(actual, original_approvers(values.clone(), threshold));
        }
    });
    let exact: Vec<_> = (0..16).map(principal).rev().collect();
    assert!(ApprovalRequirement::new(exact, 16).is_ok());
    assert_eq!(ApprovalRequirement::new(vec![principal(0); 17], 1), Err(ModelError::InvalidApprovalRequirement));
    assert_eq!(BoundedSet::<u8, 2>::new(vec![0, 0, 0]), Err(BoundError::AboveMaximum));
    assert_eq!(BoundedSet::<u8, 0>::new(vec![]), Err(BoundError::Empty));
}

#[test]
fn keyed_constructor_identity_is_the_key_not_the_full_payload() {
    words(3, 5, |tags| {
        let extensions: Vec<_> = tags.iter().enumerate().map(|(position, tag)| {
            CriticalExtension::new(ExtensionId::parse(&format!("extension-{tag}")).unwrap(), vec![position as u8]).unwrap()
        }).collect();
        assert_eq!(CriticalExtensions::new(extensions.clone()).map(|value| value.as_slice().to_vec()), original_extensions(extensions));
        let facts: Vec<_> = tags.iter().enumerate().map(|(position, tag)| fact(*tag, position as u64)).collect();
        assert_eq!(ObservationFacts::new(facts.clone()).map(|value| value.as_slice().to_vec()), original_facts(facts));
        let proof: Vec<_> = tags.iter().enumerate().map(|(position, tag)| evidence(*tag, position as u8)).collect();
        let approval = approval_statement();
        let sig = signature();
        let actual = SignedApproval::new(approval.clone(), sig.clone(), proof.clone()).map(|value| {
            assert_eq!(value.statement(), &approval);
            assert_eq!(value.signature(), &sig);
            value.evidence().to_vec()
        });
        assert_eq!(actual, original_evidence(proof.clone(), ModelError::InvalidApproval));
        let observation = observation_statement();
        let actual = SignedObservation::new(observation.clone(), sig.clone(), proof.clone()).map(|value| {
            assert_eq!(value.statement(), &observation);
            assert_eq!(value.signature(), &sig);
            value.evidence().to_vec()
        });
        assert_eq!(actual, original_evidence(proof, ModelError::InvalidObservation));
    });
    let extensions = vec![CriticalExtension::new(ExtensionId::parse("same-id").unwrap(), vec![]).unwrap(); 33];
    assert_eq!(CriticalExtensions::new(extensions), Err(ModelError::InvalidExtension));
    assert_eq!(ObservationFacts::new(vec![fact(0, 0); 17]), Err(ModelError::InvalidObservation));
}

#[test]
fn ordered_requirements_keep_distinct_values_and_reject_separated_repeats() {
    let first = ApprovalRequirement::new(vec![principal(1), principal(0)], 1).unwrap();
    let second = ApprovalRequirement::new(vec![principal(0), principal(1)], 2).unwrap();
    let raw = vec![second.clone(), first.clone()];
    assert_eq!(ApprovalRequirements::new(raw.clone()).unwrap().as_slice(), raw);
    assert_eq!(ApprovalRequirements::new(vec![first.clone(), second, first]), Err(ModelError::InvalidApprovalRequirement));
    assert_eq!(ApprovalRequirements::new(vec![ApprovalRequirement::new(vec![principal(0)], 1).unwrap(); 5]), Err(ModelError::CollectionLimitExceeded));
    let first = ObservationRequirement::new(
        ObserverAnchorId::parse("observer").unwrap(), ObservationSchemaId::parse("schema").unwrap(),
        ObservationSubject::Resource(ResourceId::parse("test:resource").unwrap()), 1,
        vec![ObservationCondition::new(FactName::parse("amount").unwrap(), ConditionTest::EqLiteral(FactValue::Uint(1)))],
    ).unwrap();
    let second = ObservationRequirement::new(
        ObserverAnchorId::parse("observer").unwrap(), ObservationSchemaId::parse("schema").unwrap(),
        ObservationSubject::Resource(ResourceId::parse("test:resource").unwrap()), 2,
        vec![ObservationCondition::new(FactName::parse("amount").unwrap(), ConditionTest::EqLiteral(FactValue::Uint(1)))],
    ).unwrap();
    let raw = vec![second.clone(), first.clone()];
    assert_eq!(ObservationRequirements::new(raw.clone()).unwrap().as_slice(), raw);
    assert_eq!(ObservationRequirements::new(vec![first.clone(), second, first]), Err(ModelError::InvalidObservationRequirement));
    let ordered = vec![FactValue::Uint(2), FactValue::Text(FactText::new("").unwrap()), FactValue::Bytes(FactBytes::new(vec![]).unwrap())];
    assert_eq!(MemberValues::new(ordered.clone()).unwrap().as_slice(), ordered);
    assert_eq!(MemberValues::new(vec![FactValue::Uint(1), FactValue::Uint(2), FactValue::Uint(1)]), Err(ModelError::InvalidObservationRequirement));
}

#[test]
fn approval_satisfaction_and_binding_keep_their_original_bounds_and_sort() {
    words(3, 6, |tags| {
        let requirement = ApprovalRequirementId::new([5; 32]);
        let raw: Vec<_> = tags.iter().map(|tag| ApprovalDigest::new([*tag; 32])).collect();
        let mut sorted = raw.clone();
        sorted.sort();
        let expected = if sorted.is_empty() || sorted.len() > MAX_APPROVERS_PER_REQUIREMENT
            || sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            Err(ModelError::InvalidApproval)
        } else { Ok(sorted) };
        let actual = ApprovalSatisfaction::new(requirement, raw).map(|value| {
            assert_eq!(value.requirement(), requirement);
            value.approvals().to_vec()
        });
        assert_eq!(actual, expected);
        let statement = StatementRef::Grant(GrantId::new([6; 32]));
        let raw: Vec<_> = tags.iter().map(|tag| EvidenceId::new([*tag; 32])).collect();
        let mut sorted = raw.clone();
        sorted.sort();
        let expected = if sorted.is_empty() || sorted.len() > HARD_MAX_BINDING_EVIDENCE
            || sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            Err(ModelError::InvalidEvidenceBinding)
        } else { Ok(sorted) };
        let actual = ControlBinding::new(statement, raw).map(|value| {
            assert_eq!(value.statement(), statement);
            value.evidence().to_vec()
        });
        assert_eq!(actual, expected);
    });
    let ids: Vec<_> = (0..16).map(|tag| ApprovalDigest::new([tag; 32])).rev().collect();
    assert_eq!(ApprovalSatisfaction::new(ApprovalRequirementId::new([5; 32]), ids).unwrap().approvals().len(), 16);
    assert_eq!(ApprovalSatisfaction::new(ApprovalRequirementId::new([5; 32]), vec![ApprovalDigest::new([0; 32]); 17]), Err(ModelError::InvalidApproval));
}

#[test]
fn set_wrappers_preserve_prior_values_and_exact_refusal_codes() {
    words(3, 6, |tags| {
        let permissions: Vec<_> = tags.iter().map(|tag| {
            Permission::new(CapabilityId::parse(if *tag == 0 { "read" } else { "write" }).unwrap(),
                ResourceId::parse(if *tag == 2 { "resource:é" } else { "resource:a" }).unwrap())
        }).collect();
        let expected = original_typed_set::<_, HARD_MAX_PERMISSIONS>(permissions.clone()).map_err(|error| match error {
            BoundError::Duplicate => ModelError::DuplicatePermission,
            BoundError::Empty | BoundError::AboveMaximum => ModelError::InvalidPermissionSet,
        });
        assert_eq!(PermissionSet::new(permissions).map(|value| value.as_slice().to_vec()), expected);
        let audiences: Vec<_> = tags.iter().map(|tag| Audience::parse(match tag {
            0 => "audience:z", 1 => "audience:é", _ => "audience:客户",
        }).unwrap()).collect();
        let expected = original_typed_set::<_, HARD_MAX_AUDIENCES>(audiences.clone()).map_err(|error| match error {
            BoundError::Duplicate => ModelError::DuplicateAudience,
            BoundError::Empty | BoundError::AboveMaximum => ModelError::InvalidAudienceSet,
        });
        assert_eq!(AudienceSet::new(audiences).map(|value| value.as_slice().to_vec()), expected);
        let digests: Vec<_> = tags.iter().map(|tag| Digest::new([*tag; 32])).collect();
        let expected = original_typed_set::<_, HARD_MAX_BODY_DIGESTS>(digests.clone()).map_err(|error| match error {
            BoundError::Duplicate => ModelError::DuplicateBodyDigest,
            BoundError::Empty | BoundError::AboveMaximum => ModelError::InvalidActionConstraint,
        });
        assert_eq!(BodyDigestSet::new(digests).map(|value| value.as_slice().to_vec()), expected);
    });
    assert_eq!(PermissionSet::new(vec![Permission::new(CapabilityId::parse("read").unwrap(), ResourceId::parse("resource:a").unwrap()); 1025]), Err(ModelError::InvalidPermissionSet));
    assert_eq!(AudienceSet::new(vec![Audience::parse("same").unwrap(); 257]), Err(ModelError::InvalidAudienceSet));
    assert_eq!(BodyDigestSet::new(vec![Digest::new([0; 32]); 257]), Err(ModelError::InvalidActionConstraint));
    let boundary: Vec<_> = (0..=u8::MAX).rev().map(|tag| Digest::new([tag; 32])).collect();
    assert_eq!(BodyDigestSet::new(boundary).unwrap().as_slice().len(), 256);
}

fn composite_requirement(variant: u8, age: u32) -> ObservationRequirement {
    let mut literals = vec![FactValue::Uint(1), FactValue::Text(FactText::new("1").unwrap()),
        FactValue::Bytes(FactBytes::new(vec![b'1']).unwrap())];
    if variant == 8 {
        literals.reverse();
    }
    let mut conditions = vec![
        ObservationCondition::new(FactName::parse(if variant == 9 { "amount-other" } else { "amount" }).unwrap(),
            if variant == 6 { ConditionTest::EqLiteral(FactValue::Uint(1)) }
            else { ConditionTest::Member(MemberValues::new(literals).unwrap()) }),
        ObservationCondition::new(FactName::parse("range").unwrap(),
            ConditionTest::UintRange(UintRange::new(3, if variant == 7 { 6 } else { 5 }).unwrap())),
    ];
    if variant == 5 {
        conditions.reverse();
    }
    ObservationRequirement::new(
        ObserverAnchorId::parse(if variant == 1 { "observer-b" } else { "observer-a" }).unwrap(),
        ObservationSchemaId::parse(if variant == 2 { "schema-b" } else { "schema-a" }).unwrap(),
        if variant == 3 { ObservationSubject::ActionFact(FactName::parse("resource").unwrap()) }
        else { ObservationSubject::Resource(ResourceId::parse(if variant == 10 { "resource-other" } else { "resource" }).unwrap()) },
        age,
        conditions,
    ).unwrap()
}

#[test]
fn requirement_duplicate_identity_includes_every_field_and_signed_position() {
    let base = composite_requirement(0, 1);
    let mut variants: Vec<_> = (1..=10).filter(|variant| *variant != 4)
        .map(|variant| composite_requirement(variant, 1)).collect();
    variants.push(composite_requirement(0, 2));
    for variant in variants {
        assert_ne!(base, variant);
        let ordered = vec![variant.clone(), base.clone()];
        assert_eq!(ObservationRequirements::new(ordered.clone()).unwrap().as_slice(), ordered);
        assert_eq!(ObservationRequirements::new(vec![base.clone(), variant, base.clone()]),
            Err(ModelError::InvalidObservationRequirement));
    }
    let typed_zeros = vec![FactValue::Uint(0), FactValue::Text(FactText::new("").unwrap()),
        FactValue::Bytes(FactBytes::new(vec![]).unwrap())];
    assert_eq!(MemberValues::new(typed_zeros.clone()).unwrap().as_slice(), typed_zeros);
}

#[test]
fn observation_constructor_keeps_inclusive_range_age_and_condition_bounds() {
    assert!(UintRange::new(5, 5).is_ok());
    assert_eq!(UintRange::new(6, 5), Err(ModelError::InvalidObservationRequirement));
    let base = composite_requirement(0, 1);
    for age in [0, 1, 86400, 86401] {
        for count in [0, 1, 16, 17] {
            let raw = ObservationRequirement::new(base.observer_anchor().clone(), base.schema().clone(),
                base.subject().clone(), age, vec![base.conditions()[0].clone(); count]);
            if (1..=86400).contains(&age) && (1..=16).contains(&count) {
                let value = raw.unwrap();
                assert_eq!(value.max_age_seconds(), age);
                assert_eq!(value.conditions().len(), count);
            } else {
                assert_eq!(raw, Err(ModelError::InvalidObservationRequirement));
            }
        }
    }
}
