//! Canonical construction against the independent frozen whole-wire path.

extern crate std;

use crate::{protocol_reference as former, *};
use auths_model::{GrantStatusSnapshot, PrincipalStatusSnapshot, ProofBundle, TrustedContext, VerifierLimits};
use std::{fs, path::PathBuf};

macro_rules! assert_normalized {
    ($raw:expr, $carrier:ty, $encode:ident, $decode:ident $(, $argument:expr)* $(,)?) => {{
        let raw = $raw;
        let before = former::$encode(&raw).unwrap();
        let canonical = <$carrier>::new(raw).unwrap();
        assert_eq!(crate::$encode(&canonical).unwrap(), before);
        assert_eq!(former::$encode(canonical.as_value()).unwrap(), before);
        let decoded = former::$decode(&before $(, $argument)*).unwrap();
        // Full structural equality checks signatures and every retained field,
        // as well as all collection orders. It is stronger than byte parity.
        assert_eq!(&decoded, canonical.as_value());
        assert_eq!(crate::$decode(&before $(, $argument)*).unwrap(), canonical);
        let repeated = <$carrier>::new(canonical.clone().into_value()).unwrap();
        assert_eq!(repeated, canonical);
        canonical
    }};
}

fn reverse_principal_ties(value: PrincipalStatusSnapshot) -> PrincipalStatusSnapshot {
    let mut parts = value.into_parts();
    parts.statements.reverse();
    PrincipalStatusSnapshot::with_trust(
        parts.id, parts.observed_at, parts.valid_until,
        parts.statements, parts.checkpoints, parts.trust,
    ).unwrap()
}

fn reverse_grant_ties(value: GrantStatusSnapshot) -> GrantStatusSnapshot {
    let mut parts = value.into_parts();
    parts.statements.reverse();
    GrantStatusSnapshot::with_trust(
        parts.id, parts.observed_at, parts.valid_until,
        parts.statements, parts.checkpoints, parts.trust,
    ).unwrap()
}

fn bundle_from_parts(parts: auths_model::ProofBundleParts) -> ProofBundle {
    ProofBundle::new(
        parts.header, parts.grants, parts.actions, parts.plan,
        parts.evidence, parts.bindings, parts.principal_status,
        parts.grant_status, parts.attachments, parts.canonical_body,
    ).unwrap().with_approvals(parts.approvals).unwrap()
}

#[test]
fn discarding_sort_keys_moves_nonclone_records_in_order() {
    #[derive(Debug)]
    struct SortKey(u8);
    #[derive(Debug)]
    struct Record {
        position: usize,
        bytes: alloc::vec::Vec<u8>,
    }
    for length in [0, 1, 2, 32, 256, 512] {
        let input: alloc::vec::Vec<_> = (0..length).map(|position| (
            SortKey(u8::try_from(position % 3).unwrap()),
            Record { position, bytes: alloc::vec![u8::try_from(position % 251).unwrap(); 16 + position % 5] },
        )).collect();
        let expected: alloc::vec::Vec<_> = input.iter().map(|(key, record)| {
            assert_eq!(usize::from(key.0), record.position % 3);
            (record.position, record.bytes.clone(), record.bytes.as_ptr())
        }).collect();
        let output = crate::canonical_value::unkey_records(input);
        assert_eq!(output.len(), expected.len());
        for (record, (position, bytes, allocation)) in output.iter().zip(expected) {
            assert_eq!(record.position, position);
            assert_eq!(record.bytes, bytes);
            assert_eq!(record.bytes.as_ptr(), allocation, "the owned payload allocation must move intact");
        }
    }
}

#[test]
fn unsigned_identifier_ties_retain_signatures_order_and_multiplicity() {
    use auths_model::{SignatureBytes, SignatureEnvelope, SignedGrant};
    let limits = VerifierLimits::hard();
    let original = former::decode_bundle(include_bytes!(
        "../../../fixtures/v1/valid/raw-key-chain.proof.cbor"
    ), &limits).unwrap();
    let mut parts = original.into_parts();
    let first = parts.grants.first().expect("chain fixture must contain a grant").clone();
    let second = SignedGrant::new(
        first.statement().clone(),
        SignatureEnvelope::new(
            first.signature().descriptor().clone(),
            SignatureBytes::new(alloc::vec![0x37; 64]).unwrap(),
        ),
    );
    assert_ne!(first, second);
    assert_eq!(grant_id(first.statement()).unwrap(), grant_id(second.statement()).unwrap());
    // The signatures are deliberately different synthetic carriers. This is
    // a codec test; neither authorization nor cryptographic validity is assumed.
    let tied = alloc::vec![second.clone(), first, second];
    parts.grants = tied.clone();
    let canonical = assert_normalized!(
        bundle_from_parts(parts), CanonicalProofBundle,
        encode_bundle, decode_bundle, &limits,
    );
    assert_eq!(canonical.grants(), tied.as_slice());
}

#[test]
fn optional_body_presence_survives_full_value_and_frozen_wire_round_trips() {
    let limits = VerifierLimits::hard();
    let original = former::decode_bundle(include_bytes!(
        "../../../fixtures/v1/valid/raw-key-chain.proof.cbor"
    ), &limits).unwrap();
    let mut encodings = alloc::vec::Vec::new();
    for body in [None, Some(alloc::vec::Vec::new()), Some(alloc::vec![0, 255, 1])] {
        let mut parts = original.clone().into_parts();
        parts.canonical_body = body.clone();
        let canonical = assert_normalized!(
            bundle_from_parts(parts), CanonicalProofBundle,
            encode_bundle, decode_bundle, &limits,
        );
        assert_eq!(canonical.canonical_body(), body.as_deref());
        assert_eq!(proof_digest(canonical.as_value()), former::proof_digest(canonical.as_value()));
        encodings.push(encode_bundle(&canonical).unwrap());
    }
    // Presence is part of the canonical value even when the byte string is
    // empty. This is codec/commitment precision, not an authorization witness.
    assert_ne!(encodings[0], encodings[1]);
    assert_ne!(encodings[1], encodings[2]);
}

#[test]
fn trusted_context_approval_capacity_is_distinct_from_grant_capacity() {
    use auths_model::{ApprovalRequirement, ApprovalRequirements, ApproverAnchor, PrincipalId, StatusPolicy};
    let original = former::decode_verifier_context(include_bytes!(
        "../../../fixtures/v1/valid/raw-key-chain.context.cbor"
    )).unwrap();
    let principals: alloc::vec::Vec<_> = (0..7).map(|index| {
        PrincipalId::parse(alloc::format!("test:context-approver-{index}")).unwrap()
    }).collect();
    let methods = original.accepted_registries().principal_methods().to_vec();
    let validity = original.trust_anchors()[0].validity();
    let approvers: alloc::vec::Vec<_> = principals.iter().map(|principal| {
        ApproverAnchor::new(principal.clone(), methods.clone(), validity, StatusPolicy::ExpiryOnly).unwrap()
    }).collect();
    let make_requirements = |count| -> alloc::vec::Vec<_> {
        (1_u32..=count).map(|mask| {
            let members: alloc::vec::Vec<_> = principals.iter().enumerate()
                .filter(|(index, _)| mask & (1_u32 << *index) != 0)
                .map(|(_, principal)| principal.clone()).collect();
            let threshold = u16::try_from(members.len().min(2)).unwrap();
            ApprovalRequirement::new(members, threshold).unwrap()
        }).collect()
    };
    for count in [4, 5, 16, 64] {
        let requirements = make_requirements(count);
        if count > 4 {
            assert!(ApprovalRequirements::new(requirements.clone()).is_err(),
                "a grant extension must retain its four-requirement bound");
        }
        let parts = original.clone().into_parts();
        let context = TrustedContext::new(
            parts.configuration, parts.composition, parts.trust_anchors,
            parts.accepted_registries, parts.expected_audience, parts.expected_challenge,
            parts.evaluation_time, parts.assurance_policy, parts.principal_status_snapshot,
            parts.grant_status_snapshot, parts.resource_matcher, parts.profile_policy,
            parts.channel_policy, VerifierLimits::hard(),
        ).unwrap().with_observer_anchors(parts.observer_anchors).unwrap()
            .with_approvals(approvers.clone(), requirements).unwrap();
        let canonical = assert_normalized!(
            context, CanonicalTrustedContext,
            encode_verifier_context, decode_verifier_context,
        );
        assert_eq!(canonical.approval_requirements().len(), usize::try_from(count).unwrap());
        assert!(canonical.clone().into_value().with_approvals(
            approvers.clone(), make_requirements(65)).is_err());
    }
    // Synthetic test principals exercise codec/model capacity. No signature,
    // distinct-human or execution-authority claim follows from these contexts.
}

#[test]
fn assurance_policy_options_preserve_full_context_values_and_commitments() {
    use auths_model::{
        AcceptedRegistries, AdapterId, AssuranceClaimId, AssurancePolicy, AssuranceQuantifier,
        AssuranceRequirement, ClaimParameterId, EvidenceSourceId, FreshnessLimit, ParticipantRole,
    };
    let original = former::decode_verifier_context(include_bytes!(
        "../../../fixtures/v1/valid/raw-key-chain.context.cbor"
    )).unwrap();
    let old = original.accepted_registries();
    let claim = AssuranceClaimId::parse("test-assurance-claim").unwrap();
    let mut claims = old.assurance_claims().to_vec();
    claims.push(claim.clone());
    let registries = AcceptedRegistries::new(
        old.manifest_id().clone(), old.principal_methods().to_vec(), old.signature_suites().to_vec(),
        old.evidence_types().to_vec(), old.principal_status_methods().to_vec(),
        old.grant_status_methods().to_vec(), claims, old.assurance_implications().to_vec(),
        old.resource_matchers().to_vec(), old.budget_algebras().to_vec(),
        old.critical_extensions().to_vec(), old.profiles().to_vec(), old.profile_policies().to_vec(),
    ).unwrap().with_budget_free_profiles(old.budget_free_profiles().to_vec()).unwrap();
    let source = EvidenceSourceId::parse("test-evidence-source").unwrap();
    let adapter = AdapterId::parse("test-assurance-adapter").unwrap();
    let parameter = |value| ClaimParameterId::parse(value).unwrap();
    let mut encodings = alloc::collections::BTreeSet::new();
    for role in [ParticipantRole::Root, ParticipantRole::Intermediate, ParticipantRole::Actor, ParticipantRole::ExternalIssuer] {
        for quantifier in [AssuranceQuantifier::Any, AssuranceQuantifier::Every] {
            for with_source in [false, true] {
                for adapter_mode in 0..4 {
                    for age in [None, Some(FreshnessLimit::new(1).unwrap()), Some(FreshnessLimit::new(u64::MAX).unwrap())] {
                        let (selected_adapter, version) = match adapter_mode {
                            0 => (None, None),
                            1 => (Some(adapter.clone()), None),
                            2 => (Some(adapter.clone()), Some(1)),
                            _ => (Some(adapter.clone()), Some(u16::MAX)),
                        };
                        let requirement = AssuranceRequirement::constrained(
                            role, quantifier, claim.clone(),
                            alloc::vec![(parameter("z-name"), parameter("last-value")),
                                (parameter("a-name"), parameter("first-value"))],
                            if with_source { Some(source.clone()) } else { None },
                            selected_adapter, version, age,
                        ).unwrap();
                        let parts = original.clone().into_parts();
                        let policy = AssurancePolicy::new(parts.assurance_policy.id().clone(), alloc::vec![requirement]).unwrap();
                        let context = TrustedContext::new(
                            parts.configuration, parts.composition, parts.trust_anchors, registries.clone(),
                            parts.expected_audience, parts.expected_challenge, parts.evaluation_time, policy,
                            parts.principal_status_snapshot, parts.grant_status_snapshot, parts.resource_matcher,
                            parts.profile_policy, parts.channel_policy, parts.limits,
                        ).unwrap().with_observer_anchors(parts.observer_anchors).unwrap()
                            .with_approvals(parts.approver_anchors, parts.approval_requirements).unwrap();
                        let canonical = assert_normalized!(context, CanonicalTrustedContext,
                            encode_verifier_context, decode_verifier_context);
                        let encoded = encode_verifier_context(&canonical).unwrap();
                        let (digest, size) = context_digest_and_size(canonical.as_value()).unwrap();
                        assert_eq!(digest, former::context_digest(canonical.as_value()).unwrap());
                        assert_eq!(size, encoded.len());
                        assert!(encodings.insert(encoded), "each legal policy variation must remain byte-distinct");
                    }
                }
            }
        }
    }
    assert_eq!(encodings.len(), 192);
    // These are synthetically configured codec inputs, not authenticated
    // assurance claims or a witness that any action is authorized.
}

#[test]
fn canonical_bundle_rejects_inconsistent_evidence_identity() {
    use auths_model::{EvidenceId, EvidenceObject};
    let original = former::decode_bundle(include_bytes!(
        "../../../fixtures/v1/valid/raw-key-chain.proof.cbor"
    ), &VerifierLimits::hard()).unwrap();
    let mut parts = original.into_parts();
    let evidence = parts.evidence.first().expect("chain fixture must contain control evidence");
    let mut incorrect = *evidence_id(evidence).unwrap().as_bytes();
    incorrect[0] ^= 1;
    parts.evidence[0] = EvidenceObject::new(
        EvidenceId::new(incorrect), evidence.evidence_type().clone(),
        evidence.media_type().clone(), evidence.bytes().to_vec(),
    ).unwrap();
    assert_eq!(
        CanonicalProofBundle::new(bundle_from_parts(parts)),
        Err(CodecError::DigestMismatch),
    );
}

#[test]
fn policy_carrier_checks_the_exact_opening_without_repair() {
    use auths_model::{BoundedPolicyCommitment, Digest, PolicyCommitment, PolicyIdentifier};
    let policy = b"synthetic canonical policy".to_vec();
    let digest = bounded_policy_digest(&policy).unwrap();
    let commitment = |digest| PolicyCommitment::new(
        PolicyIdentifier::parse("synthetic-policy", auths_model::MAX_POLICY_IDENTIFIER_BYTES).unwrap(),
        1,
        PolicyIdentifier::parse("synthetic-canonicalization", auths_model::MAX_POLICY_CANONICALIZATION_BYTES).unwrap(),
        digest,
        PolicyIdentifier::parse("synthetic-evaluator", auths_model::MAX_POLICY_IDENTIFIER_BYTES).unwrap(),
    ).unwrap();
    let raw = BoundedPolicyCommitment::new(commitment(digest), policy.clone(), None).unwrap();
    let canonical = assert_normalized!(
        raw.clone(), CanonicalBoundedPolicyCommitment,
        encode_bounded_policy_commitment, decode_bounded_policy_commitment,
    );
    assert_eq!(canonical.as_value(), &raw);
    assert_eq!(
        former::decode_bounded_policy_commitment(&former::encode_bounded_policy_commitment(&raw).unwrap()).unwrap(),
        raw,
    );
    let mut incorrect = *digest.as_bytes();
    incorrect[0] ^= 1;
    let inconsistent = BoundedPolicyCommitment::new(
        commitment(Digest::new(incorrect)), policy, None,
    ).unwrap();
    let encoded = former::encode_bounded_policy_commitment(&inconsistent).unwrap();
    assert_eq!(decode_bounded_policy_commitment(&encoded), Err(CodecError::DigestMismatch));
    // The frozen encoder deliberately supplies adversarial bytes that the
    // checked public constructor refuses. A nonminimal map head must retain
    // the earlier canonical-byte refusal even when its opening is also wrong.
    assert_eq!(encoded[0], 0xa3);
    let mut nonminimal = alloc::vec![0xb8, 3];
    nonminimal.extend_from_slice(&encoded[1..]);
    assert_eq!(former::decode_bounded_policy_commitment(&nonminimal), Err(CodecError::NonCanonical));
    assert_eq!(decode_bounded_policy_commitment(&nonminimal), Err(CodecError::NonCanonical));
    assert_eq!(
        CanonicalBoundedPolicyCommitment::new(inconsistent),
        Err(CodecError::DigestMismatch),
    );
}

#[test]
fn bounded_policy_full_fields_and_parent_presence_match_frozen_wire() {
    use auths_model::{BoundedPolicyCommitment, Digest, PolicyCommitment, PolicyIdentifier};
    let mut encodings = alloc::collections::BTreeSet::new();
    for policy in [alloc::vec![0], alloc::vec![0, 255, 1], alloc::vec![0xa5; auths_model::MAX_BOUNDED_POLICY_BYTES]] {
        let opening = former::bounded_policy_digest(&policy).unwrap();
        assert_eq!(bounded_policy_digest(&policy).unwrap(), opening);
        for parent in [None, Some(Digest::new([0; 32])), Some(Digest::new([255; 32]))] {
            for version in [1, u16::MAX] {
                for policy_type in [alloc::string::String::from("t"), "t".repeat(auths_model::MAX_POLICY_IDENTIFIER_BYTES)] {
                    for canonicalization in [alloc::string::String::from("c"), "c".repeat(auths_model::MAX_POLICY_CANONICALIZATION_BYTES)] {
                        for evaluator in [alloc::string::String::from("e"), "e".repeat(auths_model::MAX_POLICY_IDENTIFIER_BYTES)] {
                            let commitment = PolicyCommitment::new(
                                PolicyIdentifier::parse(&policy_type, auths_model::MAX_POLICY_IDENTIFIER_BYTES).unwrap(),
                                version,
                                PolicyIdentifier::parse(&canonicalization, auths_model::MAX_POLICY_CANONICALIZATION_BYTES).unwrap(),
                                opening,
                                PolicyIdentifier::parse(&evaluator, auths_model::MAX_POLICY_IDENTIFIER_BYTES).unwrap(),
                            ).unwrap();
                            let raw = BoundedPolicyCommitment::new(commitment, policy.clone(), parent).unwrap();
                            let canonical = assert_normalized!(raw, CanonicalBoundedPolicyCommitment,
                                encode_bounded_policy_commitment, decode_bounded_policy_commitment);
                            let bytes = encode_bounded_policy_commitment(&canonical).unwrap();
                            assert_eq!(bounded_policy_link(&bytes).unwrap(), former::bounded_policy_link(&bytes).unwrap());
                            assert!(encodings.insert(bytes), "every policy field and parent presence must remain byte-bound");
                        }
                    }
                }
            }
        }
    }
    assert_eq!(encodings.len(), 144);
    // Parent bytes are opaque commitments here; this does not certify a
    // parent's existence or any product evaluator's attenuation semantics.
}

fn sample_result(
    decision: auths_model::VerificationDecision,
    code: auths_model::VerificationCode,
) -> auths_model::PortableVerificationResult {
    use auths_model::{ContextDigest, Digest, PortableVerificationResult, RegistryManifestId,
        VerificationResources, VerificationStage, VerifierConfigurationId};
    PortableVerificationResult::new(
        decision, VerificationStage::Decode, code,
        Digest::new([0; 32]), Digest::new([0; 32]), ContextDigest::new([0; 32]),
        None, alloc::vec![], alloc::vec![], alloc::vec![],
        VerificationResources::new(0, 0, 0, 0, 0, 0, 0),
        RegistryManifestId::new([0; 32]), None, VerifierConfigurationId::new([0; 32]),
    )
}

#[test]
fn result_carrier_requires_consistent_tags_and_the_exact_self_digest() {
    use auths_model::{DenialReason, VerificationCode, VerificationDecision, VerificationResultDigest};
    let raw = sample_result(
        VerificationDecision::Denied,
        VerificationCode::Denied(DenialReason::ResourceLimitExceeded),
    );
    let digest = verification_result_digest(&raw).unwrap();
    let bound = raw.with_result_digest(digest);
    let canonical = assert_normalized!(
        bound.clone(), CanonicalVerificationResult,
        encode_verification_result, decode_verification_result,
    );
    assert_eq!(canonical.as_value(), &bound);
    let mut incorrect = *digest.as_bytes();
    incorrect[0] ^= 1;
    assert_eq!(
        CanonicalVerificationResult::new(bound.with_result_digest(VerificationResultDigest::new(incorrect))),
        Err(CodecError::DigestMismatch),
    );
    // A digest over a contradictory pair cannot make its tags consistent.
    let contradiction = sample_result(
        VerificationDecision::Authorized,
        VerificationCode::Denied(DenialReason::ResourceLimitExceeded),
    );
    let digest = verification_result_digest(&contradiction).unwrap();
    assert_eq!(
        CanonicalVerificationResult::new(contradiction.with_result_digest(digest)),
        Err(CodecError::Malformed),
    );
    let both_invalid = sample_result(
        VerificationDecision::Authorized,
        VerificationCode::Denied(DenialReason::ResourceLimitExceeded),
    );
    let correct = verification_result_digest(&both_invalid).unwrap();
    let mut mismatched = *correct.as_bytes();
    mismatched[0] ^= 1;
    assert_eq!(CanonicalVerificationResult::new(both_invalid.with_result_digest(
        VerificationResultDigest::new(mismatched))), Err(CodecError::Malformed));
}

#[test]
fn complete_result_fields_and_zero_self_digest_match_frozen_projection() {
    use auths_model::{
        AdapterId, ApprovalDigest, ApprovalRequirementId, ApprovalSatisfaction, AssuranceClaim,
        AssuranceClaimId, AssuranceSatisfaction, AttachmentDigest, ClaimParameterId, ContextDigest,
        DenialReason, Digest, EvidenceId, EvidenceSourceId, ObservationRequirementId,
        ObservationSatisfaction, ParticipantAssurance, ParticipantRole, PlanId,
        PortableVerificationResult, PrincipalId, ProofRef, RegistryManifestId, Requirement, Timestamp,
        VerificationCode, VerificationDecision, VerificationResources, VerificationResultDigest,
        VerificationStage, VerifierConfigurationId,
    };
    let mut encodings = alloc::collections::BTreeSet::new();
    let mut cases = 0;
    for (decision, code) in [
        (VerificationDecision::Authorized, VerificationCode::Authorized),
        (VerificationDecision::Denied, VerificationCode::Denied(DenialReason::ResourceLimitExceeded)),
        (VerificationDecision::Indeterminate, VerificationCode::Indeterminate(Requirement::MissingPrincipalEvidence)),
    ] {
        for (stage_index, stage) in [VerificationStage::Decode, VerificationStage::Resolve,
            VerificationStage::PrincipalControl, VerificationStage::Authority, VerificationStage::Complete].into_iter().enumerate()
        {
            for with_plan in [false, true] {
                for with_configuration in [false, true] {
                    for extreme in [false, true] {
                        for with_records in [false, true] {
                            let principal = PrincipalId::parse("test:reported-principal").unwrap();
                            let claim = AssuranceClaim::new(
                                AssuranceClaimId::parse("test-reported-claim").unwrap(),
                                alloc::vec![(ClaimParameterId::parse("z-name").unwrap(), ClaimParameterId::parse("last").unwrap()),
                                    (ClaimParameterId::parse("a-name").unwrap(), ClaimParameterId::parse("first").unwrap())],
                                if extreme { Some(Timestamp::new(u64::MAX)) } else { None },
                                EvidenceSourceId::parse("test-reported-source").unwrap(),
                            ).unwrap();
                            let evidence = alloc::vec![EvidenceId::new([2; 32]), EvidenceId::new([1; 32])];
                            let role = [ParticipantRole::Root, ParticipantRole::Intermediate, ParticipantRole::Actor,
                                ParticipantRole::ExternalIssuer][stage_index % 4];
                            let report = ParticipantAssurance::new(principal.clone(), role, alloc::vec![claim.clone()],
                                evidence.clone(), AdapterId::parse("test-reported-adapter").unwrap(),
                                if extreme { u16::MAX } else { 1 }).unwrap();
                            let satisfaction = AssuranceSatisfaction::new(if extreme { u16::MAX } else { 0 },
                                principal, claim, evidence);
                            let resources = if extreme {
                                VerificationResources::new(u64::MAX, u64::MAX - 1, u64::MAX - 2,
                                    u64::MAX - 3, u64::MAX - 4, u64::MAX - 5, u64::MAX - 6)
                            } else { VerificationResources::new(0, 0, 0, 0, 0, 0, 0) };
                            let mut raw = PortableVerificationResult::new(
                                decision, stage, code, Digest::new([3; 32]), Digest::new([4; 32]),
                                ContextDigest::new([5; 32]), if with_plan { Some(PlanId::new([0; 32])) } else { None },
                                if with_records { alloc::vec![ProofRef::new([7; 32]), ProofRef::new([6; 32])] } else { alloc::vec![] },
                                if with_records { alloc::vec![report] } else { alloc::vec![] },
                                if with_records { alloc::vec![satisfaction] } else { alloc::vec![] }, resources,
                                RegistryManifestId::new([8; 32]),
                                if with_configuration { Some(VerifierConfigurationId::new([0; 32])) } else { None },
                                VerifierConfigurationId::new([9; 32]),
                            );
                            if with_records {
                                raw = raw.with_observation_satisfactions(alloc::vec![
                                    ObservationSatisfaction::new(ObservationRequirementId::new([10; 32]), AttachmentDigest::new([11; 32])),
                                    ObservationSatisfaction::new(ObservationRequirementId::new([12; 32]), AttachmentDigest::new([13; 32])),
                                ]).with_approval_satisfactions(alloc::vec![ApprovalSatisfaction::new(
                                    ApprovalRequirementId::new([14; 32]), alloc::vec![ApprovalDigest::new([16; 32]), ApprovalDigest::new([15; 32])],
                                ).unwrap()]);
                            }
                            let projection = encode_verification_result_digest_input(&raw).unwrap();
                            assert_eq!(projection, former::encode_verification_result_digest_input(&raw).unwrap());
                            let expected = former::verification_result_digest(&raw).unwrap();
                            for replacement in [VerificationResultDigest::new([0; 32]), VerificationResultDigest::new([255; 32])] {
                                let rebound = raw.clone().with_result_digest(replacement);
                                assert_eq!(encode_verification_result_digest_input(&rebound).unwrap(), projection);
                                assert_eq!(verification_result_digest(&rebound).unwrap(), expected);
                            }
                            let zero = raw.clone().with_result_digest(VerificationResultDigest::new([0; 32]));
                            let maximum = raw.clone().with_result_digest(VerificationResultDigest::new([255; 32]));
                            assert_ne!(crate::encode::encode_verification_result_value(&zero).unwrap(),
                                crate::encode::encode_verification_result_value(&maximum).unwrap());
                            let bound = raw.with_result_digest(expected);
                            let canonical = assert_normalized!(bound, CanonicalVerificationResult,
                                encode_verification_result, decode_verification_result);
                            assert!(encodings.insert(encode_verification_result(&canonical).unwrap()));
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 240);
    assert_eq!(encodings.len(), cases);
    // Self-bound reported data is not evidence of verifier origin, signature
    // authenticity, valid authority chains or permission to execute an action.
}

#[test]
fn nested_normalization_retains_the_full_frozen_wire_value() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1");
    let mut pending = std::vec![root];
    let mut bundle_count = 0;
    let mut context_count = 0;
    let mut approval_count = 0;
    let mut observation_count = 0;
    let mut policy_count = 0;
    let mut result_count = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if !path.extension().is_some_and(|extension| extension == "cbor") {
                continue;
            }
            let input = fs::read(path).unwrap();
            let limits = VerifierLimits::hard();
            if let Ok(raw) = former::decode_bundle(&input, &limits) {
                let mut parts = raw.into_parts();
                parts.grants.reverse();
                parts.principal_status.reverse();
                parts.grant_status.reverse();
                let reversed = bundle_from_parts(parts);
                let bundle = assert_normalized!(
                    reversed, CanonicalProofBundle,
                    encode_bundle, decode_bundle, &limits,
                );
                for approval in bundle.approvals() {
                    assert_normalized!(
                        approval.clone(), CanonicalSignedApproval,
                        encode_signed_approval, decode_signed_approval, &limits,
                    );
                    approval_count += 1;
                }
                for grant in bundle.grants() {
                    for extension in grant.statement().extensions().as_slice() {
                        if let Ok(policy) = former::decode_bounded_policy_commitment(extension.bytes()) {
                            assert_normalized!(
                                policy, CanonicalBoundedPolicyCommitment,
                                encode_bounded_policy_commitment, decode_bounded_policy_commitment,
                            );
                            policy_count += 1;
                        }
                    }
                }
                bundle_count += 1;
            }
            if let Ok(action) = former::decode_canonical_action(&input, &limits) {
                for attachment in action.detached_attachments() {
                    if let Ok(observation) = former::decode_signed_observation(attachment.bytes(), &limits) {
                        assert_normalized!(
                            observation, CanonicalSignedObservation,
                            encode_signed_observation, decode_signed_observation, &limits,
                        );
                        observation_count += 1;
                    }
                }
            }
            if let Ok(result) = former::decode_verification_result(&input) {
                assert_normalized!(
                    result, CanonicalVerificationResult,
                    encode_verification_result, decode_verification_result,
                );
                result_count += 1;
            }
            if let Ok(raw) = former::decode_verifier_context(&input) {
                let mut parts = raw.into_parts();
                let principal_status = assert_normalized!(
                    reverse_principal_ties(parts.principal_status_snapshot),
                    CanonicalPrincipalStatusSnapshot,
                    encode_principal_status_snapshot,
                    decode_principal_status_snapshot, &limits,
                );
                let grant_status = assert_normalized!(
                    reverse_grant_ties(parts.grant_status_snapshot),
                    CanonicalGrantStatusSnapshot,
                    encode_grant_status_snapshot,
                    decode_grant_status_snapshot, &limits,
                );
                parts.approval_requirements.reverse();
                let reversed = TrustedContext::new(
                    parts.configuration, parts.composition, parts.trust_anchors,
                    parts.accepted_registries, parts.expected_audience,
                    parts.expected_challenge, parts.evaluation_time,
                    parts.assurance_policy, principal_status.into_value(),
                    grant_status.into_value(), parts.resource_matcher,
                    parts.profile_policy, parts.channel_policy, parts.limits,
                ).unwrap()
                    .with_observer_anchors(parts.observer_anchors).unwrap()
                    .with_approvals(parts.approver_anchors, parts.approval_requirements).unwrap();
                assert_normalized!(
                    reversed, CanonicalTrustedContext,
                    encode_verifier_context, decode_verifier_context,
                );
                context_count += 1;
            }
        }
    }
    assert!(bundle_count > 0, "bundle normalization cases must execute");
    assert!(context_count > 0, "context and both snapshot cases must execute");
    assert!(approval_count > 0, "signed approval cases must execute");
    assert!(observation_count > 0, "signed observation cases must execute");
    assert!(policy_count > 0, "bounded-policy opening cases must execute");
    assert!(result_count > 0, "portable-result commitment cases must execute");
}
