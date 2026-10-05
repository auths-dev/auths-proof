//! Assembly, closure, signing, and the generic stages, through the public
//! interface only.

#![allow(clippy::too_many_lines, reason = "case tables read top to bottom")]

mod common;

use auths_recipe_qualification::{
    ClosureFault, EvidenceMemberKind, GitCommit, LiveEffects, QualificationFormatError,
    QualificationInputs, QualificationRefusal, QualificationRootId, QualificationSignerId,
    RecipeQualificationState, VerifiedQualifications, VerifierState, WallRow,
};
use auths_recipe_qualification_issuance::{
    CaseReport, CertificateRequest, IssuanceError, NotApplicable, QualificationProposal,
    ReleaseSigner, RootSigner, SigningSeed, evidence, stages,
};
use common::{DAY, HOUR, NOW, all_evidence, cases, commit, draft, member_evidence, tuple};
use zeroize::Zeroizing;

fn seed(byte: u8) -> SigningSeed {
    SigningSeed::from_bytes(Zeroizing::new([byte; 32]))
}

fn root() -> RootSigner {
    RootSigner::create(
        &seed(0x11),
        QualificationRootId::parse("test-root").expect("root"),
    )
    .expect("root")
}

fn signer(root: &RootSigner, byte: u8, name: &str) -> ReleaseSigner {
    let certificate = root
        .certify(CertificateRequest {
            signer_id: QualificationSignerId::parse(name).expect("signer"),
            public_key_b64: seed(byte).public_key(),
            issued_at: NOW - DAY,
            not_before: NOW - DAY,
            not_after: NOW + 180 * DAY,
        })
        .expect("certificate");
    ReleaseSigner::open(&seed(byte), certificate).expect("signer")
}

fn proposal() -> QualificationProposal {
    QualificationProposal::assemble(draft(), all_evidence()).expect("proposal")
}

#[test]
fn a_record_is_assembled_from_its_evidence_and_closes_over_it() {
    let mut shuffled = all_evidence();
    shuffled.reverse();
    let assembled = QualificationProposal::assemble(draft(), shuffled).expect("proposal");
    let record = assembled.record().body();
    assert_eq!(record.evidence.len(), 10);
    assert_eq!(record.live_effects.entered, 3);
    for (stated, artifact) in record.evidence.iter().zip(assembled.evidence()) {
        assert_eq!(stated.evidence_sha256, artifact.digest());
        assert_eq!(stated.cases as usize, artifact.body().cases.len());
    }
    let evidence: Vec<&[u8]> = assembled
        .evidence()
        .iter()
        .map(auths_recipe_qualification::Canonical::canonical_bytes)
        .collect();
    let decoded =
        QualificationProposal::from_parts(assembled.record().canonical_bytes(), &evidence)
            .expect("the same proposal from its bytes");
    assert_eq!(decoded, assembled);
}

#[test]
fn a_run_with_a_failed_case_produces_no_evidence() {
    let member = EvidenceMemberKind::Hostile;
    let mut failed = cases(member);
    failed[0].passed = false;
    assert_eq!(
        evidence(member, &commit(), &tuple(), failed, None),
        Err(IssuanceError::CaseFailed)
    );
    let mut entered = cases(member);
    entered[0].unauthorized_provider_entries = 1;
    assert_eq!(
        evidence(member, &commit(), &tuple(), entered, None),
        Err(IssuanceError::CaseFailed)
    );
    let unread = Some(LiveEffects {
        entered: 3,
        confirmed_by_read_back: 2,
    });
    assert_eq!(
        evidence(
            EvidenceMemberKind::Live,
            &commit(),
            &tuple(),
            cases(EvidenceMemberKind::Live),
            unread
        ),
        Err(IssuanceError::Format(
            QualificationFormatError::InvalidEvidence
        ))
    );
    let misplaced = vec![CaseReport::new("misplaced", WallRow::Redaction, true).expect("case")];
    assert_eq!(
        evidence(member, &commit(), &tuple(), misplaced, None),
        Err(IssuanceError::Format(
            QualificationFormatError::InvalidEvidence
        ))
    );
}

#[test]
fn assembly_refuses_a_wall_that_is_not_whole() {
    let replace = |member, artifact| {
        let mut evidence = all_evidence();
        let position = evidence
            .iter()
            .position(|held: &auths_recipe_qualification::QualificationEvidence| {
                held.body().member == member
            })
            .expect("member");
        evidence[position] = artifact;
        evidence
    };

    let mut missing = all_evidence();
    missing.pop();
    assert_eq!(
        QualificationProposal::assemble(draft(), missing),
        Err(IssuanceError::Format(
            QualificationFormatError::InvalidEvidence
        )),
        "a member is absent"
    );

    // The hostile member without its secret-isolation row.
    let member = EvidenceMemberKind::Hostile;
    let partial: Vec<CaseReport> = cases(member)
        .into_iter()
        .filter(|case| case.wall_row != WallRow::SecretIsolation)
        .collect();
    let partial = evidence(member, &commit(), &tuple(), partial, None).expect("evidence");
    assert_eq!(
        QualificationProposal::assemble(draft(), replace(member, partial)),
        Err(IssuanceError::Closure(ClosureFault::WallRow))
    );

    let other_commit = GitCommit::parse("f".repeat(40)).expect("commit");
    let elsewhere =
        evidence(member, &other_commit, &tuple(), cases(member), None).expect("evidence");
    assert_eq!(
        QualificationProposal::assemble(draft(), replace(member, elsewhere)),
        Err(IssuanceError::Closure(ClosureFault::Candidate)),
        "evidence from another commit"
    );

    let mut other_tuple = tuple();
    other_tuple.compiled_recipe_sha256 = other_tuple.profile_lock_sha256;
    let other = evidence(member, &commit(), &other_tuple, cases(member), None).expect("evidence");
    assert_eq!(
        QualificationProposal::assemble(draft(), replace(member, other)),
        Err(IssuanceError::Closure(ClosureFault::Candidate)),
        "evidence for another tuple"
    );

    let mut unexplained = draft();
    unexplained.not_applicable.pop();
    assert_eq!(
        QualificationProposal::assemble(unexplained, all_evidence()),
        Err(IssuanceError::Capability),
        "a capability no case shows has no reason"
    );

    let mut contradicted = draft();
    contradicted.not_applicable.push(NotApplicable {
        capability: auths_recipe_qualification::CapabilityKind::Budget,
        reason: auths_recipe_qualification::BoundedText::parse("declared absent").expect("reason"),
    });
    assert_eq!(
        QualificationProposal::assemble(contradicted, all_evidence()),
        Err(IssuanceError::Capability),
        "a capability a case shows is declared absent"
    );
}

#[test]
fn a_record_does_not_close_over_other_evidence() {
    let assembled = proposal();
    let record = assembled.record().canonical_bytes();
    let bytes = |evidence: &[auths_recipe_qualification::QualificationEvidence]| -> Vec<Vec<u8>> {
        evidence
            .iter()
            .map(|artifact| artifact.canonical_bytes().to_vec())
            .collect()
    };
    let from = |held: &[Vec<u8>]| {
        let borrowed: Vec<&[u8]> = held.iter().map(Vec::as_slice).collect();
        QualificationProposal::from_parts(record, &borrowed)
    };
    let mut held = bytes(assembled.evidence());
    held.pop();
    assert_eq!(
        from(&held),
        Err(IssuanceError::Closure(ClosureFault::MemberSet))
    );

    // The same member with one more case: a valid artifact the record does
    // not name.
    let member = EvidenceMemberKind::Redaction;
    let mut more = cases(member);
    more.push(CaseReport::new("one-more", WallRow::Redaction, true).expect("case"));
    let substituted = evidence(member, &commit(), &tuple(), more, None).expect("evidence");
    let mut held = bytes(assembled.evidence());
    held[8] = substituted.canonical_bytes().to_vec();
    assert_eq!(
        from(&held),
        Err(IssuanceError::Closure(ClosureFault::Digest))
    );

    assert!(matches!(
        from(&[b"{}".to_vec()]),
        Err(IssuanceError::Format(_))
    ));
}

#[test]
fn a_signed_release_qualifies_its_deployment_and_nothing_else() {
    let root = root();
    let release_signer = signer(&root, 0x22, "release-signer");
    let proposal = proposal();
    let record = proposal.record().body();
    let attestation = release_signer
        .attest(&proposal, NOW, NOW, record.not_after)
        .expect("attestation");
    let index = release_signer
        .index(NOW, &[(proposal.record(), &attestation)])
        .expect("index");
    let list = root
        .revoke(1, NOW - HOUR, NOW + 47 * HOUR, Vec::new(), Vec::new())
        .expect("list");
    let verified = VerifiedQualifications::verify(
        root.trust_root(),
        &QualificationInputs {
            signer_certificate: release_signer.certificate().canonical_bytes(),
            revocation_list: list.canonical_bytes(),
            release_index: index.canonical_bytes(),
            records: &[proposal.record().canonical_bytes()],
            attestations: &[attestation.canonical_bytes()],
        },
    );
    let state = VerifierState::default();
    assert!(
        verified
            .evaluate(&tuple(), NOW, true, &state)
            .permits_lease()
    );
    let mut drifted = tuple();
    drifted.gateway_semantic_closure_sha256 = drifted.profile_lock_sha256;
    let verdict = verified.evaluate(&drifted, NOW, true, &state);
    assert_eq!(verdict.state, RecipeQualificationState::Stale);
    assert_eq!(verdict.refusal, Some(QualificationRefusal::DigestMismatch));

    // A proposal alone, with nothing signed, qualifies nothing.
    let unsigned = VerifiedQualifications::verify(
        root.trust_root(),
        &QualificationInputs {
            signer_certificate: release_signer.certificate().canonical_bytes(),
            revocation_list: list.canonical_bytes(),
            release_index: b"",
            records: &[proposal.record().canonical_bytes()],
            attestations: &[],
        },
    );
    assert!(
        !unsigned
            .evaluate(&tuple(), NOW, true, &state)
            .permits_lease()
    );
}

#[test]
fn each_signing_role_refuses_what_is_not_its_own() {
    let root = root();
    let release_signer = signer(&root, 0x22, "release-signer");
    let other_signer = signer(&root, 0x33, "other-signer");
    let proposal = proposal();
    let record = proposal.record().body();

    assert!(matches!(
        ReleaseSigner::open(&seed(0x44), release_signer.certificate().clone()),
        Err(IssuanceError::KeyMismatch)
    ));
    assert!(matches!(
        RootSigner::open(&seed(0x22), root.trust_root().clone()),
        Err(IssuanceError::KeyMismatch)
    ));
    for (not_before, not_after) in [
        (record.not_before - 1, record.not_after),
        (NOW, record.not_after + 1),
        (NOW - 2 * DAY, record.not_after),
    ] {
        assert_eq!(
            release_signer
                .attest(&proposal, NOW, not_before, not_after)
                .map(|_| ()),
            Err(IssuanceError::Window),
            "window {not_before}..{not_after}"
        );
    }
    let foreign = other_signer
        .attest(&proposal, NOW, NOW, record.not_after)
        .expect("attestation");
    assert_eq!(
        release_signer
            .index(NOW, &[(proposal.record(), &foreign)])
            .map(|_| ()),
        Err(IssuanceError::IndexEntry),
        "an index lists only its own signer's attestations"
    );
    assert!(
        root.revoke(1, NOW, NOW + 73 * HOUR, Vec::new(), Vec::new())
            .is_err(),
        "a list cannot be fresh for more than 72 hours"
    );
    assert_eq!(format!("{:?}", seed(0x55)), "SigningSeed(<redacted>)");
    assert!(!format!("{release_signer:?} {root:?}").contains("key"));
}

#[test]
fn the_differential_stage_reports_every_disagreement() {
    let corpus = [1_u8, 2, 3, 4];
    let reports = stages::differential(
        &corpus,
        |member| format!("member-{member}"),
        |member| member % 2 == 0,
        |member| member % 2 == 0 || *member == 3,
    )
    .expect("reports");
    let passed: Vec<bool> = reports.iter().map(|case| case.passed).collect();
    assert_eq!(passed, [true, true, false, true]);
    assert!(
        reports
            .iter()
            .all(|case| case.wall_row == WallRow::OracleAgreement)
    );
}

#[test]
fn the_redaction_stage_finds_a_canary_in_every_spelling() {
    use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
    let canary: &[u8] = b"canary-value-not-a-secret";
    let scan = |bytes: &[u8]| {
        stages::redaction(&[canary], &[stages::ScanSource { name: "log", bytes }]).expect("scan")[0]
            .passed
    };
    assert!(scan(b"request accepted, nothing else recorded"));
    assert!(!scan(b"header: canary-value-not-a-secret;"));
    assert!(!scan(hex::encode(canary).as_bytes()));
    assert!(!scan(hex::encode_upper(canary).as_bytes()));
    for lead in ["", "a", "ab", "abc", "abcd"] {
        let embedded = [lead.as_bytes(), canary, b"tail"].concat();
        assert!(!scan(Base64::encode_string(&embedded).as_bytes()), "{lead}");
        assert!(
            !scan(Base64UrlUnpadded::encode_string(&embedded).as_bytes()),
            "{lead}"
        );
    }
    assert_eq!(
        stages::redaction(
            &[b"short"],
            &[stages::ScanSource {
                name: "log",
                bytes: b"x"
            }]
        ),
        Err(IssuanceError::CaseFailed)
    );
    assert_eq!(
        stages::redaction(&[canary], &[]),
        Err(IssuanceError::CaseFailed)
    );
    assert_eq!(
        stages::redaction(
            &[],
            &[stages::ScanSource {
                name: "log",
                bytes: b"x"
            }]
        ),
        Err(IssuanceError::CaseFailed)
    );
}

#[test]
fn the_freshness_and_rotation_stages_hold_on_a_valid_candidate() {
    let root = root();
    let release_signer = signer(&root, 0x22, "release-signer");
    let proposal = proposal();
    let record = proposal.record().body();
    let attestation = release_signer
        .attest(&proposal, NOW, NOW, record.not_after)
        .expect("attestation");
    let index = release_signer
        .index(NOW, &[(proposal.record(), &attestation)])
        .expect("index");
    let list = root
        .revoke(1, NOW - HOUR, NOW + 47 * HOUR, Vec::new(), Vec::new())
        .expect("list");
    let inputs = QualificationInputs {
        signer_certificate: release_signer.certificate().canonical_bytes(),
        revocation_list: list.canonical_bytes(),
        release_index: index.canonical_bytes(),
        records: &[proposal.record().canonical_bytes()],
        attestations: &[attestation.canonical_bytes()],
    };
    let state = VerifierState::default();
    let fresh = stages::freshness(root.trust_root(), &inputs, &tuple(), &state, NOW + 1)
        .expect("freshness");
    assert_eq!(fresh.len(), 4);
    assert!(fresh.iter().all(|case| case.passed), "{fresh:?}");

    // The same stage on a deployment the release does not qualify fails its
    // first case rather than reporting a pass.
    let mut drifted = tuple();
    drifted.profile_lock_sha256 = drifted.compiled_recipe_sha256;
    let unqualified = stages::freshness(root.trust_root(), &inputs, &drifted, &state, NOW + 1)
        .expect("freshness");
    assert!(!unqualified[0].passed);

    let rotation = stages::signer_rotation(&proposal, NOW).expect("rotation");
    assert_eq!(rotation.len(), 7);
    assert!(rotation.iter().all(|case| case.passed), "{rotation:?}");
    assert_eq!(
        stages::signer_rotation(&proposal, record.not_after),
        Err(IssuanceError::Window)
    );

    // Both stages' cases are admissible evidence for the rotation member.
    let mut reported = cases(EvidenceMemberKind::Rotation);
    reported.extend(fresh);
    reported.extend(rotation);
    evidence(
        EvidenceMemberKind::Rotation,
        &commit(),
        &tuple(),
        reported,
        None,
    )
    .expect("rotation evidence");
    let _ = member_evidence(EvidenceMemberKind::Rotation);
}
