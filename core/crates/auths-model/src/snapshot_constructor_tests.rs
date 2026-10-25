//! Frozen snapshot constructors from ce7f1f3c for source-cutover evidence.
//! Global duplicate refusal is an intentional correction; all other result and
//! normalized-order behavior remains compared with these former algorithms.

use super::*;

fn former_principal(
    id: StatusSnapshotId,
    observed_at: Timestamp,
    valid_until: Timestamp,
    mut statements: Vec<SignedPrincipalStatus>,
    mut checkpoints: Vec<EvidenceId>,
    mut trust: Vec<StatusTrustRule>,
) -> Result<PrincipalStatusSnapshot, ModelError> {
    if observed_at > valid_until
        || statements.len() > HARD_MAX_PRINCIPAL_STATUS
        || checkpoints.len() > HARD_MAX_EVIDENCE
        || trust.len() > HARD_MAX_REGISTRY_ENTRIES
    {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    statements.sort_by(|left, right| {
        left.statement()
            .principal()
            .cmp(right.statement().principal())
            .then_with(|| left.statement().method().cmp(right.statement().method()))
            .then_with(|| {
                left.statement()
                    .sequence()
                    .cmp(&right.statement().sequence())
            })
            .then_with(|| left.statement().issuer().cmp(right.statement().issuer()))
    });
    if statements
        .windows(2)
        .any(|window| window[0].statement() == window[1].statement())
        || statements.iter().any(|signed| {
            signed.statement().observed_at() > observed_at
                || signed.statement().valid_until() < valid_until
        })
    {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    checkpoints.sort();
    checkpoints.dedup();
    trust.sort();
    if trust.windows(2).any(|window| {
        window[0].method() == window[1].method() && window[0].issuer() == window[1].issuer()
    }) {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    Ok(PrincipalStatusSnapshot {
        id,
        observed_at,
        valid_until,
        statements,
        checkpoints,
        trust,
    })
}

fn former_grant(
    id: StatusSnapshotId,
    observed_at: Timestamp,
    valid_until: Timestamp,
    mut statements: Vec<SignedGrantStatus>,
    mut checkpoints: Vec<EvidenceId>,
    mut trust: Vec<StatusTrustRule>,
) -> Result<GrantStatusSnapshot, ModelError> {
    if observed_at > valid_until
        || statements.len() > HARD_MAX_GRANT_STATUS
        || checkpoints.len() > HARD_MAX_EVIDENCE
        || trust.len() > HARD_MAX_REGISTRY_ENTRIES
    {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    statements.sort_by(|left, right| {
        left.statement()
            .grant_id()
            .cmp(&right.statement().grant_id())
            .then_with(|| left.statement().method().cmp(right.statement().method()))
            .then_with(|| {
                left.statement()
                    .sequence()
                    .cmp(&right.statement().sequence())
            })
            .then_with(|| left.statement().issuer().cmp(right.statement().issuer()))
    });
    if statements
        .windows(2)
        .any(|window| window[0].statement() == window[1].statement())
        || statements.iter().any(|signed| {
            signed.statement().observed_at() > observed_at
                || signed.statement().valid_until() < valid_until
        })
    {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    checkpoints.sort();
    checkpoints.dedup();
    trust.sort();
    if trust.windows(2).any(|window| {
        window[0].method() == window[1].method() && window[0].issuer() == window[1].issuer()
    }) {
        return Err(ModelError::InvalidStatusSnapshot);
    }
    Ok(GrantStatusSnapshot {
        id,
        observed_at,
        valid_until,
        statements,
        checkpoints,
        trust,
    })
}


use alloc::vec;

fn signature(byte: u8) -> SignatureEnvelope {
    SignatureEnvelope::new(
        SignatureDescriptor::new(
            PrincipalMethodId::parse("did-key").unwrap(),
            VerificationMethod::parse("did:example:issuer#key-1").unwrap(),
            SignatureSuiteId::parse("eddsa-ed25519").unwrap(),
        ),
        SignatureBytes::new(vec![byte; 64]).unwrap(),
    )
}

fn principal(state: PrincipalState, sequence: u64, signature_byte: u8) -> SignedPrincipalStatus {
    SignedPrincipalStatus::new(
        PrincipalStatusStatement::new(
            StatusMethodId::parse("status-test-v1").unwrap(),
            PrincipalId::parse("did:example:subject").unwrap(),
            state,
            sequence,
            Timestamp::new(0),
            Timestamp::new(100),
            PrincipalId::parse("did:example:issuer").unwrap(),
            CriticalExtensions::empty(),
        ).unwrap(),
        signature(signature_byte),
    )
}

fn grant(state: GrantState, sequence: u64, signature_byte: u8) -> SignedGrantStatus {
    SignedGrantStatus::new(
        GrantStatusStatement::new(
            StatusMethodId::parse("status-test-v1").unwrap(),
            GrantId::new([9; 32]),
            state,
            sequence,
            Timestamp::new(0),
            Timestamp::new(100),
            PrincipalId::parse("did:example:issuer").unwrap(),
            CriticalExtensions::empty(),
        ).unwrap(),
        signature(signature_byte),
    )
}

#[test]
fn principal_duplicate_cannot_hide_behind_a_distinct_same_key_statement() {
    let active = principal(PrincipalState::Active, 7, 1);
    let revoked = principal(PrincipalState::Revoked, 7, 2);
    let resigned = principal(PrincipalState::Active, 7, 3);
    let statements = vec![active, revoked.clone(), resigned];
    assert!(former_principal(
        StatusSnapshotId::new([1; 32]), Timestamp::new(20), Timestamp::new(80),
        statements.clone(), vec![], vec![],
    ).is_ok(), "frozen oracle must reproduce the former gap");
    assert_eq!(PrincipalStatusSnapshot::with_trust(
        StatusSnapshotId::new([1; 32]), Timestamp::new(20), Timestamp::new(80),
        statements, vec![], vec![],
    ), Err(ModelError::InvalidStatusSnapshot));
    // Conflicting but distinct statements are retained. Choosing between them
    // belongs to the status selector, whose ambiguity refusal is unchanged.
    assert!(PrincipalStatusSnapshot::with_trust(
        StatusSnapshotId::new([1; 32]), Timestamp::new(20), Timestamp::new(80),
        vec![principal(PrincipalState::Active, 7, 1), revoked], vec![], vec![],
    ).is_ok());
}

#[test]
fn grant_duplicate_cannot_hide_behind_a_distinct_same_key_statement() {
    let active = grant(GrantState::Active, 7, 1);
    let revoked = grant(GrantState::Revoked, 7, 2);
    let resigned = grant(GrantState::Active, 7, 3);
    let statements = vec![active, revoked.clone(), resigned];
    assert!(former_grant(
        StatusSnapshotId::new([2; 32]), Timestamp::new(20), Timestamp::new(80),
        statements.clone(), vec![], vec![],
    ).is_ok(), "frozen oracle must reproduce the former gap");
    assert_eq!(GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([2; 32]), Timestamp::new(20), Timestamp::new(80),
        statements, vec![], vec![],
    ), Err(ModelError::InvalidStatusSnapshot));
    assert!(GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([2; 32]), Timestamp::new(20), Timestamp::new(80),
        vec![grant(GrantState::Active, 7, 1), revoked], vec![], vec![],
    ).is_ok());
}

#[test]
fn full_snapshot_result_and_order_match_except_for_global_duplicate_correction() {
    let principal_choices = [
        principal(PrincipalState::Active, 7, 1),
        principal(PrincipalState::Revoked, 7, 2),
        principal(PrincipalState::Active, 7, 3),
        principal(PrincipalState::Active, 8, 1),
    ];
    let grant_choices = [
        grant(GrantState::Active, 7, 1),
        grant(GrantState::Revoked, 7, 2),
        grant(GrantState::Active, 7, 3),
        grant(GrantState::Active, 8, 1),
    ];
    for length in 0..=5_u32 {
        for encoded in 0..4_usize.pow(length) {
            let mut choice = encoded;
            let mut principals = Vec::new();
            let mut grants = Vec::new();
            for _ in 0..length {
                principals.push(principal_choices[choice % 4].clone());
                grants.push(grant_choices[choice % 4].clone());
                choice /= 4;
            }
            let duplicate = principals.iter().enumerate().any(|(index, value)|
                principals[..index].iter().any(|earlier| earlier.statement() == value.statement()));
            let expected_principal = former_principal(
                StatusSnapshotId::new([1; 32]), Timestamp::new(20), Timestamp::new(80),
                principals.clone(), vec![], vec![],
            );
            let expected_grant = former_grant(
                StatusSnapshotId::new([2; 32]), Timestamp::new(20), Timestamp::new(80),
                grants.clone(), vec![], vec![],
            );
            let actual_principal = PrincipalStatusSnapshot::with_trust(
                StatusSnapshotId::new([1; 32]), Timestamp::new(20), Timestamp::new(80),
                principals, vec![], vec![],
            );
            let actual_grant = GrantStatusSnapshot::with_trust(
                StatusSnapshotId::new([2; 32]), Timestamp::new(20), Timestamp::new(80),
                grants, vec![], vec![],
            );
            if duplicate {
                assert_eq!(actual_principal, Err(ModelError::InvalidStatusSnapshot));
                assert_eq!(actual_grant, Err(ModelError::InvalidStatusSnapshot));
            } else {
                assert_eq!(actual_principal, expected_principal);
                assert_eq!(actual_grant, expected_grant);
            }
        }
    }
}

#[test]
fn existing_snapshot_time_capacity_and_checkpoint_normalization_are_preserved() {
    for (observed, valid) in [(20, 80), (0, 100), (100, 100), (101, 100), (20, 101)] {
        let principal_values = vec![principal(PrincipalState::Active, 1, 1)];
        let grant_values = vec![grant(GrantState::Active, 1, 1)];
        let checkpoints = vec![EvidenceId::new([2; 32]), EvidenceId::new([1; 32]), EvidenceId::new([2; 32])];
        assert_eq!(
            PrincipalStatusSnapshot::with_trust(
                StatusSnapshotId::new([1; 32]), Timestamp::new(observed), Timestamp::new(valid),
                principal_values.clone(), checkpoints.clone(), vec![],
            ),
            former_principal(
                StatusSnapshotId::new([1; 32]), Timestamp::new(observed), Timestamp::new(valid),
                principal_values, checkpoints.clone(), vec![],
            ),
        );
        assert_eq!(
            GrantStatusSnapshot::with_trust(
                StatusSnapshotId::new([2; 32]), Timestamp::new(observed), Timestamp::new(valid),
                grant_values.clone(), checkpoints.clone(), vec![],
            ),
            former_grant(
                StatusSnapshotId::new([2; 32]), Timestamp::new(observed), Timestamp::new(valid),
                grant_values, checkpoints, vec![],
            ),
        );
    }
    let too_many_principals = vec![principal(PrincipalState::Active, 1, 1); HARD_MAX_PRINCIPAL_STATUS + 1];
    let too_many_grants = vec![grant(GrantState::Active, 1, 1); HARD_MAX_GRANT_STATUS + 1];
    assert_eq!(
        PrincipalStatusSnapshot::with_trust(StatusSnapshotId::new([1; 32]), Timestamp::new(20),
            Timestamp::new(80), too_many_principals.clone(), vec![], vec![]),
        former_principal(StatusSnapshotId::new([1; 32]), Timestamp::new(20),
            Timestamp::new(80), too_many_principals, vec![], vec![]),
    );
    assert_eq!(
        GrantStatusSnapshot::with_trust(StatusSnapshotId::new([2; 32]), Timestamp::new(20),
            Timestamp::new(80), too_many_grants.clone(), vec![], vec![]),
        former_grant(StatusSnapshotId::new([2; 32]), Timestamp::new(20),
            Timestamp::new(80), too_many_grants, vec![], vec![]),
    );
}
