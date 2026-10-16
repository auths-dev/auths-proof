//! Frozen pre-refactor selector and visibility algorithms used only as differential oracles.
//! The production selector has no path to this module.
use super::*;
use auths_model::{StatusScope, StatusTrustRule, TrustAnchor};

struct ReferenceStatusMethod {
    id: StatusMethodId,
}
impl ReferenceStatusMethod {
    fn freshness(
        policy: &StatusPolicy,
        observed_at: Timestamp,
        valid_until: Timestamp,
        evaluation_time: Timestamp,
    ) -> StatusDecision {
        let StatusPolicy::SnapshotRequired { max_age, .. } = policy else {
            return StatusDecision::Active;
        };
        if observed_at > evaluation_time
            || valid_until < evaluation_time
            || evaluation_time.get().saturating_sub(observed_at.get()) > max_age.get()
        {
            StatusDecision::Stale
        } else {
            StatusDecision::Active
        }
    }
    fn principal(
        &self,
        policy: &StatusPolicy,
        snapshot: &PrincipalStatusSnapshot,
        principal: &PrincipalId,
        view: StatusView<'_>,
        evaluation_time: Timestamp,
    ) -> Result<StatusEvaluation, RegistryOperationError> {
        let StatusPolicy::SnapshotRequired { method, .. } = policy else {
            return Ok(StatusEvaluation::new(
                StatusDecision::Active,
                Timestamp::new(u64::MAX),
            ));
        };
        if method != &self.id {
            return Ok(StatusEvaluation::new(
                StatusDecision::WrongMethod,
                evaluation_time,
            ));
        }
        if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
            return Ok(StatusEvaluation::new(
                StatusDecision::Stale,
                evaluation_time,
            ));
        }
        let candidates: Vec<_> = snapshot
            .statements()
            .iter()
            .map(auths_model::SignedPrincipalStatus::statement)
            .filter(|statement| {
                statement.principal() == principal
                    && status_issuer_visible(snapshot.trust(), statement.issuer(), view)
            })
            .collect();
        select_principal(policy, snapshot, &candidates, evaluation_time)
    }

    fn grant(
        &self,
        policy: &StatusPolicy,
        snapshot: &GrantStatusSnapshot,
        grant: GrantId,
        view: StatusView<'_>,
        evaluation_time: Timestamp,
    ) -> Result<StatusEvaluation, RegistryOperationError> {
        let StatusPolicy::SnapshotRequired { method, .. } = policy else {
            return Ok(StatusEvaluation::new(
                StatusDecision::Active,
                Timestamp::new(u64::MAX),
            ));
        };
        if method != &self.id {
            return Ok(StatusEvaluation::new(
                StatusDecision::WrongMethod,
                evaluation_time,
            ));
        }
        if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
            return Ok(StatusEvaluation::new(
                StatusDecision::Stale,
                evaluation_time,
            ));
        }
        let candidates: Vec<_> = snapshot
            .statements()
            .iter()
            .map(auths_model::SignedGrantStatus::statement)
            .filter(|statement| {
                statement.grant_id() == grant
                    && status_issuer_visible(snapshot.trust(), statement.issuer(), view)
            })
            .collect();
        select_grant(policy, snapshot, &candidates, evaluation_time)
    }
}
fn select_principal(
    policy: &StatusPolicy,
    snapshot: &PrincipalStatusSnapshot,
    candidates: &[&auths_model::PrincipalStatusStatement],
    evaluation_time: Timestamp,
) -> Result<StatusEvaluation, RegistryOperationError> {
    let StatusPolicy::SnapshotRequired {
        method, max_age, ..
    } = policy
    else {
        return Ok(StatusEvaluation::new(
            StatusDecision::Active,
            Timestamp::new(u64::MAX),
        ));
    };
    if candidates.is_empty() {
        return Ok(StatusEvaluation::new(
            StatusDecision::Missing,
            snapshot.valid_until(),
        ));
    }
    if candidates
        .iter()
        .all(|statement| statement.method() != method)
    {
        return Ok(StatusEvaluation::new(
            StatusDecision::WrongMethod,
            evaluation_time,
        ));
    }
    let mut trusted = Vec::new();
    for statement in candidates
        .iter()
        .copied()
        .filter(|statement| statement.method() == method)
    {
        let Some(rule) = snapshot
            .trust()
            .iter()
            .find(|rule| rule.method() == method && rule.issuer() == statement.issuer())
        else {
            continue;
        };
        if statement.sequence() < rule.sequence_floor() {
            return Ok(StatusEvaluation::new(
                StatusDecision::Rollback,
                evaluation_time,
            ));
        }
        trusted.push(statement);
    }
    if trusted.is_empty() {
        return Ok(StatusEvaluation::new(
            StatusDecision::UntrustedIssuer,
            evaluation_time,
        ));
    }
    let maximum = trusted
        .iter()
        .map(|statement| statement.sequence())
        .max()
        .ok_or(RegistryOperationError::InvalidInput)?;
    let latest: Vec<_> = trusted
        .into_iter()
        .filter(|statement| statement.sequence() == maximum)
        .collect();
    if latest.iter().any(|statement| {
        ReferenceStatusMethod::freshness(
            policy,
            statement.observed_at(),
            statement.valid_until(),
            evaluation_time,
        ) == StatusDecision::Stale
    }) {
        return Ok(StatusEvaluation::new(
            StatusDecision::Stale,
            evaluation_time,
        ));
    }
    let valid_through = latest
        .iter()
        .fold(snapshot.valid_until(), |through, statement| {
            through.min(statement.valid_until()).min(Timestamp::new(
                statement.observed_at().get().saturating_add(max_age.get()),
            ))
        });
    let decision = if latest
        .iter()
        .any(|statement| statement.state() != PrincipalState::Active)
    {
        StatusDecision::Revoked
    } else {
        StatusDecision::Active
    };
    Ok(StatusEvaluation::new(decision, valid_through))
}

fn select_grant(
    policy: &StatusPolicy,
    snapshot: &GrantStatusSnapshot,
    candidates: &[&auths_model::GrantStatusStatement],
    evaluation_time: Timestamp,
) -> Result<StatusEvaluation, RegistryOperationError> {
    let StatusPolicy::SnapshotRequired {
        method, max_age, ..
    } = policy
    else {
        return Ok(StatusEvaluation::new(
            StatusDecision::Active,
            Timestamp::new(u64::MAX),
        ));
    };
    if candidates.is_empty() {
        return Ok(StatusEvaluation::new(
            StatusDecision::Missing,
            snapshot.valid_until(),
        ));
    }
    if candidates
        .iter()
        .all(|statement| statement.method() != method)
    {
        return Ok(StatusEvaluation::new(
            StatusDecision::WrongMethod,
            evaluation_time,
        ));
    }
    let mut trusted = Vec::new();
    for statement in candidates
        .iter()
        .copied()
        .filter(|statement| statement.method() == method)
    {
        let Some(rule) = snapshot
            .trust()
            .iter()
            .find(|rule| rule.method() == method && rule.issuer() == statement.issuer())
        else {
            continue;
        };
        if statement.sequence() < rule.sequence_floor() {
            return Ok(StatusEvaluation::new(
                StatusDecision::Rollback,
                evaluation_time,
            ));
        }
        trusted.push(statement);
    }
    if trusted.is_empty() {
        return Ok(StatusEvaluation::new(
            StatusDecision::UntrustedIssuer,
            evaluation_time,
        ));
    }
    let maximum = trusted
        .iter()
        .map(|statement| statement.sequence())
        .max()
        .ok_or(RegistryOperationError::InvalidInput)?;
    let latest: Vec<_> = trusted
        .into_iter()
        .filter(|statement| statement.sequence() == maximum)
        .collect();
    if latest.iter().any(|statement| {
        ReferenceStatusMethod::freshness(
            policy,
            statement.observed_at(),
            statement.valid_until(),
            evaluation_time,
        ) == StatusDecision::Stale
    }) {
        return Ok(StatusEvaluation::new(
            StatusDecision::Stale,
            evaluation_time,
        ));
    }
    let valid_through = latest
        .iter()
        .fold(snapshot.valid_until(), |through, statement| {
            through.min(statement.valid_until()).min(Timestamp::new(
                statement.observed_at().get().saturating_add(max_age.get()),
            ))
        });
    let decision = if latest
        .iter()
        .any(|statement| statement.state() != GrantState::Active)
    {
        StatusDecision::Revoked
    } else {
        StatusDecision::Active
    };
    Ok(StatusEvaluation::new(decision, valid_through))
}
fn status_issuer_visible(
    trust: &[StatusTrustRule],
    issuer: &PrincipalId,
    view: StatusView<'_>,
) -> bool {
    match view {
        StatusView::Anchor(anchor) => {
            trust
                .iter()
                .filter(|rule| rule.issuer() == issuer)
                .all(|rule| match rule.scope() {
                    StatusScope::OwnAnchor => anchor.principal() == issuer,
                    StatusScope::Anchors(anchors) => {
                        anchors.ids().binary_search(anchor.id()).is_ok()
                    }
                    StatusScope::AnyAnchor => true,
                })
        }
        StatusView::Approver => trust
            .iter()
            .filter(|rule| rule.issuer() == issuer)
            .all(|rule| matches!(rule.scope(), StatusScope::AnyAnchor)),
    }
}

fn principal(value: &str) -> PrincipalId {
    PrincipalId::parse(value).expect("principal")
}

fn method(value: &str) -> StatusMethodId {
    StatusMethodId::parse(value).expect("status method")
}

fn status_anchor(id: &str, root: &str) -> TrustAnchor {
    TrustAnchor::new(
        auths_model::TrustAnchorId::parse(id).expect("anchor ID"),
        principal(root),
        vec![PrincipalMethodId::parse("raw-key-v1").expect("method")],
        vec![
            auths_model::ProfileRef::new(
                auths_model::ProfileId::parse("auths.mcp").expect("profile"),
                1,
            )
            .expect("profile"),
        ],
        auths_model::PermissionSet::new(vec![auths_model::Permission::new(
            auths_model::CapabilityId::parse("tools/call").expect("capability"),
            ResourceId::parse("mcp://reports/read").expect("resource"),
        )])
        .expect("permissions"),
        Vec::new(),
        auths_model::AudienceSet::new(vec![
            auths_model::Audience::parse("audience://verifier").expect("audience"),
        ])
        .expect("audiences"),
        auths_model::ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).expect("validity"),
        None,
        1,
        auths_model::AssurancePolicyId::parse("policy").expect("policy"),
        StatusPolicy::ExpiryOnly,
    )
    .expect("anchor")
}

fn envelope() -> auths_model::SignatureEnvelope {
    auths_model::SignatureEnvelope::new(
        auths_model::SignatureDescriptor::new(
            PrincipalMethodId::parse("raw-key-v1").expect("method"),
            auths_model::VerificationMethod::parse("raw:issuer#key-1").expect("key"),
            SignatureSuiteId::parse("ed25519-v1").expect("suite"),
        ),
        auths_model::SignatureBytes::new(vec![1; 64]).expect("signature"),
    )
}

fn rule(status_method: &str, issuer: &str, floor: u64, scope: StatusScope) -> StatusTrustRule {
    StatusTrustRule::new(method(status_method), principal(issuer), floor, scope)
}

/// Seeded boundary/property generator, matching the crate's dependency-free
/// property-test convention. Every snapshot passes the actual constructors.
struct Cases(u64);
impl Cases {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let value = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        usize::try_from(value % u64::try_from(bound).expect("small bound")).expect("small value")
    }
    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len())]
    }
}

fn outcome_index(decision: StatusDecision) -> usize {
    match decision {
        StatusDecision::Active => 0,
        StatusDecision::Revoked => 1,
        StatusDecision::Missing => 2,
        StatusDecision::Stale => 3,
        StatusDecision::Rollback => 4,
        StatusDecision::UntrustedIssuer => 5,
        StatusDecision::WrongMethod => 6,
    }
}

const METHODS: [&str; 2] = ["auths-principal-status-v1", "other-principal-status-v1"];
const ISSUERS: [&str; 4] = ["raw:v-root", "raw:f-root", "raw:other", "raw:unknown"];
const SUBJECTS: [&str; 3] = ["raw:actor", "raw:other-actor", "raw:third-actor"];

fn generated_trust(cases: &mut Cases, anchors: &[TrustAnchor; 2]) -> Vec<StatusTrustRule> {
    use auths_model::StatusScopeAnchors;
    let methods = METHODS;
    let issuers = ISSUERS;
    let mut trust = Vec::new();
    for status_method in methods {
        for issuer in &issuers[..3] {
            if cases.below(2) == 0 {
                let scope = match cases.below(4) {
                    0 => StatusScope::OwnAnchor,
                    1 => StatusScope::Anchors(
                        StatusScopeAnchors::new(vec![anchors[cases.below(2)].id().clone()])
                            .expect("scope"),
                    ),
                    _ => StatusScope::AnyAnchor,
                };
                trust.push(rule(
                    status_method,
                    issuer,
                    cases.pick(&[0, 1, 3, u64::MAX]),
                    scope,
                ));
            }
        }
    }
    trust
}

fn generated_snapshots(
    cases: &mut Cases,
    anchors: &[TrustAnchor; 2],
) -> Option<(PrincipalStatusSnapshot, GrantStatusSnapshot)> {
    use auths_model::{
        CriticalExtensions, GrantStatusStatement, PrincipalStatusStatement, SignedGrantStatus,
        SignedPrincipalStatus, StatusSnapshotId,
    };
    let methods = METHODS;
    let issuers = ISSUERS;
    let subjects = SUBJECTS;
    let trust = generated_trust(cases, anchors);
    let mut principals = Vec::new();
    let mut grants = Vec::new();
    for _ in 0..cases.below(13) {
        let subject = cases.below(3);
        let status_method = method(cases.pick(&methods));
        let issuer = principal(cases.pick(&issuers));
        let sequence = cases.pick(&[0, 1, 2, 3, u64::MAX]);
        let observed = Timestamp::new(cases.pick(&[0, 20, 40]));
        let until = Timestamp::new(cases.pick(&[100, 120, u64::MAX]));
        let state = cases.below(3);
        let principal_state = [
            PrincipalState::Active,
            PrincipalState::Revoked,
            PrincipalState::Superseded,
        ][state];
        let grant_state = [
            GrantState::Active,
            GrantState::Revoked,
            GrantState::Superseded,
        ][state];
        principals.push(SignedPrincipalStatus::new(
            PrincipalStatusStatement::new(
                status_method.clone(),
                principal(subjects[subject]),
                principal_state,
                sequence,
                observed,
                until,
                issuer.clone(),
                CriticalExtensions::empty(),
            )
            .expect("principal statement"),
            envelope(),
        ));
        grants.push(SignedGrantStatus::new(
            GrantStatusStatement::new(
                status_method,
                GrantId::new([u8::try_from(subject).expect("small subject"); 32]),
                grant_state,
                sequence,
                observed,
                until,
                issuer,
                CriticalExtensions::empty(),
            )
            .expect("grant statement"),
            envelope(),
        ));
    }
    let snapshots = (
        PrincipalStatusSnapshot::with_trust(
            StatusSnapshotId::new([1; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            principals,
            Vec::new(),
            trust.clone(),
        ),
        GrantStatusSnapshot::with_trust(
            StatusSnapshotId::new([2; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            grants,
            Vec::new(),
            trust,
        ),
    );
    let (Ok(principal), Ok(grant)) = snapshots else {
        return None;
    };
    Some((principal, grant))
}

#[test]
fn status_selection_matches_frozen_reference_on_validated_boundary_properties() {
    use auths_model::FreshnessLimit;
    let methods = METHODS;
    let issuers = ISSUERS;
    let subjects = SUBJECTS;
    let anchors = [
        status_anchor("anchor-v", issuers[0]),
        status_anchor("anchor-f", issuers[1]),
    ];
    let views = [
        StatusView::Anchor(&anchors[0]),
        StatusView::Anchor(&anchors[1]),
        StatusView::Approver,
    ];
    let mut principal_outcomes = [0_u64; 7];
    let mut grant_outcomes = [0_u64; 7];
    let mut horizons = alloc::collections::BTreeSet::new();
    let mut checked = 0;
    for seed in [1, 0x5eed, 0x1234_5678_9abc_def0, u64::MAX] {
        let mut cases = Cases(seed);
        for _ in 0..5_000 {
            // Duplicate generated statements are outside the constructor's domain.
            let Some((principal_snapshot, grant_snapshot)) =
                generated_snapshots(&mut cases, &anchors)
            else {
                continue;
            };
            let id = method(cases.pick(&methods));
            let actual = ExactStatusMethod { id: id.clone() };
            let reference = ReferenceStatusMethod { id };
            let policy = if cases.below(8) == 0 {
                StatusPolicy::ExpiryOnly
            } else {
                StatusPolicy::SnapshotRequired {
                    method: method(cases.pick(&methods)),
                    max_age: FreshnessLimit::new(cases.pick(&[1, 10, 20, 100, u64::MAX]))
                        .expect("age"),
                }
            };
            let now = Timestamp::new(cases.pick(&[0, 39, 40, 41, 49, 50, 60, 100, 101, u64::MAX]));
            let subject_index = cases.below(4);
            let subject =
                principal([subjects[0], subjects[1], subjects[2], "raw:absent"][subject_index]);
            let grant = GrantId::new([u8::try_from(subject_index).expect("small subject"); 32]);
            for view in views {
                for issuer in issuers {
                    assert_eq!(
                        auths_model::status_issuer_visible(
                            principal_snapshot.trust(),
                            &principal(issuer),
                            view
                        ),
                        status_issuer_visible(principal_snapshot.trust(), &principal(issuer), view),
                        "visibility seed {seed}"
                    );
                }
                let principal_result =
                    actual.principal(&policy, &principal_snapshot, &subject, view, now);
                let grant_result = actual.grant(&policy, &grant_snapshot, grant, view, now);
                assert_eq!(
                    principal_result,
                    reference.principal(&policy, &principal_snapshot, &subject, view, now),
                    "principal seed {seed}; snapshot {principal_snapshot:?}; policy {policy:?}; now {now:?}; view {view:?}"
                );
                assert_eq!(
                    grant_result,
                    reference.grant(&policy, &grant_snapshot, grant, view, now),
                    "grant seed {seed}; snapshot {grant_snapshot:?}; policy {policy:?}; now {now:?}; view {view:?}"
                );
                let principal_evaluation = principal_result.expect("total status evaluation");
                let grant_evaluation = grant_result.expect("total status evaluation");
                principal_outcomes[outcome_index(principal_evaluation.decision())] += 1;
                grant_outcomes[outcome_index(grant_evaluation.decision())] += 1;
                horizons.insert(principal_evaluation.valid_through().get());
                horizons.insert(grant_evaluation.valid_through().get());
            }
            checked += 1;
        }
    }
    assert!(checked > 19_000, "valid cases: {checked}");
    assert!(
        principal_outcomes.iter().all(|count| *count > 0),
        "principal decisions: {principal_outcomes:?}"
    );
    assert!(
        grant_outcomes.iter().all(|count| *count > 0),
        "grant decisions: {grant_outcomes:?}"
    );
    assert!(
        horizons.contains(&u64::MAX) && horizons.len() >= 10,
        "horizon diversity: {horizons:?}"
    );
}

#[test]
fn status_selection_keeps_latest_ties_rollback_and_stale_precedence() {
    use auths_model::{
        CriticalExtensions, FreshnessLimit, PrincipalStatusStatement, SignedPrincipalStatus,
        StatusSnapshotId,
    };
    let id = method("auths-principal-status-v1");
    let implementation = ExactStatusMethod { id: id.clone() };
    let policy = StatusPolicy::SnapshotRequired {
        method: id.clone(),
        max_age: FreshnessLimit::new(20).expect("age"),
    };
    let signed = |state, sequence, observed, issuer: &str| {
        SignedPrincipalStatus::new(
            PrincipalStatusStatement::new(
                id.clone(),
                principal("raw:actor"),
                state,
                sequence,
                Timestamp::new(observed),
                Timestamp::new(100),
                principal(issuer),
                CriticalExtensions::empty(),
            )
            .expect("statement"),
            envelope(),
        )
    };
    let evaluate = |statements, floor| {
        let snapshot = PrincipalStatusSnapshot::with_trust(
            StatusSnapshotId::new([3; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            statements,
            Vec::new(),
            vec![
                rule(id.as_str(), "raw:v-root", floor, StatusScope::AnyAnchor),
                rule(id.as_str(), "raw:f-root", 0, StatusScope::AnyAnchor),
            ],
        )
        .expect("snapshot");
        implementation
            .principal(
                &policy,
                &snapshot,
                &principal("raw:actor"),
                StatusView::Approver,
                Timestamp::new(50),
            )
            .expect("evaluation")
    };
    assert_eq!(
        evaluate(
            vec![
                signed(PrincipalState::Revoked, 1, 0, "raw:v-root"),
                signed(PrincipalState::Active, 2, 40, "raw:v-root")
            ],
            0
        ),
        StatusEvaluation::new(StatusDecision::Active, Timestamp::new(60))
    );
    assert_eq!(
        evaluate(
            vec![
                signed(PrincipalState::Active, 2, 40, "raw:v-root"),
                signed(PrincipalState::Superseded, 2, 40, "raw:f-root")
            ],
            0
        ),
        StatusEvaluation::new(StatusDecision::Revoked, Timestamp::new(60))
    );
    assert_eq!(
        evaluate(
            vec![
                signed(PrincipalState::Active, 1, 40, "raw:v-root"),
                signed(PrincipalState::Active, 2, 40, "raw:f-root")
            ],
            2
        ),
        StatusEvaluation::new(StatusDecision::Rollback, Timestamp::new(50))
    );
    assert_eq!(
        evaluate(
            vec![
                signed(PrincipalState::Revoked, 2, 40, "raw:v-root"),
                signed(PrincipalState::Active, 2, 0, "raw:f-root")
            ],
            0
        ),
        StatusEvaluation::new(StatusDecision::Stale, Timestamp::new(50))
    );
}

struct WordLimitFixture {
    implementation: ExactStatusMethod,
    principal_snapshot: PrincipalStatusSnapshot,
    grant_snapshot: GrantStatusSnapshot,
    subject: PrincipalId,
    grant: GrantId,
}

fn word_limit_fixture() -> WordLimitFixture {
    use auths_model::{
        CriticalExtensions, GrantStatusStatement, PrincipalStatusStatement, SignedGrantStatus,
        SignedPrincipalStatus, StatusSnapshotId,
    };
    let id = method(METHODS[0]);
    let implementation = ExactStatusMethod { id: id.clone() };
    let observed = Timestamp::new(u64::MAX - 5);
    let end = Timestamp::new(u64::MAX);
    let issuer = principal(ISSUERS[0]);
    let subject = principal(SUBJECTS[0]);
    let grant = GrantId::new([7; 32]);
    let trust = vec![rule(
        METHODS[0],
        ISSUERS[0],
        u64::MAX,
        StatusScope::AnyAnchor,
    )];
    let principal_snapshot = PrincipalStatusSnapshot::with_trust(
        StatusSnapshotId::new([3; 32]),
        observed,
        end,
        vec![SignedPrincipalStatus::new(
            PrincipalStatusStatement::new(
                id.clone(),
                subject.clone(),
                PrincipalState::Active,
                u64::MAX,
                observed,
                end,
                issuer.clone(),
                CriticalExtensions::empty(),
            )
            .expect("statement"),
            envelope(),
        )],
        Vec::new(),
        trust.clone(),
    )
    .expect("snapshot");
    let grant_snapshot = GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([4; 32]),
        observed,
        end,
        vec![SignedGrantStatus::new(
            GrantStatusStatement::new(
                id,
                grant,
                GrantState::Active,
                u64::MAX,
                observed,
                end,
                issuer,
                CriticalExtensions::empty(),
            )
            .expect("statement"),
            envelope(),
        )],
        Vec::new(),
        trust,
    )
    .expect("snapshot");
    WordLimitFixture {
        implementation,
        principal_snapshot,
        grant_snapshot,
        subject,
        grant,
    }
}

#[test]
fn status_selection_preserves_word_limits_and_header_precedence() {
    use auths_model::FreshnessLimit;
    let WordLimitFixture {
        implementation,
        principal_snapshot,
        grant_snapshot,
        subject,
        grant,
    } = word_limit_fixture();
    let cases = [
        (
            StatusPolicy::SnapshotRequired {
                method: method(METHODS[0]),
                max_age: FreshnessLimit::new(10).expect("age"),
            },
            u64::MAX - 3,
            StatusDecision::Active,
            u64::MAX,
        ),
        (
            StatusPolicy::SnapshotRequired {
                method: method(METHODS[0]),
                max_age: FreshnessLimit::new(1).expect("age"),
            },
            u64::MAX - 3,
            StatusDecision::Stale,
            u64::MAX - 3,
        ),
        (
            StatusPolicy::SnapshotRequired {
                method: method(METHODS[1]),
                max_age: FreshnessLimit::new(1).expect("age"),
            },
            0,
            StatusDecision::WrongMethod,
            0,
        ),
        (
            StatusPolicy::ExpiryOnly,
            0,
            StatusDecision::Active,
            u64::MAX,
        ),
    ];
    for (policy, now, decision, through) in cases {
        let expected = Ok(StatusEvaluation::new(decision, Timestamp::new(through)));
        assert_eq!(
            implementation.principal(
                &policy,
                &principal_snapshot,
                &subject,
                StatusView::Approver,
                Timestamp::new(now)
            ),
            expected
        );
        assert_eq!(
            implementation.grant(
                &policy,
                &grant_snapshot,
                grant,
                StatusView::Approver,
                Timestamp::new(now)
            ),
            expected
        );
    }
}
