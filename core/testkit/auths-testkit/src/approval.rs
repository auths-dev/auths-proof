//! Native K-of-N approval corpus vectors.
//!
//! A root grants the actor the scope of one action, and the actor signs it:
//! one authority branch. Three managers A, B, and C, and an outsider O, each
//! have an approver anchor. In the context vectors the trusted context
//! requires two of {A, B, C}; in the grant vectors the root's grant carries
//! the same requirement in `approval-requirement-v1`. The presenter attaches
//! the signed approvals it holds, in any order and with repetitions and
//! strays, and the verifier counts distinct approvers.
//!
//! Encodings a valid model cannot represent (one approval past the count
//! bound) are derived from canonical encodings by extending the final array,
//! so every vector still comes from this generator.

use super::*;
use auths_codec::{
    approval_requirement_id, approval_signing_preimage, encode_approval_requirements,
    encode_signed_approval,
};
use auths_model::{
    ApprovalRequirement, ApprovalRequirementId, ApprovalRequirements, ApprovalStatement,
    ApproverAnchor, SignedApproval, StatusScope,
};
use auths_registries::APPROVAL_REQUIREMENT_EXTENSION_V1;

const STATUS_METHOD: &str = "auths-principal-status-v1";
const OTHER_BODY: &[u8] = &[
    0xa2, 0x00, 0x64, b'r', b'e', b'a', b'd', 0x01, 0x6f, b'/', b'r', b'e', b'p', b'o', b'r', b't',
    b's', b'/', b'q', b'4', b'.', b'p', b'd', b'f',
];

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
enum Who {
    Root,
    Actor,
    Middle,
    A,
    B,
    C,
    Outsider,
    StatusService,
}

fn identity(who: Who) -> Identity {
    Identity::ed25519(match who {
        Who::Root => 231,
        Who::Actor => 232,
        Who::Middle => 233,
        Who::A => 234,
        Who::B => 235,
        Who::C => 236,
        Who::Outsider => 237,
        Who::StatusService => 238,
    })
}

fn requirement(approvers: &[Who], threshold: u16) -> ApprovalRequirement {
    ApprovalRequirement::new(
        approvers
            .iter()
            .map(|who| identity(*who).principal)
            .collect(),
        threshold,
    )
    .expect("fixture approval requirement")
}

fn managers() -> ApprovalRequirement {
    requirement(&[Who::A, Who::B, Who::C], 2)
}

fn identifier(requirement: &ApprovalRequirement) -> ApprovalRequirementId {
    approval_requirement_id(requirement).expect("requirement identifier")
}

/// How one approval deviates from an exact approval of the request.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    OtherBody,
    OtherAudience,
    OtherChallenge,
    OtherRequirement,
    Expired,
    /// Names its approver but is signed with the actor's key.
    Forged,
}

#[derive(Clone, Copy)]
struct Approval {
    by: Who,
    /// The requirement it binds; `None` binds the case's first requirement.
    requirement: Option<fn() -> ApprovalRequirement>,
    fault: Fault,
}

const fn approval(by: Who) -> Approval {
    Approval {
        by,
        requirement: None,
        fault: Fault::None,
    }
}

const fn faulty(by: Who, fault: Fault) -> Approval {
    Approval {
        by,
        requirement: None,
        fault,
    }
}

const fn for_requirement(by: Who, requirement: fn() -> ApprovalRequirement) -> Approval {
    Approval {
        by,
        requirement: Some(requirement),
        fault: Fault::None,
    }
}

fn sign_approval(signer: &Identity, statement: ApprovalStatement) -> SignedApproval {
    let descriptor = signer.descriptor();
    let preimage =
        approval_signing_preimage(&statement, &descriptor, &profile()).expect("approval preimage");
    SignedApproval::new(
        statement,
        SignatureEnvelope::new(descriptor, signer.sign(&preimage)),
        vec![signer.evidence()],
    )
    .expect("signed approval")
}

fn build_approval(spec: Approval, default_requirement: &ApprovalRequirement) -> SignedApproval {
    let approver = identity(spec.by);
    let bound = spec
        .requirement
        .map_or_else(|| default_requirement.clone(), |make| make());
    let requirement_id = if spec.fault == Fault::OtherRequirement {
        identifier(&requirement(&[Who::A, Who::B, Who::C], 3))
    } else {
        identifier(&bound)
    };
    let body: &[u8] = if spec.fault == Fault::OtherBody {
        OTHER_BODY
    } else {
        BODY
    };
    let audience = if spec.fault == Fault::OtherAudience {
        Audience::parse("mcp://elsewhere").expect("audience")
    } else {
        audience()
    };
    let challenge = if spec.fault == Fault::OtherChallenge {
        Challenge::new([0x23; 32])
    } else {
        Challenge::new([0x22; 32])
    };
    let validity = if spec.fault == Fault::Expired {
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(49)).expect("validity")
    } else {
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity")
    };
    let statement = ApprovalStatement::new(
        approver.principal.clone(),
        requirement_id,
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        body_digest(body),
        permission(),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget algebra"),
            5,
        )),
        None,
        audience,
        challenge,
        validity,
    );
    if spec.fault == Fault::Forged {
        let presenter = identity(Who::Actor);
        let descriptor = approver.descriptor();
        let preimage = approval_signing_preimage(&statement, &descriptor, &profile())
            .expect("approval preimage");
        return SignedApproval::new(
            statement,
            SignatureEnvelope::new(descriptor, presenter.sign(&preimage)),
            vec![approver.evidence()],
        )
        .expect("forged approval");
    }
    sign_approval(&approver, statement)
}

/// The approver anchor's status policy in a case.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Status {
    /// No approver's status is checked.
    None,
    /// B's status is required; the snapshot says B is active.
    BActive,
    /// B's status is required; the snapshot says B is revoked.
    BRevoked,
    /// B's status is required; the snapshot names no statement about B.
    BMissing,
    /// B's status is required; B is revoked by an issuer whose scope is
    /// `own`, which no approver anchor is in.
    BRevokedOutOfScope,
}

/// How a three-party chain's second grant treats the first grant's
/// requirements.
#[derive(Clone)]
enum Chain {
    /// Root → actor, the root's grant carrying the case's grant requirements.
    Direct,
    /// Root → middle → actor; the middle's grant carries these requirements,
    /// or no extension when `None`.
    Delegated(Option<Vec<ApprovalRequirement>>),
    /// Root → middle → actor, where the root's grant carries no requirement
    /// and the middle's grant carries the case's grant requirements.
    AddedByDelegate,
}

struct Case {
    name: &'static str,
    expected: Expected,
    approvals: Vec<Approval>,
    /// Requirements of the trusted context.
    context_requirements: Vec<ApprovalRequirement>,
    /// Requirements carried by the root's grant.
    grant_requirements: Vec<ApprovalRequirement>,
    chain: Chain,
    status: Status,
    /// The actor is also a listed approver with an anchor.
    actor_listed: bool,
}

fn class_of(expected: Expected) -> &'static str {
    match expected {
        Expected::Authorized => "valid",
        Expected::Denied(_) => "denied",
        Expected::Indeterminate(_) => "indeterminate",
    }
}

fn context_case(name: &'static str, expected: Expected, approvals: Vec<Approval>) -> Case {
    Case {
        name,
        expected,
        approvals,
        context_requirements: vec![managers()],
        grant_requirements: Vec::new(),
        chain: Chain::Direct,
        status: Status::None,
        actor_listed: false,
    }
}

fn grant_case(name: &'static str, expected: Expected, approvals: Vec<Approval>) -> Case {
    Case {
        name,
        expected,
        approvals,
        context_requirements: Vec::new(),
        grant_requirements: vec![managers()],
        chain: Chain::Direct,
        status: Status::None,
        actor_listed: false,
    }
}

fn extensions(requirements: &[ApprovalRequirement]) -> CriticalExtensions {
    if requirements.is_empty() {
        return CriticalExtensions::empty();
    }
    let bytes = encode_approval_requirements(
        &ApprovalRequirements::new(requirements.to_vec()).expect("bounded requirement list"),
    )
    .expect("canonical requirements");
    CriticalExtensions::new(vec![
        CriticalExtension::new(
            ExtensionId::parse(APPROVAL_REQUIREMENT_EXTENSION_V1).expect("extension ID"),
            bytes,
        )
        .expect("bounded extension"),
    ])
    .expect("extension set")
}

fn grant_statement(
    issuer: &Identity,
    subject: &Identity,
    remaining_depth: u16,
    parent: Option<GrantId>,
    extensions: CriticalExtensions,
) -> GrantStatement {
    GrantStatement::new(
        issuer.principal.clone(),
        subject.principal.clone(),
        profile(),
        PermissionSet::new(vec![permission()]).expect("permissions"),
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
        AudienceSet::new(vec![audience()]).expect("audience"),
        ActionConstraint::ExactBodyDigest(body_digest(BODY)),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
            10,
        )),
        remaining_depth,
        parent,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
        extensions,
    )
}

fn grant_chain(case: &Case) -> (Vec<SignedGrant>, Vec<Identity>) {
    let (root, actor, middle) = (
        identity(Who::Root),
        identity(Who::Actor),
        identity(Who::Middle),
    );
    let root_extensions = match case.chain {
        Chain::AddedByDelegate => CriticalExtensions::empty(),
        _ => extensions(&case.grant_requirements),
    };
    match &case.chain {
        Chain::Direct => {
            let grant = signed_grant(
                &root,
                grant_statement(&root, &actor, 0, None, root_extensions),
            );
            (vec![grant], vec![root])
        }
        Chain::Delegated(child) => {
            let parent = signed_grant(
                &root,
                grant_statement(&root, &middle, 1, None, root_extensions),
            );
            let parent_id = grant_id(parent.statement()).expect("parent grant ID");
            let child_extensions = child
                .as_ref()
                .map_or_else(CriticalExtensions::empty, |requirements| {
                    extensions(requirements)
                });
            let child = signed_grant(
                &middle,
                grant_statement(&middle, &actor, 0, Some(parent_id), child_extensions),
            );
            (vec![parent, child], vec![root, middle])
        }
        Chain::AddedByDelegate => {
            let parent = signed_grant(
                &root,
                grant_statement(&root, &middle, 1, None, root_extensions),
            );
            let parent_id = grant_id(parent.statement()).expect("parent grant ID");
            let child = signed_grant(
                &middle,
                grant_statement(
                    &middle,
                    &actor,
                    0,
                    Some(parent_id),
                    extensions(&case.grant_requirements),
                ),
            );
            (vec![parent, child], vec![root, middle])
        }
    }
}

fn approver_anchor(who: Who, status: StatusPolicy) -> ApproverAnchor {
    ApproverAnchor::new(
        identity(who).principal,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).expect("validity"),
        status,
    )
    .expect("approver anchor")
}

struct StatusMaterial {
    snapshot: PrincipalStatusSnapshot,
    statements: Vec<(StatementRef, Identity)>,
}

fn status_material(status: Status) -> StatusMaterial {
    let service = identity(Who::StatusService);
    let root = identity(Who::Root);
    let (issuer, statement_state) = match status {
        Status::None | Status::BMissing => (None, None),
        Status::BActive => (Some(service.clone()), Some(PrincipalState::Active)),
        Status::BRevoked => (Some(service.clone()), Some(PrincipalState::Revoked)),
        Status::BRevokedOutOfScope => (Some(root.clone()), Some(PrincipalState::Revoked)),
    };
    let mut signed = Vec::new();
    let mut statements = Vec::new();
    if let (Some(issuer), Some(state)) = (issuer, statement_state) {
        let statement = PrincipalStatusStatement::new(
            StatusMethodId::parse(STATUS_METHOD).expect("status method"),
            identity(Who::B).principal,
            state,
            1,
            Timestamp::new(40),
            Timestamp::new(100),
            issuer.principal.clone(),
            CriticalExtensions::empty(),
        )
        .expect("principal status");
        let status = signed_principal_status(&issuer, statement);
        statements.push((
            StatementRef::PrincipalStatus(
                principal_status_id(status.statement()).expect("principal status ID"),
            ),
            issuer,
        ));
        signed.push(status);
    }
    let rule = |issuer: &Identity, scope: StatusScope| {
        auths_model::StatusTrustRule::new(
            StatusMethodId::parse(STATUS_METHOD).expect("status method"),
            issuer.principal.clone(),
            1,
            scope,
        )
    };
    let trust = match status {
        Status::None => Vec::new(),
        Status::BRevokedOutOfScope => vec![
            rule(&service, StatusScope::AnyAnchor),
            rule(&root, StatusScope::OwnAnchor),
        ],
        _ => vec![rule(&service, StatusScope::AnyAnchor)],
    };
    StatusMaterial {
        snapshot: PrincipalStatusSnapshot::with_trust(
            StatusSnapshotId::new([0xa7; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            signed,
            Vec::new(),
            trust,
        )
        .expect("principal snapshot"),
        statements,
    }
}

fn build_context(case: &Case, material: &StatusMaterial, depth: u16) -> TrustedContext {
    let mut identities = vec![identity(Who::Root)];
    identities.push(identity(Who::Actor));
    let status_methods = if case.status == Status::None {
        Vec::new()
    } else {
        vec![StatusMethodId::parse(STATUS_METHOD).expect("status method")]
    };
    let base = registries_with_status(&identities, status_methods, Vec::new());
    let accepted = accepted_from(
        &base,
        base.manifest_id(),
        base.resource_matchers().to_vec(),
        vec![ExtensionId::parse(APPROVAL_REQUIREMENT_EXTENSION_V1).expect("extension ID")],
        base.profile_policies().to_vec(),
    );
    let required = || StatusPolicy::SnapshotRequired {
        method: StatusMethodId::parse(STATUS_METHOD).expect("status method"),
        max_age: FreshnessLimit::new(20).expect("freshness"),
    };
    let mut anchors: Vec<ApproverAnchor> = [Who::A, Who::B, Who::C, Who::Outsider]
        .into_iter()
        .map(|who| {
            let policy = if who == Who::B && case.status != Status::None {
                required()
            } else {
                StatusPolicy::ExpiryOnly
            };
            approver_anchor(who, policy)
        })
        .collect();
    if case.actor_listed {
        anchors.push(approver_anchor(Who::Actor, StatusPolicy::ExpiryOnly));
    }
    TrustedContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor(&identity(Who::Root), depth)],
        accepted,
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&identities),
        material.snapshot.clone(),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0xa8; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant snapshot"),
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("approval context")
    .with_approvals(anchors, case.context_requirements.clone())
    .expect("approval anchors and requirements")
}

fn build_bundle(case: &Case) -> (ProofBundle, TrustedContext, CanonicalAction) {
    let actor = identity(Who::Actor);
    let canonical = canonical_action(BODY.to_vec());
    let (grants, issuers) = grant_chain(case);
    let proof_ref = ProofRef::new([0xa6; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let terminal = grants
        .last()
        .map(|grant| grant_id(grant.statement()).expect("grant ID"));
    let action = signed_action(
        &actor,
        action_envelope(
            &actor,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            terminal,
        ),
    );
    let mut bindings: Vec<_> = grants
        .iter()
        .zip(&issuers)
        .map(|(grant, issuer)| {
            ControlBinding::new(
                StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
                vec![issuer.evidence().id()],
            )
            .expect("grant binding")
        })
        .collect();
    bindings.push(
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    );
    let material = status_material(case.status);
    let mut signers = issuers.clone();
    signers.push(actor.clone());
    for (reference, issuer) in &material.statements {
        bindings.push(
            ControlBinding::new(*reference, vec![issuer.evidence().id()]).expect("status binding"),
        );
        if !signers
            .iter()
            .any(|signer| signer.principal == issuer.principal)
        {
            signers.push(issuer.clone());
        }
    }
    let default_requirement = case
        .context_requirements
        .first()
        .or_else(|| case.grant_requirements.first())
        .cloned()
        .unwrap_or_else(managers);
    let approvals: Vec<_> = case
        .approvals
        .iter()
        .map(|spec| build_approval(*spec, &default_requirement))
        .collect();
    let depth = u16::try_from(grants.len()).expect("short chain");
    let context = build_context(case, &material, depth);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        vec![action],
        plan,
        addressed_evidence(&signers),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .expect("approval bundle")
    .with_approvals(approvals)
    .expect("bounded approvals");
    (bundle, context, canonical)
}

fn build(case: &Case) -> CorpusFixture {
    let (name, expected) = (case.name, case.expected);
    let (bundle, context, canonical) = build_bundle(case);
    fixture(
        name,
        class_of(expected),
        &bundle,
        &context,
        canonical,
        expected,
    )
}

/// Replaces the final array of `bundle`, which holds `count` copies of
/// `item`, with one of `count + 1` copies.
fn append_approval(bundle: &[u8], count: usize, item: &[u8]) -> Vec<u8> {
    let tail = count * item.len();
    let header_end = bundle.len() - tail;
    assert_eq!(
        &bundle[header_end - 2..header_end],
        &[0x98, 0x80],
        "128-item header"
    );
    let mut extended = bundle[..header_end - 2].to_vec();
    extended.extend_from_slice(&[0x98, 0x81]);
    extended.extend_from_slice(&bundle[header_end..]);
    extended.extend_from_slice(item);
    extended
}

fn narrowed() -> ApprovalRequirement {
    requirement(&[Who::A, Who::B], 2)
}

fn widened() -> ApprovalRequirement {
    requirement(&[Who::A, Who::B, Who::C, Who::Outsider], 2)
}

fn lowered() -> ApprovalRequirement {
    requirement(&[Who::A, Who::B, Who::C], 1)
}

fn clerks() -> ApprovalRequirement {
    requirement(&[Who::C, Who::Outsider], 1)
}

fn with_actor() -> ApprovalRequirement {
    requirement(&[Who::A, Who::B, Who::C, Who::Actor], 2)
}

/// Every approval vector.
#[allow(clippy::too_many_lines)]
pub(crate) fn approval_vectors() -> Vec<CorpusFixture> {
    use Who::{A, Actor, B, C, Outsider};
    let authorized = Expected::Authorized;
    let not_met = Expected::Denied(DenialReason::ApprovalThresholdNotMet);
    let unavailable = Expected::Indeterminate(Requirement::ApprovalUnavailable);
    let expanded = Expected::Denied(DenialReason::DelegationExpanded);
    let mut vectors = vec![
        build(&context_case(
            "approval-2-of-3",
            authorized,
            vec![approval(A), approval(B)],
        )),
        build(&context_case(
            "approval-3-of-3",
            authorized,
            vec![approval(A), approval(B), approval(C)],
        )),
        build(&context_case(
            "approval-order-independent",
            authorized,
            vec![approval(B), approval(A)],
        )),
        build(&context_case(
            "approval-with-stray-action",
            authorized,
            vec![approval(A), approval(B), faulty(C, Fault::OtherBody)],
        )),
        build(&context_case("approval-single", not_met, vec![approval(A)])),
        build(&context_case(
            "approval-duplicate",
            not_met,
            vec![approval(A), approval(A)],
        )),
        build(&context_case(
            "approval-other-action",
            not_met,
            vec![approval(A), faulty(B, Fault::OtherBody)],
        )),
        build(&context_case(
            "approval-outsider",
            not_met,
            vec![approval(A), approval(Outsider)],
        )),
        build(&context_case(
            "approval-forged",
            not_met,
            vec![approval(A), faulty(B, Fault::Forged)],
        )),
        build(&context_case("approval-none", not_met, Vec::new())),
        build(&Case {
            context_requirements: vec![with_actor()],
            actor_listed: true,
            ..context_case("approval-self", not_met, vec![approval(A), approval(Actor)])
        }),
        build(&context_case(
            "approval-wrong-audience",
            not_met,
            vec![approval(A), faulty(B, Fault::OtherAudience)],
        )),
        build(&context_case(
            "approval-wrong-challenge",
            not_met,
            vec![approval(A), faulty(B, Fault::OtherChallenge)],
        )),
        build(&context_case(
            "approval-wrong-requirement",
            not_met,
            vec![approval(A), faulty(B, Fault::OtherRequirement)],
        )),
        build(&context_case(
            "approval-expired",
            not_met,
            vec![approval(A), faulty(B, Fault::Expired)],
        )),
        build(&Case {
            status: Status::BActive,
            ..context_case(
                "approval-status-active",
                authorized,
                vec![approval(A), approval(B)],
            )
        }),
        build(&Case {
            status: Status::BRevoked,
            ..context_case("approval-revoked", not_met, vec![approval(A), approval(B)])
        }),
        build(&Case {
            status: Status::BMissing,
            ..context_case(
                "approval-status-unavailable",
                unavailable,
                vec![approval(A), approval(B)],
            )
        }),
        build(&Case {
            status: Status::BRevokedOutOfScope,
            ..context_case(
                "approval-status-out-of-scope",
                unavailable,
                vec![approval(A), approval(B)],
            )
        }),
        build(&grant_case(
            "approval-grant-2-of-3",
            authorized,
            vec![approval(A), approval(B)],
        )),
        build(&grant_case(
            "approval-grant-single",
            not_met,
            vec![approval(A)],
        )),
        build(&Case {
            status: Status::BMissing,
            ..grant_case(
                "approval-grant-status-unavailable",
                unavailable,
                vec![approval(A), approval(B)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![managers()])),
            ..grant_case(
                "approval-grant-child-keeps",
                authorized,
                vec![approval(A), approval(B)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![narrowed()])),
            ..grant_case(
                "approval-grant-child-narrows",
                authorized,
                vec![
                    approval(A),
                    approval(B),
                    for_requirement(A, narrowed),
                    for_requirement(B, narrowed),
                ],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![narrowed()])),
            ..grant_case(
                "approval-grant-narrowed-parent-unmet",
                not_met,
                vec![for_requirement(A, narrowed), for_requirement(B, narrowed)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![managers(), clerks()])),
            ..grant_case(
                "approval-grant-child-adds",
                authorized,
                vec![approval(A), approval(B), for_requirement(C, clerks)],
            )
        }),
        build(&Case {
            chain: Chain::AddedByDelegate,
            ..grant_case(
                "approval-grant-added-by-delegate",
                authorized,
                vec![approval(A), approval(B)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![widened()])),
            ..grant_case(
                "approval-grant-child-widens",
                expanded,
                vec![approval(A), approval(B), for_requirement(A, widened)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(Some(vec![lowered()])),
            ..grant_case(
                "approval-grant-child-lowers",
                expanded,
                vec![approval(A), approval(B), for_requirement(A, lowered)],
            )
        }),
        build(&Case {
            chain: Chain::Delegated(None),
            ..grant_case(
                "approval-grant-child-drops",
                expanded,
                vec![approval(A), approval(B)],
            )
        }),
    ];

    // 128 approvals is the bound: A and B, then 126 byte-identical repeats
    // of A, which count once.
    let mut at_limit = vec![approval(A), approval(B)];
    at_limit.extend(core::iter::repeat_n(approval(A), 126));
    vectors.push(build(&context_case(
        "approval-count-at-limit",
        authorized,
        at_limit,
    )));

    // One approval past the bound fails decoding.
    let repeated = context_case(
        "approval-limit",
        Expected::Denied(DenialReason::ResourceLimitExceeded),
        vec![approval(A); 128],
    );
    let (bundle, context, canonical) = build_bundle(&repeated);
    let item = encode_signed_approval(&bundle.approvals()[0]).expect("approval bytes");
    let base = fixture(
        repeated.name,
        class_of(repeated.expected),
        &bundle,
        &context,
        canonical,
        repeated.expected,
    );
    vectors.push(CorpusFixture {
        proof_bytes: append_approval(base.proof_bytes(), 128, &item),
        ..base
    });
    vectors
}
