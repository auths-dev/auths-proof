//! Vectors for the kernel's canonical-action input bounds, its action-binding,
//! validity, attenuation, and composition checks, and its check precedence.
//!
//! A single-fault vector differs from an authorizing input in exactly one
//! fact, so the first check in verification order that rejects that fact
//! decides it; the inventory in [`crate::check_sites`] records which check
//! decides which vector. A two-fault vector carries two faults that different
//! checks reject, so its result names the check the specified precedence runs
//! first, and every conforming verifier must return that class and code.

use super::*;

/// The reviewed body with one byte changed. Same length and shape, so only
/// its digest differs from the digest every action signs.
const SWAPPED_BODY: &[u8] = &[
    0xa2, 0x00, 0x64, b'r', b'e', b'a', b'd', 0x01, 0x6f, b'/', b'r', b'e', b'p', b'o', b'r', b't',
    b's', b'/', b'q', b'4', b'.', b'p', b'd', b'f',
];

const GRANT_STATUS_METHOD: &str = "auths-grant-status-v1";

fn class_of(expected: Expected) -> &'static str {
    match expected {
        Expected::Authorized => "valid",
        Expected::Denied(_) => "denied",
        Expected::Indeterminate(_) => "indeterminate",
    }
}

fn numeric_budget(value: u64) -> BudgetCeiling {
    BudgetCeiling::new(
        BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget algebra"),
        value,
    )
}

fn canonical_with(
    source: &CanonicalAction,
    media_type: MediaType,
    body: Vec<u8>,
    permission: Permission,
    requested_budget: Option<BudgetCeiling>,
) -> CanonicalAction {
    CanonicalAction::new(
        source.profile().clone(),
        media_type,
        body,
        permission,
        requested_budget,
    )
    .expect("canonical action")
    .with_detached_attachments(source.detached_attachments().to_vec())
    .expect("canonical attachments")
}

/// `raw-key-chain` presented with a canonical action whose one field differs
/// from what every signed envelope binds.
fn substituted(
    name: &'static str,
    substitute: impl FnOnce(&CanonicalAction) -> CanonicalAction,
) -> CorpusFixture {
    let mut fixture = raw_key_chain();
    fixture.canonical_action = substitute(&fixture.canonical_action);
    fixture.name = name;
    fixture.class = "denied";
    fixture.expected = Expected::Denied(DenialReason::ActionBodyMismatch);
    fixture
}

fn media_type_substituted() -> CorpusFixture {
    substituted("action-media-type-substituted", |source| {
        canonical_with(
            source,
            MediaType::parse("application/vnd.auths.mcp-call.v2+cbor").expect("media type"),
            source.body().to_vec(),
            source.permission().clone(),
            source.requested_budget().cloned(),
        )
    })
}

fn permission_substituted() -> CorpusFixture {
    substituted("action-permission-substituted", |source| {
        canonical_with(
            source,
            source.media_type().clone(),
            source.body().to_vec(),
            Permission::new(
                CapabilityId::parse("tools/admin").expect("capability"),
                source.permission().resource().clone(),
            ),
            source.requested_budget().cloned(),
        )
    })
}

fn budget_substituted() -> CorpusFixture {
    substituted("action-budget-substituted", |source| {
        canonical_with(
            source,
            source.media_type().clone(),
            source.body().to_vec(),
            source.permission().clone(),
            Some(numeric_budget(7)),
        )
    })
}

/// `raw-key-chain` with the proof's body field set to `embedded` (absent is
/// a detached body) and the canonical action carrying `canonical_body`.
/// Neither field is signed; only the envelope's body digest is.
fn body_carriage(
    name: &'static str,
    embedded: Option<&[u8]>,
    canonical_body: &[u8],
    expected: Expected,
) -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        embedded.map(<[u8]>::to_vec),
    )
    .expect("proof bundle");
    let source = fixture.canonical_action.clone();
    fixture.canonical_action = canonical_with(
        &source,
        source.media_type().clone(),
        canonical_body.to_vec(),
        source.permission().clone(),
        source.requested_budget().cloned(),
    );
    fixture.proof_bytes = encode_bundle(&rebuilt).expect("canonical proof");
    fixture.name = name;
    fixture.class = class_of(expected);
    fixture.expected = expected;
    fixture
}

/// `raw-key-chain` evaluated one second after its action's validity ends.
pub(crate) fn evaluation_time_after_validity() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = decode_context(&fixture);
    let replacement = context
        .for_request(
            context.expected_audience().clone(),
            context.expected_challenge(),
            Timestamp::new(61),
        )
        .expect("evaluation time remains inside the snapshot windows");
    fixture.name = "evaluation-time-after-validity";
    fixture.class = "denied";
    fixture.context_bytes = encode_verifier_context(&replacement).expect("canonical context");
    fixture.expected = Expected::Denied(DenialReason::ActionOutsideValidity);
    fixture
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    actor: &Identity,
    canonical: &CanonicalAction,
    plan: PlanId,
    proof_ref: ProofRef,
    terminal_grant: Option<GrantId>,
    audience: Audience,
    validity: ValidityWindow,
    attachments: Vec<AttachmentDescriptor>,
) -> ActionEnvelope {
    ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience,
        Challenge::new([0x22; 32]),
        validity,
        actor.principal.clone(),
        terminal_grant,
        plan,
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        attachments,
        CriticalExtensions::empty(),
    )
}

fn window(not_before: u64, expires_at: u64) -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at)).expect("validity")
}

fn offline_policy() -> AssurancePolicy {
    let offline = AssuranceClaimId::parse("offline-verifiable").expect("assurance claim");
    AssurancePolicy::new(
        AssurancePolicyId::parse("raw-key-baseline").expect("assurance policy"),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                offline.clone(),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                offline,
                None,
            ),
        ],
    )
    .expect("assurance policy")
}

/// Two self-anchored actors under `AllOf`; the second signs a validity window
/// that starts one second later. Both windows contain the evaluation time.
fn plan_actions_differ() -> CorpusFixture {
    let identities = [Identity::ed25519(231), Identity::ed25519(232)];
    let canonical = canonical_action(BODY.to_vec());
    let proof_refs = [ProofRef::new([0xd1; 32]), ProofRef::new([0xd2; 32])];
    let plan = AuthorizationPlan::all_of(
        proof_refs
            .iter()
            .copied()
            .map(AuthorizationPlan::proof)
            .collect(),
    )
    .expect("all-of");
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let windows = [window(40, 60), window(41, 60)];
    let actions: Vec<_> = identities
        .iter()
        .zip(proof_refs)
        .zip(windows)
        .map(|((identity, proof_ref), validity)| {
            signed_action(
                identity,
                envelope(
                    identity,
                    &canonical,
                    plan_identifier,
                    proof_ref,
                    None,
                    audience(),
                    validity,
                    Vec::new(),
                ),
            )
        })
        .collect();
    let bindings = actions
        .iter()
        .zip(&identities)
        .map(|(action, identity)| {
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![identity.evidence().id()],
            )
            .expect("action binding")
        })
        .collect();
    let anchors = identities
        .iter()
        .map(|identity| anchor(identity, 0))
        .collect();
    let verifier_context = context_with_assurance(&identities, anchors, offline_policy());
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        actions,
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("two-action proof");
    fixture(
        "plan-actions-differ",
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Denied(DenialReason::PlanActionMismatch),
    )
}

/// `attachment-valid` whose proof lists no attachment descriptor although
/// the signed action binds one.
fn attachment_descriptor_set_mismatch() -> CorpusFixture {
    let mut fixture = attachment_fixture(
        "attachment-descriptor-set-mismatch",
        AttachmentVariation::Valid,
        Expected::Authorized,
    );
    let bundle = decoded_bundle(&fixture);
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        Vec::new(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof without descriptors");
    fixture.proof_bytes = encode_bundle(&rebuilt).expect("canonical proof");
    fixture.class = "denied";
    fixture.expected = Expected::Denied(DenialReason::UnusedCriticalAttachment);
    fixture
}

/// How the second grant of a root → delegate → actor chain departs from its
/// parent. Both grants require grant status, which the snapshot holds as
/// active for every grant that requires it.
#[derive(Clone, Copy)]
enum StatusEdge {
    Kept,
    StatusRelaxed,
    ActionConstraintRelaxed,
}

fn required_grant_status() -> StatusPolicy {
    required_status(GRANT_STATUS_METHOD)
}

#[allow(clippy::too_many_lines)]
fn status_edge(name: &'static str, edge: StatusEdge, expected: Expected) -> CorpusFixture {
    let identities = [
        Identity::ed25519(233),
        Identity::ed25519(234),
        Identity::ed25519(235),
    ];
    let [root, delegate, actor] = &identities;
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xd3; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let exact = ActionConstraint::ExactBodyDigest(body_digest(canonical.body()));
    let statement = |issuer: &Identity,
                     subject: &Identity,
                     depth: u16,
                     parent: Option<GrantId>,
                     constraint: ActionConstraint,
                     status: StatusPolicy| {
        GrantStatement::new(
            issuer.principal.clone(),
            subject.principal.clone(),
            profile(),
            PermissionSet::new(vec![permission()]).expect("permissions"),
            window(20, 80),
            AudienceSet::new(vec![audience()]).expect("audience"),
            constraint,
            Some(numeric_budget(10)),
            depth,
            parent,
            status,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        )
    };
    let parent = signed_grant(
        root,
        statement(
            root,
            delegate,
            1,
            None,
            exact.clone(),
            required_grant_status(),
        ),
    );
    let parent_id = grant_id(parent.statement()).expect("parent grant ID");
    let (child_constraint, child_status) = match edge {
        StatusEdge::Kept => (exact, required_grant_status()),
        StatusEdge::StatusRelaxed => (exact, StatusPolicy::ExpiryOnly),
        StatusEdge::ActionConstraintRelaxed => (ActionConstraint::AnyBody, required_grant_status()),
    };
    let child_requires_status = matches!(child_status, StatusPolicy::SnapshotRequired { .. });
    let child = signed_grant(
        delegate,
        statement(
            delegate,
            actor,
            0,
            Some(parent_id),
            child_constraint,
            child_status,
        ),
    );
    let child_id = grant_id(child.statement()).expect("child grant ID");
    let action = signed_action(
        actor,
        action_envelope(
            actor,
            &canonical,
            plan_identifier,
            proof_ref,
            Some(child_id),
        ),
    );
    let mut bindings = vec![
        ControlBinding::new(StatementRef::Grant(parent_id), vec![root.evidence().id()])
            .expect("parent binding"),
        ControlBinding::new(
            StatementRef::Grant(child_id),
            vec![delegate.evidence().id()],
        )
        .expect("child binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let mut statuses = Vec::new();
    let mut status_of = |grant: GrantId| {
        let signed = signed_grant_status(
            root,
            GrantStatusStatement::new(
                StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
                grant,
                GrantState::Active,
                1,
                Timestamp::new(40),
                Timestamp::new(100),
                root.principal.clone(),
                CriticalExtensions::empty(),
            )
            .expect("grant status"),
        );
        bindings.push(
            ControlBinding::new(
                StatementRef::GrantStatus(grant_status_id(signed.statement()).expect("status ID")),
                vec![root.evidence().id()],
            )
            .expect("grant-status binding"),
        );
        statuses.push(signed);
    };
    status_of(parent_id);
    if child_requires_status {
        status_of(child_id);
    }
    let grant_snapshot = GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xd4; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        statuses,
        Vec::new(),
        vec![auths_model::StatusTrustRule::new(
            StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
            root.principal.clone(),
            1,
        )],
    )
    .expect("grant snapshot");
    let verifier_context = TrustedContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor_with_status(root, 2, StatusPolicy::ExpiryOnly)],
        registries_with_status(
            &identities,
            Vec::new(),
            vec![StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method")],
        ),
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&identities),
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0xd5; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal snapshot"),
        grant_snapshot,
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("status-edge context");
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![parent, child],
        vec![action],
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("status-edge proof");
    fixture(
        name,
        class_of(expected),
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// How the second grant of an expiry-only root → delegate → actor chain is
/// linked to its parent.
#[derive(Clone, Copy)]
enum LinkEdge {
    ProfileChanged,
    IssuerNotSubject,
}

fn link_edge(name: &'static str, edge: LinkEdge, expected: Expected) -> CorpusFixture {
    let root = Identity::ed25519(236);
    let delegate = Identity::ed25519(237);
    let stranger = Identity::ed25519(238);
    let actor = Identity::ed25519(239);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xd6; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let statement = |issuer: &Identity,
                     subject: &Identity,
                     depth: u16,
                     parent: Option<GrantId>,
                     selected: ProfileRef| {
        GrantStatement::new(
            issuer.principal.clone(),
            subject.principal.clone(),
            selected,
            PermissionSet::new(vec![permission()]).expect("permissions"),
            window(20, 80),
            AudienceSet::new(vec![audience()]).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            Some(numeric_budget(10)),
            depth,
            parent,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        )
    };
    let parent = signed_grant(&root, statement(&root, &delegate, 1, None, profile()));
    let parent_id = grant_id(parent.statement()).expect("parent grant ID");
    let (child_issuer, child_profile) = match edge {
        LinkEdge::ProfileChanged => (
            &delegate,
            ProfileRef::new(ProfileId::parse("auths.http").expect("profile"), 1)
                .expect("profile version"),
        ),
        LinkEdge::IssuerNotSubject => (&stranger, profile()),
    };
    let child = signed_grant(
        child_issuer,
        statement(child_issuer, &actor, 0, Some(parent_id), child_profile),
    );
    let child_id = grant_id(child.statement()).expect("child grant ID");
    let action = signed_action(
        &actor,
        action_envelope(
            &actor,
            &canonical,
            plan_identifier,
            proof_ref,
            Some(child_id),
        ),
    );
    let signers = [root.clone(), child_issuer.clone(), actor.clone()];
    let bindings = vec![
        ControlBinding::new(StatementRef::Grant(parent_id), vec![root.evidence().id()])
            .expect("parent binding"),
        ControlBinding::new(
            StatementRef::Grant(child_id),
            vec![child_issuer.evidence().id()],
        )
        .expect("child binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let verifier_context = context(&signers, vec![anchor(&root, 2)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![parent, child],
        vec![action],
        plan,
        addressed_evidence(&signers),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("link-edge proof");
    fixture(
        name,
        class_of(expected),
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// How a root → actor grant fails to cover an action that every binding
/// check accepts.
#[derive(Clone, Copy)]
enum CoverageGap {
    Profile,
    Audience,
}

#[allow(clippy::too_many_lines)]
fn coverage_gap(name: &'static str, gap: CoverageGap, expected: Expected) -> CorpusFixture {
    let root = Identity::ed25519(241);
    let actor = Identity::ed25519(242);
    let identities = [root.clone(), actor.clone()];
    let http = ProfileRef::new(ProfileId::parse("auths.http").expect("profile"), 1)
        .expect("profile version");
    let archive = Audience::parse("mcp://reports-archive").expect("audience");
    let action_profile = match gap {
        CoverageGap::Profile => http.clone(),
        CoverageGap::Audience => profile(),
    };
    let canonical = CanonicalAction::new(
        action_profile,
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        BODY.to_vec(),
        permission(),
        Some(numeric_budget(5)),
    )
    .expect("canonical action");
    let proof_ref = ProofRef::new([0xd7; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grant_audiences = match gap {
        CoverageGap::Profile => vec![audience()],
        CoverageGap::Audience => vec![archive.clone()],
    };
    let grant = signed_grant(
        &root,
        GrantStatement::new(
            root.principal.clone(),
            actor.principal.clone(),
            profile(),
            PermissionSet::new(vec![permission()]).expect("permissions"),
            window(20, 80),
            AudienceSet::new(grant_audiences).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(BODY)),
            Some(numeric_budget(10)),
            0,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        ),
    );
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action = signed_action(
        &actor,
        envelope(
            &actor,
            &canonical,
            plan_identifier,
            proof_ref,
            Some(grant_identifier),
            audience(),
            window(40, 60),
            Vec::new(),
        ),
    );
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![root.evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let base = context(&identities, vec![anchor(&root, 1)]);
    let source = &base.trust_anchors()[0];
    let widened_anchor = TrustAnchor::new(
        source.id().clone(),
        source.principal().clone(),
        source.accepted_methods().to_vec(),
        vec![profile(), http.clone()],
        source.permissions().clone(),
        source.resource_namespaces().to_vec(),
        AudienceSet::new(vec![audience(), archive]).expect("audiences"),
        source.validity(),
        source.budget_ceiling().cloned(),
        source.max_delegation_depth(),
        source.assurance_policy().clone(),
        source.status_policy().clone(),
    )
    .expect("anchor");
    let registries = base.accepted_registries();
    let accepted = AcceptedRegistries::new(
        registries.manifest_id(),
        registries.principal_methods().to_vec(),
        registries.signature_suites().to_vec(),
        registries.evidence_types().to_vec(),
        registries.principal_status_methods().to_vec(),
        registries.grant_status_methods().to_vec(),
        registries.assurance_claims().to_vec(),
        registries.assurance_implications().to_vec(),
        registries.resource_matchers().to_vec(),
        registries.budget_algebras().to_vec(),
        registries.critical_extensions().to_vec(),
        vec![profile(), http],
        registries.profile_policies().to_vec(),
    )
    .expect("accepted registries");
    let verifier_context = context_replacement(
        &base,
        vec![widened_anchor],
        accepted,
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .expect("coverage proof");
    fixture(
        name,
        class_of(expected),
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// A self-anchored action whose resource lies outside the anchor's only
/// namespace, although the anchor's permissions name it.
fn action_resource_outside_namespace() -> CorpusFixture {
    let identity = Identity::ed25519(243);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xd8; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let action = signed_action(
        &identity,
        action_envelope(
            &identity,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            None,
        ),
    );
    let evidence = identity.evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![evidence.id()],
    )
    .expect("action binding");
    let base = context(core::slice::from_ref(&identity), vec![anchor(&identity, 0)]);
    let source = &base.trust_anchors()[0];
    let elsewhere = TrustAnchor::new(
        source.id().clone(),
        source.principal().clone(),
        source.accepted_methods().to_vec(),
        source.profiles().to_vec(),
        source.permissions().clone(),
        vec![ResourceId::parse("mcp://elsewhere").expect("namespace")],
        source.audiences().clone(),
        source.validity(),
        source.budget_ceiling().cloned(),
        source.max_delegation_depth(),
        source.assurance_policy().clone(),
        source.status_policy().clone(),
    )
    .expect("anchor");
    let verifier_context = context_replacement(
        &base,
        vec![elsewhere],
        base.accepted_registries().clone(),
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("self-anchored proof");
    fixture(
        "action-resource-outside-namespace",
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Denied(DenialReason::ResourceNamespaceMismatch),
    )
}

/// `source` under a trusted context that requires the given composition
/// minimums in addition to its exact plan.
fn composition_floor(
    mut source: CorpusFixture,
    name: &'static str,
    minimum_authorized_branches: u16,
    minimum_distinct_actors: u16,
    minimum_distinct_roots: u16,
) -> CorpusFixture {
    let context = decode_context(&source);
    let replacement = context
        .with_composition(
            CompositionRequirement::new(
                context.composition().expected_plan(),
                minimum_authorized_branches,
                minimum_distinct_actors,
                minimum_distinct_roots,
            )
            .expect("composition requirement"),
        )
        .expect("composition replacement");
    source.name = name;
    source.class = "denied";
    source.context_bytes = encode_verifier_context(&replacement).expect("canonical context");
    source.expected = Expected::Denied(DenialReason::CompositionRequirementNotMet);
    source
}

/// Every single-fault vector of this module, in corpus order.
pub(crate) fn kernel_check_vectors() -> Vec<CorpusFixture> {
    let body_mismatch = Expected::Denied(DenialReason::ActionBodyMismatch);
    let expanded = Expected::Denied(DenialReason::DelegationExpanded);
    vec![
        media_type_substituted(),
        permission_substituted(),
        budget_substituted(),
        body_carriage(
            "embedded-body-differs",
            Some(SWAPPED_BODY),
            BODY,
            body_mismatch,
        ),
        body_carriage(
            "embedded-body-swapped",
            Some(SWAPPED_BODY),
            SWAPPED_BODY,
            body_mismatch,
        ),
        body_carriage("detached-body", None, BODY, Expected::Authorized),
        body_carriage("detached-body-swapped", None, SWAPPED_BODY, body_mismatch),
        evaluation_time_after_validity(),
        plan_actions_differ(),
        attachment_descriptor_set_mismatch(),
        status_edge(
            "delegated-grant-status-kept",
            StatusEdge::Kept,
            Expected::Authorized,
        ),
        status_edge(
            "delegation-status-relaxed",
            StatusEdge::StatusRelaxed,
            expanded,
        ),
        status_edge(
            "delegation-action-constraint-relaxed",
            StatusEdge::ActionConstraintRelaxed,
            expanded,
        ),
        link_edge(
            "delegation-profile-changed",
            LinkEdge::ProfileChanged,
            expanded,
        ),
        link_edge(
            "delegation-issuer-not-subject",
            LinkEdge::IssuerNotSubject,
            Expected::Denied(DenialReason::BrokenGrantChain),
        ),
        coverage_gap(
            "action-profile-outside-grant",
            CoverageGap::Profile,
            Expected::Denied(DenialReason::BrokenGrantChain),
        ),
        coverage_gap(
            "action-audience-outside-grant",
            CoverageGap::Audience,
            Expected::Denied(DenialReason::AudienceMismatch),
        ),
        action_resource_outside_namespace(),
        composition_floor(raw_key_chain(), "composition-branch-minimum", 2, 1, 1),
        composition_floor(
            composition_same_actor_two_branches(),
            "composition-same-actor",
            2,
            2,
            1,
        ),
        composition_floor(
            composition_shared_root_two_actors(),
            "composition-shared-root",
            2,
            2,
            2,
        ),
    ]
}

/// `source` under a trusted context whose deployment limits are `limits`.
fn with_limits(
    mut source: CorpusFixture,
    name: &'static str,
    limits: VerifierLimits,
    expected: Expected,
) -> CorpusFixture {
    let context = decode_context(&source);
    let replacement = context.with_limits(limits).expect("deployment limits");
    source.name = name;
    source.class = match expected {
        Expected::Authorized => "valid",
        Expected::Denied(_) | Expected::Indeterminate(_) => "invalid",
    };
    source.context_bytes = encode_verifier_context(&replacement).expect("canonical context");
    source.expected = expected;
    source
}

fn lowered(kind: LimitKind, value: usize) -> VerifierLimits {
    VerifierLimits::default()
        .with_limit(kind, value)
        .expect("deployment limit")
}

fn action_input_bytes_over_limit() -> CorpusFixture {
    let fixture = raw_key_chain();
    let length = auths_codec::encode_canonical_action(fixture.canonical_action())
        .expect("canonical action")
        .len();
    with_limits(
        fixture,
        "action-input-bytes-over-limit",
        lowered(LimitKind::ActionBytes, length - 1),
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

/// The detached-body proof, so the canonical action is the only input that
/// carries the body.
fn detached_body_bytes_over_limit() -> CorpusFixture {
    with_limits(
        body_carriage(
            "detached-body-bytes-over-limit",
            None,
            BODY,
            Expected::Authorized,
        ),
        "detached-body-bytes-over-limit",
        lowered(LimitKind::CanonicalBodyBytes, BODY.len() - 1),
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

fn attachment_bytes_over_limit() -> CorpusFixture {
    let fixture = attachment_fixture(
        "attachment-bytes-over-limit",
        AttachmentVariation::Valid,
        Expected::Authorized,
    );
    let length = fixture.canonical_action().detached_attachments()[0]
        .bytes()
        .len();
    with_limits(
        fixture,
        "attachment-bytes-over-limit",
        lowered(LimitKind::AttachmentBytes, length - 1),
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

/// Detached bytes larger than the whole proof, under a bundle limit set to
/// exactly the proof's length: only the attachment limit bounds them.
fn attachment_larger_than_bundle_limit() -> CorpusFixture {
    let fixture = attachment_fixture_with_bytes(
        "attachment-larger-than-bundle-limit",
        AttachmentVariation::Valid,
        vec![0x5a; 2048],
        Expected::Authorized,
    );
    let proof_length = fixture.proof_bytes().len();
    assert!(proof_length < 2048, "the attachment must exceed the proof");
    with_limits(
        fixture,
        "attachment-larger-than-bundle-limit",
        lowered(LimitKind::BundleBytes, proof_length),
        Expected::Authorized,
    )
}

/// An over-limit canonical-action input beside a proof of an unsupported
/// protocol version: the canonical action is decoded first.
fn action_input_before_proof() -> CorpusFixture {
    let mut fixture = action_input_bytes_over_limit();
    assert_eq!(fixture.proof_bytes.get(4), Some(&1), "proof header version");
    fixture.proof_bytes[4] = 2;
    fixture.name = "two-fault-action-input-and-protocol";
    fixture
}

/// Vectors for the input bounds applied while the canonical action is
/// decoded, before the proof, and for the aggregate attachment bound.
pub(crate) fn input_bound_vectors() -> Vec<CorpusFixture> {
    vec![
        action_input_bytes_over_limit(),
        detached_body_bytes_over_limit(),
        attachment_bytes_over_limit(),
        attachment_larger_than_bundle_limit(),
        action_input_before_proof(),
    ]
}

/// `source` renamed, with its trusted context transformed and a new expected
/// result.
fn with_context(
    mut source: CorpusFixture,
    name: &'static str,
    transform: impl FnOnce(&TrustedContext) -> TrustedContext,
    expected: Expected,
) -> CorpusFixture {
    let context = transform(&decode_context(&source));
    source.name = name;
    source.class = class_of(expected);
    source.context_bytes = encode_verifier_context(&context).expect("canonical context");
    source.expected = expected;
    source
}

fn configuration_mismatch(context: &TrustedContext) -> TrustedContext {
    context
        .with_configuration(VerifierConfigurationId::new([0x5a; 32]))
        .expect("configuration replacement")
}

fn manifest_mismatch(context: &TrustedContext) -> TrustedContext {
    let registries = context.accepted_registries();
    let accepted = accepted_from(
        registries,
        RegistryManifestId::new([0x99; 32]),
        registries.resource_matchers().to_vec(),
        registries.critical_extensions().to_vec(),
        registries.profile_policies().to_vec(),
    );
    context_replacement(
        context,
        context.trust_anchors().to_vec(),
        accepted,
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
    )
}

fn other_audience(context: &TrustedContext) -> TrustedContext {
    context
        .for_request(
            Audience::parse("mcp://other-service").expect("audience"),
            context.expected_challenge(),
            context.evaluation_time(),
        )
        .expect("request context")
}

fn other_challenge(context: &TrustedContext) -> TrustedContext {
    context
        .for_request(
            context.expected_audience().clone(),
            Challenge::new([0x99; 32]),
            context.evaluation_time(),
        )
        .expect("request context")
}

fn unsupported_matcher(context: &TrustedContext) -> TrustedContext {
    let selected = ResourceMatcherId::parse("unknown-resource-v1").expect("matcher");
    let registries = context.accepted_registries();
    let accepted = accepted_from(
        registries,
        registries.manifest_id(),
        vec![selected.clone()],
        registries.critical_extensions().to_vec(),
        registries.profile_policies().to_vec(),
    );
    context_replacement(
        context,
        context.trust_anchors().to_vec(),
        accepted,
        selected,
        context.profile_policy().clone(),
    )
}

fn unsupported_policy(context: &TrustedContext) -> TrustedContext {
    let selected = ProfilePolicyId::parse("unknown-profile-policy-v1").expect("policy");
    let registries = context.accepted_registries();
    let accepted = accepted_from(
        registries,
        registries.manifest_id(),
        registries.resource_matchers().to_vec(),
        registries.critical_extensions().to_vec(),
        vec![selected.clone()],
    );
    context_replacement(
        context,
        context.trust_anchors().to_vec(),
        accepted,
        context.resource_matcher().clone(),
        selected,
    )
}

/// Every anchor keeps its principal, permissions, and policies but trusts
/// only `namespace`; with `principal`, the anchors are replaced by one
/// unrelated anchor instead.
fn replaced_anchors(
    context: &TrustedContext,
    namespace: &str,
    principal: Option<&str>,
) -> TrustedContext {
    let anchors = context
        .trust_anchors()
        .iter()
        .map(|source| {
            TrustAnchor::new(
                source.id().clone(),
                principal.map_or_else(
                    || source.principal().clone(),
                    |value| PrincipalId::parse(value).expect("principal"),
                ),
                source.accepted_methods().to_vec(),
                source.profiles().to_vec(),
                source.permissions().clone(),
                vec![ResourceId::parse(namespace).expect("namespace")],
                source.audiences().clone(),
                source.validity(),
                source.budget_ceiling().cloned(),
                source.max_delegation_depth(),
                source.assurance_policy().clone(),
                source.status_policy().clone(),
            )
            .expect("anchor")
        })
        .collect();
    context_replacement(
        context,
        anchors,
        context.accepted_registries().clone(),
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
    )
}

fn composition_minimums(context: &TrustedContext, branches: u16) -> TrustedContext {
    context
        .with_composition(
            CompositionRequirement::new(context.composition().expected_plan(), branches, 1, 1)
                .expect("composition requirement"),
        )
        .expect("composition replacement")
}

/// One root → actor grant whose scope, budgets, and action are varied to
/// reach one budget or namespace check.
#[derive(Clone, Copy)]
enum Scope {
    GrantPermissionOutsideNamespace,
    EdgeAlgebraUnsupported,
    EdgeAlgebraMismatch,
    RequestAlgebraMismatch,
    NamespaceBeforeBudget,
    BudgetBeforeDelegation,
    BudgetBeforeCoverage,
}

#[allow(clippy::too_many_lines)]
fn scoped_grant(name: &'static str, scope: Scope, expected: Expected) -> CorpusFixture {
    let root = Identity::ed25519(244);
    let actor = Identity::ed25519(245);
    let identities = [root.clone(), actor.clone()];
    let billing = Permission::new(
        CapabilityId::parse("tools/call").expect("capability"),
        ResourceId::parse("mcp://billing/charge").expect("resource"),
    );
    let unknown = BudgetAlgebraId::parse("unknown-budget-v1").expect("budget algebra");
    let other = BudgetAlgebraId::parse("other-budget-v1").expect("budget algebra");
    let (anchor_permissions, grant_permissions) = match scope {
        Scope::GrantPermissionOutsideNamespace | Scope::NamespaceBeforeBudget => (
            vec![permission(), billing.clone()],
            vec![permission(), billing],
        ),
        _ => (vec![permission()], vec![permission()]),
    };
    let anchor_ceiling = match scope {
        Scope::EdgeAlgebraUnsupported => BudgetCeiling::new(unknown.clone(), 20),
        _ => numeric_budget(20),
    };
    let grant_ceiling = match scope {
        Scope::EdgeAlgebraMismatch => BudgetCeiling::new(other.clone(), 10),
        _ => numeric_budget(10),
    };
    let requested = match scope {
        Scope::RequestAlgebraMismatch => BudgetCeiling::new(other, 5),
        Scope::NamespaceBeforeBudget
        | Scope::BudgetBeforeDelegation
        | Scope::BudgetBeforeCoverage => numeric_budget(11),
        _ => numeric_budget(5),
    };
    let grant_validity = match scope {
        Scope::BudgetBeforeDelegation => window(0, 101),
        _ => window(20, 80),
    };
    let action_permission = match scope {
        Scope::BudgetBeforeCoverage => Permission::new(
            CapabilityId::parse("tools/admin").expect("capability"),
            ResourceId::parse("mcp://reports/admin").expect("resource"),
        ),
        _ => permission(),
    };
    let canonical = CanonicalAction::new(
        profile(),
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        BODY.to_vec(),
        action_permission,
        Some(requested),
    )
    .expect("canonical action");
    let proof_ref = ProofRef::new([0xd9; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let grant = signed_grant(
        &root,
        GrantStatement::new(
            root.principal.clone(),
            actor.principal.clone(),
            profile(),
            PermissionSet::new(grant_permissions).expect("permissions"),
            grant_validity,
            AudienceSet::new(vec![audience()]).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(BODY)),
            Some(grant_ceiling),
            0,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        ),
    );
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action = signed_action(
        &actor,
        action_envelope(
            &actor,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            Some(grant_identifier),
        ),
    );
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![root.evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let base = context(&identities, vec![anchor(&root, 1)]);
    let source = &base.trust_anchors()[0];
    let scoped_anchor = TrustAnchor::new(
        source.id().clone(),
        source.principal().clone(),
        source.accepted_methods().to_vec(),
        source.profiles().to_vec(),
        PermissionSet::new(anchor_permissions).expect("permissions"),
        source.resource_namespaces().to_vec(),
        source.audiences().clone(),
        source.validity(),
        Some(anchor_ceiling),
        source.max_delegation_depth(),
        source.assurance_policy().clone(),
        source.status_policy().clone(),
    )
    .expect("anchor");
    let registries = base.accepted_registries();
    let mut algebras = registries.budget_algebras().to_vec();
    if matches!(scope, Scope::EdgeAlgebraUnsupported) {
        algebras.push(unknown);
    }
    let accepted = AcceptedRegistries::new(
        registries.manifest_id(),
        registries.principal_methods().to_vec(),
        registries.signature_suites().to_vec(),
        registries.evidence_types().to_vec(),
        registries.principal_status_methods().to_vec(),
        registries.grant_status_methods().to_vec(),
        registries.assurance_claims().to_vec(),
        registries.assurance_implications().to_vec(),
        registries.resource_matchers().to_vec(),
        algebras,
        registries.critical_extensions().to_vec(),
        registries.profiles().to_vec(),
        registries.profile_policies().to_vec(),
    )
    .expect("accepted registries");
    let verifier_context = context_replacement(
        &base,
        vec![scoped_anchor],
        accepted,
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .expect("scoped proof");
    fixture(
        name,
        class_of(expected),
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// A self-anchored action requesting a budget in an algebra the verifier
/// does not install, under an unbounded anchor: no ceiling is compared, so
/// the algebra is never resolved.
fn unbounded_request_unknown_algebra() -> CorpusFixture {
    let identity = Identity::ed25519(246);
    let canonical = CanonicalAction::new(
        profile(),
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        BODY.to_vec(),
        permission(),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("unknown-budget-v1").expect("budget algebra"),
            5,
        )),
    )
    .expect("canonical action");
    let proof_ref = ProofRef::new([0xda; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let action = signed_action(
        &identity,
        action_envelope(
            &identity,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            None,
        ),
    );
    let evidence = identity.evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![evidence.id()],
    )
    .expect("action binding");
    let base = context(core::slice::from_ref(&identity), vec![anchor(&identity, 0)]);
    let source = &base.trust_anchors()[0];
    let unbounded = TrustAnchor::new(
        source.id().clone(),
        source.principal().clone(),
        source.accepted_methods().to_vec(),
        source.profiles().to_vec(),
        source.permissions().clone(),
        source.resource_namespaces().to_vec(),
        source.audiences().clone(),
        source.validity(),
        None,
        source.max_delegation_depth(),
        source.assurance_policy().clone(),
        source.status_policy().clone(),
    )
    .expect("anchor");
    let verifier_context = context_replacement(
        &base,
        vec![unbounded],
        base.accepted_registries().clone(),
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("self-anchored proof");
    fixture(
        "unbounded-request-unknown-algebra",
        "valid",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Authorized,
    )
}

/// A root → delegate → actor chain whose first grant carries an observation
/// requirement that the second grant drops, while the second grant's status
/// is revoked: every status is judged before the delegation walk.
#[allow(clippy::too_many_lines)]
fn revoked_grant_dropping_requirement() -> CorpusFixture {
    let identities = [
        Identity::ed25519(247),
        Identity::ed25519(248),
        Identity::ed25519(249),
    ];
    let [root, delegate, actor] = &identities;
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xdb; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let observation = ExtensionId::parse(auths_registries::OBSERVATION_REQUIREMENT_EXTENSION_V1)
        .expect("extension ID");
    let requirement = auths_model::ObservationRequirement::new(
        auths_model::ObserverAnchorId::parse("test-observer").expect("anchor ID"),
        auths_model::ObservationSchemaId::parse("auths.test-outcome/1").expect("schema"),
        auths_model::ObservationSubject::Resource(
            ResourceId::parse("mcp://reports/read").expect("subject"),
        ),
        10,
        vec![auths_model::ObservationCondition::new(
            auths_model::FactName::parse("stage").expect("fact name"),
            auths_model::ConditionTest::EqLiteral(auths_model::FactValue::Text(
                auths_model::FactText::new("observed-by-provider").expect("fact text"),
            )),
        )],
    )
    .expect("observation requirement");
    let requirement_bytes = auths_codec::encode_observation_requirements(
        &auths_model::ObservationRequirements::new(vec![requirement]).expect("requirements"),
    )
    .expect("canonical requirements");
    let statement = |issuer: &Identity,
                     subject: &Identity,
                     depth: u16,
                     parent: Option<GrantId>,
                     extensions: CriticalExtensions| {
        GrantStatement::new(
            issuer.principal.clone(),
            subject.principal.clone(),
            profile(),
            PermissionSet::new(vec![permission()]).expect("permissions"),
            window(20, 80),
            AudienceSet::new(vec![audience()]).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            Some(numeric_budget(10)),
            depth,
            parent,
            required_grant_status(),
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            extensions,
        )
    };
    let parent = signed_grant(
        root,
        statement(
            root,
            delegate,
            1,
            None,
            CriticalExtensions::new(vec![
                CriticalExtension::new(observation.clone(), requirement_bytes).expect("extension"),
            ])
            .expect("extension set"),
        ),
    );
    let parent_id = grant_id(parent.statement()).expect("parent grant ID");
    let child = signed_grant(
        delegate,
        statement(
            delegate,
            actor,
            0,
            Some(parent_id),
            CriticalExtensions::empty(),
        ),
    );
    let child_id = grant_id(child.statement()).expect("child grant ID");
    let action = signed_action(
        actor,
        action_envelope(
            actor,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            Some(child_id),
        ),
    );
    let mut bindings = vec![
        ControlBinding::new(StatementRef::Grant(parent_id), vec![root.evidence().id()])
            .expect("parent binding"),
        ControlBinding::new(
            StatementRef::Grant(child_id),
            vec![delegate.evidence().id()],
        )
        .expect("child binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let mut statuses = Vec::new();
    for (grant, state) in [
        (parent_id, GrantState::Active),
        (child_id, GrantState::Revoked),
    ] {
        let signed = signed_grant_status(
            root,
            GrantStatusStatement::new(
                StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
                grant,
                state,
                1,
                Timestamp::new(40),
                Timestamp::new(100),
                root.principal.clone(),
                CriticalExtensions::empty(),
            )
            .expect("grant status"),
        );
        bindings.push(
            ControlBinding::new(
                StatementRef::GrantStatus(grant_status_id(signed.statement()).expect("status ID")),
                vec![root.evidence().id()],
            )
            .expect("grant-status binding"),
        );
        statuses.push(signed);
    }
    let grant_snapshot = GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xdc; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        statuses,
        Vec::new(),
        vec![auths_model::StatusTrustRule::new(
            StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
            root.principal.clone(),
            1,
        )],
    )
    .expect("grant snapshot");
    let registries = registries_with_status(
        &identities,
        Vec::new(),
        vec![StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method")],
    );
    let accepted = accepted_from(
        &registries,
        registries.manifest_id(),
        registries.resource_matchers().to_vec(),
        vec![observation],
        registries.profile_policies().to_vec(),
    );
    let verifier_context = TrustedContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor_with_status(root, 2, StatusPolicy::ExpiryOnly)],
        accepted,
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&identities),
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0xdd; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal snapshot"),
        grant_snapshot,
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("context");
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![parent, child],
        vec![action],
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("proof");
    fixture(
        "two-fault-grant-revoked-and-requirement-dropped",
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Denied(DenialReason::GrantRevoked),
    )
}

/// `attachment-missing` with the proof carrying a body other than the
/// canonical body.
fn embedded_body_before_attachments() -> CorpusFixture {
    let mut fixture = attachment_fixture(
        "two-fault-embedded-body-and-attachment",
        AttachmentVariation::Missing,
        Expected::Denied(DenialReason::ActionBodyMismatch),
    );
    let bundle = decoded_bundle(&fixture);
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        Some(SWAPPED_BODY.to_vec()),
    )
    .expect("proof with another body");
    fixture.proof_bytes = encode_bundle(&rebuilt).expect("canonical proof");
    fixture.class = "denied";
    fixture
}

fn missing_attachment() -> CorpusFixture {
    attachment_fixture(
        "attachment-missing",
        AttachmentVariation::Missing,
        Expected::Denied(DenialReason::AttachmentMissing),
    )
}

/// Single-fault vectors for the namespace rule and the budget chain, and a
/// two-fault vector at every boundary of the specified check precedence:
/// each carries two faults decided at different checks, and its result
/// names the check that runs first.
#[allow(clippy::too_many_lines)]
pub(crate) fn precedence_vectors() -> Vec<CorpusFixture> {
    let denied = Expected::Denied;
    vec![
        scoped_grant(
            "grant-permission-outside-namespace",
            Scope::GrantPermissionOutsideNamespace,
            denied(DenialReason::ResourceNamespaceMismatch),
        ),
        scoped_grant(
            "budget-edge-algebra-unsupported",
            Scope::EdgeAlgebraUnsupported,
            Expected::Indeterminate(Requirement::UnsupportedBudgetAlgebra),
        ),
        scoped_grant(
            "budget-edge-algebra-mismatch",
            Scope::EdgeAlgebraMismatch,
            denied(DenialReason::LocalPolicyDenied),
        ),
        scoped_grant(
            "budget-request-algebra-mismatch",
            Scope::RequestAlgebraMismatch,
            denied(DenialReason::LocalPolicyDenied),
        ),
        unbounded_request_unknown_algebra(),
        with_context(
            composition_requirement_not_met(),
            "two-fault-expected-plan-and-configuration",
            configuration_mismatch,
            denied(DenialReason::CompositionRequirementNotMet),
        ),
        with_context(
            missing_grant_reference(),
            "two-fault-missing-reference-and-configuration",
            configuration_mismatch,
            denied(DenialReason::MissingReference),
        ),
        with_context(
            duplicate_action_object(),
            "two-fault-duplicate-object-and-registry-manifest",
            manifest_mismatch,
            denied(DenialReason::DuplicateObject),
        ),
        with_context(
            invalid_signature(),
            "two-fault-invalid-signature-and-audience",
            other_audience,
            denied(DenialReason::AudienceMismatch),
        ),
        embedded_body_before_attachments(),
        with_context(
            missing_attachment(),
            "two-fault-challenge-and-attachment",
            other_challenge,
            denied(DenialReason::ChallengeMismatch),
        ),
        with_context(
            missing_attachment(),
            "two-fault-attachment-and-profile-policy",
            unsupported_policy,
            denied(DenialReason::AttachmentMissing),
        ),
        with_context(
            permission_substituted(),
            "two-fault-permission-and-profile-policy",
            unsupported_policy,
            denied(DenialReason::ActionBodyMismatch),
        ),
        with_context(
            raw_key_chain(),
            "two-fault-audience-and-resource-matcher",
            |context| unsupported_matcher(&other_audience(context)),
            denied(DenialReason::AudienceMismatch),
        ),
        with_context(
            unsupported_budget_algebra(),
            "two-fault-challenge-and-budget-algebra",
            other_challenge,
            denied(DenialReason::ChallengeMismatch),
        ),
        with_context(
            invalid_signature(),
            "two-fault-root-control-and-untrusted-root",
            |context| replaced_anchors(context, "mcp://reports", Some("raw:untrusted-root")),
            denied(DenialReason::InvalidSignature),
        ),
        with_context(
            revoked_principal_status(),
            "two-fault-principal-revoked-and-namespace",
            |context| replaced_anchors(context, "mcp://elsewhere", None),
            denied(DenialReason::PrincipalRevoked),
        ),
        with_context(
            revoked_grant_status(),
            "two-fault-grant-revoked-and-resource-matcher",
            unsupported_matcher,
            denied(DenialReason::GrantRevoked),
        ),
        revoked_grant_dropping_requirement(),
        scoped_grant(
            "two-fault-namespace-and-budget",
            Scope::NamespaceBeforeBudget,
            denied(DenialReason::ResourceNamespaceMismatch),
        ),
        scoped_grant(
            "two-fault-budget-and-delegation",
            Scope::BudgetBeforeDelegation,
            denied(DenialReason::BudgetCeilingExceeded),
        ),
        scoped_grant(
            "two-fault-budget-and-permission",
            Scope::BudgetBeforeCoverage,
            denied(DenialReason::BudgetCeilingExceeded),
        ),
        with_context(
            invalid_signature(),
            "two-fault-branch-denied-and-composition",
            |context| composition_minimums(context, 2),
            denied(DenialReason::InvalidSignature),
        ),
    ]
}
