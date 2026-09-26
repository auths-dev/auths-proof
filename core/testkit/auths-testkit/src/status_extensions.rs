//! Vectors for the accepted-extension rule on status statements.
//!
//! Status statements carry signed critical extensions, and no registered
//! extension gives a status statement meaning. Every vector is one root →
//! delegate → actor chain whose trust anchor and grants require snapshot
//! status, changed in one fact (or, for a precedence vector, two): a status
//! statement about a principal or grant the branch evaluates carries an
//! extension the context does not accept, or one it accepts. The accepted
//! extension is `exact-marker-v1` with its valid bytes, whose installed
//! handler serves grants and actions and never a status statement.

use super::*;

/// One exact method serves the anchor's policy, both grants' policies, and
/// every statement: a grant's status policy must preserve or narrow the
/// anchor's, and so names the same method.
const STATUS_METHOD: &str = "auths-principal-status-v1";
const UNKNOWN_EXTENSION: &str = "unknown-critical-v1";
const MARKER_EXTENSION: &str = "exact-marker-v1";

/// The extension a status statement carries.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Carried {
    /// An identifier the trusted context does not accept.
    Unknown,
    /// `exact-marker-v1`, which the trusted context accepts.
    Accepted,
    /// Both, the accepted identifier first in canonical order.
    AcceptedThenUnknown,
}

impl Carried {
    fn extensions(self) -> CriticalExtensions {
        let extension = |id: &str| {
            CriticalExtension::new(ExtensionId::parse(id).expect("extension ID"), vec![1])
                .expect("extension")
        };
        CriticalExtensions::new(match self {
            Self::Unknown => vec![extension(UNKNOWN_EXTENSION)],
            Self::Accepted => vec![extension(MARKER_EXTENSION)],
            Self::AcceptedThenUnknown => {
                vec![extension(MARKER_EXTENSION), extension(UNKNOWN_EXTENSION)]
            }
        })
        .expect("status extensions")
    }
}

/// Which statement carries the extension, and what else about the snapshot
/// differs from the authorizing chain.
#[derive(Clone, Copy)]
enum Placement {
    /// The trust anchor's own statement.
    Anchor,
    /// An active statement listing the delegate.
    Delegate,
    /// An active statement listing the actor.
    Actor,
    /// An older statement listing the delegate, beside a newer clean one that
    /// selection alone would pick.
    DelegateBesideNewer,
    /// A statement about a principal outside the branch.
    Unrelated,
    /// The status of the terminal grant.
    TerminalGrant,
    /// A revoked statement listing the delegate.
    RevokedDelegate,
    /// A statement listing the delegate that no control binding names.
    UnboundDelegate,
}

struct Chain {
    root: Identity,
    delegate: Identity,
    actor: Identity,
    unrelated: Identity,
}

impl Chain {
    fn new() -> Self {
        Self {
            root: Identity::ed25519(211),
            delegate: Identity::ed25519(212),
            actor: Identity::ed25519(213),
            unrelated: Identity::ed25519(214),
        }
    }
}

/// A root-issued principal-status statement and its control binding.
fn principal_entry(
    chain: &Chain,
    subject: &Identity,
    state: PrincipalState,
    sequence: u64,
    extensions: CriticalExtensions,
) -> (SignedPrincipalStatus, ControlBinding) {
    let statement = PrincipalStatusStatement::new(
        StatusMethodId::parse(STATUS_METHOD).expect("status method"),
        subject.principal.clone(),
        state,
        sequence,
        Timestamp::new(40),
        Timestamp::new(100),
        chain.root.principal.clone(),
        extensions,
    )
    .expect("principal status");
    let signed = signed_principal_status(&chain.root, statement);
    let identifier = principal_status_id(signed.statement()).expect("principal status ID");
    let binding = ControlBinding::new(
        StatementRef::PrincipalStatus(identifier),
        vec![chain.root.evidence().id()],
    )
    .expect("principal-status binding");
    (signed, binding)
}

/// A root-issued active grant-status statement and its control binding.
fn grant_entry(
    chain: &Chain,
    grant: GrantId,
    extensions: CriticalExtensions,
) -> (SignedGrantStatus, ControlBinding) {
    let statement = GrantStatusStatement::new(
        StatusMethodId::parse(STATUS_METHOD).expect("status method"),
        grant,
        GrantState::Active,
        1,
        Timestamp::new(40),
        Timestamp::new(100),
        chain.root.principal.clone(),
        extensions,
    )
    .expect("grant status");
    let signed = signed_grant_status(&chain.root, statement);
    let identifier = grant_status_id(signed.statement()).expect("grant status ID");
    let binding = ControlBinding::new(
        StatementRef::GrantStatus(identifier),
        vec![chain.root.evidence().id()],
    )
    .expect("grant-status binding");
    (signed, binding)
}

/// The principal-status statements of the chain and whether each is bound.
fn principal_statements(
    chain: &Chain,
    placement: Placement,
    carried: Carried,
) -> Vec<((SignedPrincipalStatus, ControlBinding), bool)> {
    let extensions = carried.extensions();
    let anchor_extensions = if matches!(placement, Placement::Anchor) {
        extensions.clone()
    } else {
        CriticalExtensions::empty()
    };
    let mut statements = vec![(
        principal_entry(
            chain,
            &chain.root,
            PrincipalState::Active,
            1,
            anchor_extensions,
        ),
        true,
    )];
    let active = PrincipalState::Active;
    match placement {
        Placement::Anchor | Placement::TerminalGrant => {}
        Placement::Delegate => statements.push((
            principal_entry(chain, &chain.delegate, active, 1, extensions),
            true,
        )),
        Placement::Actor => statements.push((
            principal_entry(chain, &chain.actor, active, 1, extensions),
            true,
        )),
        Placement::DelegateBesideNewer => {
            statements.push((
                principal_entry(chain, &chain.delegate, active, 1, extensions),
                true,
            ));
            statements.push((
                principal_entry(
                    chain,
                    &chain.delegate,
                    active,
                    2,
                    CriticalExtensions::empty(),
                ),
                true,
            ));
        }
        Placement::Unrelated => statements.push((
            principal_entry(chain, &chain.unrelated, active, 1, extensions),
            true,
        )),
        Placement::RevokedDelegate => statements.push((
            principal_entry(
                chain,
                &chain.delegate,
                PrincipalState::Revoked,
                1,
                extensions,
            ),
            true,
        )),
        Placement::UnboundDelegate => statements.push((
            principal_entry(chain, &chain.delegate, active, 1, extensions),
            false,
        )),
    }
    statements
}

#[allow(clippy::too_many_lines)]
fn status_extension_fixture(
    name: &'static str,
    placement: Placement,
    carried: Carried,
    expected: Expected,
) -> CorpusFixture {
    let chain = Chain::new();
    let identities = [
        chain.root.clone(),
        chain.delegate.clone(),
        chain.actor.clone(),
    ];
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xe5; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grant_scope =
        |issuer: &Identity, subject: &Identity, remaining_depth: u16, parent: Option<GrantId>| {
            GrantStatement::new(
                issuer.principal.clone(),
                subject.principal.clone(),
                profile(),
                PermissionSet::new(vec![permission()]).expect("permissions"),
                ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
                AudienceSet::new(vec![audience()]).expect("audience"),
                ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
                Some(BudgetCeiling::new(
                    BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
                    10,
                )),
                remaining_depth,
                parent,
                required_status(STATUS_METHOD),
                AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
                CriticalExtensions::empty(),
            )
        };
    let parent_grant = signed_grant(
        &chain.root,
        grant_scope(&chain.root, &chain.delegate, 1, None),
    );
    let parent_id = grant_id(parent_grant.statement()).expect("parent grant ID");
    let child_grant = signed_grant(
        &chain.delegate,
        grant_scope(&chain.delegate, &chain.actor, 0, Some(parent_id)),
    );
    let child_id = grant_id(child_grant.statement()).expect("child grant ID");
    let action = signed_action(
        &chain.actor,
        action_envelope(
            &chain.actor,
            &canonical,
            plan_identifier,
            proof_ref,
            Some(child_id),
        ),
    );
    let mut bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(parent_id),
            vec![chain.root.evidence().id()],
        )
        .expect("parent binding"),
        ControlBinding::new(
            StatementRef::Grant(child_id),
            vec![chain.delegate.evidence().id()],
        )
        .expect("child binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![chain.actor.evidence().id()],
        )
        .expect("action binding"),
    ];

    let mut principal_status = Vec::new();
    for ((signed, binding), bound) in principal_statements(&chain, placement, carried) {
        principal_status.push(signed);
        if bound {
            bindings.push(binding);
        }
    }
    let terminal_extensions = if matches!(placement, Placement::TerminalGrant) {
        carried.extensions()
    } else {
        CriticalExtensions::empty()
    };
    let (grant_status, grant_bindings): (Vec<_>, Vec<_>) = [
        grant_entry(&chain, parent_id, CriticalExtensions::empty()),
        grant_entry(&chain, child_id, terminal_extensions),
    ]
    .into_iter()
    .unzip();
    bindings.extend(grant_bindings);

    let method = || StatusMethodId::parse(STATUS_METHOD).expect("status method");
    let trust = || {
        vec![auths_model::StatusTrustRule::new(
            method(),
            chain.root.principal.clone(),
            1,
        )]
    };
    let principal_snapshot = PrincipalStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xe6; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        principal_status,
        Vec::new(),
        trust(),
    )
    .expect("principal snapshot");
    let grant_snapshot = GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xe7; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        grant_status,
        Vec::new(),
        trust(),
    )
    .expect("grant snapshot");

    let base_registries = registries_with_status(&identities, vec![method()], vec![method()]);
    let accepted_extensions = if carried == Carried::Unknown {
        Vec::new()
    } else {
        vec![ExtensionId::parse(MARKER_EXTENSION).expect("extension ID")]
    };
    let accepted = accepted_from(
        &base_registries,
        base_registries.manifest_id(),
        base_registries.resource_matchers().to_vec(),
        accepted_extensions,
        base_registries.profile_policies().to_vec(),
    );
    let verifier_context = TrustedContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor_with_status(
            &chain.root,
            2,
            required_status(STATUS_METHOD),
        )],
        accepted,
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&identities),
        principal_snapshot,
        grant_snapshot,
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("status extension context");
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![parent_grant, child_grant],
        vec![action],
        plan,
        addressed_evidence(&identities),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("status extension proof");
    fixture(
        name,
        "status",
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// The status-extension vectors. The first eight each violate one fact that a
/// status-extension check site rejects first; the ninth authorizes because
/// the statement names a principal the branch never evaluates; the last three
/// each carry two faults and pin the specified precedence between them.
pub(crate) fn status_extension_vectors() -> Vec<CorpusFixture> {
    let unknown = Expected::Denied(DenialReason::CriticalExtensionUnknown);
    let unsupported = Expected::Indeterminate(Requirement::UnsupportedCriticalExtension);
    vec![
        status_extension_fixture(
            "anchor-status-extension-unknown",
            Placement::Anchor,
            Carried::Unknown,
            unknown,
        ),
        status_extension_fixture(
            "delegate-status-extension-unknown",
            Placement::Delegate,
            Carried::Unknown,
            unknown,
        ),
        status_extension_fixture(
            "actor-status-extension-unknown",
            Placement::Actor,
            Carried::Unknown,
            unknown,
        ),
        // Every statement about the principal is checked, not only the one
        // selection picks.
        status_extension_fixture(
            "delegate-status-extension-beside-newer",
            Placement::DelegateBesideNewer,
            Carried::Unknown,
            unknown,
        ),
        status_extension_fixture(
            "anchor-status-extension-without-handler",
            Placement::Anchor,
            Carried::Accepted,
            unsupported,
        ),
        status_extension_fixture(
            "delegate-status-extension-without-handler",
            Placement::Delegate,
            Carried::Accepted,
            unsupported,
        ),
        status_extension_fixture(
            "grant-status-extension-unknown",
            Placement::TerminalGrant,
            Carried::Unknown,
            unknown,
        ),
        status_extension_fixture(
            "grant-status-extension-without-handler",
            Placement::TerminalGrant,
            Carried::Accepted,
            unsupported,
        ),
        // Only statements about a principal or grant the branch evaluates are
        // checked.
        status_extension_fixture(
            "unrelated-principal-status-extension",
            Placement::Unrelated,
            Carried::Unknown,
            Expected::Authorized,
        ),
        // The statement's control is checked before its extensions.
        status_extension_fixture(
            "two-fault-status-control-and-extension",
            Placement::UnboundDelegate,
            Carried::Unknown,
            Expected::Indeterminate(Requirement::MissingPrincipalEvidence),
        ),
        // Extensions are checked before selection reads the state.
        status_extension_fixture(
            "two-fault-status-extension-and-principal-revoked",
            Placement::RevokedDelegate,
            Carried::Unknown,
            unknown,
        ),
        // Extensions are checked in canonical order and the first decides.
        status_extension_fixture(
            "two-fault-status-accepted-and-unknown-extension",
            Placement::Anchor,
            Carried::AcceptedThenUnknown,
            unsupported,
        ),
    ]
}
