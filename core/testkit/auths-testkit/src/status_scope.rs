//! Vectors for status issuer scope (AP-SPEC-064).
//!
//! Two organizations anchor their roots at one verifier: V, the verifying
//! organization, and F, a partner. Both roots are trusted as status issuers
//! with scope `own`, so each root's statements count only in branches under
//! its own anchor. S is a status service that is no anchor, and U an issuer
//! no rule names. Every status statement is bound to its issuer's evidence
//! unless a vector says otherwise, so a statement that is ignored is ignored
//! for its scope alone. Each vector that expects an out-of-scope statement to
//! be ignored has a reference vector without the statement and the same
//! result: `status-scope-baseline`, or for a reinstatement, the corresponding
//! in-scope revocation.

use super::*;

/// One exact method serves the anchors' policies, the grants' policies, and
/// every statement, because a grant's status policy preserves or narrows its
/// anchor's.
const METHOD: &str = "auths-principal-status-v1";
/// A method no rule names.
const OTHER_METHOD: &str = "other-principal-status-v1";
const UNKNOWN_EXTENSION: &str = "unknown-critical-v1";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Party {
    VerifierRoot,
    VerifierActor,
    VerifierDelegate,
    VerifierManager,
    PartnerRoot,
    PartnerActor,
    Service,
    Unnamed,
    ThirdRoot,
}

struct Parties {
    verifier_root: Identity,
    verifier_actor: Identity,
    verifier_delegate: Identity,
    verifier_manager: Identity,
    partner_root: Identity,
    partner_actor: Identity,
    service: Identity,
    unnamed: Identity,
    third_root: Identity,
}

impl Parties {
    fn new() -> Self {
        Self {
            verifier_root: Identity::ed25519(221),
            verifier_actor: Identity::ed25519(222),
            verifier_delegate: Identity::ed25519(223),
            verifier_manager: Identity::ed25519(224),
            partner_root: Identity::ed25519(225),
            partner_actor: Identity::ed25519(226),
            service: Identity::ed25519(227),
            unnamed: Identity::ed25519(228),
            third_root: Identity::ed25519(229),
        }
    }

    const fn get(&self, party: Party) -> &Identity {
        match party {
            Party::VerifierRoot => &self.verifier_root,
            Party::VerifierActor => &self.verifier_actor,
            Party::VerifierDelegate => &self.verifier_delegate,
            Party::VerifierManager => &self.verifier_manager,
            Party::PartnerRoot => &self.partner_root,
            Party::PartnerActor => &self.partner_actor,
            Party::Service => &self.service,
            Party::Unnamed => &self.unnamed,
            Party::ThirdRoot => &self.third_root,
        }
    }
}

/// The proof a vector verifies.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Proof {
    /// V root → V actor.
    Verifier,
    /// V root → V delegate → V actor.
    VerifierDelegated,
    /// F root → F actor.
    Partner,
    /// Signed by V's manager M alone, a depth-zero anchor as in an approval
    /// quorum.
    Manager,
}

/// What a status statement is about.
#[derive(Clone, Copy)]
enum Subject {
    Principal(Party),
    /// The proof's terminal grant.
    TerminalGrant,
}

/// Where a status statement appears.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Placement {
    /// In the context's snapshot only.
    Snapshot,
    /// In the snapshot, and also carried in the proof.
    SnapshotAndProof,
    /// Carried in the proof only; the snapshot does not hold it, and no
    /// control binding names it.
    ProofOnly,
}

/// One status statement a vector adds to the base snapshots.
#[derive(Clone, Copy)]
struct Entry {
    issuer: Party,
    subject: Subject,
    revoked: bool,
    sequence: u64,
    method: &'static str,
    unknown_extension: bool,
    placement: Placement,
}

impl Entry {
    const fn new(issuer: Party, subject: Subject, revoked: bool, sequence: u64) -> Self {
        Self {
            issuer,
            subject,
            revoked,
            sequence,
            method: METHOD,
            unknown_extension: false,
            placement: Placement::Snapshot,
        }
    }

    const fn revokes(issuer: Party, subject: Subject, sequence: u64) -> Self {
        Self::new(issuer, subject, true, sequence)
    }

    const fn activates(issuer: Party, subject: Subject, sequence: u64) -> Self {
        Self::new(issuer, subject, false, sequence)
    }

    const fn under(mut self, method: &'static str) -> Self {
        self.method = method;
        self
    }

    const fn with_unknown_extension(mut self) -> Self {
        self.unknown_extension = true;
        self
    }

    const fn carried(mut self) -> Self {
        self.placement = Placement::SnapshotAndProof;
        self
    }

    const fn carried_only(mut self) -> Self {
        self.placement = Placement::ProofOnly;
        self
    }
}

/// A party a vector adds beyond V, F, and their anchors.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Extra {
    None,
    /// Trusts S for principal status under F's anchor.
    ServiceForPartner,
    /// Adds a third organization's anchor and own-scoped rule.
    ThirdParty,
}

/// The scope of V root's rules.
#[derive(Clone, Copy, Eq, PartialEq)]
enum VerifierScope {
    Own,
    Any,
    /// V's two anchors: its root's and its manager's.
    OrganizationAnchors,
}

struct Vector {
    name: &'static str,
    proof: Proof,
    entries: Vec<Entry>,
    /// Removes V root's statement that its own principal is active.
    without_verifier_root_status: bool,
    /// Leaves every F-root statement unbound and F root's evidence out of the
    /// proof.
    partner_unbound: bool,
    verifier_scope: VerifierScope,
    extra: Extra,
    expected: Expected,
}

impl Vector {
    fn new(name: &'static str, proof: Proof, entries: Vec<Entry>, expected: Expected) -> Self {
        Self {
            name,
            proof,
            entries,
            without_verifier_root_status: false,
            partner_unbound: false,
            verifier_scope: VerifierScope::Own,
            extra: Extra::None,
            expected,
        }
    }
}

fn status_rule(issuer: &Identity, scope: StatusScope) -> auths_model::StatusTrustRule {
    auths_model::StatusTrustRule::new(
        StatusMethodId::parse(METHOD).expect("status method"),
        issuer.principal.clone(),
        1,
        scope,
    )
}

#[allow(clippy::too_many_lines)]
fn status_scope_fixture(vector: Vector) -> CorpusFixture {
    let parties = Parties::new();
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xe8; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grant = |issuer: &Identity, subject: &Identity, depth: u16, parent: Option<GrantId>| {
        signed_grant(
            issuer,
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
                depth,
                parent,
                required_status(METHOD),
                AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
                CriticalExtensions::empty(),
            ),
        )
    };

    // The chain, root first, and the grants that link it.
    let (chain, grants): (Vec<Party>, Vec<SignedGrant>) = match vector.proof {
        Proof::Verifier => (
            vec![Party::VerifierRoot, Party::VerifierActor],
            vec![grant(
                &parties.verifier_root,
                &parties.verifier_actor,
                0,
                None,
            )],
        ),
        Proof::VerifierDelegated => {
            let parent = grant(&parties.verifier_root, &parties.verifier_delegate, 1, None);
            let parent_id = grant_id(parent.statement()).expect("parent grant ID");
            let child = grant(
                &parties.verifier_delegate,
                &parties.verifier_actor,
                0,
                Some(parent_id),
            );
            (
                vec![
                    Party::VerifierRoot,
                    Party::VerifierDelegate,
                    Party::VerifierActor,
                ],
                vec![parent, child],
            )
        }
        Proof::Partner => (
            vec![Party::PartnerRoot, Party::PartnerActor],
            vec![grant(
                &parties.partner_root,
                &parties.partner_actor,
                0,
                None,
            )],
        ),
        Proof::Manager => (vec![Party::VerifierManager], Vec::new()),
    };
    let root = *chain.first().expect("chain root");
    let actor = *chain.last().expect("chain actor");
    let grant_ids: Vec<GrantId> = grants
        .iter()
        .map(|signed| grant_id(signed.statement()).expect("grant ID"))
        .collect();
    let terminal = grant_ids.last().copied();
    let action = signed_action(
        parties.get(actor),
        action_envelope(
            parties.get(actor),
            &canonical,
            plan_identifier,
            proof_ref,
            terminal,
        ),
    );
    let mut bindings: Vec<ControlBinding> = grants
        .iter()
        .zip(&grant_ids)
        .map(|(signed, id)| {
            let issuer = if signed.statement().issuer() == &parties.verifier_delegate.principal {
                &parties.verifier_delegate
            } else if signed.statement().issuer() == &parties.partner_root.principal {
                &parties.partner_root
            } else {
                &parties.verifier_root
            };
            ControlBinding::new(StatementRef::Grant(*id), vec![issuer.evidence().id()])
                .expect("grant binding")
        })
        .collect();
    bindings.push(
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![parties.get(actor).evidence().id()],
        )
        .expect("action binding"),
    );

    // Base statements: each root says its own principal is active, and the
    // chain's root says each of the proof's grants is active.
    let mut entries = Vec::new();
    if !vector.without_verifier_root_status {
        entries.push(Entry::activates(
            Party::VerifierRoot,
            Subject::Principal(Party::VerifierRoot),
            1,
        ));
    }
    entries.push(Entry::activates(
        Party::PartnerRoot,
        Subject::Principal(Party::PartnerRoot),
        1,
    ));
    entries.extend(vector.entries);

    let mut principal_status = Vec::new();
    let mut grant_status = Vec::new();
    let mut carried_principal_status = Vec::new();
    let mut carried_grant_status = Vec::new();
    let mut evidence_parties = chain.clone();
    let mut record = |entry: Entry, grant: Option<GrantId>| {
        let issuer = parties.get(entry.issuer);
        let held = entry.placement != Placement::ProofOnly;
        let carried = entry.placement != Placement::Snapshot;
        let bound = held && !(vector.partner_unbound && entry.issuer == Party::PartnerRoot);
        let extensions = if entry.unknown_extension {
            CriticalExtensions::new(vec![
                CriticalExtension::new(
                    ExtensionId::parse(UNKNOWN_EXTENSION).expect("extension ID"),
                    vec![1],
                )
                .expect("extension"),
            ])
            .expect("status extensions")
        } else {
            CriticalExtensions::empty()
        };
        let reference = match (entry.subject, grant) {
            (Subject::Principal(subject), _) => {
                let statement = PrincipalStatusStatement::new(
                    StatusMethodId::parse(entry.method).expect("status method"),
                    parties.get(subject).principal.clone(),
                    if entry.revoked {
                        PrincipalState::Revoked
                    } else {
                        PrincipalState::Active
                    },
                    entry.sequence,
                    Timestamp::new(40),
                    Timestamp::new(100),
                    issuer.principal.clone(),
                    extensions,
                )
                .expect("principal status");
                let signed = signed_principal_status(issuer, statement);
                let identifier =
                    principal_status_id(signed.statement()).expect("principal status ID");
                if carried {
                    carried_principal_status.push(signed.clone());
                }
                if held {
                    principal_status.push(signed);
                }
                StatementRef::PrincipalStatus(identifier)
            }
            (Subject::TerminalGrant, Some(grant)) => {
                let statement = GrantStatusStatement::new(
                    StatusMethodId::parse(entry.method).expect("status method"),
                    grant,
                    if entry.revoked {
                        GrantState::Revoked
                    } else {
                        GrantState::Active
                    },
                    entry.sequence,
                    Timestamp::new(40),
                    Timestamp::new(100),
                    issuer.principal.clone(),
                    extensions,
                )
                .expect("grant status");
                let signed = signed_grant_status(issuer, statement);
                let identifier = grant_status_id(signed.statement()).expect("grant status ID");
                if carried {
                    carried_grant_status.push(signed.clone());
                }
                if held {
                    grant_status.push(signed);
                }
                StatementRef::GrantStatus(identifier)
            }
            (Subject::TerminalGrant, None) => unreachable!("grant status needs a grant"),
        };
        if bound {
            bindings.push(
                ControlBinding::new(reference, vec![issuer.evidence().id()])
                    .expect("status binding"),
            );
            if !evidence_parties.contains(&entry.issuer) {
                evidence_parties.push(entry.issuer);
            }
        }
    };
    for entry in entries {
        record(entry, terminal);
    }
    for id in &grant_ids {
        record(Entry::activates(root, Subject::TerminalGrant, 1), Some(*id));
    }

    let verifier_scope = match vector.verifier_scope {
        VerifierScope::Own => StatusScope::OwnAnchor,
        VerifierScope::Any => StatusScope::AnyAnchor,
        VerifierScope::OrganizationAnchors => {
            listed_status_scope(&[&parties.verifier_root, &parties.verifier_manager])
        }
    };
    let mut principal_trust = vec![
        status_rule(&parties.verifier_root, verifier_scope.clone()),
        status_rule(&parties.partner_root, StatusScope::OwnAnchor),
    ];
    if vector.extra == Extra::ServiceForPartner {
        principal_trust.push(status_rule(
            &parties.service,
            listed_status_scope(&[&parties.partner_root]),
        ));
    }
    if vector.extra == Extra::ThirdParty {
        principal_trust.push(status_rule(&parties.third_root, StatusScope::OwnAnchor));
    }
    let grant_trust = vec![
        status_rule(&parties.verifier_root, verifier_scope),
        status_rule(&parties.partner_root, StatusScope::OwnAnchor),
    ];
    let principal_snapshot = PrincipalStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xe9; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        principal_status,
        Vec::new(),
        principal_trust,
    )
    .expect("principal snapshot");
    let grant_snapshot = GrantStatusSnapshot::with_trust(
        StatusSnapshotId::new([0xea; 32]),
        Timestamp::new(40),
        Timestamp::new(100),
        grant_status,
        Vec::new(),
        grant_trust,
    )
    .expect("grant snapshot");

    let mut anchor_parties = vec![Party::VerifierRoot, Party::PartnerRoot];
    if vector.proof == Proof::Manager {
        anchor_parties.push(Party::VerifierManager);
    }
    if vector.extra == Extra::ThirdParty {
        anchor_parties.push(Party::ThirdRoot);
    }
    let anchors = anchor_parties
        .iter()
        .map(|party| {
            let depth = if *party == Party::VerifierManager {
                0
            } else {
                2
            };
            anchor_with_status(parties.get(*party), depth, required_status(METHOD))
        })
        .collect();
    let method = || StatusMethodId::parse(METHOD).expect("status method");
    let identities: Vec<Identity> = [
        Party::VerifierRoot,
        Party::VerifierActor,
        Party::VerifierDelegate,
        Party::VerifierManager,
        Party::PartnerRoot,
        Party::PartnerActor,
        Party::Service,
        Party::Unnamed,
        Party::ThirdRoot,
    ]
    .iter()
    .map(|party| parties.get(*party).clone())
    .collect();
    let verifier_context = TrustedContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        anchors,
        registries_with_status(&identities, vec![method()], vec![method()]),
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&[parties.get(root).clone(), parties.get(actor).clone()]),
        principal_snapshot,
        grant_snapshot,
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("status scope context");
    let evidence: Vec<Identity> = evidence_parties
        .iter()
        .map(|party| parties.get(*party).clone())
        .collect();
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        vec![action],
        plan,
        addressed_evidence(&evidence),
        bindings,
        carried_principal_status,
        carried_grant_status,
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("status scope proof");
    fixture(
        vector.name,
        "status",
        &bundle,
        &verifier_context,
        canonical,
        vector.expected,
    )
}

/// The two-organization context the invalid-scope recipes and splice tests
/// start from, with every status rule scoped `own`.
#[must_use]
pub fn status_scope_baseline() -> CorpusFixture {
    status_scope_fixture(Vector::new(
        "status-scope-baseline",
        Proof::Verifier,
        Vec::new(),
        Expected::Authorized,
    ))
}

/// The status-scope vectors. A partner's statement about the verifying
/// organization's subjects, out of scope under the verifying organization's
/// anchor, changes no result, while each organization's revocations of its
/// own subjects still count; the listed and `any` scopes extend status
/// authority only where a rule says so.
#[allow(clippy::too_many_lines)]
pub(crate) fn status_scope_vectors() -> Vec<CorpusFixture> {
    use Party::{
        PartnerActor, PartnerRoot, Service, Unnamed, VerifierActor, VerifierDelegate,
        VerifierManager, VerifierRoot,
    };
    let actor = Subject::Principal(VerifierActor);
    let grant = Subject::TerminalGrant;
    let principal_revoked = Expected::Denied(DenialReason::PrincipalRevoked);
    let grant_revoked = Expected::Denied(DenialReason::GrantRevoked);
    let missing = Expected::Indeterminate(Requirement::MissingPrincipalStatus);
    let vector = Vector::new;
    let mut vectors = vec![
        vector(
            "status-scope-own-revokes-actor",
            Proof::Verifier,
            vec![Entry::revokes(VerifierRoot, actor, 1)],
            principal_revoked,
        ),
        vector(
            "status-scope-own-revokes-grant",
            Proof::Verifier,
            vec![Entry::revokes(VerifierRoot, grant, 2)],
            grant_revoked,
        ),
        vector(
            "status-scope-foreign-revokes-actor",
            Proof::Verifier,
            vec![Entry::revokes(PartnerRoot, actor, 1)],
            Expected::Authorized,
        ),
        vector(
            "status-scope-foreign-revokes-grant",
            Proof::Verifier,
            vec![Entry::revokes(PartnerRoot, grant, 2)],
            Expected::Authorized,
        ),
        vector(
            "status-scope-foreign-revokes-root",
            Proof::Verifier,
            vec![Entry::revokes(
                PartnerRoot,
                Subject::Principal(VerifierRoot),
                2,
            )],
            Expected::Authorized,
        ),
        vector(
            "status-scope-foreign-revokes-delegate",
            Proof::VerifierDelegated,
            vec![Entry::revokes(
                PartnerRoot,
                Subject::Principal(VerifierDelegate),
                1,
            )],
            Expected::Authorized,
        ),
        vector(
            "status-scope-foreign-reinstates-actor",
            Proof::Verifier,
            vec![
                Entry::revokes(VerifierRoot, actor, 1),
                Entry::activates(PartnerRoot, actor, 2),
            ],
            principal_revoked,
        ),
        vector(
            "status-scope-foreign-reinstates-grant",
            Proof::Verifier,
            vec![
                Entry::revokes(VerifierRoot, grant, 2),
                Entry::activates(PartnerRoot, grant, 3),
            ],
            grant_revoked,
        ),
        // Visible, this statement alone would be `status-method-mismatch`.
        vector(
            "status-scope-foreign-other-method",
            Proof::Verifier,
            vec![Entry::revokes(PartnerRoot, actor, 1).under(OTHER_METHOD)],
            Expected::Authorized,
        ),
        // Visible, it would be `critical-extension-unknown`.
        vector(
            "status-scope-foreign-unknown-extension",
            Proof::Verifier,
            vec![Entry::revokes(PartnerRoot, actor, 1).with_unknown_extension()],
            Expected::Authorized,
        ),
        // The anchor's own status still needs an in-scope statement.
        Vector {
            without_verifier_root_status: true,
            ..vector(
                "status-scope-foreign-anchor-only",
                Proof::Verifier,
                vec![Entry::activates(
                    PartnerRoot,
                    Subject::Principal(VerifierRoot),
                    1,
                )],
                missing,
            )
        },
        // Each organization's revocation of its own subject still counts.
        vector(
            "status-scope-partner-revokes-own-actor",
            Proof::Partner,
            vec![Entry::revokes(
                PartnerRoot,
                Subject::Principal(PartnerActor),
                1,
            )],
            principal_revoked,
        ),
        Vector {
            extra: Extra::ServiceForPartner,
            ..vector(
                "status-scope-listed-anchor-revokes",
                Proof::Partner,
                vec![Entry::revokes(Service, Subject::Principal(PartnerActor), 1)],
                principal_revoked,
            )
        },
        Vector {
            extra: Extra::ServiceForPartner,
            ..vector(
                "status-scope-listed-anchor-elsewhere",
                Proof::Verifier,
                vec![Entry::revokes(Service, actor, 1)],
                Expected::Authorized,
            )
        },
        // The verifying organization keeps authority over a partner's
        // subjects only by choosing `any`.
        Vector {
            verifier_scope: VerifierScope::Any,
            ..vector(
                "status-scope-any-revokes-partner-actor",
                Proof::Partner,
                vec![Entry::revokes(
                    VerifierRoot,
                    Subject::Principal(PartnerActor),
                    1,
                )],
                principal_revoked,
            )
        },
        // A carried statement is compared only with the snapshot statements
        // of its own issuer and method.
        vector(
            "status-scope-carried-other-issuer",
            Proof::Verifier,
            vec![
                Entry::activates(VerifierRoot, actor, 1).carried(),
                Entry::revokes(PartnerRoot, actor, 2),
            ],
            Expected::Authorized,
        ),
        vector(
            "status-scope-carried-same-issuer",
            Proof::Verifier,
            vec![
                Entry::activates(VerifierRoot, actor, 1).carried(),
                Entry::revokes(VerifierRoot, actor, 2),
            ],
            Expected::Denied(DenialReason::StatusSequenceRollback),
        ),
        // An issuer no rule names keeps failing closed.
        vector(
            "status-scope-unknown-issuer",
            Proof::Verifier,
            vec![Entry::revokes(Unnamed, actor, 1)],
            Expected::Denied(DenialReason::StatusIssuerUntrusted),
        ),
        // An organization with several anchors lists them all.
        Vector {
            verifier_scope: VerifierScope::OrganizationAnchors,
            ..vector(
                "status-scope-organization-anchors",
                Proof::Manager,
                vec![Entry::activates(
                    VerifierRoot,
                    Subject::Principal(VerifierManager),
                    1,
                )],
                Expected::Authorized,
            )
        },
        vector(
            "status-scope-own-misses-second-anchor",
            Proof::Manager,
            vec![Entry::activates(
                VerifierRoot,
                Subject::Principal(VerifierManager),
                1,
            )],
            missing,
        ),
        // The partner cannot override the verifying organization's subject at
        // a third organization's boundary either.
        Vector {
            extra: Extra::ThirdParty,
            ..vector(
                "status-scope-foreign-revokes-actor-at-third-party",
                Proof::Verifier,
                vec![Entry::revokes(PartnerRoot, actor, 1)],
                Expected::Authorized,
            )
        },
    ];
    // Visible, the unbound statement would be `missing-principal-evidence`.
    vectors.push(Vector {
        partner_unbound: true,
        ..vector(
            "status-scope-foreign-unbound",
            Proof::Verifier,
            vec![Entry::revokes(PartnerRoot, actor, 1)],
            Expected::Authorized,
        )
    });
    let mut fixtures = vec![status_scope_baseline()];
    fixtures.extend(vectors.into_iter().map(status_scope_fixture));
    fixtures
}

/// The two-fault vector for stage 2, step 9. The proof carries a
/// principal-status statement the snapshot does not hold, about a principal
/// the snapshot has no statement about, and a grant-status statement older
/// than the snapshot's statement about the same grant from the same issuer
/// under the same method. Every rollback check runs before any holding check,
/// so the result is the rollback, not the missing statement.
pub(crate) fn carried_status_precedence_vectors() -> Vec<CorpusFixture> {
    vec![status_scope_fixture(Vector::new(
        "two-fault-carried-unheld-and-rollback",
        Proof::Verifier,
        vec![
            Entry::activates(
                Party::VerifierRoot,
                Subject::Principal(Party::VerifierActor),
                1,
            )
            .carried_only(),
            Entry::activates(Party::VerifierRoot, Subject::TerminalGrant, 2),
            Entry::revokes(Party::VerifierRoot, Subject::TerminalGrant, 1).carried_only(),
        ],
        Expected::Denied(DenialReason::StatusSequenceRollback),
    ))]
}
