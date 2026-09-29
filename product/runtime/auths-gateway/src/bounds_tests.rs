//! Bounded-policy cases of the hostile suite, with real proofs.
//!
//! Two agents share one contract under one root, each with its own bound, and
//! an agent may delegate a narrower bound to a sub-agent, whose actions also
//! charge the agent's counter. Every case runs the engine's dispatch against
//! the counting provider: an authorized case enters the provider once, and
//! every refused case leaves zero provider entries and zero credential
//! leases.

use super::*;
use crate::{ArgumentCeilingPolicy, UnverifiedEntries};
use auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1;
use std::collections::BTreeSet;

const WINDOW: u64 = 3_600;

#[derive(serde::Deserialize)]
struct Suite {
    schema: String,
    cases: Vec<SuiteCase>,
}

#[derive(serde::Deserialize)]
struct SuiteCase {
    id: String,
    decision: String,
    code: Option<String>,
    provider_entries: usize,
}

fn bounds_recipe() -> CompiledRecipe {
    recipe(
        &json!({"amount": {"kind": "integer", "minimum": 0, "maximum": 1_000_000}}),
        &json!({"verified": ["amount"]}),
    )
}

fn bound(ceiling: u64, max_count: u64) -> ArgumentCeilingPolicy {
    ArgumentCeilingPolicy::new("amount", ceiling, WINDOW, max_count).expect("policy")
}

fn extension(body: Vec<u8>) -> CriticalExtensions {
    CriticalExtensions::new(vec![
        CriticalExtension::new(
            ExtensionId::parse(BOUNDED_POLICY_COMMITMENT_EXTENSION_V1).expect("extension"),
            body,
        )
        .expect("extension"),
    ])
    .expect("extensions")
}

/// A grant from `issuer` to `subject` carrying `body` under `parent`.
fn bounded_grant(
    issuer: &Signer,
    subject: &Signer,
    parent: Option<&SignedGrant>,
    remaining_depth: u16,
    body: Option<Vec<u8>>,
) -> SignedGrant {
    let statement = GrantStatement::new(
        issuer.principal.clone(),
        subject.principal.clone(),
        call(&Map::new()).profile_ref().expect("profile"),
        PermissionSet::new(vec![call(&Map::new()).permission().expect("permission")])
            .expect("permissions"),
        window(NOW - 3_600, NOW + 86_400),
        AudienceSet::new(vec![audience()]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        remaining_depth,
        parent.map(|parent| grant_id(parent.statement()).expect("parent ID")),
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        body.map_or_else(CriticalExtensions::empty, extension),
    );
    let descriptor = issuer.descriptor();
    let signature =
        issuer.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
    SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
}

/// The extension bytes a grant carries.
fn body_of(grant: &SignedGrant) -> Vec<u8> {
    grant.statement().extensions().as_slice()[0]
        .bytes()
        .to_vec()
}

/// The parent link a child bound carries for `parent`.
fn link(parent: &SignedGrant) -> auths_model::Digest {
    auths_codec::bounded_policy_link(&body_of(parent)).expect("link")
}

/// An action by `agent` whose terminal grant is the last of `grants`, signed
/// through the whole chain.
fn chain_submission(
    issuers: &[&Signer],
    grants: &[SignedGrant],
    agent: &Signer,
    arguments: &Map<String, Value>,
) -> Submission {
    let bytes = call(arguments).canonical_bytes().expect("canonical call");
    let canonical: CanonicalAction = McpProfile.canonicalize(&bytes).expect("canonical action");
    let proof_ref = ProofRef::new([0x0b; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let terminal = grants.last().expect("terminal grant");
    let action = sign_action(
        agent,
        envelope(agent, &canonical, terminal, &plan, proof_ref, Vec::new()),
    );
    let mut bindings: Vec<ControlBinding> = grants
        .iter()
        .zip(issuers)
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
            vec![agent.evidence().id()],
        )
        .expect("action binding"),
    );
    let mut evidence: Vec<EvidenceObject> =
        issuers.iter().map(|issuer| issuer.evidence()).collect();
    evidence.push(agent.evidence());
    evidence.sort_by_key(EvidenceObject::id);
    evidence.dedup_by_key(|object| object.id());
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants.to_vec(),
        vec![action],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("bundle");
    let action = encode_canonical_action(&canonical).expect("action bytes");
    let commitment = *domain_commitment("auths.canonical-action.v1", &action)
        .expect("commitment")
        .as_bytes();
    Submission {
        proof: encode_bundle(&bundle).expect("proof bytes"),
        action,
        commitment,
    }
}

/// Root, agent A, agent B, and A's sub-agent under one two-edge contract.
struct Principals {
    harness: Harness,
    a: Signer,
    b: Signer,
    sub: Signer,
}

impl Principals {
    fn open(backend: Backend) -> Self {
        let root = Signer::new(0x11);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = context_with_depth(&root, observer.principal(), None, 2);
        Self {
            harness: Harness::with(
                bounds_recipe(),
                context,
                observer,
                root,
                Signer::new(0x22),
                backend,
            ),
            a: Signer::new(0x44),
            b: Signer::new(0x55),
            sub: Signer::new(0x66),
        }
    }

    fn arguments(&self, operation: &str, amount: u64) -> Map<String, Value> {
        self.harness
            .arguments(operation, RECORD, &json!({"amount": amount}))
    }

    fn root_grant(&self, agent: &Signer, policy: &ArgumentCeilingPolicy) -> SignedGrant {
        bounded_grant(
            &self.harness.root,
            agent,
            None,
            1,
            Some(policy.extension_body(None).expect("body")),
        )
    }

    fn delegated(&self, parent: &SignedGrant, body: Vec<u8>) -> SignedGrant {
        bounded_grant(&self.a, &self.sub, Some(parent), 0, Some(body))
    }
}

/// A commitment to `policy` naming an evaluator the gateway never registered.
fn unregistered_body(policy: &ArgumentCeilingPolicy) -> Vec<u8> {
    let policy = policy.encode().expect("policy");
    let commitment = auths_model::PolicyCommitment::new(
        auths_model::PolicyIdentifier::parse(crate::ARGUMENT_CEILING_POLICY_TYPE, 128)
            .expect("type"),
        1,
        auths_model::PolicyIdentifier::parse(crate::ARGUMENT_CEILING_CANONICALIZATION, 64)
            .expect("canonicalization"),
        auths_codec::bounded_policy_digest(&policy).expect("digest"),
        auths_model::PolicyIdentifier::parse("auths.gateway.unregistered/1", 128)
            .expect("evaluator"),
    )
    .expect("commitment");
    auths_codec::encode_bounded_policy_commitment(
        &auths_model::BoundedPolicyCommitment::new(commitment, policy, None).expect("body"),
    )
    .expect("bytes")
}

/// The submissions of one case, in order.
fn submissions(principals: &Principals, id: &str) -> Vec<Submission> {
    let root = &principals.harness.root;
    let a_grant = principals.root_grant(&principals.a, &bound(500, 3));
    let b_grant = principals.root_grant(&principals.b, &bound(5_000, 3));
    match id {
        "a-inside-a-bound" => vec![chain_submission(
            &[root],
            &[a_grant],
            &principals.a,
            &principals.arguments("a-inside", 400),
        )],
        "a-outside-a-bound" => vec![chain_submission(
            &[root],
            &[a_grant],
            &principals.a,
            &principals.arguments("a-outside", 600),
        )],
        "a-presents-b-bound" => vec![chain_submission(
            &[root],
            &[b_grant],
            &principals.a,
            &principals.arguments("a-as-b", 600),
        )],
        "sub-agent-narrower-inside" => {
            let child = principals.delegated(
                &a_grant,
                bound(100, 1)
                    .extension_body(Some(link(&a_grant)))
                    .expect("body"),
            );
            vec![chain_submission(
                &[root, &principals.a],
                &[a_grant, child],
                &principals.sub,
                &principals.arguments("sub-inside", 100),
            )]
        }
        "sub-agent-wider-than-parent" => {
            let child = principals.delegated(
                &a_grant,
                bound(1_000, 1)
                    .extension_body(Some(link(&a_grant)))
                    .expect("body"),
            );
            vec![chain_submission(
                &[root, &principals.a],
                &[a_grant, child],
                &principals.sub,
                &principals.arguments("sub-wider", 50),
            )]
        }
        "sub-agent-unlinked-bound" => {
            let child =
                principals.delegated(&a_grant, bound(100, 1).extension_body(None).expect("body"));
            vec![chain_submission(
                &[root, &principals.a],
                &[a_grant, child],
                &principals.sub,
                &principals.arguments("sub-unlinked", 50),
            )]
        }
        "window-exhausted" => {
            let once = principals.root_grant(&principals.a, &bound(500, 1));
            vec![
                chain_submission(
                    &[root],
                    std::slice::from_ref(&once),
                    &principals.a,
                    &principals.arguments("window-1", 10),
                ),
                chain_submission(
                    &[root],
                    &[once],
                    &principals.a,
                    &principals.arguments("window-2", 10),
                ),
            ]
        }
        "unregistered-evaluator" => {
            let grant = bounded_grant(
                root,
                &principals.a,
                None,
                1,
                Some(unregistered_body(&bound(500, 3))),
            );
            vec![chain_submission(
                &[root],
                &[grant],
                &principals.a,
                &principals.arguments("unregistered", 10),
            )]
        }
        other => panic!("unknown bounded case {other}"),
    }
}

/// Runs one case and reports its decision, code, and provider entries.
async fn run(id: &str, backend: Backend) -> (String, Option<String>, (usize, usize, usize)) {
    let principals = Principals::open(backend);
    let mut last = None;
    for submission in &submissions(&principals, id) {
        last = Some(principals.harness.submit(submission, NOW).await);
    }
    let (decision, code) = match last.expect("one submission") {
        GatewaySubmitResult::Denied { code } => ("denied".to_owned(), Some(code)),
        GatewaySubmitResult::Indeterminate { code } => ("indeterminate".to_owned(), Some(code)),
        GatewaySubmitResult::NotEntered { code } => ("not-entered".to_owned(), Some(code)),
        GatewaySubmitResult::Unknown => ("unknown".to_owned(), None),
        GatewaySubmitResult::ResponseRecorded { .. }
        | GatewaySubmitResult::Observed { .. }
        | GatewaySubmitResult::ObservedByProvider { .. } => ("entered".to_owned(), None),
    };
    (decision, code, principals.harness.provider.counts())
}

/// Two sub-agents under one agent's bound: each action charges the agent's
/// counter as well as the sub-agent's own, so together they get the agent's
/// count and no more, although each sub-agent's own counter has room.
#[tokio::test]
async fn delegates_share_their_parent_counter() {
    let principals = Principals::open(Backend::File);
    let root = &principals.harness.root;
    let second = Signer::new(0x77);
    let a_grant = principals.root_grant(&principals.a, &bound(500, 2));
    let child = |subject: &Signer| {
        bounded_grant(
            &principals.a,
            subject,
            Some(&a_grant),
            0,
            Some(
                bound(100, 2)
                    .extension_body(Some(link(&a_grant)))
                    .expect("body"),
            ),
        )
    };
    let (first_grant, second_grant) = (child(&principals.sub), child(&second));
    let submit = |grant: &SignedGrant, agent: &Signer, operation: &str| {
        chain_submission(
            &[root, &principals.a],
            &[a_grant.clone(), grant.clone()],
            agent,
            &principals.arguments(operation, 50),
        )
    };
    let mut verdicts = Vec::new();
    for (grant, agent, operation) in [
        (&first_grant, &principals.sub, "delegate-1"),
        (&second_grant, &second, "delegate-2"),
        (&first_grant, &principals.sub, "delegate-3"),
    ] {
        let result = principals
            .harness
            .submit(&submit(grant, agent, operation), NOW)
            .await;
        let (decision, code) = verdict(&result);
        verdicts.push((decision, code.map(str::to_owned)));
    }
    assert_eq!(
        verdicts,
        [
            ("entered", None),
            ("entered", None),
            (
                "not-entered",
                Some("gateway.policy.window-exhausted".to_owned())
            ),
        ]
    );
    let (writes, _reads, leases) = principals.harness.provider.counts();
    assert_eq!(
        (writes, leases),
        (2, 4),
        "the exhausted action never leases"
    );
}

/// Drives the pre-generated bounded hostile suite against `backend`; the
/// per-window counts live in the same store as the attempt claims.
async fn bounded_hostile_suite(backend: Backend) {
    let suite: Suite = serde_json::from_str(include_str!(
        "../../../../bindings/fixtures/gateway/bounds-hostile.json"
    ))
    .expect("bounded hostile suite");
    assert_eq!(suite.schema, "auths.gateway-bounds-hostile/1");
    for case in suite.cases {
        let (decision, code, (writes, _reads, leases)) = run(&case.id, backend).await;
        assert_eq!(decision, case.decision, "{}", case.id);
        assert_eq!(code, case.code, "{}", case.id);
        assert_eq!(
            writes, case.provider_entries,
            "{}: provider entries",
            case.id
        );
        assert_eq!(
            leases,
            2 * case.provider_entries,
            "{}: leases only for an entered write and its read-back",
            case.id
        );
    }
}

#[tokio::test]
async fn per_principal_bounds_admit_only_actions_inside_the_signer_bound() {
    bounded_hostile_suite(Backend::File).await;
}

#[tokio::test]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_per_principal_bounds_admit_only_actions_inside_the_signer_bound() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    bounded_hostile_suite(Backend::Postgres).await;
}

/// A root with one delegation edge, three managers named as approvers, and
/// agents holding bounded grants from the root. Installed trust requires
/// `branches` authorized branches and approvals from any two of the three
/// managers, so a bounded agent needs two managers' approvals beside its own
/// signature.
struct RefundQuorum {
    harness: Harness,
    managers: [Signer; 3],
    grant: SignedGrant,
    other: Signer,
    other_grant: SignedGrant,
}

const MANAGER_APPROVALS: u16 = 2;

impl RefundQuorum {
    fn open(ceiling: u64, max_count: u64, branches: u16) -> Self {
        let root = Signer::new(0x11);
        let managers = [Signer::new(0xa1), Signer::new(0xb2), Signer::new(0xc3)];
        let observer = GatewayObserver::from_test_seed(0x33);
        let approvers = managers
            .iter()
            .map(|manager| {
                auths_model::ApproverAnchor::new(
                    manager.principal.clone(),
                    vec![
                        auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)
                            .expect("method"),
                    ],
                    window(NOW - 86_400, NOW + 86_400),
                    StatusPolicy::ExpiryOnly,
                )
                .expect("approver anchor")
            })
            .collect();
        let requirement = auths_model::ApprovalRequirement::new(
            managers
                .iter()
                .map(|manager| manager.principal.clone())
                .collect(),
            MANAGER_APPROVALS,
        )
        .expect("requirement");
        let context = h::context_with_roots(
            &[&root],
            observer.principal(),
            None,
            NOW,
            1,
            auths_model::CompositionRequirement::new(None, branches, branches, 1)
                .expect("composition"),
        )
        .expect("refund trust")
        .with_approvals(approvers, vec![requirement])
        .expect("approvals");
        let harness = Harness::with(
            bounds_recipe(),
            context,
            observer,
            root,
            Signer::new(0x44),
            Backend::File,
        );
        let policy = bound(ceiling, max_count);
        let body = || Some(policy.extension_body(None).expect("body"));
        let grant = bounded_grant(&harness.root, &harness.agent, None, 0, body());
        let other = Signer::new(0x55);
        let other_grant = bounded_grant(&harness.root, &other, None, 0, body());
        Self {
            harness,
            managers,
            grant,
            other,
            other_grant,
        }
    }

    fn canonical(&self, operation: &str, amount: u64) -> CanonicalAction {
        let arguments = self
            .harness
            .arguments(operation, RECORD, &json!({"amount": amount}));
        let bytes = call(&arguments).canonical_bytes().expect("canonical call");
        McpProfile.canonicalize(&bytes).expect("canonical")
    }

    fn proposal(
        &self,
        canonical: &CanonicalAction,
        actor: (&Signer, Option<&SignedGrant>),
    ) -> auths_approval_quorum::QuorumProposal {
        auths_approval_quorum::QuorumProposal::new(
            canonical.clone(),
            &audience(),
            [0; 32],
            NOW - 600,
            Some(3_600),
            MANAGER_APPROVALS,
            &self
                .managers
                .iter()
                .map(|manager| manager.principal.clone())
                .collect::<Vec<_>>(),
            &auths_approval_quorum::QuorumActor::new(actor.0.principal.clone(), actor.1)
                .expect("actor"),
        )
        .expect("proposal")
    }

    fn approvals(
        proposal: &auths_approval_quorum::QuorumProposal,
        approvers: &[&Signer],
    ) -> Vec<auths_model::SignedApproval> {
        approvers
            .iter()
            .map(|approver| {
                let statement = proposal
                    .statement(&approver.principal)
                    .expect("listed manager")
                    .clone();
                let descriptor = approver.descriptor();
                let signature = approver.sign(
                    &auths_codec::approval_signing_preimage(
                        &statement,
                        &descriptor,
                        proposal.canonical().profile(),
                    )
                    .expect("preimage"),
                );
                auths_model::SignedApproval::new(
                    statement,
                    SignatureEnvelope::new(descriptor, signature),
                    vec![approver.evidence()],
                )
                .expect("approval")
            })
            .collect()
    }

    fn finish(canonical: &CanonicalAction, bundle: &ProofBundle) -> Submission {
        let action = encode_canonical_action(canonical).expect("action bytes");
        let commitment = *domain_commitment("auths.canonical-action.v1", &action)
            .expect("commitment")
            .as_bytes();
        Submission {
            proof: encode_bundle(bundle).expect("proof bytes"),
            action,
            commitment,
        }
    }

    /// One exact action signed by `actor` and approved by `approvers`, as
    /// the approval-quorum SDK assembles it. Fewer approvers than the
    /// threshold, which the SDK refuses to assemble, are carried as given.
    fn submission(
        &self,
        operation: &str,
        amount: u64,
        actor: (&Signer, Option<&SignedGrant>),
        approvers: &[&Signer],
    ) -> Submission {
        let canonical = self.canonical(operation, amount);
        let proposal = self.proposal(&canonical, actor);
        let action = auths_approval_quorum::QuorumAction::new(
            sign_action(actor.0, proposal.envelope().clone()),
            actor
                .1
                .map(|grant| vec![(grant.clone(), vec![self.harness.root.evidence()])])
                .unwrap_or_default(),
            vec![actor.0.evidence()],
        )
        .expect("action");
        let approvals = Self::approvals(&proposal, approvers);
        let bundle = if approvers.len() >= usize::from(MANAGER_APPROVALS) {
            proposal.assemble(&action, &approvals).expect("assembled")
        } else {
            let full = Self::approvals(&proposal, &[&self.managers[0], &self.managers[1]]);
            proposal
                .assemble(&action, &full)
                .expect("assembled")
                .with_approvals(approvals)
                .expect("fewer approvals")
        };
        Self::finish(&canonical, &bundle)
    }

    /// One action signed by every actor, each on its own leaf of an
    /// all-of plan, approved by `approvers`.
    fn composed(
        &self,
        operation: &str,
        amount: u64,
        actors: &[(&Signer, &SignedGrant)],
        approvers: &[&Signer],
    ) -> Submission {
        let canonical = self.canonical(operation, amount);
        let references: Vec<ProofRef> = (1..=actors.len())
            .map(|index| ProofRef::new([u8::try_from(index).expect("small"); 32]))
            .collect();
        let plan = AuthorizationPlan::all_of(
            references
                .iter()
                .copied()
                .map(AuthorizationPlan::proof)
                .collect(),
        )
        .expect("plan");
        let mut evidence = vec![self.harness.root.evidence()];
        let mut bindings = Vec::new();
        let mut grants = Vec::new();
        let mut actions = Vec::new();
        for ((signer, grant), reference) in actors.iter().zip(&references) {
            let proposal = self.proposal(&canonical, (signer, Some(grant)));
            let envelope = proposal.envelope();
            let envelope = ActionEnvelope::new(
                envelope.profile().clone(),
                envelope.body_media_type().clone(),
                envelope.canonical_body_digest(),
                envelope.permission().clone(),
                envelope.requested_budget().cloned(),
                envelope.audience().clone(),
                envelope.challenge(),
                envelope.validity(),
                envelope.actor().clone(),
                envelope.terminal_grant(),
                plan_id(&plan).expect("plan ID"),
                envelope.channel_binding().clone(),
                *reference,
                Vec::new(),
                CriticalExtensions::empty(),
            );
            let action = sign_action(signer, envelope);
            bindings.push(
                ControlBinding::new(
                    StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                    vec![signer.evidence().id()],
                )
                .expect("binding"),
            );
            bindings.push(
                ControlBinding::new(
                    StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
                    vec![self.harness.root.evidence().id()],
                )
                .expect("binding"),
            );
            evidence.push(signer.evidence());
            grants.push((*grant).clone());
            actions.push(action);
        }
        evidence.sort_by_key(EvidenceObject::id);
        evidence.dedup();
        bindings.sort_by_key(ControlBinding::statement);
        grants.sort_by_cached_key(|grant| grant_id(grant.statement()).ok());
        let approvals = Self::approvals(&self.proposal(&canonical, (actors[0].0, None)), approvers);
        let bundle = ProofBundle::new(
            BundleHeader::v1(),
            grants,
            actions,
            plan,
            evidence,
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(canonical.body().to_vec()),
        )
        .expect("composed bundle")
        .with_approvals(approvals)
        .expect("approvals");
        Self::finish(&canonical, &bundle)
    }

    fn agent(&self) -> (&Signer, Option<&SignedGrant>) {
        (&self.harness.agent, Some(&self.grant))
    }

    fn manager(&self, index: usize) -> &Signer {
        &self.managers[index]
    }

    /// The refund journey's submissions in order: one inside the bound, one
    /// with a single manager, one above the ceiling, one past the window.
    fn journey(&self) -> Vec<(&'static str, Submission)> {
        vec![
            (
                "refund-1",
                self.submission(
                    "refund-1",
                    400,
                    self.agent(),
                    &[self.manager(0), self.manager(1)],
                ),
            ),
            (
                "refund-2",
                self.submission("refund-2", 100, self.agent(), &[self.manager(0)]),
            ),
            (
                "refund-3",
                self.submission(
                    "refund-3",
                    600,
                    self.agent(),
                    &[self.manager(0), self.manager(1)],
                ),
            ),
            (
                "refund-4",
                self.submission(
                    "refund-4",
                    100,
                    self.agent(),
                    &[self.manager(1), self.manager(2)],
                ),
            ),
        ]
    }
}

fn verdict(result: &GatewaySubmitResult) -> (&'static str, Option<&str>) {
    match result {
        GatewaySubmitResult::Denied { code } => ("denied", Some(code)),
        GatewaySubmitResult::Indeterminate { code } => ("indeterminate", Some(code)),
        GatewaySubmitResult::NotEntered { code } => ("not-entered", Some(code)),
        GatewaySubmitResult::Unknown
        | GatewaySubmitResult::ResponseRecorded { .. }
        | GatewaySubmitResult::Observed { .. }
        | GatewaySubmitResult::ObservedByProvider { .. } => ("entered", None),
    }
}

#[tokio::test]
async fn bounded_agent_needs_two_managers_and_stays_inside_its_bound() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut results = Vec::new();
    for (_, submission) in quorum.journey() {
        results.push(quorum.harness.submit(&submission, NOW).await);
    }
    assert_eq!(
        results.iter().map(verdict).collect::<Vec<_>>(),
        vec![
            ("entered", None),
            ("denied", Some("approval-threshold-not-met")),
            ("not-entered", Some("gateway.policy.above-ceiling")),
            ("not-entered", Some("gateway.policy.window-exhausted")),
        ]
    );
    let (writes, _reads, leases) = quorum.harness.provider.counts();
    assert_eq!(
        (writes, leases),
        (1, 2),
        "refused refunds never lease; the entered one leases for its write and read-back"
    );
}

#[tokio::test]
async fn an_unbounded_actor_is_admitted_without_a_count() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let managers = [quorum.manager(0), quorum.manager(2)];
    for operation in ["root-1", "root-2"] {
        let result = quorum
            .harness
            .submit(
                &quorum.submission(operation, 900, (&quorum.harness.root, None), &managers),
                NOW,
            )
            .await;
        assert_eq!(verdict(&result), ("entered", None), "{operation}");
    }
    let (writes, _reads, leases) = quorum.harness.provider.counts();
    assert_eq!((writes, leases), (2, 4), "no bound, no ceiling, no count");
}

#[tokio::test]
async fn one_bounded_branch_is_admitted_and_counted_against_its_actor() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let first = quorum.submission(
        "bounded-1",
        100,
        quorum.agent(),
        &[quorum.manager(0), quorum.manager(1)],
    );
    let second = quorum.submission(
        "bounded-2",
        100,
        quorum.agent(),
        &[quorum.manager(1), quorum.manager(2)],
    );
    let other = quorum.submission(
        "other-agent",
        100,
        (&quorum.other, Some(&quorum.other_grant)),
        &[quorum.manager(0), quorum.manager(2)],
    );
    assert_eq!(
        verdict(&quorum.harness.submit(&first, NOW).await),
        ("entered", None)
    );
    assert_eq!(
        verdict(&quorum.harness.submit(&second, NOW).await),
        ("not-entered", Some("gateway.policy.window-exhausted")),
        "the agent's one slot is spent whichever managers approve"
    );
    assert_eq!(
        verdict(&quorum.harness.submit(&other, NOW).await),
        ("entered", None),
        "another agent's count is separate"
    );
    let (writes, _reads, leases) = quorum.harness.provider.counts();
    assert_eq!((writes, leases), (2, 4));
}

#[tokio::test]
async fn two_bounded_branches_in_one_composition_are_refused() {
    let quorum = RefundQuorum::open(500, 3, 2);
    let submission = quorum.composed(
        "two-bounded",
        100,
        &[
            (&quorum.harness.agent, &quorum.grant),
            (&quorum.other, &quorum.other_grant),
        ],
        &[quorum.manager(0), quorum.manager(1)],
    );
    let result = quorum.harness.submit(&submission, NOW).await;
    assert_eq!(
        verdict(&result),
        ("not-entered", Some("gateway.policy.multiple-branches"))
    );
    assert_eq!(quorum.harness.provider.counts(), (0, 0, 0));
}

/// Runs the refund journey and exports its audit bundle as the application
/// would: proof, action, and the gateway-signed outcome when one exists.
async fn journey_bundle(quorum: &RefundQuorum) -> Value {
    let mut entries = Vec::new();
    for (operation, submission) in quorum.journey() {
        let _ = quorum.harness.submit(&submission, NOW).await;
        let outcome = match quorum.harness.outcome(operation, NOW + 1).await {
            GatewayObserveResult::Signed {
                observation_b64, ..
            } => Some(observation_b64),
            GatewayObserveResult::PreEntry { .. } | GatewayObserveResult::Refused { .. } => None,
        };
        entries.push(json!({
            "operation_id": operation,
            "proof_b64": Base64UrlUnpadded::encode_string(&submission.proof),
            "action_b64": Base64UrlUnpadded::encode_string(&submission.action),
            "outcome_b64": outcome,
        }));
    }
    let (source, lock) = h::recipe_sources(
        &json!({"amount": {"kind": "integer", "minimum": 0, "maximum": 1_000_000}}),
        &json!({"verified": ["amount"]}),
    )
    .expect("recipe sources");
    json!({
        "schema": crate::AUDIT_BUNDLE_SCHEMA,
        "recipe_b64": Base64UrlUnpadded::encode_string(&source),
        "profile_lock_b64": Base64UrlUnpadded::encode_string(&lock),
        "trusted_context_b64": Base64UrlUnpadded::encode_string(&context_bytes(quorum)),
        "entries": entries,
    })
}

fn context_bytes(quorum: &RefundQuorum) -> Vec<u8> {
    auths_codec::encode_verifier_context(&quorum.harness.context).expect("context bytes")
}

fn pins(quorum: &RefundQuorum) -> crate::AuditPins {
    crate::AuditPins {
        trusted_context_sha256: <sha2::Sha256 as sha2::Digest>::digest(context_bytes(quorum))
            .into(),
        observer: quorum.harness.observer.principal().clone(),
    }
}

fn audit(bundle: &Value, pins: &crate::AuditPins) -> crate::AuditReport {
    crate::audit_bundle(&serde_json::to_vec(bundle).expect("bundle"), pins).expect("audit")
}

fn statuses(report: &crate::AuditReport) -> Vec<(crate::AuditStatus, String)> {
    report
        .entries
        .iter()
        .map(|entry| (entry.status, entry.code.clone()))
        .collect()
}

/// Status, code, and `admitted` of every entry.
fn rows(report: &crate::AuditReport) -> Vec<(crate::AuditStatus, String, bool)> {
    report
        .entries
        .iter()
        .map(|entry| (entry.status, entry.code.clone(), entry.admitted))
        .collect()
}

/// Verified, refused, unverified, and inconsistent counts.
fn counts(report: &crate::AuditReport) -> (usize, usize, usize, usize) {
    (
        report.verified,
        report.refused,
        report.unverified,
        report.inconsistent,
    )
}

/// The audit's result by default and with `--allow-unverified-refusals`.
fn results(report: &crate::AuditReport) -> [Result<(), &'static str>; 2] {
    [UnverifiedEntries::Fail, UnverifiedEntries::AllowRefusals].map(|policy| report.verdict(policy))
}

fn bundle_entries(bundle: &mut Value) -> &mut Vec<Value> {
    bundle["entries"].as_array_mut().expect("entries")
}

/// Leaves every gateway-signed outcome out, as an export without them does.
fn strip_outcomes(bundle: &mut Value) {
    for entry in bundle_entries(bundle) {
        entry.as_object_mut().expect("entry").remove("outcome_b64");
    }
}

fn remove_outcome(bundle: &mut Value, index: usize) {
    bundle_entries(bundle)[index]
        .as_object_mut()
        .expect("entry")
        .remove("outcome_b64");
}

/// Flips the low bit of the middle byte of an entry's proof.
fn flip_proof(bundle: &mut Value, index: usize) {
    let entry = &mut bundle_entries(bundle)[index];
    let mut proof = Base64UrlUnpadded::decode_vec(entry["proof_b64"].as_str().expect("proof"))
        .expect("proof bytes");
    let middle = proof.len() / 2;
    proof[middle] ^= 1;
    entry["proof_b64"] = Value::String(Base64UrlUnpadded::encode_string(&proof));
}

fn duplicate(bundle: &mut Value, index: usize) {
    let copy = bundle_entries(bundle)[index].clone();
    bundle_entries(bundle).push(copy);
}

/// Exchanges the proof, action, and outcome of two entries and keeps each
/// operation ID. A missing outcome moves as `null`, which decodes the same.
fn swap_evidence(bundle: &mut Value, first: usize, second: usize) {
    let entries = bundle_entries(bundle);
    for field in ["proof_b64", "action_b64", "outcome_b64"] {
        let left = entries[first].get(field).cloned().unwrap_or(Value::Null);
        let right = entries[second].get(field).cloned().unwrap_or(Value::Null);
        entries[first][field] = right;
        entries[second][field] = left;
    }
}

#[tokio::test]
async fn offline_audit_reproduces_every_gateway_decision() {
    use crate::AuditStatus::{Refused, Unverified, Verified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let bundle = journey_bundle(&quorum).await;
    let report = audit(&bundle, &pins(&quorum));
    // The two refusals made before the claim carry no outcome, so nothing
    // shows what the gateway did with them; the auditor refuses both proofs.
    assert_eq!(
        rows(&report),
        vec![
            (Verified, "audit.verified".to_owned(), true),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Refused, "gateway.policy.window-exhausted".to_owned(), true),
        ]
    );
    assert_eq!(counts(&report), (1, 1, 2, 0));
    assert_eq!(results(&report), [Err("audit.unverified"), Ok(())]);
    let approvals: BTreeSet<&str> = report.entries[0]
        .approvals
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        quorum.managers[0].principal.as_str(),
        quorum.managers[1].principal.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(approvals, expected);
    let result = report.entries[0]
        .provider_result
        .as_ref()
        .expect("provider result");
    assert_eq!(result.stage, "observed-by-provider");
    assert_eq!(result.http_status, Some(200));
    assert_eq!(
        report.entries[3]
            .provider_result
            .as_ref()
            .and_then(|result| result.refusal.as_deref()),
        Some("gateway.policy.window-exhausted")
    );
    assert_eq!(report.entries[1].provider_result, None);
    assert_eq!(report.inconsistent, 0);
}

/// An exhaustion refusal keeps the gateway's code; when the bundle's own
/// entered entries leave room on its counter, the recount says the bundle
/// does not show it, because a bundle may be incomplete.
#[tokio::test]
async fn offline_audit_reports_an_exhaustion_the_bundle_does_not_show() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    let pins = pins(&quorum);
    let recount = |bundle: &Value| {
        let report = audit(bundle, &pins);
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.operation_id == "refund-4")
            .expect("refund-4")
            .clone();
        (
            entry.status,
            entry.code,
            entry.provider_result.and_then(|result| result.recount),
        )
    };
    assert_eq!(
        recount(&bundle),
        (
            crate::AuditStatus::Refused,
            "gateway.policy.window-exhausted".to_owned(),
            None
        )
    );
    bundle["entries"].as_array_mut().expect("entries").remove(0);
    assert_eq!(
        recount(&bundle),
        (
            crate::AuditStatus::Refused,
            "gateway.policy.window-exhausted".to_owned(),
            Some("not-shown-by-bundle")
        )
    );
}

#[tokio::test]
async fn offline_audit_detects_a_tampered_bundle() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let bundle = journey_bundle(&quorum).await;
    let pins = pins(&quorum);
    let finding = |bundle: &Value, pins: &crate::AuditPins| {
        let report = audit(bundle, pins);
        assert_eq!(
            results(&report),
            [Err("audit.inconsistent"), Err("audit.inconsistent")],
            "a tampered bundle fails under both policies"
        );
        report
            .entries
            .iter()
            .filter(|entry| entry.status == crate::AuditStatus::Inconsistent)
            .map(|entry| entry.code.clone())
            .collect::<Vec<_>>()
    };

    let mut flipped = bundle.clone();
    flip_proof(&mut flipped, 0);
    assert_eq!(
        finding(&flipped, &pins),
        vec!["audit.entered-without-authority"]
    );

    // Each outcome's subject names the other operation.
    let mut misfiled = bundle.clone();
    swap_evidence(&mut misfiled, 0, 3);
    assert_eq!(
        finding(&misfiled, &pins),
        vec!["audit.outcome-invalid", "audit.outcome-invalid"]
    );

    let mut duplicated = bundle.clone();
    duplicate(&mut duplicated, 0);
    assert_eq!(
        finding(&duplicated, &pins),
        vec!["audit.duplicate-operation"]
    );

    let mut swapped = bundle.clone();
    swapped["entries"][0]["action_b64"] = bundle["entries"][3]["action_b64"].clone();
    assert_eq!(
        finding(&swapped, &pins),
        vec!["audit.outcome-commitment-mismatch"]
    );

    let mut replayed = bundle.clone();
    replayed["entries"][0]["outcome_b64"] = bundle["entries"][3]["outcome_b64"].clone();
    assert_eq!(finding(&replayed, &pins), vec!["audit.outcome-invalid"]);

    let mut forged_observer = pins.clone();
    forged_observer.observer = quorum.managers[0].principal.clone();
    assert_eq!(
        finding(&bundle, &forged_observer),
        vec!["audit.outcome-invalid", "audit.outcome-invalid"]
    );

    let mut other_trust = pins.clone();
    other_trust.trusted_context_sha256[0] ^= 1;
    assert_eq!(
        crate::audit_bundle(&serde_json::to_vec(&bundle).expect("bundle"), &other_trust).err(),
        Some("audit.trust-pin-mismatch")
    );
}

/// A bundle exported without outcomes verifies nothing: every entry is
/// unverified, and the audit fails under both policies, because two of the
/// proofs are admitted.
#[tokio::test]
async fn offline_audit_without_outcomes_reports_every_entry_unverified() {
    use crate::AuditStatus::Unverified;
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    strip_outcomes(&mut bundle);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Unverified, "audit.outcome-missing".to_owned(), true),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Unverified, "audit.outcome-missing".to_owned(), true),
        ]
    );
    assert_eq!(counts(&report), (0, 0, 4, 0));
    assert_eq!(
        results(&report),
        [Err("audit.unverified"), Err("audit.unverified")]
    );
}

/// An altered proof in a bundle without outcomes is never reported as a
/// refusal, and the bundle fails under both policies.
#[tokio::test]
async fn offline_audit_without_outcomes_never_passes_an_altered_proof() {
    use crate::AuditStatus::Unverified;
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    strip_outcomes(&mut bundle);
    flip_proof(&mut bundle, 0);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Unverified, "missing-reference".to_owned(), false),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Unverified, "audit.outcome-missing".to_owned(), true),
        ]
    );
    assert_eq!(counts(&report), (0, 0, 4, 0));
    assert_eq!(
        results(&report),
        [Err("audit.unverified"), Err("audit.unverified")]
    );
}

/// A duplicated operation needs no outcome to be found.
#[tokio::test]
async fn offline_audit_without_outcomes_flags_a_duplicated_entry() {
    use crate::AuditStatus::{Inconsistent, Unverified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    strip_outcomes(&mut bundle);
    duplicate(&mut bundle, 0);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report)[4],
        (Inconsistent, "audit.duplicate-operation".to_owned(), false)
    );
    assert!(
        rows(&report)[..4]
            .iter()
            .all(|(status, _, _)| *status == Unverified)
    );
    assert_eq!(counts(&report), (0, 0, 4, 1));
    assert_eq!(
        results(&report),
        [Err("audit.inconsistent"), Err("audit.inconsistent")]
    );
}

/// A valid proof filed under another operation needs no outcome to be found.
#[tokio::test]
async fn offline_audit_without_outcomes_flags_misfiled_proofs() {
    use crate::AuditStatus::{Inconsistent, Unverified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    strip_outcomes(&mut bundle);
    swap_evidence(&mut bundle, 0, 3);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Inconsistent, "audit.operation-mismatch".to_owned(), false),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Inconsistent, "audit.operation-mismatch".to_owned(), false),
        ]
    );
    assert_eq!(counts(&report), (0, 0, 2, 2));
    assert_eq!(
        results(&report),
        [Err("audit.inconsistent"), Err("audit.inconsistent")]
    );
}

/// A valid refund the gateway refused before recording it, here while its
/// connection was disabled, carries no outcome. Offline it cannot be told
/// apart from an entered refund whose outcome was removed, so it fails the
/// audit under both policies.
#[tokio::test]
async fn offline_audit_fails_a_valid_submission_refused_while_disabled() {
    use crate::AuditStatus::{Refused, Unverified, Verified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    quorum.harness.disable_entry();
    // The second agent's count is untouched, so only the connection stops it.
    let submission = quorum.submission(
        "refund-5",
        100,
        (&quorum.other, Some(&quorum.other_grant)),
        &[quorum.manager(0), quorum.manager(1)],
    );
    assert_eq!(
        verdict(&quorum.harness.submit(&submission, NOW).await),
        ("not-entered", Some("gateway.connection.unavailable"))
    );
    assert!(matches!(
        quorum.harness.outcome("refund-5", NOW + 1).await,
        GatewayObserveResult::Refused { .. }
    ));
    bundle_entries(&mut bundle).push(json!({
        "operation_id": "refund-5",
        "proof_b64": Base64UrlUnpadded::encode_string(&submission.proof),
        "action_b64": Base64UrlUnpadded::encode_string(&submission.action),
        "outcome_b64": null,
    }));
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Verified, "audit.verified".to_owned(), true),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Refused, "gateway.policy.window-exhausted".to_owned(), true),
            (Unverified, "audit.outcome-missing".to_owned(), true),
        ]
    );
    assert_eq!(counts(&report), (1, 1, 3, 0));
    assert_eq!(
        results(&report),
        [Err("audit.unverified"), Err("audit.unverified")]
    );
}

/// An entered refund whose outcome was left out of the bundle fails under
/// both policies, and the recount no longer shows the exhaustion it caused.
#[tokio::test]
async fn offline_audit_fails_an_admitted_entry_whose_outcome_was_removed() {
    use crate::AuditStatus::{Refused, Unverified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    remove_outcome(&mut bundle, 0);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Unverified, "audit.outcome-missing".to_owned(), true),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Refused, "gateway.policy.window-exhausted".to_owned(), true),
        ]
    );
    assert_eq!(
        report.entries[3]
            .provider_result
            .as_ref()
            .and_then(|result| result.recount),
        Some("not-shown-by-bundle")
    );
    assert_eq!(counts(&report), (0, 1, 3, 0));
    assert_eq!(
        results(&report),
        [Err("audit.unverified"), Err("audit.unverified")]
    );
}

/// The documented limit of `--allow-unverified-refusals`: once an entered
/// refund's outcome is removed and its proof altered, the audit refuses the
/// proof and the relaxed policy accepts the entry. It is still reported
/// `unverified`, never `refused`, and the default policy fails it.
#[tokio::test]
async fn offline_audit_allowing_unverified_refusals_accepts_an_altered_proof_without_its_outcome() {
    use crate::AuditStatus::{Refused, Unverified};
    let quorum = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&quorum).await;
    remove_outcome(&mut bundle, 0);
    flip_proof(&mut bundle, 0);
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        rows(&report),
        vec![
            (Unverified, "missing-reference".to_owned(), false),
            (Unverified, "approval-threshold-not-met".to_owned(), false),
            (Unverified, "gateway.policy.above-ceiling".to_owned(), false),
            (Refused, "gateway.policy.window-exhausted".to_owned(), true),
        ]
    );
    assert_eq!(counts(&report), (0, 1, 3, 0));
    assert_eq!(results(&report), [Err("audit.unverified"), Ok(())]);
}

#[tokio::test]
async fn offline_audit_report_names_unverified_entries() {
    let quorum = RefundQuorum::open(500, 1, 1);
    let report = audit(&journey_bundle(&quorum).await, &pins(&quorum));
    let value = serde_json::to_value(&report).expect("report JSON");
    assert_eq!(value["schema"], "auths.gateway-audit-report/3");
    assert_eq!(value["unverified"], 2);
    assert_eq!(value["entries"][0]["admitted"], true);
    for index in [1, 2] {
        assert_eq!(value["entries"][index]["status"], "unverified");
        assert_eq!(value["entries"][index]["admitted"], false);
    }
}

/// A namespace served from two stores counts separately: a second gateway
/// with its own store enters the refund the first refused. The audit finds
/// two entered refunds on a counter of capacity one, which no arrival order
/// allows, and flags both without relying on any order.
#[tokio::test]
async fn offline_audit_flags_an_over_admission_without_any_order() {
    use crate::AuditStatus::{Inconsistent, Unverified};
    let first = RefundQuorum::open(500, 1, 1);
    let mut bundle = journey_bundle(&first).await;
    let second = RefundQuorum::open(500, 1, 1);
    let (operation, submission) = second.journey().remove(3);
    assert_eq!(
        verdict(&second.harness.submit(&submission, NOW).await),
        ("entered", None)
    );
    let GatewayObserveResult::Signed {
        observation_b64, ..
    } = second.harness.outcome(operation, NOW + 1).await
    else {
        panic!("the second gateway signs its outcome");
    };
    bundle["entries"][3]["outcome_b64"] = json!(observation_b64);
    let report = audit(&bundle, &pins(&first));
    assert_eq!(
        statuses(&report),
        vec![
            (Inconsistent, "audit.bound-exceeded".to_owned()),
            (Unverified, "approval-threshold-not-met".to_owned()),
            (Unverified, "gateway.policy.above-ceiling".to_owned()),
            (Inconsistent, "audit.bound-exceeded".to_owned()),
        ]
    );
    let mut reordered = bundle.clone();
    let entries = reordered["entries"].as_array_mut().expect("entries");
    entries.reverse();
    let mut reversed = statuses(&audit(&reordered, &pins(&first)));
    reversed.reverse();
    assert_eq!(
        reversed,
        statuses(&report),
        "the verdicts do not depend on order"
    );
}

#[tokio::test]
async fn offline_audit_lists_recorded_approval_responses_without_changing_verdicts() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../bindings/fixtures/approval/remote-approval.json"
    ))
    .expect("approval corpus");
    let response = |name: &str| {
        let bytes = Base64UrlUnpadded::decode_vec(
            corpus["responses"]
                .as_array()
                .expect("responses")
                .iter()
                .find(|item| item["name"] == name)
                .expect("response")["response_b64"]
                .as_str()
                .expect("base64"),
        )
        .expect("bytes");
        auths_approval_quorum::decode_response(&bytes)
            .expect("response")
            .to_text()
            .expect("text")
    };
    let quorum = RefundQuorum::open(500, 1, 1);
    let bundle = journey_bundle(&quorum).await;
    let plain = audit(&bundle, &pins(&quorum));
    let mut recorded = bundle.clone();
    recorded["approval_responses"] = json!([
        {"operation_id": "refund-declined", "response": response("approve-manager-a")},
        {"operation_id": "refund-declined", "response": response("decline-manager-b")},
    ]);
    let report = audit(&recorded, &pins(&quorum));
    assert_eq!(statuses(&report), statuses(&plain));
    let listed: Vec<(&str, &str, Option<u64>)> = report
        .approval_responses
        .iter()
        .map(|item| (item.approver.as_str(), item.decision, item.decided_at))
        .collect();
    let member = |name: &str| {
        corpus["members"]
            .as_array()
            .expect("members")
            .iter()
            .find(|item| item["name"] == name)
            .expect("member")["principal"]
            .as_str()
            .expect("principal")
            .to_owned()
    };
    let (manager_a, manager_b) = (member("manager-a"), member("manager-b"));
    assert_eq!(
        listed,
        vec![
            (manager_a.as_str(), "approve", None),
            (manager_b.as_str(), "decline", corpus["decided_at"].as_u64()),
        ]
    );
    let mut malformed = bundle.clone();
    malformed["approval_responses"] =
        json!([{"operation_id": "refund-declined", "response": "auths-as2-AAAA"}]);
    assert_eq!(
        crate::audit_bundle(
            &serde_json::to_vec(&malformed).expect("bundle"),
            &pins(&quorum)
        )
        .err(),
        Some("audit.bundle-malformed")
    );
}
