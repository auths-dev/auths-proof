//! Per-principal bounded-policy cases of the hostile suite.
//!
//! Two agents share one contract under one root, each with its own bound, and
//! an agent may delegate a narrower bound to a sub-agent. Every case runs the
//! engine's dispatch against the counting provider: an authorized case enters
//! the provider once, and every refused case leaves zero provider entries and
//! zero credential leases.

use super::*;
use crate::ArgumentCeilingPolicy;
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
        auths_model::PolicyIdentifier::parse(crate::ARGUMENT_CEILING_POLICY_TYPE_V1, 128)
            .expect("type"),
        1,
        auths_model::PolicyIdentifier::parse(crate::ARGUMENT_CEILING_CANONICALIZATION_V1, 64)
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
            leases, case.provider_entries,
            "{}: a lease is taken only for an entered write",
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

/// A root with one delegation edge, three managers anchored directly, and
/// agents holding bounded grants from the root. Installed trust requires
/// three authorized approvals from three distinct actors and `roots`
/// distinct roots, so a bounded agent needs two managers beside it.
struct RefundQuorum {
    harness: Harness,
    managers: [Signer; 3],
    grant: SignedGrant,
    other: Signer,
    other_grant: SignedGrant,
}

impl RefundQuorum {
    fn open(ceiling: u64, max_count: u64, roots: u16) -> Self {
        let root = Signer::new(0x11);
        let managers = [Signer::new(0xa1), Signer::new(0xb2), Signer::new(0xc3)];
        let observer = GatewayObserver::from_test_seed(0x33);
        let anchors: Vec<&Signer> = vec![&root, &managers[0], &managers[1], &managers[2]];
        let context = h::context_with_roots(
            &anchors,
            observer.principal(),
            None,
            NOW,
            1,
            auths_model::CompositionRequirement::new(None, 3, 3, roots).expect("composition"),
        )
        .expect("refund trust");
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

    /// One exact action signed by every listed approver under the core
    /// threshold plan the approval-quorum SDK builds.
    fn submission(
        &self,
        operation: &str,
        amount: u64,
        signers: &[(&Signer, Option<&SignedGrant>)],
    ) -> Submission {
        let arguments = self
            .harness
            .arguments(operation, RECORD, &json!({"amount": amount}));
        let bytes = call(&arguments).canonical_bytes().expect("canonical call");
        let canonical: CanonicalAction = McpProfile.canonicalize(&bytes).expect("canonical");
        let approvers: Vec<_> = signers
            .iter()
            .map(|(signer, grant)| {
                auths_approval_quorum::QuorumApprover::new(signer.principal.clone(), *grant)
                    .expect("approver")
            })
            .collect();
        let proposal = auths_approval_quorum::QuorumProposal::new(
            canonical.clone(),
            &audience(),
            [0; 32],
            NOW - 600,
            Some(3_600),
            u16::try_from(signers.len()).expect("count"),
            &approvers,
        )
        .expect("proposal");
        let approvals: Vec<_> = signers
            .iter()
            .zip(proposal.envelopes())
            .map(|((signer, grant), envelope)| {
                auths_approval_quorum::QuorumApproval::new(
                    sign_action(signer, envelope.clone()),
                    grant
                        .map(|grant| vec![(grant.clone(), vec![self.harness.root.evidence()])])
                        .unwrap_or_default(),
                    vec![signer.evidence()],
                )
                .expect("approval")
            })
            .collect();
        let bundle = proposal.assemble(&approvals).expect("assembled");
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

    fn agent(&self) -> (&Signer, Option<&SignedGrant>) {
        (&self.harness.agent, Some(&self.grant))
    }

    fn manager(&self, index: usize) -> (&Signer, Option<&SignedGrant>) {
        (&self.managers[index], None)
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
                    &[self.agent(), self.manager(0), self.manager(1)],
                ),
            ),
            (
                "refund-2",
                self.submission("refund-2", 100, &[self.agent(), self.manager(0)]),
            ),
            (
                "refund-3",
                self.submission(
                    "refund-3",
                    600,
                    &[self.agent(), self.manager(0), self.manager(1)],
                ),
            ),
            (
                "refund-4",
                self.submission(
                    "refund-4",
                    100,
                    &[self.agent(), self.manager(1), self.manager(2)],
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
    let quorum = RefundQuorum::open(500, 1, 3);
    let mut results = Vec::new();
    for (_, submission) in quorum.journey() {
        results.push(quorum.harness.submit(&submission, NOW).await);
    }
    assert_eq!(
        results.iter().map(verdict).collect::<Vec<_>>(),
        vec![
            ("entered", None),
            ("denied", Some("composition-requirement-not-met")),
            ("not-entered", Some("gateway.policy.above-ceiling")),
            ("not-entered", Some("gateway.policy.window-exhausted")),
        ]
    );
    let (writes, _reads, leases) = quorum.harness.provider.counts();
    assert_eq!((writes, leases), (1, 1), "refused refunds never lease");
}

#[tokio::test]
async fn unbounded_composition_is_admitted_without_a_count() {
    let quorum = RefundQuorum::open(500, 1, 3);
    let managers = [quorum.manager(0), quorum.manager(1), quorum.manager(2)];
    for operation in ["managers-1", "managers-2"] {
        let result = quorum
            .harness
            .submit(&quorum.submission(operation, 900, &managers), NOW)
            .await;
        assert_eq!(verdict(&result), ("entered", None), "{operation}");
    }
    let (writes, _reads, leases) = quorum.harness.provider.counts();
    assert_eq!((writes, leases), (2, 2), "no bound, no ceiling, no count");
}

#[tokio::test]
async fn one_bounded_branch_is_admitted_and_counted_against_its_actor() {
    let quorum = RefundQuorum::open(500, 1, 3);
    let first = quorum.submission(
        "bounded-1",
        100,
        &[quorum.agent(), quorum.manager(0), quorum.manager(1)],
    );
    let second = quorum.submission(
        "bounded-2",
        100,
        &[quorum.agent(), quorum.manager(1), quorum.manager(2)],
    );
    let other = quorum.submission(
        "other-agent",
        100,
        &[
            (&quorum.other, Some(&quorum.other_grant)),
            quorum.manager(0),
            quorum.manager(2),
        ],
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
    assert_eq!((writes, leases), (2, 2));
}

#[tokio::test]
async fn two_bounded_branches_in_one_composition_are_refused() {
    let quorum = RefundQuorum::open(500, 3, 2);
    let submission = quorum.submission(
        "two-bounded",
        100,
        &[
            quorum.agent(),
            (&quorum.other, Some(&quorum.other_grant)),
            quorum.manager(0),
        ],
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
            GatewayObserveResult::Refused { .. } => None,
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

#[tokio::test]
async fn offline_audit_reproduces_every_gateway_decision() {
    use crate::AuditStatus::{Refused, Verified};
    let quorum = RefundQuorum::open(500, 1, 3);
    let bundle = journey_bundle(&quorum).await;
    let report = audit(&bundle, &pins(&quorum));
    assert_eq!(
        statuses(&report),
        vec![
            (Verified, "audit.verified".to_owned()),
            (Refused, "composition-requirement-not-met".to_owned()),
            (Refused, "gateway.policy.above-ceiling".to_owned()),
            (Refused, "gateway.policy.window-exhausted".to_owned()),
        ]
    );
    let approvals: BTreeSet<&str> = report.entries[0]
        .approvals
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        quorum.harness.agent.principal.as_str(),
        quorum.managers[0].principal.as_str(),
        quorum.managers[1].principal.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(approvals, expected);
    assert_eq!(
        report.entries[0].gateway_stage.as_deref(),
        Some("observed-by-provider")
    );
    assert_eq!(report.inconsistent, 0);
}

#[tokio::test]
async fn offline_audit_detects_a_tampered_bundle() {
    let quorum = RefundQuorum::open(500, 1, 3);
    let bundle = journey_bundle(&quorum).await;
    let pins = pins(&quorum);
    let finding = |bundle: &Value, pins: &crate::AuditPins| {
        let report = audit(bundle, pins);
        report
            .entries
            .iter()
            .filter(|entry| entry.status == crate::AuditStatus::Inconsistent)
            .map(|entry| entry.code.clone())
            .collect::<Vec<_>>()
    };

    let mut flipped = bundle.clone();
    let mut proof =
        Base64UrlUnpadded::decode_vec(flipped["entries"][0]["proof_b64"].as_str().expect("proof"))
            .expect("proof bytes");
    let middle = proof.len() / 2;
    proof[middle] ^= 1;
    flipped["entries"][0]["proof_b64"] = Value::String(Base64UrlUnpadded::encode_string(&proof));
    assert_eq!(
        finding(&flipped, &pins),
        vec!["audit.entered-without-authority"]
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
