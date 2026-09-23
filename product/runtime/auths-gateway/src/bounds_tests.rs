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
    fn open() -> Self {
        let root = Signer::new(0x11);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = context_with_depth(&root, observer.principal(), None, 2);
        Self {
            harness: Harness::with(bounds_recipe(), context, observer, root, Signer::new(0x22)),
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
async fn run(id: &str) -> (String, Option<String>, (usize, usize, usize)) {
    let principals = Principals::open();
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

#[tokio::test]
async fn per_principal_bounds_admit_only_actions_inside_the_signer_bound() {
    let suite: Suite = serde_json::from_str(include_str!(
        "../../../../bindings/fixtures/gateway/bounds-hostile.json"
    ))
    .expect("bounded hostile suite");
    assert_eq!(suite.schema, "auths.gateway-bounds-hostile/1");
    for case in suite.cases {
        let (decision, code, (writes, _reads, leases)) = run(&case.id).await;
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
