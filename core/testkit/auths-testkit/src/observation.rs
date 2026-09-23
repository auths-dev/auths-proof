//! Evidence-conditioned authority corpus vectors.
//!
//! A root grants the actor a scope carrying the `observation-requirement-v1`
//! critical extension. The actor attaches signed observations as detached
//! attachments bound by its action signature. Vectors cover every verdict of
//! the observation stage, each bound at its exact limit and one past it, the
//! parent-requirement rule at chain validation, and the hostile cases.
//!
//! Encodings a valid model cannot represent (one item past a count or byte
//! bound) are derived from canonical encodings by extending the final array
//! or byte string, so every vector still comes from this generator.

use super::*;
use auths_codec::{
    encode_observation_requirement, encode_observation_requirements, encode_observation_statement,
    encode_signed_observation, observation_signing_preimage,
};
use auths_model::{
    ConditionTest, FactBytes, FactName, FactText, FactValue, MemberValues, OBSERVATION_MEDIA_TYPE,
    ObservationCondition, ObservationFact, ObservationFacts, ObservationRequirement,
    ObservationRequirements, ObservationSchemaId, ObservationStatement, ObservationSubject,
    ObserverAnchor, ObserverAnchorId, SignedObservation, UintRange,
};
use auths_registries::OBSERVATION_REQUIREMENT_EXTENSION_V1;

const SCHEMA: &str = "auths.test-outcome/1";
const OTHER_SCHEMA: &str = "auths.test-readback/1";
const ANCHOR: &str = "test-observer";
const SUBJECT: &str = "mcp://reports/read";
const NAMESPACE: &str = "mcp://reports";
const STAGE: &str = "observed-by-provider";
const EVALUATION_TIME: u64 = 50;
const MAX_AGE: u32 = 10;
const FRESH: u64 = 45;

fn root() -> Identity {
    Identity::ed25519(201)
}

fn actor() -> Identity {
    Identity::ed25519(202)
}

fn observer() -> Identity {
    Identity::ed25519(203)
}

fn intermediary() -> Identity {
    Identity::ed25519(204)
}

fn stranger() -> Identity {
    Identity::ed25519(205)
}

fn fact_name(value: &str) -> FactName {
    FactName::parse(value).expect("fixture fact name")
}

fn text(value: &str) -> FactValue {
    FactValue::Text(FactText::new(value).expect("bounded fixture text"))
}

fn stage_condition() -> ObservationCondition {
    ObservationCondition::new(fact_name("stage"), ConditionTest::EqLiteral(text(STAGE)))
}

fn count_condition(hi: u64) -> ObservationCondition {
    ObservationCondition::new(
        fact_name("count"),
        ConditionTest::UintRange(UintRange::new(1, hi).expect("ordered range")),
    )
}

fn requirement(
    schema: &str,
    subject: ObservationSubject,
    max_age: u32,
    conditions: Vec<ObservationCondition>,
) -> ObservationRequirement {
    ObservationRequirement::new(
        ObserverAnchorId::parse(ANCHOR).expect("anchor ID"),
        ObservationSchemaId::parse(schema).expect("schema"),
        subject,
        max_age,
        conditions,
    )
    .expect("bounded requirement")
}

fn subject(value: &str) -> ObservationSubject {
    ObservationSubject::Resource(ResourceId::parse(value).expect("subject"))
}

fn default_requirement() -> ObservationRequirement {
    requirement(
        SCHEMA,
        subject(SUBJECT),
        MAX_AGE,
        vec![stage_condition(), count_condition(5)],
    )
}

fn requirement_bytes(requirements: Vec<ObservationRequirement>) -> Vec<u8> {
    encode_observation_requirements(
        &ObservationRequirements::new(requirements).expect("bounded requirement list"),
    )
    .expect("canonical requirements")
}

fn facts(stage: &str, count: u64) -> Vec<ObservationFact> {
    vec![
        ObservationFact::new(fact_name("stage"), text(stage)),
        ObservationFact::new(fact_name("count"), FactValue::Uint(count)),
    ]
}

fn statement(
    signer: &PrincipalId,
    schema: &str,
    subject: &str,
    observed_at: u64,
    facts: Vec<ObservationFact>,
) -> ObservationStatement {
    ObservationStatement::new(
        signer.clone(),
        ObservationSchemaId::parse(schema).expect("schema"),
        ResourceId::parse(subject).expect("subject"),
        Timestamp::new(observed_at),
        ObservationFacts::new(facts).expect("bounded facts"),
    )
}

fn sign_observation(signer: &Identity, statement: ObservationStatement) -> SignedObservation {
    let descriptor = signer.descriptor();
    let preimage =
        observation_signing_preimage(&statement, &descriptor).expect("observation preimage");
    let signature = signer.sign(&preimage);
    SignedObservation::new(
        statement,
        SignatureEnvelope::new(descriptor, signature),
        vec![signer.evidence()],
    )
    .expect("signed observation")
}

fn observation(observed_at: u64, facts: Vec<ObservationFact>) -> Vec<u8> {
    let observer = observer();
    let statement = statement(&observer.principal, SCHEMA, SUBJECT, observed_at, facts);
    encode_signed_observation(&sign_observation(&observer, statement)).expect("observation")
}

fn with_corrupted_signature(bytes: &[u8]) -> Vec<u8> {
    let decoded = auths_codec::decode_signed_observation(bytes, &VerifierLimits::default())
        .expect("repository-owned observation");
    let mut signature = decoded.signature().signature().as_slice().to_vec();
    signature[0] ^= 1;
    let corrupted = SignedObservation::new(
        decoded.statement().clone(),
        SignatureEnvelope::new(
            decoded.signature().descriptor().clone(),
            SignatureBytes::new(signature).expect("signature length"),
        ),
        decoded.evidence().to_vec(),
    )
    .expect("corrupted observation");
    encode_signed_observation(&corrupted).expect("observation")
}

fn observer_anchor(id: &str, principal: &PrincipalId, not_before: u64) -> ObserverAnchor {
    ObserverAnchor::new(
        ObserverAnchorId::parse(id).expect("anchor ID"),
        principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("method")],
        vec![
            ObservationSchemaId::parse(SCHEMA).expect("schema"),
            ObservationSchemaId::parse(OTHER_SCHEMA).expect("schema"),
        ],
        vec![ResourceId::parse(NAMESPACE).expect("namespace")],
        ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(100)).expect("validity"),
    )
    .expect("observer anchor")
}

/// How the second grant of a three-party chain treats the first grant's
/// observation requirements.
#[derive(Clone)]
enum Child {
    None,
    Without,
    With(Vec<u8>),
}

struct Case {
    name: &'static str,
    class: &'static str,
    expected: Expected,
    extension: Vec<u8>,
    child: Child,
    attachments: Vec<Vec<u8>>,
    anchors: Vec<ObserverAnchor>,
    limits: VerifierLimits,
}

fn case(name: &'static str, class: &'static str, expected: Expected) -> Case {
    Case {
        name,
        class,
        expected,
        extension: requirement_bytes(vec![default_requirement()]),
        child: Child::None,
        attachments: vec![observation(FRESH, facts(STAGE, 3))],
        anchors: vec![observer_anchor(ANCHOR, &observer().principal, 0)],
        limits: VerifierLimits::default(),
    }
}

fn authorized(name: &'static str) -> Case {
    case(name, "valid", Expected::Authorized)
}

fn denied(name: &'static str, reason: DenialReason) -> Case {
    case(name, "denied", Expected::Denied(reason))
}

fn indeterminate(name: &'static str, requirement: Requirement) -> Case {
    case(name, "indeterminate", Expected::Indeterminate(requirement))
}

fn extensions(bytes: Option<Vec<u8>>) -> CriticalExtensions {
    match bytes {
        None => CriticalExtensions::empty(),
        Some(bytes) => CriticalExtensions::new(vec![
            CriticalExtension::new(
                ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1).expect("extension ID"),
                bytes,
            )
            .expect("bounded extension"),
        ])
        .expect("extension set"),
    }
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

/// Signs the grant chain root to actor and returns it with the signers.
fn grant_chain(case: &Case) -> (Vec<SignedGrant>, Vec<Identity>) {
    let (root, actor) = (root(), actor());
    if matches!(case.child, Child::None) {
        let grant = signed_grant(
            &root,
            grant_statement(
                &root,
                &actor,
                0,
                None,
                extensions(Some(case.extension.clone())),
            ),
        );
        return (vec![grant], vec![root]);
    }
    let middle = intermediary();
    let parent = signed_grant(
        &root,
        grant_statement(
            &root,
            &middle,
            1,
            None,
            extensions(Some(case.extension.clone())),
        ),
    );
    let parent_id = grant_id(parent.statement()).expect("parent grant ID");
    let child_extensions = match &case.child {
        Child::With(bytes) => extensions(Some(bytes.clone())),
        Child::None | Child::Without => extensions(None),
    };
    let child = signed_grant(
        &middle,
        grant_statement(&middle, &actor, 0, Some(parent_id), child_extensions),
    );
    (vec![parent, child], vec![root, middle])
}

fn attachment_inputs(case: &Case) -> (Vec<AttachmentDescriptor>, Vec<DetachedAttachment>) {
    let mut descriptors = Vec::new();
    let mut detached = Vec::new();
    for bytes in &case.attachments {
        let digest = attachment_digest(bytes);
        descriptors.push(AttachmentDescriptor::new(
            digest,
            MediaType::parse(OBSERVATION_MEDIA_TYPE).expect("observation media type"),
            u64::try_from(bytes.len()).expect("small attachment"),
            DispositionId::parse("authorization-input").expect("disposition"),
            Confidentiality::Plain,
            Presence::Required,
            Opacity::MustBeInspectable,
        ));
        detached.push(DetachedAttachment::new(digest, bytes.clone()).expect("attachment"));
    }
    descriptors.sort();
    (descriptors, detached)
}

fn build_context(case: Case, identities: &[Identity], depth: u16) -> TrustedContext {
    let base = context(identities, vec![anchor(&identities[0], depth)]);
    let accepted = accepted_from(
        base.accepted_registries(),
        base.accepted_registries().manifest_id(),
        base.accepted_registries().resource_matchers().to_vec(),
        vec![ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1).expect("extension ID")],
        base.accepted_registries().profile_policies().to_vec(),
    );
    context_replacement(
        &base,
        base.trust_anchors().to_vec(),
        accepted,
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    )
    .with_limits(case.limits)
    .expect("fixture limits")
    .with_observer_anchors(case.anchors)
    .expect("observer anchors")
}

fn build(case: Case) -> CorpusFixture {
    let actor = actor();
    let (grants, issuers) = grant_chain(&case);
    let (descriptors, detached) = attachment_inputs(&case);
    let canonical = canonical_action(BODY.to_vec())
        .with_detached_attachments(detached)
        .expect("canonical attachments");
    let proof_ref = ProofRef::new([0x0b; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let terminal = grants
        .last()
        .map(|grant| grant_id(grant.statement()).expect("grant ID"));
    let mut envelope = action_envelope(
        &actor,
        &canonical,
        plan_id(&plan).expect("plan ID"),
        proof_ref,
        terminal,
    );
    envelope = ActionEnvelope::new(
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
        envelope.authorization_plan(),
        envelope.channel_binding().clone(),
        envelope.proof_ref(),
        descriptors.clone(),
        CriticalExtensions::empty(),
    );
    let action = signed_action(&actor, envelope);
    let mut signers = issuers.clone();
    signers.push(actor.clone());
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
    let mut identities = signers.clone();
    identities.push(observer());
    let depth = u16::try_from(grants.len()).expect("short chain");
    let (name, class, expected) = (case.name, case.class, case.expected);
    let verifier_context = build_context(case, &identities, depth);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        vec![action],
        plan,
        addressed_evidence(&signers),
        bindings,
        Vec::new(),
        Vec::new(),
        descriptors,
        Some(BODY.to_vec()),
    )
    .expect("observation bundle");
    fixture(name, class, &bundle, &verifier_context, canonical, expected)
}

/// Appends a seventeenth item to the final array of `full`, which has
/// sixteen. `one` and `two` encode the same object with one and two items in
/// that array; their first difference locates the array header, and the tail
/// of `two` is the appended item.
fn append_seventeenth(one: &[u8], two: &[u8], full: &[u8]) -> Vec<u8> {
    let header = one
        .iter()
        .zip(two)
        .position(|(left, right)| left != right)
        .expect("array header differs");
    assert_eq!(full[header], 0x90, "sixteen-item array header");
    let mut extended = full.to_vec();
    extended[header] = 0x91;
    extended.extend_from_slice(&two[one.len()..]);
    extended
}

fn replace_unique(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let positions: Vec<_> = bytes
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "unique replacement site");
    let mut replaced = bytes[..positions[0]].to_vec();
    replaced.extend_from_slice(to);
    replaced.extend_from_slice(&bytes[positions[0] + from.len()..]);
    replaced
}

/// Re-frames a signed observation around replacement statement bytes. The
/// signature no longer matches, which is irrelevant: decoding rejects the
/// statement before any signature is checked.
fn with_statement_bytes(signed: &[u8], original: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(
        &signed[2..2 + original.len()],
        original,
        "statement framing"
    );
    let mut framed = signed[..2].to_vec();
    framed.extend_from_slice(replacement);
    framed.extend_from_slice(&signed[2 + original.len()..]);
    framed
}

fn padded_facts(pad: &[usize]) -> Vec<ObservationFact> {
    let mut facts = facts(STAGE, 3);
    for (index, length) in pad.iter().enumerate() {
        facts.push(ObservationFact::new(
            fact_name(&format!("pad{index:02}")),
            text(&"p".repeat(*length)),
        ));
    }
    facts
}

/// A valid signed observation of exactly `target` bytes. Padding text
/// stays between 24 and 255 bytes so each step grows the encoding by one.
fn observation_of_size(target: usize) -> Vec<u8> {
    let mut pad = vec![24usize; 14];
    let mut cursor = 0;
    loop {
        let bytes = observation(FRESH, padded_facts(&pad));
        if bytes.len() == target {
            return bytes;
        }
        assert!(bytes.len() < target, "observation padding overshot");
        while pad[cursor] == 255 {
            cursor += 1;
            assert!(cursor < pad.len(), "observation padding capacity");
        }
        pad[cursor] += 1;
    }
}

fn fact_bounds_statement(tail: FactValue) -> ObservationStatement {
    let mut facts = facts(STAGE, 3);
    for index in 0..13 {
        facts.push(ObservationFact::new(
            fact_name(&format!("extra{index:02}")),
            FactValue::Uint(index),
        ));
    }
    facts.push(ObservationFact::new(fact_name("zz-tail"), tail));
    statement(&observer().principal, SCHEMA, SUBJECT, FRESH, facts)
}

fn observation_from_statement(statement: ObservationStatement) -> (Vec<u8>, Vec<u8>) {
    let statement_bytes = encode_observation_statement(&statement).expect("statement");
    let signed =
        encode_signed_observation(&sign_observation(&observer(), statement)).expect("observation");
    (signed, statement_bytes)
}

fn over_limit_facts() -> Vec<u8> {
    let count = ObservationFact::new(fact_name("count"), FactValue::Uint(3));
    let stage = ObservationFact::new(fact_name("stage"), text(STAGE));
    let prefix = |facts| {
        encode_observation_statement(&statement(
            &observer().principal,
            SCHEMA,
            SUBJECT,
            FRESH,
            facts,
        ))
        .expect("statement")
    };
    let one = prefix(vec![count.clone()]);
    let two = prefix(vec![count, stage]);
    let mut full_facts = facts(STAGE, 3);
    for index in 0..14 {
        full_facts.push(ObservationFact::new(
            fact_name(&format!("extra{index:02}")),
            FactValue::Uint(index),
        ));
    }
    let (signed, full) = observation_from_statement(statement(
        &observer().principal,
        SCHEMA,
        SUBJECT,
        FRESH,
        full_facts,
    ));
    let extended = append_seventeenth(&one, &two, &full);
    with_statement_bytes(&signed, &full, &extended)
}

fn over_limit_tail(tail: FactValue, from: &[u8], to: &[u8]) -> Vec<u8> {
    let (signed, statement) = observation_from_statement(fact_bounds_statement(tail));
    assert!(statement.ends_with(from), "tail value is last");
    let mut extended = statement[..statement.len() - from.len()].to_vec();
    extended.extend_from_slice(to);
    with_statement_bytes(&signed, &statement, &extended)
}

fn distinct_requirements(count: u64) -> Vec<ObservationRequirement> {
    (0..count)
        .map(|index| {
            requirement(
                SCHEMA,
                subject(SUBJECT),
                MAX_AGE,
                vec![stage_condition(), count_condition(5 + index)],
            )
        })
        .collect()
}

fn conditions_requirement(count: u64) -> ObservationRequirement {
    let mut conditions = vec![stage_condition()];
    conditions.extend((1..count).map(|index| count_condition(4 + index)));
    requirement(SCHEMA, subject(SUBJECT), MAX_AGE, conditions)
}

fn member_requirement(count: usize) -> ObservationRequirement {
    let mut values = vec![text(STAGE)];
    values.extend((1..count).map(|index| text(&format!("stage-{index:02}"))));
    requirement(
        SCHEMA,
        subject(SUBJECT),
        MAX_AGE,
        vec![ObservationCondition::new(
            fact_name("stage"),
            ConditionTest::Member(MemberValues::new(values).expect("bounded members")),
        )],
    )
}

fn single(requirement: &ObservationRequirement) -> Vec<u8> {
    requirement_bytes(vec![requirement.clone()])
}

fn over_limit_requirements() -> Vec<u8> {
    let mut bytes = requirement_bytes(distinct_requirements(8));
    assert_eq!(bytes[0], 0x88, "eight-requirement header");
    bytes[0] = 0x89;
    bytes
        .extend(encode_observation_requirement(&distinct_requirements(9)[8]).expect("requirement"));
    bytes
}

fn sequenced_observations(count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|sequence| {
            let mut facts = facts(STAGE, 3);
            facts.push(ObservationFact::new(
                fact_name("sequence"),
                FactValue::Uint(sequence),
            ));
            observation(FRESH, facts)
        })
        .collect()
}

fn extra_anchors(count: u8) -> Vec<ObserverAnchor> {
    let mut anchors = vec![observer_anchor(ANCHOR, &observer().principal, 0)];
    for index in 0..count {
        anchors.push(observer_anchor(
            &format!("extra-observer-{index:02}"),
            &Identity::ed25519(210 + index).principal,
            0,
        ));
    }
    anchors
}

/// Thirty-three observer anchors cannot be modelled; the context is derived
/// from the thirty-two-anchor encoding by extending its final array. Corpus
/// contexts must decode, so this bound is proved by a unit test instead of a
/// corpus vector.
#[cfg(test)]
fn over_limit_anchors(mut fixture: CorpusFixture) -> CorpusFixture {
    let context = decode_context(&fixture);
    let encode = |anchors: Vec<ObserverAnchor>| {
        encode_verifier_context(
            &context
                .clone()
                .with_observer_anchors(anchors)
                .expect("bounded anchors"),
        )
        .expect("canonical context")
    };
    let none = encode(Vec::new());
    let extra = observer_anchor("zz-extra-observer", &stranger().principal, 0);
    let one = encode(vec![extra.clone()]);
    assert_eq!(
        none.last(),
        Some(&0x80),
        "observer anchors are the final field"
    );
    let mut extended = none[..none.len() - 1].to_vec();
    extended.extend_from_slice(&[0x98, 0x21]);
    extended.extend_from_slice(&fixture.context_bytes[none.len() + 1..]);
    extended.extend_from_slice(&one[none.len()..]);
    fixture.name = "observer-anchors-over-limit";
    fixture.class = "invalid";
    fixture.context_bytes = extended;
    fixture.expected = Expected::Denied(DenialReason::ResourceLimitExceeded);
    fixture
}

fn verdict_vectors() -> Vec<CorpusFixture> {
    let satisfying = observation(FRESH, facts(STAGE, 3));
    let mut vectors = vec![
        build(authorized("observation-satisfied")),
        build(Case {
            attachments: vec![observation(
                EVALUATION_TIME - u64::from(MAX_AGE),
                facts(STAGE, 3),
            )],
            ..authorized("observation-freshness-boundary")
        }),
        build(Case {
            attachments: vec![observation(EVALUATION_TIME, facts(STAGE, 3))],
            ..authorized("observation-observed-at-evaluation-time")
        }),
        build(Case {
            extension: single(&member_requirement(2)),
            ..authorized("observation-member-condition")
        }),
        build(Case {
            attachments: vec![
                with_corrupted_signature(&observation(FRESH, facts(STAGE, 9))),
                satisfying.clone(),
            ],
            ..authorized("observation-invalid-signature-ignored")
        }),
        build(Case {
            attachments: vec![observation(FRESH, facts(STAGE, 9))],
            ..denied(
                "observation-condition-false",
                DenialReason::ObservationConditionFalse,
            )
        }),
        build(Case {
            attachments: vec![observation(
                FRESH,
                vec![
                    ObservationFact::new(fact_name("stage"), text(STAGE)),
                    ObservationFact::new(fact_name("count"), text("3")),
                ],
            )],
            ..denied(
                "observation-fact-type-mismatch",
                DenialReason::ObservationConditionFalse,
            )
        }),
        build(Case {
            attachments: vec![observation(FRESH, vec![facts(STAGE, 3).remove(0)])],
            ..denied(
                "observation-fact-absent",
                DenialReason::ObservationConditionFalse,
            )
        }),
        build(Case {
            extension: requirement_bytes(vec![
                default_requirement(),
                requirement(
                    OTHER_SCHEMA,
                    subject(SUBJECT),
                    MAX_AGE,
                    vec![stage_condition()],
                ),
            ]),
            attachments: vec![observation(FRESH, facts(STAGE, 9))],
            ..denied(
                "observation-denial-dominates-missing",
                DenialReason::ObservationConditionFalse,
            )
        }),
        build(Case {
            attachments: Vec::new(),
            ..indeterminate("observation-missing", Requirement::ObservationMissing)
        }),
    ];
    vectors.extend(ineligible_vectors());
    vectors
}

fn ineligible_vectors() -> Vec<CorpusFixture> {
    let observer = observer();
    let other = |schema: &str, subject: &str, signer: &Identity| {
        let statement = statement(&signer.principal, schema, subject, FRESH, facts(STAGE, 3));
        encode_signed_observation(&sign_observation(signer, statement)).expect("observation")
    };
    let missing = Requirement::ObservationMissing;
    vec![
        build(Case {
            attachments: vec![observation(
                EVALUATION_TIME - u64::from(MAX_AGE) - 1,
                facts(STAGE, 3),
            )],
            ..indeterminate("observation-stale-by-one-second", missing)
        }),
        build(Case {
            attachments: vec![observation(EVALUATION_TIME + 1, facts(STAGE, 3))],
            ..indeterminate("observation-future-dated", missing)
        }),
        build(Case {
            attachments: vec![other(SCHEMA, "mcp://reports/other", &observer)],
            ..indeterminate("observation-wrong-subject", missing)
        }),
        build(Case {
            extension: single(&requirement(
                SCHEMA,
                subject("mcp://billing/read"),
                MAX_AGE,
                vec![stage_condition()],
            )),
            attachments: vec![other(SCHEMA, "mcp://billing/read", &observer)],
            ..indeterminate("observation-subject-outside-namespace", missing)
        }),
        build(Case {
            attachments: vec![other(OTHER_SCHEMA, SUBJECT, &observer)],
            ..indeterminate("observation-wrong-schema", missing)
        }),
        build(Case {
            attachments: vec![other(SCHEMA, SUBJECT, &stranger())],
            ..indeterminate("observation-untrusted-observer", missing)
        }),
        build(Case {
            attachments: vec![with_corrupted_signature(&observation(
                FRESH,
                facts(STAGE, 3),
            ))],
            ..indeterminate("observation-invalid-signature-only", missing)
        }),
        build(Case {
            anchors: vec![observer_anchor(ANCHOR, &observer.principal, FRESH + 1)],
            ..indeterminate("observation-outside-anchor-validity", missing)
        }),
        build(Case {
            anchors: Vec::new(),
            ..indeterminate("observation-unknown-observer-anchor", missing)
        }),
        build(Case {
            extension: single(&requirement(
                SCHEMA,
                ObservationSubject::ActionFact(fact_name("record_uri")),
                MAX_AGE,
                vec![stage_condition()],
            )),
            ..indeterminate(
                "observation-action-fact-unavailable",
                Requirement::ObservationActionFactUnavailable,
            )
        }),
        build(Case {
            extension: single(&requirement(
                SCHEMA,
                subject(SUBJECT),
                MAX_AGE,
                vec![ObservationCondition::new(
                    fact_name("stage"),
                    ConditionTest::EqAction(fact_name("expected")),
                )],
            )),
            ..indeterminate(
                "observation-action-condition-unavailable",
                Requirement::ObservationActionFactUnavailable,
            )
        }),
    ]
}

fn chain_vectors() -> Vec<CorpusFixture> {
    let actor = actor();
    let self_observed = {
        let statement = statement(&actor.principal, SCHEMA, SUBJECT, FRESH, facts(STAGE, 3));
        encode_signed_observation(&sign_observation(&actor, statement)).expect("observation")
    };
    let parent = default_requirement();
    let altered = requirement(
        SCHEMA,
        subject(SUBJECT),
        MAX_AGE + 1,
        vec![stage_condition(), count_condition(5)],
    );
    vec![
        build(Case {
            anchors: vec![observer_anchor(ANCHOR, &actor.principal, 0)],
            attachments: vec![self_observed],
            ..denied(
                "observer-in-authority-chain",
                DenialReason::ObserverInAuthorityChain,
            )
        }),
        build(Case {
            child: Child::With(single(&parent)),
            ..authorized("observation-requirement-preserved")
        }),
        build(Case {
            child: Child::Without,
            ..denied(
                "observation-requirement-dropped",
                DenialReason::ObservationRequirementDropped,
            )
        }),
        build(Case {
            child: Child::With(single(&altered)),
            ..denied(
                "observation-requirement-altered",
                DenialReason::ObservationRequirementDropped,
            )
        }),
        build(Case {
            child: Child::With(requirement_bytes(vec![
                parent,
                requirement(
                    OTHER_SCHEMA,
                    subject(SUBJECT),
                    MAX_AGE,
                    vec![stage_condition()],
                ),
            ])),
            ..denied(
                "observation-requirement-added",
                DenialReason::DelegationExpanded,
            )
        }),
    ]
}

fn requirement_limit_vectors() -> Vec<CorpusFixture> {
    let limit = Expected::Denied(DenialReason::ResourceLimitExceeded);
    let member = |count| single(&member_requirement(count));
    let conditions = |count| single(&conditions_requirement(count));
    let max_age = single(&requirement(
        SCHEMA,
        subject(SUBJECT),
        auths_model::MAX_OBSERVATION_AGE_SECONDS,
        vec![stage_condition()],
    ));
    vec![
        build(Case {
            extension: requirement_bytes(distinct_requirements(8)),
            ..authorized("observation-requirements-at-limit")
        }),
        build(Case {
            extension: over_limit_requirements(),
            ..case("observation-requirements-over-limit", "invalid", limit)
        }),
        build(Case {
            extension: conditions(16),
            ..authorized("observation-conditions-at-limit")
        }),
        build(Case {
            extension: append_seventeenth(&conditions(1), &conditions(2), &conditions(16)),
            ..case("observation-conditions-over-limit", "invalid", limit)
        }),
        build(Case {
            extension: member(16),
            ..authorized("observation-member-values-at-limit")
        }),
        build(Case {
            extension: append_seventeenth(&member(1), &member(2), &member(16)),
            ..case("observation-member-values-over-limit", "invalid", limit)
        }),
        build(Case {
            extension: max_age.clone(),
            attachments: vec![observation(0, facts(STAGE, 3))],
            ..authorized("observation-max-age-at-limit")
        }),
        build(Case {
            extension: replace_unique(
                &max_age,
                &[0x03, 0x1a, 0x00, 0x01, 0x51, 0x80],
                &[0x03, 0x1a, 0x00, 0x01, 0x51, 0x81],
            ),
            attachments: vec![observation(0, facts(STAGE, 3))],
            ..denied(
                "observation-max-age-over-limit",
                DenialReason::LocalPolicyDenied,
            )
        }),
    ]
}

fn observation_limit_vectors() -> Vec<CorpusFixture> {
    let limit = Expected::Denied(DenialReason::ResourceLimitExceeded);
    let tail_bytes = vec![0x5a; auths_model::MAX_FACT_VALUE_BYTES];
    let tail_text = "t".repeat(auths_model::MAX_FACT_VALUE_TEXT_BYTES);
    let (at_bounds, _) = observation_from_statement(fact_bounds_statement(FactValue::Bytes(
        FactBytes::new(tail_bytes.clone()).expect("bounded bytes"),
    )));
    let (at_text, _) = observation_from_statement(fact_bounds_statement(text(&tail_text)));
    let mut over_bytes_from = vec![0x58, 0x40];
    over_bytes_from.extend(&tail_bytes);
    let mut over_bytes_to = vec![0x58, 0x41];
    over_bytes_to.extend(&tail_bytes);
    over_bytes_to.push(0x5a);
    let mut over_text_from = vec![0x79, 0x01, 0x00];
    over_text_from.extend(tail_text.as_bytes());
    let mut over_text_to = vec![0x79, 0x01, 0x01];
    over_text_to.extend(tail_text.as_bytes());
    over_text_to.push(b't');
    let over_bytes = over_limit_tail(
        FactValue::Bytes(FactBytes::new(tail_bytes).expect("bounded bytes")),
        &over_bytes_from,
        &over_bytes_to,
    );
    let over_text = over_limit_tail(text(&tail_text), &over_text_from, &over_text_to);
    let wide_attachments = VerifierLimits::default()
        .with_limit(LimitKind::Attachments, 64)
        .expect("attachment limit");
    let at_anchor_limit = build(Case {
        anchors: extra_anchors(31),
        ..authorized("observer-anchors-at-limit")
    });
    vec![
        build(Case {
            attachments: vec![at_bounds],
            ..authorized("observation-fact-bytes-at-limit")
        }),
        build(Case {
            attachments: vec![over_bytes],
            ..case("observation-fact-bytes-over-limit", "invalid", limit)
        }),
        build(Case {
            attachments: vec![at_text],
            ..authorized("observation-fact-text-at-limit")
        }),
        build(Case {
            attachments: vec![over_text],
            ..case("observation-fact-text-over-limit", "invalid", limit)
        }),
        build(Case {
            attachments: vec![over_limit_facts()],
            ..case("observation-facts-over-limit", "invalid", limit)
        }),
        build(Case {
            attachments: vec![observation_of_size(auths_model::MAX_OBSERVATION_BYTES)],
            ..authorized("observation-bytes-at-limit")
        }),
        build(Case {
            attachments: vec![observation_of_size(auths_model::MAX_OBSERVATION_BYTES + 1)],
            ..case("observation-bytes-over-limit", "invalid", limit)
        }),
        build(Case {
            attachments: sequenced_observations(32),
            ..authorized("observation-attachments-at-limit")
        }),
        build(Case {
            attachments: sequenced_observations(33),
            limits: wide_attachments,
            ..case("observation-attachments-over-limit", "invalid", limit)
        }),
        at_anchor_limit,
    ]
}

/// Evidence-conditioned authority vectors, in corpus order.
pub(crate) fn observation_corpus() -> Vec<CorpusFixture> {
    let mut vectors = verdict_vectors();
    vectors.extend(chain_vectors());
    vectors.extend(requirement_limit_vectors());
    vectors.extend(observation_limit_vectors());
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_anchor_limit_is_exact() {
        let at_limit = build(Case {
            anchors: extra_anchors(31),
            ..authorized("observer-anchors-at-limit")
        });
        assert!(auths_codec::decode_verifier_context(at_limit.context_bytes()).is_ok());
        let over = over_limit_anchors(at_limit);
        assert_eq!(
            auths_codec::decode_verifier_context(over.context_bytes()),
            Err(auths_codec::CodecError::LimitExceeded)
        );
    }
}
