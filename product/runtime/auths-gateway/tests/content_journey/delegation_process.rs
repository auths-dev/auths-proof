//! Installed Python/npm participants, fresh process-held keys, native daemon,
//! shared file authority/journal, independent scripted reviewer and HTTP double.
use super::*;
use auths_gateway::participant_enrollment::*;
use auths_model::*;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[path = "delegation_process/actor.rs"]
mod actor;
#[path = "delegation_process/author.rs"]
mod author;
use actor::{Actor, Language};
use author::{Grant, Invocation, PublicIdentity, author, call, context, control_audience, grant};

fn control_evidence(
    parent: [u8; 32],
    authorization: &Invocation,
    acceptance: &Invocation,
    resources: &[Invocation],
    pins: &ParentEnrollmentPins,
) -> auths_gateway::EngagementControlEvidence {
    let resources: Vec<_> = pins
        .scopes
        .iter()
        .zip(resources)
        .map(|(scope, proof)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: proof.borrowed(),
        })
        .collect();
    auths_gateway::EngagementControlEvidence::enroll(
        parent,
        &ParticipantEnrollmentProofs {
            parent: authorization.borrowed(),
            child: acceptance.borrowed(),
            resources: &resources,
        },
    )
    .expect("native owned enrollment")
}
fn resource_proofs(
    signer: &mut Actor,
    grants: &[&Grant],
    calls: &[McpToolCall],
    audience: &Audience,
    trust: &TrustedContext,
    now: u64,
) -> Vec<Invocation> {
    calls
        .iter()
        .map(|call| author(signer, grants, call, audience.clone(), trust, now))
        .collect()
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit native child enrollment inputs"
)]
fn descriptor(
    pins: &ParentEnrollmentPins,
    parent: [u8; 32],
    actor: &Actor,
    name: &str,
    control: &Grant,
    resource: &Grant,
    depth: u16,
) -> ParticipantEnrollment {
    ParticipantEnrollment {
        schema: PARTICIPANT_ENROLLMENT_SCHEMA.into(),
        engagement_commitment: pins.engagement_commitment,
        partition_generation: pins.partition_generation,
        parent_enrollment: parent,
        parent_instance_generation: 1,
        enrollment_id: format!("agent-{name}"),
        child_principal: actor.public.principal.as_str().into(),
        child_instance_generation: 1,
        delivery_channel: name.into(),
        control_grant: *control.id().as_bytes(),
        scopes: pins
            .scopes
            .iter()
            .map(|scope| ParticipantScopeGrant {
                scope_id: scope.scope_id.clone(),
                grant_id: *resource.id().as_bytes(),
            })
            .collect(),
        not_before: pins.not_before,
        expires_at: pins.expires_at,
        remaining_depth: depth,
        ceilings: pins.ceilings,
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "separate native parent, child and resource evidence"
)]
fn enrollment(
    signer: &mut Actor,
    child: &mut Actor,
    parent: [u8; 32],
    descriptor: &ParticipantEnrollment,
    parent_grants: &[&Grant],
    child_grants: &[&Grant],
    resources: &[Invocation],
    pins: &ParentEnrollmentPins,
    trust: &TrustedContext,
    now: u64,
) -> auths_gateway::EngagementControlEvidence {
    let authorization = author(
        signer,
        parent_grants,
        &call(
            PARTICIPANT_SERVICE,
            ENROLL_PARTICIPANT_TOOL,
            json!({"enrollment":descriptor}),
        ),
        control_audience(),
        trust,
        now,
    );
    let acceptance = author(
        child,
        child_grants,
        &call(
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment":descriptor.commitment().expect("commitment")}),
        ),
        control_audience(),
        trust,
        now,
    );
    control_evidence(parent, &authorization, &acceptance, resources, pins)
}
#[allow(
    clippy::too_many_arguments,
    reason = "exact native review and independent external signer"
)]
fn approve_native(
    state: &Path,
    proof: Invocation,
    name: &str,
    reviewer: &mut Actor,
    now: u64,
    extra: &[(&str, &str)],
    flags: &[&str],
) -> Approved {
    let directory = state.parent().expect("private operator parent");
    let file = |extension: &str| directory.join(format!("{name}.{extension}"));
    let proof_path = file("proof");
    let action_path = file("action");
    let binding = file("binding");
    let request = file("request");
    let approval = file("approval");
    private(&proof_path, &proof.proof);
    private(&action_path, &proof.action);
    let from = (now - 1).to_string();
    let until = (now + 250).to_string();
    let mut args = vec![
        ("--state-dir", path(state)),
        ("--proof", path(&proof_path)),
        ("--action", path(&action_path)),
        ("--not-before", &from),
        ("--expires-at", &until),
        ("--request-out", path(&request)),
        ("--binding-out", path(&binding)),
    ];
    args.extend_from_slice(extra);
    let review: Value = serde_json::from_slice(&success(cli("effect-review", &args, flags, None)))
        .expect("native review");
    assert!(
        !review["literal_review"]
            .as_str()
            .expect("complete native literal review")
            .is_empty()
    );
    let request =
        EffectApprovalRequest::from_private_bytes(&std::fs::read(request).expect("native request"))
            .expect("request");
    let message = request.signing_message().expect("native signing message");
    assert_eq!(review["signing_message_hex"], hex::encode(message));
    let signature = reviewer.sign(&message);
    private(
        &approval,
        &request
            .with_signature(signature.as_slice().try_into().expect("Ed25519 signature"))
            .to_private_bytes()
            .expect("native approval"),
    );
    Approved {
        proof: proof_path,
        action: action_path,
        binding,
        approval,
    }
}
fn submission(actor: &mut Actor, socket: &Path, approved: &Approved, operation: &str) -> Value {
    actor.call(json!({"operation":operation,"socket":path(socket),
        "proof":Base64UrlUnpadded::encode_string(&std::fs::read(&approved.proof).expect("proof")),
        "action":Base64UrlUnpadded::encode_string(&std::fs::read(&approved.action).expect("action")),
        "approval":Base64UrlUnpadded::encode_string(&std::fs::read(&approved.approval).expect("approval"))}))
}
fn forbidden(bytes: &[u8], secret: &[u8]) {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(secret);
    for value in [
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        Base64UrlUnpadded::encode_string(secret).into_bytes(),
        base64ct::Base64::encode_string(secret).into_bytes(),
        digest.to_vec(),
        hex::encode(digest).into_bytes(),
    ] {
        assert!(
            !bytes.windows(value.len()).any(|part| part == value),
            "private value/raw digest reached public evidence"
        );
    }
}

#[test]
#[ignore = "requires installed wheel/npm consumer; source-free CI explicitly runs this constructor"]
#[allow(
    clippy::too_many_lines,
    reason = "complete native installed multi-agent read/disclose/write, refusal, restart and revocation journey"
)]
fn native_installed_delegation_process_fixture_is_current() {
    let consumer = std::env::var_os("AUTHS_DELEGATION_CONSUMER_DIR")
        .map(PathBuf::from)
        .expect("installed consumer directory required");
    let distinct = std::env::var_os("AUTHS_DELEGATION_DISTINCT_UIDS").is_some();
    let uid = |index: u32| distinct.then_some(65201 + index);
    let mut owner = Actor::start(Language::Python, &consumer, uid(0));
    let mut machine = Actor::start(Language::Python, &consumer, uid(1));
    let mut a = Actor::start(Language::Node, &consumer, uid(2));
    let mut b = Actor::start(Language::Python, &consumer, uid(3));
    let mut reviewer = Actor::start(Language::Node, &consumer, uid(4));
    let keys = [
        owner.public.key,
        machine.public.key,
        a.public.key,
        b.public.key,
        reviewer.public.key,
    ];
    let unique: std::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), 5);
    let directory = tempfile::Builder::new()
        .prefix("ap073-process-")
        .tempdir_in("/tmp")
        .expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .expect("traversable app socket parent");
    let operator = root.join("operator");
    std::fs::create_dir(&operator).expect("operator");
    std::fs::set_permissions(&operator, std::fs::Permissions::from_mode(0o700))
        .expect("private operator");
    let state = operator.join("state");
    let socket = root.join("app.sock");
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .expect("recipe corpus");
    let mut source = corpus["bases"]["airtable"]["recipe"].clone();
    source["content"] = json!({"schema":"auths.gateway-content-read/1","resource_field":"record_id",
        "path":[{"kind":"fixed","value":"documents"},{"kind":"field","name":"record_id"}],
        "query":[{"name":"format","value":"text/plain"}],"projection":{"kind":"utf8"},"maximum_response_bytes":1024,"maximum_content_bytes":64});
    let source = serde_json::to_vec(&source).expect("source");
    let lock = serde_json::to_vec(&corpus["bases"]["airtable"]["lock"]).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("recipe");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut engagement = [0; 32];
    getrandom::fill(&mut engagement).expect("fresh engagement");
    let audience =
        resource_audience(&engagement, 1, &recipe.digest_hex()).expect("native scoped audience");
    let control_tools = [
        ACTIVATE_ROOT_TOOL,
        ENROLL_PARTICIPANT_TOOL,
        ACCEPT_PARTICIPANT_TOOL,
        REVOKE_PARTICIPANT_TOOL,
    ];
    let mut calls: Vec<_> = control_tools
        .iter()
        .map(|tool| call(PARTICIPANT_SERVICE, tool, json!({})))
        .collect();
    let recipe_review = recipe.review();
    let tools = [
        CONTENT_READ_TOOL,
        DISCLOSURE_TOOL,
        recipe_review.tool(),
        "auths_gateway_recovery_read_v1",
    ];
    calls.extend(
        tools
            .iter()
            .map(|tool| call(recipe.review().service(), tool, json!({}))),
    );
    let trust = context(&owner.public, &calls, audience.clone(), now);
    assert_eq!(
        trust.trust_anchors()[0].principal(),
        &owner.public.principal
    );
    let machine_public = machine.public.clone();
    let a_public = a.public.clone();
    let b_public = b.public.clone();
    let machine_control = grant(
        &mut owner,
        &machine_public,
        PARTICIPANT_SERVICE,
        &control_tools,
        None,
        2,
        control_audience(),
        now,
    );
    let a_control = grant(
        &mut machine,
        &a_public,
        PARTICIPANT_SERVICE,
        &control_tools,
        Some(machine_control.id()),
        1,
        control_audience(),
        now,
    );
    let b_control = grant(
        &mut a,
        &b_public,
        PARTICIPANT_SERVICE,
        &control_tools,
        Some(a_control.id()),
        0,
        control_audience(),
        now,
    );
    let machine_resource = grant(
        &mut owner,
        &machine_public,
        recipe.review().service(),
        &tools,
        None,
        2,
        audience.clone(),
        now,
    );
    let a_resource = grant(
        &mut machine,
        &a_public,
        recipe.review().service(),
        &tools,
        Some(machine_resource.id()),
        1,
        audience.clone(),
        now,
    );
    let b_resource = grant(
        &mut a,
        &b_public,
        recipe.review().service(),
        &tools,
        Some(a_resource.id()),
        0,
        audience.clone(),
        now,
    );
    let machine_resources = [&machine_resource];
    let a_resources = [&machine_resource, &a_resource];
    let b_resources = [&machine_resource, &a_resource, &b_resource];
    let machine_controls = [&machine_control];
    let a_controls = [&machine_control, &a_control];
    let b_controls = [&machine_control, &a_control, &b_control];
    let initial =
        EffectPolicy::new("ap073-installed".into(), 1, reviewer.public.key).expect("policy");
    for (name, bytes) in [
        ("recipe", source),
        ("lock", lock),
        (
            "trust",
            auths_codec::encode_verifier_context(&trust).expect("trust"),
        ),
        (
            "policy",
            initial.to_private_bytes().expect("policy").to_vec(),
        ),
    ] {
        private(&operator.join(name), &bytes);
    }
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy).expect("credential entropy");
    let secret = Zeroizing::new(format!("pat_ap073_{}", hex::encode(entropy)).into_bytes());
    getrandom::fill(&mut entropy).expect("content entropy");
    let content =
        Zeroizing::new(format!("PRIVATE_AP073_{}", hex::encode(&entropy[..16])).into_bytes());
    let provider = Provider::with_content(secret.to_vec(), true, content.to_vec());
    success(cli(
        "install",
        &[
            ("--state-dir", path(&state)),
            ("--recipe", path(&operator.join("recipe"))),
            ("--profile-lock", path(&operator.join("lock"))),
            ("--trusted-context", path(&operator.join("trust"))),
            ("--effect-policy", path(&operator.join("policy"))),
            ("--approve-digest", &recipe.digest_hex()),
            ("--provider", "airtable"),
            ("--alias", "delegation"),
            ("--account-label", "ap073-simulation"),
        ],
        &["--credential-stdin"],
        Some(&secret),
    ));
    let gateway_uid = rustix::process::geteuid().as_raw();
    let channel = UnixDisclosurePolicy::new(gateway_uid, a.uid, [0x73; 32]);
    let mut pins = ParentEnrollmentPins {
        admission_namespace: "ap073-engagement".into(),
        admission_partition: "installed".into(),
        active: true,
        engagement_commitment: engagement,
        partition_generation: 1,
        enrollment_commitment: [1; 32],
        principal: machine.public.principal.clone(),
        instance_generation: 1,
        control_grant: machine_control.id(),
        not_before: now - 10,
        expires_at: now + 600,
        remaining_depth: 2,
        ceilings: ParticipantCeilings {
            provider_reads: 4,
            disclosures: 1,
            disclosure_bytes: 512,
            writes: 1,
        },
        permitted_channels: BTreeMap::from([
            (
                "a".into(),
                EnrollmentChannelPins {
                    channel_binding: channel.commitment().expect("channel"),
                    principal: a.public.principal.clone(),
                    instance_generation: 1,
                },
            ),
            (
                "b".into(),
                EnrollmentChannelPins {
                    channel_binding: [0x74; 32],
                    principal: b.public.principal.clone(),
                    instance_generation: 1,
                },
            ),
        ]),
        scopes: tools
            .iter()
            .enumerate()
            .map(|(index, tool)| EnrollmentScopePins {
                connection_binding: [0; 32],
                scope_id: format!("scope-{index}"),
                recipe_digest: recipe.digest_hex(),
                parent_grant: machine_resource.id(),
                service: recipe.review().service().into(),
                tool: (*tool).into(),
                resource_argument: "record_id".into(),
                resource: EnrollmentResourceBinding::Exact {
                    handle: RECORD.into(),
                },
            })
            .collect(),
    };
    let pins_file = operator.join("root.pins");
    private(&pins_file, &serde_json::to_vec(&pins).expect("pins"));
    let prepared = success(cli(
        "engagement-root",
        &[("--state-dir", path(&state)), ("--pins", path(&pins_file))],
        &[],
        None,
    ));
    pins = serde_json::from_slice(&prepared).expect("native pins");
    private(&pins_file, &prepared);
    let scoped = initial
        .with_engagement(
            auths_gateway::effect::EngagementPolicy::new(pins.clone(), "gateway".into())
                .expect("engagement"),
        )
        .expect("policy");
    let policy_file = operator.join("scoped.policy");
    private(&policy_file, &scoped.to_private_bytes().expect("policy"));
    let review: Value = serde_json::from_slice(&success(cli(
        "effect-configuration-review",
        &[
            ("--state-dir", path(&state)),
            ("--effect-policy", path(&policy_file)),
        ],
        &[],
        None,
    )))
    .expect("review");
    success(cli(
        "effect-configuration-activate",
        &[
            ("--state-dir", path(&state)),
            ("--effect-policy", path(&policy_file)),
            (
                "--expected-revision",
                review["previous_revision_hex"].as_str().expect("revision"),
            ),
            (
                "--expected-candidate",
                review["candidate_hex"].as_str().expect("candidate"),
            ),
        ],
        &[],
        None,
    ));
    let resource = operator.join("resource.json");
    private(
        &resource,
        &serde_json::to_vec(&json!({"record_id":RECORD})).expect("resource"),
    );
    let read_call = operator.join("read.call");
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&resource)),
            ("--operation", "delegated-read"),
            ("--call-out", path(&read_call)),
        ],
        &[],
        None,
    ));
    let mutation = |operation: &str| {
        call(
            recipe.review().service(),
            recipe.review().tool(),
            json!({"operation_id":operation,
        "operator_namespace":recipe.namespace().as_str(),"recipe_digest":recipe.digest_hex(),"record_id":RECORD,"replacement":"Approved"}),
        )
    };
    let witnesses: Vec<_> = tools
        .iter()
        .map(|tool| {
            if *tool == CONTENT_READ_TOOL {
                call_file(&read_call)
            } else if *tool == recipe.review().tool() {
                mutation("enrollment-witness")
            } else {
                call(recipe.review().service(), tool, json!({"record_id":RECORD}))
            }
        })
        .collect();
    let root_proofs = resource_proofs(
        &mut machine,
        &machine_resources,
        &witnesses,
        &audience,
        &trust,
        now,
    );
    // A genuine native resource witness is constructible before activation,
    // but its current managed approval must still fail closed.
    let inactive_proof = operator.join("inactive.proof");
    let inactive_action = operator.join("inactive.action");
    let inactive_request = operator.join("inactive.request");
    let inactive_binding = operator.join("inactive.binding");
    private(&inactive_proof, &root_proofs[0].proof);
    private(&inactive_action, &root_proofs[0].action);
    assert!(
        !cli(
            "effect-review",
            &[
                ("--state-dir", path(&state)),
                ("--proof", path(&inactive_proof)),
                ("--action", path(&inactive_action)),
                ("--not-before", &now.to_string()),
                ("--expires-at", &(now + 250).to_string()),
                ("--request-out", path(&inactive_request)),
                ("--binding-out", path(&inactive_binding)),
            ],
            &["--content"],
            None
        )
        .status
        .success()
    );
    assert!(!inactive_request.exists() && !inactive_binding.exists());
    assert!(provider.calls().is_empty());
    let activate = author(
        &mut machine,
        &machine_controls,
        &call(
            PARTICIPANT_SERVICE,
            ACTIVATE_ROOT_TOOL,
            json!({"root_enrollment_commitment":pins.enrollment_commitment}),
        ),
        control_audience(),
        &trust,
        now,
    );
    let resources: Vec<_> = pins
        .scopes
        .iter()
        .zip(&root_proofs)
        .map(|(scope, proof)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: proof.borrowed(),
        })
        .collect();
    let root_evidence = auths_gateway::EngagementControlEvidence::root(&RootEnrollmentProofs {
        activation: activate.borrowed(),
        resources: &resources,
    })
    .expect("native root evidence");
    let bootstrap = operator.join("root.evidence");
    private(
        &bootstrap,
        &root_evidence.to_private_bytes().expect("root evidence"),
    );
    assert_eq!(
        public(cli(
            "engagement-bootstrap",
            &[
                ("--state-dir", path(&state)),
                ("--evidence", path(&bootstrap))
            ],
            &[],
            None
        ))["kind"],
        "recorded"
    );
    let mut daemon = Daemon::start(&state, &socket, provider.port);
    let a_descriptor = descriptor(
        &pins,
        pins.enrollment_commitment,
        &a,
        "a",
        &a_control,
        &a_resource,
        1,
    );
    let a_proofs = resource_proofs(&mut a, &a_resources, &witnesses, &audience, &trust, now);
    let a_evidence = enrollment(
        &mut machine,
        &mut a,
        pins.enrollment_commitment,
        &a_descriptor,
        &machine_controls,
        &a_controls,
        &a_proofs,
        &pins,
        &trust,
        now,
    );
    let b_descriptor = descriptor(
        &pins,
        a_descriptor.commitment().expect("A"),
        &b,
        "b",
        &b_control,
        &b_resource,
        0,
    );
    let b_proofs = resource_proofs(&mut b, &b_resources, &witnesses, &audience, &trust, now);
    let b_evidence = enrollment(
        &mut a,
        &mut b,
        a_descriptor.commitment().expect("A"),
        &b_descriptor,
        &a_controls,
        &b_controls,
        &b_proofs,
        &pins,
        &trust,
        now,
    );
    assert_eq!(
        b.control(&socket, &b_evidence)["kind"],
        "refused",
        "B needs active enrolled A"
    );
    assert_eq!(
        a.control(&socket, &root_evidence)["code"],
        "gateway.engagement.operator-required"
    );
    assert_eq!(
        machine.control(&socket, &a_evidence),
        json!({"kind":"recorded","revision":2})
    );
    assert_eq!(
        a.control(&socket, &b_evidence),
        json!({"kind":"recorded","revision":3})
    );
    assert_eq!(
        a.control(&socket, &a_evidence),
        json!({"kind":"recorded","revision":2})
    );
    let private_paths = super::interface_tests::private_paths(&operator);
    assert!(
        private_paths.iter().any(|path| path
            .file_name()
            .is_some_and(|name| name == "credentials.cbor")),
        "probe actual custody file"
    );
    for actor in [&mut machine, &mut a, &mut b] {
        if distinct {
            let probe = actor.call(json!({"operation":"probe","files":private_paths}));
            assert!(
                probe["readable"]
                    .as_array()
                    .expect("probe")
                    .iter()
                    .all(|value| value == false)
            );
        }
        assert_eq!(
            actor.call(json!({"operation":"direct-provider","port":provider.port}))["status"],
            401
        );
    }
    assert!(provider.calls().is_empty());
    if distinct {
        assert_eq!(
            b.call(json!({"operation":"probe","files":["/proc/self/mem"]}))["readable"],
            json!([true]),
            "positive control must open its own memory"
        );
        let memory = vec![
            format!("/proc/{}/mem", owner.pid),
            format!("/proc/{}/mem", machine.pid),
            format!("/proc/{}/mem", a.pid),
            format!("/proc/{}/mem", reviewer.pid),
        ];
        assert!(
            b.call(json!({"operation":"probe","files":memory}))["readable"]
                .as_array()
                .expect("memory probe")
                .iter()
                .all(|readable| readable == false)
        );
    }
    let read = approve_native(
        &state,
        author(
            &mut b,
            &b_resources,
            &call_file(&read_call),
            audience.clone(),
            &trust,
            now,
        ),
        "read",
        &mut reviewer,
        now,
        &[],
        &["--content"],
    );
    let acquired = submission(&mut b, &socket, &read, "acquire");
    assert_eq!(
        acquired["history"]["snapshot"]["stage"],
        "response-recorded"
    );
    assert_eq!(provider.calls().len(), 1);
    assert_eq!(submission(&mut b, &socket, &read, "acquire"), acquired);
    assert_eq!(provider.calls().len(), 1);
    forbidden(&serde_json::to_vec(&acquired).expect("metadata"), &content);
    forbidden(&serde_json::to_vec(&acquired).expect("metadata"), &secret);
    let target = AppDisclosureTarget {
        source_operation: "delegated-read".into(),
        recipient_key: a.public.key,
        channel,
        delivery_instance: [0x75; 32],
    };
    let target_file = operator.join("disclosure.target");
    private(&target_file, &serde_json::to_vec(&target).expect("target"));
    let release_call = operator.join("release.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target_file)),
            ("--operation", "delegated-release"),
            ("--call-out", path(&release_call)),
        ],
        &[],
        None,
    ));
    let release = approve_native(
        &state,
        author(
            &mut b,
            &b_resources,
            &call_file(&release_call),
            audience.clone(),
            &trust,
            now,
        ),
        "release",
        &mut reviewer,
        now,
        &[("--disclosure", path(&target_file))],
        &[],
    );
    let receive = json!({"operation":"receive","socket":socket,"gateway":gateway_binary(),"bytes":content.len(),
        "proof":Base64UrlUnpadded::encode_string(&std::fs::read(&release.proof).expect("proof")),
        "action":Base64UrlUnpadded::encode_string(&std::fs::read(&release.action).expect("action")),
        "approval":Base64UrlUnpadded::encode_string(&std::fs::read(&release.approval).expect("approval")),
        "binding":Base64UrlUnpadded::encode_string(&std::fs::read(&release.binding).expect("binding")),
        "target":Base64UrlUnpadded::encode_string(&std::fs::read(&target_file).expect("target"))});
    forbidden(
        &serde_json::to_vec(&receive).expect("recipient input"),
        &content,
    );
    forbidden(
        &serde_json::to_vec(&receive).expect("recipient input"),
        &secret,
    );
    assert_eq!(a.call(receive)["outcome"], "recipient-ack-sent");
    assert_eq!(
        a.call(
            json!({"operation":"received","expected":Base64UrlUnpadded::encode_string(&content)})
        )["matches"],
        true
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observed = history(&socket, "delegated-release");
        if observed["history"]["snapshot"]["stage"] == "acknowledged" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recipient ACK must be durably recorded"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let write_proof = author(
        &mut b,
        &b_resources,
        &mutation("delegated-write"),
        audience.clone(),
        &trust,
        now,
    );
    let write = approve_native(&state, write_proof, "write", &mut reviewer, now, &[], &[]);
    let saved_approval = std::fs::read(&write.approval).expect("approval");
    // The agent signs the actual exact approval request with its own key;
    // native entry must require the independently installed reviewer instead.
    let native_request = EffectApprovalRequest::from_private_bytes(
        &std::fs::read(operator.join("write.request")).expect("request"),
    )
    .expect("request");
    let wrong_signer = b.sign(&native_request.signing_message().expect("signing message"));
    private(
        &write.approval,
        &native_request
            .with_signature(wrong_signer.as_slice().try_into().expect("signature"))
            .to_private_bytes()
            .expect("approval"),
    );
    let denied = submission(&mut b, &socket, &write, "submit");
    assert_eq!(provider.calls().len(), 1);
    assert_ne!(denied["outcome"], "response-recorded");
    private(&write.approval, &saved_approval);
    let written = submission(&mut b, &socket, &write, "submit");
    assert_eq!(written["outcome"], "response-recorded");
    assert_eq!(
        provider
            .calls()
            .iter()
            .filter(|line| line.starts_with("PATCH "))
            .count(),
        1
    );
    let a_write = approve_native(
        &state,
        author(
            &mut a,
            &a_resources,
            &mutation("a-second-write"),
            audience.clone(),
            &trust,
            now,
        ),
        "a-write",
        &mut reviewer,
        now,
        &[],
        &[],
    );
    let exhausted = submission(&mut a, &socket, &a_write, "submit");
    assert_ne!(exhausted["outcome"], "response-recorded");
    assert_eq!(
        provider
            .calls()
            .iter()
            .filter(|line| line.starts_with("PATCH "))
            .count(),
        1
    );
    let first_logs = daemon.finish_logs();
    forbidden(&first_logs, &secret);
    forbidden(&first_logs, &content);
    daemon = Daemon::start(&state, &socket, provider.port);
    let replay = submission(&mut b, &socket, &write, "submit");
    assert_eq!(replay["outcome"], "response-recorded");
    assert_eq!(
        provider
            .calls()
            .iter()
            .filter(|line| line.starts_with("PATCH "))
            .count(),
        1
    );
    let revoke = author(
        &mut machine,
        &machine_controls,
        &call(
            PARTICIPANT_SERVICE,
            REVOKE_PARTICIPANT_TOOL,
            json!({"root_enrollment":pins.enrollment_commitment,"participant":a_descriptor.commitment().expect("A")}),
        ),
        control_audience(),
        &trust,
        now,
    );
    let revoke = auths_gateway::EngagementControlEvidence::revoke(revoke.borrowed())
        .expect("native withdrawal");
    assert_eq!(
        machine.control(&socket, &revoke),
        json!({"kind":"recorded","revision":4})
    );
    assert_eq!(
        b.control(&socket, &b_evidence),
        json!({"kind":"recorded","revision":3})
    );
    let denied_call = operator.join("withdrawn.call");
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&resource)),
            ("--operation", "after-withdrawal"),
            ("--call-out", path(&denied_call)),
        ],
        &[],
        None,
    ));
    let denied_proof = author(
        &mut b,
        &b_resources,
        &call_file(&denied_call),
        audience.clone(),
        &trust,
        now,
    );
    let denied_proof_file = operator.join("withdrawn.proof");
    let denied_action = operator.join("withdrawn.action");
    private(&denied_proof_file, &denied_proof.proof);
    private(&denied_action, &denied_proof.action);
    let no_request = operator.join("withdrawn.request");
    let no_binding = operator.join("withdrawn.binding");
    assert!(
        !cli(
            "effect-review",
            &[
                ("--state-dir", path(&state)),
                ("--proof", path(&denied_proof_file)),
                ("--action", path(&denied_action)),
                ("--not-before", &now.to_string()),
                ("--expires-at", &(now + 250).to_string()),
                ("--request-out", path(&no_request)),
                ("--binding-out", path(&no_binding))
            ],
            &["--content"],
            None
        )
        .status
        .success()
    );
    assert!(
        !no_request.exists() && !no_binding.exists(),
        "historical enrollment receipt cannot restore approval eligibility"
    );
    let archive = operator.join("engagement.audit");
    let checkpoint = operator.join("engagement.head");
    success(cli(
        "engagement-audit-export",
        &[
            ("--state-dir", path(&state)),
            ("--out", path(&archive)),
            ("--checkpoint", path(&checkpoint)),
        ],
        &[],
        None,
    ));
    let audit: Value = serde_json::from_slice(&success(cli(
        "engagement-audit-verify",
        &[
            ("--bundle", path(&archive)),
            ("--checkpoint", path(&checkpoint)),
            ("--root", path(&pins_file)),
            ("--trusted-context", path(&operator.join("trust"))),
        ],
        &[],
        None,
    )))
    .expect("independent native audit");
    assert_eq!(audit["revision"], 4);
    assert_eq!(audit["participants"], 3);
    assert_eq!(audit["current_eligibility"], "not-established");
    let logs = daemon.finish_logs();
    forbidden(&logs, &secret);
    forbidden(&logs, &content);
    let report = json!({"schema":"auths.installed-delegation-process-vectors/1","distinct_uids":distinct,
        "installed_python_and_npm":true,"fresh_process_held_keys":5,"private_keys_exported":0,
        "native_enrollment_revisions":[1,2,3,4],"resource_authority_suffix":3,"scripted_independent_reviewer":true,"human_presence":false,
        "native_read_calls":1,"separate_native_disclosure_ack":true,"native_provider_writes":1,
        "wrong_reviewer_refused":true,"ancestor_shared_limit_refused_second_writer":true,"restart_replay_new_writes":0,
        "old_enrollment_retry_revision":3,"current_control_revision":4,"original_control_audit_replayed":true,
        "withdrawn_descendant_new_review_refused":true,
        "not_established":["live-provider-qualification","human-presence","process-crash-at-every-boundary","postgres-execution","full-AP073-acceptance"]});
    let bytes = serde_json::to_vec_pretty(&report).expect("evidence");
    forbidden(&bytes, &secret);
    forbidden(&bytes, &content);
    if let Some(output) = std::env::var_os("AUTHS_DELEGATION_EVIDENCE_OUT") {
        private(&PathBuf::from(output), &bytes);
    } else {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/gateway/engagement/installed-process.json");
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, &bytes).expect("fixture");
        }
        assert_eq!(std::fs::read(path).expect("fixture"), bytes);
    }
}
