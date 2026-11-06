//! Actual application interfaces; distinct UID mode additionally tests Linux DAC.
use super::*;
use auths_gateway::{admin, app};
use sha2::Digest as _;
use sha2::Sha256;
use std::collections::BTreeSet;

fn no_canaries(bytes: &[u8], secret: &[u8]) {
    for value in [CONTENT, secret] {
        let digest = Sha256::digest(value);
        let variants = [
            value.to_vec(),
            base64ct::Base64::encode_string(value).into_bytes(),
            Base64UrlUnpadded::encode_string(value).into_bytes(),
            hex::encode(value).into_bytes(),
            digest.to_vec(),
            hex::encode(digest).into_bytes(),
            base64ct::Base64::encode_string(&digest).into_bytes(),
            Base64UrlUnpadded::encode_string(&digest).into_bytes(),
        ];
        for variant in variants {
            assert!(
                !bytes.windows(variant.len()).any(|part| part == variant),
                "sensitive value or guessable digest reached a public boundary"
            );
        }
    }
}
fn scan_value(value: &Value, secret: &[u8]) {
    match value {
        Value::String(value) => {
            no_canaries(value.as_bytes(), secret);
            for decoded in [
                base64ct::Base64::decode_vec(value),
                Base64UrlUnpadded::decode_vec(value),
            ]
            .into_iter()
            .flatten()
            {
                no_canaries(&decoded, secret);
            }
        }
        Value::Array(values) => {
            for value in values {
                scan_value(value, secret);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                scan_value(value, secret);
            }
        }
        _ => {}
    }
}
fn checked(output: &Output, secret: &[u8]) -> Value {
    no_canaries(&output.stdout, secret);
    no_canaries(&output.stderr, secret);
    assert!(output.status.success(), "native process failed");
    let value = serde_json::from_slice(&output.stdout).expect("native public JSON");
    scan_value(&value, secret);
    value
}
fn envelope(input: &Approved) -> Value {
    let encode =
        |path: &Path| Base64UrlUnpadded::encode_string(&std::fs::read(path).expect("native input"));
    json!({"schema":app::APP_REQUEST_SCHEMA, "proof_b64":encode(&input.proof), "action_b64":encode(&input.action), "approval_b64":encode(&input.approval)})
}
fn case(name: &str, value: &Value) -> Value {
    json!({"case":name,"frame":serde_json::to_string(value).expect("frame")})
}
fn private_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).expect("owned fixture directory") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("type").is_dir() {
            paths.extend(private_paths(&entry.path()));
        } else if entry.file_type().expect("type").is_file() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    paths
}
fn witness(state: &Path, admin: &Path, secret: &[u8]) -> Value {
    checked(
        &cli(
            "execution-witness",
            &[
                ("--state-dir", path(state)),
                ("--admin-socket", path(admin)),
            ],
            &[],
            None,
        ),
        secret,
    )["execution_witness"]
        .clone()
}

fn check_public_response(value: &mut Value, secret: &[u8]) {
    if value["response"]["outcome"] == "signed" {
        let response = &value["response"];
        assert_eq!(response["schema"], "auths.gateway-outcome/3");
        let bytes =
            Base64UrlUnpadded::decode_vec(response["observation_b64"].as_str().expect("signature"))
                .expect("base64");
        no_canaries(&bytes, secret);
        let signed =
            auths_codec::decode_signed_observation(&bytes, &auths_model::VerifierLimits::default())
                .expect("native canonical signature");
        assert_eq!(
            signed.statement().schema().as_str(),
            auths_gateway::OUTCOME_SCHEMA
        );
        let names: Vec<_> = signed
            .statement()
            .facts()
            .as_slice()
            .iter()
            .map(|fact| fact.name().as_str())
            .collect();
        assert_eq!(
            names,
            [
                "effect-reference",
                "evaluated-at",
                "http-status",
                "recipe-reference",
                "record-commitment",
                "stage"
            ]
        );
        value["response"] = json!({"outcome":"signed", "schema":auths_gateway::OUTCOME_SCHEMA, "native_canonical_public_projection_checked":true});
    }
    if value["response"]["outcome"] == "pre-entry" {
        let commitment = value["response"]["record_commitment"]
            .as_str()
            .expect("hiding commitment");
        assert_eq!(commitment.len(), 64);
        assert!(
            commitment
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(value["response"].get("observations_b64").is_none());
        value["response"]["record_commitment"] = json!("native-hiding-value-checked");
    }
}

fn probe(mut payload: Value, secret: &[u8]) -> Value {
    let distinct = payload["distinct_uid"].as_bool().expect("mode");
    let admin_socket = PathBuf::from(payload["admin_socket"].as_str().expect("admin socket"));
    let admin_directory = admin_socket.parent().expect("admin directory");
    if distinct {
        std::fs::set_permissions(admin_directory, std::fs::Permissions::from_mode(0o755))
            .expect("exercise accept-time UID guard");
        std::fs::set_permissions(&admin_socket, std::fs::Permissions::from_mode(0o666))
            .expect("exercise peer guard beyond DAC");
    }
    let mut child = if distinct {
        let mut command = Command::new("sudo");
        command
            .args(["-n", "setpriv", "--reuid=65534"])
            .arg(format!("--regid={}", rustix::process::getegid().as_raw()))
            .args([
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "python3",
            ]);
        command
    } else {
        Command::new("python3")
    };
    child
        .arg("-c")
        .arg(include_str!("../managed_interface_probe.py"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("PATH"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    payload["binary"] = json!(env!("CARGO_BIN_EXE_auths-gateway"));
    let mut child = child.spawn().expect("untrusted process");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&serde_json::to_vec(&payload).expect("probe data"))
        .expect("probe input");
    let output = child.wait_with_output().expect("untrusted process output");
    if distinct {
        // The permissive inode is scoped to the untrusted peer probe. Trusted
        // admin clients must still enforce a private directory and socket.
        std::fs::set_permissions(&admin_socket, std::fs::Permissions::from_mode(0o600))
            .expect("restore private admin socket");
        std::fs::set_permissions(admin_directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore private admin directory");
    }
    no_canaries(&output.stdout, secret);
    no_canaries(&output.stderr, secret);
    assert!(
        output.status.success(),
        "untrusted process assertion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut result: Value = serde_json::from_slice(&output.stdout).expect("probe report");
    scan_value(&result, secret);
    for value in result["cases"].as_array_mut().expect("cases") {
        for frame in value["after_ready_b64"].as_array().expect("frames") {
            let bytes =
                base64ct::Base64::decode_vec(frame.as_str().expect("base64")).expect("frame bytes");
            no_canaries(&bytes, secret);
        }
        let count = value["after_ready_b64"].as_array().expect("frames").len();
        value
            .as_object_mut()
            .expect("case")
            .remove("after_ready_b64");
        value["post_ready_control_frames"] = json!(count);
        check_public_response(value, secret);
    }
    for value in result["private_cli"].as_array_mut().expect("private CLI") {
        for field in ["stdout_b64", "stderr_b64"] {
            let bytes = base64ct::Base64::decode_vec(value[field].as_str().expect("base64"))
                .expect("output");
            no_canaries(&bytes, secret);
            value.as_object_mut().expect("result").remove(field);
        }
    }
    result
}

#[allow(
    clippy::too_many_lines,
    reason = "one installed native fixture checks all application interfaces against a counting provider and owned private state"
)]
fn run(distinct: bool) -> Value {
    #[cfg(not(target_os = "linux"))]
    assert!(!distinct, "distinct-UID evidence requires Linux");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let bases: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("hostile-recipes-v2.json")).expect("recipes"),
    )
    .expect("JSON");
    let mut source = bases["bases"]["airtable"]["recipe"].clone();
    source["content"] = json!({"schema":"auths.gateway-content-read/1","resource_field":"record_id",
        "path":[{"kind":"fixed","value":"documents"},{"kind":"field","name":"record_id"}],
        "query":[{"name":"format","value":"text/plain"}],"projection":{"kind":"utf8"},"maximum_response_bytes":1024,"maximum_content_bytes":64});
    let source = serde_json::to_vec(&source).expect("recipe");
    let lock = serde_json::to_vec(&bases["bases"]["airtable"]["lock"]).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("native recipe");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let tools = [
        CONTENT_READ_TOOL,
        DISCLOSURE_TOOL,
        recipe.review().tool(),
        "auths_gateway_recovery_read_v1",
    ]
    .map(|name| {
        McpToolCall::new(recipe.review().service(), name, serde_json::Map::new()).expect("tool")
    });
    let trust = tools_context(&tools, now).expect("native trust");
    let reviewer = SigningKey::from_bytes(&[29; 32]);
    let recipient = SigningKey::from_bytes(&[31; 32]);
    let policy = EffectPolicy::new(
        "managed-interface-probe".to_owned(),
        1,
        reviewer.verifying_key().to_bytes(),
    )
    .expect("policy");
    let directory = tempfile::Builder::new()
        .prefix("ap74-if-")
        .tempdir_in("/tmp")
        .expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .expect("traversable socket parent");
    let state = root.join("state");
    let socket = root.join("app.sock");
    let admin_directory = root.join("operator");
    std::fs::create_dir(&admin_directory).expect("operator directory");
    std::fs::set_permissions(&admin_directory, std::fs::Permissions::from_mode(0o700))
        .expect("private operator directory");
    let admin_socket = admin_directory.join("admin.sock");
    for (name, bytes) in [
        ("recipe", source),
        ("lock", lock),
        ("trust", trust),
        (
            "policy",
            policy.to_private_bytes().expect("policy").to_vec(),
        ),
    ] {
        private(&root.join(name), &bytes);
    }
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).expect("fresh credential entropy");
    let secret = zeroize::Zeroizing::new(
        format!("pat_ap074_isolation_{}", hex::encode(entropy)).into_bytes(),
    );
    let provider = Provider::configured(secret.to_vec(), true);
    let installed = cli(
        "install",
        &[
            ("--state-dir", path(&state)),
            ("--recipe", path(&root.join("recipe"))),
            ("--profile-lock", path(&root.join("lock"))),
            ("--trusted-context", path(&root.join("trust"))),
            ("--effect-policy", path(&root.join("policy"))),
            ("--approve-digest", &recipe.digest_hex()),
            ("--provider", "airtable"),
            ("--alias", "interfaces"),
            ("--account-label", "public-fixture"),
        ],
        &["--credential-stdin"],
        Some(&secret),
    );
    no_canaries(&installed.stdout, &secret);
    no_canaries(&installed.stderr, &secret);
    assert!(installed.status.success(), "native install");
    success(cli(
        "observer-init",
        &[("--state-dir", path(&state))],
        &[],
        None,
    ));
    let configuration = checked(
        &cli(
            "effect-configuration-review",
            &[("--state-dir", path(&state))],
            &[],
            None,
        ),
        &secret,
    );
    success(cli(
        "effect-configuration-activate",
        &[
            ("--state-dir", path(&state)),
            (
                "--expected-revision",
                configuration["previous_revision_hex"]
                    .as_str()
                    .expect("configuration revision"),
            ),
            (
                "--expected-candidate",
                configuration["candidate_hex"]
                    .as_str()
                    .expect("configuration candidate"),
            ),
        ],
        &[],
        None,
    ));
    let arguments = root.join("resource.json");
    private(
        &arguments,
        &serde_json::to_vec(&json!({"record_id":RECORD})).expect("resource"),
    );
    let read_call = root.join("read.call");
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&arguments)),
            ("--operation", "read"),
            ("--call-out", path(&read_call)),
        ],
        &[],
        None,
    ));
    let read = approve(
        &state,
        &call_file(&read_call),
        "read",
        now,
        &reviewer,
        &[],
        &["--content"],
    );
    let mut daemon = Daemon::start_at_admin(&state, &socket, &admin_socket, provider.port);
    let acquired = checked(
        &read.execute("content-acquire", &socket, &[], &[], None),
        &secret,
    );
    assert_eq!(
        acquired["history"]["snapshot"]["content_projection"]["kind"], "ready",
        "native acquisition result: {acquired}"
    );
    assert_eq!(provider.calls().len(), 1);
    let write_call = McpToolCall::new(
        recipe.review().service(),
        recipe.review().tool(),
        json!({"operation_id":"write", "operator_namespace":recipe.namespace().as_str(),
            "recipe_digest":recipe.digest_hex(), "record_id":RECORD, "replacement":"Approved"})
        .as_object()
        .expect("arguments")
        .clone(),
    )
    .expect("mutation call");
    let write = approve(&state, &write_call, "write", now, &reviewer, &[], &[]);
    assert_eq!(
        checked(&write.execute("submit", &socket, &[], &[], None), &secret)["outcome"],
        "response-recorded"
    );
    let public_bundle = admin_directory.join("submission-bundle.json");
    private(&public_bundle, &serde_json::to_vec(&json!({"schema":auths_gateway::AUDIT_BUNDLE_SCHEMA,
        "recipe_b64":Base64UrlUnpadded::encode_string(&std::fs::read(root.join("recipe")).expect("recipe")),
        "profile_lock_b64":Base64UrlUnpadded::encode_string(&std::fs::read(root.join("lock")).expect("lock")),
        "trusted_context_b64":Base64UrlUnpadded::encode_string(&std::fs::read(root.join("trust")).expect("trust")),
        "entries":[{"operation_id":"write", "proof_b64":Base64UrlUnpadded::encode_string(&std::fs::read(&write.proof).expect("proof")),
            "action_b64":Base64UrlUnpadded::encode_string(&std::fs::read(&write.action).expect("action")), "outcome_b64":null}]
        })).expect("submission inventory"));
    let private_audit = admin_directory.join("private-audit.json");
    let exported = cli(
        "audit-export",
        &[
            ("--state-dir", path(&state)),
            ("--admin-socket", path(&admin_socket)),
            ("--bundle", path(&public_bundle)),
            ("--out", path(&private_audit)),
        ],
        &[],
        None,
    );
    checked(&exported, &secret);
    assert_eq!(
        std::fs::metadata(&private_audit)
            .expect("private audit")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let observer = checked(
        &cli("observer-show", &[("--state-dir", path(&state))], &[], None),
        &secret,
    );
    let trust_digest = hex::encode(sha2::Sha256::digest(
        std::fs::read(root.join("trust")).expect("trust"),
    ));
    let audited = cli(
        "audit",
        &[
            ("--bundle", path(&private_audit)),
            ("--trusted-context-sha256", &trust_digest),
            (
                "--observer",
                observer["observer_anchor"]["principal"]
                    .as_str()
                    .expect("observer"),
            ),
        ],
        &[],
        None,
    );
    // This operator-only report intentionally contains protected audit facts.
    assert!(audited.status.success(), "operator private audit refused");
    let audited: Value = serde_json::from_slice(&audited.stdout).expect("audit report");
    assert_eq!(audited["verified"], 1);
    assert_eq!(audited["inconsistent"], 0);
    let repeated = cli(
        "audit-export",
        &[
            ("--state-dir", path(&state)),
            ("--admin-socket", path(&admin_socket)),
            ("--operation-id", "write"),
            ("--out", path(&private_audit)),
        ],
        &[],
        None,
    );
    assert!(
        !repeated.status.success(),
        "private export must never overwrite an existing artifact"
    );
    no_canaries(&repeated.stdout, &secret);
    no_canaries(&repeated.stderr, &secret);
    let uid = rustix::process::geteuid().as_raw();
    let target = root.join("target.json");
    private(
        &target,
        &serde_json::to_vec(&AppDisclosureTarget {
            source_operation: "read".to_owned(),
            recipient_key: recipient.verifying_key().to_bytes(),
            channel: UnixDisclosurePolicy::new(uid, uid, [5; 32]),
            delivery_instance: [6; 32],
        })
        .expect("target"),
    );
    let release_call = root.join("release.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target)),
            ("--operation", "release"),
            ("--call-out", path(&release_call)),
        ],
        &[],
        None,
    ));
    let release = approve(
        &state,
        &call_file(&release_call),
        "release",
        now,
        &reviewer,
        &[("--disclosure", path(&target))],
        &[],
    );
    let disclose = json!({"schema":app::APP_DISCLOSURE_SCHEMA,"target":serde_json::from_slice::<Value>(&std::fs::read(&target).expect("target")).expect("JSON"),"submission":envelope(&release)});
    let mut calls = vec![
        case("submit-with-read-authority", &envelope(&read)),
        case(
            "content-replay",
            &json!({"schema":app::APP_CONTENT_SCHEMA,"submission":envelope(&read)}),
        ),
        case(
            "content-history",
            &json!({"schema":app::APP_CONTENT_HISTORY_SCHEMA,"operation":"read"}),
        ),
        case("disclose-without-recipient-authentication", &disclose),
        case(
            "recover-with-acquisition-source",
            &json!({"schema":app::APP_RECOVERY_SCHEMA,"source_operation":"read","submission":envelope(&read)}),
        ),
        case(
            "observe-outcome",
            &json!({"schema":app::APP_OBSERVE_SCHEMA,"request":{"kind":"outcome","operation_id":"write"}}),
        ),
        case(
            "observe-pre-entry",
            &json!({"schema":app::APP_OBSERVE_SCHEMA,"request":{"kind":"pre-entry","operation_id":"write"}}),
        ),
        case(
            "forged-ack",
            &json!({"schema":app::APP_DISCLOSURE_ACK_SCHEMA,"operation":"release","acknowledgement_b64":Base64UrlUnpadded::encode_string(b"{}")}),
        ),
        case(
            "native-participant-control-without-installed-engagement",
            &serde_json::from_slice::<Value>(
                &std::fs::read(fixtures.join("engagement/control.json"))
                    .expect("native control corpus"),
            )
            .expect("native control JSON")["file"]["enrollment_request"],
        ),
    ];
    let covered: BTreeSet<_> = calls
        .iter()
        .map(|value| {
            serde_json::from_str::<Value>(value["frame"].as_str().expect("frame"))
                    .expect("JSON")["schema"]
                    .as_str()
                    .expect("schema")
                    .to_owned()
        })
        .collect();
    assert_eq!(
        covered,
        app::APPLICATION_REQUEST_SCHEMAS
            .iter()
            .map(|schema| (*schema).to_owned())
            .collect()
    );
    let boundary: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("admin-request-boundary.json")).expect("admin corpus"),
    )
    .expect("JSON");
    let admin_frames: Vec<_> = boundary["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| case["case"].as_str().expect("name").ends_with(":valid"))
        .map(|case| case["input"].clone())
        .collect();
    assert_eq!(admin_frames.len(), admin::ADMIN_REQUEST_COMMANDS.len());
    for value in &admin_frames {
        let frame: Value = serde_json::from_str(value.as_str().expect("frame")).expect("JSON");
        calls.push(case(
            &format!(
                "admin-on-app:{}",
                frame["command"].as_str().expect("command")
            ),
            &frame,
        ));
    }
    for schema in [
        "auths.gateway-submit/1",
        "auths.gateway-observe/2",
        "auths.gateway-recover/0",
        "auths.gateway-content/0",
        "auths.gateway-disclose/0",
    ] {
        calls.push(case(schema, &json!({"schema":schema,"operation":"read"})));
    }
    for command in [
        "reobserve",
        "raw-http",
        "credential-export",
        "retry",
        "refund",
        "resolve-as-not-entered",
    ] {
        calls.push(case(command,&json!({"schema":app::APP_REQUEST_SCHEMA,"command":command,"url":"https://untrusted.invalid","body":"untrusted"})));
    }
    calls.push(
        json!({"case":"oversized-advertised-frame","advertised_length":app::MAX_FRAME_BYTES+1}),
    );
    calls.push(json!({"case":"http-on-app-socket","raw_http":true}));
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("managed-cli-inventory.json")).expect("native CLI catalog"),
    )
    .expect("JSON");
    let commands: Vec<_> = inventory["cli"]
        .as_array()
        .expect("CLI")
        .iter()
        .map(|value| value["command"].clone())
        .collect();
    let key = auths_gateway::GatewayAttemptKey::for_operation(
        &policy,
        recipe.namespace(),
        &auths_gateway::LogicalOperationId::parse("read").expect("operation"),
    )
    .expect("key");
    let source_path = state
        .join("attempts")
        .join(format!("claim-{}.json", hex::encode(key.as_bytes())));
    let source_before = std::fs::read(&source_path).expect("private source journal");
    let before = witness(&state, &admin_socket, &secret);
    let payload = json!({"distinct_uid":distinct,"gateway_uid":uid,"gateway_pid":daemon.0.id(),"socket":socket,"state":state,"admin_socket":admin_socket,"provider_port":provider.port,"private_paths":private_paths(&root),"cases":calls,"admin_frames":admin_frames,"cli_commands":commands});
    let first = probe(payload.clone(), &secret);
    assert_eq!(witness(&state, &admin_socket, &secret), before);
    assert_eq!(provider.calls().len(), 2);
    assert_eq!(provider.denied.load(Ordering::SeqCst), 2);
    assert!(
        source_before == std::fs::read(&source_path).expect("source"),
        "source journal changed"
    );
    let reserved = history(&socket, "release");
    assert_eq!(reserved["history"]["snapshot"]["stage"], "reserved");
    let content = root.join("received");
    let ack = root.join("ack");
    let expected_bytes = CONTENT.len().to_string();
    let received = checked(
        &release.execute(
            "disclosure-receive",
            &socket,
            &[
                ("--target", path(&target)),
                ("--expected-binding", path(&release.binding)),
                ("--expected-bytes", &expected_bytes),
                ("--content-out", path(&content)),
                ("--acknowledgement-out", path(&ack)),
            ],
            &["--recipient-seed-stdin"],
            Some(&[31; 32]),
        ),
        &secret,
    );
    assert_eq!(received["outcome"], "recipient-ack-sent");
    // Keep protected bytes out of assertion diagnostics.
    assert!(
        std::fs::read(&content).expect("trusted recipient content") == CONTENT,
        "trusted recipient content differs"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let acknowledged = loop {
        let value = history(&socket, "release");
        scan_value(&value, &secret);
        if value["history"]["snapshot"]["stage"] == "acknowledged" {
            break value;
        }
        assert!(Instant::now() < deadline, "ACK was not durably recorded");
        thread::sleep(Duration::from_millis(10));
    };
    let mut replay_payload = payload;
    replay_payload["private_paths"] = json!(private_paths(&root));
    replay_payload["cases"] = json!([case("disclosure-replay-after-owner-ack", &disclose)]);
    replay_payload["admin_frames"] = json!([]);
    replay_payload["cli_commands"] = json!([]);
    let replay = probe(replay_payload, &secret);
    assert_eq!(provider.calls().len(), 2);
    assert_eq!(provider.denied.load(Ordering::SeqCst), 4);
    assert_eq!(witness(&state, &admin_socket, &secret), before);
    assert_eq!(history(&socket, "release"), acknowledged);
    no_canaries(&daemon.finish_logs(), &secret);
    json!({"schema":"auths.managed-interface-probe/1","distinct_uid":distinct,
        "scope":"real native daemon, fresh runtime credential, actual local HTTP, all native application schemas, all operator commands injected on the application channel and every CLI help entry",
        "excluded":["hostile OS or root", "provider or production custody qualification", "all privileged CLI execution paths", "live-provider qualification"],
        "first":first,"replay":replay,"private_source_journal_unchanged":true,"provider_authorized_calls":2,
        "direct_provider_refusals":4,"no_new_custody_or_provider_entries":true,
        "recipient_key_and_uid_guard_precede_content":true,"trusted_recipient_positive_control":true,
        "public_channels_exclude_plaintext_encodings_and_raw_digests":true,
        "operator_private_export_mode":384, "operator_private_audit_verified_entries":1, "private_export_refuses_overwrite":true})
}

#[test]
fn native_managed_interface_fixture_is_current() {
    let report = run(false);
    let bytes = serde_json::to_vec_pretty(&report).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/managed-interface-unix.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), bytes);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires hosted Linux sudo and a distinct UID"]
fn distinct_uid_managed_interface_evidence() {
    let mut report = run(true);
    report["source_commit"] =
        json!(std::env::var("AUTHS_EVIDENCE_SOURCE_REVISION").expect("source revision"));
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target");
    std::fs::create_dir_all(&target).expect("artifact directory");
    std::fs::write(
        target.join("ap074-managed-interface-isolation.json"),
        serde_json::to_vec_pretty(&report).expect("artifact"),
    )
    .expect("artifact");
}
