#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn adversarial_conformance(args: Vec<String>) -> Result<(), String> {
    let manifest_path = root().join("core/conformance/v1/manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?;
    let manifest = auths_testkit::conformance::ConformanceManifest::parse(&manifest_bytes)?;

    let mut selection: Option<(&str, &str)> = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if matches!(argument, "--surface" | "--adapter" | "--case") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{argument} requires a value"))?;
            selection = Some((argument, value));
            index += 2;
        } else if argument == "--update" {
            index += 1;
        } else {
            return Err(format!(
                "unknown adversarial-conformance argument {argument}"
            ));
        }
    }

    let selected: Vec<_> = manifest
        .cases
        .iter()
        .filter(|case| {
            selection.is_none_or(|(kind, value)| match kind {
                "--case" => case.case == value,
                "--surface" | "--adapter" => case.case.starts_with(&format!("{value}/")),
                _ => false,
            })
        })
        .collect();
    if selected.is_empty() {
        return Err("adversarial-conformance selection matched no cases".to_owned());
    }

    let adapters_root = root().join("core/conformance/v1/adapters");
    let adapters = files_with_extension(&adapters_root, "json")?;
    if adapters.len() != 7 {
        return Err(format!(
            "expected seven principal adapter manifests, found {}",
            adapters.len()
        ));
    }
    for path in adapters {
        let value: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
        if value.get("schema").and_then(Value::as_str) != Some("auths-proof-adapter-conformance/v1")
        {
            return Err(format!(
                "invalid adapter conformance schema in {}",
                path.display()
            ));
        }
    }

    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;

    let mut executions = Vec::with_capacity(selected.len());
    let mut passed = 0usize;
    for case in &selected {
        let actual = match auths_testkit::conformance::execute_case(&case.case)? {
            auths_testkit::conformance::BoundaryExecution::Completed(code) => code.to_owned(),
            auths_testkit::conformance::BoundaryExecution::FullVerifier(fixture) => {
                let context = auths_codec::decode_verifier_context(fixture.context_bytes())
                    .map_err(|error| format!("{} context: {error}", case.case))?;
                auths_verifier::verify_portable(
                    fixture.proof_bytes(),
                    fixture.canonical_action(),
                    &context,
                    &registries,
                )
                .code()
                .code()
                .to_owned()
            }
        };
        let case_passed = actual == case.expected_code;
        passed += usize::from(case_passed);
        executions.push(json!({
            "case": case.case,
            "boundary": case.boundary,
            "expected_code": case.expected_code,
            "actual_code": actual,
            "passed": case_passed
        }));
    }

    let selected_context: BTreeSet<_> = selected
        .iter()
        .flat_map(|case| case.requirements.iter())
        .filter(|requirement| requirement.starts_with("CONTEXT."))
        .collect();
    let all_context: BTreeSet<_> = manifest
        .cases
        .iter()
        .flat_map(|case| case.requirements.iter())
        .filter(|requirement| requirement.starts_with("CONTEXT."))
        .collect();
    let selected_methods: BTreeSet<_> = selected
        .iter()
        .filter_map(|case| case.case.split_once('/'))
        .map(|(surface, _)| surface)
        .filter(|surface| *surface != "context")
        .collect();
    let all_methods: BTreeSet<_> = manifest
        .cases
        .iter()
        .filter_map(|case| case.case.split_once('/'))
        .map(|(surface, _)| surface)
        .filter(|surface| *surface != "context")
        .collect();
    let selected_common: BTreeSet<_> = selected
        .iter()
        .filter(|case| {
            case.requirements
                .iter()
                .any(|requirement| requirement.starts_with("ADAPTER.COMMON."))
        })
        .filter_map(|case| case.case.split_once('/').map(|(surface, _)| surface))
        .collect();
    let all_common: BTreeSet<_> = manifest
        .cases
        .iter()
        .filter(|case| {
            case.requirements
                .iter()
                .any(|requirement| requirement.starts_with("ADAPTER.COMMON."))
        })
        .filter_map(|case| case.case.split_once('/').map(|(surface, _)| surface))
        .collect();
    let failed = selected.len().saturating_sub(passed);
    let output = json!({
        "schema": "auths-proof-conformance-result/v1",
        "manifest_sha256": sha256_file(&manifest_path)?,
        "cases": selected.len(),
        "passed": passed,
        "failed": failed,
        "coverage": {
            "context_fields": format!("{}/{}", selected_context.len(), all_context.len()),
            "principal_methods": format!("{}/{}", selected_methods.len(), all_methods.len()),
            "common_contract": format!("{}/{}", selected_common.len(), all_common.len())
        },
        "executions": executions
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .map_err(|error| format!("could not encode conformance result: {error}"))?
    );
    if failed == 0 {
        Ok(())
    } else {
        Err(format!(
            "{failed} of {} adversarial conformance cases failed",
            selected.len()
        ))
    }
}

pub(crate) fn target_conformance() -> Result<(), String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    for fixture in auths_testkit::corpus() {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let actual = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let matches = match (fixture.expected(), &actual) {
            (Expected::Authorized, auths_verifier::VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), auths_verifier::VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (
                Expected::Indeterminate(expected),
                auths_verifier::VerificationOutcome::Indeterminate(actual),
            ) => expected == *actual,
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {actual:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
    }
    println!("target V1 canonical corpus conformance passed");
    Ok(())
}

pub(crate) fn semantic_digest() -> Result<(), String> {
    println!("{}", semantic_digest_value()?);
    Ok(())
}

pub(crate) fn semantic_digest_value() -> Result<String, String> {
    use auths_model::ParticipantRole;
    use auths_verifier::VerificationOutcome;

    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let fixtures = auths_testkit::corpus();
    let mut summary = Sha256::new();
    for fixture in &fixtures {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes())
            .map_err(|error| format!("{} context: {error}", fixture.name()))?;
        let outcome = auths_verifier::verify(
            fixture.proof_bytes(),
            fixture.canonical_action(),
            &context,
            &registries,
        );
        let (decision, code) = match &outcome {
            VerificationOutcome::Authorized(_) => ("authorized", "authorized"),
            VerificationOutcome::Denied(reason) => ("denied", reason.code()),
            VerificationOutcome::Indeterminate(requirement) => {
                ("indeterminate", requirement.code())
            }
        };
        let matches = match (fixture.expected(), &outcome) {
            (Expected::Authorized, VerificationOutcome::Authorized(_)) => true,
            (Expected::Denied(expected), VerificationOutcome::Denied(actual)) => {
                expected == *actual
            }
            (Expected::Indeterminate(expected), VerificationOutcome::Indeterminate(actual)) => {
                expected == *actual
            }
            _ => false,
        };
        if !matches {
            return Err(format!(
                "{} expected {:?}, got {outcome:?}",
                fixture.name(),
                fixture.expected()
            ));
        }
        let proof_digest = Sha256::digest(fixture.proof_bytes());
        let context_digest =
            auths_codec::context_digest(&context).map_err(|error| error.to_string())?;
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| error.to_string())?;
        let action_digest = Sha256::digest(action_bytes);
        let plan = auths_verifier::decode_proof(fixture.proof_bytes(), &context)
            .ok()
            .and_then(|decoded| auths_codec::plan_id(decoded.bundle().plan()).ok());
        write_field(&mut summary, fixture.name());
        write_field(&mut summary, decision);
        write_field(&mut summary, code);
        write_bytes(&mut summary, &proof_digest);
        write_bytes(&mut summary, context_digest.as_bytes());
        write_bytes(&mut summary, &action_digest);
        write_bytes(
            &mut summary,
            plan.as_ref()
                .map_or(&[][..], |identifier| identifier.as_bytes()),
        );
        if let VerificationOutcome::Authorized(action) = &outcome {
            for identifier in action.action_ids() {
                write_bytes(&mut summary, identifier.as_bytes());
            }
            write_field(&mut summary, "|");
            for reference in action.authorized_branches() {
                write_bytes(&mut summary, reference.as_bytes());
            }
            write_field(&mut summary, "|");
            for report in action.assurance() {
                write_field(&mut summary, report.principal().as_str());
                write_field(
                    &mut summary,
                    match report.role() {
                        ParticipantRole::Root => "0",
                        ParticipantRole::Intermediate => "1",
                        ParticipantRole::Actor => "2",
                        ParticipantRole::ExternalIssuer => "3",
                    },
                );
                write_field(&mut summary, report.adapter().as_str());
                for claim in report.claims() {
                    write_field(&mut summary, claim.kind().as_str());
                    write_field(
                        &mut summary,
                        &claim
                            .observed_at()
                            .map_or_else(|| "-".to_owned(), |value| value.get().to_string()),
                    );
                }
                write_field(&mut summary, ";");
            }
        } else {
            write_field(&mut summary, "|");
            write_field(&mut summary, "|");
        }
        write_field(&mut summary, "\n");
    }
    Ok(format!(
        "{}:{}",
        fixtures.len(),
        hex::encode(summary.finalize())
    ))
}

pub(crate) fn write_field(summary: &mut Sha256, value: &str) {
    summary.update(value.as_bytes());
    summary.update([0]);
}

pub(crate) fn write_bytes(summary: &mut Sha256, value: &[u8]) {
    write_field(summary, &hex::encode(value));
}

pub(crate) fn wire(update: bool) -> Result<(), String> {
    let generated = generated_vectors()?;
    let fixture_root = root().join("core/fixtures/v1");
    if update {
        for (relative, bytes) in &generated {
            let path = fixture_root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
            }
            fs::write(&path, bytes)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        }
        for relative in fixture_inventory(&fixture_root)? {
            if !generated.contains_key(&relative) {
                fs::remove_file(fixture_root.join(&relative)).map_err(|error| {
                    format!(
                        "could not remove stale fixture {}: {error}",
                        relative.display()
                    )
                })?;
            }
        }
        println!("updated {} golden vector files", generated.len());
        return Ok(());
    }

    for (relative, expected) in &generated {
        let path = fixture_root.join(relative);
        let actual = fs::read(&path)
            .map_err(|error| format!("missing golden vector {}: {error}", path.display()))?;
        if &actual != expected {
            return Err(format!(
                "golden vector {} changed; review and run `cargo xtask wire --update`",
                path.display()
            ));
        }
    }
    let actual = fixture_inventory(&fixture_root)?;
    let expected: BTreeSet<_> = generated.keys().cloned().collect();
    if actual != expected {
        let stale: Vec<_> = actual.difference(&expected).collect();
        let missing: Vec<_> = expected.difference(&actual).collect();
        return Err(format!(
            "fixture inventory mismatch; stale={stale:?}, missing={missing:?}"
        ));
    }
    println!("{} golden vector files are byte-stable", generated.len());
    Ok(())
}

pub(crate) fn generated_vectors() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
            .map_err(|error| error.to_string())?;
    let hsm = auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
        .map_err(|error| error.to_string())?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)
        .map_err(|error| error.to_string())?;
    let mut generated = BTreeMap::new();
    let mut entries = Vec::new();
    for fixture in auths_testkit::corpus() {
        let directory = fixture.class();
        let proof_path = format!("{directory}/{}.proof.cbor", fixture.name());
        let context_path = format!("{directory}/{}.context.cbor", fixture.name());
        let action_path = format!("{directory}/{}.action.cbor", fixture.name());
        let body_path = format!("{directory}/{}.body.cbor", fixture.name());
        let result_path = format!("{directory}/{}.result.cbor", fixture.name());
        let action_bytes = auths_codec::encode_canonical_action(fixture.canonical_action())
            .map_err(|error| format!("{} action: {error}", fixture.name()))?;
        let result_bytes = auths_verifier::verify_v1(
            fixture.proof_bytes(),
            &action_bytes,
            fixture.context_bytes(),
            &registries,
        )
        .map_err(|error| format!("{} portable ABI: {error}", fixture.name()))?;
        let result = auths_codec::decode_verification_result(&result_bytes)
            .map_err(|error| format!("{} result: {error}", fixture.name()))?;
        let (expected_decision, expected_code) = match fixture.expected() {
            Expected::Authorized => ("authorized", "authorized"),
            Expected::Denied(reason) => ("denied", reason.code()),
            Expected::Indeterminate(requirement) => ("indeterminate", requirement.code()),
        };
        entries.push(json!({
            "name": fixture.name(),
            "class": directory,
            "proof": {
                "path": proof_path,
                "sha256": hex::encode(Sha256::digest(fixture.proof_bytes())),
            },
            "context": {
                "path": context_path,
                "sha256": hex::encode(Sha256::digest(fixture.context_bytes())),
            },
            "canonical_action": {
                "path": action_path,
                "sha256": hex::encode(Sha256::digest(&action_bytes)),
                "profile": fixture.canonical_action().profile().id().as_str(),
                "profile_version": fixture.canonical_action().profile().version(),
                "media_type": fixture.canonical_action().media_type().as_str(),
                "capability": fixture.canonical_action().permission().capability().as_str(),
                "resource": fixture.canonical_action().permission().resource().as_str(),
                "requested_budget": fixture.canonical_action().requested_budget().map(|budget| {
                    json!({
                        "algebra": budget.algebra().as_str(),
                        "value": budget.value(),
                    })
                }),
            },
            "canonical_body": {
                "path": body_path,
                "sha256": hex::encode(Sha256::digest(fixture.canonical_action().body())),
            },
            "expected_result": {
                "path": result_path,
                "sha256": hex::encode(Sha256::digest(&result_bytes)),
                "stage": format!("{:?}", result.stage()).to_ascii_lowercase(),
                "decision": expected_decision,
                "code": expected_code,
                "proof_digest": hex::encode(result.proof_digest().as_bytes()),
                "action_digest": hex::encode(result.action_digest().as_bytes()),
                "context_digest": hex::encode(result.context_digest().as_bytes()),
                "plan_digest": result.plan_id().map(|id| hex::encode(id.as_bytes())),
                "result_digest": hex::encode(result.result_digest().as_bytes()),
                "authorized_branches": result.authorized_branches().iter()
                    .map(|id| hex::encode(id.as_bytes())).collect::<Vec<_>>(),
                "assurance_satisfactions": result.assurance_satisfactions().len(),
                "resources": {
                    "proof_bytes": result.resources().proof_bytes(),
                    "action_bytes": result.resources().action_bytes(),
                    "context_bytes": result.resources().context_bytes(),
                    "object_count": result.resources().object_count(),
                    "plan_leaves": result.resources().plan_leaves(),
                    "plan_depth": result.resources().plan_depth(),
                    "work_units": result.resources().work_units(),
                },
                "registry_manifest": hex::encode(result.registry_manifest().as_bytes()),
            },
            "expected_decision": expected_decision,
            "expected_code": expected_code,
        }));
        generated.insert(PathBuf::from(proof_path), fixture.proof_bytes().to_vec());
        generated.insert(
            PathBuf::from(context_path),
            fixture.context_bytes().to_vec(),
        );
        generated.insert(PathBuf::from(action_path), action_bytes);
        generated.insert(
            PathBuf::from(body_path),
            fixture.canonical_action().body().to_vec(),
        );
        generated.insert(PathBuf::from(result_path), result_bytes);
    }
    let manifest = serde_json::to_vec_pretty(&json!({
        "protocol": "Auths Proof Protocol V1",
        "protocol_major": 1,
        "fixture_set": "target-v1",
        "hash": "sha-256",
        "adapter_context": corpus_adapter_context(),
        "fixtures": entries,
    }))
    .map_err(|error| format!("could not encode target fixture manifest: {error}"))?;
    generated.insert(PathBuf::from("manifest.json"), manifest);
    Ok(generated)
}

pub(crate) fn fixture_inventory(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn walk(root: &Path, current: &Path, output: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current)
            .map_err(|error| format!("could not list {}: {error}", current.display()))?
        {
            let entry = entry.map_err(|error| format!("invalid fixture entry: {error}"))?;
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, output)?;
            } else if path
                .extension()
                .is_some_and(|extension| extension == "cbor")
                || path.file_name().is_some_and(|name| name == "manifest.json")
            {
                output.insert(
                    path.strip_prefix(root)
                        .map_err(|_| "fixture escaped root".to_owned())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }
    let mut output = BTreeSet::new();
    walk(root, root, &mut output)?;
    Ok(output)
}

pub(crate) fn corpus_adapter_context() -> Value {
    let did_web = auths_testkit::did_web_corpus_trust_records()
        .iter()
        .map(|record| match record {
            auths_did_web::DidWebTrustRecord::Current {
                principal,
                document_digest,
                observed_at,
                valid_until,
            } => json!({
                "kind": "current",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "observed_at": observed_at.get(),
                "valid_until": valid_until.get(),
            }),
            auths_did_web::DidWebTrustRecord::Historical {
                principal,
                document_digest,
                valid_from,
                valid_until,
                statement,
            } => json!({
                "kind": "historical",
                "principal": principal.as_str(),
                "document_digest": hex::encode(document_digest),
                "valid_from": valid_from.get(),
                "valid_until": valid_until.get(),
                "statement": statement.map(|pin| json!({
                    "signing_preimage_digest":
                        hex::encode(pin.signing_preimage_digest()),
                    "existed_at": pin.existed_at().get(),
                })),
            }),
        })
        .collect::<Vec<_>>();
    let webauthn = auths_testkit::webauthn_corpus_credentials()
        .iter()
        .map(|credential| {
            let counter_policy = match credential.counter_policy() {
                auths_webauthn::CounterPolicy::Disabled => json!({"kind": "disabled"}),
                auths_webauthn::CounterPolicy::GreaterThan(value) => {
                    json!({"kind": "greater-than", "value": value})
                }
            };
            json!({
                "credential_id": hex::encode(credential.credential_id()),
                "principal": credential.principal().as_str(),
                "verification_method": credential.verification_method().as_str(),
                "public_key": hex::encode(credential.public_key()),
                "rp_id": credential.rp_id(),
                "origins": credential.origins(),
                "require_user_verification": credential.require_user_verification(),
                "counter_policy": counter_policy,
                "attestation_level": credential.attestation_level(),
                "observed_at": credential.observed_at().get(),
                "valid_until": credential.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let hsm = auths_testkit::hsm_corpus_records()
        .iter()
        .map(|record| {
            json!({
                "principal": record.principal().as_str(),
                "verification_method": record.verification_method().as_str(),
                "suite": record.suite().as_str(),
                "public_key": hex::encode(record.public_key()),
                "profile": record.profile(),
                "provider": record.provider(),
                "protection_level": record.protection_level(),
                "key_handle_digest": hex::encode(record.key_handle_digest()),
                "device_chain_digest": hex::encode(record.device_chain_digest()),
                "non_exportable": record.non_exportable(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    let (trust_domains, status) = auths_testkit::spiffe_corpus_context();
    let spiffe_trust_domains = trust_domains
        .iter()
        .map(|trust| {
            json!({
                "name": trust.name(),
                "roots": trust.roots().iter().map(hex::encode).collect::<Vec<_>>(),
                "require_status": trust.requires_status(),
            })
        })
        .collect::<Vec<_>>();
    let spiffe_status = status
        .iter()
        .map(|record| {
            json!({
                "leaf_digest": hex::encode(record.leaf_digest()),
                "active": record.is_active(),
                "observed_at": record.observed_at().get(),
                "valid_until": record.valid_until().get(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "configuration": hex::encode(auths_testkit::corpus_configuration_id().as_bytes()),
        "did_web": did_web,
        "webauthn": webauthn,
        "hsm": hsm,
        "spiffe": {
            "trust_domains": spiffe_trust_domains,
            "status": spiffe_status,
        },
        "did_keri": {
            "checkpoints": [],
        },
    })
}
