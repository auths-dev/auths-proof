use auths_profile_api::ActionProfile as _;
use ed25519_dalek::{Signer as _, SigningKey};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        env::args()
            .nth(1)
            .ok_or("expected generated-package output directory")?,
    );
    fs::create_dir_all(&output)?;
    let proof = include_bytes!("../../../../core/fixtures/v1/valid/raw-key-chain.proof.cbor");
    let action = include_bytes!("../../../../core/fixtures/v1/valid/raw-key-chain.action.cbor");
    let context = include_bytes!("../../../../core/fixtures/v1/valid/raw-key-chain.context.cbor");
    let context = auths_codec::decode_verifier_context(context)?.with_configuration(
        auths_model::VerifierConfigurationId::new(
            auths_proof_wasm::self_contained_v1_configuration()?,
        ),
    )?;
    let context = auths_codec::encode_verifier_context(&context)?;
    let result = auths_proof_wasm::verify_self_contained_v1(proof, action, &context)?;
    fs::write(output.join("authorized.context.cbor"), context)?;
    fs::write(output.join("authorized.result.cbor"), result)?;
    write_scenario_vectors(&output)?;
    write_authoring_vectors(&output, proof)?;
    write_mcp_workflow_vectors(&output)?;
    Ok(())
}

fn write_authoring_vectors(
    output: &std::path::Path,
    proof: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle =
        auths_codec::decode_bundle(proof, &auths_model::VerifierLimits::default_deployment())?;
    let proposed = bundle
        .grants()
        .first()
        .ok_or("raw-key chain omitted its grant")?
        .statement();
    fs::write(
        output.join("authoring.signed-root-grant.cbor"),
        auths_codec::encode_signed_grant(
            bundle
                .grants()
                .first()
                .ok_or("raw-key chain omitted its grant")?,
        )?,
    )?;
    let parent = auths_model::GrantStatement::new(
        proposed.issuer().clone(),
        proposed.issuer().clone(),
        proposed.profile().clone(),
        proposed.permissions().clone(),
        auths_model::ValidityWindow::new(
            auths_model::Timestamp::new(0),
            auths_model::Timestamp::new(100),
        )?,
        proposed.audiences().clone(),
        auths_model::ActionConstraint::AnyBody,
        Some(auths_model::BudgetCeiling::new(
            proposed
                .budget_ceiling()
                .ok_or("raw-key chain omitted its budget")?
                .algebra()
                .clone(),
            20,
        )),
        1,
        None,
        proposed.status_policy().clone(),
        proposed.assurance_floor().clone(),
        auths_model::CriticalExtensions::empty(),
    );
    let delegation_root = delegation_root(
        proposed,
        bundle
            .grants()
            .first()
            .ok_or("raw-key chain omitted its grant")?,
    )?;
    let plan = auths_author::plan_child_grant(
        &parent,
        auths_author::GrantRequest::from_proposed_statement(proposed),
    )?;
    let signed_action = bundle
        .actions()
        .first()
        .ok_or("raw-key chain omitted its action")?;
    let signing = auths_author::prepare_action(
        signed_action.envelope().clone(),
        signed_action.signature().descriptor().clone(),
    )?;
    fs::write(
        output.join("authoring.parent-grant.cbor"),
        auths_codec::encode_grant_statement(&parent)?,
    )?;
    fs::write(
        output.join("authoring.delegation-root-grant.cbor"),
        auths_codec::encode_signed_grant(&delegation_root)?,
    )?;
    fs::write(
        output.join("authoring.proposed-grant.cbor"),
        auths_codec::encode_grant_statement(proposed)?,
    )?;
    fs::write(
        output.join("authoring.planned-grant.cbor"),
        auths_codec::encode_grant_statement(plan.statement())?,
    )?;
    fs::write(
        output.join("authoring.action-signing-preimage.cbor"),
        signing.signing_preimage(),
    )?;
    Ok(())
}

fn write_scenario_vectors(output: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../core/fixtures/v1");
    let scenario_output = output.join("scenarios");
    fs::create_dir_all(&scenario_output)?;
    let configuration = auths_model::VerifierConfigurationId::new(
        auths_proof_wasm::self_contained_v1_configuration()?,
    );
    let mut manifest = Vec::new();
    for kind in ["valid", "denied", "indeterminate", "invalid", "status"] {
        let directory = fixture_root.join(kind);
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            let Some(name) = filename.strip_suffix(".result.cbor") else {
                continue;
            };
            let expected = fs::read(directory.join(format!("{name}.result.cbor")))?;
            let expected = auths_codec::decode_verification_result(&expected)?;
            let proof = fs::read(directory.join(format!("{name}.proof.cbor")))?;
            let action = fs::read(directory.join(format!("{name}.action.cbor")))?;
            let context = fs::read(directory.join(format!("{name}.context.cbor")))?;
            let context = auths_codec::decode_verifier_context(&context)?
                .with_configuration(configuration)?;
            let context = auths_codec::encode_verifier_context(&context)?;
            let result = auths_proof_wasm::verify_self_contained_v1(&proof, &action, &context)?;
            let decoded = auths_codec::decode_verification_result(&result)?;
            if decoded.code() != expected.code() {
                continue;
            }
            let id = format!("{kind}.{name}");
            fs::write(scenario_output.join(format!("{id}.proof.cbor")), proof)?;
            fs::write(scenario_output.join(format!("{id}.action.cbor")), action)?;
            fs::write(scenario_output.join(format!("{id}.context.cbor")), context)?;
            fs::write(scenario_output.join(format!("{id}.result.cbor")), result)?;
            manifest.push(serde_json::json!({ "id": id, "kind": kind, "name": name }));
        }
    }
    manifest.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    fs::write(
        output.join("scenarios.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn write_mcp_workflow_vectors(output: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let root_key = SigningKey::from_bytes(&[11; 32]);
    let actor_key = SigningKey::from_bytes(&[12; 32]);
    let child_key = SigningKey::from_bytes(&[13; 32]);
    let root_descriptor = auths_raw_key::RawKeyDescriptor::new(
        auths_raw_key::RawKeyType::Ed25519,
        root_key.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| std::io::Error::other("invalid fixed root key"))?;
    let actor_descriptor = auths_raw_key::RawKeyDescriptor::new(
        auths_raw_key::RawKeyType::Ed25519,
        actor_key.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| std::io::Error::other("invalid fixed actor key"))?;
    let child_descriptor = auths_raw_key::RawKeyDescriptor::new(
        auths_raw_key::RawKeyType::Ed25519,
        child_key.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| std::io::Error::other("invalid fixed child key"))?;
    let root = root_descriptor.principal()?;
    let actor = actor_descriptor.principal()?;
    let child = child_descriptor.principal()?;
    let call = auths_profile_mcp::McpToolCall::new(
        "reports",
        "update_demo_record",
        serde_json::from_value(serde_json::json!({"value": "reviewed"}))?,
    )?;
    let canonical = auths_profile_mcp::McpProfile.canonicalize(&call.canonical_bytes()?)?;
    let template =
        auths_codec::decode_verifier_context(&fs::read(output.join("authorized.context.cbor"))?)?;
    let anchor = auths_model::TrustAnchor::new(
        auths_model::TrustAnchorId::parse(root.as_str())?,
        root.clone(),
        vec![auths_model::PrincipalMethodId::parse(
            auths_raw_key::RAW_KEY_V1,
        )?],
        vec![canonical.profile().clone()],
        auths_model::PermissionSet::new(vec![canonical.permission().clone()])?,
        vec![auths_model::ResourceId::parse("mcp://reports")?],
        auths_model::AudienceSet::new(vec![call.audience()?])?,
        auths_model::ValidityWindow::new(
            auths_model::Timestamp::new(0),
            auths_model::Timestamp::new(100),
        )?,
        Some(auths_model::BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1")?,
            20,
        )),
        2,
        auths_model::AssurancePolicyId::parse("raw-key-baseline")?,
        auths_model::StatusPolicy::ExpiryOnly,
    )?;
    let context = auths_model::TrustedContext::new(
        template.configuration(),
        template.composition(),
        vec![anchor],
        // `auths.mcp/1` has no budget field in its canonical body, so an MCP
        // tool call can never declare a spend. Without this declaration the
        // bounded ceilings below would deny every MCP action: an absent request
        // would read as an unknown spend rather than the provable zero it is.
        // The value is read off the Rust profile, never asserted here.
        template
            .accepted_registries()
            .clone()
            .with_budget_free_profiles(
                auths_profile_mcp::budget_expression(canonical.profile())
                    .filter(|expression| {
                        *expression == auths_model::ProfileBudgetExpression::Inexpressible
                    })
                    .map(|_| canonical.profile().clone())
                    .into_iter()
                    .collect(),
            )?,
        call.audience()?,
        auths_model::Challenge::new([0x22; 32]),
        auths_model::Timestamp::new(50),
        template.assurance_policy().clone(),
        template.principal_status_snapshot().clone(),
        template.grant_status_snapshot().clone(),
        template.resource_matcher().clone(),
        template.profile_policy().clone(),
        template.channel_policy().clone(),
        template.limits().clone(),
    )?;
    fs::write(
        output.join("mcp.context.cbor"),
        auths_codec::encode_verifier_context(&context)?,
    )?;
    let statement = auths_model::GrantStatement::new(
        root.clone(),
        actor.clone(),
        canonical.profile().clone(),
        auths_model::PermissionSet::new(vec![canonical.permission().clone()])?,
        auths_model::ValidityWindow::new(
            auths_model::Timestamp::new(20),
            auths_model::Timestamp::new(80),
        )?,
        auths_model::AudienceSet::new(vec![call.audience()?])?,
        auths_model::ActionConstraint::AnyBody,
        Some(auths_model::BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1")?,
            20,
        )),
        1,
        None,
        auths_model::StatusPolicy::ExpiryOnly,
        auths_model::AssurancePolicyId::parse("raw-key-baseline")?,
        auths_model::CriticalExtensions::empty(),
    );
    let signing = auths_author::prepare_grant(
        statement,
        auths_model::SignatureDescriptor::new(
            auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?,
            auths_model::VerificationMethod::parse(root.as_str())?,
            auths_model::SignatureSuiteId::parse("ed25519-v1")?,
        ),
    )?;
    let signature = root_key
        .sign(signing.signing_preimage())
        .to_bytes()
        .to_vec();
    let signed = signing.complete(auths_model::SignatureBytes::new(signature)?);
    fs::write(
        output.join("mcp.signed-root-grant.cbor"),
        auths_codec::encode_signed_grant(&signed)?,
    )?;
    let actor_signature = auths_model::SignatureDescriptor::new(
        auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?,
        auths_model::VerificationMethod::parse(actor.as_str())?,
        auths_model::SignatureSuiteId::parse("ed25519-v1")?,
    );
    for (name, file) in [
        ("update_demo_record", "mcp.action-signature.bin"),
        ("delete_demo_record", "mcp.denied-action-signature.bin"),
    ] {
        let action_call = auths_profile_mcp::McpToolCall::new(
            "reports",
            name,
            serde_json::from_value(serde_json::json!({"value": "reviewed"}))?,
        )?;
        let action_canonical =
            auths_profile_mcp::McpProfile.canonicalize(&action_call.canonical_bytes()?)?;
        let prepared = auths_author::prepare_profile_action(
            action_canonical,
            action_call.audience()?,
            actor.clone(),
            &signed,
            [0x22; 32],
            50,
        )?;
        let signing =
            auths_author::prepare_action(prepared.envelope().clone(), actor_signature.clone())?;
        fs::write(
            output.join(file),
            actor_key.sign(signing.signing_preimage()).to_bytes(),
        )?;
    }
    let child_plan = auths_author::plan_child_grant(
        signed.statement(),
        auths_author::GrantRequest::new(
            child.clone(),
            canonical.profile().clone(),
            auths_model::PermissionSet::new(vec![canonical.permission().clone()])?,
            auths_model::ValidityWindow::new(
                auths_model::Timestamp::new(30),
                auths_model::Timestamp::new(70),
            )?,
            auths_model::AudienceSet::new(vec![call.audience()?])?,
            auths_model::ActionConstraint::AnyBody,
            Some(auths_model::BudgetCeiling::new(
                auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1")?,
                10,
            )),
            0,
            auths_model::StatusPolicy::ExpiryOnly,
            auths_model::AssurancePolicyId::parse("raw-key-baseline")?,
            auths_model::CriticalExtensions::empty(),
        ),
    )?;
    let child_diff = child_plan.diff().clone();
    let child_signing = auths_author::prepare_grant(child_plan.into_statement(), actor_signature)?;
    let child_grant_signature = actor_key.sign(child_signing.signing_preimage()).to_bytes();
    let signed_child = child_signing.complete(auths_model::SignatureBytes::new(
        child_grant_signature.to_vec(),
    )?);
    fs::write(
        output.join("mcp.child-grant-signature.bin"),
        child_grant_signature,
    )?;
    fs::write(
        output.join("mcp.signed-child-grant.cbor"),
        auths_codec::encode_signed_grant(&signed_child)?,
    )?;
    let child_action = auths_author::prepare_profile_action(
        canonical.clone(),
        call.audience()?,
        child.clone(),
        &signed_child,
        [0x22; 32],
        50,
    )?;
    let child_action_signing = auths_author::prepare_action(
        child_action.envelope().clone(),
        auths_model::SignatureDescriptor::new(
            auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?,
            auths_model::VerificationMethod::parse(child.as_str())?,
            auths_model::SignatureSuiteId::parse("ed25519-v1")?,
        ),
    )?;
    fs::write(
        output.join("mcp.child-action-signature.bin"),
        child_key
            .sign(child_action_signing.signing_preimage())
            .to_bytes(),
    )?;
    fs::write(
        output.join("mcp.root-evidence.bin"),
        root_descriptor.encode(),
    )?;
    fs::write(
        output.join("mcp.actor-evidence.bin"),
        actor_descriptor.encode(),
    )?;
    fs::write(
        output.join("mcp.child-evidence.bin"),
        child_descriptor.encode(),
    )?;
    fs::write(output.join("mcp.root-seed.bin"), [11; 32])?;
    fs::write(output.join("mcp.actor-seed.bin"), [12; 32])?;
    fs::write(output.join("mcp.child-seed.bin"), [13; 32])?;
    fs::write(output.join("mcp.child-principal.txt"), child.as_str())?;
    write_shared_workflow_projection(
        output,
        &root_descriptor,
        &actor_descriptor,
        &actor_key,
        &actor,
        &signed,
        &context,
        &call,
        &canonical,
        &child_diff,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_shared_workflow_projection(
    output: &std::path::Path,
    root_descriptor: &auths_raw_key::RawKeyDescriptor,
    actor_descriptor: &auths_raw_key::RawKeyDescriptor,
    actor_key: &SigningKey,
    actor: &auths_model::PrincipalId,
    root_grant: &auths_model::SignedGrant,
    context: &auths_model::TrustedContext,
    call: &auths_profile_mcp::McpToolCall,
    canonical: &auths_model::CanonicalAction,
    child_diff: &auths_author::AuthorityDiff,
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = auths_author::prepare_profile_action(
        canonical.clone(),
        call.audience()?,
        actor.clone(),
        root_grant,
        [0x22; 32],
        50,
    )?;
    let signing = auths_author::prepare_action(
        prepared.envelope().clone(),
        auths_model::SignatureDescriptor::new(
            auths_model::PrincipalMethodId::parse(auths_raw_key::RAW_KEY_V1)?,
            auths_model::VerificationMethod::parse(actor.as_str())?,
            auths_model::SignatureSuiteId::parse("ed25519-v1")?,
        ),
    )?;
    let signature = actor_key.sign(signing.signing_preimage());
    let signed_action = signing.complete(auths_model::SignatureBytes::new(
        signature.to_bytes().to_vec(),
    )?);
    let mut proof = auths_author::WorkflowProofBuilder::new();
    let grant_index = proof.push_grant(root_grant.clone())?;
    proof.bind_grant_evidence(
        grant_index,
        auths_author::address_evidence(
            auths_model::EvidenceTypeId::parse(auths_raw_key::RAW_KEY_V1)?,
            auths_model::MediaType::parse("application/vnd.auths.raw-key.v1")?,
            root_descriptor.encode(),
        )?,
    )?;
    proof.bind_action_evidence(auths_author::address_evidence(
        auths_model::EvidenceTypeId::parse(auths_raw_key::RAW_KEY_V1)?,
        auths_model::MediaType::parse("application/vnd.auths.raw-key.v1")?,
        actor_descriptor.encode(),
    )?)?;
    let artifacts = proof.finish(&signed_action, canonical, context)?;
    let proof_cbor = auths_codec::encode_bundle(artifacts.proof())?;
    let action_cbor = auths_codec::encode_canonical_action(canonical)?;
    let context_cbor = auths_codec::encode_verifier_context(artifacts.context())?;
    let result_cbor =
        auths_proof_wasm::verify_self_contained_v1(&proof_cbor, &action_cbor, &context_cbor)?;
    fs::write(output.join("workflow.proof.cbor"), &proof_cbor)?;
    fs::write(output.join("workflow.action.cbor"), &action_cbor)?;
    fs::write(output.join("workflow.context.cbor"), &context_cbor)?;
    fs::write(output.join("workflow.result.cbor"), &result_cbor)?;
    let result = auths_codec::decode_verification_result(&result_cbor)?;
    let member = auths_author::ProfilePlanMember::encode(
        canonical,
        &auths_model::ResourceId::parse("mcp://reports")?,
        &call.audience()?,
    )?;
    let plan = auths_author::ProfilePlanCommitment::commit(
        auths_profile_mcp::PROFILE_ID,
        auths_profile_mcp::PROFILE_VERSION,
        &[member.as_slice(), member.as_slice()],
    )?;
    let plan_approval =
        auths_author::commit_plan_approval(plan.plan().as_bytes(), &[7; 32], 2, 350)?;
    let receipt_signer = auths_receipts::ReceiptSigner::new(
        actor.clone(),
        auths_model::VerificationMethod::parse(actor.as_str())?,
        auths_model::SignatureSuiteId::parse("ed25519-v1")?,
    );
    let decision_receipt = auths_receipts::prepare_decision_receipt(
        auths_codec::proof_digest(artifacts.proof())?,
        canonical,
        artifacts.context(),
        auths_receipts::DecisionClass::Authorized,
        vec!["authorized".to_owned()],
        auths_model::Timestamp::new(60),
        &receipt_signer,
    )?;
    let result_bytes = br#"{"provider":"ok"}"#;
    let plan_digest = auths_model::Digest::new(*plan.plan().as_bytes());
    let execution_receipt = auths_receipts::prepare_execution_receipt(
        decision_receipt.id(),
        "workflow-fixture",
        Some(plan_digest),
        Some((0, 2)),
        &action_cbor,
        auths_receipts::ExecutionOutcome::Succeeded,
        Some(result_bytes),
        auths_model::Timestamp::new(70),
        &receipt_signer,
    )?;
    let execution_lease = auths_receipts::application_execution_lease_digest(
        "workflow-fixture",
        Some(plan_digest),
        Some((0, 2)),
    )?;
    let resources = result.resources();
    let projection = serde_json::json!({
        "schema": "auths.full-workflow-projection/2",
        "verdict": decision_label(result.decision()),
        "stage": stage_label(result.stage()),
        "code": result.code().code(),
        "commitments": {
            "action": hex(auths_codec::domain_commitment("auths.canonical-action.v1", &action_cbor)?.as_bytes()),
            "result": hex(auths_codec::domain_commitment("auths.verification-result.v1", &result_cbor)?.as_bytes()),
            "localConfiguration": hex(auths_codec::domain_commitment(
                "auths.verifier-configuration.v1",
                result.local_configuration().as_bytes(),
            )?.as_bytes()),
            "plan": hex(plan.plan().as_bytes()),
            "planMembers": plan.members().iter().map(|value| hex(value.as_bytes())).collect::<Vec<_>>(),
            "planApproval": hex(plan_approval.as_bytes()),
        },
        "metrics": {
            "proofBytes": resources.proof_bytes(),
            "actionBytes": resources.action_bytes(),
            "contextBytes": resources.context_bytes(),
            "objectCount": resources.object_count(),
            "planLeaves": resources.plan_leaves(),
            "planDepth": resources.plan_depth(),
            "workUnits": resources.work_units(),
        },
        "authorityDiff": {
            "removedPermissions": child_diff.removed_permissions(),
            "removedAudiences": child_diff.removed_audiences(),
            "validityShortened": child_diff.validity_shortened(),
            "actionNarrowed": child_diff.action_narrowed(),
            "budgetNarrowed": child_diff.budget_narrowed(),
            "statusNarrowed": child_diff.status_narrowed(),
            "delegationDepth": child_diff.delegation_depth(),
        },
        "command": {
            "profile": "auths.mcp/1",
            "service": call.service(),
            "name": call.name(),
            "argumentsJson": String::from_utf8(serde_json_canonicalizer::to_vec(call.arguments())?)?,
        },
        "receipts": {
            "signer": {
                "principal": actor.as_str(),
                "verificationMethod": actor.as_str(),
                "suite": "ed25519-v1",
            },
            "decision": {
                "id": hex(decision_receipt.id().as_bytes()),
                "canonical": hex(decision_receipt.canonical()),
                "signingPreimage": hex(decision_receipt.signing_preimage()),
            },
            "execution": {
                "idempotencyKey": "workflow-fixture",
                "memberIndex": 0,
                "memberCount": 2,
                "completedAt": 70,
                "result": hex(result_bytes),
                "lease": hex(execution_lease.as_bytes()),
                "id": hex(execution_receipt.id().as_bytes()),
                "canonical": hex(execution_receipt.canonical()),
                "signingPreimage": hex(execution_receipt.signing_preimage()),
            },
        },
    });
    fs::write(
        output.join("workflow.projection.json"),
        serde_json::to_vec_pretty(&projection)?,
    )?;
    Ok(())
}

fn decision_label(decision: auths_model::VerificationDecision) -> &'static str {
    match decision {
        auths_model::VerificationDecision::Authorized => "authorized",
        auths_model::VerificationDecision::Denied => "denied",
        auths_model::VerificationDecision::Indeterminate => "indeterminate",
    }
}

fn stage_label(stage: auths_model::VerificationStage) -> &'static str {
    match stage {
        auths_model::VerificationStage::Decode => "decode",
        auths_model::VerificationStage::Resolve => "resolve",
        auths_model::VerificationStage::PrincipalControl => "principal-control",
        auths_model::VerificationStage::Authority => "authority",
        auths_model::VerificationStage::Complete => "complete",
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[usize::from(byte >> 4)] as char);
        value.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    value
}

fn delegation_root(
    proposed: &auths_model::GrantStatement,
    signed: &auths_model::SignedGrant,
) -> Result<auths_model::SignedGrant, Box<dyn std::error::Error>> {
    let statement = auths_model::GrantStatement::new(
        proposed.issuer().clone(),
        proposed.subject().clone(),
        proposed.profile().clone(),
        proposed.permissions().clone(),
        auths_model::ValidityWindow::new(
            auths_model::Timestamp::new(0),
            auths_model::Timestamp::new(100),
        )?,
        proposed.audiences().clone(),
        auths_model::ActionConstraint::AnyBody,
        Some(auths_model::BudgetCeiling::new(
            proposed
                .budget_ceiling()
                .ok_or("raw-key chain omitted its budget")?
                .algebra()
                .clone(),
            20,
        )),
        2,
        None,
        auths_model::StatusPolicy::SnapshotRequired {
            method: auths_model::StatusMethodId::parse("status.test-v1")?,
            max_age: auths_model::FreshnessLimit::new(60)?,
        },
        proposed.assurance_floor().clone(),
        auths_model::CriticalExtensions::new(vec![auths_model::CriticalExtension::new(
            auths_model::ExtensionId::parse("extension.test-v1")?,
            vec![1, 2, 3],
        )?])?,
    );
    Ok(auths_model::SignedGrant::new(
        statement,
        signed.signature().clone(),
    ))
}
