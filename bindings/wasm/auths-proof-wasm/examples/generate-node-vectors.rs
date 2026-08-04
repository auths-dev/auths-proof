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
    write_mcp_workflow_vectors(&output)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn write_mcp_workflow_vectors(output: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let root_key = SigningKey::from_bytes(&[11; 32]);
    let actor_key = SigningKey::from_bytes(&[12; 32]);
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
    let root = root_descriptor.principal()?;
    let actor = actor_descriptor.principal()?;
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
        1,
        auths_model::AssurancePolicyId::parse("raw-key-baseline")?,
        auths_model::StatusPolicy::ExpiryOnly,
    )?;
    let context = auths_model::VerifierContext::new(
        template.configuration(),
        template.composition(),
        vec![anchor],
        template.accepted_registries().clone(),
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
        actor,
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
        0,
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
    fs::write(
        output.join("mcp.root-evidence.bin"),
        root_descriptor.encode(),
    )?;
    fs::write(
        output.join("mcp.actor-evidence.bin"),
        actor_descriptor.encode(),
    )?;
    fs::write(output.join("mcp.root-seed.bin"), [11; 32])?;
    fs::write(output.join("mcp.actor-seed.bin"), [12; 32])?;
    Ok(())
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
