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

    let bundle = auths_codec::decode_bundle(proof, &auths_model::VerifierLimits::default_deployment())?;
    let proposed = bundle
        .grants()
        .first()
        .ok_or("raw-key chain omitted its grant")?
        .statement();
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
