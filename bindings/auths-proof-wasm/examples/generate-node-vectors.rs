use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        env::args()
            .nth(1)
            .ok_or("expected generated-package output directory")?,
    );
    fs::create_dir_all(&output)?;
    let proof = include_bytes!("../../../fixtures/v1/valid/raw-key-chain.proof.cbor");
    let action = include_bytes!("../../../fixtures/v1/valid/raw-key-chain.action.cbor");
    let context = include_bytes!("../../../fixtures/v1/valid/raw-key-chain.context.cbor");
    let context = auths_codec::decode_verifier_context(context)?.with_configuration(
        auths_model::VerifierConfigurationId::new(
            auths_proof_wasm::self_contained_v1_configuration()?,
        ),
    )?;
    let context = auths_codec::encode_verifier_context(&context)?;
    let result = auths_proof_wasm::verify_self_contained_v1(proof, action, &context)?;
    fs::write(output.join("authorized.context.cbor"), context)?;
    fs::write(output.join("authorized.result.cbor"), result)?;
    Ok(())
}
