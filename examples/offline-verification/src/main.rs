use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_proof::{Engine, Verdict};

const PROOF: &[u8] = include_bytes!("../../../core/fixtures/v1/valid/raw-key-chain.proof.cbor");
const ACTION: &[u8] = include_bytes!("../../../core/fixtures/v1/valid/raw-key-chain.action.cbor");
const TRUSTED_CONTEXT: &[u8] =
    include_bytes!("../../../core/fixtures/v1/valid/raw-key-chain.context.cbor");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let method = auths_raw_key::RawKeyMethod::new()?;
    let suite = auths_signature::Ed25519Suite::new()?;
    let methods: [&dyn PrincipalMethod; 1] = [&method];
    let suites: [&dyn SignatureSuite; 1] = [&suite];
    let registries = auths_registries::ImmutableRegistries::new(&methods, &suites)?;

    // The trusted host, not the proof producer, commits the exact executable
    // configuration and required composition policy.
    let context = auths_codec::decode_verifier_context(TRUSTED_CONTEXT)?
        .with_configuration(registries.configuration_id())?;
    let required_plan = context
        .composition()
        .expected_plan()
        .ok_or("example context must require an exact plan")?;
    let context_bytes = auths_codec::encode_verifier_context(&context)?;

    let result = Engine::new(registries).verify_cbor(PROOF, ACTION, &context_bytes)?;
    let explanation = result.explanation();
    let portable = result.portable();
    let resources = result.resources();
    println!(
        "verdict={:?} code={} stage={:?} retryable={} work_units={}",
        result.verdict(),
        result.code(),
        explanation.stage(),
        explanation.retryable(),
        resources.work_units()
    );
    println!(
        "proof={:?} action={:?} context={:?} required_configuration={:?} local_configuration={:?}",
        portable.proof_digest().as_bytes(),
        portable.action_digest().as_bytes(),
        portable.context_digest().as_bytes(),
        portable
            .required_configuration()
            .map(|configuration| *configuration.as_bytes()),
        portable.local_configuration().as_bytes()
    );

    match result.verdict() {
        Verdict::Authorized => {
            if portable.plan_id() != Some(required_plan) {
                return Err("authorized result did not satisfy the host-required plan".into());
            }
            Ok(())
        }
        Verdict::Denied => Err(format!("stable authorization denial: {}", result.code()).into()),
        Verdict::Indeterminate => Err(format!(
            "not authorized; obtain new trusted facts before retrying: {}",
            result.code()
        )
        .into()),
    }
}
