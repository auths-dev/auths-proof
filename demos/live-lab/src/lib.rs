#![forbid(unsafe_code)]

use auths_apps_testkit::{DemoFixtureBytes, demo_fixture_bytes, run_memory_demo, run_replay_demo};
use auths_model::{
    VerificationDecision, VerificationResources, VerificationStage, VerifierConfigurationId,
};
use auths_proof_exchange_model::{ActionResponse, ExchangeOutcome, RefusalKind, VerdictDecision};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

const INDEX_HTML: &[u8] = include_bytes!("../web/index.html");
const APP_JS: &[u8] = include_bytes!("../web/app.js");
const LAB_CORE_JS: &[u8] = include_bytes!("../web/lab-core.js");
const PACKAGE_JSON: &[u8] = include_bytes!("../package.json");
const STYLES_CSS: &[u8] = include_bytes!("../web/styles.css");
const VERCEL_JSON: &[u8] = include_bytes!("../web/vercel.json");

#[derive(Debug)]
pub enum BuildError {
    Codec(auths_codec::CodecError),
    Engine(auths_proof_wasm::EngineError),
    Io(io::Error),
    Json(serde_json::Error),
    MissingVendor(PathBuf),
    Model(auths_model::ModelError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "could not encode demo fixture: {error}"),
            Self::Engine(error) => write!(formatter, "demo verifier failed: {error}"),
            Self::Io(error) => write!(formatter, "could not write demo bundle: {error}"),
            Self::Json(error) => write!(formatter, "could not encode demo metadata: {error}"),
            Self::MissingVendor(path) => {
                write!(
                    formatter,
                    "required generated browser SDK is missing: {}",
                    path.display()
                )
            }
            Self::Model(error) => write!(formatter, "invalid demo model: {error}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<auths_codec::CodecError> for BuildError {
    fn from(error: auths_codec::CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<auths_proof_wasm::EngineError> for BuildError {
    fn from(error: auths_proof_wasm::EngineError) -> Self {
        Self::Engine(error)
    }
}

impl From<auths_model::ModelError> for BuildError {
    fn from(error: auths_model::ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<io::Error> for BuildError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BuildError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub struct GeneratedVariant {
    pub id: &'static str,
    pub proof: Vec<u8>,
    pub action: Vec<u8>,
    pub context: Vec<u8>,
    pub result: Vec<u8>,
    pub projection: Value,
}

pub struct GeneratedBundle {
    pub scenario: Value,
    pub variants: Vec<GeneratedVariant>,
}

#[must_use]
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .components()
        .collect()
}

/// Generates the complete static browser lab from repository-owned artifacts.
///
/// # Errors
///
/// Returns an error when verifier inputs cannot be generated, required
/// TypeScript/WASM artifacts are absent, or the output cannot be written.
pub async fn build_site(repository: &Path, output: &Path) -> Result<(), BuildError> {
    let sdk = repository.join("bindings/typescript");
    let wasm = sdk.join("wasm/auths_proof_wasm_bg.wasm");
    if !wasm.is_file() {
        return Err(BuildError::MissingVendor(wasm));
    }
    let release_id =
        std::env::var("AUTHS_LIVE_RELEASE_ID").unwrap_or_else(|_| "development".to_owned());
    let wasm_sha256 = sha256(&fs::read(&wasm)?);
    let bundle = generate_release_bundle(&release_id, &wasm_sha256).await?;
    write(output.join("index.html"), INDEX_HTML)?;
    write(output.join("app.js"), APP_JS)?;
    write(output.join("lab-core.js"), LAB_CORE_JS)?;
    write(output.join("package.json"), PACKAGE_JSON)?;
    write(output.join("styles.css"), STYLES_CSS)?;
    write(output.join("vercel.json"), VERCEL_JSON)?;

    copy_javascript_tree(&sdk.join("dist"), &output.join("vendor/dist"))?;
    for name in [
        "auths_proof_wasm.js",
        "auths_proof_wasm_bg.wasm",
        "auths_proof_wasm.d.ts",
        "auths_proof_wasm_bg.wasm.d.ts",
    ] {
        copy_required(
            &sdk.join("wasm").join(name),
            &output.join("vendor/wasm").join(name),
        )?;
    }

    let scenario = serde_json::to_vec_pretty(&bundle.scenario)?;
    write(output.join("assets/scenario.json"), &scenario)?;
    for variant in bundle.variants {
        let directory = output.join("assets").join(variant.id);
        write(directory.join("proof.cbor"), &variant.proof)?;
        write(directory.join("action.cbor"), &variant.action)?;
        write(directory.join("context.cbor"), &variant.context)?;
        write(directory.join("native-result.cbor"), &variant.result)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
/// Generates a development-identified scenario bundle.
///
/// # Errors
///
/// Returns an error when fixture encoding or native verification fails.
pub async fn generate_bundle() -> Result<GeneratedBundle, BuildError> {
    generate_release_bundle("development", "development").await
}

/// Generates a scenario bundle bound to an immutable release and WASM digest.
///
/// # Errors
///
/// Returns an error when fixture encoding, native verification, or runtime
/// evidence generation fails.
pub async fn generate_release_bundle(
    release_id: &str,
    wasm_sha256: &str,
) -> Result<GeneratedBundle, BuildError> {
    let fixture = demo_fixture_bytes();
    let variants = generate_variants(fixture)?;
    let native = run_memory_demo().await;
    let replay = run_replay_demo().await;
    let configuration = hex::encode(auths_proof_wasm::self_contained_v1_configuration()?);
    let action_digest = sha256(&variants[0].action);
    let proof_digest = sha256(&variants[0].proof);
    let context_digest = sha256(&variants[0].context);
    let root_principal = demo_fixture_bytes().root_principal;
    let scenario = json!({
        "schema": "auths-live-lab/v1",
        "release": {
            "id": release_id,
            "protocol_major": 1,
            "portable_abi": 2,
            "verifier_configuration": configuration,
            "wasm_sha256": wasm_sha256,
            "wasm_engine": "auths-proof-wasm/self-contained-v1",
            "native_engine": "auths-proof-wasm/native-self-contained-v1",
        },
        "action": {
            "profile": "auths.mcp/1",
            "service": "reports",
            "tool": "read_report",
            "arguments": { "name": "q3" },
            "audience": "mcp://reports",
            "canonical_sha256": action_digest,
        },
        "proof": {
            "root_principal": root_principal,
            "proof_sha256": proof_digest,
            "context_sha256": context_digest,
            "plan": "one exact proof branch",
            "assurance": "self-certifying raw-key control",
        },
        "runtime": {
            "first_execution": response_projection(&native.response),
            "transport": native.path,
            "proof_bytes": native.proof_bytes,
            "executor_invocations": native.executor_invocations,
            "decision_receipts": native.decision_receipts,
            "execution_receipts": native.execution_receipts,
            "replay": response_projection(&replay.replay),
            "replay_executor_invocations": replay.executor_invocations,
            "replay_decision_receipts": replay.decision_receipts,
            "replay_execution_receipts": replay.execution_receipts,
        },
        "variants": variants
            .iter()
            .map(|variant| variant.projection.clone())
            .collect::<Vec<_>>(),
    });
    Ok(GeneratedBundle { scenario, variants })
}

/// Produces the repository-owned valid and adversarial verifier variants.
///
/// # Errors
///
/// Returns an error when the fixture cannot be mutated into valid model
/// inputs or the native portable verifier fails.
pub fn generate_variants(fixture: DemoFixtureBytes) -> Result<Vec<GeneratedVariant>, BuildError> {
    let mut tampered_action = fixture.canonical_action.clone();
    if let Some(last) = tampered_action.last_mut() {
        *last ^= 1;
    }
    let mut tampered_proof = fixture.proof.clone();
    if let Some(last) = tampered_proof.last_mut() {
        *last ^= 1;
    }
    let wrong_context = auths_codec::decode_verifier_context(&fixture.context)?
        .with_configuration(VerifierConfigurationId::new([0xa5; 32]))?;
    let wrong_context = auths_codec::encode_verifier_context(&wrong_context)?;

    let specifications = [
        (
            "valid",
            "Valid exact action",
            "The proof and trusted context authorize the exact MCP call.",
            fixture.proof.clone(),
            fixture.canonical_action.clone(),
            fixture.context.clone(),
        ),
        (
            "tampered-action",
            "Action byte changed",
            "One canonical action byte changes after approval.",
            fixture.proof.clone(),
            tampered_action,
            fixture.context.clone(),
        ),
        (
            "tampered-proof",
            "Proof byte changed",
            "One signed proof byte changes in transit.",
            tampered_proof,
            fixture.canonical_action.clone(),
            fixture.context.clone(),
        ),
        (
            "wrong-configuration",
            "Wrong verifier configuration",
            "The trusted context requires a configuration this engine did not execute.",
            fixture.proof,
            fixture.canonical_action.clone(),
            wrong_context,
        ),
    ];
    let mut variants = Vec::new();
    for (id, title, description, proof, action, context) in specifications {
        let result = auths_proof_wasm::verify_self_contained_v1(&proof, &action, &context)?;
        let decoded = auths_codec::decode_verification_result(&result)?;
        variants.push(GeneratedVariant {
            id,
            proof,
            action,
            context,
            projection: json!({
                "id": id,
                "title": title,
                "description": description,
                "native": portable_projection(&decoded, &result),
                "files": {
                    "proof": format!("assets/{id}/proof.cbor"),
                    "action": format!("assets/{id}/action.cbor"),
                    "context": format!("assets/{id}/context.cbor"),
                    "result": format!("assets/{id}/native-result.cbor"),
                },
            }),
            result,
        });
    }

    Ok(variants)
}

fn portable_projection(result: &auths_model::PortableVerificationResult, bytes: &[u8]) -> Value {
    let resources = result.resources();
    json!({
        "decision": decision_name(result.decision()),
        "stage": stage_name(result.stage()),
        "code": result.code().code(),
        "result_sha256": sha256(bytes),
        "required_configuration": result
            .required_configuration()
            .map(|configuration| hex::encode(configuration.as_bytes())),
        "executed_configuration": hex::encode(result.local_configuration().as_bytes()),
        "metrics": resource_projection(resources),
    })
}

fn resource_projection(resources: VerificationResources) -> Value {
    json!({
        "proof_bytes": resources.proof_bytes(),
        "action_bytes": resources.action_bytes(),
        "context_bytes": resources.context_bytes(),
        "object_count": resources.object_count(),
        "plan_leaves": resources.plan_leaves(),
        "plan_depth": resources.plan_depth(),
        "work_units": resources.work_units(),
    })
}

const fn decision_name(decision: VerificationDecision) -> &'static str {
    match decision {
        VerificationDecision::Authorized => "authorized",
        VerificationDecision::Denied => "denied",
        VerificationDecision::Indeterminate => "indeterminate",
    }
}

const fn stage_name(stage: VerificationStage) -> &'static str {
    match stage {
        VerificationStage::Decode => "decode",
        VerificationStage::Resolve => "resolve",
        VerificationStage::PrincipalControl => "principal-control",
        VerificationStage::Authority => "authority",
        VerificationStage::Complete => "complete",
    }
}

fn response_projection(response: &ActionResponse) -> Value {
    let request_id = response.request_id().map(hex::encode);
    match response.outcome() {
        ExchangeOutcome::Completed { result } => json!({
            "outcome": "completed",
            "request_id": request_id,
            "result_sha256": sha256(result),
        }),
        ExchangeOutcome::Refused {
            kind,
            verdict,
            message,
        } => json!({
            "outcome": "refused",
            "kind": refusal_name(*kind),
            "message": message,
            "verdict": verdict.as_ref().map(|summary| json!({
                "decision": verdict_name(summary.decision()),
                "reasons": summary.reasons(),
            })),
            "request_id": request_id,
        }),
    }
}

const fn refusal_name(kind: RefusalKind) -> &'static str {
    match kind {
        RefusalKind::ApplicationPolicy => "application-policy",
        RefusalKind::TransportPolicy => "transport-policy",
        RefusalKind::AuthsVerdict => "auths-verdict",
        RefusalKind::MalformedInput => "malformed-input",
        RefusalKind::OversizedInput => "oversized-input",
        RefusalKind::UnknownChallenge => "unknown-challenge",
        RefusalKind::ExpiredChallenge => "expired-challenge",
        RefusalKind::ConsumedChallenge => "consumed-challenge",
    }
}

const fn verdict_name(decision: VerdictDecision) -> &'static str {
    match decision {
        VerdictDecision::Authorized => "authorized",
        VerdictDecision::Denied => "denied",
        VerdictDecision::Indeterminate => "indeterminate",
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write(path: PathBuf, bytes: &[u8]) -> Result<(), BuildError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn copy_required(source: &Path, destination: &Path) -> Result<(), BuildError> {
    if !source.is_file() {
        return Err(BuildError::MissingVendor(source.to_owned()));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    Ok(())
}

fn copy_javascript_tree(source: &Path, destination: &Path) -> Result<(), BuildError> {
    if !source.is_dir() {
        return Err(BuildError::MissingVendor(source.to_owned()));
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_javascript_tree(&source_path, &destination_path)?;
        } else if source_path.extension().and_then(std::ffi::OsStr::to_str) == Some("js") {
            copy_required(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scenario_is_built_from_real_verifiers_and_runtime() {
        let bundle = generate_bundle().await.unwrap();
        let variants = bundle.scenario["variants"].as_array().unwrap();
        assert_eq!(variants.len(), 4);
        assert_eq!(variants[0]["native"]["decision"], "authorized");
        assert_eq!(
            variants[0]["native"]["required_configuration"],
            variants[0]["native"]["executed_configuration"]
        );
        assert!(
            variants[1..]
                .iter()
                .all(|variant| variant["native"]["decision"] != "authorized")
        );
        assert_eq!(
            variants[3]["native"]["code"],
            "verifier-configuration-mismatch"
        );
        assert_ne!(
            variants[3]["native"]["required_configuration"],
            variants[3]["native"]["executed_configuration"]
        );
        assert_eq!(bundle.scenario["runtime"]["executor_invocations"], 1);
        assert_eq!(
            bundle.scenario["runtime"]["replay"]["kind"],
            "consumed-challenge"
        );
        assert_eq!(bundle.scenario["runtime"]["replay_executor_invocations"], 1);
        assert_eq!(bundle.scenario["runtime"]["decision_receipts"], 1);
        assert_eq!(bundle.scenario["runtime"]["execution_receipts"], 1);
    }
}
