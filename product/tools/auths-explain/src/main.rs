#![forbid(unsafe_code)]

use auths_codec::{decode_canonical_action, decode_verifier_context};
use auths_did_keri::DidKeriMethod;
use auths_did_key::DidKeyMethod;
use auths_did_web::DidWebMethod;
use auths_hsm_attested::HsmAttestedMethod;
use auths_operations::{
    explanation::{DisclosurePolicy, explain},
    render::{render_json, render_text},
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_registries::ImmutableRegistries;
use auths_signature::{Ed25519Suite, P256Sha256Suite};
use auths_spiffe_x509::SpiffeX509Method;
use auths_verifier::{VerificationOutcome, verify_explained};
use auths_webauthn::WebAuthnMethod;
use std::{env, fs, path::PathBuf, process::ExitCode};

struct Arguments {
    proof: PathBuf,
    action: PathBuf,
    context: PathBuf,
    engine_config: PathBuf,
    disclosure: DisclosurePolicy,
    format: String,
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("auths explain: {error}");
            ExitCode::from(4)
        }
    }
}

fn value(args: &[String], name: &str) -> Result<String, String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
        .ok_or_else(|| format!("missing {name}"))
}

fn arguments() -> Result<Arguments, String> {
    let args: Vec<_> = env::args().skip(1).collect();
    let disclosure = match value(&args, "--disclosure")
        .unwrap_or_else(|_| "summary".to_owned())
        .as_str()
    {
        "summary" => DisclosurePolicy::Summary,
        "operator" => DisclosurePolicy::Operator,
        "audit" => DisclosurePolicy::Audit,
        value => return Err(format!("unsupported disclosure {value}")),
    };
    let output = value(&args, "--output").ok().map(PathBuf::from);
    if disclosure == DisclosurePolicy::Audit && output.is_none() {
        return Err("audit disclosure requires --output".to_owned());
    }
    Ok(Arguments {
        proof: value(&args, "--proof")?.into(),
        action: value(&args, "--action")?.into(),
        context: value(&args, "--context")?.into(),
        engine_config: value(&args, "--engine-config")?.into(),
        disclosure,
        format: value(&args, "--format").unwrap_or_else(|_| "text".to_owned()),
        output,
    })
}

fn run() -> Result<u8, String> {
    let args = arguments()?;
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(&args.engine_config).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if config.get("profile").and_then(serde_json::Value::as_str) != Some("target-v1-corpus") {
        return Err("engine config must select the offline target-v1-corpus profile".to_owned());
    }

    let proof = fs::read(&args.proof).map_err(|error| error.to_string())?;
    let context_bytes = fs::read(&args.context).map_err(|error| error.to_string())?;
    let action_bytes = fs::read(&args.action).map_err(|error| error.to_string())?;
    let context = decode_verifier_context(&context_bytes).map_err(|error| error.to_string())?;
    let action = decode_canonical_action(&action_bytes, context.limits())
        .map_err(|error| error.to_string())?;

    let raw = RawKeyMethod::new().map_err(|error| error.to_string())?;
    let did_key = DidKeyMethod::new().map_err(|error| error.to_string())?;
    let did_keri = DidKeriMethod::new().map_err(|error| error.to_string())?;
    let did_web = DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
        .map_err(|error| error.to_string())?;
    let webauthn = WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
        .map_err(|error| error.to_string())?;
    let hsm = HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
        .map_err(|error| error.to_string())?;
    let (domains, status) = auths_testkit::spiffe_corpus_context();
    let spiffe = SpiffeX509Method::new(domains, status).map_err(|error| error.to_string())?;
    let ed25519 = Ed25519Suite::new().map_err(|error| error.to_string())?;
    let p256 = P256Sha256Suite::new().map_err(|error| error.to_string())?;
    let methods: [&dyn PrincipalMethod; 7] = [
        &raw, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries =
        ImmutableRegistries::new(&methods, &suites).map_err(|error| error.to_string())?;

    let verification = verify_explained(&proof, &action, &context, &registries)
        .map_err(|error| format!("trace reservation failed: {error:?}"))?;
    let report = explain(
        &verification,
        &proof,
        &action,
        &context,
        &registries,
        args.disclosure,
    )
    .map_err(|error| error.to_string())?;
    let rendered = match args.format.as_str() {
        "text" => render_text(&report, 100),
        "json" => render_json(&report),
        value => return Err(format!("unsupported format {value}")),
    }
    .map_err(|error| error.to_string())?;
    if let Some(output) = args.output {
        fs::write(output, rendered).map_err(|error| error.to_string())?;
    } else {
        println!("{rendered}");
    }
    Ok(match verification.outcome() {
        VerificationOutcome::Authorized(_) => 0,
        VerificationOutcome::Denied(_) => 2,
        VerificationOutcome::Indeterminate(_) => 3,
    })
}
