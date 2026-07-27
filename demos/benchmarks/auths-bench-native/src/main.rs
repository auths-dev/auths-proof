#![forbid(unsafe_code)]

use auths_bench_model::{
    BenchmarkInput, BenchmarkProfile, BenchmarkResult, Environment, RunArtifact, SemanticRecord,
    hex_digest, statistics, validate_result,
};
use auths_codec::decode_verification_result;
use auths_did_keri::DidKeriMethod;
use auths_did_key::DidKeyMethod;
use auths_did_web::DidWebMethod;
use auths_hsm_attested::HsmAttestedMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_registries::ImmutableRegistries;
use auths_signature::{Ed25519Suite, P256Sha256Suite};
use auths_spiffe_x509::SpiffeX509Method;
use auths_verifier::verify_v1;
use auths_webauthn::WebAuthnMethod;
use sha2::{Digest as _, Sha256};
use std::{
    env, fs,
    hint::black_box,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths-bench-native: {error}");
            ExitCode::FAILURE
        }
    }
}

fn benchmark_input(
    input: &BenchmarkInput,
    profile: &BenchmarkProfile,
    registries: &ImmutableRegistries<'_>,
) -> Result<BenchmarkResult, String> {
    let preflight = verify_v1(
        &input.proof_cbor,
        &input.canonical_action_cbor,
        &input.trusted_context_cbor,
        registries,
    )
    .map_err(|error| error.to_string())?;
    let preflight_decoded =
        decode_verification_result(&preflight).map_err(|error| error.to_string())?;
    let expected_decision = format!("{:?}", preflight_decoded.decision()).to_ascii_lowercase();
    let expected_code = preflight_decoded.code().code().to_owned();
    if expected_decision != input.scenario.expected.decision
        || expected_code != input.scenario.expected.code
    {
        return Err(format!(
            "semantic preflight drift for {}",
            input.scenario.id
        ));
    }

    let warmup_started = Instant::now();
    while warmup_started.elapsed() < Duration::from_millis(profile.warmup_ms) {
        black_box(
            verify_v1(
                black_box(&input.proof_cbor),
                black_box(&input.canonical_action_cbor),
                black_box(&input.trusted_context_cbor),
                black_box(registries),
            )
            .map_err(|error| error.to_string())?,
        );
    }

    let mut samples = Vec::with_capacity(profile.samples);
    for _ in 0..profile.samples {
        let started = Instant::now();
        for _ in 0..profile.operations_per_sample {
            black_box(
                verify_v1(
                    black_box(&input.proof_cbor),
                    black_box(&input.canonical_action_cbor),
                    black_box(&input.trusted_context_cbor),
                    black_box(registries),
                )
                .map_err(|error| error.to_string())?,
            );
        }
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        samples.push(elapsed / u64::try_from(profile.operations_per_sample).unwrap_or(1));
    }
    let postflight = verify_v1(
        &input.proof_cbor,
        &input.canonical_action_cbor,
        &input.trusted_context_cbor,
        registries,
    )
    .map_err(|error| error.to_string())?;
    if postflight != preflight {
        return Err(format!(
            "semantic postflight drift for {}",
            input.scenario.id
        ));
    }
    let resources = preflight_decoded.resources();
    let result = BenchmarkResult {
        schema: "auths-proof-benchmark-result/v1".to_owned(),
        revision: option_env!("AUTHS_BENCH_REVISION")
            .unwrap_or("unknown")
            .to_owned(),
        dirty: option_env!("AUTHS_BENCH_DIRTY").unwrap_or("true") != "false",
        target: env::consts::ARCH.to_owned(),
        environment: Environment {
            os: env::consts::OS.to_owned(),
            arch: env::consts::ARCH.to_owned(),
            cpu: "unknown".to_owned(),
            logical_cores: std::thread::available_parallelism().map_or(0, usize::from),
            memory_bytes: 0,
            runtime: "native".to_owned(),
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            rustc: option_env!("RUSTC_VERSION").unwrap_or("unknown").to_owned(),
            power_mode: "unknown".to_owned(),
            virtualized: "unknown".to_owned(),
        },
        scenario: input.scenario.id.clone(),
        input_sha256: hex_digest(input.input_digest),
        semantic: SemanticRecord {
            decision: expected_decision,
            code: expected_code,
            result_sha256: hex_digest(Sha256::digest(&preflight).into()),
            work_units: resources.work_units(),
            proof_bytes: resources.proof_bytes(),
            context_bytes: resources.context_bytes(),
            plan_leaves: resources.plan_leaves(),
            plan_depth: resources.plan_depth(),
        },
        summary: statistics(&samples),
        samples_ns: samples,
    };
    validate_result(input, &result).map_err(|error| error.to_string())?;
    Ok(result)
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("usage: auths-bench-native <inputs.json> <output.json> [paper]")?,
    );
    let output = PathBuf::from(args.next().ok_or("missing output path")?);
    let profile = if args.next().as_deref() == Some("paper") {
        BenchmarkProfile::paper()
    } else {
        BenchmarkProfile::developer()
    };
    let inputs: Vec<BenchmarkInput> = serde_json::from_slice(
        &fs::read(&input)
            .map_err(|error| format!("could not read {}: {error}", input.display()))?,
    )
    .map_err(|error| format!("invalid benchmark inputs: {error}"))?;

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

    let results = inputs
        .iter()
        .map(|input| benchmark_input(input, &profile, &registries))
        .collect::<Result<Vec<_>, _>>()?;
    let artifact = RunArtifact {
        schema: "auths-proof-benchmark-run/v1".to_owned(),
        profile,
        results,
    };
    let bytes = serde_json::to_vec_pretty(&artifact).map_err(|error| error.to_string())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(output, bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_bench_model::generate_suite;

    #[test]
    fn native_runner_preserves_shared_input_semantics() {
        let profile = BenchmarkProfile {
            name: "test".to_owned(),
            warmup_ms: 0,
            samples: 1,
            operations_per_sample: 1,
        };
        let input = generate_suite(&profile)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let raw = RawKeyMethod::new().unwrap();
        let did_key = DidKeyMethod::new().unwrap();
        let did_keri = DidKeriMethod::new().unwrap();
        let did_web = DidWebMethod::new(auths_testkit::did_web_corpus_trust_records()).unwrap();
        let webauthn = WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials()).unwrap();
        let hsm = HsmAttestedMethod::new(auths_testkit::hsm_corpus_records()).unwrap();
        let (domains, status) = auths_testkit::spiffe_corpus_context();
        let spiffe = SpiffeX509Method::new(domains, status).unwrap();
        let ed25519 = Ed25519Suite::new().unwrap();
        let p256 = P256Sha256Suite::new().unwrap();
        let methods: [&dyn PrincipalMethod; 7] = [
            &raw, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
        ];
        let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();

        let result = benchmark_input(&input, &profile, &registries).unwrap();
        assert_eq!(result.scenario, input.scenario.id);
        assert_eq!(result.input_sha256, hex_digest(input.input_digest));
        assert_eq!(result.semantic.decision, input.scenario.expected.decision);
        assert_eq!(result.semantic.code, input.scenario.expected.code);
    }
}
