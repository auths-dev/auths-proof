#![forbid(unsafe_code)]

use auths_node::{
    KernelRuntime, NodeConfig, NodeKernel, NodeRuntime, PostgresSandboxStore, app, shutdown,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    env, fs,
    path::Path,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths-node: {error}");
            ExitCode::from(1)
        }
    }
}

/// Builds the deployment's verification inputs from configuration.
///
/// The trusted context is supplied as canonical bytes rather than assembled
/// from TOML: it is the deployment's complete trust decision, and re-encoding it
/// from a friendlier format would put a second, unverified encoder between the
/// operator and the verifier.
///
/// The registered principal methods are the three that need no external trust
/// material. `did:web`, `WebAuthn`, HSM attestation, and SPIFFE each require
/// deployment-supplied trust records that this configuration does not yet carry;
/// a proof relying on one of them is answered `core.authorization-indeterminate`
/// rather than accepted, which is the fail-closed direction.
fn kernel(config: &NodeConfig) -> Result<NodeKernel, Box<dyn std::error::Error>> {
    let bytes = fs::read(config.trusted_context_path())
        .map_err(|_| "the trusted context is unavailable")?;
    let context = auths_codec::decode_verifier_context(&bytes)
        .map_err(|_| "the trusted context is not canonical")?;
    Ok(NodeKernel::with_built_ins(context)?)
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let config_path = arguments
        .next()
        .ok_or("usage: auths-node <config> [doctor]")?;
    let command = arguments.next();
    if arguments.next().is_some() || command.as_deref().is_some_and(|value| value != "doctor") {
        return Err("usage: auths-node <config> [doctor]".into());
    }
    let config = NodeConfig::from_path(Path::new(&config_path))?;
    if !config.sandbox_providers() {
        if command.as_deref() == Some("doctor") {
            println!("{}", serde_json::to_string_pretty(&config.doctor(false))?);
        }
        return Err("production ports must be assembled with the auths-node library".into());
    }
    let seed_slot = config
        .fixture_seed_env()
        .ok_or("local fixture custody is not configured")?;
    let seed = env::var(seed_slot).map_err(|_| "local fixture custody seed is unavailable")?;
    let mut seed_bytes = [0; 32];
    Base64UrlUnpadded::decode(&seed, &mut seed_bytes)
        .map_err(|_| "local fixture custody seed is malformed")?;
    let kernel = kernel(&config)?;
    let connection = env::var(config.lifecycle_url_env())
        .map_err(|_| "PostgreSQL lifecycle connection is unavailable")?;
    let lifecycle_ca_pem = config.lifecycle_ca_pem().to_owned();
    let lifecycle_server_name = config.lifecycle_server_name().to_owned();
    let maximum_lifecycle_records = config.maximum_lifecycle_records();
    let store = tokio::task::spawn_blocking(move || {
        PostgresSandboxStore::connect(
            &connection,
            &lifecycle_ca_pem,
            &lifecycle_server_name,
            maximum_lifecycle_records,
        )
    })
    .await??;
    let runtime = Arc::new(KernelRuntime::with_postgres(
        kernel,
        seed_bytes,
        config.enabled_profiles(),
        store,
    )?);
    if command.as_deref() == Some("doctor") {
        let report = config.doctor(runtime.ready());
        println!("{}", serde_json::to_string_pretty(&report)?);
        return if report.ready {
            Ok(())
        } else {
            Err("one or more required dependencies are unavailable".into())
        };
    }
    let accepting = Arc::new(AtomicBool::new(true));
    let router = app(&config, runtime, Arc::clone(&accepting));
    let listener = tokio::net::TcpListener::bind(config.bind()).await?;
    println!(
        "auths-node release={} semantic={} listening={}",
        config.release(),
        config.semantic_id(),
        config.bind()
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::drain(
            accepting,
            config.drain_timeout(),
            shutdown::termination_signal(),
        ))
        .await?;
    Ok(())
}
