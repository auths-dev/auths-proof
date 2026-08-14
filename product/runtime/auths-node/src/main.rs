#![forbid(unsafe_code)]

use auths_node::{NodeConfig, NodeRuntime, PostgresSandboxStore, SandboxRuntime, app, shutdown};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    env,
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
    let connection = env::var(config.lifecycle_url_env())
        .map_err(|_| "PostgreSQL lifecycle connection is unavailable")?;
    let store = PostgresSandboxStore::connect(
        &connection,
        config.lifecycle_ca_pem(),
        config.lifecycle_server_name(),
        config.maximum_lifecycle_records(),
    )?;
    let runtime = Arc::new(SandboxRuntime::with_postgres(
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
