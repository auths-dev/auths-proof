#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use auths_proof_exchange_iroh::ALPN_V1;
use auths_records_demo::app::{AppConfig, app_with_iroh, send_envelope_file, serve_iroh};
use clap::{Parser, Subcommand};
use iroh::{Endpoint, endpoint::presets};

#[derive(Parser)]
#[command(name = "auths-records-demo")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Send {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        envelope: PathBuf,
    },
}

fn main() -> ExitCode {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("auths-records-demo: could not create runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(Command::Send { endpoint, envelope }) = cli.command {
        return runtime.block_on(async move {
            match send_envelope_file(&endpoint, &envelope).await {
                Ok(result) => match serde_json::to_string_pretty(&result) {
                    Ok(json) => {
                        println!("{json}");
                        ExitCode::SUCCESS
                    }
                    Err(_) => ExitCode::FAILURE,
                },
                Err(error) => {
                    eprintln!("auths-records-demo: {error}");
                    ExitCode::FAILURE
                }
            }
        });
    }
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("auths-records-demo: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let endpoint = match Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_V1.to_vec()])
            .bind()
            .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                eprintln!("auths-records-demo: could not bind Iroh endpoint: {error}");
                return ExitCode::FAILURE;
            }
        };
        let target = endpoint.addr();
        let mut config = config;
        config.iroh_endpoint = match serde_json::to_vec(&target) {
            Ok(bytes) => hex::encode(bytes),
            Err(error) => {
                eprintln!("auths-records-demo: could not encode Iroh endpoint: {error}");
                return ExitCode::FAILURE;
            }
        };
        let bind = config.bind;
        let (router, state) = match app_with_iroh(config, Some(target)) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("auths-records-demo: {error}");
                return ExitCode::FAILURE;
            }
        };
        tokio::spawn(serve_iroh(endpoint, state));
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("auths-records-demo: could not bind {bind}: {error}");
                return ExitCode::FAILURE;
            }
        };
        println!("auths-records-demo listening on http://{bind}");
        match axum::serve(listener, router).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("auths-records-demo: {error}");
                ExitCode::FAILURE
            }
        }
    })
}
