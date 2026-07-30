#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, process::ExitCode};

use auths_stripe_payout_demo::{AppConfig, app};

fn main() -> ExitCode {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let config = match AppConfig::from_environment() {
        Ok(value) => value,
        Err(error) => return failure(&error.to_string()),
    };
    let router = match app(config) {
        Ok(value) => value,
        Err(error) => return failure(&error.to_string()),
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(value) => value,
        Err(error) => return failure(&format!("could not create runtime: {error}")),
    };
    runtime.block_on(serve(router))
}

async fn serve(router: axum::Router) -> ExitCode {
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let address = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(value) => value,
        Err(error) => return failure(&format!("could not bind {address}: {error}")),
    };
    if let Err(error) = axum::serve(listener, router).await {
        return failure(&format!("server failed: {error}"));
    }
    ExitCode::SUCCESS
}

fn failure(error: &str) -> ExitCode {
    eprintln!("auths-stripe-payout-demo: {error}");
    ExitCode::from(1)
}
