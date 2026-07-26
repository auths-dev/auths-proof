#![forbid(unsafe_code)]

use auths_live_service::{AppConfig, app};
use std::{env, net::SocketAddr, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let config = match AppConfig::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("auths-live-service: {error}");
            return ExitCode::from(1);
        }
    };
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("auths-live-service: could not bind {address}: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "auths-live-service release={} region={} listening={address}",
        config.release_id(),
        config.region()
    );
    let router = match app(config) {
        Ok(router) => router,
        Err(error) => {
            eprintln!("auths-live-service: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await
    {
        eprintln!("auths-live-service: server failed: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

async fn shutdown() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
