use std::{env, net::SocketAddr};

use auths_identity_iroh_demo::{AppConfig, serve};

#[tokio::main]
async fn main() {
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let config = AppConfig::from_environment();
    if serve(config, address).await.is_err() {
        eprintln!("auths-identity-iroh-demo: service terminated");
        std::process::exit(1);
    }
}
