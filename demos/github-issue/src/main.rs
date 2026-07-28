use std::{env, net::SocketAddr};

use auths_github_demo::{AppConfig, serve};

#[tokio::main]
async fn main() {
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let Ok(config) = AppConfig::from_environment() else {
        eprintln!("auths-github-demo: invalid startup configuration");
        std::process::exit(1);
    };
    if serve(config, address).await.is_err() {
        eprintln!("auths-github-demo: service terminated");
        std::process::exit(1);
    }
}
