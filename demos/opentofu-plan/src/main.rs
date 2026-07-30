use auths_opentofu_demo::{AppConfig, serve};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("OpenTofu demo configuration error: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = serve(config).await {
        eprintln!("OpenTofu demo failed: {error}");
        std::process::exit(1);
    }
}
