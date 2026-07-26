#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let repository = auths_live_lab::repository_root();
    let output = env::args_os()
        .nth(1)
        .map_or_else(|| repository.join("target/live-demo/site"), PathBuf::from);
    match auths_live_lab::build_site(&repository, &output).await {
        Ok(()) => {
            println!("generated Auths live lab at {}", output.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("auths-live-lab: {error}");
            ExitCode::from(1)
        }
    }
}
