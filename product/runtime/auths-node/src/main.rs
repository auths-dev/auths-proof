//! Auths deployment CLI.
//!
//! The gateway is the single provider-write path. This binary holds the
//! operator-side check of a closed recipe against its generated profile lock
//! and an operator-selected credential header. It reads no credential, opens
//! no socket, and contacts nothing.

#![forbid(unsafe_code)]

use auths_gateway::{CompiledRecipe, GatewayConnectionDescriptor};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_RECIPE_BYTES: usize = 65_536;
const MAX_PROFILE_LOCK_BYTES: usize = 65_536;

#[derive(Parser)]
#[command(
    name = "auths-node",
    version,
    about = "Auths deployment administration"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compile and inspect a closed developer-authored gateway recipe.
    Gateway(Gateway),
}

#[derive(Args)]
struct Gateway {
    #[command(subcommand)]
    command: GatewayCommand,
}

#[derive(Subcommand)]
enum GatewayCommand {
    /// Work with a closed request recipe.
    Recipe(GatewayRecipe),
}

#[derive(Args)]
struct GatewayRecipe {
    #[command(subcommand)]
    command: GatewayRecipeCommand,
}

#[derive(Subcommand)]
enum GatewayRecipeCommand {
    /// Validate one recipe against its generated exact-profile lock.
    Check {
        /// Versioned closed recipe source; no credential is read.
        #[arg(long)]
        recipe: PathBuf,
        /// Generated profile.lock.json from a packaged SDK.
        #[arg(long)]
        profile_lock: PathBuf,
        /// Operator-selected injection header; defaults to bearer Authorization.
        #[arg(long, default_value = "Authorization")]
        credential_header: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths-node: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Gateway(Gateway {
            command:
                GatewayCommand::Recipe(GatewayRecipe {
                    command:
                        GatewayRecipeCommand::Check {
                            recipe,
                            profile_lock,
                            credential_header,
                        },
                }),
        }) => {
            let source = bounded_regular_file(&recipe, MAX_RECIPE_BYTES)?;
            let lock = bounded_regular_file(&profile_lock, MAX_PROFILE_LOCK_BYTES)?;
            print_json(&recipe_check(&source, &lock, &credential_header)?)
        }
    }
}

/// Compiles the recipe, approves it with the operator's credential header,
/// and returns the review document with that header and the claim this
/// check makes.
fn recipe_check(
    source: &[u8],
    lock: &[u8],
    credential_header: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let compiled = CompiledRecipe::compile(source, lock)?;
    GatewayConnectionDescriptor::approve(&compiled, credential_header)?;
    let mut review = compiled.review_document();
    review["operator_credential_header"] = json!(credential_header);
    review["claim"] =
        json!("closed request construction only; no credential or provider-effect qualification");
    Ok(review)
}

fn bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let file: File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    #[cfg(not(unix))]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum)
    {
        return Err("input must be a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("input exceeds its bound".into());
    }
    Ok(bytes)
}

fn print_json(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_and_non_regular_inputs_are_refused() {
        let directory = std::env::temp_dir();
        assert!(bounded_regular_file(&directory, MAX_RECIPE_BYTES).is_err());
    }

    #[test]
    fn malformed_recipe_is_refused_before_review() {
        assert!(recipe_check(b"{}", b"{}", "Authorization").is_err());
    }
}
