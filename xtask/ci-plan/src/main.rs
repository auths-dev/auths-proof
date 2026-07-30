#![forbid(unsafe_code)]

use auths_ci_plan::{Command, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    match Command::parse(std::env::args().skip(1)).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths-ci-plan: {error}");
            ExitCode::from(1)
        }
    }
}
