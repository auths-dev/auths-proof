//! Qualification-only build of the shipping local-agent CLI.

#![forbid(unsafe_code)]

// The separately selected Cargo feature adds the exact unqualified five-profile
// qualification roster and after-decision crash checkpoint. Both are absent
// from the production build and never advertise an imported qualification.
#[path = "auths.rs"]
mod shipping_cli;

fn main() -> std::process::ExitCode {
    shipping_cli::main()
}
