//! Production-only wrapper around the shipping Auths CLI.

#![forbid(unsafe_code)]

// These assertions belong to this binary target rather than the shared CLI
// module. Every production build therefore fails if Cargo feature unification
// enables a qualification-only dependency surface through any direct,
// transitive, target-specific, or command-line edge. The separately named
// qualification agent reuses the CLI module without compiling this wrapper.
const _: () = assert!(
    !auths_connections::__QUALIFICATION_BROKER_ENABLED,
    "production auths cannot enable qualification-broker",
);
const _: () = assert!(
    !auths_stores::__QUALIFICATION_EVIDENCE_ENABLED,
    "production auths cannot enable qualification-evidence",
);
const _: () = assert!(
    !auths_stripe::__TESTKIT_AGENT_ENABLED,
    "production auths cannot enable testkit-agent",
);

#[path = "auths.rs"]
mod shipping_cli;

fn main() -> std::process::ExitCode {
    shipping_cli::main()
}
