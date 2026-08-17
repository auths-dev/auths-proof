//! Emits the local-fixture `TrustedContext` the reference compose stack needs.
//!
//! `[verification] trusted_context_path` is mandatory and nothing produced a
//! context for the compose demo, so every replica exited 1 on startup. This
//! writes one derived from the stack's own `AUTHS_LOCAL_SEED`.
//!
//! Local fixture only. The anchor key is derivable from the seed by anyone who
//! holds it; a production deployment mounts operator-held context bytes.

use auths_node::local_fixture::{SEED_ENV, build_context};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    env, fs,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_LIFETIME_SECONDS: u64 = 6 * 60 * 60;

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(output) = arguments.next() else {
        eprintln!("usage: auths-local-context <output-path> [lifetime-seconds]");
        return ExitCode::from(1);
    };
    let lifetime = arguments
        .next()
        .as_deref()
        .unwrap_or(&DEFAULT_LIFETIME_SECONDS.to_string())
        .parse::<u64>()
        .ok()
        .filter(|value| (60..=30 * 24 * 60 * 60).contains(value));
    if arguments.next().is_some() {
        eprintln!("auths-local-context: unexpected extra argument");
        return ExitCode::from(1);
    }
    let Some(lifetime) = lifetime else {
        eprintln!("auths-local-context: lifetime must be between 60 and 2592000 seconds");
        return ExitCode::from(1);
    };
    let Ok(encoded) = env::var(SEED_ENV) else {
        eprintln!("auths-local-context: {SEED_ENV} is not set");
        return ExitCode::from(1);
    };
    let mut seed = [0_u8; 32];
    if Base64UrlUnpadded::decode(encoded.trim(), &mut seed).is_err() {
        eprintln!("auths-local-context: {SEED_ENV} is not 32 unpadded base64url bytes");
        return ExitCode::from(1);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let context = match build_context(&seed, now, lifetime) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("auths-local-context: {error}");
            return ExitCode::from(1);
        }
    };
    let Ok(bytes) = auths_codec::encode_verifier_context(&context) else {
        eprintln!("auths-local-context: the context could not be encoded canonically");
        return ExitCode::from(1);
    };
    if fs::write(&output, &bytes).is_err() {
        eprintln!("auths-local-context: {output} could not be written");
        return ExitCode::from(1);
    }
    eprintln!(
        "auths-local-context: wrote {} canonical bytes to {output}, valid for {lifetime}s (LOCAL FIXTURE)",
        bytes.len()
    );
    ExitCode::SUCCESS
}
