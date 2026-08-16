//! The offline-authored proof must verify against the generated context.
//!
//! `auths-local-context` builds the trusted context the reference stack runs
//! with, and `auths-local-authority` authors a proof against the same anchor.
//! Nothing checked that the two agree. They are derived from one seed through
//! `reference_grant_terms`, but "derived from one source" is a claim about the
//! code, not a check on the result -- and every way this can drift produces the
//! same symptom, a node denying every request, which reads as a verifier bug.
//!
//! This test closes that loop by running the real verifier.

use auths_node::local_fixture::build_context;
use std::{
    collections::BTreeSet,
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const SEED_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

struct FixedClock(u64);

impl auths_node::NodeClock for FixedClock {
    fn now_unix_seconds(&self) -> u64 {
        self.0
    }
}

fn authored(profile: &str, body: &str, agent: &str) -> (Vec<u8>, Vec<u8>) {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let action_path = std::env::temp_dir().join(format!("auths-fixture-{agent}.bin"));
    std::fs::write(&action_path, body).expect("action body");
    let binary = env!("CARGO_BIN_EXE_auths-local-authority");
    let output = Command::new(binary)
        .args([profile, action_path.to_str().expect("path"), agent])
        .env("AUTHS_LOCAL_SEED", SEED_B64)
        .output()
        .expect("author");
    assert!(
        output.status.success(),
        "authoring failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("utf8");
    let field = |name: &str| {
        let encoded = text
            .split(&format!("\"{name}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("field");
        Base64UrlUnpadded::decode_vec(encoded).expect("base64url")
    };
    (field("proof"), field("action"))
}

#[test]
fn an_offline_authored_proof_is_authorized_by_the_generated_context() {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let mut seed = [0_u8; 32];
    Base64UrlUnpadded::decode(SEED_B64, &mut seed).expect("seed");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let context = build_context(&seed, now, 3_600).expect("trusted context");
    let kernel = auths_node::NodeKernel::with_built_ins(context)
        .expect("the deployed verifier registry must initialize");
    let runtime = auths_node::KernelRuntime::with_clock(
        kernel,
        [0x55; 32],
        BTreeSet::from([auths_production_client::QualifiedProfile::OpenTofuSavedPlanApply]),
        Arc::new(FixedClock(now)),
    )
    .expect("runtime");

    for profile in auths_node::local_fixture::REFERENCE_PROFILES {
        let (proof, action_bytes) = authored(profile, "exact reference operation", "fixture-agent");
        runtime
            .authorize(&proof, &action_bytes)
            .unwrap_or_else(|error| panic!("{profile} was not authorized: {error:?}"));
    }
}
