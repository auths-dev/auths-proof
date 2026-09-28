//! Signed outcomes: verification never panics, accepts only canonical bytes
//! of the pinned test observer, and every accepted fact set satisfies the
//! presence rule and names an outcome stage.

#![no_main]

use auths_gateway::fuzzing;
use auths_model::{PrincipalId, VerifierLimits};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The observer of the committed outcome vectors.
const OBSERVER_SEED: u8 = 0x5a;

fn observer() -> &'static PrincipalId {
    static OBSERVER: OnceLock<PrincipalId> = OnceLock::new();
    OBSERVER.get_or_init(|| fuzzing::test_observer(OBSERVER_SEED))
}

fuzz_target!(|data: &[u8]| {
    let Some(verified) = fuzzing::verify_outcome(data, observer()) else {
        return;
    };
    assert!(verified.well_formed);
    assert!(matches!(
        verified.stage,
        "not-entered" | "unknown" | "response-recorded" | "observed" | "observed-by-provider"
    ));
    let Ok(decoded) = auths_codec::decode_signed_observation(data, &VerifierLimits::default())
    else {
        panic!("an accepted outcome decodes");
    };
    let Ok(encoded) = auths_codec::encode_signed_observation(&decoded) else {
        panic!("an accepted outcome encodes");
    };
    assert_eq!(encoded, data, "an accepted outcome is canonical");
    let statement = decoded.statement();
    assert_eq!(statement.observer(), observer());
    assert_eq!(statement.schema().as_str(), fuzzing::outcome_schema());
    assert_eq!(statement.subject().as_str(), verified.subject);
    assert_eq!(statement.observed_at().get(), verified.observed_at);
});
