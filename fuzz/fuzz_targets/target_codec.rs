#![no_main]

use auths_codec::{decode_bundle, decode_verifier_context};
use auths_model::VerifierLimits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_bundle(data, &VerifierLimits::default_deployment());
    let _ = decode_verifier_context(data);
});
