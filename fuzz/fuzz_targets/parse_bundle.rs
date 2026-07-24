#![no_main]

use auths_proof_codec::{decode_bundle, DecodeLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_bundle(data, DecodeLimits::standard());
});
