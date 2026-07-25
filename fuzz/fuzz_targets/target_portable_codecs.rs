#![no_main]

use auths_codec::{
    decode_canonical_action, decode_verification_result, decode_verifier_context,
    encode_canonical_action, encode_verification_result, encode_verifier_context,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = decode_canonical_action(data) {
        assert_eq!(encode_canonical_action(&value).ok().as_deref(), Some(data));
    }
    if let Ok(value) = decode_verifier_context(data) {
        assert_eq!(encode_verifier_context(&value).ok().as_deref(), Some(data));
    }
    if let Ok(value) = decode_verification_result(data) {
        assert_eq!(
            encode_verification_result(&value).ok().as_deref(),
            Some(data)
        );
    }
});
