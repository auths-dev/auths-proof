#![no_main]

use auths_codec::{
    decode_bundle, decode_canonical_action, decode_verification_result, decode_verifier_context,
    encode_verification_result, verification_result_digest,
};
use auths_model::VerifierLimits;
use auths_registries::ImmutableRegistries;
use auths_verifier::verify_v1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = data.len() / 3;
    let second = first.saturating_mul(2);
    let _ = decode_bundle(&data[..first], &VerifierLimits::default_deployment());
    let _ = decode_canonical_action(&data[first..second]);
    let _ = decode_verifier_context(&data[second..]);
    let methods: [&dyn auths_ports::PrincipalMethod; 0] = [];
    let suites: [&dyn auths_ports::SignatureSuite; 0] = [];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let corpus_proof = include_bytes!("../../fixtures/v1/valid/raw-key-chain.proof.cbor");
    let corpus_action = include_bytes!("../../fixtures/v1/valid/raw-key-chain.action.cbor");
    let corpus_context = include_bytes!("../../fixtures/v1/valid/raw-key-chain.context.cbor");
    let corpus_first = verify_v1(corpus_proof, corpus_action, corpus_context, &registries).unwrap();
    let corpus_second =
        verify_v1(corpus_proof, corpus_action, corpus_context, &registries).unwrap();
    assert_eq!(corpus_first, corpus_second);
    decode_verification_result(&corpus_first).unwrap();
    if let Ok(result_bytes) = verify_v1(
        &data[..first],
        &data[first..second],
        &data[second..],
        &registries,
    ) {
        let result = decode_verification_result(&result_bytes).unwrap();
        assert_eq!(
            verify_v1(
                &data[..first],
                &data[first..second],
                &data[second..],
                &registries,
            )
            .ok()
            .as_deref(),
            Some(result_bytes.as_slice())
        );
        assert_eq!(
            verification_result_digest(&result),
            verification_result_digest(&result)
        );
    }
    if let Ok(result) = decode_verification_result(data) {
        let encoded = encode_verification_result(&result).unwrap();
        assert_eq!(encoded, data);
        assert_eq!(
            verification_result_digest(&result),
            verification_result_digest(&result)
        );
    }
});
