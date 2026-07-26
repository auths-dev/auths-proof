#![no_main]

use auths_codec::{
    decode_bundle, decode_canonical_action, decode_verification_result, decode_verifier_context,
    encode_verification_result, encode_verifier_context, verification_result_digest,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_verifier::verify_v1;
use libfuzzer_sys::fuzz_target;

const PROOF: &[u8] = include_bytes!("../../fixtures/v1/valid/raw-key-chain.proof.cbor");
const ACTION: &[u8] = include_bytes!("../../fixtures/v1/valid/raw-key-chain.action.cbor");
const CONTEXT: &[u8] = include_bytes!("../../fixtures/v1/valid/raw-key-chain.context.cbor");

fn mutate(source: &[u8], instructions: &[u8]) -> Vec<u8> {
    let mut output = source.to_vec();
    for pair in instructions.chunks_exact(2).take(64) {
        if output.is_empty() {
            break;
        }
        let index = usize::from(pair[0]) % output.len();
        output[index] ^= pair[1];
    }
    output
}

fn framed(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if data.get(..4)? != b"APF1" {
        return None;
    }
    let proof_len = usize::try_from(u32::from_be_bytes(data.get(4..8)?.try_into().ok()?)).ok()?;
    let action_len =
        usize::try_from(u32::from_be_bytes(data.get(8..12)?.try_into().ok()?)).ok()?;
    let context_len =
        usize::try_from(u32::from_be_bytes(data.get(12..16)?.try_into().ok()?)).ok()?;
    let proof_end = 16usize.checked_add(proof_len)?;
    let action_end = proof_end.checked_add(action_len)?;
    let context_end = action_end.checked_add(context_len)?;
    if context_end != data.len() {
        return None;
    }
    Some((
        data.get(16..proof_end)?,
        data.get(proof_end..action_end)?,
        data.get(action_end..context_end)?,
    ))
}

fuzz_target!(|data: &[u8]| {
    let raw_key = auths_raw_key::RawKeyMethod::new().unwrap();
    let did_key = auths_did_key::DidKeyMethod::new().unwrap();
    let did_keri = auths_did_keri::DidKeriMethod::new().unwrap();
    let ed25519 = auths_signature::Ed25519Suite::new().unwrap();
    let p256 = auths_signature::P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();

    let baseline_context = decode_verifier_context(CONTEXT)
        .unwrap()
        .with_configuration(registries.configuration_id())
        .unwrap();
    let baseline_context = encode_verifier_context(&baseline_context).unwrap();
    let (proof, action, context) = if let Some(tuple) = framed(data) {
        (tuple.0.to_vec(), tuple.1.to_vec(), tuple.2.to_vec())
    } else {
        let selector = data.first().copied().unwrap_or(0) % 3;
        let instructions = data.get(1..).unwrap_or_default();
        (
            if selector == 0 {
                mutate(PROOF, instructions)
            } else {
                PROOF.to_vec()
            },
            if selector == 1 {
                mutate(ACTION, instructions)
            } else {
                ACTION.to_vec()
            },
            if selector == 2 {
                mutate(&baseline_context, instructions)
            } else {
                baseline_context
            },
        )
    };

    if let Ok(decoded_context) = decode_verifier_context(&context) {
        let _ = decode_bundle(&proof, decoded_context.limits());
        let _ = decode_canonical_action(&action, decoded_context.limits());
    }

    let first = verify_v1(&proof, &action, &context, &registries).unwrap();
    let second = verify_v1(&proof, &action, &context, &registries).unwrap();
    assert_eq!(first, second);
    let result = decode_verification_result(&first).unwrap();
    assert_eq!(encode_verification_result(&result).unwrap(), first);
    assert_eq!(
        verification_result_digest(&result).unwrap(),
        result.result_digest()
    );
});
