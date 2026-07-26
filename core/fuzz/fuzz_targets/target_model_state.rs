#![no_main]

use auths_model::{
    AuthorizationPlan, BodyDigestSet, Digest, PrincipalId, ProofRef, VerifierLimits,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(candidate) = core::str::from_utf8(data) {
        let _ = PrincipalId::parse(candidate);
    }

    let digests: Vec<_> = data
        .chunks(32)
        .take(256)
        .map(|chunk| {
            let mut bytes = [0_u8; 32];
            bytes[..chunk.len()].copy_from_slice(chunk);
            Digest::new(bytes)
        })
        .collect();
    let _ = BodyDigestSet::new(digests);

    let leaves: Vec<_> = data
        .chunks(32)
        .take(128)
        .map(|chunk| {
            let mut bytes = [0_u8; 32];
            bytes[..chunk.len()].copy_from_slice(chunk);
            AuthorizationPlan::proof(ProofRef::new(bytes))
        })
        .collect();
    if let Ok(plan) = AuthorizationPlan::all_of(leaves) {
        let _ = plan.validate(&VerifierLimits::default_deployment());
    }
});
