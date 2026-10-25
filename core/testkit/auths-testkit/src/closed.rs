//! Useful positive witnesses for each closed principal/suite combination.

use super::*;

/// Returns a direct, authentic authorization for every supported combination
/// of self-certifying principal method and mandatory signature suite.
///
/// These are ordinary portable corpus cases. They use the same authoring,
/// signing, evidence, binding, context and codec path as the existing corpus.
///
/// # Panics
/// Panics only if deterministic repository-owned fixture data is invalid.
#[must_use]
pub fn closed_signature_vectors() -> Vec<CorpusFixture> {
    [
        ("closed-raw-key-ed25519", Identity::ed25519(91)),
        ("closed-raw-key-p256", Identity::p256(92)),
        ("closed-did-key-ed25519", Identity::did_key_ed25519(93)),
        ("closed-did-key-p256", Identity::did_key_p256(94)),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (name, identity))| {
        let proof_ref = ProofRef::new([0xc0 + u8::try_from(index).expect("four cases"); 32]);
        direct_case(
            &identity,
            DirectCase {
                name,
                plan: AuthorizationPlan::proof(proof_ref),
                proof_ref,
                terminal_grant: None,
                descriptor: None,
                extra_registry_identities: Vec::new(),
                signature: FixtureSignature::Normal,
                expected: Expected::Authorized,
            },
        )
    })
    .collect()
}
