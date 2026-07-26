//! Browser benchmark for the target V1 canonical raw-key fixture.

#![forbid(unsafe_code)]

#[cfg(all(test, target_arch = "wasm32"))]
mod browser {
    use auths_codec::decode_verifier_context;
    use auths_ports::{PrincipalMethod, SignatureSuite};
    use auths_raw_key::RawKeyMethod;
    use auths_registries::ImmutableRegistries;
    use auths_signature::{Ed25519Suite, P256Sha256Suite};
    use auths_testkit::raw_key_chain;
    use auths_verifier::{VerificationOutcome, verify};
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const ITERATIONS: u32 = 100;

    #[wasm_bindgen_test]
    fn canonical_raw_key_proof_verification_time() {
        let fixture = raw_key_chain();
        let context =
            decode_verifier_context(fixture.context_bytes()).expect("canonical context fixture");
        let raw = RawKeyMethod::new().expect("raw-key method");
        let ed25519 = Ed25519Suite::new().expect("Ed25519 suite");
        let p256 = P256Sha256Suite::new().expect("P-256 suite");
        let methods: [&dyn PrincipalMethod; 1] = [&raw];
        let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
        let registries =
            ImmutableRegistries::new(&methods, &suites).expect("exact executable registries");

        let started = js_sys::Date::now();
        for _ in 0..ITERATIONS {
            let verdict = verify(
                fixture.proof_bytes(),
                fixture.canonical_action(),
                &context,
                &registries,
            );
            assert!(matches!(verdict, VerificationOutcome::Authorized(_)));
        }
        let elapsed = js_sys::Date::now() - started;
        let average = elapsed / f64::from(ITERATIONS);
        web_sys::console::log_1(
            &format!(
                "Auths target V1 browser verification: {average:.3} ms average over {ITERATIONS} iterations; proof={} bytes",
                fixture.proof_bytes().len()
            )
            .into(),
        );
    }
}
