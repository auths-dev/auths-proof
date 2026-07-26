#![no_main]

use auths_did_keri::{KeriEvidence, KeriLimits};
use auths_did_key::DidKeyEvidence;
use auths_did_web::DidWebEvidence;
use auths_hsm_attested::HsmAttestationEvidence;
use auths_multikey::Multikey;
use auths_raw_key::RawKeyDescriptor;
use auths_spiffe_x509::SpiffeX509Evidence;
use auths_webauthn::WebAuthnEvidence;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = DidKeyEvidence::decode(data);
    let _ = KeriEvidence::decode(data, KeriLimits::standard());
    let _ = DidWebEvidence::decode(data);
    let _ = HsmAttestationEvidence::decode(data);
    let _ = SpiffeX509Evidence::decode(data);
    let _ = RawKeyDescriptor::decode(data);
    let _ = WebAuthnEvidence::decode(data);
    if let Ok(candidate) = core::str::from_utf8(data) {
        let _ = Multikey::parse(candidate);
    }
});
