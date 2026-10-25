//! Shared synthetic snapshot vectors, consumed independently by Rust, Go and
//! TypeScript. These check carrier/codec semantics, not signature authenticity.

use auths_codec::{
    CodecError, decode_grant_status_snapshot, decode_principal_status_snapshot,
    encode_grant_status_snapshot, encode_principal_status_snapshot,
};
use auths_model::{ModelError, VerifierLimits};

#[test]
fn shared_snapshot_uniqueness_corpus() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/codec/snapshot-uniqueness-v1.json"
    )).unwrap();
    assert_eq!(corpus["schema"], "auths-proof-status-snapshot-uniqueness/v1");
    let cases = corpus["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let hex = case["snapshot_cbor_hex"].as_str().unwrap();
        assert_eq!(hex.len() % 2, 0);
        let input: Vec<_> = (0..hex.len()).step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect();
        let accepts = case["accepts"].as_bool().unwrap();
        match case["kind"].as_str().unwrap() {
            "principal" => {
                let decoded = decode_principal_status_snapshot(&input, &VerifierLimits::hard());
                if accepts {
                    let snapshot = decoded.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                    assert_eq!(encode_principal_status_snapshot(&snapshot).unwrap(), input, "{name}");
                    for (index, value) in snapshot.statements().iter().enumerate() {
                        assert!(!snapshot.statements()[..index].iter()
                            .any(|earlier| earlier.statement() == value.statement()), "{name}");
                    }
                } else {
                    assert_eq!(decoded, Err(CodecError::Model(ModelError::InvalidStatusSnapshot)), "{name}");
                }
            }
            "grant" => {
                let decoded = decode_grant_status_snapshot(&input, &VerifierLimits::hard());
                if accepts {
                    let snapshot = decoded.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                    assert_eq!(encode_grant_status_snapshot(&snapshot).unwrap(), input, "{name}");
                    for (index, value) in snapshot.statements().iter().enumerate() {
                        assert!(!snapshot.statements()[..index].iter()
                            .any(|earlier| earlier.statement() == value.statement()), "{name}");
                    }
                } else {
                    assert_eq!(decoded, Err(CodecError::Model(ModelError::InvalidStatusSnapshot)), "{name}");
                }
            }
            other => panic!("unknown fixture kind: {other}"),
        }
    }
}
