//! A complete records-domain authorization vertical.
//!
//! The package owns its actions, policies, evaluators, verified commands,
//! state transitions, and receipt meanings. HTTP and Iroh are delivery
//! adapters in the demo and never become authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    reason = "public APIs return closed, self-describing error enums"
)]

pub mod action;
pub mod canonical;
pub mod decision;
pub mod envelope;
pub mod executor;
pub mod ledger;
pub mod lifecycle;
pub mod policy;
pub mod presentation;
pub mod profile;
pub mod receipts;
pub mod service;

pub use action::*;
pub use decision::*;
pub use envelope::*;
pub use executor::*;
pub use ledger::*;
pub use lifecycle::*;
pub use policy::*;
pub use presentation::*;
pub use profile::*;
pub use receipts::*;
pub use service::*;

#[cfg(test)]
mod fixture_tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/v1/records-api");

    #[test]
    fn canonical_product_fixtures_match_shipping_decoders() {
        let create = std::fs::read(format!("{FIXTURES}/create-action.json")).unwrap();
        let read = std::fs::read(format!("{FIXTURES}/read-action.json")).unwrap();
        let policy: BoundedRecordApiPolicyV1 =
            serde_json::from_slice(&std::fs::read(format!("{FIXTURES}/policy.json")).unwrap())
                .unwrap();
        let configuration: RecordsApiVerifierConfigurationV1 = serde_json::from_slice(
            &std::fs::read(format!("{FIXTURES}/configuration.json")).unwrap(),
        )
        .unwrap();
        let decoded_create: CreateRecordV1 = serde_json::from_slice(&create).unwrap();
        let reencoded_create = decoded_create.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(create.clone()).unwrap(),
            String::from_utf8(reencoded_create).unwrap(),
            "canonical create fixture"
        );
        CreateRecordV1::from_canonical_bytes(&create).expect("canonical create fixture");
        ReadRecordV1::from_canonical_bytes(&read).expect("canonical read fixture");
        assert!(policy.validate().is_ok());
        assert!(configuration.validate().is_ok());
    }
}
