//! Provider bytes must have one member-name interpretation before they can
//! become account, ceiling, locator, echo or signed observation facts.

use super::*;
use crate::recipe::{ClosedActionRead, ClosedObservationRequest, ReadBack};
use crate::transport::ProviderResponse;
use serde_json::json;

fn observation() -> ClosedObservationRequest {
    ClosedObservationRequest {
        url: "https://api.example.com/records/one".to_owned(), headers: Vec::new(),
        json_pointer: "/state".to_owned(), expected: json!("Approved"),
        maximum_response_bytes: 1024, echo_pointer: Some("/echo".to_owned()),
    }
}

#[test]
fn ambiguous_observations_cannot_select_a_value_or_an_echo() {
    let request = observation();
    for body in [
        br#"{"state":"Denied","state":"Approved","echo":"token"}"#.as_slice(),
        br#"{"state":"Approved","echo":"wrong","echo":"token"}"#,
        br#"{"state":"Approved","\u0073tate":"Approved","echo":"token"}"#,
        br#"{"state":"Approved","echo":"token","extra":[{"x":1,"x":2}]}"#,
    ] {
        assert!(serde_json::from_slice::<Value>(body).is_ok(), "the former parser accepted this document");
        assert!(request.observed_values(body).is_none());
        assert_eq!(request.read_back(Some("token"), body), None);
    }
    let positive = br#"{"state":"Approved","echo":"token","left":{"x":1},"right":{"x":2}}"#;
    assert_eq!(request.observed_values(positive), Some((json!("Approved"), Some(json!("token")))));
    assert_eq!(request.read_back(Some("token"), positive), Some(ReadBack::EchoMatched));
}

#[test]
fn ambiguous_account_labels_never_select_the_last_member() {
    for body in [
        br#"{"id":"acct_wrong","id":"acct_expected"}"#.as_slice(),
        br#"{"id":"acct_expected","\u0069d":"acct_expected"}"#,
        br#"{"id":"acct_expected","unused":{"x":0,"x":1}}"#,
    ] {
        let response = ProviderResponse { status: 200, version_ok: true, body: body.to_vec() };
        assert!(crate::submit::account_label(Some(&response), "/id").is_none());
    }
    let response = ProviderResponse { status: 200, version_ok: true, body: br#"{"id":"acct_expected"}"#.to_vec() };
    assert_eq!(crate::submit::account_label(Some(&response), "/id").as_deref(), Some("acct_expected"));
}

#[test]
fn ceiling_basis_and_binding_share_the_unique_document() {
    let check = CeilingCheck { argument: "amount".to_owned(), basis_points: 10_000,
        json_pointer: "/basis".to_owned(), subtract_pointer: None,
        binds: vec![("/invoice".to_owned(), "invoice".to_owned())] };
    let arguments = json!({"amount":1,"invoice":"in_expected"});
    let arguments = arguments.as_object().unwrap();
    for body in [
        br#"{"basis":1,"basis":100,"invoice":"in_expected"}"#.as_slice(),
        br#"{"basis":100,"invoice":"in_wrong","invoice":"in_expected"}"#,
        br#"{"basis":100,"\u0062asis":100,"invoice":"in_expected"}"#,
    ] { assert_eq!(check.read(body, arguments), CeilingReading::Unavailable); }
    assert_eq!(check.read(br#"{"basis":100,"invoice":"in_expected"}"#, arguments),
        CeilingReading::Read { basis: 100, binds_equal: true });
    assert_eq!(check.read(br#"{"basis":9007199254740991,"invoice":"in_expected"}"#, arguments),
        CeilingReading::Read { basis: 9_007_199_254_740_991, binds_equal: true });
    for number in ["-1", "1.0", "1e0", "9007199254740992", "18446744073709551615"] {
        let body = format!("{{\"basis\":{number},\"invoice\":\"in_expected\"}}");
        assert_eq!(check.read(body.as_bytes(), arguments), CeilingReading::Unavailable);
    }
}

#[test]
fn response_locators_and_persisted_expected_values_are_unambiguous() {
    let mut template = ObservationTemplate {
        origin: "https://api.example.com".to_owned(),
        segments: vec![TemplateSegment::ResponseField { pointer: "/id".to_owned(), max_bytes: 64 }],
        headers: Vec::new(), json_pointer: "/state".to_owned(), expected: "\"Approved\"".to_owned(),
        maximum_response_bytes: 1024, echo_pointer: None,
    };
    for body in [br#"{"id":"wrong","id":"expected"}"#.as_slice(), br#"{"id":"expected","\u0069d":"expected"}"#] {
        assert!(template.extract_locator(body).is_none());
    }
    let locator = template.extract_locator(br#"{"id":"expected"}"#).unwrap();
    assert_eq!(locator.get("/id").map(String::as_str), Some("expected"));
    assert!(template.request(Some(&locator)).is_some());
    template.expected = "{\"state\":\"Denied\",\"state\":\"Approved\"}".to_owned();
    assert!(template.request(Some(&locator)).is_none(), "a corrupted expected document cannot select its last member");
}

#[test]
fn duplicate_provider_members_cannot_be_signed_as_pre_entry_facts() {
    let observer = crate::GatewayObserver::from_test_seed(0x63);
    let read = ClosedActionRead { url: "https://api.example.com/records/one".to_owned(),
        headers: Vec::new(), maximum_response_bytes: 1024 };
    let pointers = vec!["/state".to_owned()];
    for body in [br#"{"state":"Denied","state":"Approved"}"#.as_slice(),
        br#"{"state":"Approved","extra":{"x":1,"x":2}}"#] {
        assert!(crate::pre_entry::sign_observations(&observer, &read, &pointers, body, 100).is_none());
    }
    let observations = crate::pre_entry::sign_observations(&observer, &read, &pointers,
        br#"{"state":"Approved"}"#, 100).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].observed_at, 100);
    assert_eq!(observations[0].subject, "https://api.example.com/records/one#/state");
}
