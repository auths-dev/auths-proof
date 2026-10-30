//! Native ACK and sole-reducer corpus. Synthetic binding/content identifiers
//! are private test inputs, not evidence of installed disclosure transport.

use super::*;
use auths_gateway_kernel::transition::{
    self as reducer, AttemptView, Link, Protocol as Kind, Reading, Stage,
};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

const STAGES: [Stage; 8] = [
    Stage::Reserved,
    Stage::EntryGranted,
    Stage::NotEntered,
    Stage::Unknown,
    Stage::ResponseRecorded,
    Stage::Observed,
    Stage::ObservedByProvider,
    Stage::Acknowledged,
];
const KINDS: [Kind; 3] = [Kind::Mutation, Kind::Acquisition, Kind::Disclosure];

fn disclosure(key: &SigningKey) -> EffectBinding {
    let mut wire = super::tests::wire();
    wire.reservations = vec![Reservation {
        key: [15; 32],
        unit: Unit::DisclosureBytes,
        amount: 42,
        ceiling: 100,
        window: ReservationWindow::SourceLifetime,
    }];
    wire.protocol = Protocol::Disclosure {
        source_effect: [10; 32],
        protected_content: [11; 32],
        recipient: RawKeyDescriptor::new(
            RawKeyType::Ed25519,
            key.verifying_key().to_bytes().to_vec(),
        )
        .expect("descriptor")
        .principal()
        .expect("recipient")
        .as_str()
        .to_owned(),
        channel: [12; 32],
        delivery_instance: [13; 32],
        projection: [14; 32],
        maximum_bytes: 100,
    };
    EffectBinding::new(wire).expect("synthetic private disclosure")
}

fn signed(binding: &EffectBinding, length: u64, key: &SigningKey) -> DisclosureAcknowledgement {
    let request = DisclosureAcknowledgementRequest::for_delivery(
        binding,
        length,
        key.verifying_key().to_bytes(),
    )
    .expect("signing request");
    let signature = key
        .sign(&request.signing_message().expect("message"))
        .to_bytes();
    request.with_signature(signature)
}

fn view(kind: Kind, stage: Stage) -> AttemptView {
    AttemptView {
        protocol: kind,
        revision: 1,
        // Identical bytes across protocols deliberately exercise the typed guard.
        fixed: vec![1, 2, 3],
        entry: if matches!(stage, Stage::Reserved | Stage::NotEntered) {
            vec![]
        } else {
            vec![4]
        },
        stage,
        refusal: stage == Stage::NotEntered,
        pre_entry: vec![],
        response: if matches!(stage, Stage::ResponseRecorded | Stage::Observed) {
            vec![5]
        } else {
            vec![]
        },
        acknowledgement: if stage == Stage::Acknowledged {
            vec![6]
        } else {
            vec![]
        },
        locator: vec![],
        reading: if stage == Stage::Observed {
            Reading::Match
        } else {
            Reading::None
        },
        evidence: stage == Stage::ObservedByProvider,
        observation: kind == Kind::Mutation,
        link: if kind == Kind::Mutation {
            Link::Verified
        } else {
            Link::None
        },
    }
}

// Independent specification table. This oracle calls none of the shipping
// shape/stage helpers: evidence, grant, revision and protocol are projected
// independently and each invalid cross-protocol edge is also exercised.
fn expected(kind: Kind, from: Stage, to: Stage) -> bool {
    match kind {
        Kind::Mutation => matches!(
            (from, to),
            (Stage::Reserved, Stage::EntryGranted | Stage::NotEntered)
                | (
                    Stage::EntryGranted,
                    Stage::Unknown | Stage::ResponseRecorded | Stage::ObservedByProvider
                )
                | (
                    Stage::Unknown,
                    Stage::ResponseRecorded | Stage::ObservedByProvider
                )
                | (
                    Stage::ResponseRecorded,
                    Stage::Observed | Stage::ObservedByProvider
                )
        ),
        Kind::Acquisition => matches!(
            (from, to),
            (Stage::Reserved, Stage::EntryGranted | Stage::NotEntered)
                | (
                    Stage::EntryGranted,
                    Stage::Unknown | Stage::ResponseRecorded
                )
                | (Stage::Unknown, Stage::ResponseRecorded)
        ),
        Kind::Disclosure => matches!(
            (from, to),
            (Stage::Reserved, Stage::EntryGranted | Stage::NotEntered)
                | (Stage::EntryGranted, Stage::Unknown | Stage::Acknowledged)
                | (Stage::Unknown, Stage::Acknowledged)
        ),
    }
}

fn edges() -> Value {
    let mut allowed = vec![];
    let mut checked = 0;
    for old_kind in KINDS {
        for new_kind in KINDS {
            for from in STAGES {
                for to in STAGES {
                    let old = view(old_kind, from);
                    let mut new = view(new_kind, to);
                    new.revision = 2;
                    // A provider-linked observation keeps an existing response.
                    if from == Stage::ResponseRecorded && to == Stage::ObservedByProvider {
                        new.response.clone_from(&old.response);
                    }
                    let actual = reducer::valid_transition(&old, &new);
                    let want = old_kind == new_kind && expected(old_kind, from, to);
                    assert_eq!(actual, want, "{old_kind:?}/{from:?} -> {new_kind:?}/{to:?}");
                    checked += 1;
                    if actual {
                        allowed.push(json!({"protocol": format!("{old_kind:?}"),
                            "from": format!("{from:?}"), "to": format!("{to:?}")}));
                    }
                }
            }
        }
    }
    json!({"checked_protocol_stage_pairs": checked, "allowed": allowed})
}

fn histories(evidence: &[u8]) -> Value {
    let mut histories = vec![];
    for stages in [
        vec![Stage::Reserved, Stage::NotEntered],
        vec![Stage::Reserved, Stage::EntryGranted, Stage::Acknowledged],
        vec![Stage::Reserved, Stage::EntryGranted, Stage::Unknown],
        vec![
            Stage::Reserved,
            Stage::EntryGranted,
            Stage::Unknown,
            Stage::Acknowledged,
        ],
    ] {
        let mut current = view(Kind::Disclosure, Stage::Reserved);
        let mut events = vec![json!({"stage": "Reserved", "revision": 1})];
        for stage in stages.iter().skip(1) {
            let mut next = view(Kind::Disclosure, *stage);
            next.revision = current.revision + 1;
            if *stage == Stage::Acknowledged {
                next.acknowledgement = evidence.to_vec();
            }
            assert!(reducer::valid_transition(&current, &next));
            assert_eq!(
                next.fixed, current.fixed,
                "identity and charge allocation are retained"
            );
            current = next;
            events.push(json!({"stage": format!("{stage:?}"), "revision": current.revision}));
        }
        let before = current.clone();
        let replay = reducer::exact_acknowledgement_replay(&current, evidence);
        assert_eq!(replay, current.stage == Stage::Acknowledged);
        assert_eq!(
            before, current,
            "ACK replay is read-only, including revision"
        );
        assert!(!reducer::exact_acknowledgement_replay(
            &current,
            b"substituted"
        ));
        for forbidden in [Stage::Reserved, Stage::EntryGranted] {
            let mut next = view(Kind::Disclosure, forbidden);
            next.revision = current.revision + 1;
            assert!(!reducer::valid_transition(&current, &next));
        }
        histories.push(json!({"events": events, "exact_ack_replay": replay,
            "reentry_refused": true, "fixed_allocation_retained": true}));
    }
    json!(histories)
}

fn field_mutations(evidence: &[u8]) -> Value {
    let old = view(Kind::Disclosure, Stage::Unknown);
    let mut valid = view(Kind::Disclosure, Stage::Acknowledged);
    valid.revision = 2;
    valid.acknowledgement = evidence.to_vec();
    assert!(reducer::valid_transition(&old, &valid));
    let mut rejected = vec![];
    for field in [
        "protocol",
        "revision",
        "fixed",
        "entry",
        "stage",
        "refusal",
        "pre-entry",
        "response",
        "acknowledgement",
        "locator",
        "reading",
        "evidence",
        "observation",
        "link",
    ] {
        let mut next = valid.clone();
        match field {
            "protocol" => next.protocol = Kind::Acquisition,
            "revision" => next.revision += 1,
            "fixed" => next.fixed.push(7),
            "entry" => next.entry.push(7),
            "stage" => next.stage = Stage::NotEntered,
            "refusal" => next.refusal = true,
            "pre-entry" => next.pre_entry = vec![7],
            "response" => next.response = vec![7],
            "acknowledgement" => next.acknowledgement.clear(),
            "locator" => next.locator = vec![7],
            "reading" => next.reading = Reading::Match,
            "evidence" => next.evidence = true,
            "observation" => next.observation = true,
            "link" => next.link = Link::Verified,
            _ => unreachable!(),
        }
        assert!(!reducer::valid_transition(&old, &next), "{field}");
        rejected.push(field);
    }
    for kind in [Kind::Mutation, Kind::Acquisition] {
        let mut next = view(kind, Stage::Unknown);
        next.acknowledgement = evidence.to_vec();
        assert!(
            !reducer::consistent(&next),
            "ACK cannot be smuggled into provider history"
        );
    }
    let mut saturated = old.clone();
    saturated.revision = (1 << 53) - 1;
    valid.revision = saturated.revision + 1;
    assert!(!reducer::valid_transition(&saturated, &valid));
    json!({"rejected": rejected, "saturated_revision_refused": true,
        "provider_ack_injection_refused": true})
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded substitution corpus against both statement and retained binding"
)]
fn substitutions(
    binding: &EffectBinding,
    ack: &DisclosureAcknowledgement,
    key: &SigningKey,
) -> Value {
    let original: Value =
        serde_json::from_slice(&binding.to_private_bytes().expect("binding")).expect("JSON");
    let mut cases = vec![];
    for field in [
        "source_effect",
        "protected_content",
        "recipient",
        "channel",
        "delivery_instance",
        "projection",
        "maximum_bytes",
    ] {
        let mut changed = original.clone();
        match field {
            "recipient" => changed["protocol"][field] = json!("another-recipient"),
            "maximum_bytes" => changed["protocol"][field] = json!(101),
            _ => changed["protocol"][field][0] = json!(99),
        }
        let target = EffectBinding::from_private_bytes(&canonical(&changed).expect("JSON"))
            .expect("changed data binding");
        assert!(ack.verify(&target, 42).is_err(), "{field}");
        cases.push(field);
    }
    // Re-sign each altered assertion while preserving the original effect ID.
    // This proves explicit dimension matching, beyond the effect-ID comparison.
    let ack_json: Value =
        serde_json::from_slice(&ack.to_private_bytes().expect("ACK")).expect("JSON");
    let mut resigned = vec![];
    for field in [
        "effect",
        "source_effect",
        "protected_content",
        "channel",
        "delivery_instance",
        "projection",
        "maximum_bytes",
        "acknowledged_bytes",
    ] {
        let mut statement = ack_json["request"].clone();
        if matches!(field, "maximum_bytes" | "acknowledged_bytes") {
            statement[field] = json!(99);
        } else {
            statement[field][0] = json!(99);
        }
        let request = DisclosureAcknowledgementRequest::from_private_bytes(
            &canonical(&statement).expect("JSON"),
        )
        .expect("changed data");
        let signature = key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        assert!(
            request
                .with_signature(signature)
                .verify(binding, 42)
                .is_err(),
            "re-signed {field}"
        );
        resigned.push(field);
    }
    let mut changed = original.clone();
    changed["operation"] = json!("another-operation");
    let target =
        EffectBinding::from_private_bytes(&canonical(&changed).expect("JSON")).expect("binding");
    assert!(ack.verify(&target, 42).is_err());
    assert!(ack.verify(binding, 41).is_err());
    assert!(
        DisclosureAcknowledgementRequest::for_delivery(
            binding,
            101,
            key.verifying_key().to_bytes()
        )
        .is_err()
    );
    let foreign = SigningKey::from_bytes(&[37; 32]);
    assert!(
        DisclosureAcknowledgementRequest::for_delivery(
            binding,
            42,
            foreign.verifying_key().to_bytes()
        )
        .is_err()
    );
    let request =
        DisclosureAcknowledgementRequest::for_delivery(binding, 42, key.verifying_key().to_bytes())
            .expect("request");
    let forged = request.clone().with_signature(
        foreign
            .sign(&request.signing_message().expect("message"))
            .to_bytes(),
    );
    assert!(forged.verify(binding, 42).is_err());
    let mutation = EffectBinding::new(super::tests::wire()).expect("mutation");
    assert!(ack.verify(&mutation, 42).is_err());
    json!({"bound_dimension_substitutions_refused": cases, "resigned_assertion_substitutions_refused": resigned, "other_operation_refused": true,
        "different_byte_count_refused": true, "over_limit_refused": true,
        "other_signer_refused": true, "forged_signature_refused": true, "mutation_refused": true})
}

fn decoding(ack: &DisclosureAcknowledgement) -> Value {
    let bytes = ack.to_private_bytes().expect("canonical ACK");
    let text = std::str::from_utf8(&bytes).expect("JSON");
    for malformed in [
        format!("{text} "),
        text.replacen('{', "{\"extra\":0,", 1),
        text.replacen(
            "\"request\":{",
            "\"request\":{\"schema\":\"auths.gateway-disclosure-ack/1\",",
            1,
        ),
        text.replace(DISCLOSURE_ACK_SCHEMA, "auths.gateway-disclosure-ack/0"),
    ] {
        assert!(DisclosureAcknowledgement::from_private_bytes(malformed.as_bytes()).is_err());
    }
    for length in [0, MAX_DISCLOSURE_ACK_BYTES, MAX_DISCLOSURE_ACK_BYTES + 1] {
        assert!(DisclosureAcknowledgement::from_private_bytes(&vec![b' '; length]).is_err());
        assert!(DisclosureAcknowledgementRequest::from_private_bytes(&vec![b' '; length]).is_err());
    }
    let mut malformed: Value = serde_json::from_slice(&bytes).expect("JSON");
    malformed["signature_b64"] = json!("AA");
    assert!(
        DisclosureAcknowledgement::from_private_bytes(&canonical(&malformed).expect("JSON"))
            .is_err()
    );
    json!({"duplicate_unknown_obsolete_noncanonical_refused": true,
        "empty_limit_limit_plus_one_refused": true, "short_signature_refused": true})
}

#[test]
fn native_disclosure_acknowledgement_fixture_is_current() {
    let key = SigningKey::from_bytes(&[31; 32]);
    let binding = disclosure(&key);
    let ack = signed(&binding, 42, &key);
    let request = DisclosureAcknowledgementRequest::for_delivery(
        &binding,
        42,
        key.verifying_key().to_bytes(),
    )
    .expect("request");
    let request_bytes = request.to_private_bytes().expect("request bytes");
    assert_eq!(
        DisclosureAcknowledgementRequest::from_private_bytes(&request_bytes).expect("request"),
        request
    );
    let encoded = ack.to_private_bytes().expect("ACK");
    let retained = DisclosureAcknowledgement::from_private_bytes(&encoded).expect("decode");
    let authenticated = retained
        .verify(&binding, 42)
        .expect("authenticated history");
    assert_eq!(authenticated.as_private_bytes(), encoded.as_slice());
    for length in [0, 100] {
        assert!(
            signed(&binding, length, &key)
                .verify(&binding, length)
                .is_ok()
        );
    }
    assert_eq!(
        format!("{request:?}"),
        "DisclosureAcknowledgementRequest { private: [redacted] }"
    );
    assert_eq!(
        format!("{ack:?}"),
        "DisclosureAcknowledgement { private: [redacted] }"
    );
    assert_eq!(
        format!("{authenticated:?}"),
        "AuthenticatedDisclosureAcknowledgement { private: [redacted] }"
    );
    let fixture = json!({
        "schema": "auths.gateway-disclosure-ack-fixture/1",
        "scope": "native canonical evidence and pure reducer; no delivery, adapter or isolation claim",
        "request": serde_json::from_slice::<Value>(&request_bytes).expect("JSON"),
        "acknowledgement": serde_json::from_slice::<Value>(&encoded).expect("JSON"),
        "edges": edges(), "histories": histories(authenticated.as_private_bytes()),
        "state_mutations": field_mutations(authenticated.as_private_bytes()),
        "substitutions": substitutions(&binding, &ack, &key), "decoding": decoding(&ack),
        "empty_and_ceiling_byte_counts_verified": true,
        "no_current_authority_or_time_required_for_history": true,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/disclosure-acknowledgement.json");
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&fixture).expect("fixture JSON")
    );
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &text).expect("fixture");
    }
    assert_eq!(std::fs::read_to_string(&path).expect("fixture"), text);
}
