//! Original native evidence replay over maintained adapters. Checkpoints and
//! times here are controlled fixture inputs, not externally anchored evidence.
use super::configuration_tests::{ControlFaultStore, controller};
use super::{Fixture, NOW, invocation};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    EngagementAudit, EngagementAuditCheckpoint, EngagementConfigurationError as Error, FixedClock,
    GatewayAttemptError, GatewayRecordKind,
};
use base64ct::{Base64, Encoding as _};
use serde_json::{Value, json};
use std::sync::Arc;

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}
fn envelope(audit: &EngagementAudit) -> Value {
    serde_json::from_slice(audit.private_bytes()).unwrap()
}
fn decoded(value: &Value) -> EngagementAudit {
    EngagementAudit::from_private_bytes(&canonical(value)).unwrap()
}

fn checkpoint(envelope: &Value, original: &EngagementAuditCheckpoint) -> EngagementAuditCheckpoint {
    // This helper deliberately trusts a forged metadata head to isolate native
    // proof validation. Production callers must never obtain trust this way.
    let mut value: Value = serde_json::from_slice(&original.to_private_bytes().unwrap()).unwrap();
    value["record"] = json!(
        *auths_codec::domain_commitment(
            "auths.engagement-audit-checkpoint/1",
            envelope["configuration"].as_str().unwrap().as_bytes()
        )
        .unwrap()
        .as_bytes()
    );
    EngagementAuditCheckpoint::from_private_bytes(&canonical(&value)).unwrap()
}

fn forge_child_signature(audit: &EngagementAudit) -> Value {
    let mut value = envelope(audit);
    let mut record: Value = serde_json::from_str(value["configuration"].as_str().unwrap()).unwrap();
    let blobs = value["blobs"].as_array_mut().unwrap();
    let mut forged = false;
    for blob in &mut *blobs {
        let bytes = Base64::decode_vec(blob["data_b64"].as_str().unwrap()).unwrap();
        let Ok(mut inputs) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if inputs["control"]["kind"] != "enroll" {
            continue;
        }
        let original = blob["reference"].clone();
        let proof = &mut inputs["control"]["acceptance"]["proof_b64"];
        let mut bytes = Base64::decode_vec(proof.as_str().unwrap()).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        *proof = json!(Base64::encode_string(&bytes));
        let bytes = canonical(&inputs);
        let reference = json!({"commitment":*auths_codec::domain_commitment("auths.engagement-audit-blob/1",&bytes).unwrap().as_bytes(),"bytes":bytes.len()});
        blob["reference"] = reference.clone();
        blob["data_b64"] = json!(Base64::encode_string(&bytes));
        for event in record["events"].as_array_mut().unwrap() {
            if event["inputs"] == original {
                event["inputs"] = reference.clone();
            }
        }
        forged = true;
        break;
    }
    assert!(forged);
    blobs.sort_by_key(|b| {
        (
            serde_json::from_value::<[u8; 32]>(b["reference"]["commitment"].clone()).unwrap(),
            b["reference"]["bytes"].as_u64().unwrap(),
        )
    });
    value["configuration"] = json!(String::from_utf8(canonical(&record)).unwrap());
    value
}

#[allow(
    clippy::too_many_lines,
    reason = "one native audit history and all independently trusted input substitutions"
)]
fn lifecycle(backend: Backend) -> Value {
    let db = TestAttempts::open(backend);
    let clock = Arc::new(FixedClock::at(NOW));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, db.raw(), Arc::clone(&clock));
    let initial = fixture.bootstrap_configuration(&control).unwrap();
    let old_checkpoint = initial.audit_checkpoint().unwrap();
    let retained_prefix = control.export_audit().unwrap();
    fixture.enroll_configuration(&control).unwrap();
    clock.set(NOW + 1);
    let child = fixture.enrollment.commitment().unwrap();
    control
        .revoke(&invocation(&fixture.withdraw_as_parent(child)))
        .unwrap();
    let snapshot = control
        .revoke(&invocation(
            &fixture.withdraw_as_parent(fixture.pins.enrollment_commitment),
        ))
        .unwrap();
    let trusted = snapshot.audit_checkpoint().unwrap();
    let archive = control.export_audit().unwrap();
    let contexts = [fixture.context.clone()];
    assert_eq!(
        retained_prefix.verify(&fixture.pins, &contexts, &trusted),
        Err(Error::UntrustedEvidence),
        "a restored coherent prefix cannot satisfy an independently retained newer head"
    );
    assert_eq!(
        archive.verify(&fixture.pins, &contexts, &trusted).unwrap(),
        snapshot
    );
    assert_eq!(
        archive.verify(&fixture.pins, &contexts, &old_checkpoint),
        Err(Error::UntrustedEvidence)
    );
    assert_eq!(
        archive.verify(&fixture.pins, &[], &trusted),
        Err(Error::UntrustedEvidence)
    );
    let mut wrong = Fixture::new();
    wrong.pins.admission_partition = "other-audit-partition".into();
    wrong.commit_root();
    assert!(archive.verify(&wrong.pins, &contexts, &trusted).is_err());
    let trusted_bytes = trusted.to_private_bytes().unwrap();
    assert_eq!(
        EngagementAuditCheckpoint::from_private_bytes(&trusted_bytes).unwrap(),
        trusted
    );
    let mut noncanonical = trusted_bytes.to_vec();
    noncanonical.push(b'\n');
    assert!(EngagementAuditCheckpoint::from_private_bytes(&noncanonical).is_err());
    let mut noncanonical = archive.private_bytes().to_vec();
    noncanonical.push(b'\n');
    assert!(EngagementAudit::from_private_bytes(&noncanonical).is_err());
    let mut too_many = envelope(&archive);
    too_many["blobs"] = json!(vec![too_many["blobs"][0].clone(); 65]);
    assert!(EngagementAudit::from_private_bytes(&canonical(&too_many)).is_err());
    for case in 0..5 {
        let mut changed = envelope(&archive);
        match case {
            0 => {
                changed["blobs"].as_array_mut().unwrap().pop();
            }
            1 => {
                changed["blobs"][0] = changed["blobs"][1].clone();
            }
            2 => {
                changed["blobs"][0]["data_b64"] =
                    json!(Base64::encode_string(b"SYNTHETIC-WRONG-EVIDENCE"));
            }
            3 => changed["blobs"][0]["reference"]["bytes"] = json!(0),
            _ => changed["blobs"].as_array_mut().unwrap().reverse(),
        }
        assert!(
            decoded(&changed)
                .verify(&fixture.pins, &contexts, &trusted)
                .is_err(),
            "case {case}"
        );
    }
    let forged = forge_child_signature(&archive);
    let forged_checkpoint = checkpoint(&forged, &trusted);
    assert_eq!(
        decoded(&forged).verify(&fixture.pins, &contexts, &trusted),
        Err(Error::UntrustedEvidence)
    );
    // Even a trusted metadata head is not a valid child acceptance signature.
    assert!(matches!(
        decoded(&forged).verify(&fixture.pins, &contexts, &forged_checkpoint),
        Err(Error::Native(_))
    ));
    let mut late = envelope(&archive);
    let mut record: Value = serde_json::from_str(late["configuration"].as_str().unwrap()).unwrap();
    record["accepted_at"] = json!(NOW + 3601);
    record["events"].as_array_mut().unwrap().last_mut().unwrap()["accepted_at"] = json!(NOW + 3601);
    late["configuration"] = json!(String::from_utf8(canonical(&record)).unwrap());
    assert!(matches!(
        decoded(&late).verify(&fixture.pins, &contexts, &checkpoint(&late, &trusted)),
        Err(Error::Native(_))
    ));
    let value = envelope(&archive);
    let store = db.raw();
    let stored = store
        .load(
            GatewayRecordKind::EffectConfiguration,
            &control.dependency_key(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(value["configuration"].as_str().unwrap().as_bytes(), stored);
    // Corrupt one actual permanent chunk, not an edited audit projection.
    // Export must report the missing/corrupt evidence explicitly; restoring
    // fixture bytes never grants new authority or changes the retained head.
    let chunk_key = crate::GatewayAttemptKey::from_bytes(
        *auths_codec::domain_commitment(
            "auths.engagement-audit-record-key/1",
            &canonical(&json!([value["blobs"][0]["reference"], 0])),
        )
        .unwrap()
        .as_bytes(),
    );
    let original_chunk = store
        .load(GatewayRecordKind::EffectConfiguration, &chunk_key)
        .unwrap()
        .unwrap();
    store
        .replace(
            GatewayRecordKind::EffectConfiguration,
            &chunk_key,
            &original_chunk,
            b"SYNTHETIC-CORRUPT-AUDIT-CHUNK",
        )
        .unwrap();
    assert!(control.export_audit().is_err());
    assert_eq!(control.snapshot().unwrap(), snapshot);
    store
        .replace(
            GatewayRecordKind::EffectConfiguration,
            &chunk_key,
            b"SYNTHETIC-CORRUPT-AUDIT-CHUNK",
            &original_chunk,
        )
        .unwrap();
    clock.set(NOW + 86400);
    let (reopened, _) = controller(&fixture, db.reopen().store(), Arc::clone(&clock));
    let history = reopened.export_audit().unwrap();
    assert_eq!(history.private_bytes(), archive.private_bytes());
    assert_eq!(
        history.verify(&fixture.pins, &contexts, &trusted).unwrap(),
        snapshot
    );
    assert!(
        snapshot
            .tree()
            .parent_pins(fixture.pins.enrollment_commitment, NOW + 86400)
            .is_err()
    );
    for debug in [
        format!("{archive:?}"),
        format!("{trusted:?}"),
        format!("{snapshot:?}"),
    ] {
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(fixture.child.principal.as_str()));
    }
    assert!(store.attempt_keys(16).unwrap().is_empty());
    json!({"bundle":value,"fixture_trusted_root":fixture.pins,
        "fixture_trusted_context_cbor_b64":Base64::encode_string(&auths_codec::encode_verifier_context(&fixture.context).unwrap()),
        "fixture_trusted_checkpoint":serde_json::from_slice::<Value>(&trusted_bytes).unwrap(),
        "verified_revision":snapshot.revision(),"participants":snapshot.tree().participant_count(),
        "cases":["full-native-replay","original-context-required","checkpoint-floor","restored-prefix-vs-current-checkpoint","wrong-root",
            "missing-blob","duplicate-blob","corrupt-blob","blob-length","blob-order",
            "forged-child-signature-even-with-trusted-metadata","native-validity-at-recorded-time",
            "historical-expiry-is-not-current-authority","reopen-original-bytes","corrupt-retained-chunk-export-refused"],
        "operation_records":0,"provider_requests":0})
}

fn acknowledgements(backend: Backend) {
    let db = TestAttempts::open(backend);
    let clock = Arc::new(FixedClock::at(NOW));
    let fault = Arc::new(ControlFaultStore::new(db.raw(), Arc::clone(&clock)));
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let (control, _) = controller(&fixture, fault.clone(), clock);
    let initial = fixture.bootstrap_configuration(&control).unwrap();
    let initial_export = control.export_audit().unwrap();
    fault.lose_next_blob_reply();
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(Error::Store(GatewayAttemptError::Unavailable))
    );
    assert_eq!(control.snapshot().unwrap(), initial);
    assert_eq!(
        control.export_audit().unwrap().private_bytes(),
        initial_export.private_bytes()
    );
    fault.hide_next_manifest();
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(Error::MissingEvidence)
    );
    assert_eq!(control.snapshot().unwrap(), initial);
    fault.lose_next_control_reply();
    assert_eq!(
        fixture.enroll_configuration(&control),
        Err(Error::Store(GatewayAttemptError::Unavailable))
    );
    let accepted = control.snapshot().unwrap();
    assert_eq!(accepted.revision(), 2);
    let archive = control.export_audit().unwrap();
    assert_eq!(
        archive
            .verify(
                &fixture.pins,
                &[fixture.context.clone()],
                &accepted.audit_checkpoint().unwrap()
            )
            .unwrap(),
        accepted
    );
    assert!(fixture.enroll_configuration(&control).is_err());
    assert_eq!(
        control.export_audit().unwrap().private_bytes(),
        archive.private_bytes()
    );
}

#[test]
fn native_engagement_audit_fixture_is_current() {
    // Independent constructor cases all run even if one panics.
    let history = std::thread::spawn(|| lifecycle(Backend::File));
    let acknowledgement = std::thread::spawn(|| acknowledgements(Backend::File));
    let history = history.join();
    let acknowledgement = acknowledgement.join();
    assert!(
        history.is_ok() && acknowledgement.is_ok(),
        "native audit constructor cases failed"
    );
    let value = json!({"schema":"auths.engagement-audit-vectors/1",
        "generated_by":"native_engagement_audit_fixture_is_current",
        "scope":"full original native control replay from actual file-backed records; fixture trust/context/checkpoint and clock; no operation grant or provider request",
        "not_established":["external-checkpoint-authentication","external-timestamp-authentication",
            "whole-store-rollback-detection","postgres-execution","process-crash","installed-key-containment"],
        "case":history.unwrap(),"acknowledgement_loss_and_missing_manifest_fail_closed":true});
    let bytes = canonical(&value);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/audit.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn postgres_native_original_control_audit_and_acknowledgement_history() {
    if postgres_configured() {
        lifecycle(Backend::Postgres);
        acknowledgements(Backend::Postgres);
    }
}

proptest::proptest! {
    #[test]
    fn audit_and_checkpoint_arbitrary_bytes_never_create_authority(bytes in proptest::collection::vec(proptest::num::u8::ANY,0..8192)) {
        if let Ok(audit)=EngagementAudit::from_private_bytes(&bytes) {
            proptest::prop_assert_eq!(audit.private_bytes(),bytes.as_slice());
            let printed=format!("{audit:?}");
            proptest::prop_assert!(printed.contains("[redacted]"));
        }
        if let Ok(checkpoint)=EngagementAuditCheckpoint::from_private_bytes(&bytes) {
            let roundtrip=checkpoint.to_private_bytes().unwrap();
            proptest::prop_assert_eq!(roundtrip.as_slice(),bytes.as_slice());
        }
    }
}
