//! The qualification gate in front of the engine's lease: a qualified
//! deployment leases, and every fault refuses with its stable code before
//! the credential store is asked.

#![allow(clippy::too_many_lines, reason = "case tables read top to bottom")]

use crate::engine::tests::administration::{Host, Installation, installation};
use crate::{
    FixedClock, QualificationBundle, QualificationGate, QualificationPolicy, qualification_policy,
};
use auths_recipe_qualification::{
    QualificationTrustRoot, QualificationTuple, RecipeQualificationState, TargetOs, VerifierState,
};
use auths_recipe_qualification_issuance::{
    QualificationProposal,
    testkit::{self, TestRelease},
};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::Ordering};

const NOW: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;

fn digest(byte: &str) -> String {
    byte.repeat(32)
}

fn tuple_for(family: &str) -> QualificationTuple {
    serde_json::from_value(json!({
        "recipe_family": family,
        "compiled_recipe_sha256": digest("11"),
        "profile_lock_sha256": digest("22"),
        "provider_contract_id": digest("33"),
        "gateway_semantic_closure_sha256": digest("44"),
        "target": {
            "os": "linux",
            "arch": "x86_64",
            "gateway_package": "auths-gateway",
            "gateway_version": "1.0.0-rc.1",
            "gateway_build_sha256": digest("55"),
            "store_kind": "shared-file-v1",
            "store_schema": "auths.gateway-attempt/3",
            "credential_store_kind": "local-file-v1",
        },
    }))
    .expect("tuple")
}

fn tuple() -> QualificationTuple {
    tuple_for("example-field-update-v1")
}

fn proposal(index: u8, tuple: &QualificationTuple) -> QualificationProposal {
    testkit::proposal(index, tuple, NOW)
}

/// One change to a deployed tuple.
type Drift = fn(&mut QualificationTuple);

fn bundle(release: &TestRelease, proposals: &[&QualificationProposal]) -> QualificationBundle {
    let bytes = release.release(proposals);
    QualificationBundle {
        signer_certificate: bytes.signer_certificate,
        revocation_list: bytes.revocation_list,
        release_index: bytes.release_index,
        records: bytes.records,
        attestations: bytes.attestations,
    }
}

fn required(
    root: Option<QualificationTrustRoot>,
    deployment: QualificationTuple,
    clock: &Arc<FixedClock>,
) -> Arc<QualificationGate> {
    Arc::new(QualificationGate::new(
        QualificationPolicy::Required,
        root,
        Some(deployment),
        Box::new(Arc::clone(clock)),
        VerifierState::default(),
    ))
}

async fn host_with(gate: &Arc<QualificationGate>) -> (Installation, ()) {
    let mut installation = installation(8).await;
    #[cfg(feature = "loopback-provider")]
    {
        installation.first.engine = installation.first.engine.with_loopback_provider(9);
    }
    installation
        .first
        .engine
        .set_qualification(Arc::clone(gate));
    (installation, ())
}

async fn refusal(host: &Host) -> Option<String> {
    let before = host.leases.load(Ordering::SeqCst);
    let result = host.entry_refusal().await;
    assert_eq!(
        host.leases.load(Ordering::SeqCst) - before,
        u64::from(result.is_none()),
        "a qualified entry calls the store exactly once; a refusal calls it zero times"
    );
    result
}

#[tokio::test]
async fn an_engine_without_a_configured_gate_leases_nothing() {
    let (installation, ()) = host_with(&Arc::new(QualificationGate::unconfigured())).await;
    assert_eq!(
        refusal(&installation.first).await.as_deref(),
        Some("gateway.qualification.unavailable")
    );
    assert!(installation.first.lease_refused_after(|| {}).await);
    assert_eq!(installation.first.leases.load(Ordering::SeqCst), 0);
}

#[test]
fn verify_simulation_reports() {
    use sha2::Digest as _;
    use std::io::Read as _;

    let Some(directory) = std::env::var_os("AUTHS_QUALIFICATION_SIMULATION_OUTPUT") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    let bounded = |path: &std::path::Path, maximum: u64| {
        assert!(
            std::fs::symlink_metadata(path)
                .expect("metadata")
                .file_type()
                .is_file()
        );
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .expect("public file")
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .expect("bounded public file");
        assert!(bytes.len() as u64 <= maximum);
        bytes
    };
    let mut verified = Vec::new();
    for family in ["stripe-platform-refund-v1", "airtable-record-update-v1"] {
        let report = bounded(&directory.join(format!("{family}.json")), 1_048_576);
        let signature = bounded(&directory.join(format!("{family}.attestation.json")), 4096);
        assert!(crate::simulation_attestation::verify(&report, &signature));
        verified.push(
            json!({"family": family, "report_sha256": hex::encode(sha2::Sha256::digest(&report)),
            "signature_sha256": hex::encode(sha2::Sha256::digest(&signature))}),
        );
    }
    std::fs::write(
        directory.join("provider-signature-verification.json"),
        serde_json::to_vec_pretty(
            &json!({"schema": "auths.provider-simulation-signature-verification/1",
            "simulation": true, "stable_launch_ready": false, "verified": verified,
            "scope": "detached self-signed simulation reports; no production trust"}),
        )
        .expect("verification report"),
    )
    .expect("write verification report");
}

/// Rehearses the first ceremony under fresh ephemeral trust. The signed
/// records are deliberately the issuance testkit's placeholder records;
/// their excluded claim says they stand for no provider run. Family driver
/// measurements are separate artifacts, never substituted for this corpus.
#[tokio::test]
async fn operator_bootstrap_qualification_simulation() {
    use auths_recipe_qualification::{QualificationRootId, QualificationSignerId};
    use auths_recipe_qualification_issuance::{
        CertificateRequest, ReleaseSigner, RootSigner, SigningSeed,
    };

    let root_seed = SigningSeed::generate().expect("disposable root");
    let signer_seed = SigningSeed::generate().expect("disposable release signer");
    let root = RootSigner::create(
        &root_seed,
        QualificationRootId::parse("simulation-root").expect("root ID"),
    )
    .expect("root");
    let certificate = root
        .certify(CertificateRequest {
            signer_id: QualificationSignerId::parse("simulation-signer").expect("signer ID"),
            public_key_b64: signer_seed.public_key(),
            issued_at: NOW - HOUR,
            not_before: NOW - HOUR,
            not_after: NOW + 24 * HOUR,
        })
        .expect("certificate");
    let signer = ReleaseSigner::open(&signer_seed, certificate).expect("signer");
    let proposals = [
        proposal(1, &tuple_for("simulation-stripe-platform-refund-v1")),
        proposal(2, &tuple_for("simulation-airtable-update-v1")),
    ];
    let attestations: Vec<_> = proposals
        .iter()
        .map(|proposal| {
            signer
                .attest(proposal, NOW, NOW, NOW + 12 * HOUR)
                .expect("attestation")
        })
        .collect();
    let listed: Vec<_> = proposals
        .iter()
        .zip(&attestations)
        .map(|(proposal, attestation)| (proposal.record(), attestation))
        .collect();
    let index = signer.index(NOW, &listed).expect("signed index");
    let list = root
        .revoke(1, NOW - HOUR, NOW + 24 * HOUR, Vec::new(), Vec::new())
        .expect("list");
    let attested_bundle = QualificationBundle {
        signer_certificate: signer.certificate().canonical_bytes().to_vec(),
        revocation_list: list.canonical_bytes().to_vec(),
        release_index: index.canonical_bytes().to_vec(),
        records: proposals
            .iter()
            .map(|proposal| proposal.record().canonical_bytes().to_vec())
            .collect(),
        attestations: attestations
            .iter()
            .map(|attestation| attestation.canonical_bytes().to_vec())
            .collect(),
    };
    let clock = Arc::new(FixedClock::at(NOW));
    let mut measurements = Vec::new();
    for closed in &proposals {
        let deployment = closed.record().body().tuple.clone();
        let gate = required(Some(root.trust_root().clone()), deployment.clone(), &clock);
        let (installation, ()) = host_with(&gate).await;
        let host = &installation.first;
        assert_eq!(
            refusal(host).await.as_deref(),
            Some("gateway.qualification.unavailable")
        );
        let mut unsigned = attested_bundle.clone();
        unsigned.attestations.clear();
        assert!(gate.load(&unsigned));
        assert_eq!(
            refusal(host).await.as_deref(),
            Some("gateway.qualification.missing")
        );
        assert_eq!(host.leases.load(Ordering::SeqCst), 0);
        let before_signature_leases = host.leases.load(Ordering::SeqCst);
        assert!(gate.load(&attested_bundle));
        assert_eq!(refusal(host).await, None);
        assert_eq!(host.leases.load(Ordering::SeqCst), 1);
        let after_verified_import_leases = host.leases.load(Ordering::SeqCst);
        let mut forged = attested_bundle.clone();
        let position = forged.attestations[0].len() / 2;
        forged.attestations[0][position] ^= 1;
        assert!(gate.load(&forged));
        // The untouched second record may remain qualified. A corrupt member
        // cannot enable the record whose attestation was changed.
        if deployment.recipe_family == proposals[0].record().body().tuple.recipe_family {
            assert!(refusal(host).await.is_some());
            assert_eq!(host.leases.load(Ordering::SeqCst), 1);
        }
        assert!(gate.load(&attested_bundle));
        clock.set(NOW + 13 * HOUR);
        assert_eq!(
            refusal(host).await.as_deref(),
            Some("gateway.qualification.expired")
        );
        clock.set(NOW);
        let no_root = required(None, deployment.clone(), &clock);
        assert!(!no_root.load(&attested_bundle));
        let (untrusted, ()) = host_with(&no_root).await;
        assert_eq!(
            refusal(&untrusted.first).await.as_deref(),
            Some("gateway.qualification.unavailable")
        );
        assert_eq!(untrusted.first.leases.load(Ordering::SeqCst), 0);
        measurements.push(json!({"family": deployment.recipe_family,
            "before_signature_leases": before_signature_leases,
            "after_verified_import_leases": after_verified_import_leases,
            "unsigned_refused": true, "expired_refused": true, "missing_root_refused": true}));
    }
    if let Some(directory) = std::env::var_os("AUTHS_QUALIFICATION_SIMULATION_OUTPUT") {
        let directory = std::path::PathBuf::from(directory).join("bootstrap");
        std::fs::create_dir_all(&directory).expect("public output directory");
        std::fs::write(
            directory.join("root.json"),
            root.trust_root().canonical_bytes(),
        )
        .expect("public root");
        for (name, bytes) in [
            (
                "signer-certificate.json",
                &attested_bundle.signer_certificate,
            ),
            ("revocation-list.json", &attested_bundle.revocation_list),
            ("release-index.json", &attested_bundle.release_index),
        ] {
            std::fs::write(directory.join(name), bytes).expect("public artifact");
        }
        for (position, closed) in proposals.iter().enumerate() {
            std::fs::write(
                directory.join(format!("record-{position}.json")),
                closed.record().canonical_bytes(),
            )
            .expect("record");
            std::fs::write(
                directory.join(format!("attestation-{position}.json")),
                &attested_bundle.attestations[position],
            )
            .expect("attestation");
            for (member, evidence) in closed.evidence().iter().enumerate() {
                std::fs::write(
                    directory.join(format!("fixture-evidence-{position}-{member}.json")),
                    evidence.canonical_bytes(),
                )
                .expect("explicit fixture");
            }
        }
        std::fs::write(directory.join("simulation.json"), serde_json::to_vec_pretty(&json!({
            "schema": "auths.qualification-bootstrap-simulation/1", "simulation": true,
            "stable_launch_ready": false, "ephemeral_keys_destroyed_on_return": true,
            "clock": {"kind": "fixed-test-clock", "unix_seconds": NOW},
            "evidence_kind": "explicit placeholder fixtures: no provider-run claim",
            "measurements": measurements, "production_root_changed": false,
            "excluded_claims": ["production qualification", "live provider acceptance", "human review"]
        })).expect("report")).expect("write report");
    }
}

#[tokio::test]
async fn a_qualified_deployment_leases_and_each_fault_refuses_before_the_lease() {
    let release = TestRelease::new(NOW);
    let closed = proposal(1, &tuple());
    let qualification_id = closed.record().body().qualification_id.clone();
    let bundle = bundle(&release, &[&closed]);
    let clock = Arc::new(FixedClock::at(NOW));
    let gate = required(Some(release.pinned()), tuple(), &clock);
    let (installation, ()) = host_with(&gate).await;
    let host = &installation.first;

    // Nothing imported: the recipe is disabled, and nothing else is.
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.unavailable")
    );
    assert!(gate.load(&bundle));
    assert_eq!(refusal(host).await, None, "a qualified deployment leases");
    assert!(!gate.load(&bundle), "equal inputs are not verified again");
    assert_eq!(gate.status().state, RecipeQualificationState::Qualified);

    // Trusted time decides at every lease, with no cache to refresh.
    clock.trust_is(false);
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.clock-untrusted")
    );
    clock.trust_is(true);
    clock.set(NOW - 2 * HOUR);
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.clock-untrusted"),
        "local time behind a signed issue time"
    );
    clock.set(NOW + 48 * HOUR);
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.revocation-stale")
    );
    clock.set(NOW);
    let leases_before_expiry = host.leases.load(Ordering::SeqCst);
    assert!(
        host.lease_refused_after(|| clock.set(NOW + 48 * HOUR))
            .await,
        "an entry prepared while qualified does not lease after the list went stale"
    );
    assert_eq!(host.leases.load(Ordering::SeqCst), leases_before_expiry);
    clock.set(NOW);
    assert_eq!(refusal(host).await, None);

    // A fresh list long after the attestation ended.
    let after = closed.record().body().not_after + 1;
    let mut expired = bundle.clone();
    expired.revocation_list = release.list(2, after, &[]);
    assert!(gate.load(&expired));
    clock.set(after);
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.expired")
    );
    clock.set(NOW);

    // Forged and unsigned inputs.
    // Each keeps the list the gate last accepted, so only the fault named
    // can be what refuses.
    let mut forged = expired.clone();
    let last = forged.release_index.len() - 3;
    forged.release_index[last] ^= 1;
    assert!(gate.load(&forged));
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.unavailable")
    );
    let mut unsigned = expired.clone();
    unsigned.release_index.clear();
    unsigned.attestations.clear();
    assert!(gate.load(&unsigned));
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.unavailable"),
        "a record no signer indexed"
    );

    // Revocation, and a later list that omits it.
    let mut revoking = bundle.clone();
    revoking.revocation_list = release.list(3, NOW, &[&qualification_id]);
    assert!(gate.load(&revoking));
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.revoked")
    );
    let mut omitting = bundle.clone();
    omitting.revocation_list = release.list(4, NOW, &[]);
    assert!(gate.load(&omitting));
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.revoked"),
        "a later list does not restore a revoked qualification"
    );
    assert!(
        gate.verifier_state()
            .revoked_qualifications
            .contains(&qualification_id)
    );
    assert_eq!(gate.verifier_state().accepted_revocation_sequence, 4);
    assert!(gate.load(&bundle));
    assert_eq!(
        refusal(host).await.as_deref(),
        Some("gateway.qualification.revoked"),
        "an older list is refused and the revocation stands"
    );
    assert!(!gate.inputs_usable(), "an older list is not importable");
    assert!(gate.load(&omitting));
    assert!(gate.inputs_usable());
    assert!(gate.load(&unsigned));
    assert!(
        !gate.inputs_usable(),
        "an unsigned record is not importable"
    );
}

#[tokio::test]
async fn a_drifted_deployment_is_stale_under_the_same_release() {
    let release = TestRelease::new(NOW);
    let closed = proposal(1, &tuple());
    let other_family = proposal(2, &tuple_for("example-other-v1"));
    let bundle = bundle(&release, &[&closed, &other_family]);
    let clock = Arc::new(FixedClock::at(NOW));
    let cases: [(&str, Drift, &str); 4] = [
        (
            "recipe",
            |tuple| tuple.compiled_recipe_sha256 = tuple.profile_lock_sha256,
            "gateway.qualification.digest-mismatch",
        ),
        (
            "closure",
            |tuple| tuple.gateway_semantic_closure_sha256 = tuple.profile_lock_sha256,
            "gateway.qualification.digest-mismatch",
        ),
        (
            "operating system",
            |tuple| tuple.target.os = TargetOs::Macos,
            "gateway.qualification.target-mismatch",
        ),
        (
            "build",
            |tuple| tuple.target.gateway_build_sha256 = tuple.profile_lock_sha256,
            "gateway.qualification.target-mismatch",
        ),
    ];
    for (member, drift, code) in cases {
        let mut deployed = tuple();
        drift(&mut deployed);
        let gate = required(Some(release.pinned()), deployed, &clock);
        gate.load(&bundle);
        let (installation, ()) = host_with(&gate).await;
        assert_eq!(
            refusal(&installation.first).await.as_deref(),
            Some(code),
            "{member}"
        );
        assert_eq!(
            gate.status().state,
            RecipeQualificationState::Stale,
            "{member}"
        );
    }

    // A family the release does not attest is missing, and the family it
    // does attest is unaffected by the other's presence.
    let unattested = required(
        Some(release.pinned()),
        tuple_for("example-third-v1"),
        &clock,
    );
    unattested.load(&bundle);
    assert_eq!(unattested.check(), Err("gateway.qualification.missing"));
    let attested = required(
        Some(release.pinned()),
        tuple_for("example-other-v1"),
        &clock,
    );
    attested.load(&bundle);
    assert_eq!(attested.check(), Ok(()));

    // Another root's release qualifies nothing here.
    let elsewhere = required(Some(TestRelease::foreign_root()), tuple(), &clock);
    elsewhere.load(&bundle);
    assert_eq!(elsewhere.check(), Err("gateway.qualification.unavailable"));
}

#[tokio::test]
async fn the_optional_policy_reports_and_never_refuses() {
    let (installation, ()) = host_with(&Arc::new(QualificationGate::development())).await;
    assert_eq!(refusal(&installation.first).await, None);
    let status = installation.first.engine.qualification().status();
    assert_eq!(status.policy, QualificationPolicy::Optional);
    assert_eq!(status.state, RecipeQualificationState::Unqualified);
    assert_eq!(status.code, Some("gateway.qualification.unavailable"));
    assert!(status.permits_lease());
}

#[test]
fn production_never_accepts_the_optional_policy() {
    use QualificationPolicy::{Optional, Required};
    assert_eq!(qualification_policy(None, true), Ok(Required));
    assert_eq!(qualification_policy(Some("required"), true), Ok(Required));
    assert_eq!(qualification_policy(None, false), Ok(Optional));
    assert_eq!(qualification_policy(Some("optional"), false), Ok(Optional));
    assert_eq!(qualification_policy(Some("required"), false), Ok(Required));
    for refused in ["optional", "Optional", "none", "", "required ", "force"] {
        assert_eq!(
            qualification_policy(Some(refused), true),
            Err(crate::QUALIFICATION_POLICY_REFUSED),
            "{refused:?} under production"
        );
    }
    for refused in ["Required", "none", "", "force"] {
        assert_eq!(
            qualification_policy(Some(refused), false),
            Err(crate::QUALIFICATION_POLICY_REFUSED),
            "{refused:?} under development"
        );
    }
}

/// Every frozen verification case, decided by the gate with the code the
/// case freezes.
#[test]
fn every_frozen_verification_case_decides_the_gate() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/qualification/verification-vectors.json"
    ))
    .expect("vectors");
    let base = &corpus["base"];
    let root = QualificationTrustRoot::from_canonical_json(
        base["trust_root"].as_str().expect("root").as_bytes(),
    )
    .expect("trust root");
    let cases = corpus["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 57);
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let input = |member: &str| case["replace"].get(member).unwrap_or(&base[member]);
        let bytes = |member: &str| input(member).as_str().expect("text").as_bytes().to_vec();
        let all = |member: &str| -> Vec<Vec<u8>> {
            input(member)
                .as_array()
                .expect("texts")
                .iter()
                .map(|text| text.as_str().expect("text").as_bytes().to_vec())
                .collect()
        };
        let known = input("known_revocations");
        let state = VerifierState {
            accepted_revocation_sequence: input("accepted_revocation_sequence")
                .as_u64()
                .expect("sequence"),
            revoked_signers: serde_json::from_value(known["signers"].clone()).expect("signers"),
            revoked_qualifications: serde_json::from_value(known["qualifications"].clone())
                .expect("qualifications"),
            ..VerifierState::default()
        };
        let clock = Arc::new(FixedClock::at(input("now").as_u64().expect("now")));
        clock.trust_is(input("clock") == "trusted");
        let gate = QualificationGate::new(
            QualificationPolicy::Required,
            Some(root.clone()),
            Some(serde_json::from_value(input("deployment").clone()).expect("deployment")),
            Box::new(clock),
            state,
        );
        gate.load(&QualificationBundle {
            signer_certificate: bytes("signer_certificate"),
            revocation_list: bytes("revocation_list"),
            release_index: bytes("release_index"),
            records: all("records"),
            attestations: all("attestations"),
        });
        let status = gate.status();
        assert_eq!(
            status.state.as_str(),
            case["expect"]["state"],
            "case {id}: state"
        );
        assert_eq!(
            json!(status.code),
            case["expect"]["code"],
            "case {id}: code"
        );
        assert_eq!(
            json!(gate.check().is_ok()),
            case["expect"]["lease"],
            "case {id}: lease"
        );
    }
}

/// The gate is told a provider contract as a digest and nothing else about
/// a provider, and contains no oracle.
#[test]
fn the_gate_is_told_no_provider_name_and_runs_no_oracle() {
    let source = include_str!("qualification.rs").to_lowercase();
    for forbidden in [
        "providerkind",
        "provider_kind",
        "oracle(",
        "fn oracle",
        "alias",
    ] {
        assert!(!source.contains(forbidden), "the gate names {forbidden}");
    }
}
