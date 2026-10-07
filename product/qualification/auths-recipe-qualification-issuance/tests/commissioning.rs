//! Purpose separation, closed bounds and exact-run commissioning verification.
//! All keys and evidence are synthetic public test constants; no provider
//! qualification or durable lease consumption is claimed by these tests.

#![allow(clippy::too_many_lines, reason = "explicit hostile case tables")]

mod common;

use auths_recipe_qualification::{
    BoundedText, ClosureFault, CommissioningBinding, CommissioningInputs,
    CommissioningOfflineEvidence, CommissioningRefusal, CommissioningRequest, EvidenceMemberKind,
    GitCommit, MAX_COMMISSIONING_ACTIONS, MAX_COMMISSIONING_LEASES, MAX_COMMISSIONING_PERMIT_BYTES,
    MAX_COMMISSIONING_SECONDS, ProviderEnvironmentClass, QualificationArtifactKind,
    QualificationCommissioningPermit, QualificationEvidence, QualificationFormatError,
    QualificationInputs, QualificationRevocationList, QualificationRootId,
    QualificationSignerCertificate, QualificationSignerId, QualificationTuple,
    RecipeQualificationState, Scenario, Sha256Digest, SignatureB64, VerifiedCommissioningPermit,
    VerifiedQualifications, VerifierState,
};
use auths_recipe_qualification_issuance::{
    CertificateRequest, CommissioningProposal, CommissioningSigner, IssuanceError, ReleaseSigner,
    RootSigner, SigningSeed,
};
use common::{DAY, HOUR, NOW, commit, member_evidence, tuple};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn seed(byte: u8) -> SigningSeed {
    SigningSeed::from_bytes(Zeroizing::new([byte; 32]))
}

fn root() -> RootSigner {
    RootSigner::create(
        &seed(0x11),
        QualificationRootId::parse("test-root").expect("root"),
    )
    .expect("root")
}

fn certificate_request() -> CertificateRequest {
    CertificateRequest {
        signer_id: QualificationSignerId::parse("test-commissioner").expect("signer"),
        public_key_b64: seed(0x22).public_key(),
        issued_at: NOW - DAY,
        not_before: NOW - DAY,
        not_after: NOW + DAY,
    }
}

fn commissioner(root: &RootSigner) -> CommissioningSigner {
    CommissioningSigner::open(
        &seed(0x22),
        root.certify_commissioner(certificate_request())
            .expect("certificate"),
    )
    .expect("commissioner")
}

fn binding() -> CommissioningBinding {
    CommissioningBinding {
        protected_run: BoundedText::parse(
            "github.com/auths-dev/auths-proof/actions/runs/1/attempts/1",
        )
        .expect("run"),
        source_commit: commit(),
        tuple: tuple(),
        principal_sha256: digest(0x60),
        trusted_context_sha256: digest(0x61),
        resources_sha256: digest(0x62),
        provider_environment_class: ProviderEnvironmentClass::ProviderTestMode,
        offline_evidence: CommissioningOfflineEvidence {
            conformance_sha256: member_evidence(EvidenceMemberKind::Conformance).digest(),
            differential_sha256: member_evidence(EvidenceMemberKind::Differential).digest(),
        },
        allowed_actions: vec![digest(0x63), digest(0x64)],
        maximum_credential_leases: 32,
    }
}

fn proposal() -> CommissioningProposal {
    CommissioningProposal::assemble(
        binding(),
        member_evidence(EvidenceMemberKind::Conformance),
        member_evidence(EvidenceMemberKind::Differential),
    )
    .expect("proposal")
}

fn permit(signer: &CommissioningSigner) -> QualificationCommissioningPermit {
    signer
        .permit(&proposal(), NOW, NOW, NOW + MAX_COMMISSIONING_SECONDS)
        .expect("permit")
}

fn revocations(root: &RootSigner, sequence: u64) -> QualificationRevocationList {
    root.revoke(sequence, NOW - HOUR, NOW + 24 * HOUR, vec![], vec![])
        .expect("list")
}

fn verify(
    root: &RootSigner,
    certificate: &QualificationSignerCertificate,
    list: &QualificationRevocationList,
    permit: &QualificationCommissioningPermit,
) -> Result<VerifiedCommissioningPermit, CommissioningRefusal> {
    VerifiedCommissioningPermit::verify(
        root.trust_root(),
        &CommissioningInputs {
            signer_certificate: certificate.canonical_bytes(),
            revocation_list: list.canonical_bytes(),
            permit: permit.canonical_bytes(),
        },
    )
}

fn request(binding: &CommissioningBinding) -> CommissioningRequest<'_> {
    CommissioningRequest {
        source_commit: &binding.source_commit,
        tuple: &binding.tuple,
        protected_run: &binding.protected_run,
        principal_sha256: binding.principal_sha256,
        trusted_context_sha256: binding.trusted_context_sha256,
        resources_sha256: binding.resources_sha256,
        canonical_action_sha256: binding.allowed_actions[0],
    }
}

#[test]
fn a_commissioning_permit_never_qualifies_ordinary_production() {
    let root = root();
    let signer = commissioner(&root);
    let permit = permit(&signer);
    let list = revocations(&root, 1);
    let verified = verify(&root, signer.certificate(), &list, &permit).expect("authority");
    assert_eq!(verified.permit(), &permit);
    assert_eq!(
        verified.evaluate(&request(&binding()), NOW, true, &VerifierState::default()),
        Ok(())
    );
    // No permit bytes decode as a record, attestation or release index, even
    // when the normal verifier receives the valid purpose certificate/list.
    let ordinary = VerifiedQualifications::verify(
        root.trust_root(),
        &QualificationInputs {
            signer_certificate: signer.certificate().canonical_bytes(),
            revocation_list: list.canonical_bytes(),
            release_index: permit.canonical_bytes(),
            records: &[permit.canonical_bytes()],
            attestations: &[permit.canonical_bytes()],
        },
    );
    let verdict = ordinary.evaluate(&tuple(), NOW, true, &VerifierState::default());
    assert_eq!(verdict.state, RecipeQualificationState::Unqualified);
    assert!(!verdict.permits_lease());
}

#[test]
fn commissioning_and_release_signers_have_separate_purposes() {
    let root = root();
    let signer = commissioner(&root);
    let release_certificate = root.certify(certificate_request()).expect("certificate");
    assert_eq!(
        CommissioningSigner::open(&seed(0x22), release_certificate.clone()).map(|_| ()),
        Err(IssuanceError::NotPermitted)
    );
    assert_eq!(
        CommissioningSigner::open(&seed(0x33), signer.certificate().clone()).map(|_| ()),
        Err(IssuanceError::KeyMismatch)
    );
    let release = ReleaseSigner::open(&seed(0x22), signer.certificate().clone()).expect("key");
    assert_eq!(
        release.index(NOW, &[]).map(|_| ()),
        Err(IssuanceError::NotPermitted)
    );
    let record = auths_recipe_qualification_issuance::QualificationProposal::assemble(
        common::draft(),
        common::all_evidence(),
    )
    .expect("record proposal");
    assert_eq!(
        release.attest(&record, NOW, NOW, NOW + HOUR).map(|_| ()),
        Err(IssuanceError::NotPermitted)
    );
    let permit = permit(&signer);
    let list = revocations(&root, 1);
    assert_eq!(
        verify(&root, &release_certificate, &list, &permit).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );

    // Even an authentic mixed-purpose certificate is rejected. The offline
    // authority must explicitly separate commissioning and qualification keys.
    let mut mixed = signer.certificate().body().clone();
    mixed
        .statement
        .permitted_artifact_kinds
        .push(QualificationArtifactKind::QualificationReleaseIndex);
    mixed.root_signature_b64 = SignatureB64::from_bytes(
        &SigningKey::from_bytes(seed(0x11).expose())
            .sign(&mixed.signing_preimage().expect("preimage"))
            .to_bytes(),
    );
    let mixed = QualificationSignerCertificate::from_body(&mixed).expect("mixed certificate");
    assert_eq!(
        verify(&root, &mixed, &list, &permit).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    assert_eq!(
        CommissioningSigner::open(&seed(0x22), mixed).map(|_| ()),
        Err(IssuanceError::NotPermitted)
    );
    assert!(!format!("{signer:?}").contains("key"));
}

#[test]
fn each_signature_root_and_domain_is_required() {
    let root = root();
    let signer = commissioner(&root);
    let permit = permit(&signer);
    let list = revocations(&root, 1);
    let mut forged = permit.body().clone();
    forged.statement.binding.maximum_credential_leases += 1;
    let forged = QualificationCommissioningPermit::from_body(&forged).expect("changed body");
    assert_eq!(
        verify(&root, signer.certificate(), &list, &forged).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    let mut certificate = signer.certificate().body().clone();
    certificate.statement.not_after += 1;
    let certificate =
        QualificationSignerCertificate::from_body(&certificate).expect("changed certificate");
    assert_eq!(
        verify(&root, &certificate, &list, &permit).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    let mut changed_list = list.body().clone();
    changed_list.statement.sequence += 1;
    let changed_list = QualificationRevocationList::from_body(&changed_list).expect("changed list");
    assert_eq!(
        verify(&root, signer.certificate(), &changed_list, &permit).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    let other_root = RootSigner::create(
        &seed(0x33),
        QualificationRootId::parse("test-root").expect("root"),
    )
    .expect("root");
    assert_eq!(
        verify(&other_root, signer.certificate(), &list, &permit).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    let mut wrong_domain = permit.body().clone();
    let preimage = wrong_domain.signing_preimage().expect("preimage");
    let statement_bytes =
        &preimage[auths_recipe_qualification::COMMISSIONING_PERMIT_SCHEMA.len() + 1..];
    let substituted = [
        b"auths.recipe-qualification-attestation/1\0".as_slice(),
        statement_bytes,
    ]
    .concat();
    wrong_domain.signature_b64 = SignatureB64::from_bytes(
        &SigningKey::from_bytes(seed(0x22).expose())
            .sign(&substituted)
            .to_bytes(),
    );
    let wrong_domain = QualificationCommissioningPermit::from_body(&wrong_domain).expect("permit");
    assert_eq!(
        verify(&root, signer.certificate(), &list, &wrong_domain).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
    let mut wrong_signer = permit.body().clone();
    wrong_signer.statement.signer_id =
        QualificationSignerId::parse("another-commissioner").expect("signer");
    wrong_signer.signature_b64 = SignatureB64::from_bytes(
        &SigningKey::from_bytes(seed(0x22).expose())
            .sign(&wrong_signer.signing_preimage().expect("preimage"))
            .to_bytes(),
    );
    let wrong_signer = QualificationCommissioningPermit::from_body(&wrong_signer).expect("permit");
    assert_eq!(
        verify(&root, signer.certificate(), &list, &wrong_signer).map(|_| ()),
        Err(CommissioningRefusal::Unavailable)
    );
}

#[test]
fn every_runtime_binding_must_equal_the_reviewed_session() {
    let root = root();
    let signer = commissioner(&root);
    let verified = verify(
        &root,
        signer.certificate(),
        &revocations(&root, 1),
        &permit(&signer),
    )
    .expect("authority");
    let evaluate = |request: &CommissioningRequest<'_>| {
        verified.evaluate(request, NOW, true, &VerifierState::default())
    };
    let original = binding();
    let run = BoundedText::parse("github.com/auths-dev/auths-proof/actions/runs/2/attempts/1")
        .expect("run");
    let other_commit = GitCommit::parse("f".repeat(40)).expect("commit");
    for request in [
        CommissioningRequest {
            protected_run: &run,
            ..request(&original)
        },
        CommissioningRequest {
            source_commit: &other_commit,
            ..request(&original)
        },
        CommissioningRequest {
            principal_sha256: digest(0x70),
            ..request(&original)
        },
        CommissioningRequest {
            trusted_context_sha256: digest(0x70),
            ..request(&original)
        },
        CommissioningRequest {
            resources_sha256: digest(0x70),
            ..request(&original)
        },
        CommissioningRequest {
            canonical_action_sha256: digest(0x70),
            ..request(&original)
        },
    ] {
        assert_eq!(
            evaluate(&request),
            Err(CommissioningRefusal::BindingMismatch)
        );
    }
    for (pointer, changed) in [
        ("/recipe_family", json!("another-family")),
        ("/compiled_recipe_sha256", json!(digest(0x70))),
        ("/profile_lock_sha256", json!(digest(0x70))),
        ("/provider_contract_id", json!(digest(0x70))),
        ("/gateway_semantic_closure_sha256", json!(digest(0x70))),
        ("/target/os", json!("macos")),
        ("/target/arch", json!("aarch64")),
        ("/target/gateway_package", json!("another-gateway")),
        ("/target/gateway_version", json!("2.0.0")),
        ("/target/gateway_build_sha256", json!(digest(0x70))),
        ("/target/store_kind", json!("shared-file-v1")),
        ("/target/store_schema", json!("another-schema")),
        ("/target/credential_store_kind", json!("local-file-v1")),
    ] {
        let mut document = serde_json::to_value(tuple()).expect("tuple");
        *document.pointer_mut(pointer).expect("member") = changed;
        let target: QualificationTuple = serde_json::from_value(document).expect("tuple shape");
        assert_eq!(
            evaluate(&CommissioningRequest {
                tuple: &target,
                ..request(&original)
            }),
            Err(CommissioningRefusal::BindingMismatch),
            "{pointer}"
        );
    }
    let mut another_allowed = request(&original);
    another_allowed.canonical_action_sha256 = original.allowed_actions[1];
    assert_eq!(evaluate(&another_allowed), Ok(()));
}

#[test]
fn commissioning_windows_are_half_open_and_require_trusted_time() {
    let root = root();
    let signer = commissioner(&root);
    let verified = verify(
        &root,
        signer.certificate(),
        &revocations(&root, 1),
        &permit(&signer),
    )
    .expect("authority");
    let original = binding();
    for (time, trusted, expected) in [
        (NOW - 1, true, Err(CommissioningRefusal::ClockUntrusted)),
        (NOW, false, Err(CommissioningRefusal::ClockUntrusted)),
        (NOW, true, Ok(())),
        (NOW + MAX_COMMISSIONING_SECONDS - 1, true, Ok(())),
        (
            NOW + MAX_COMMISSIONING_SECONDS,
            true,
            Err(CommissioningRefusal::Expired),
        ),
    ] {
        assert_eq!(
            verified.evaluate(
                &request(&original),
                time,
                trusted,
                &VerifierState::default()
            ),
            expected
        );
    }
    let short_list = root
        .revoke(1, NOW - HOUR, NOW + 1, vec![], vec![])
        .expect("list");
    let verified =
        verify(&root, signer.certificate(), &short_list, &permit(&signer)).expect("authority");
    assert_eq!(
        verified.evaluate(
            &request(&original),
            NOW + 1,
            true,
            &VerifierState::default()
        ),
        Err(CommissioningRefusal::RevocationStale)
    );
    for (issued, start, end) in [
        (NOW, NOW, NOW),
        (NOW, NOW + 1, NOW + MAX_COMMISSIONING_SECONDS + 1),
        (NOW, NOW, NOW + MAX_COMMISSIONING_SECONDS + 1),
        (NOW + 1, NOW, NOW + HOUR),
        (NOW, NOW, u64::MAX),
    ] {
        assert_eq!(
            signer.permit(&proposal(), issued, start, end).map(|_| ()),
            if end == u64::MAX {
                Err(IssuanceError::Window)
            } else {
                Err(IssuanceError::Format(
                    QualificationFormatError::InvalidTimeWindow,
                ))
            }
        );
    }
    assert_eq!(
        signer
            .permit(
                &proposal(),
                NOW - 2 * DAY,
                NOW - 2 * DAY,
                NOW - 2 * DAY + HOUR
            )
            .map(|_| ()),
        Err(IssuanceError::Window)
    );
}

#[test]
fn revocations_are_permanent_and_an_older_list_cannot_restore_authority() {
    let root = root();
    let signer = commissioner(&root);
    let permit = permit(&signer);
    let original = binding();
    let revoked = root
        .revoke(
            2,
            NOW - HOUR,
            NOW + HOUR,
            vec![certificate_request().signer_id],
            vec![],
        )
        .expect("revoked");
    let verified = verify(&root, signer.certificate(), &revoked, &permit).expect("signatures");
    let mut state = VerifierState::default();
    assert_eq!(
        verified.evaluate(&request(&original), NOW, true, &state),
        Err(CommissioningRefusal::Revoked)
    );
    assert_eq!(
        verified.evaluate(&request(&original), NOW + 2 * HOUR, false, &state),
        Err(CommissioningRefusal::Revoked)
    );
    verified.remember(&mut state);
    let omitted =
        verify(&root, signer.certificate(), &revocations(&root, 3), &permit).expect("signatures");
    omitted.remember(&mut state);
    assert_eq!(state.accepted_revocation_sequence, 3);
    assert_eq!(
        omitted.evaluate(&request(&original), NOW, true, &state),
        Err(CommissioningRefusal::Revoked)
    );
    let unrevoked =
        verify(&root, signer.certificate(), &revocations(&root, 1), &permit).expect("signatures");
    let mut floor = VerifierState {
        accepted_revocation_sequence: 2,
        ..VerifierState::default()
    };
    unrevoked.remember(&mut floor);
    assert_eq!(floor.accepted_revocation_sequence, 2);
    assert_eq!(
        unrevoked.evaluate(&request(&original), NOW, true, &floor),
        Err(CommissioningRefusal::RevocationRollback)
    );
}

#[test]
fn proposal_rechecks_exact_offline_artifacts_and_all_required_scenarios() {
    let conformance = member_evidence(EvidenceMemberKind::Conformance);
    let differential = member_evidence(EvidenceMemberKind::Differential);
    for (member, source) in [
        (EvidenceMemberKind::Conformance, &conformance),
        (EvidenceMemberKind::Differential, &differential),
    ] {
        for scenario in Scenario::ALL {
            if scenario.member() != member || !scenario.always_required() {
                continue;
            }
            let mut incomplete = source.body().clone();
            incomplete.cases.retain(|case| case.scenario != scenario);
            let incomplete =
                QualificationEvidence::from_body(&incomplete).expect("incomplete artifact");
            let mut changed = binding();
            let (c, d) = if member == EvidenceMemberKind::Conformance {
                changed.offline_evidence.conformance_sha256 = incomplete.digest();
                (incomplete, differential.clone())
            } else {
                changed.offline_evidence.differential_sha256 = incomplete.digest();
                (conformance.clone(), incomplete)
            };
            assert_eq!(
                CommissioningProposal::assemble(changed, c, d),
                Err(IssuanceError::Closure(ClosureFault::Scenario)),
                "{scenario:?}"
            );
        }
    }
    let mut wrong_digest = binding();
    wrong_digest.offline_evidence.differential_sha256 = digest(0x70);
    assert_eq!(
        CommissioningProposal::assemble(wrong_digest, conformance.clone(), differential.clone()),
        Err(IssuanceError::Closure(ClosureFault::Digest))
    );
    let mut wrong_commit = binding();
    wrong_commit.source_commit = GitCommit::parse("f".repeat(40)).expect("commit");
    assert_eq!(
        CommissioningProposal::assemble(wrong_commit, conformance.clone(), differential.clone()),
        Err(IssuanceError::Closure(ClosureFault::Candidate))
    );
    let mut wrong_tuple = binding();
    wrong_tuple.tuple.profile_lock_sha256 = digest(0x70);
    assert_eq!(
        CommissioningProposal::assemble(wrong_tuple, conformance.clone(), differential.clone()),
        Err(IssuanceError::Closure(ClosureFault::Candidate))
    );
    assert_eq!(
        CommissioningProposal::assemble(binding(), differential.clone(), conformance.clone()),
        Err(IssuanceError::Closure(ClosureFault::MemberSet))
    );
    let mut unauthorized = conformance.body().clone();
    unauthorized.cases[0].unauthorized_provider_entries = 1;
    let unauthorized = QualificationEvidence::from_body(&unauthorized).expect("reported entry");
    let mut changed = binding();
    changed.offline_evidence.conformance_sha256 = unauthorized.digest();
    assert_eq!(
        CommissioningProposal::assemble(changed, unauthorized, differential),
        Err(IssuanceError::CaseFailed)
    );
    assert_eq!(proposal().offline_evidence()[0], &conformance);
}

#[test]
fn action_and_lease_bounds_are_exact_and_never_silently_repaired() {
    let root = root();
    let signer = commissioner(&root);
    let base = permit(&signer).body().clone();
    for count in [
        0,
        1,
        MAX_COMMISSIONING_ACTIONS,
        MAX_COMMISSIONING_ACTIONS + 1,
    ] {
        let mut body = base.clone();
        body.statement.binding.allowed_actions = (0..count)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
                Sha256Digest::from_bytes(bytes)
            })
            .collect();
        assert_eq!(
            QualificationCommissioningPermit::from_body(&body).map(|_| ()),
            if (1..=MAX_COMMISSIONING_ACTIONS).contains(&count) {
                Ok(())
            } else {
                Err(QualificationFormatError::ListBound)
            },
            "{count}"
        );
    }
    for leases in [
        0,
        1,
        MAX_COMMISSIONING_LEASES,
        MAX_COMMISSIONING_LEASES + 1,
        u64::MAX,
    ] {
        let mut body = base.clone();
        body.statement.binding.maximum_credential_leases = leases;
        assert_eq!(
            QualificationCommissioningPermit::from_body(&body).map(|_| ()),
            if (1..=MAX_COMMISSIONING_LEASES).contains(&leases) {
                Ok(())
            } else {
                Err(QualificationFormatError::ListBound)
            },
            "{leases}"
        );
    }
    for actions in [vec![digest(1), digest(1)], vec![digest(2), digest(1)]] {
        let mut body = base.clone();
        body.statement.binding.allowed_actions = actions;
        assert_eq!(
            QualificationCommissioningPermit::from_body(&body).map(|_| ()),
            Err(QualificationFormatError::ListOrder)
        );
    }
    for (pointer, changed) in [
        ("/target/store_kind", json!("shared-file-v1")),
        ("/target/credential_store_kind", json!("local-file-v1")),
    ] {
        let mut body = base.clone();
        let mut target = serde_json::to_value(&body.statement.binding.tuple).expect("tuple");
        *target.pointer_mut(pointer).expect("member") = changed;
        body.statement.binding.tuple = serde_json::from_value(target).expect("tuple");
        assert_eq!(
            QualificationCommissioningPermit::from_body(&body).map(|_| ()),
            Err(QualificationFormatError::Malformed)
        );
    }
    let permit = permit(&signer);
    let mut noncanonical = permit.canonical_bytes().to_vec();
    noncanonical.push(b'\n');
    assert_eq!(
        QualificationCommissioningPermit::from_canonical_json(&noncanonical).map(|_| ()),
        Err(QualificationFormatError::NonCanonical)
    );
    assert_eq!(
        QualificationCommissioningPermit::from_canonical_json(&vec![
            b' ';
            MAX_COMMISSIONING_PERMIT_BYTES
                + 1
        ])
        .map(|_| ()),
        Err(QualificationFormatError::Oversized)
    );
    let mut extra: Value = serde_json::from_slice(permit.canonical_bytes()).expect("JSON");
    extra["statement"]["unreviewed"] = json!(true);
    assert_eq!(
        QualificationCommissioningPermit::from_canonical_json(
            &serde_json::to_vec(&extra).expect("JSON")
        )
        .map(|_| ()),
        Err(QualificationFormatError::Malformed)
    );
}

#[test]
fn renewal_cannot_change_the_durable_budget_identity_or_binding() {
    let root = root();
    let signer = commissioner(&root);
    let first = signer
        .permit(&proposal(), NOW, NOW, NOW + HOUR)
        .expect("first");
    let renewed = signer
        .permit(&proposal(), NOW + HOUR, NOW + HOUR, NOW + 2 * HOUR)
        .expect("renewed");
    assert_ne!(first.digest(), renewed.digest());
    let a = &first.body().statement.binding;
    let b = &renewed.body().statement.binding;
    assert_eq!(a.budget_key(), b.budget_key());
    assert_eq!(a.budget_binding(), b.budget_binding());
    let original = binding();
    for changed in [
        CommissioningBinding {
            maximum_credential_leases: 33,
            ..original.clone()
        },
        CommissioningBinding {
            principal_sha256: digest(0x70),
            ..original.clone()
        },
        CommissioningBinding {
            resources_sha256: digest(0x70),
            ..original.clone()
        },
        CommissioningBinding {
            allowed_actions: vec![digest(0x70)],
            ..original.clone()
        },
        CommissioningBinding {
            trusted_context_sha256: digest(0x70),
            ..original.clone()
        },
    ] {
        assert_eq!(original.budget_key(), changed.budget_key());
        assert_ne!(original.budget_binding(), changed.budget_binding());
    }
    let mut another_run = original.clone();
    another_run.protected_run = BoundedText::parse("another-protected-run").expect("run");
    assert_ne!(original.budget_key(), another_run.budget_key());
    let mut another_family = original.clone();
    another_family.tuple.recipe_family =
        auths_recipe_qualification::RecipeFamilyId::parse("another-family").expect("family");
    assert_ne!(original.budget_key(), another_family.budget_key());
}

#[test]
fn commissioning_artifact_fixture_is_current() {
    let root = root();
    let signer = commissioner(&root);
    let permit = permit(&signer);
    let list = revocations(&root, 1);
    let document = json!({
        "schema": "auths.qualification-commissioning-vectors/1",
        "synthetic": true,
        "trust_root": std::str::from_utf8(root.trust_root().canonical_bytes()).expect("UTF-8"),
        "signer_certificate": std::str::from_utf8(signer.certificate().canonical_bytes()).expect("UTF-8"),
        "revocation_list": std::str::from_utf8(list.canonical_bytes()).expect("UTF-8"),
        "permit": std::str::from_utf8(permit.canonical_bytes()).expect("UTF-8"),
        "permit_digest": permit.digest(),
        "budget_scope_sha256": permit.body().statement.binding.budget_key().expect("key"),
        "budget_binding_sha256": permit.body().statement.binding.budget_binding().expect("binding"),
        "limits": { "actions": MAX_COMMISSIONING_ACTIONS,
            "leases": MAX_COMMISSIONING_LEASES, "seconds": MAX_COMMISSIONING_SECONDS,
            "bytes": MAX_COMMISSIONING_PERMIT_BYTES },
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/qualification/commissioning-v1.json");
    let mut encoded = serde_json::to_vec_pretty(&document).expect("fixture");
    encoded.push(b'\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(path, encoded).expect("fixture write");
    } else {
        assert_eq!(
            std::fs::read(path).expect("fixture"),
            encoded,
            "regenerate commissioning fixtures with AUTHS_UPDATE_FIXTURES=1"
        );
    }
}
