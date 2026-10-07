//! Identical capacity, race, crash and rollback checks on both atomic stores.
//! Public synthetic permits authorize no real credential or provider entry.

use super::*;
use crate::store_testkit::{Backend, TestAttempts};
use auths_recipe_qualification::{
    CommissioningInputs, QualificationCommissioningPermit, QualificationRevocationList,
    QualificationSignerCertificate, QualificationTrustRoot, SignatureB64,
};
use auths_recipe_qualification_issuance::{RootSigner, SigningSeed};
use ed25519_dalek::{Signer as _, SigningKey};
use proptest::prelude::*;
use std::sync::Barrier;
use zeroize::Zeroizing;

struct Fixture {
    root: QualificationTrustRoot,
    certificate: QualificationSignerCertificate,
    list: QualificationRevocationList,
    permit: QualificationCommissioningPermit,
}

impl Fixture {
    fn load() -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/qualification/commissioning-v2.json");
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("JSON");
        let text = |name: &str| document[name].as_str().expect("artifact").as_bytes();
        Self {
            root: QualificationTrustRoot::from_canonical_json(text("trust_root")).expect("root"),
            certificate: QualificationSignerCertificate::from_canonical_json(text(
                "signer_certificate",
            ))
            .expect("certificate"),
            list: QualificationRevocationList::from_canonical_json(text("revocation_list"))
                .expect("list"),
            permit: QualificationCommissioningPermit::from_canonical_json(text("permit"))
                .expect("permit"),
        }
    }

    fn authority(&self) -> VerifiedCommissioningPermit {
        VerifiedCommissioningPermit::verify(
            &self.root,
            &CommissioningInputs {
                signer_certificate: self.certificate.canonical_bytes(),
                revocation_list: self.list.canonical_bytes(),
                permit: self.permit.canonical_bytes(),
            },
        )
        .expect("synthetic authority")
    }

    fn binding(&self) -> &CommissioningBinding {
        &self.permit.body().statement.binding
    }

    fn now(&self) -> u64 {
        self.permit.body().statement.not_before
    }

    fn request(&self) -> CommissioningRequest<'_> {
        let binding = self.binding();
        CommissioningRequest {
            source_commit: &binding.source_commit,
            tuple: &binding.tuple,
            protected_run: &binding.protected_run,
            principal_sha256: binding.principal_sha256,
            trusted_context_sha256: binding.trusted_contexts_sha256[0],
            resources_sha256: binding.resources_sha256,
            canonical_action_sha256: binding.allowed_actions[0],
        }
    }

    fn root_signer(&self) -> RootSigner {
        RootSigner::open(
            &SigningSeed::from_bytes(Zeroizing::new([0x11; 32])),
            self.root.clone(),
        )
        .expect("public test root")
    }
}

fn budget(store: &TestAttempts, fixture: &Fixture) -> CommissioningBudget {
    CommissioningBudget::new(store.raw(), fixture.binding().clone()).expect("binding")
}

fn consume(
    budget: &CommissioningBudget,
    fixture: &Fixture,
    floor: &CommissioningBudgetSnapshot,
) -> CommissioningBudgetUpdate {
    budget
        .claim(
            &fixture.authority(),
            &fixture.request(),
            fixture.now(),
            true,
            floor,
            &VerifierState::default(),
        )
        .expect("atomic claim")
}

fn permanent_capacity_and_restart(backend: Backend) {
    let store = TestAttempts::open(backend);
    let fixture = Fixture::load();
    let budget = budget(&store, &fixture);
    assert_eq!(budget.load(), Err(CommissioningBudgetRefusal::Missing));
    let initial = budget.initialize().expect("fresh setup");
    let claimed = consume(&budget, &fixture, &initial);
    assert_eq!(claimed.refusal, None);
    assert_eq!(claimed.snapshot.consumed_credential_leases(), 1);
    // Simulate process loss immediately after the durable claim, before any
    // credential acquisition. Reopening does not refund that consumed unit.
    drop(budget);
    let reopened = CommissioningBudget::new(store.reopen().store(), fixture.binding().clone())
        .expect("reopened budget");
    assert_eq!(reopened.load().expect("permanent record"), claimed.snapshot);
    assert_eq!(
        reopened.initialize().expect("idempotent setup"),
        claimed.snapshot
    );
    // A returned receipt is not reused to authorize a second lease: another
    // claim always consumes another ordinal on the shared record.
    let next = consume(&reopened, &fixture, &claimed.snapshot);
    assert_eq!(next.snapshot.consumed_credential_leases(), 2);
    let raw = store.raw();
    assert_eq!(raw.sweep_expired(u64::MAX / 2, 10).expect("sweep"), 0);
    assert_eq!(reopened.load().expect("not swept"), next.snapshot);
}

#[test]
fn capacity_survives_crash_restart_and_sweep_file() {
    permanent_capacity_and_restart(Backend::File);
}

#[test]
#[ignore = "requires TLS PostgreSQL fixture"]
fn capacity_survives_crash_restart_and_sweep_postgres() {
    permanent_capacity_and_restart(Backend::Postgres);
}

fn final_unit_race(backend: Backend) {
    let store = TestAttempts::open(backend);
    let fixture = Fixture::load();
    let budget = budget(&store, &fixture);
    let mut floor = budget.initialize().expect("setup");
    for ordinal in 1..fixture.binding().maximum_credential_leases {
        let claimed = consume(&budget, &fixture, &floor);
        assert_eq!(claimed.refusal, None);
        assert_eq!(claimed.snapshot.consumed_credential_leases(), ordinal);
        floor = claimed.snapshot;
    }
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|context_index| {
            // Distinct file handles or PostgreSQL pools model independent hosts.
            let budget = CommissioningBudget::new(store.raw(), fixture.binding().clone())
                .expect("second host");
            let authority = fixture.authority();
            let binding = fixture.binding().clone();
            let floor = floor.clone();
            let barrier = Arc::clone(&barrier);
            let now = fixture.now();
            std::thread::spawn(move || {
                let request = CommissioningRequest {
                    source_commit: &binding.source_commit,
                    tuple: &binding.tuple,
                    protected_run: &binding.protected_run,
                    principal_sha256: binding.principal_sha256,
                    trusted_context_sha256: binding.trusted_contexts_sha256[context_index],
                    resources_sha256: binding.resources_sha256,
                    canonical_action_sha256: binding.allowed_actions[0],
                };
                barrier.wait();
                budget
                    .claim(
                        &authority,
                        &request,
                        now,
                        true,
                        &floor,
                        &VerifierState::default(),
                    )
                    .expect("raced claim")
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("host"))
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| result.refusal.is_none())
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.refusal == Some(CommissioningBudgetRefusal::Exhausted))
            .count(),
        1
    );
    assert_eq!(
        budget
            .load()
            .expect("shared capacity")
            .consumed_credential_leases(),
        fixture.binding().maximum_credential_leases
    );
}

#[test]
fn exactly_one_host_claims_the_final_unit_file() {
    final_unit_race(Backend::File);
}

#[test]
#[ignore = "requires TLS PostgreSQL fixture"]
fn exactly_one_host_claims_the_final_unit_postgres() {
    final_unit_race(Backend::Postgres);
}

fn renewal_binding_and_rollback(backend: Backend) {
    let store = TestAttempts::open(backend);
    let mut fixture = Fixture::load();
    let budget = budget(&store, &fixture);
    let initial = budget.initialize().expect("setup");
    let first = consume(&budget, &fixture, &initial);
    let mut renewed = fixture.permit.body().clone();
    renewed.statement.issued_at += 1;
    renewed.statement.not_before += 1;
    renewed.signature_b64 = SignatureB64::from_bytes(
        &SigningKey::from_bytes(&[0x22; 32])
            .sign(&renewed.signing_preimage().expect("preimage"))
            .to_bytes(),
    );
    fixture.permit =
        QualificationCommissioningPermit::from_body(&renewed).expect("renewed authority");
    let second = consume(&budget, &fixture, &first.snapshot);
    assert_eq!(second.refusal, None);
    assert_eq!(second.snapshot.consumed_credential_leases(), 2);
    let mut changed = fixture.binding().clone();
    changed.maximum_credential_leases += 1;
    let changed = CommissioningBudget::new(store.raw(), changed).expect("finite changed ceiling");
    assert_eq!(
        changed.initialize(),
        Err(CommissioningBudgetRefusal::BindingMismatch)
    );
    assert_eq!(
        changed.load(),
        Err(CommissioningBudgetRefusal::BindingMismatch)
    );
    let mut changed_contexts = fixture.binding().clone();
    changed_contexts
        .trusted_contexts_sha256
        .push(Sha256Digest::from_bytes([0x70; 32]));
    let changed_contexts = CommissioningBudget::new(store.raw(), changed_contexts)
        .expect("bounded changed context set");
    assert_eq!(
        changed_contexts.initialize(),
        Err(CommissioningBudgetRefusal::BindingMismatch)
    );
    assert_eq!(
        budget
            .load()
            .expect("original budget")
            .consumed_credential_leases(),
        2
    );
    // Inject a restored older database record while retaining the host's
    // separately persisted accepted snapshot. Opening never repairs it.
    let raw = store.raw();
    raw.replace(
        GatewayRecordKind::CommissioningBudget,
        &budget.key,
        second.snapshot.canonical_bytes(),
        initial.canonical_bytes(),
    )
    .expect("restore old record");
    assert_eq!(
        budget.claim(
            &fixture.authority(),
            &fixture.request(),
            fixture.now(),
            true,
            &second.snapshot,
            &VerifierState::default()
        ),
        Err(CommissioningBudgetRefusal::Rollback)
    );
}

#[test]
fn renewal_keeps_consumption_and_a_retained_floor_detects_restore_file() {
    renewal_binding_and_rollback(Backend::File);
}

#[test]
#[ignore = "requires TLS PostgreSQL fixture"]
fn renewal_keeps_consumption_and_a_retained_floor_detects_restore_postgres() {
    renewal_binding_and_rollback(Backend::Postgres);
}

fn refusals_and_permanent_revocations(backend: Backend) {
    let store = TestAttempts::open(backend);
    let mut fixture = Fixture::load();
    let budget = budget(&store, &fixture);
    let initial = budget.initialize().expect("setup");
    let mut request = fixture.request();
    request.canonical_action_sha256 = Sha256Digest::from_bytes([0xff; 32]);
    let denied = budget
        .claim(
            &fixture.authority(),
            &request,
            fixture.now(),
            true,
            &initial,
            &VerifierState::default(),
        )
        .expect("denied update");
    assert_eq!(
        denied.refusal,
        Some(CommissioningBudgetRefusal::Permit(
            CommissioningRefusal::BindingMismatch
        ))
    );
    assert_eq!(denied.snapshot.consumed_credential_leases(), 0);
    let clock = budget
        .claim(
            &fixture.authority(),
            &fixture.request(),
            fixture.now(),
            false,
            &denied.snapshot,
            &VerifierState::default(),
        )
        .expect("clock update");
    assert_eq!(
        clock.refusal,
        Some(CommissioningBudgetRefusal::Permit(
            CommissioningRefusal::ClockUntrusted
        ))
    );
    assert_eq!(clock.snapshot.consumed_credential_leases(), 0);
    let root = fixture.root_signer();
    fixture.list = root
        .revoke(
            2,
            fixture.now() - 1,
            fixture.now() + 3600,
            vec![fixture.certificate.body().statement.signer_id.clone()],
            vec![],
        )
        .expect("revoked list");
    let revoked = consume(&budget, &fixture, &clock.snapshot);
    assert_eq!(
        revoked.refusal,
        Some(CommissioningBudgetRefusal::Permit(
            CommissioningRefusal::Revoked
        ))
    );
    assert_eq!(revoked.snapshot.consumed_credential_leases(), 0);
    fixture.list = root
        .revoke(3, fixture.now() - 1, fixture.now() + 3600, vec![], vec![])
        .expect("omitted list");
    let still_revoked = consume(&budget, &fixture, &revoked.snapshot);
    assert_eq!(still_revoked.refusal, revoked.refusal);
    assert_eq!(still_revoked.snapshot.consumed_credential_leases(), 0);
    assert!(
        still_revoked
            .snapshot
            .record
            .revoked_signers
            .contains(&fixture.certificate.body().statement.signer_id)
    );
}

#[test]
fn hostile_inputs_consume_nothing_and_revocation_survives_omission_file() {
    refusals_and_permanent_revocations(Backend::File);
}

#[test]
#[ignore = "requires TLS PostgreSQL fixture"]
fn hostile_inputs_consume_nothing_and_revocation_survives_omission_postgres() {
    refusals_and_permanent_revocations(Backend::Postgres);
}

#[test]
fn snapshots_reject_noncanonical_unknown_oversized_and_impossible_state() {
    let store = TestAttempts::open(Backend::File);
    let fixture = Fixture::load();
    let snapshot = budget(&store, &fixture).initialize().expect("setup");
    let decode =
        |bytes: &[u8]| CommissioningBudgetSnapshot::from_canonical_json(bytes, fixture.binding());
    let mut bytes = snapshot.canonical_bytes().to_vec();
    bytes.push(b'\n');
    assert_eq!(decode(&bytes), Err(CommissioningBudgetRefusal::Corrupt));
    assert_eq!(
        decode(&vec![b' '; MAX_COMMISSIONING_BUDGET_BYTES + 1]),
        Err(CommissioningBudgetRefusal::Corrupt)
    );
    let mut document = serde_json::to_value(&snapshot.record).expect("record");
    document["unreviewed"] = serde_json::json!(true);
    assert_eq!(
        decode(&serde_json_canonicalizer::to_vec(&document).expect("canonical")),
        Err(CommissioningBudgetRefusal::Corrupt)
    );
    for (pointer, value) in [
        (
            "/schema",
            serde_json::json!("auths.gateway-commissioning-budget/0"),
        ),
        ("/consumed_credential_leases", serde_json::json!(1025)),
        ("/maximum_credential_leases", serde_json::json!(0)),
        ("/accepted_revocation_sequence", serde_json::json!(u64::MAX)),
    ] {
        let mut document = serde_json::to_value(&snapshot.record).expect("record");
        *document.pointer_mut(pointer).expect("member") = value;
        let bytes = serde_json::to_vec(&document).expect("JSON");
        assert_eq!(
            decode(&bytes),
            Err(CommissioningBudgetRefusal::Corrupt),
            "{pointer}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn consumption_never_exceeds_the_ceiling_or_charges_a_refused_action(
        inputs in prop::collection::vec((any::<bool>(), any::<bool>()), 0..64)
    ) {
        let store = TestAttempts::open(Backend::File);
        let fixture = Fixture::load();
        let authority = fixture.authority();
        let budget = budget(&store, &fixture);
        let mut floor = budget.initialize().expect("setup");
        let mut eligible = 0;
        for (exact_action, trusted_clock) in inputs {
            let mut request = fixture.request();
            if !exact_action {
                request.canonical_action_sha256 = Sha256Digest::from_bytes([0xff; 32]);
            }
            let before = floor.consumed_credential_leases();
            let updated = budget.claim(&authority, &request, fixture.now(), trusted_clock,
                &floor, &VerifierState::default()).expect("claim or refusal");
            if exact_action && trusted_clock { eligible += 1; }
            prop_assert_eq!(updated.snapshot.consumed_credential_leases(),
                eligible.min(fixture.binding().maximum_credential_leases));
            prop_assert!(updated.snapshot.consumed_credential_leases() >= before);
            if !exact_action || !trusted_clock {
                prop_assert!(updated.refusal.is_some());
                prop_assert_eq!(updated.snapshot.consumed_credential_leases(), before);
            }
            floor = updated.snapshot;
        }
        prop_assert_eq!(budget.load().expect("permanent record"), floor);
    }
}
