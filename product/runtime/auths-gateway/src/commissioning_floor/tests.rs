use super::*;
use crate::store_testkit::{Backend, TestAttempts};
use auths_recipe_qualification::{CommissioningInputs, QualificationTrustRoot};
use std::sync::{Arc, Barrier};

fn fixture() -> VerifiedCommissioningPermit {
    let document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../bindings/fixtures/qualification/commissioning-v2.json"
    ))
    .expect("public synthetic fixture");
    let text = |name: &str| document[name].as_str().expect("artifact").as_bytes();
    VerifiedCommissioningPermit::verify(
        &QualificationTrustRoot::from_canonical_json(text("trust_root")).expect("root"),
        &CommissioningInputs {
            signer_certificate: text("signer_certificate"),
            revocation_list: text("revocation_list"),
            permit: text("permit"),
        },
    )
    .expect("synthetic authority")
}

fn request(binding: &CommissioningBinding) -> CommissioningRequest<'_> {
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

fn setup() -> (
    TestAttempts,
    tempfile::TempDir,
    VerifiedCommissioningPermit,
    CommissioningBudget,
    CommissioningFloor,
) {
    let store = TestAttempts::open(Backend::File);
    let directory = tempfile::tempdir().expect("host floor");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let authority = fixture();
    let binding = authority.permit().body().statement.binding.clone();
    let budget = CommissioningBudget::new(store.raw(), binding.clone()).expect("budget");
    let floor = CommissioningFloor::new(directory.path().to_owned(), binding).expect("floor");
    (store, directory, authority, budget, floor)
}

fn claim(
    floor: &CommissioningFloor,
    budget: &CommissioningBudget,
    authority: &VerifiedCommissioningPermit,
) -> Result<CommissioningBudgetUpdate, CommissioningBudgetRefusal> {
    let statement = &authority.permit().body().statement;
    floor.claim(
        budget,
        authority,
        &request(&statement.binding),
        statement.not_before,
        true,
        &VerifierState::default(),
    )
}

#[test]
fn runtime_never_creates_a_missing_floor() {
    let (_store, _directory, authority, budget, floor) = setup();
    budget.initialize().expect("registered");
    assert_eq!(
        claim(&floor, &budget, &authority),
        Err(CommissioningBudgetRefusal::Rollback)
    );
    assert_eq!(
        budget
            .load()
            .expect("database")
            .consumed_credential_leases(),
        0
    );
    assert_eq!(floor.load(), Err(CommissioningBudgetRefusal::Missing));
}

#[test]
fn committed_floor_survives_restart_and_cannot_be_reset() {
    let (_store, directory, authority, budget, floor) = setup();
    let initial = budget.initialize().expect("registered");
    floor.initialize(&initial).expect("fresh floor");
    assert_eq!(
        claim(&floor, &budget, &authority).expect("claim").refusal(),
        None
    );
    let reopened = CommissioningFloor::new(
        directory.path().to_owned(),
        authority.permit().body().statement.binding.clone(),
    )
    .expect("reopen");
    assert_eq!(
        reopened
            .load()
            .expect("retained")
            .consumed_credential_leases(),
        1
    );
    assert_eq!(
        reopened.initialize(&initial),
        Err(CommissioningBudgetRefusal::Rollback)
    );
    assert_eq!(
        claim(&reopened, &budget, &authority)
            .expect("second")
            .refusal(),
        None
    );
    assert_eq!(
        reopened.load().expect("floor").consumed_credential_leases(),
        2
    );
}

#[test]
fn concurrent_local_claims_never_decrease_the_witness() {
    let (_store, _directory, authority, budget, floor) = setup();
    floor
        .initialize(&budget.initialize().expect("registration"))
        .expect("floor");
    let budget = Arc::new(budget);
    let start = Arc::new(Barrier::new(9));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let budget = budget.clone();
            let floor = floor.clone();
            let authority = authority.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                claim(&floor, &budget, &authority)
            })
        })
        .collect();
    start.wait();
    for worker in workers {
        assert_eq!(
            worker.join().expect("worker").expect("persisted").refusal(),
            None
        );
    }
    assert_eq!(floor.load().expect("floor").consumed_credential_leases(), 8);
    assert_eq!(
        budget
            .load()
            .expect("database")
            .consumed_credential_leases(),
        8
    );
}

#[test]
fn unsafe_witness_paths_refuse_before_capacity_claim() {
    for fault in ["symlink", "hardlink", "public", "oversized", "malformed"] {
        let (_store, directory, authority, budget, floor) = setup();
        floor
            .initialize(&budget.initialize().expect("registration"))
            .expect("floor");
        let path = directory.path().join(format!("{}.json", floor.leaf));
        match fault {
            "symlink" => {
                let target = directory.path().join("retained.json");
                fs::rename(&path, &target).expect("move");
                std::os::unix::fs::symlink(target, &path).expect("symlink");
            }
            "hardlink" => {
                fs::hard_link(&path, directory.path().join("alias.json")).expect("link");
            }
            "public" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
            }
            "oversized" => {
                fs::write(&path, vec![b' '; MAX_COMMISSIONING_BUDGET_BYTES + 1]).expect("write");
            }
            "malformed" => {
                fs::write(&path, b"{}").expect("write");
            }
            _ => unreachable!(),
        }
        assert!(claim(&floor, &budget, &authority).is_err(), "{fault}");
        assert_eq!(
            budget
                .load()
                .expect("database")
                .consumed_credential_leases(),
            0
        );
    }
}

#[test]
fn database_restore_below_retained_witness_is_refused() {
    let (store, _directory, authority, budget, floor) = setup();
    let initial = budget.initialize().expect("registration");
    floor.initialize(&initial).expect("floor");
    claim(&floor, &budget, &authority).expect("first claim");
    let latest = budget.load().expect("database");
    let key = crate::GatewayAttemptKey::from_bytes(
        *authority
            .permit()
            .body()
            .statement
            .binding
            .budget_key()
            .expect("key")
            .as_bytes(),
    );
    store
        .raw()
        .replace(
            crate::GatewayRecordKind::CommissioningBudget,
            &key,
            latest.canonical_bytes(),
            initial.canonical_bytes(),
        )
        .expect("simulate restore");
    assert_eq!(
        claim(&floor, &budget, &authority),
        Err(CommissioningBudgetRefusal::Rollback)
    );
    assert_eq!(
        floor.load().expect("retained").consumed_credential_leases(),
        1
    );
}

#[test]
fn database_claim_without_witness_acknowledgement_stays_spent() {
    let (_store, _directory, authority, budget, floor) = setup();
    let initial = budget.initialize().expect("registration");
    floor.initialize(&initial).expect("floor");
    // Process loss after the shared commit and before the host witness write.
    let statement = &authority.permit().body().statement;
    budget
        .claim(
            &authority,
            &request(&statement.binding),
            statement.not_before,
            true,
            &initial,
            &VerifierState::default(),
        )
        .expect("database commit");
    assert_eq!(
        floor
            .load()
            .expect("old witness")
            .consumed_credential_leases(),
        0
    );
    claim(&floor, &budget, &authority).expect("restart claim");
    assert_eq!(
        floor.load().expect("retained").consumed_credential_leases(),
        2
    );
}
