//! One spend limit: every case of `bounds-aggregate.json` through both
//! stores.
//!
//! Each case's grants are decoded from their committed canonical bytes
//! through the gateway's evaluator registry, the submission's chain of links
//! runs through the gateway's own bounded-policy admission, and the step
//! machine then claims the operation with its count and sum slots in one
//! batch and drives the counting provider. After the submissions, the store
//! must hold exactly the case's slot table: a refused submission leaks no
//! slot and enters nothing. The race cases then submit concurrently through
//! two store handles, and the audit cases run the order-free recount over
//! every permutation of their entries.

#![allow(clippy::too_many_lines, reason = "fixture tables read top to bottom")]

use crate::audit::{count_bound_violations, sum_bound_violations};
use crate::bounds::{
    BoundLink, count_counter_key, count_slot_key, link_policy, sum_counter_key, sum_slot_key,
};
use crate::engine::GatewaySubmitResult;
use crate::pending_vectors::bounds::FILE;
use crate::scenario_tests::{TableProvider, TestIo, admitted, test_context};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::submit::{self, SubmitContext};
use crate::{
    CompiledRecipe, GatewayAttemptKey, GatewayAttemptStore, GatewayAttempts, GatewayObserver,
    GatewayRecordKind, LogicalOperationId,
};
use auths_model::{PolicyCommitment, PolicyIdentifier, PrincipalId};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering;

const OBSERVER_SEED: u8 = 0x33;

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture JSON")
}

/// The committed vectors and what every case shares.
struct Vectors {
    document: Value,
    recipes: Value,
    answers: Value,
}

impl Vectors {
    fn load() -> Self {
        let document = fixture(FILE);
        assert_eq!(document["schema"], "auths.gateway-bounds-aggregate/1");
        assert_eq!(
            document["evaluator"],
            crate::ARGUMENT_CEILING_EVALUATOR,
            "the vectors name the registered evaluator"
        );
        assert_eq!(document["policy_type"], crate::ARGUMENT_CEILING_POLICY_TYPE);
        let recipes = fixture(document["recipes"].as_str().expect("recipes"));
        let scenarios = fixture(crate::pending_vectors::attempts::FILE);
        let mut answers = scenarios["defaults"]["stripe"]["responses"].clone();
        for intent in document["provider"]["payment_intents"]
            .as_array()
            .expect("payment intents")
        {
            let id = intent["id"].as_str().expect("intent");
            answers[format!("GET /v1/payment_intents/{id}")] = json!({
                "status": 200,
                "headers": {"Stripe-Version": "2025-03-31.basil"},
                "body": {"id": id, "amount_received": intent["amount_received"],
                    "currency": intent["currency"]}
            });
        }
        Self {
            document,
            recipes,
            answers,
        }
    }

    fn recipe(&self, base: &str) -> CompiledRecipe {
        CompiledRecipe::compile(
            &serde_json::to_vec(&self.recipes["bases"][base]["recipe"]).expect("recipe"),
            &serde_json::to_vec(&self.recipes["bases"][base]["lock"]).expect("lock"),
        )
        .expect("recipe compiles")
    }

    fn principal(&self, name: &str) -> PrincipalId {
        let entry = &self.document["principals"][name];
        let text = entry["principal"].as_str().map_or_else(
            || {
                format!(
                    "did:key:{}",
                    entry["multibase"].as_str().expect("did:key multibase")
                )
            },
            str::to_owned,
        );
        PrincipalId::parse(&text).expect("principal")
    }

    /// The case's grants from the submission's grant back to its root, in
    /// root-to-terminal order.
    fn chain<'a>(case: &'a Value, terminal: &str) -> Vec<&'a Value> {
        let grants = case["grants"].as_array().expect("grants");
        let mut chain = Vec::new();
        let mut cursor = Some(terminal.to_owned());
        while let Some(id) = cursor {
            let grant = grants
                .iter()
                .find(|grant| grant["id"] == id.as_str())
                .expect("grant");
            chain.push(grant);
            cursor = grant["parent"].as_str().map(str::to_owned);
        }
        chain.reverse();
        chain
    }

    /// The links of a chain: each bounded grant's subject and the policy its
    /// commitment names, decoded through the evaluator registry.
    fn links(&self, case: &Value, terminal: &str) -> Result<Vec<BoundLink>, &'static str> {
        let mut links = Vec::new();
        for grant in Self::chain(case, terminal) {
            let Some(bytes) = grant["policy_cbor_hex"].as_str() else {
                continue;
            };
            let bytes = hex::decode(bytes).expect("policy bytes");
            let commitment = PolicyCommitment::new(
                PolicyIdentifier::parse(grant["policy_type"].as_str().expect("type"), 128)
                    .expect("type"),
                crate::ARGUMENT_CEILING_POLICY_VERSION,
                PolicyIdentifier::parse(crate::ARGUMENT_CEILING_CANONICALIZATION, 64)
                    .expect("canonicalization"),
                auths_codec::bounded_policy_digest(&bytes).expect("digest"),
                PolicyIdentifier::parse(grant["evaluator"].as_str().expect("evaluator"), 128)
                    .expect("evaluator"),
            )
            .expect("commitment");
            let policy = link_policy(&commitment, &bytes)?;
            assert_eq!(
                policy,
                crate::scenario_tests::policy_from_members(&grant["policy"]),
                "{}: the committed bytes are the listed members",
                grant["id"]
            );
            links.push(BoundLink {
                subject: self.principal(grant["subject"].as_str().expect("subject")),
                policy,
            });
        }
        Ok(links)
    }

    fn arguments(&self, case: &Value, arguments: &Value, operation: &str) -> Map<String, Value> {
        let base = case["recipe"].as_str().expect("recipe");
        let mut values = self.document["default_arguments"][base]
            .as_object()
            .expect("default arguments")
            .clone();
        values.extend(
            arguments
                .as_object()
                .expect("arguments")
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        values.insert("operation_id".into(), json!(operation));
        values
    }
}

/// What one submission did.
struct Submitted {
    result: GatewaySubmitResult,
    writes: usize,
    leases: usize,
}

/// Admits and submits one operation at `at` through `attempts`.
async fn submit_one(
    vectors: &Vectors,
    recipe: &CompiledRecipe,
    attempts: &GatewayAttempts,
    case: &Value,
    submission: &Value,
    operation: &str,
) -> Submitted {
    let at = submission["at"].as_u64().expect("at");
    let arguments = vectors.arguments(case, &submission["arguments"], operation);
    let grant = submission["grant"].as_str().expect("grant");
    let command = vectors
        .links(case, grant)
        .map_err(crate::engine::not_entered)
        .and_then(|links| {
            let mut commitment = [0_u8; 32];
            commitment[..operation.len().min(32)]
                .copy_from_slice(&operation.as_bytes()[..operation.len().min(32)]);
            admitted(recipe, &arguments, commitment, Vec::new(), 3_600, links, at)
        });
    let provider = TableProvider::new(recipe, &vectors.answers, "respond");
    let mut io = TestIo::answering(&provider, command);
    io.recipe = Some(recipe);
    io.clock.store(at, Ordering::SeqCst);
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let context = test_context(&observer);
    let result = submit::run(
        &SubmitContext {
            recipe,
            attempts,
            context: &context,
            observer: Some(&observer),
        },
        &io,
    )
    .await;
    Submitted {
        result,
        writes: provider.writes(),
        leases: io.leases(),
    }
}

fn entered(result: &GatewaySubmitResult) -> bool {
    matches!(
        result,
        GatewaySubmitResult::ResponseRecorded { .. }
            | GatewaySubmitResult::Observed { .. }
            | GatewaySubmitResult::ObservedByProvider { .. }
    )
}

fn code(result: &GatewaySubmitResult) -> Option<&str> {
    match result {
        GatewaySubmitResult::NotEntered { code } => Some(code),
        _ => None,
    }
}

/// The number of slots of `subject`'s count counter in window `index`.
fn stored_count(
    store: &dyn GatewayAttemptStore,
    recipe: &CompiledRecipe,
    subject: &PrincipalId,
    window_seconds: u64,
    index: u64,
) -> u64 {
    let counter = count_counter_key(recipe.namespace(), subject, window_seconds, index);
    let mut slots = 0;
    while store
        .load(
            GatewayRecordKind::CountSlot,
            &GatewayAttemptKey::from_bytes(count_slot_key(&counter, slots)),
        )
        .expect("load")
        .is_some()
    {
        slots += 1;
    }
    slots
}

/// The window sum of `subject`'s sum counter for `partition` in window
/// `index`: the last slot's cumulative sum, zero without a slot.
fn stored_sum(
    store: &dyn GatewayAttemptStore,
    recipe: &CompiledRecipe,
    subject: &PrincipalId,
    partition: &str,
    window_seconds: u64,
    index: u64,
) -> u64 {
    let counter = sum_counter_key(
        recipe.namespace(),
        subject,
        partition,
        window_seconds,
        index,
    );
    let mut slot = 0;
    let mut cumulative = 0;
    while let Some(bytes) = store
        .load(
            GatewayRecordKind::SumSlot,
            &GatewayAttemptKey::from_bytes(sum_slot_key(&counter, slot)),
        )
        .expect("load")
    {
        let record: Value = serde_json::from_slice(&bytes).expect("sum slot");
        assert_eq!(record["schema"], "auths.gateway-bounded-sum/1");
        assert_eq!(record["slot"], slot);
        cumulative = record["cumulative"].as_u64().expect("cumulative");
        slot += 1;
    }
    cumulative
}

/// Checks the stored slot tables of a case against its vectors. The store
/// is read on a plain thread, because the `PostgreSQL` store's synchronous
/// client may not run on an async executor thread.
fn check_slots_on_thread(
    vectors: &Vectors,
    recipe: &CompiledRecipe,
    case: &Value,
    store: &dyn GatewayAttemptStore,
    label: &str,
) {
    let window = vectors.document["window_seconds"].as_u64().expect("window");
    for row in case["count_slots"].as_array().expect("count slots") {
        let subject = vectors.principal(row["subject"].as_str().expect("subject"));
        let index = row["window_index"].as_u64().expect("index");
        assert_eq!(
            stored_count(store, recipe, &subject, window, index),
            row["slots"].as_u64().expect("slots"),
            "{label}: count slots of {}",
            row["subject"]
        );
    }
    for row in case["sum_slots"].as_array().expect("sum slots") {
        let subject = vectors.principal(row["subject"].as_str().expect("subject"));
        let partition = row["partition"].as_str().unwrap_or_default();
        let index = row["window_index"].as_u64().expect("index");
        assert_eq!(
            stored_sum(store, recipe, &subject, partition, window, index),
            row["cumulative"].as_u64().expect("cumulative"),
            "{label}: sum of {} for {partition:?}",
            row["subject"]
        );
    }
}

fn check_slots(
    vectors: &Vectors,
    recipe: &CompiledRecipe,
    case: &Value,
    store: &TestAttempts,
    label: &str,
) {
    let raw = store.raw();
    std::thread::scope(|scope| {
        scope
            .spawn(|| check_slots_on_thread(vectors, recipe, case, &*raw, label))
            .join()
            .expect("slot check");
    });
}

/// Runs one submission case and returns the store for a following race.
async fn submission_case(
    vectors: &Vectors,
    case: &Value,
    backend: Backend,
) -> (TestAttempts, usize) {
    let id = case["id"].as_str().expect("id");
    let label = format!("{}: {id}", backend.label());
    let recipe = vectors.recipe(case["recipe"].as_str().expect("recipe"));
    let store = TestAttempts::open(backend);
    let mut writes = 0;
    for (index, submission) in case["submissions"]
        .as_array()
        .expect("submissions")
        .iter()
        .enumerate()
    {
        let operation = format!("{id}-{index}");
        let done = submit_one(
            vectors,
            &recipe,
            store.attempts(),
            case,
            submission,
            &operation,
        )
        .await;
        let expected_code = submission["code"].as_str();
        if submission["decision"] == "entered" {
            assert!(entered(&done.result), "{label} #{index}: {:?}", done.result);
            assert_eq!(done.writes, 1, "{label} #{index}: one provider entry");
        } else {
            assert_eq!(code(&done.result), expected_code, "{label} #{index}");
            assert_eq!(
                (done.writes, done.leases),
                (0, 0),
                "{label} #{index}: a refusal leases and enters nothing"
            );
        }
        writes += done.writes;
        let stored = store
            .attempts()
            .read(
                recipe.namespace(),
                &LogicalOperationId::parse(&operation).expect("operation"),
            )
            .await
            .expect("read");
        assert_eq!(
            stored.is_some(),
            submission["stored"].as_bool().expect("stored"),
            "{label} #{index}: the claim is stored exactly when the vectors say"
        );
        if let (Some(snapshot), Some(expected)) = (&stored, expected_code) {
            assert_eq!(snapshot.refusal(), Some(expected), "{label} #{index}");
            assert!(
                snapshot.counters().is_empty(),
                "{label} #{index}: an exhausted claim holds no slot"
            );
        }
    }
    if case.get("race").is_none() {
        check_slots(vectors, &recipe, case, &store, &label);
        assert_eq!(
            writes,
            usize::try_from(case["provider_entries"].as_u64().expect("entries")).expect("entries"),
            "{label}: provider entries"
        );
    }
    (store, writes)
}

/// Submits the race's concurrent operations through two store handles, as
/// two processes sharing one store would, and checks that exactly the
/// capacity was admitted.
async fn race_case(vectors: &Vectors, case: &Value, backend: Backend) {
    let id = case["id"].as_str().expect("id");
    let label = format!("{}: {id} race", backend.label());
    let race = &case["race"];
    let recipe = Arc::new(vectors.recipe(case["recipe"].as_str().expect("recipe")));
    let (store, before) = submission_case(vectors, case, backend).await;
    let processes = [store.reopen(), store.reopen()];
    let concurrent = race["concurrent"].as_array().expect("concurrent");
    let mut tasks = Vec::new();
    for (index, entry) in concurrent.iter().enumerate() {
        let process = usize::try_from(entry["process"].as_u64().expect("process")).expect("index");
        let attempts = processes[process].clone();
        let recipe = Arc::clone(&recipe);
        let case = case.clone();
        let mut submission = entry.clone();
        submission["at"] = vectors.document["evaluated_at"].clone();
        let answers = vectors.answers.clone();
        let document = vectors.document.clone();
        let recipes = vectors.recipes.clone();
        let id = id.to_owned();
        tasks.push(tokio::spawn(async move {
            let vectors = Vectors {
                document,
                recipes,
                answers,
            };
            let operation = format!("{id}-race-{index}");
            submit_one(&vectors, &recipe, &attempts, &case, &submission, &operation).await
        }));
    }
    let mut admitted = 0;
    let mut refused = Vec::new();
    let mut writes = before;
    for task in tasks {
        let done = task.await.expect("task");
        writes += done.writes;
        if entered(&done.result) {
            admitted += 1;
        } else {
            assert_eq!(done.writes, 0, "{label}");
            refused.push(code(&done.result).map(str::to_owned));
        }
    }
    assert_eq!(
        admitted,
        race["admitted"].as_u64().expect("admitted"),
        "{label}"
    );
    let expected_code = race["refused"]["code"].as_str().map(str::to_owned);
    assert_eq!(
        refused,
        vec![
            expected_code;
            usize::try_from(race["refused"]["count"].as_u64().expect("count")).expect("count")
        ],
        "{label}"
    );
    assert_eq!(
        writes,
        usize::try_from(case["provider_entries"].as_u64().expect("entries")).expect("entries"),
        "{label}: provider entries"
    );
    check_slots(vectors, &recipe, case, &store, &label);
}

/// Every permutation of `items`.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for index in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(index);
        for mut tail in permutations(&rest) {
            tail.insert(0, first.clone());
            all.push(tail);
        }
    }
    all
}

/// Runs the order-free recount of one audit case over every order of its
/// entries.
fn audit_case(case: &Value) {
    let id = case["id"].as_str().expect("id");
    let audit = &case["audit"];
    let entries = audit["entries"].as_array().expect("entries");
    let expected: Vec<(String, String, Option<String>)> = audit["verdicts"]
        .as_array()
        .expect("verdicts")
        .iter()
        .map(|verdict| {
            (
                verdict["id"].as_str().expect("id").to_owned(),
                verdict["status"].as_str().expect("status").to_owned(),
                verdict["code"].as_str().map(str::to_owned),
            )
        })
        .collect();
    let orders = permutations(&(0..entries.len()).collect::<Vec<_>>());
    assert!(orders.len() > 1, "{id}");
    for order in orders {
        let flagged: Vec<usize> = match audit["counter"].as_str().expect("counter") {
            "count" => count_bound_violations(
                &order
                    .iter()
                    .map(|index| {
                        (
                            *index,
                            entries[*index]["capacity"].as_u64().expect("capacity"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            "sum" => sum_bound_violations(
                &order
                    .iter()
                    .map(|index| {
                        (
                            *index,
                            entries[*index]["capacity"].as_u64().expect("capacity"),
                            entries[*index]["argument"].as_u64().expect("argument"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            other => panic!("unknown counter {other}"),
        };
        let code = if audit["counter"] == "count" {
            "audit.bound-exceeded"
        } else {
            "audit.sum-exceeded"
        };
        let verdicts: Vec<(String, String, Option<String>)> = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let id = entry["id"].as_str().expect("id").to_owned();
                if flagged.contains(&index) {
                    (id, "inconsistent".to_owned(), Some(code.to_owned()))
                } else {
                    (id, "verified".to_owned(), None)
                }
            })
            .collect();
        assert_eq!(verdicts, expected, "{id} in order {order:?}");
    }
}

async fn bounds_aggregate(backend: Backend) {
    let vectors = Vectors::load();
    let mut ran = 0;
    for case in vectors.document["cases"].as_array().expect("cases") {
        if case.get("audit").is_some() {
            audit_case(case);
        } else if case.get("race").is_some() {
            race_case(&vectors, case, backend).await;
        } else {
            submission_case(&vectors, case, backend).await;
        }
        ran += 1;
    }
    assert_eq!(ran, 30);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_store_passes_bounds_aggregate() {
    bounds_aggregate(Backend::File).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_store_passes_bounds_aggregate() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    bounds_aggregate(Backend::Postgres).await;
}

/// The order-free recount agrees with a brute-force search over every
/// arrival order for up to five entries.
#[test]
fn recount_agrees_with_every_arrival_order() {
    fn admissible_counts(capacities: &[u64]) -> bool {
        permutations(&(0..capacities.len()).collect::<Vec<_>>())
            .iter()
            .any(|order| {
                order.iter().enumerate().all(|(position, index)| {
                    u64::try_from(position).expect("position") < capacities[*index]
                })
            })
    }
    fn admissible_sums(entries: &[(u64, u64)]) -> bool {
        permutations(&(0..entries.len()).collect::<Vec<_>>())
            .iter()
            .any(|order| {
                let mut total = 0;
                order.iter().all(|index| {
                    total += entries[*index].1;
                    total <= entries[*index].0
                })
            })
    }
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for _ in 0..400 {
        let length = 1 + usize::try_from(next(5)).expect("length");
        let capacities: Vec<u64> = (0..length).map(|_| 1 + next(4)).collect();
        let charges: Vec<(usize, u64)> = capacities.iter().copied().enumerate().collect();
        assert_eq!(
            count_bound_violations(&charges).is_empty(),
            admissible_counts(&capacities),
            "{capacities:?}"
        );
        let sums: Vec<(u64, u64)> = (0..length).map(|_| (1 + next(12), next(6))).collect();
        let charges: Vec<(usize, u64, u64)> = sums
            .iter()
            .enumerate()
            .map(|(index, (capacity, argument))| (index, *capacity, *argument))
            .collect();
        assert_eq!(
            sum_bound_violations(&charges).is_empty(),
            admissible_sums(&sums),
            "{sums:?}"
        );
    }
}
