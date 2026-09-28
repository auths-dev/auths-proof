//! Property tests over the gateway's digests, derivations, request paths,
//! relative ceiling, audit recount, signed outcomes, and attempt store.

use crate::audit::{count_bound_violations, sum_bound_violations};
use crate::observer::{OUTCOME_SCHEMA, OutcomeRecord, verify_outcome};
use crate::{
    CompiledRecipe, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptStage,
    GatewayAttempts, GatewayObserver, LogicalOperationId, OperatorNamespace, echo_token,
    idempotency_key,
};
use auths_gateway_kernel::ratio::relative_ceiling_admits;
use proptest::prelude::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

const AIRTABLE_RECIPE: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const AIRTABLE_LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");

fn airtable() -> CompiledRecipe {
    CompiledRecipe::compile(AIRTABLE_RECIPE, AIRTABLE_LOCK).expect("fixture recipe")
}

/// Rebuilds every object of `value` with its members inserted in the order
/// `order` picks, recursively.
fn reorder(value: &Value, order: &mut impl Iterator<Item = usize>) -> Value {
    match value {
        Value::Object(object) => {
            let mut members: Vec<(String, Value)> = object
                .iter()
                .map(|(key, member)| (key.clone(), reorder(member, order)))
                .collect();
            let rotation = order.next().unwrap_or(0) % members.len().max(1);
            members.rotate_left(rotation);
            if order.next().unwrap_or(0) % 2 == 1 {
                members.reverse();
            }
            let mut rebuilt = Map::new();
            for (key, member) in members {
                rebuilt.insert(key, member);
            }
            Value::Object(rebuilt)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| reorder(item, order)).collect())
        }
        other => other.clone(),
    }
}

fn arguments(operation: &str, record: &str, replacement: &str) -> Map<String, Value> {
    let recipe = airtable();
    serde_json::json!({
        "operation_id": operation,
        "operator_namespace": recipe.namespace().as_str(),
        "recipe_digest": recipe.digest_hex(),
        "record_id": record,
        "replacement": replacement,
    })
    .as_object()
    .expect("object")
    .clone()
}

fn percent_decode(segment: &str) -> Option<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = segment.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

/// Every order in which `charges` could have arrived: whether any keeps each
/// entry's slot below its capacity (count) or each running sum within every
/// capacity (sum).
fn some_order_admits(charges: &[(usize, u64, u64)], sum: bool) -> bool {
    fn permute(items: &mut Vec<(usize, u64, u64)>, start: usize, sum: bool) -> bool {
        if start == items.len() {
            let mut used = 0_u128;
            return items
                .iter()
                .enumerate()
                .all(|(position, (_, capacity, argument))| {
                    if sum {
                        used += u128::from(*argument);
                        used <= u128::from(*capacity)
                    } else {
                        (position as u64) < *capacity
                    }
                });
        }
        for index in start..items.len() {
            items.swap(start, index);
            if permute(items, start + 1, sum) {
                items.swap(start, index);
                return true;
            }
            items.swap(start, index);
        }
        false
    }
    permute(&mut charges.to_vec(), 0, sum)
}

fn stage_strategy() -> impl Strategy<Value = GatewayAttemptStage> {
    prop_oneof![
        Just(GatewayAttemptStage::NotEntered),
        Just(GatewayAttemptStage::Unknown),
        Just(GatewayAttemptStage::ResponseRecorded),
        Just(GatewayAttemptStage::Observed),
        Just(GatewayAttemptStage::ObservedByProvider),
    ]
}

prop_compose! {
    /// Any outcome record the presence rule accepts.
    fn outcome_record()(
        stage in stage_strategy(),
        commitment in any::<[u8; 32]>(),
        recipe in any::<[u8; 32]>(),
        evaluated_at in any::<u64>(),
        counters in proptest::option::of(any::<[u8; 32]>()),
        code in "[a-z]{1,20}(\\.[a-z-]{1,20}){0,3}",
        status in 100_u16..=599,
        response in any::<[u8; 32]>(),
        observed_after_unknown in any::<bool>(),
        reading in 0_u8..3,
        evidence in any::<[u8; 32]>(),
        pre_entry in proptest::option::of(any::<[u8; 32]>()),
        basis in proptest::option::of((0_u64..=(1 << 53) - 1, any::<[u8; 32]>())),
    ) -> OutcomeRecord {
        let responded = match stage {
            GatewayAttemptStage::ResponseRecorded | GatewayAttemptStage::Observed => true,
            GatewayAttemptStage::ObservedByProvider => !observed_after_unknown,
            _ => false,
        };
        OutcomeRecord {
            commitment: hex::encode(commitment),
            stage,
            evaluated_at,
            recipe_digest: hex::encode(recipe),
            counters_digest: counters,
            refusal: (stage == GatewayAttemptStage::NotEntered).then_some(code),
            http_status: responded.then_some(status),
            response_digest: responded.then_some(response),
            observation: (stage == GatewayAttemptStage::Observed)
                .then_some(["match", "mismatch", "echo-mismatch"][usize::from(reading)]),
            evidence_digest: (stage == GatewayAttemptStage::ObservedByProvider).then_some(evidence),
            pre_entry_digest: pre_entry,
            relative_basis: basis.map(|(value, _)| value),
            relative_basis_digest: basis.map(|(_, digest)| digest),
        }
    }
}

/// One step of the attempt-store model.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// A submission claims operation `n`; only a successful claim may write.
    Claim(u8),
    /// The holder of operation `n`'s claim records an outcome, or crashes
    /// holding it.
    Finish(u8, u8),
    /// The process restarts: every held claim is dropped unrecorded.
    Restart,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0_u8..3).prop_map(Step::Claim),
        ((0_u8..3), (0_u8..4)).prop_map(|(operation, kind)| Step::Finish(operation, kind)),
        Just(Step::Restart),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Key order never changes a recipe's digest.
    #[test]
    fn key_order_never_changes_a_digest(order in proptest::collection::vec(any::<usize>(), 64)) {
        let source: Value = serde_json::from_slice(AIRTABLE_RECIPE).expect("fixture JSON");
        let reordered = reorder(&source, &mut order.into_iter().cycle());
        let bytes = serde_json::to_vec(&reordered).expect("reordered bytes");
        let compiled = CompiledRecipe::compile(&bytes, AIRTABLE_LOCK).expect("reordered compiles");
        prop_assert_eq!(compiled.digest_hex(), airtable().digest_hex());
    }

    /// The echo token and the idempotency key are injective over their
    /// NUL-separated inputs, and the key ignores the commitment.
    #[test]
    fn echo_token_and_key_are_injective(
        first in ("[a-z][a-z0-9-]{0,10}", "[A-Za-z0-9][A-Za-z0-9._-]{0,20}", any::<[u8; 32]>()),
        second in ("[a-z][a-z0-9-]{0,10}", "[A-Za-z0-9][A-Za-z0-9._-]{0,20}", any::<[u8; 32]>()),
    ) {
        let parse = |(namespace, operation, commitment): &(String, String, [u8; 32])| {
            OperatorNamespace::parse(namespace)
                .ok()
                .zip(LogicalOperationId::parse(operation).ok())
                .map(|(namespace, operation)| (namespace, operation, *commitment))
        };
        let (Some(left), Some(right)) = (parse(&first), parse(&second)) else {
            return Ok(());
        };
        let tokens_equal = echo_token(&left.0, &left.1, &left.2) == echo_token(&right.0, &right.1, &right.2);
        prop_assert_eq!(tokens_equal, first == second);
        let keys_equal = idempotency_key(&left.0, &left.1) == idempotency_key(&right.0, &right.1);
        prop_assert_eq!(keys_equal, first.0 == second.0 && first.1 == second.1);
    }

    /// Every verified path value decodes back from its segment and never
    /// adds a `/`.
    #[test]
    fn path_values_decode_back_and_never_add_a_segment(record in "[ -~\u{e9}\u{4e2d}]{17,40}") {
        prop_assume!(record.len() <= 43);
        let recipe = airtable();
        let Ok(request) = recipe.closed_request_from_arguments(&arguments("op-1", &record, "Approved"), [7; 32]) else {
            return Ok(());
        };
        let path = request.url().strip_prefix("https://api.airtable.com/").expect("origin");
        let segments: Vec<&str> = path.split('/').collect();
        prop_assert_eq!(segments.len(), 4);
        prop_assert_eq!(percent_decode(segments[3]), Some(record.as_bytes().to_vec()));
    }

    /// The relative ceiling agrees with floor division around every exact
    /// multiple of the ratio.
    #[test]
    fn relative_ceiling_agrees_with_floor_division(
        basis in any::<u64>(),
        basis_points in 1_u16..=10_000,
        offset in 0_u64..3,
    ) {
        let ceiling = u128::from(basis) * u128::from(basis_points) / 10_000;
        let argument = u64::try_from(ceiling).unwrap_or(u64::MAX).saturating_add(offset).saturating_sub(1);
        prop_assert_eq!(
            relative_ceiling_admits(argument, basis, basis_points),
            u128::from(argument) <= ceiling
        );
    }

    /// The audit's order-free count and sum conditions agree with a
    /// brute-force search over every arrival order of up to six entries.
    #[test]
    fn audit_conditions_agree_with_every_arrival_order(
        entries in proptest::collection::vec((1_u64..6, 0_u64..8), 1..=6),
    ) {
        let charges: Vec<(usize, u64, u64)> = entries
            .iter()
            .enumerate()
            .map(|(index, (capacity, argument))| (index, *capacity, *argument))
            .collect();
        let counts: Vec<(usize, u64)> = charges.iter().map(|(index, capacity, _)| (*index, *capacity)).collect();
        prop_assert_eq!(count_bound_violations(&counts).is_empty(), some_order_admits(&charges, false));
        let sums: Vec<(usize, u64, u64)> = charges
            .iter()
            .map(|(index, capacity, argument)| (*index, capacity * 3, *argument))
            .collect();
        prop_assert_eq!(sum_bound_violations(&sums).is_empty(), some_order_admits(&sums, true));
    }

    /// Every outcome record the presence rule accepts round-trips through
    /// signing and verification.
    #[test]
    fn outcome_facts_round_trip_through_signing(record in outcome_record()) {
        let observer = GatewayObserver::from_test_seed(0x5a);
        let facts = record.facts().expect("an accepted record has facts");
        let signed = observer
            .sign(OUTCOME_SCHEMA, "auths-gateway://ns/operations/op-1", 1_790_000_000, facts)
            .expect("signed");
        let verified = verify_outcome(signed.bytes(), observer.principal()).expect("verified");
        prop_assert_eq!(verified.record, record);
    }

    /// Against the file store and a pure model: at most one claim, and so at
    /// most one write, per logical operation; a recorded stage never
    /// changes; `not-entered` never follows a write; and a claim held by a
    /// crashed process reads as `unknown`.
    #[test]
    fn attempt_store_follows_the_model(steps in proptest::collection::vec(step(), 1..24)) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        let directory = tempfile::tempdir().expect("tempdir");
        let recipe = airtable();
        let digest = <[u8; 32]>::try_from(hex::decode(recipe.digest_hex()).expect("hex")).expect("digest");
        let root = std::fs::canonicalize(directory.path()).expect("canonical").join("attempts");
        let open = || GatewayAttempts::new(Arc::new(FileGatewayAttemptStore::open(root.clone()).expect("store")));
        let mut attempts = open();
        let mut held: BTreeMap<u8, crate::ClaimedGatewayAttempt> = BTreeMap::new();
        let mut writes: BTreeMap<u8, usize> = BTreeMap::new();
        let mut recorded: BTreeMap<u8, GatewayAttemptStage> = BTreeMap::new();
        for step in steps {
            match step {
                Step::Claim(operation) => {
                    let request = recipe
                        .closed_request_from_arguments(
                            &arguments(&format!("op-{operation}"), "recTEST0000000001", "Approved"),
                            [operation; 32],
                        )
                        .expect("request");
                    match runtime.block_on(attempts.claim(&request, digest, 1_790_000_000)) {
                        Ok(claim) => {
                            *writes.entry(operation).or_default() += 1;
                            held.insert(operation, claim);
                        }
                        Err(GatewayAttemptError::Replay) => {}
                        Err(error) => prop_assert!(false, "claim failed: {error:?}"),
                    }
                }
                Step::Finish(operation, kind) => {
                    let Some(claim) = held.remove(&operation) else { continue };
                    let stage = match kind {
                        0 => runtime.block_on(claim.record_not_entered("gateway.transport.not-entered", None)).map(|snapshot| snapshot.stage()),
                        1 => runtime.block_on(claim.record_unknown()).map(|snapshot| snapshot.stage()),
                        2 => runtime
                            .block_on(claim.record_response(200, [9; 32], None))
                            .and_then(|observable| observable.snapshot())
                            .map(|snapshot| snapshot.stage()),
                        _ => {
                            drop(claim);
                            continue;
                        }
                    };
                    let stage = stage.expect("recorded");
                    prop_assert!(!recorded.contains_key(&operation), "a recorded stage changed");
                    recorded.insert(operation, stage);
                }
                Step::Restart => {
                    held.clear();
                    attempts = open();
                }
            }
            for (operation, count) in &writes {
                prop_assert!(*count <= 1, "operation {operation} was claimed {count} times");
            }
        }
        for operation in 0_u8..3 {
            let stored = runtime
                .block_on(attempts.read(
                    recipe.namespace(),
                    &LogicalOperationId::parse(&format!("op-{operation}")).expect("operation"),
                ))
                .expect("readable");
            match (recorded.get(&operation), stored) {
                (Some(stage), Some(snapshot)) => prop_assert_eq!(snapshot.stage(), *stage),
                (None, Some(snapshot)) => prop_assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown),
                (None, None) => prop_assert!(!writes.contains_key(&operation)),
                (Some(_), None) => prop_assert!(false, "a recorded attempt vanished"),
            }
        }
    }
}
