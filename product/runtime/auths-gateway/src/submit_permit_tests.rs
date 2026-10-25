//! Actual claim/send handler regressions, entering after the verification
//! boundary like the existing scenario corpus. These do not replace verifier
//! soundness or backend conformance tests.

use super::*;
use crate::harness::OBSERVER_SEED;
use crate::transport::ProviderPort;
use crate::ClosedProviderRequest;
use crate::scenario_tests::{TestIo, admitted, test_context};
use crate::store_testkit::{Backend, TestAttempts};
use serde_json::json;
use std::sync::Mutex;

const NOW: u64 = 1_790_000_000;

#[derive(Debug, Eq, PartialEq)]
struct Captured {
    namespace: String,
    recipe: [u8; 32],
    operation: String,
    action: [u8; 32],
    method: String,
    url: String,
    content_type: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl Captured {
    fn from(request: &ClosedProviderRequest) -> Self {
        Self {
            namespace: request.namespace().as_str().to_owned(),
            recipe: *request.recipe_digest(),
            operation: request.operation_id().as_str().to_owned(),
            action: *request.action_commitment(),
            method: format!("{:?}", request.method()),
            url: request.url().to_owned(),
            content_type: request.content_type().to_owned(),
            body: request.body().to_vec(),
            headers: request.headers().iter()
                .map(|header| (header.name().to_owned(), header.value().to_owned())).collect(),
        }
    }
}

#[derive(Default)]
struct Provider {
    writes: Mutex<Vec<Captured>>,
    final_gate_refuses: bool,
}

impl ProviderPort for Provider {
    async fn write(&self, request: &ClosedProviderRequest)
        -> Result<WriteTransportOutcome, GatewayTransportError> {
        if self.final_gate_refuses {
            return Err(GatewayTransportError::EntryDeadline);
        }
        self.writes.lock().unwrap().push(Captured::from(request));
        Ok(WriteTransportOutcome::Unknown)
    }
}

impl ProviderReadPort for Provider {
    async fn action_read(&self, _url: &str, _headers: &[RequestHeader], _maximum: usize)
        -> Option<ProviderResponse> { None }
    async fn credential_read(&self, _read: &ClosedCredentialRead)
        -> Option<ProviderResponse> { None }
}

fn installation() -> (CompiledRecipe, TestAttempts, TrustedContext) {
    let recipe = CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    ).unwrap();
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    (recipe, TestAttempts::open(Backend::File), test_context(&observer))
}

fn command(recipe: &CompiledRecipe, operation: &str, record: &str, value: &str, digest: u8) -> VerifiedCommand {
    admitted(recipe, json!({
        "operation_id": operation, "record_id": record, "replacement": value,
    }).as_object().unwrap(), [digest; 32], Vec::new(), 60, Vec::new(), NOW).unwrap()
}

#[tokio::test]
async fn a_deadline_refusal_at_the_http_leaf_keeps_the_specific_durable_refusal() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "leaf-deadline", "recTEST0000000001", "approved", 1);
    let request = verified.projection().request.clone();
    let provider = Provider { final_gate_refuses: true, ..Provider::default() };
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    run.lease = Some(());
    assert_eq!(run.perform(SubmitAction::CheckDeadline).await, SubmitEvent::Deadline(true));
    assert_eq!(run.send().await, WriteResult::NotEntered);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(run.record_not_entered(Refusal::TransportNotEntered).await);
    let snapshot = store.attempts().read(request.namespace(), request.operation_id()).await.unwrap().unwrap();
    assert_eq!(snapshot.refusal(), Some("gateway.attempt.entry-deadline"));
    assert_eq!(snapshot.stage(), crate::GatewayAttemptStage::NotEntered);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_deadline_that_changes_after_the_order_gate_cannot_enter_or_rearm() {
    use auths_gateway_kernel::deadline::EntryBound;
    use std::sync::atomic::Ordering;

    for (inclusive, dispatch_at) in [(true, NOW + 6), (false, NOW + 5), (true, NOW - 1)] {
        let (recipe, store, context) = installation();
        let mut verified = command(&recipe, "dispatch-deadline", "recTEST0000000001", "approved", 1);
        verified.projection_mut_for_test().entry_not_after = EntryBound {
            not_after: NOW + 5, inclusive,
        };
        let request = verified.projection().request.clone();
        let provider = Provider::default();
        let io = TestIo::new(&provider, verified);
        let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
        let mut run = Run::new(&cx, &io);
        run.evaluated_at = NOW;
        assert!(matches!(run.verify(), Verification::Authorized { .. }));
        assert_eq!(run.claim().await, ClaimResult::Inserted);
        run.lease = Some(());
        assert_eq!(run.perform(SubmitAction::CheckDeadline).await, SubmitEvent::Deadline(true));

        // A scheduler may defer the next action after the order gate passed.
        io.clock.store(dispatch_at, Ordering::SeqCst);
        assert_eq!(run.send().await, WriteResult::NotEntered);
        io.clock.store(NOW, Ordering::SeqCst);
        assert_eq!(run.send().await, WriteResult::Unknown);
        assert_eq!(run.claim().await, ClaimResult::Unavailable);
        assert!(run.record_not_entered(Refusal::TransportNotEntered).await);
        let snapshot = store.attempts().read(request.namespace(), request.operation_id()).await.unwrap().unwrap();
        assert_eq!(snapshot.stage(), crate::GatewayAttemptStage::NotEntered);
        assert_eq!(snapshot.refusal(), Some("gateway.attempt.entry-deadline"));
        assert!(provider.writes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn dropping_a_pending_send_retains_the_claim_and_consumes_the_write_permit() {
    use std::future::Future as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    struct PendingProvider { entries: AtomicUsize }
    impl ProviderPort for PendingProvider {
        async fn write(&self, _request: &ClosedProviderRequest)
            -> Result<WriteTransportOutcome, GatewayTransportError> {
            self.entries.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }
    impl ProviderReadPort for PendingProvider {
        async fn action_read(&self, _url: &str, _headers: &[RequestHeader], _maximum: usize)
            -> Option<ProviderResponse> { None }
        async fn credential_read(&self, _read: &ClosedCredentialRead)
            -> Option<ProviderResponse> { None }
    }

    let (recipe, store, context) = installation();
    let verified = command(&recipe, "cancelled-send", "recTEST0000000001", "approved", 1);
    let request = verified.projection().request.clone();
    let provider = PendingProvider { entries: AtomicUsize::new(0) };
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    run.lease = Some(());
    let mut send = Box::pin(run.send());
    assert!(send.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(send);
    assert_eq!(provider.entries.load(Ordering::SeqCst), 1);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert_eq!(run.claim().await, ClaimResult::Unavailable);
    drop(run);
    assert!(matches!(store.attempts().claim(&request, NOW).await, Err(GatewayAttemptError::Replay)));
    let snapshot = store.attempts().read(request.namespace(), request.operation_id()).await.unwrap().unwrap();
    assert_eq!(snapshot.stage(), crate::GatewayAttemptStage::Attempting);
    assert_eq!(provider.entries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn send_uses_the_claimed_request_once_even_if_later_run_data_changes() {
    let (recipe, store, context) = installation();
    let original = command(&recipe, "permit-one", "recTEST0000000001", "approved", 1);
    let replacement = command(&recipe, "permit-other", "recTEST0000000002", "substituted", 2);
    let expected = Captured::from(&original.projection().request);
    let provider = Provider::default();
    let io = TestIo::new(&provider, original);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    assert_eq!(run.verify(), Verification::Refused, "claimed command is frozen");
    assert_eq!(run.claim().await, ClaimResult::Unavailable, "a run cannot claim another operation");
    // Deliberate internal mutation tests the dataflow barrier independently
    // of the normal step-machine order and the verify-handler freeze.
    assert!(run.verified.is_none(), "the acknowledged claim owns the verified command");
    run.verified = Some(replacement);
    run.evaluated_at = NOW + 1_000;
    run.selected.clear();
    run.lease = Some(());
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert_eq!(run.claim().await, ClaimResult::Unavailable);
    let sent = provider.writes.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0], expected);
}

#[tokio::test]
async fn the_capture_keeps_verification_time_if_pending_clock_state_changes_before_claim() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "permit-evaluation-time", "recTEST0000000001", "approved", 1);
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified).at_entry_time(NOW + 10);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    run.evaluated_at = NOW + 1_000;
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    let captured = run.claimed_command.as_ref().unwrap();
    assert_eq!(write_permit::captured_time(captured), NOW);
    assert_eq!(write_permit::captured_command(captured).projection().evaluated_at, NOW);
    assert_eq!(run.perform(SubmitAction::CheckDeadline).await, SubmitEvent::Deadline(true));
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deadline_uses_the_claimed_witness_even_if_pending_inputs_are_replaced() {
    for (original_horizon, replacement_horizon, final_time, expected) in [
        (NOW + 60, NOW - 1, NOW + 10, true),
        (NOW + 5, u64::MAX, NOW + 6, false),
    ] {
        let (recipe, store, context) = installation();
        let mut original = command(&recipe, "permit-time", "recTEST0000000001", "approved", 1);
        original.projection_mut_for_test().entry_not_after.not_after = original_horizon;
        let mut replacement = command(&recipe, "permit-other-time", "recTEST0000000002", "substituted", 2);
        replacement.projection_mut_for_test().entry_not_after.not_after = replacement_horizon;
        let provider = Provider::default();
        let io = TestIo::new(&provider, original).at_entry_time(final_time);
        let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
        let mut run = Run::new(&cx, &io);
        run.evaluated_at = NOW;
        assert!(matches!(run.verify(), Verification::Authorized { .. }));
        assert_eq!(run.claim().await, ClaimResult::Inserted);
        run.verified = Some(replacement);
        // Both a later lower bound and an earlier one must be ineffective.
        run.evaluated_at = if expected { NOW + 1_000 } else { 0 };
        run.selected.clear();
        assert_eq!(
            run.perform(SubmitAction::CheckDeadline).await,
            SubmitEvent::Deadline(expected),
        );
        assert!(provider.writes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_claim_and_lease_without_the_captured_command_cannot_enter_transport() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "permit-no-witness", "recTEST0000000001", "approved", 1);
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    run.claimed_command = None;
    run.lease = Some(());
    assert_eq!(run.perform(SubmitAction::CheckDeadline).await, SubmitEvent::Deadline(false));
    assert_eq!(run.send().await, WriteResult::NotEntered);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unrelated_captured_command_cannot_license_the_claimed_payload() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "permit-original-witness", "recTEST0000000001", "approved", 1);
    let replacement = command(&recipe, "permit-other-witness", "recTEST0000000002", "substituted", 2);
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    run.claimed_command = Some(Arc::new(write_permit::capture_input(replacement, NOW, Vec::new())));
    run.lease = Some(());
    assert_eq!(run.send().await, WriteResult::NotEntered);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_claim_cannot_use_an_armed_slot_or_lease() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "permit-no-claim", "recTEST0000000001", "approved", 1);
    let payload = Arc::new(write_permit::capture_input(verified.clone(), NOW, Vec::new()));
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.write_permit = write_permit::arm(write_permit::empty(), payload);
    run.lease = Some(());
    assert_eq!(run.send().await, WriteResult::NotEntered);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_lease_consumes_the_slot_without_later_write_permission() {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "permit-no-lease", "recTEST0000000001", "approved", 1);
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    assert_eq!(run.send().await, WriteResult::NotEntered);
    run.lease = Some(());
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn crash_before_or_after_send_cannot_reissue_the_persisted_operation() {
    for enters in [false, true] {
        let (recipe, store, context) = installation();
        let verified = command(&recipe, "permit-crash", "recTEST0000000001", "approved", 1);
        let provider = Provider::default();
        let io = TestIo::new(&provider, verified);
        {
            let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
            let mut run = Run::new(&cx, &io);
            run.evaluated_at = NOW;
            assert!(matches!(run.verify(), Verification::Authorized { .. }));
            assert_eq!(run.claim().await, ClaimResult::Inserted);
            if enters {
                run.lease = Some(());
                assert_eq!(run.send().await, WriteResult::Unknown);
            }
            // Dropping the run discards volatile ownership, not its durable claim.
        }
        let reopened = store.reopen();
        let cx = SubmitContext { recipe: &recipe, attempts: &reopened, context: &context, observer: None };
        let mut restarted = Run::new(&cx, &io);
        restarted.evaluated_at = NOW;
        assert!(matches!(restarted.verify(), Verification::Authorized { .. }));
        assert_eq!(restarted.claim().await, ClaimResult::Replay);
        restarted.lease = Some(());
        assert_eq!(restarted.send().await, WriteResult::NotEntered);
        assert_eq!(provider.writes.lock().unwrap().len(), usize::from(enters));
    }
}

#[tokio::test]
async fn verification_refuses_a_closed_request_from_another_recipe_before_claim() {
    let (recipe, store, context) = installation();
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/recipe.json")).unwrap();
    source["write"]["body"]["value"]["fields"]["mapping_literal"] = json!({"kind": "string", "value": "different mapping"});
    let other_recipe = CompiledRecipe::compile(&serde_json::to_vec(&source).unwrap(), include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/profile.lock.json")).unwrap();
    assert_ne!(recipe.digest(), other_recipe.digest());
    assert_eq!(recipe.namespace(), other_recipe.namespace());
    let verified = command(&other_recipe, "cross-recipe", "recTEST0000000001", "approved", 1);
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert_eq!(run.verify(), Verification::Refused);
    assert_eq!(run.claim().await, ClaimResult::Unavailable);
    assert!(store.attempts().stages(16).await.unwrap().is_empty());
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn send_refuses_a_different_operation_or_backend_handle_even_when_a_claim_is_present() {
    for different_backend in [false, true] {
        let (recipe, store, context) = installation();
        let verified = command(&recipe, "bound-operation", "recTEST0000000001", "approved", 1);
        let original_request = verified.projection().request.clone();
        let provider = Provider::default();
        let io = TestIo::new(&provider, verified);
        let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
        let mut run = Run::new(&cx, &io);
        run.evaluated_at = NOW;
        assert!(matches!(run.verify(), Verification::Authorized { .. }));
        assert_eq!(run.claim().await, ClaimResult::Inserted);
        let other_store = TestAttempts::open(Backend::File);
        let (substitute, target_request) = if different_backend {
            (other_store.attempts().claim(&original_request, NOW).await.unwrap(), original_request.clone())
        } else {
            let other = command(&recipe, "different-operation", "recTEST0000000001", "approved", 1);
            (store.attempts().claim(&other.projection().request, NOW).await.unwrap(), other.into_projection().request)
        };
        let target_store = if different_backend { other_store.attempts() } else { store.attempts() };
        let before = target_store.read(target_request.namespace(), target_request.operation_id()).await.unwrap();
        assert!(!crate::store::claimed_request_matches(&substitute, store.attempts(), &original_request, NOW));
        run.claim = Some(substitute);
        run.lease = Some(());
        assert_eq!(run.send().await, WriteResult::NotEntered);
        assert_eq!(run.send().await, WriteResult::Unknown);
        assert!(!run.record_not_entered(Refusal::TransportNotEntered).await);
        assert_eq!(target_store.read(target_request.namespace(), target_request.operation_id()).await.unwrap(), before);
        assert!(provider.writes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_replacement_permit_and_command_cannot_change_the_claimed_verification_time() {
    for captured_time in [NOW, NOW + 1] {
    let (recipe, store, context) = installation();
    let verified = command(&recipe, "bound-time", "recTEST0000000001", "approved", 1);
    let mut replacement = verified.clone();
    replacement.projection_mut_for_test().evaluated_at = NOW + 1;
    let provider = Provider::default();
    let io = TestIo::new(&provider, verified);
    let cx = SubmitContext { recipe: &recipe, attempts: store.attempts(), context: &context, observer: None };
    let mut run = Run::new(&cx, &io);
    run.evaluated_at = NOW;
    assert!(matches!(run.verify(), Verification::Authorized { .. }));
    assert_eq!(run.claim().await, ClaimResult::Inserted);
    let replacement = Arc::new(write_permit::capture_input(replacement, captured_time, Vec::new()));
    run.write_permit = write_permit::arm(write_permit::empty(), Arc::clone(&replacement));
    run.claimed_command = Some(replacement);
    run.lease = Some(());
    assert_eq!(run.send().await, WriteResult::NotEntered);
    assert_eq!(run.send().await, WriteResult::Unknown);
    assert!(provider.writes.lock().unwrap().is_empty());
    }
}
