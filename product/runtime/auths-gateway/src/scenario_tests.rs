//! The attempt-scenario corpus and the shared store conformance suite,
//! driven through the engine's own submission driver with counting provider
//! doubles.
//!
//! The corpus enters after native verification: each case builds the
//! verified command from its arguments and admits it under its grant's
//! policy `/2` with the gateway's own admission, and the step machine then
//! directs the account-scope binding and every claim, lease, credential
//! read, action read, store write, and write entry against a provider
//! double that counts them.

#![allow(clippy::too_many_lines, reason = "scenario tables read top to bottom")]

use crate::engine::{GatewaySubmitResult, VerifiedCommand, replay_refused};
use crate::harness::{OBSERVER_SEED, ROOT_SEED, Signer, context};
use crate::pending_vectors::attempts::FILE as SCENARIOS;
use crate::recipe::GuardChecks;
use crate::store::BatchCrash;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::submit::{self, SubmitContext, SubmitIo, account_commitment};
use crate::transport::{
    GatewayTransportError, ProviderPort, ProviderResponse, WriteTransportOutcome,
};
use crate::{
    ClosedCredentialRead, ClosedProviderRequest, CompiledRecipe, FileGatewayAttemptStore,
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptSnapshot, GatewayAttemptStage,
    GatewayAttemptStore, GatewayAttempts, GatewayInsert, GatewayObservationFact, GatewayObserver,
    GatewayRecordEntry, GatewayRecordKind, LogicalOperationId, RequestHeader, echo_token,
};
use auths_model::{
    ConditionTest, FactName, ObservationCondition, ObservationRequirement, ObservationSchemaId,
    ObservationSubject, ObserverAnchorId, TrustedContext,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: u64 = 1_790_000_000;
const ORIGINAL: [u8; 32] = [0x11; 32];
const FRESH: [u8; 32] = [0x22; 32];
const RECORD: &str = "recTEST0000000001";
const FOREIGN: &str = "auths-e1-0000000000000000000000000000000000000000000000000000000000000000";

fn corpus(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture JSON")
}

// ---------------------------------------------------------------------------
// A store that records every stored attempt stage and can lose one write.

/// Wraps a store, recording each stored attempt stage in order. When armed,
/// it fails the one replacement that would record `response-recorded`, as a
/// crash between the write and its response record would.
struct RecordingStore {
    inner: Arc<dyn GatewayAttemptStore>,
    stages: Mutex<Vec<String>>,
    lose_response_record: AtomicBool,
}

impl RecordingStore {
    fn new(inner: Arc<dyn GatewayAttemptStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            stages: Mutex::new(Vec::new()),
            lose_response_record: AtomicBool::new(false),
        })
    }

    fn stage_of(bytes: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(bytes)
            .ok()?
            .get("stage")?
            .as_str()
            .map(str::to_owned)
    }

    fn record(&self, bytes: &[u8]) {
        if let Some(stage) = Self::stage_of(bytes) {
            self.stages.lock().expect("stages").push(stage);
        }
    }

    fn stages(&self) -> Vec<String> {
        self.stages.lock().expect("stages").clone()
    }
}

impl GatewayAttemptStore for RecordingStore {
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        let inserted = self.inner.insert_all(entries)?;
        if inserted == GatewayInsert::Inserted {
            for entry in entries {
                if entry.kind == GatewayRecordKind::Attempt {
                    self.record(&entry.record);
                }
            }
        }
        Ok(inserted)
    }

    fn insert(&self, entry: &GatewayRecordEntry) -> Result<(), GatewayAttemptError> {
        self.inner.insert(entry)?;
        if entry.kind == GatewayRecordKind::Attempt {
            self.record(&entry.record);
        }
        Ok(())
    }

    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.inner.load(kind, key)
    }

    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if Self::stage_of(next).as_deref() == Some("response-recorded")
            && self.lose_response_record.swap(false, Ordering::SeqCst)
        {
            return Err(GatewayAttemptError::Unavailable);
        }
        self.inner.replace(kind, key, current, next)?;
        if kind == GatewayRecordKind::Attempt {
            self.record(next);
        }
        Ok(())
    }

    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
}

// ---------------------------------------------------------------------------
// The submission I/O of a verified command.

pub(crate) struct TestIo<'a, P> {
    provider: &'a P,
    /// The verified command, or the refusal verification and admission
    /// return before any claim.
    pub(crate) verified: Result<VerifiedCommand, GatewaySubmitResult>,
    /// The recipe whose account-scope binding the step machine runs; `None`
    /// binds nothing.
    pub(crate) recipe: Option<&'a CompiledRecipe>,
    pub(crate) clock: AtomicU64,
    deadline_advance: u64,
    secret: Vec<u8>,
    account: [u8; 32],
    leases: AtomicUsize,
}

impl<'a, P> TestIo<'a, P> {
    pub(crate) fn new(provider: &'a P, verified: VerifiedCommand) -> Self {
        Self::answering(provider, Ok(verified))
    }

    pub(crate) fn answering(
        provider: &'a P,
        verified: Result<VerifiedCommand, GatewaySubmitResult>,
    ) -> Self {
        Self {
            provider,
            verified,
            recipe: None,
            clock: AtomicU64::new(NOW),
            deadline_advance: 0,
            secret: b"rk_test_not-a-real-credential".to_vec(),
            account: account_commitment("acct_TESTPLATFORM1"),
            leases: AtomicUsize::new(0),
        }
    }

    pub(crate) fn leases(&self) -> usize {
        self.leases.load(Ordering::SeqCst)
    }
}

impl<P: ProviderPort> SubmitIo for TestIo<'_, P> {
    type Lease = ();

    fn clock(&self) -> Option<u64> {
        Some(self.clock.load(Ordering::SeqCst))
    }

    fn verify(&self, _now: u64) -> Result<VerifiedCommand, GatewaySubmitResult> {
        self.verified.clone()
    }

    fn bind_scope(&self, verified: &VerifiedCommand) -> Result<(), &'static str> {
        self.recipe.map_or(Ok(()), |recipe| {
            crate::bounds::bind_account_scope(recipe, verified.bound.as_ref(), &verified.arguments)
        })
    }

    async fn prepare(&self) -> Result<(), &'static str> {
        Ok(())
    }

    async fn reload(&self) -> bool {
        true
    }

    async fn lease(&self) -> Option<()> {
        self.leases.fetch_add(1, Ordering::SeqCst);
        Some(())
    }

    fn secret_admitted(&self, _lease: &(), guard: &GuardChecks) -> bool {
        guard.admits_secret(&self.secret)
    }

    fn account_commitment(&self) -> Option<[u8; 32]> {
        Some(self.account)
    }

    fn within_entry_deadline(&self, evaluated_at: u64) -> bool {
        self.clock.load(Ordering::SeqCst) + self.deadline_advance
            <= evaluated_at + crate::recipe::ENTRY_DEADLINE_SECONDS
    }

    async fn write(
        &self,
        _lease: &(),
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.provider.write(request).await
    }

    async fn action_read(
        &self,
        _lease: &(),
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        self.provider
            .action_read(url, headers, maximum_response_bytes)
            .await
    }

    async fn credential_read(
        &self,
        _lease: &(),
        read: &ClosedCredentialRead,
    ) -> Option<ProviderResponse> {
        self.provider.credential_read(read).await
    }
}

/// Trust with the test root and the test observer's anchor.
pub(crate) fn test_context(observer: &GatewayObserver) -> TrustedContext {
    context(&Signer::new(ROOT_SEED), observer.principal(), None, NOW).expect("context")
}

/// The verified command of `arguments` under `recipe`, as native
/// verification would project it.
fn verified(
    recipe: &CompiledRecipe,
    values: &Map<String, Value>,
    commitment: [u8; 32],
    requirements: Vec<ObservationRequirement>,
    validity_seconds: u64,
) -> VerifiedCommand {
    admitted(
        recipe,
        values,
        commitment,
        requirements,
        validity_seconds,
        Vec::new(),
        NOW,
    )
    .expect("verified command")
}

/// The verified command of `values` under `recipe`, admitted under `links`
/// by the gateway's own bounded-policy admission at `now`, or the refusal
/// verification returns before any claim: an admission refusal, or a value
/// the closed request refuses.
pub(crate) fn admitted(
    recipe: &CompiledRecipe,
    values: &Map<String, Value>,
    commitment: [u8; 32],
    requirements: Vec<ObservationRequirement>,
    validity_seconds: u64,
    links: Vec<crate::bounds::BoundLink>,
    now: u64,
) -> Result<VerifiedCommand, GatewaySubmitResult> {
    let mut arguments = values.clone();
    arguments.insert(
        "operator_namespace".into(),
        json!(recipe.namespace().as_str()),
    );
    arguments.insert("recipe_digest".into(), json!(recipe.digest_hex()));
    let review = recipe.review();
    let call = McpToolCall::new(review.service(), review.tool(), arguments.clone()).expect("call");
    let canonical_action = McpProfile
        .canonicalize(&call.canonical_bytes().expect("canonical call"))
        .expect("canonical action");
    let bound = crate::bounds::admit_links(links, &canonical_action, recipe, now)
        .map_err(crate::engine::not_entered)?;
    let request = recipe
        .closed_request_from_arguments(&arguments, commitment)
        .map_err(|error| crate::engine::not_entered(error.code()))?;
    Ok(VerifiedCommand {
        request,
        bound,
        approvers: Vec::new(),
        arguments,
        requirements,
        canonical_action,
        validity_seconds,
        observer_refusal: None,
    })
}

/// Policy `/2` from its members as the fixtures list them.
pub(crate) fn policy_from_members(members: &Value) -> crate::ArgumentCeilingPolicy {
    let list = |value: &Value| {
        let values: Vec<&str> = value["values"]
            .as_array()
            .expect("values")
            .iter()
            .map(|item| item.as_str().expect("value"))
            .collect();
        crate::ListedValues::new(value["argument"].as_str().expect("argument"), &values)
            .expect("listed values")
    };
    let mut policy = crate::ArgumentCeilingPolicy::new(
        members["argument"].as_str().expect("argument"),
        members["ceiling"].as_u64().expect("ceiling"),
        members["window_seconds"].as_u64().expect("window"),
        members["max_count"].as_u64().expect("count"),
    )
    .expect("policy");
    if let Some(limit) = members.get("sum_limit").and_then(Value::as_u64) {
        let partition = members
            .get("partition")
            .filter(|value| !value.is_null())
            .map(list);
        policy = policy.with_sum(limit, partition).expect("sum");
    }
    if let Some(scope) = members.get("scope").filter(|value| !value.is_null()) {
        policy = policy.with_scope(list(scope)).expect("scope");
    }
    policy
}

async fn run<P: ProviderPort>(
    attempts: &GatewayAttempts,
    recipe: &CompiledRecipe,
    observer: &GatewayObserver,
    io: &TestIo<'_, P>,
) -> GatewaySubmitResult {
    let context = test_context(observer);
    submit::run(
        &SubmitContext {
            recipe,
            attempts,
            context: &context,
            observer: Some(observer),
        },
        io,
    )
    .await
}

// ---------------------------------------------------------------------------
// The record double of the `/2` record scenarios.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivery {
    Respond,
    RespondWithoutApplying,
    TimeoutAfterApplying,
    LostBeforeApplying,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reading {
    Faithful,
    Unavailable,
    ForeignEcho,
    EchoStripped,
    ValueChanged,
}

/// A provider holding one Airtable record that counts every write entry and
/// read-back.
struct RecordProvider {
    delivery: Delivery,
    reading: Reading,
    writes: AtomicUsize,
    reads: AtomicUsize,
    fields: Mutex<Map<String, Value>>,
    last_read: Mutex<Vec<u8>>,
    idempotency_keys: Mutex<Vec<Option<String>>>,
}

impl RecordProvider {
    fn new(delivery: Delivery, reading: Reading) -> Self {
        let mut fields = Map::new();
        fields.insert("DemoStatus".into(), json!("Pending"));
        Self {
            delivery,
            reading,
            writes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            fields: Mutex::new(fields),
            last_read: Mutex::new(Vec::new()),
            idempotency_keys: Mutex::new(Vec::new()),
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl ProviderPort for RecordProvider {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.idempotency_keys
            .lock()
            .expect("keys")
            .push(request.idempotency_key().map(str::to_owned));
        if matches!(
            self.delivery,
            Delivery::Respond | Delivery::TimeoutAfterApplying
        ) {
            let body: Value = serde_json::from_slice(request.body())
                .map_err(|_| GatewayTransportError::NotEntered)?;
            if let Some(update) = body.get("fields").and_then(Value::as_object) {
                self.fields.lock().expect("fields").extend(update.clone());
            }
        }
        Ok(match self.delivery {
            Delivery::Respond | Delivery::RespondWithoutApplying => {
                WriteTransportOutcome::ResponseRecorded {
                    status: 200,
                    digest: [4; 32],
                    body: br#"{"id":"recTEST0000000001","number":7}"#.to_vec(),
                    version_ok: true,
                }
            }
            Delivery::TimeoutAfterApplying | Delivery::LostBeforeApplying => {
                WriteTransportOutcome::Unknown
            }
        })
    }

    async fn action_read(
        &self,
        _url: &str,
        _headers: &[RequestHeader],
        _maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut fields = self.fields.lock().expect("fields").clone();
        match self.reading {
            Reading::Faithful => {}
            Reading::Unavailable => return None,
            Reading::ForeignEcho => {
                fields.insert("auths_echo".into(), json!(FOREIGN));
            }
            Reading::EchoStripped => {
                fields.remove("auths_echo");
            }
            Reading::ValueChanged => {
                fields.insert("DemoStatus".into(), json!("Pending"));
            }
        }
        let bytes = serde_json::to_vec(&json!({"id": RECORD, "fields": fields})).ok()?;
        *self.last_read.lock().expect("last read") = bytes.clone();
        Some(ProviderResponse {
            status: 200,
            version_ok: true,
            body: bytes,
        })
    }

    async fn credential_read(&self, _read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        None
    }
}

fn fixture_recipe(name: &str) -> CompiledRecipe {
    let (source, lock): (&[u8], &[u8]) = match name {
        "airtable" => (
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        ),
        "github" => (
            include_bytes!("../../../../bindings/fixtures/gateway/github/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/github/profile.lock.json"),
        ),
        _ => panic!("unknown test-only fixture"),
    };
    CompiledRecipe::compile(source, lock).expect("fixture compiles")
}

/// One installed fixture recipe over one attempt store.
struct Record {
    recipe: CompiledRecipe,
    store: TestAttempts,
    observer: GatewayObserver,
}

impl Record {
    fn open(name: &str, backend: Backend) -> Self {
        Self {
            recipe: fixture_recipe(name),
            store: TestAttempts::open(backend),
            observer: GatewayObserver::from_test_seed(OBSERVER_SEED),
        }
    }

    fn command(&self, commitment: [u8; 32], values: &Value) -> VerifiedCommand {
        verified(
            &self.recipe,
            values.as_object().expect("object"),
            commitment,
            Vec::new(),
            3_600,
        )
    }

    fn airtable(&self, commitment: [u8; 32], replacement: &str) -> VerifiedCommand {
        self.command(
            commitment,
            &json!({"operation_id": "run-1", "record_id": RECORD, "replacement": replacement}),
        )
    }

    fn github(&self) -> VerifiedCommand {
        self.command(
            ORIGINAL,
            &json!({"operation_id": "issue-1", "title": "Exact", "body": "One issue"}),
        )
    }

    async fn submit(
        &self,
        command: &VerifiedCommand,
        provider: &RecordProvider,
    ) -> GatewaySubmitResult {
        let io = TestIo::new(provider, command.clone());
        run(self.store.attempts(), &self.recipe, &self.observer, &io).await
    }

    async fn submit_on(
        &self,
        attempts: &GatewayAttempts,
        command: &VerifiedCommand,
        provider: &RecordProvider,
    ) -> GatewaySubmitResult {
        let io = TestIo::new(provider, command.clone());
        run(attempts, &self.recipe, &self.observer, &io).await
    }

    async fn snapshot(&self, command: &VerifiedCommand) -> GatewayAttemptSnapshot {
        self.store
            .attempts()
            .read(command.request.namespace(), command.request.operation_id())
            .await
            .expect("read")
            .expect("retained claim")
    }

    async fn describe(&self, command: &VerifiedCommand) -> String {
        let snapshot = self.snapshot(command).await;
        let stage = serde_json::to_value(snapshot.stage())
            .expect("stage")
            .as_str()
            .expect("kebab stage")
            .to_owned();
        match (snapshot.observation_match(), snapshot.observation_fact()) {
            (Some(true), _) => format!("{stage}-match"),
            (Some(false), Some(GatewayObservationFact::EchoMismatch)) => {
                format!("{stage}-mismatch-echo-mismatch")
            }
            (Some(false), None) => format!("{stage}-mismatch"),
            (None, _) => stage,
        }
    }
}

fn original_token() -> String {
    echo_token(
        &crate::OperatorNamespace::parse("airtable-demo").expect("namespace"),
        &LogicalOperationId::parse("run-1").expect("operation"),
        &ORIGINAL,
    )
}

async fn run_claim_case(id: &str, backend: Backend) -> (String, usize) {
    let mut record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let original = record.airtable(ORIGINAL, "Approved");
    drop(
        record
            .store
            .attempts()
            .claim(&original.request, *record.recipe.digest(), NOW)
            .await
            .expect("first claim"),
    );
    let transition = match id {
        "first-claim" => "unclaimed->attempting".to_owned(),
        "same-id-fresh-challenge" | "changed-action-same-id" => {
            let replacement = if id == "same-id-fresh-challenge" {
                "Approved"
            } else {
                "Pending"
            };
            let second = record.airtable(FRESH, replacement);
            assert_eq!(record.submit(&second, &provider).await, replay_refused());
            "attempting->replay-refused".to_owned()
        }
        "crash-after-claim" => {
            record.store.restart();
            format!(
                "attempting->{}-on-restart",
                record.describe(&original).await
            )
        }
        _ => panic!("unhandled claim scenario {id}"),
    };
    (transition, provider.writes())
}

async fn run_first_attempt_case(id: &str, backend: Backend) -> (String, usize) {
    let (delivery, reading) = match id {
        "complete-http-response" | "echo-read-back" => (Delivery::Respond, Reading::Faithful),
        "ambiguous-transport" => (Delivery::LostBeforeApplying, Reading::Faithful),
        "matching-read-back" => (Delivery::Respond, Reading::EchoStripped),
        "mismatching-read-back" => (Delivery::RespondWithoutApplying, Reading::Faithful),
        "observation-unavailable" => (Delivery::Respond, Reading::Unavailable),
        "echo-overwritten-by-provider" => (Delivery::Respond, Reading::ForeignEcho),
        "echo-present-value-changed" => (Delivery::Respond, Reading::ValueChanged),
        _ => panic!("unhandled first-attempt scenario {id}"),
    };
    let record = Record::open(
        if matches!(id, "complete-http-response" | "ambiguous-transport") {
            "github"
        } else {
            "airtable"
        },
        backend,
    );
    let provider = RecordProvider::new(delivery, reading);
    let command = if record.recipe.review().has_observation() {
        record.airtable(ORIGINAL, "Approved")
    } else {
        record.github()
    };
    let result = record.submit(&command, &provider).await;
    let from = if matches!(result, GatewaySubmitResult::Unknown)
        || !record.recipe.review().has_observation()
    {
        "attempting"
    } else {
        "response-recorded"
    };
    (
        format!("{from}->{}", record.describe(&command).await),
        provider.writes(),
    )
}

async fn run_resolution_case(id: &str, backend: Backend) -> (String, usize) {
    let (delivery, reading) = match id {
        "lost-write-echo-absent" => (Delivery::LostBeforeApplying, Reading::Faithful),
        "unknown-echo-overwritten" => (Delivery::TimeoutAfterApplying, Reading::ForeignEcho),
        "fresh-challenge-after-observed-by-provider" => (Delivery::Respond, Reading::Faithful),
        _ => (Delivery::TimeoutAfterApplying, Reading::Faithful),
    };
    let mut record = Record::open("airtable", backend);
    let provider = RecordProvider::new(delivery, reading);
    let original = record.airtable(ORIGINAL, "Approved");
    let first = record.submit(&original, &provider).await;
    let before = record.describe(&original).await;
    if id == "restart-during-unknown" {
        record.store.restart();
    }
    let replacement = if id == "changed-action-during-unknown" {
        "Pending"
    } else {
        "Approved"
    };
    let replay = record
        .submit(&record.airtable(FRESH, replacement), &provider)
        .await;
    if matches!(
        record.snapshot(&original).await.stage(),
        GatewayAttemptStage::ObservedByProvider
    ) && before != "observed-by-provider"
    {
        assert!(matches!(
            replay,
            GatewaySubmitResult::ObservedByProvider { status: None, .. }
        ));
    } else {
        assert_eq!(replay, replay_refused(), "{id}: first {first:?}");
    }
    (
        format!("{before}->{}", record.describe(&original).await),
        provider.writes(),
    )
}

/// Drives the record scenarios of the corpus against `backend`.
async fn record_scenarios(backend: Backend) {
    let corpus = corpus(SCENARIOS);
    let cases = corpus["record_cases"].as_array().expect("record cases");
    assert_eq!(cases.len(), 18);
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let (transition, writes) = match id {
            "first-claim"
            | "same-id-fresh-challenge"
            | "changed-action-same-id"
            | "crash-after-claim" => run_claim_case(id, backend).await,
            "timeout-after-delivery-read-back"
            | "lost-write-echo-absent"
            | "unknown-echo-overwritten"
            | "restart-during-unknown"
            | "changed-action-during-unknown"
            | "fresh-challenge-after-observed-by-provider" => {
                run_resolution_case(id, backend).await
            }
            _ => run_first_attempt_case(id, backend).await,
        };
        assert_eq!(transition, case["transition"], "{}: {id}", backend.label());
        assert_eq!(
            u64::try_from(writes).expect("count"),
            case["provider_entries"].as_u64().expect("entries"),
            "{}: {id}",
            backend.label()
        );
    }
}

#[tokio::test]
async fn record_scenarios_drive_the_counting_provider() {
    record_scenarios(Backend::File).await;
}

#[tokio::test]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_record_scenarios_drive_the_counting_provider() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    record_scenarios(Backend::Postgres).await;
}

#[tokio::test]
async fn normal_write_reaches_observed_by_provider_with_secret_free_evidence() {
    let record = Record::open("airtable", Backend::File);
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let command = record.airtable(ORIGINAL, "Approved");
    let result = record.submit(&command, &provider).await;
    let snapshot = record.snapshot(&command).await;
    let evidence = snapshot.provider_evidence().expect("evidence");
    let bytes = provider.last_read.lock().expect("last read").clone();
    assert_eq!(snapshot.stage(), GatewayAttemptStage::ObservedByProvider);
    assert_eq!(snapshot.evaluated_at(), NOW);
    assert_eq!(
        evidence.locator(),
        command.request.observation().expect("obs").url()
    );
    assert_eq!(evidence.echo(), original_token());
    assert_eq!(evidence.evidence(), bytes.as_slice());
    assert_eq!(
        evidence.evidence_digest(),
        &<[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert!(!format!("{evidence:?}").contains("DemoStatus"));
    assert_eq!(
        result,
        GatewaySubmitResult::ObservedByProvider {
            status: Some(200),
            evidence: evidence.into(),
        }
    );
    assert_eq!((provider.writes(), provider.reads()), (1, 1));
}

/// While the attempt store is intact, the claim alone stops a fresh
/// challenge for the same logical operation. Once the store is lost the
/// operation enters the provider again; only the repeated derived key lets a
/// provider that honors it de-duplicate that second entry.
#[tokio::test]
async fn a_lost_claim_resends_the_same_idempotency_key() {
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/airtable/recipe.json"
    ))
    .expect("source");
    source["write"]["idempotency"] = json!({"kind": "derived-header", "retention_seconds": 86_400});
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&source).expect("source"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("recipe");
    let key = crate::idempotency_key(
        recipe.namespace(),
        &LogicalOperationId::parse("run-1").expect("operation"),
    );
    let intact = Record {
        recipe: recipe.clone(),
        store: TestAttempts::open(Backend::File),
        observer: GatewayObserver::from_test_seed(OBSERVER_SEED),
    };
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let original = intact.airtable(ORIGINAL, "Approved");
    assert!(matches!(
        intact.submit(&original, &provider).await,
        GatewaySubmitResult::ObservedByProvider { .. }
    ));
    let fresh = intact.airtable(FRESH, "Approved");
    assert_eq!(intact.submit(&fresh, &provider).await, replay_refused());
    assert_eq!(provider.writes(), 1, "the intact claim stops the repeat");
    let lost = Record {
        recipe,
        store: TestAttempts::open(Backend::File),
        observer: GatewayObserver::from_test_seed(OBSERVER_SEED),
    };
    assert!(matches!(
        lost.submit(&fresh, &provider).await,
        GatewaySubmitResult::ObservedByProvider { .. }
    ));
    assert_eq!(provider.writes(), 2, "a lost claim no longer stops it");
    assert_eq!(
        *provider.idempotency_keys.lock().expect("keys"),
        [Some(key.clone()), Some(key)]
    );
}

// ---------------------------------------------------------------------------
// The response-table double of the record `/3` scenarios.

/// A provider that answers each `METHOD /path` from a table, applies each
/// write to the table the way the provider would, and counts every request
/// by kind.
pub(crate) struct TableProvider {
    origin: String,
    answers: Mutex<BTreeMap<String, Value>>,
    required_versions: Vec<(String, String)>,
    write_mode: String,
    writes: AtomicUsize,
    credential_reads: AtomicUsize,
    action_reads: AtomicUsize,
    requests: Mutex<Vec<Value>>,
}

impl TableProvider {
    pub(crate) fn new(recipe: &CompiledRecipe, answers: &Value, write_mode: &str) -> Self {
        Self {
            origin: recipe.review().origin().to_owned(),
            answers: Mutex::new(
                answers
                    .as_object()
                    .expect("answers")
                    .iter()
                    .map(|(key, answer)| (key.clone(), answer.clone()))
                    .collect(),
            ),
            required_versions: recipe.required_response_versions(),
            write_mode: write_mode.to_owned(),
            writes: AtomicUsize::new(0),
            credential_reads: AtomicUsize::new(0),
            action_reads: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// How many writes entered the provider.
    pub(crate) fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn path<'a>(&self, url: &'a str) -> &'a str {
        url.strip_prefix(&self.origin).unwrap_or(url)
    }

    fn log(&self, method: &str, url: &str, headers: &[RequestHeader], key: bool) {
        let header = |name: &str| {
            headers
                .iter()
                .find(|header| header.name() == name)
                .map_or(Value::Null, |header| json!(header.value()))
        };
        self.requests.lock().expect("requests").push(json!({
            "method": method, "path": self.path(url),
            "stripe_version": header("Stripe-Version"),
            "stripe_account": header("Stripe-Account"),
            "idempotency_key": key, "credential": true
        }));
    }

    fn answer(&self, method: &str, url: &str) -> Option<ProviderResponse> {
        let answers = self.answers.lock().expect("answers");
        let answer = answers.get(&format!("{method} {}", self.path(url)))?;
        let headers = answer["headers"].as_object().cloned().unwrap_or_default();
        let version_ok = self
            .required_versions
            .iter()
            .all(|(name, value)| headers.get(name).and_then(Value::as_str) == Some(value.as_str()));
        Some(ProviderResponse {
            status: u16::try_from(answer["status"].as_u64()?).ok()?,
            version_ok,
            body: serde_json::to_vec(&answer["body"]).ok()?,
        })
    }

    /// Applies one write: placeholders take the written amount and echo, and
    /// JSON `fields` merge into the record read at the same path.
    fn apply(&self, request: &ClosedProviderRequest) {
        let (amount, echo, fields) = if request.content_type().starts_with("application/json") {
            let body: Value = serde_json::from_slice(request.body()).unwrap_or(Value::Null);
            (
                Value::Null,
                body.pointer("/fields/auths_echo")
                    .cloned()
                    .unwrap_or(Value::Null),
                body.get("fields").and_then(Value::as_object).cloned(),
            )
        } else {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(request.body())
                .into_owned()
                .collect();
            (
                form.get("amount")
                    .and_then(|amount| amount.parse::<u64>().ok())
                    .map_or(Value::Null, |amount| json!(amount)),
                form.get("metadata[auths_echo]")
                    .map_or(Value::Null, |echo| json!(echo)),
                None,
            )
        };
        let mut answers = self.answers.lock().expect("answers");
        for answer in answers.values_mut() {
            substitute(&mut answer["body"], &amount, &echo);
        }
        if let (Some(fields), Some(record)) = (
            fields,
            answers.get_mut(&format!("GET {}", self.path(request.url()))),
        ) && let Some(existing) = record["body"]["fields"].as_object_mut()
        {
            existing.extend(fields);
        }
    }
}

fn substitute(value: &mut Value, amount: &Value, echo: &Value) {
    match value {
        Value::String(text) if text == "<written amount>" => *value = amount.clone(),
        Value::String(text) if text == "<written echo>" => *value = echo.clone(),
        Value::Object(object) => object
            .values_mut()
            .for_each(|member| substitute(member, amount, echo)),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| substitute(item, amount, echo)),
        _ => {}
    }
}

impl ProviderPort for TableProvider {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.log(
            request.method().as_str(),
            request.url(),
            request.headers(),
            request.idempotency_key().is_some(),
        );
        if self.write_mode == "refused-before-send" {
            return Err(GatewayTransportError::NotEntered);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.apply(request);
        if self.write_mode == "timeout-after-send" {
            return Ok(WriteTransportOutcome::Unknown);
        }
        let response = self
            .answer(request.method().as_str(), request.url())
            .ok_or(GatewayTransportError::NotEntered)?;
        Ok(WriteTransportOutcome::ResponseRecorded {
            status: response.status,
            digest: Sha256::digest(&response.body).into(),
            body: response.body,
            version_ok: response.version_ok,
        })
    }

    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        self.action_reads.fetch_add(1, Ordering::SeqCst);
        self.log("GET", url, headers, false);
        self.answer("GET", url)
            .filter(|response| response.body.len() <= maximum_response_bytes)
    }

    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        self.credential_reads.fetch_add(1, Ordering::SeqCst);
        self.log(read.method().as_str(), read.url(), read.headers(), false);
        self.answer(read.method().as_str(), read.url())
            .filter(|response| response.body.len() <= read.maximum_response_bytes())
    }
}

/// Deep-merges `overlay` into `base`; a null member removes the base member.
fn merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                if value.is_null() {
                    base.remove(key);
                } else if key == "responses" || key == "arguments" || key == "grant_policy" {
                    merge(base.entry(key.clone()).or_insert(json!({})), value);
                } else {
                    base.insert(key.clone(), value.clone());
                }
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

/// The readback requirement a scenario grant carries.
fn grant_requirement(setup: &Value) -> Vec<ObservationRequirement> {
    let Some(requirement) = setup
        .get("grant_requirement")
        .filter(|value| !value.is_null())
    else {
        return Vec::new();
    };
    let subject = requirement["subject"]["action_fact"]
        .as_str()
        .expect("action-fact subject");
    let conditions = requirement["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .map(|condition| {
            let [name, action] = [0, 1].map(|index| {
                condition["eq-action"][index]
                    .as_str()
                    .expect("eq-action")
                    .to_owned()
            });
            ObservationCondition::new(
                FactName::parse(&name).expect("fact"),
                ConditionTest::EqAction(FactName::parse(&action).expect("fact")),
            )
        })
        .collect();
    vec![
        ObservationRequirement::new(
            ObserverAnchorId::parse(crate::harness::ANCHOR).expect("anchor"),
            ObservationSchemaId::parse(requirement["schema"].as_str().expect("schema"))
                .expect("schema"),
            ObservationSubject::ActionFact(FactName::parse(subject).expect("subject")),
            u32::try_from(requirement["maximum_age_seconds"].as_u64().expect("age")).expect("age"),
            conditions,
        )
        .expect("requirement"),
    ]
}

/// The links a scenario's grant policy yields: one grant from the test root
/// to the agent, or none when the scenario grants no bounded policy.
fn scenario_links(setup: &Value) -> Vec<crate::bounds::BoundLink> {
    setup
        .get("grant_policy")
        .filter(|policy| !policy.is_null())
        .map(|policy| {
            vec![crate::bounds::BoundLink {
                subject: Signer::new(0x44).principal,
                policy: policy_from_members(policy),
            }]
        })
        .unwrap_or_default()
}

/// Runs one record `/3` scenario and checks every recorded count, stage,
/// and code.
async fn attempt_scenario(case: &Value, corpus: &Value, recipes: &Value, backend: Backend) {
    let id = case["id"].as_str().expect("id");
    let base = case["recipe"].as_str().expect("recipe");
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&recipes["bases"][base]["recipe"]).expect("recipe"),
        &serde_json::to_vec(&recipes["bases"][base]["lock"]).expect("lock"),
    )
    .expect("scenario recipe compiles");
    let mut setup = corpus["defaults"][base].clone();
    if setup.get("responses").is_none() {
        setup["responses"] = corpus["defaults"]["airtable-pre-entry"]["responses"].clone();
    }
    merge(&mut setup, &case["setup"]);
    let provider = TableProvider::new(
        &recipe,
        &setup["responses"],
        setup["write_transport"].as_str().unwrap_or("respond"),
    );
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let test_store = TestAttempts::open(backend);
    let recording = RecordingStore::new(test_store.raw());
    if setup["crash"] == "after-write-before-response" {
        recording.lose_response_record.store(true, Ordering::SeqCst);
    }
    let attempts = GatewayAttempts::new(recording.clone());
    let arguments = setup["arguments"].as_object().expect("arguments").clone();
    let command = admitted(
        &recipe,
        &arguments,
        ORIGINAL,
        grant_requirement(&setup),
        setup["validity_seconds"].as_u64().expect("validity"),
        scenario_links(&setup),
        NOW,
    );
    let mut io = TestIo::answering(&provider, command);
    io.recipe = Some(&recipe);
    if let Some(label) = setup["account_label"].as_str() {
        io.account = account_commitment(label);
    }
    if let Some(prefix) = setup["leased_secret_prefix"].as_str() {
        io.secret = format!("{prefix}not-a-real-credential").into_bytes();
    }
    if setup["gateway_clock_advance"]["after_step"] == 10 {
        io.deadline_advance = setup["gateway_clock_advance"]["seconds"]
            .as_u64()
            .expect("seconds");
    }
    let context = test_context(&observer);
    let observer_key = setup["observer_provisioned"]
        .as_bool()
        .unwrap_or(true)
        .then_some(&observer);
    let cx = SubmitContext {
        recipe: &recipe,
        attempts: &attempts,
        context: &context,
        observer: observer_key,
    };
    let first = submit::run(&cx, &io).await;
    let mut leases = io.leases();
    if setup["replay"] == "fresh-proof" {
        let replay_command = admitted(
            &recipe,
            &arguments,
            FRESH,
            grant_requirement(&setup),
            setup["validity_seconds"].as_u64().expect("validity"),
            scenario_links(&setup),
            NOW,
        );
        let mut replay_io = TestIo::answering(&provider, replay_command);
        replay_io.recipe = Some(&recipe);
        replay_io.account = io.account;
        let _ = submit::run(&cx, &replay_io).await;
        leases += replay_io.leases();
    }
    let label = format!("{}: {id}", backend.label());
    assert_eq!(
        recording.stages(),
        case["stages"]
            .as_array()
            .expect("stages")
            .iter()
            .map(|stage| stage.as_str().expect("stage").to_owned())
            .collect::<Vec<_>>(),
        "{label}"
    );
    let code = match &first {
        GatewaySubmitResult::NotEntered { code } => Some(code.as_str()),
        _ => None,
    };
    assert_eq!(code, case["code"].as_str(), "{label}: {first:?}");
    for (name, count) in [
        ("leases", leases),
        (
            "credential_reads",
            provider.credential_reads.load(Ordering::SeqCst),
        ),
        ("action_reads", provider.action_reads.load(Ordering::SeqCst)),
        ("provider_entries", provider.writes.load(Ordering::SeqCst)),
    ] {
        assert_eq!(
            u64::try_from(count).expect("count"),
            case[name].as_u64().expect("count"),
            "{label}: {name}"
        );
    }
    if case["stages"]
        .as_array()
        .is_some_and(|stages| !stages.is_empty())
    {
        let snapshot = attempts
            .read(
                io.verified.as_ref().expect("verified").request.namespace(),
                io.verified
                    .as_ref()
                    .expect("verified")
                    .request
                    .operation_id(),
            )
            .await
            .expect("read")
            .expect("stored");
        assert_eq!(snapshot.refusal(), case["code"].as_str(), "{label}");
        if let Some(basis) = case.get("basis").and_then(Value::as_u64) {
            assert_eq!(
                snapshot
                    .pre_entry()
                    .and_then(|pre_entry| pre_entry.basis)
                    .map(|basis| basis.value),
                Some(basis),
                "{label}"
            );
        }
        if let Some(count) = case.get("pre_entry_observations").and_then(Value::as_u64) {
            let observations = snapshot
                .pre_entry()
                .map_or(0, |pre_entry| pre_entry.observations.len());
            assert_eq!(
                u64::try_from(observations).expect("count"),
                count,
                "{label}"
            );
            let digest = snapshot
                .pre_entry()
                .and_then(crate::GatewayPreEntry::digest);
            assert_eq!(digest.is_some(), count > 0, "{label}");
        }
    }
    if let Some(requests) = case.get("requests") {
        assert_eq!(
            Value::Array(provider.requests.lock().expect("requests").clone()),
            *requests,
            "{label}"
        );
    }
}

async fn attempt_scenarios(backend: Backend) {
    let corpus = corpus(SCENARIOS);
    assert_eq!(corpus["schema"], "auths.gateway-attempt-scenarios/3");
    assert_eq!(corpus["attempt_schema"], "auths.gateway-attempt/3");
    let recipes = self::corpus(corpus["recipes"].as_str().expect("recipes"));
    let mut ran = 0;
    for case in corpus["cases"].as_array().expect("cases") {
        attempt_scenario(case, &corpus, &recipes, backend).await;
        ran += 1;
    }
    assert_eq!(ran, 27);
}

/// Runs scenario `id` with the per-proof observer check failing, and returns
/// the result and the leases taken.
async fn with_observer_overlap(id: &str) -> (GatewaySubmitResult, usize) {
    let corpus = corpus(SCENARIOS);
    let recipes = self::corpus(corpus["recipes"].as_str().expect("recipes"));
    let case = corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == id)
        .expect("named case");
    let base = case["recipe"].as_str().expect("recipe");
    let recipe = CompiledRecipe::compile(
        &serde_json::to_vec(&recipes["bases"][base]["recipe"]).expect("recipe"),
        &serde_json::to_vec(&recipes["bases"][base]["lock"]).expect("lock"),
    )
    .expect("scenario recipe compiles");
    let mut setup = corpus["defaults"][base].clone();
    if setup.get("responses").is_none() {
        setup["responses"] = corpus["defaults"]["airtable-pre-entry"]["responses"].clone();
    }
    merge(&mut setup, &case["setup"]);
    let provider = TableProvider::new(&recipe, &setup["responses"], "respond");
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let store = TestAttempts::open(Backend::File);
    let arguments = setup["arguments"].as_object().expect("arguments").clone();
    let command = admitted(
        &recipe,
        &arguments,
        ORIGINAL,
        grant_requirement(&setup),
        setup["validity_seconds"].as_u64().expect("validity"),
        scenario_links(&setup),
        NOW,
    )
    .map(|mut command| {
        command.observer_refusal = Some("gateway.trust.observer-key-in-authority-chain");
        command
    });
    let mut io = TestIo::answering(&provider, command);
    io.recipe = Some(&recipe);
    let context = test_context(&observer);
    let cx = SubmitContext {
        recipe: &recipe,
        attempts: store.attempts(),
        context: &context,
        observer: Some(&observer),
    };
    let result = submit::run(&cx, &io).await;
    (result, io.leases())
}

/// Admission reports the first failing check in the documented order: the
/// retention rule and pre-entry selection before the per-proof observer
/// check. A submission that fails only the observer check reports it, and
/// none takes a lease.
#[tokio::test]
async fn admission_reports_retention_and_pre_entry_before_the_observer_check() {
    for (id, code) in [
        (
            "idempotency-window-exceeds-retention",
            "gateway.idempotency.window-exceeds-retention",
        ),
        (
            "pre-entry-requirement-missing",
            "gateway.pre-entry.requirement-missing",
        ),
        (
            "idempotency-window-at-retention",
            "gateway.trust.observer-key-in-authority-chain",
        ),
    ] {
        let (result, leases) = with_observer_overlap(id).await;
        assert_eq!(result, crate::engine::not_entered(code), "{id}");
        assert_eq!(leases, 0, "{id}");
    }
}

#[tokio::test]
async fn attempt_scenarios_v3_drive_the_counting_provider() {
    attempt_scenarios(Backend::File).await;
}

/// Stage assertions consume actual submission-driver, store and provider
/// witnesses, rather than observations copied from a corpus's expectations.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the measured stage sequence reads top to bottom"
)]
async fn qualification_stages_use_gateway_replay_and_recovery_witnesses() {
    use auths_recipe_qualification::{
        BoundedText, CapabilityKind, QualificationTuple, Scenario, Sha256Digest,
    };
    use auths_recipe_qualification_issuance::execution::{
        ExpectedObservation, Operation, RunCase, RunObservation, RunOutcome, RunPhase, RunStep,
        RunVerdict,
    };
    for scenario in [
        Scenario::ProofReplay,
        Scenario::FreshChallengeReplay,
        Scenario::ResponseLoss,
    ] {
        let mut record = Record::open("airtable", Backend::File);
        let recovering = scenario == Scenario::ResponseLoss;
        let delivery = if recovering {
            Delivery::TimeoutAfterApplying
        } else {
            Delivery::Respond
        };
        let provider = RecordProvider::new(delivery, Reading::Faithful);
        let original = record.airtable(ORIGINAL, "Approved");
        let tuple: QualificationTuple = serde_json::from_value(json!({
            "recipe_family": "reference-record-update-v1",
            "compiled_recipe_sha256": hex::encode(record.recipe.digest()),
            "profile_lock_sha256": "22".repeat(32), "provider_contract_id": "33".repeat(32),
            "gateway_semantic_closure_sha256": crate::GATEWAY_SEMANTIC_CLOSURE_SHA256,
            "target": {"os": "linux", "arch": "x86_64", "gateway_package": "auths-gateway",
                "gateway_version": "1.0.0-rc.1", "gateway_build_sha256": "55".repeat(32),
                "store_kind": "shared-file-v1", "store_schema": "auths.gateway-attempt/3",
                "credential_store_kind": "local-file-v1"}
        }))
        .expect("tuple");
        let expected_read_back = serde_json::to_vec(&json!({"id": RECORD,
            "fields": {"DemoStatus": "Approved", "auths_echo": original_token()}}))
        .expect("read-back");
        let evidence = Sha256Digest::from_bytes(Sha256::digest(expected_read_back).into());
        let expected = |outcome, code, leases, entries, confirmed| ExpectedObservation {
            verdict: RunVerdict {
                outcome,
                code: BoundedText::parse(code).expect("code"),
                request_sha256: None,
                evidence_sha256: (confirmed > 0).then_some(evidence),
            },
            credential_leases: leases,
            provider_entries: entries,
            confirmed_by_read_back: confirmed,
        };
        let steps = if recovering {
            vec![
                RunStep {
                    operation: Operation::DropResponse,
                    expected: expected(RunOutcome::Unknown, "unknown", 1, 1, 0),
                },
                RunStep {
                    operation: Operation::ReadBack,
                    expected: expected(RunOutcome::Observed, "observed-by-provider", 1, 0, 1),
                },
            ]
        } else {
            vec![
                RunStep {
                    operation: Operation::Submit,
                    expected: expected(RunOutcome::Observed, "observed-by-provider", 2, 1, 1),
                },
                RunStep {
                    operation: Operation::Replay,
                    expected: expected(RunOutcome::Refused, "gateway.attempt.replay", 0, 0, 0),
                },
            ]
        };
        let mut observations = Vec::new();
        for index in 0..2 {
            if recovering && index == 1 {
                record.store.restart();
            }
            let command = if index == 0 || scenario == Scenario::ProofReplay {
                original.clone()
            } else {
                record.airtable(FRESH, "Approved")
            };
            let io = TestIo::new(&provider, command);
            let writes_before = provider.writes();
            let result = run(
                record.store.attempts(),
                &record.recipe,
                &record.observer,
                &io,
            )
            .await;
            let (outcome, code, evidence_sha256, confirmed) = match result {
                GatewaySubmitResult::ObservedByProvider { evidence, .. } => (
                    RunOutcome::Observed,
                    "observed-by-provider".to_owned(),
                    Some(Sha256Digest::try_from(evidence.evidence_digest).expect("evidence")),
                    1,
                ),
                GatewaySubmitResult::Unknown => {
                    (RunOutcome::Unknown, "unknown".to_owned(), None, 0)
                }
                GatewaySubmitResult::NotEntered { code } => (RunOutcome::Refused, code, None, 0),
                other => panic!("unexpected result: {other:?}"),
            };
            observations.push(RunObservation {
                tuple_sha256: tuple.digest().expect("tuple digest"),
                observed: ExpectedObservation {
                    verdict: RunVerdict {
                        outcome,
                        code: BoundedText::parse(code).expect("code"),
                        request_sha256: None,
                        evidence_sha256,
                    },
                    credential_leases: u32::try_from(io.leases()).expect("leases"),
                    provider_entries: u32::try_from(provider.writes() - writes_before)
                        .expect("entries"),
                    confirmed_by_read_back: confirmed,
                },
                unauthorized_provider_entries: 0,
                secret_exposed: false,
                repository_imported: false,
                provider_token_received: false,
            });
        }
        let case = RunCase {
            id: BoundedText::parse("measured-gateway-case").expect("id"),
            scenario,
            phase: if recovering {
                RunPhase::Live
            } else {
                RunPhase::Offline
            },
            capabilities: if recovering {
                vec![CapabilityKind::Recovery]
            } else {
                Vec::new()
            },
            steps,
        };
        assert_eq!(
            observations
                .iter()
                .map(|actual| &actual.observed)
                .collect::<Vec<_>>(),
            case.steps
                .iter()
                .map(|step| &step.expected)
                .collect::<Vec<_>>(),
            "{scenario:?}: independently measured counters and verdicts"
        );
        let (_, effects) = case
            .execute(&tuple, |index, _| Ok(observations[index].clone()))
            .expect("measured stage");
        assert_eq!((effects.entered, effects.confirmed_by_read_back), (1, 1));
        observations[1].observed.provider_entries += 1;
        assert!(
            case.execute(&tuple, |index, _| Ok(observations[index].clone()))
                .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_attempt_scenarios_v3_drive_the_counting_provider() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    attempt_scenarios(Backend::Postgres).await;
}

// ---------------------------------------------------------------------------
// One shared conformance suite for every store. The file store runs it on
// every test run; the PostgreSQL store runs it against the TLS fixture in
// the PostgreSQL lifecycle workflow.

/// A logical operation enters the provider exactly once; an identical
/// replay neither writes nor records.
async fn conformance_claim_exactly_once_and_replay(backend: Backend) {
    let record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let original = record.airtable(ORIGINAL, "Approved");
    assert!(matches!(
        record.submit(&original, &provider).await,
        GatewaySubmitResult::ObservedByProvider { .. }
    ));
    for _ in 0..3 {
        assert_eq!(record.submit(&original, &provider).await, replay_refused());
    }
    assert!(matches!(
        record
            .store
            .attempts()
            .claim(&original.request, *record.recipe.digest(), NOW)
            .await,
        Err(GatewayAttemptError::Replay)
    ));
    assert_eq!((provider.writes(), provider.reads()), (1, 1));
}

/// A fresh challenge, or a changed action, under the same logical ID is
/// the same operation and never a second entry.
async fn conformance_fresh_challenge(backend: Backend) {
    let record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let first = record
        .submit(&record.airtable(ORIGINAL, "Approved"), &provider)
        .await;
    assert!(matches!(
        first,
        GatewaySubmitResult::ObservedByProvider { .. }
    ));
    for command in [
        record.airtable(ORIGINAL, "Approved"),
        record.airtable(FRESH, "Approved"),
        record.airtable(FRESH, "Pending"),
    ] {
        assert_eq!(record.submit(&command, &provider).await, replay_refused());
    }
    assert_eq!((provider.writes(), provider.reads()), (1, 1));
}

/// An unknown write is resolved only by a later read-only observation on
/// another store instance, against the original echo token.
async fn conformance_unknown_and_reobserve(backend: Backend) {
    let mut record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::TimeoutAfterApplying, Reading::Faithful);
    let original = record.airtable(ORIGINAL, "Approved");
    assert_eq!(
        record.submit(&original, &provider).await,
        GatewaySubmitResult::Unknown
    );
    assert_eq!(
        provider.reads(),
        0,
        "an unknown write is not read back in-line"
    );
    record.store.restart();
    let fresh = record.airtable(FRESH, "Approved");
    let GatewaySubmitResult::ObservedByProvider { status, evidence } =
        record.submit(&fresh, &provider).await
    else {
        panic!("expected observed-by-provider");
    };
    assert_eq!(status, None);
    assert_eq!(evidence.echo, original_token());
    assert_ne!(Some(evidence.echo.as_str()), fresh.request.echo_token());
    assert_eq!(
        record.submit(&fresh, &provider).await,
        replay_refused(),
        "terminal stage is not re-read"
    );
    assert_eq!((provider.writes(), provider.reads()), (1, 1));
}

/// A foreign echo token is recorded as `echo-mismatch`, never as the
/// attempt's own evidence.
async fn conformance_echo_mismatch(backend: Backend) {
    let record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::Respond, Reading::ForeignEcho);
    let command = record.airtable(ORIGINAL, "Approved");
    assert_eq!(
        record.submit(&command, &provider).await,
        GatewaySubmitResult::Observed {
            status: 200,
            matched: false
        }
    );
    let snapshot = record.snapshot(&command).await;
    assert_eq!(snapshot.stage(), GatewayAttemptStage::Observed);
    assert_eq!(
        snapshot.observation_fact(),
        Some(GatewayObservationFact::EchoMismatch)
    );
    assert!(snapshot.provider_evidence().is_none());
    assert_eq!(provider.writes(), 1);
}

/// Two store instances re-observing the same unknown attempt record
/// exactly one terminal stage; the other records nothing.
async fn conformance_concurrent_reobservation(backend: Backend) {
    let record = Record::open("airtable", backend);
    let provider = RecordProvider::new(Delivery::TimeoutAfterApplying, Reading::Faithful);
    let original = record.airtable(ORIGINAL, "Approved");
    assert_eq!(
        record.submit(&original, &provider).await,
        GatewaySubmitResult::Unknown
    );
    let first = record.store.reopen();
    let second = record.store.reopen();
    let fresh = record.airtable(FRESH, "Approved");
    let (left, right) = tokio::join!(
        record.submit_on(&first, &fresh, &provider),
        record.submit_on(&second, &fresh, &provider)
    );
    let terminal = [&left, &right]
        .iter()
        .filter(|result| matches!(result, GatewaySubmitResult::ObservedByProvider { .. }))
        .count();
    assert_eq!(terminal, 1, "{left:?} {right:?}");
    assert!(left == replay_refused() || right == replay_refused());
    assert_eq!(
        record.snapshot(&original).await.stage(),
        GatewayAttemptStage::ObservedByProvider
    );
    assert_eq!(provider.writes(), 1);
}

fn attempt_entry(key: GatewayAttemptKey, record: &[u8]) -> GatewayRecordEntry {
    GatewayRecordEntry {
        kind: GatewayRecordKind::Attempt,
        key,
        record: record.to_vec(),
        expires_at: None,
    }
}

/// Replacement is compare-and-swap on the exact stored bytes, and stored
/// bytes that do not decode, including a retired record `/2`, fail closed
/// rather than read as unclaimed.
async fn conformance_mechanism_fails_closed(backend: Backend) {
    let record = Record::open("airtable", backend);
    let raw = record.store.raw();
    let key = GatewayAttemptKey::for_operation(
        record.recipe.namespace(),
        &LogicalOperationId::parse("run-1").expect("operation"),
    );
    let obsolete = serde_json::to_vec(&json!({
        "schema": "auths.gateway-attempt/2", "namespace": "airtable-demo",
        "operation_id": "run-1", "action_commitment": "11".repeat(32),
        "recipe_digest": record.recipe.digest_hex(), "nonce": "00".repeat(16),
        "stage": "unknown", "response_status": null, "response_digest": null,
        "observation_match": null, "observation_plan": null, "observation_fact": null,
        "provider_evidence": null
    }))
    .expect("record");
    tokio::task::spawn_blocking(move || {
        raw.insert(&attempt_entry(key, b"{}")).expect("insert");
        assert_eq!(
            raw.insert(&attempt_entry(key, b"{}")),
            Err(GatewayAttemptError::Replay)
        );
        assert_eq!(
            raw.replace(GatewayRecordKind::Attempt, &key, b"{\"other\":1}", b"[]"),
            Err(GatewayAttemptError::Conflict)
        );
        raw.replace(GatewayRecordKind::Attempt, &key, b"{}", &obsolete)
            .expect("exact replacement");
        assert_eq!(
            raw.load(GatewayRecordKind::Attempt, &key)
                .expect("load")
                .as_deref(),
            Some(obsolete.as_slice())
        );
    })
    .await
    .expect("mechanism checks");
    let command = record.airtable(ORIGINAL, "Approved");
    assert_eq!(
        record
            .store
            .attempts()
            .read(command.request.namespace(), command.request.operation_id())
            .await,
        Err(GatewayAttemptError::Corrupt),
        "a record /2 is corrupt, not read"
    );
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    assert_eq!(record.submit(&command, &provider).await, replay_refused());
    assert_eq!((provider.writes(), provider.reads()), (0, 0));
}

fn slot_entry(
    kind: GatewayRecordKind,
    key: [u8; 32],
    tag: &[u8],
    expires_at: u64,
) -> GatewayRecordEntry {
    GatewayRecordEntry {
        kind,
        key: GatewayAttemptKey::from_bytes(key),
        record: tag.to_vec(),
        expires_at: Some(expires_at),
    }
}

fn test_key(domain: &str, index: usize, process: Option<usize>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update(index.to_be_bytes());
    if let Some(process) = process {
        hash.update(process.to_be_bytes());
    }
    hash.finalize().into()
}

/// One process's batch for operation `index`: its own claim, and a count and
/// a sum slot every process contends for.
fn contended_batch(index: usize, process: usize) -> Vec<GatewayRecordEntry> {
    let tag = format!("process-{process}").into_bytes();
    vec![
        attempt_entry(
            GatewayAttemptKey::from_bytes(test_key("claim", index, Some(process))),
            &tag,
        ),
        slot_entry(
            GatewayRecordKind::CountSlot,
            test_key("count", index, None),
            &tag,
            NOW,
        ),
        slot_entry(
            GatewayRecordKind::SumSlot,
            test_key("sum", index, None),
            &tag,
            NOW,
        ),
    ]
}

const RACE_OPERATIONS: usize = 48;
const CHILD: &str = "AUTHS_GATEWAY_CONFORMANCE_CHILD";

fn spawn_children(mode: &str, store: &TestAttempts, backend: Backend) -> Vec<String> {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        + 1_500;
    let children: Vec<_> = (0..2)
        .map(|process| {
            std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "scenario_tests::conformance_child_process",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(
                    CHILD,
                    format!(
                        "{mode}|{}|{process}|{start}|{}",
                        backend.label(),
                        store.location()
                    ),
                )
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("child gateway process")
        })
        .collect();
    children
        .into_iter()
        .map(|child| {
            let output = child.wait_with_output().expect("child exit");
            assert!(output.status.success(), "child failed");
            let text = String::from_utf8(output.stdout).expect("utf-8");
            text.lines()
                .find_map(|line| {
                    line.split_once("RACE ")
                        .map(|(_, counts)| counts.to_owned())
                })
                .expect("child result")
        })
        .collect()
}

/// Two separate gateway processes race to submit the same logical
/// operations; each operation enters the provider exactly once.
async fn conformance_concurrent_claims_from_two_processes(backend: Backend) {
    let record = Record::open("airtable", backend);
    let mut claimed = 0;
    let mut entries = 0;
    for line in spawn_children("submit", &record.store, backend) {
        let fields: Vec<usize> = line
            .split(' ')
            .map(|value| value.parse().expect("count"))
            .collect();
        claimed += fields[0];
        entries += fields[1];
    }
    assert_eq!(claimed, RACE_OPERATIONS, "{}", backend.label());
    assert_eq!(entries, RACE_OPERATIONS, "{}", backend.label());
    for index in 0..RACE_OPERATIONS {
        let stage = record.snapshot(&race_command(&record, index)).await.stage();
        assert!(
            matches!(
                stage,
                GatewayAttemptStage::ResponseRecorded
                    | GatewayAttemptStage::Observed
                    | GatewayAttemptStage::ObservedByProvider
            ),
            "{stage:?}"
        );
    }
}

/// Two processes race to insert batches that contend for the same slots:
/// exactly one batch per operation wins, and the loser leaves no record.
async fn conformance_batches_from_two_processes(backend: Backend) {
    let store = TestAttempts::open(backend);
    let mut won = 0;
    for line in spawn_children("batch", &store, backend) {
        won += line.parse::<usize>().expect("count");
    }
    assert_eq!(won, RACE_OPERATIONS, "{}", backend.label());
    let raw = store.raw();
    tokio::task::spawn_blocking(move || {
        for index in 0..RACE_OPERATIONS {
            let count = raw
                .load(
                    GatewayRecordKind::CountSlot,
                    &GatewayAttemptKey::from_bytes(test_key("count", index, None)),
                )
                .expect("load")
                .expect("count slot");
            let sum = raw
                .load(
                    GatewayRecordKind::SumSlot,
                    &GatewayAttemptKey::from_bytes(test_key("sum", index, None)),
                )
                .expect("load")
                .expect("sum slot");
            assert_eq!(count, sum, "one batch owns both slots");
            let claims: Vec<bool> = (0..2)
                .map(|process| {
                    raw.load(
                        GatewayRecordKind::Attempt,
                        &GatewayAttemptKey::from_bytes(test_key("claim", index, Some(process))),
                    )
                    .expect("load")
                    .is_some_and(|claim| claim == count)
                })
                .collect();
            assert_eq!(
                claims.iter().filter(|present| **present).count(),
                1,
                "exactly the winner's claim exists"
            );
            for process in 0..2 {
                let claim = raw
                    .load(
                        GatewayRecordKind::Attempt,
                        &GatewayAttemptKey::from_bytes(test_key("claim", index, Some(process))),
                    )
                    .expect("load");
                assert!(claim.is_none() || claim.as_deref() == Some(count.as_slice()));
            }
        }
    })
    .await
    .expect("batch checks");
}

fn race_command(record: &Record, index: usize) -> VerifiedCommand {
    record.command(
        ORIGINAL,
        &json!({"operation_id": format!("race-{index}"), "record_id": RECORD, "replacement": "Approved"}),
    )
}

/// Child half of the two-process races. It does nothing unless spawned by
/// the parent with the store location.
#[tokio::test]
#[ignore = "spawned by the two-process conformance cases"]
async fn conformance_child_process() {
    let Ok(spec) = std::env::var(CHILD) else {
        return;
    };
    let parts: Vec<&str> = spec.splitn(5, '|').collect();
    let (mode, backend, process) = (
        parts[0],
        Backend::parse(parts[1]),
        parts[2].parse::<usize>().expect("process"),
    );
    let start: u128 = parts[3].parse().expect("start");
    let store = TestAttempts::attach(backend, parts[4]);
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        < start
    {
        std::thread::yield_now();
    }
    if mode == "batch" {
        let raw = store.raw();
        let won = tokio::task::spawn_blocking(move || {
            (0..RACE_OPERATIONS)
                .filter(|index| {
                    raw.insert_all(&contended_batch(*index, process))
                        .expect("batch")
                        == GatewayInsert::Inserted
                })
                .count()
        })
        .await
        .expect("batches");
        println!("RACE {won}");
        return;
    }
    let record = Record {
        recipe: fixture_recipe("airtable"),
        store,
        observer: GatewayObserver::from_test_seed(OBSERVER_SEED),
    };
    let provider = RecordProvider::new(Delivery::Respond, Reading::Faithful);
    let mut claimed = 0;
    for index in 0..RACE_OPERATIONS {
        // Only a claim writes. A replay may re-observe the other process's
        // attempt through this process's own provider double, which never
        // saw that write, and a claim may then lose its compare-and-swap and
        // report `unknown`; neither ever writes again.
        let before = provider.writes();
        let _ = record
            .submit(&race_command(&record, index), &provider)
            .await;
        if provider.writes() > before {
            claimed += 1;
        }
    }
    println!("RACE {claimed} {}", provider.writes());
}

/// A sweep deletes only expired count and sum slots, at most `limit` a
/// call, and never an attempt or connection record.
async fn conformance_sweep_bounds(backend: Backend) {
    let store = TestAttempts::open(backend);
    let raw = store.raw();
    tokio::task::spawn_blocking(move || {
        for index in 0..5 {
            raw.insert(&slot_entry(
                GatewayRecordKind::CountSlot,
                test_key("sweep-count", index, None),
                b"slot",
                100,
            ))
            .expect("count slot");
        }
        for index in 0..2 {
            raw.insert(&slot_entry(
                GatewayRecordKind::SumSlot,
                test_key("sweep-sum", index, None),
                b"slot",
                200,
            ))
            .expect("sum slot");
        }
        let attempt = GatewayAttemptKey::from_bytes(test_key("sweep-attempt", 0, None));
        raw.insert(&attempt_entry(attempt, b"claim"))
            .expect("claim");
        let connection = GatewayRecordEntry {
            kind: GatewayRecordKind::Connection,
            key: GatewayAttemptKey::from_bytes(test_key("sweep-connection", 0, None)),
            record: b"record".to_vec(),
            expires_at: None,
        };
        raw.insert(&connection).expect("connection");
        assert_eq!(raw.sweep_expired(99, 10), Ok(0), "nothing expired yet");
        assert_eq!(raw.sweep_expired(150, 3), Ok(3), "at most the limit");
        assert_eq!(raw.sweep_expired(150, 10), Ok(2));
        assert_eq!(raw.sweep_expired(150, 10), Ok(0));
        assert_eq!(raw.sweep_expired(200, 10), Ok(2), "expiry is inclusive");
        assert_eq!(raw.sweep_expired(u64::MAX >> 1, 10), Ok(0));
        assert!(
            raw.load(GatewayRecordKind::Attempt, &attempt)
                .expect("load")
                .is_some()
        );
        assert!(
            raw.load(GatewayRecordKind::Connection, &connection.key)
                .expect("load")
                .is_some()
        );
        assert_eq!(
            raw.replace(
                GatewayRecordKind::CountSlot,
                &GatewayAttemptKey::from_bytes(test_key("sweep-count", 0, None)),
                b"slot",
                b"other"
            ),
            Err(GatewayAttemptError::InvalidTransition),
            "slots are insert-only"
        );
    })
    .await
    .expect("sweep checks");
}

/// A connection record committed through one store instance is what every
/// other instance sharing the store reads next, and a stale compare-and-swap
/// through another instance is a conflict.
async fn conformance_shared_connection_record(backend: Backend) {
    let store = TestAttempts::open(backend);
    let (first, second) = (store.raw(), store.raw());
    tokio::task::spawn_blocking(move || {
        let key = GatewayAttemptKey::from_bytes(test_key("connection", 0, None));
        first
            .insert(&GatewayRecordEntry {
                kind: GatewayRecordKind::Connection,
                key,
                record: b"generation-1".to_vec(),
                expires_at: None,
            })
            .expect("insert");
        assert_eq!(
            second
                .load(GatewayRecordKind::Connection, &key)
                .expect("load")
                .as_deref(),
            Some(&b"generation-1"[..])
        );
        second
            .replace(
                GatewayRecordKind::Connection,
                &key,
                b"generation-1",
                b"generation-2",
            )
            .expect("replace");
        assert_eq!(
            first
                .load(GatewayRecordKind::Connection, &key)
                .expect("load")
                .as_deref(),
            Some(&b"generation-2"[..])
        );
        assert_eq!(
            first.replace(
                GatewayRecordKind::Connection,
                &key,
                b"generation-1",
                b"generation-3"
            ),
            Err(GatewayAttemptError::Conflict)
        );
        assert!(
            !matches!(first.load(GatewayRecordKind::Attempt, &key), Ok(Some(_))),
            "a key is read only as its own kind"
        );
    })
    .await
    .expect("connection checks");
}

async fn store_conformance(backend: Backend) {
    conformance_claim_exactly_once_and_replay(backend).await;
    conformance_fresh_challenge(backend).await;
    conformance_unknown_and_reobserve(backend).await;
    conformance_echo_mismatch(backend).await;
    conformance_concurrent_reobservation(backend).await;
    conformance_mechanism_fails_closed(backend).await;
    conformance_concurrent_claims_from_two_processes(backend).await;
    conformance_batches_from_two_processes(backend).await;
    conformance_sweep_bounds(backend).await;
    conformance_shared_connection_record(backend).await;
}

#[tokio::test]
async fn file_store_passes_attempt_store_conformance() {
    store_conformance(Backend::File).await;
}

#[tokio::test]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_store_passes_attempt_store_conformance() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    store_conformance(Backend::Postgres).await;
}

/// A batch interrupted at any step leaves nothing once the store is opened
/// again, and the same batch then inserts.
#[test]
fn a_file_batch_crashed_at_any_step_is_rolled_back() {
    let entries = contended_batch(0, 0);
    let mut crashes = vec![BatchCrash::AfterBatchFile, BatchCrash::BeforeBatchDelete];
    crashes.extend((0..entries.len()).map(BatchCrash::AfterTargets));
    for crash in crashes {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = std::fs::canonicalize(temp.path())
            .expect("canonical")
            .join("store");
        let store = FileGatewayAttemptStore::open(&root).expect("store");
        store
            .insert_all_until(&entries, crash)
            .expect("partial batch");
        assert!(root.join(".batch.json").exists(), "{crash:?}");
        let reopened = FileGatewayAttemptStore::open(&root).expect("recovering open");
        assert!(!root.join(".batch.json").exists(), "{crash:?}");
        for entry in &entries {
            assert_eq!(
                reopened.load(entry.kind, &entry.key).expect("load"),
                None,
                "{crash:?}: rolled back"
            );
        }
        assert_eq!(
            reopened.insert_all(&entries).expect("batch"),
            GatewayInsert::Inserted
        );
        assert_eq!(
            store.load(entries[0].kind, &entries[0].key).expect("load"),
            Some(entries[0].record.clone())
        );
    }
    // A load through the crashed instance recovers too, under the lock.
    let temp = tempfile::tempdir().expect("temp directory");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical")
        .join("store");
    let store = FileGatewayAttemptStore::open(&root).expect("store");
    store
        .insert_all_until(&entries, BatchCrash::AfterTargets(2))
        .expect("partial batch");
    assert_eq!(
        store.load(entries[0].kind, &entries[0].key).expect("load"),
        None
    );
    assert!(!root.join(".batch.json").exists());
    assert_eq!(
        store.insert_all(&entries).expect("batch"),
        GatewayInsert::Inserted
    );
    assert_eq!(
        store.insert_all(&entries).expect("batch"),
        GatewayInsert::Exists { index: 0 }
    );
}
