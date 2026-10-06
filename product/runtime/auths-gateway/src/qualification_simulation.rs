//! Executable, explicitly synthetic provider qualification rehearsals.
//! The independent request oracles below do not read the compiled recipe.
//! Submission enters at the verified-command boundary; native proof/socket
//! journeys are exercised separately by the installed SDK workflows.

use super::*;
use serde::Serialize;

const STRIPE_VERSION: &str = "2025-03-31.basil";
const STRIPE_ACCOUNT: &str = "acct_TESTACCOUNT01";
const STRIPE_PAYMENT: &str = "pi_TEST0000000001";

fn stripe_setup() -> Value {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/attempt-scenarios-v3.json"
    ))
    .expect("embedded Stripe fixture");
    corpus["defaults"]["stripe"].clone()
}

#[derive(Clone, Copy)]
enum Family {
    Stripe,
    Airtable,
}

impl Family {
    fn command(
        self,
        recipe: &CompiledRecipe,
        args: &Map<String, Value>,
        commitment: [u8; 32],
    ) -> VerifiedCommand {
        self.admission(recipe, args, commitment).expect("admission")
    }

    fn admission(
        self,
        recipe: &CompiledRecipe,
        args: &Map<String, Value>,
        commitment: [u8; 32],
    ) -> Result<VerifiedCommand, GatewaySubmitResult> {
        let links = match self {
            Self::Stripe => scenario_links(&stripe_setup()),
            Self::Airtable => Vec::new(),
        };
        admitted(recipe, args, commitment, Vec::new(), 3_600, links, NOW)
    }
    fn name(self) -> &'static str {
        match self {
            Self::Stripe => "stripe-refund-v1",
            Self::Airtable => "airtable-record-update-v1",
        }
    }

    fn recipe(self) -> CompiledRecipe {
        match self {
            Self::Stripe => CompiledRecipe::compile(
                include_bytes!("../../../../examples/stripe-refund-approval/recipe.json"),
                include_bytes!("../../../../examples/stripe-refund-approval/profile.lock.json"),
            )
            .expect("Stripe recipe"),
            Self::Airtable => fixture_recipe("airtable"),
        }
    }

    fn arguments(self, operation: &str) -> Map<String, Value> {
        match self {
            Self::Stripe => json!({"operation_id": operation, "payment_intent": STRIPE_PAYMENT,
                "amount": 500, "currency": "usd", "connect_account": STRIPE_ACCOUNT}),
            Self::Airtable => json!({"operation_id": operation, "record_id": RECORD,
                "replacement": "Approved"}),
        }
        .as_object()
        .expect("arguments")
        .clone()
    }

    /// Contract-owned wire oracle. Only admitted shared echo/idempotency
    /// primitives are reused; mapping, encoding and resource IDs are fixed
    /// by this independent vertical, never projected from candidate bytes.
    fn oracle(self, operation: &str, commitment: &[u8; 32]) -> Value {
        let namespace = crate::OperatorNamespace::parse(match self {
            Self::Stripe => "stripe-refunds",
            Self::Airtable => "airtable-demo",
        })
        .expect("namespace");
        let operation = LogicalOperationId::parse(operation).expect("operation");
        let echo = echo_token(&namespace, &operation, commitment);
        match self {
            Self::Stripe => {
                let mut form = url::form_urlencoded::Serializer::new(String::new());
                form.append_pair("amount", "500");
                form.append_pair("metadata[auths_echo]", &echo);
                form.append_pair("payment_intent", STRIPE_PAYMENT);
                json!({"method": "POST", "url": "https://api.stripe.com/v1/refunds",
                    "content_type": "application/x-www-form-urlencoded", "body": form.finish(),
                    "headers": [["Stripe-Version", STRIPE_VERSION], ["Stripe-Account", STRIPE_ACCOUNT],
                        ["Idempotency-Key", crate::idempotency_key(&namespace, &operation)]],
                    "idempotency_key": crate::idempotency_key(&namespace, &operation)})
            }
            Self::Airtable => json!({"method": "PATCH",
                "url": format!("https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/{RECORD}"),
                "content_type": "application/json",
                "body": serde_json_canonicalizer::to_string(&json!({"fields": {
                    "DemoStatus": "Approved", "auths_echo": echo}})).expect("oracle JSON"),
                "headers": [], "idempotency_key": null}),
        }
    }
}

fn request_facts(request: &ClosedProviderRequest) -> Value {
    json!({"method": request.method().as_str(), "url": request.url(),
        "content_type": request.content_type(), "body": std::str::from_utf8(request.body()).expect("body"),
        "headers": request.headers().iter().map(|header| (header.name(), header.value())).collect::<Vec<_>>(),
        "idempotency_key": request.idempotency_key()})
}

/// The oracle checks the actual outbound request before the mutable provider
/// double applies it. Counting witnesses come from actual driver calls.
struct OracleProvider<P> {
    inner: P,
    expected: Value,
    checked: AtomicUsize,
}

trait SimulationProvider: ProviderPort {
    fn entries(&self) -> usize;
}

impl SimulationProvider for TableProvider {
    fn entries(&self) -> usize {
        self.writes()
    }
}

impl SimulationProvider for RecordProvider {
    fn entries(&self) -> usize {
        self.writes()
    }
}

impl<P: ProviderPort> ProviderPort for OracleProvider<P> {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        assert_eq!(
            request_facts(request),
            self.expected,
            "independent wire oracle"
        );
        self.checked.fetch_add(1, Ordering::SeqCst);
        self.inner.write(request).await
    }

    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum: usize,
    ) -> Option<ProviderResponse> {
        self.inner.action_read(url, headers, maximum).await
    }

    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        self.inner.credential_read(read).await
    }
}

#[derive(Serialize)]
struct Measurement {
    case: String,
    verdict: String,
    credential_leases: usize,
    provider_entries: usize,
    confirmed_by_read_back: usize,
}

fn measurement(
    case: &str,
    result: &GatewaySubmitResult,
    leases: usize,
    entries: usize,
) -> Measurement {
    let verdict = match result {
        GatewaySubmitResult::ObservedByProvider { .. } => "observed-by-provider".to_owned(),
        GatewaySubmitResult::ResponseRecorded { .. } => "response-recorded".to_owned(),
        GatewaySubmitResult::Unknown => "unknown".to_owned(),
        GatewaySubmitResult::NotEntered { code } => code.clone(),
        other => panic!("unexpected simulation result: {other:?}"),
    };
    Measurement {
        case: case.to_owned(),
        verdict,
        credential_leases: leases,
        provider_entries: entries,
        confirmed_by_read_back: usize::from(matches!(
            result,
            GatewaySubmitResult::ObservedByProvider { .. }
        )),
    }
}

fn publish(family: Family, recipe: &CompiledRecipe, cases: &[Measurement]) {
    let report = json!({"schema": "auths.recipe-qualification-simulation/1",
        "simulation": true, "family": family.name(), "stable_launch_ready": false,
        "compiled_recipe_sha256": recipe.digest_hex(),
        "gateway_semantic_closure_sha256": crate::GATEWAY_SEMANTIC_CLOSURE_SHA256,
        "store": "shared-file-v1", "custody": "test-only-counting-lease",
        "clock": {"kind": "fixed-test-clock", "unix_seconds": NOW},
        "verification_boundary": "native-verified-command projection",
        "provider": "in-process mutable double", "cases": cases,
        "excluded_claims": ["live provider acceptance", "production qualification",
            "production PostgreSQL/custody", "independent human onboarding"]});
    if let Some(directory) = std::env::var_os("AUTHS_QUALIFICATION_SIMULATION_OUTPUT") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).expect("report directory");
        std::fs::write(
            directory.join(format!("{}.json", family.name())),
            serde_json::to_vec_pretty(&report).expect("report"),
        )
        .expect("write report");
    }
}

/// Runs each lifecycle against real durable claims, with both original and
/// fresh proof commitments. A lost response or response-record crash must
/// use only recovery the recipe's derived capability permits: Airtable's
/// verified locator and echo can re-observe; Stripe needs its response locator.
async fn lifecycle<P: SimulationProvider>(
    family: Family,
    provider: &OracleProvider<P>,
    recording: &Arc<RecordingStore>,
    store: &mut TestAttempts,
    ambiguous: bool,
) -> Vec<Measurement> {
    let recipe = family.recipe();
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let args = family.arguments("qualification-1");
    let command = family.command(&recipe, &args, ORIGINAL);
    let attempts = GatewayAttempts::new(recording.clone());
    let mut first = TestIo::new(provider, command.clone());
    first.recipe = Some(&recipe);
    let result = run(&attempts, &recipe, &observer, &first).await;
    assert_eq!(provider.checked.load(Ordering::SeqCst), 1);
    if ambiguous {
        assert!(matches!(result, GatewaySubmitResult::Unknown));
    } else {
        assert!(
            matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
            "{result:?}"
        );
    }
    let mut cases = vec![measurement(
        if ambiguous {
            "ambiguous-write"
        } else {
            "exact-write-and-read-back"
        },
        &result,
        first.leases(),
        provider.inner.entries(),
    )];
    for (name, commitment) in [
        ("proof-replay", ORIGINAL),
        ("fresh-challenge-replay", FRESH),
        ("restart-replay", FRESH),
    ] {
        if name == "restart-replay" {
            store.restart();
        }
        let attempts = if name == "restart-replay" {
            store.attempts()
        } else {
            &attempts
        };
        let mut io = TestIo::new(provider, family.command(&recipe, &args, commitment));
        io.recipe = Some(&recipe);
        let before = provider.checked.load(Ordering::SeqCst);
        let entries_before = provider.inner.entries();
        let result = run(attempts, &recipe, &observer, &io).await;
        let recovery = ambiguous && matches!(family, Family::Airtable) && commitment == ORIGINAL;
        if recovery {
            assert!(
                matches!(result, GatewaySubmitResult::ObservedByProvider { .. }),
                "{} {name} ambiguous={ambiguous}: {result:?}",
                family.name()
            );
        } else {
            assert!(!matches!(
                result,
                GatewaySubmitResult::ObservedByProvider { .. }
            ));
        }
        assert_eq!(
            io.leases(),
            usize::from(recovery),
            "{name}: only declared read-back recovery leases"
        );
        assert_eq!(
            provider.checked.load(Ordering::SeqCst),
            before,
            "{name}: no second write"
        );
        cases.push(measurement(
            name,
            &result,
            io.leases(),
            provider.inner.entries() - entries_before,
        ));
    }
    cases
}

async fn race<P: SimulationProvider>(family: Family, provider: &OracleProvider<P>) -> Measurement {
    let recipe = family.recipe();
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let store = TestAttempts::open(Backend::File);
    let other_store = store.reopen();
    let args = family.arguments("qualification-1");
    let mut first = TestIo::new(provider, family.command(&recipe, &args, ORIGINAL));
    let mut second = TestIo::new(provider, family.command(&recipe, &args, ORIGINAL));
    first.recipe = Some(&recipe);
    second.recipe = Some(&recipe);
    let (left, right) = tokio::join!(
        run(store.attempts(), &recipe, &observer, &first),
        run(&other_store, &recipe, &observer, &second)
    );
    assert_eq!(
        provider.checked.load(Ordering::SeqCst),
        1,
        "two store handles: one write"
    );
    let observed = [&left, &right]
        .into_iter()
        .filter(|result| matches!(result, GatewaySubmitResult::ObservedByProvider { .. }))
        .count();
    assert!(
        (1..=2).contains(&observed),
        "the single write has fresh read-back"
    );
    let leases = first.leases() + second.leases();
    // A concurrent Airtable contender may read the in-flight claim through
    // its linked recovery capability. That is a read lease, never a PATCH.
    let allowed_leases = match family {
        Family::Stripe => 2..=2,
        Family::Airtable => 2..=3,
    };
    assert!(
        allowed_leases.contains(&leases),
        "one write lease, only bounded read-back leases: {leases}"
    );
    Measurement {
        case: "two-instance-race".to_owned(),
        verdict: "one-authorized-entry".to_owned(),
        credential_leases: leases,
        provider_entries: provider.inner.entries(),
        confirmed_by_read_back: usize::from(observed > 0),
    }
}

async fn hostile<P: SimulationProvider>(
    family: Family,
    provider: &OracleProvider<P>,
) -> Vec<Measurement> {
    let recipe = family.recipe();
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let store = TestAttempts::open(Backend::File);
    let target = match family {
        Family::Stripe => "payment_intent",
        Family::Airtable => "record_id",
    };
    let target_max = match family {
        Family::Stripe => 255,
        Family::Airtable => 43,
    };
    let mut measured = Vec::new();
    for name in [
        "missing-target",
        "overlong-target",
        "wrong-target-type",
        "invalid-value",
        "unknown-field",
    ] {
        let mut args = family.arguments("hostile-1");
        match name {
            "missing-target" => {
                args.remove(target);
            }
            "overlong-target" => {
                args.insert(target.into(), json!("a".repeat(target_max + 1)));
            }
            "wrong-target-type" => {
                args.insert(target.into(), json!(true));
            }
            "invalid-value" => match family {
                Family::Stripe => {
                    args.insert("amount".into(), json!(100_000_000));
                }
                Family::Airtable => {
                    args.insert("replacement".into(), json!("Rejected"));
                }
            },
            "unknown-field" => {
                args.insert("provider_token".into(), json!("synthetic-untrusted-field"));
            }
            _ => unreachable!(),
        }
        let mut io = TestIo::answering(provider, family.admission(&recipe, &args, ORIGINAL));
        io.recipe = Some(&recipe);
        let result = run(store.attempts(), &recipe, &observer, &io).await;
        assert!(
            matches!(result, GatewaySubmitResult::NotEntered { .. }),
            "{name}: {result:?}"
        );
        assert_eq!(io.leases(), 0, "{name}: refused before lease");
        assert_eq!(
            provider.checked.load(Ordering::SeqCst),
            0,
            "{name}: refused before provider"
        );
        assert_eq!(provider.inner.entries(), 0, "{name}: provider witness");
        measured.push(measurement(
            name,
            &result,
            io.leases(),
            provider.inner.entries(),
        ));
    }
    measured
}

#[tokio::test]
async fn stripe_qualification_simulation() {
    let family = Family::Stripe;
    let recipe = family.recipe();
    let mut cases = Vec::new();
    let mut defaults = stripe_setup()["responses"].clone();
    defaults["GET /v1/balance"] = json!({"status": 200,
        "headers": {"Stripe-Version": STRIPE_VERSION}, "body": {"livemode": false}});
    for mode in ["respond", "timeout-after-send", "crash-after-write"] {
        let mut store = TestAttempts::open(Backend::File);
        let recording = RecordingStore::new(store.raw());
        if mode == "crash-after-write" {
            recording.lose_response_record.store(true, Ordering::SeqCst);
        }
        let provider = OracleProvider {
            inner: TableProvider::new(
                &recipe,
                &defaults,
                if mode == "timeout-after-send" {
                    mode
                } else {
                    "respond"
                },
            ),
            expected: family.oracle("qualification-1", &ORIGINAL),
            checked: AtomicUsize::new(0),
        };
        let mut measured =
            lifecycle(family, &provider, &recording, &mut store, mode != "respond").await;
        assert_eq!(provider.inner.writes(), 1);
        for case in &mut measured {
            case.case = format!("{mode}/{}", case.case);
        }
        cases.extend(measured);
    }
    let provider = OracleProvider {
        inner: TableProvider::new(&recipe, &defaults, "respond"),
        expected: family.oracle("qualification-1", &ORIGINAL),
        checked: AtomicUsize::new(0),
    };
    cases.extend(hostile(family, &provider).await);
    cases.push(race(family, &provider).await);
    publish(family, &recipe, &cases);
}

#[tokio::test]
async fn airtable_qualification_simulation() {
    let family = Family::Airtable;
    let recipe = family.recipe();
    let mut cases = Vec::new();
    for (label, delivery) in [
        ("respond", Delivery::Respond),
        ("timeout-after-send", Delivery::TimeoutAfterApplying),
        ("crash-after-write", Delivery::Respond),
    ] {
        let mut store = TestAttempts::open(Backend::File);
        let recording = RecordingStore::new(store.raw());
        if label == "crash-after-write" {
            recording.lose_response_record.store(true, Ordering::SeqCst);
        }
        let provider = OracleProvider {
            inner: RecordProvider::new(delivery, Reading::Faithful),
            expected: family.oracle("qualification-1", &ORIGINAL),
            checked: AtomicUsize::new(0),
        };
        let mut measured = lifecycle(
            family,
            &provider,
            &recording,
            &mut store,
            label != "respond",
        )
        .await;
        assert_eq!(provider.inner.writes(), 1);
        for case in &mut measured {
            case.case = format!("{label}/{}", case.case);
        }
        cases.extend(measured);
    }
    let provider = OracleProvider {
        inner: RecordProvider::new(Delivery::Respond, Reading::Faithful),
        expected: family.oracle("qualification-1", &ORIGINAL),
        checked: AtomicUsize::new(0),
    };
    cases.extend(hostile(family, &provider).await);
    cases.push(race(family, &provider).await);
    publish(family, &recipe, &cases);
}
