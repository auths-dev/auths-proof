//! A paused provider response exposes the shared-reservation race deterministically.
//! Native projection is a test oracle; journal entries and one-use permits are real.
use super::*;
use tokio::sync::Notify;

struct HeldFirstCredentialRead<'a, P> {
    provider: &'a P,
    entered: Notify,
    release: Notify,
    pending: AtomicBool,
}

impl<P: ProviderPort> ProviderPort for HeldFirstCredentialRead<'_, P> {
    async fn write(
        &self,
        permit: crate::store::ProviderEntryPermit,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.provider.write(permit).await
    }

    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum: usize,
    ) -> Option<ProviderResponse> {
        self.provider.action_read(url, headers, maximum).await
    }

    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        if self.pending.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.provider.credential_read(read).await
    }
}

async fn pending_read_keeps_parent_reserved(backend: Backend) {
    let family = Family::Stripe;
    let recipe = family.recipe();
    let provider = OracleProvider {
        inner: TableProvider::new(&recipe, &stripe_setup()["responses"], "respond"),
        expected: family.oracle("qualification-1", &ORIGINAL),
        checked: AtomicUsize::new(0),
        read_back_url: family.read_back_url(),
        read_backs: AtomicUsize::new(0),
    };
    let held = HeldFirstCredentialRead {
        provider: &provider,
        entered: Notify::new(),
        release: Notify::new(),
        pending: AtomicBool::new(true),
    };
    let store = TestAttempts::open(backend);
    let other = store.reopen();
    let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
    let arguments = family.arguments("qualification-1");
    let mut first = TestIo::new(&held, family.command(&recipe, &arguments, ORIGINAL));
    let mut second = TestIo::new(&held, family.command(&recipe, &arguments, ORIGINAL));
    first.recipe = Some(&recipe);
    second.recipe = Some(&recipe);
    let operation = LogicalOperationId::parse("qualification-1").expect("operation");
    let (winner, contender) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(run(store.attempts(), &recipe, &observer, &first), async {
            // The first process owns the read permit but has not yet received
            // evidence. The second process cannot interpret this as a failed
            // provider predicate or consume another permit.
            held.entered.notified().await;
            let result = run(&other, &recipe, &observer, &second).await;
            let snapshot = other
                .read(recipe.namespace(), &operation)
                .await
                .expect("source read")
                .expect("source reservation");
            held.release.notify_one();
            assert_eq!(snapshot.stage(), GatewayAttemptStage::Reserved);
            result
        })
    })
    .await
    .expect("both contenders finish");
    assert!(
        matches!(contender, GatewaySubmitResult::Reserved { .. }),
        "{contender:?}"
    );
    assert_eq!(
        winner,
        GatewaySubmitResult::ResponseRecorded { status: 200 }
    );
    assert_eq!(provider.checked.load(Ordering::SeqCst), 1);
    assert_eq!(provider.inner.writes(), 1);
    assert_eq!(
        provider.inner.credential_reads.load(Ordering::SeqCst),
        3,
        "account and two denied-capability reads each consume one permit"
    );
    assert_eq!(
        provider.inner.action_reads.load(Ordering::SeqCst),
        1,
        "one ceiling read and no recovery read"
    );
    assert_eq!(first.leases(), 1);
    assert_eq!(second.leases(), 1);
    assert_eq!(
        other
            .read(recipe.namespace(), &operation)
            .await
            .expect("source read")
            .expect("source result")
            .stage(),
        GatewayAttemptStage::ResponseRecorded
    );
}

#[tokio::test]
async fn file_in_flight_prerequisite_cannot_poison_shared_parent() {
    pending_read_keeps_parent_reserved(Backend::File).await;
}

#[tokio::test]
#[ignore = "needs the TLS PostgreSQL fixture"]
async fn postgres_in_flight_prerequisite_cannot_poison_shared_parent() {
    assert!(
        postgres_configured(),
        "TLS PostgreSQL environment slots are required"
    );
    pending_read_keeps_parent_reserved(Backend::Postgres).await;
}
