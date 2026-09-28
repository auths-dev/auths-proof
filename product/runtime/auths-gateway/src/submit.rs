//! One gateway submission, driven by the admission-order step machine.
//!
//! [`run`] asks the translated leaf `auths_gateway_kernel::order::next_step`
//! for the next action, performs exactly that action through a
//! [`SubmitIo`], turns its result into the next event, and repeats until the
//! machine stops. The driver owns no ordering: a claim, a lease, a
//! credential read, an action read, a store write, and the provider write
//! each happen only when the machine names them. The engine supplies the
//! installed transport and credential store; the tests supply a counting
//! provider double through the same driver.

use crate::engine::{GatewaySubmitResult, VerifiedCommand, not_entered, replay_refused};
use crate::pre_entry::{self, PreEntryObservation, SelectedRequirement};
use crate::recipe::{CeilingCheck, CeilingReading, GuardChecks, MAX_ACCOUNT_BYTES, ReadBack};
use crate::transport::{
    GatewayTransportError, ProviderPort, ProviderResponse, WriteTransportOutcome,
};
use crate::{
    ClaimedGatewayAttempt, ClosedCredentialRead, ClosedProviderRequest, CompiledRecipe,
    GatewayAttemptError, GatewayAttempts, GatewayObserver, GatewayPreEntry, GatewayRelativeBasis,
    ObservableGatewayAttempt, RequestHeader,
};
use auths_gateway_kernel::order::{
    AccountResult, CeilingRead, ClaimResult, DeniedResult, Mode, Phase, PreEntryResult, Refusal,
    ResponseRecord, Stop, SubmitAction, SubmitDecision, SubmitEvent, SubmitPlan, SubmitState,
    Verification, WriteResult, next_step, start,
};
use auths_model::{ResourceId, TrustedContext};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// No submission takes more steps than this; a longer run halts.
const MAX_STEPS: usize = 64;
/// The account-commitment domain `install` hashes the account label under.
const ACCOUNT_DOMAIN: &[u8] = b"auths.gateway-account/1\0";

/// The I/O one submission may perform, each only when the step machine
/// names it.
pub(crate) trait SubmitIo {
    /// A credential lease.
    type Lease;

    /// Reads the gateway clock.
    fn clock(&self) -> Option<u64>;

    /// Verifies natively at `now` and projects the verified command.
    fn verify(&self, now: u64) -> Result<VerifiedCommand, GatewaySubmitResult>;

    /// Checks that every link's scope lists the verified account-scope
    /// value.
    fn bind_scope(&self, verified: &VerifiedCommand) -> Result<(), &'static str>;

    /// Loads the shared connection record, requires this process to hold
    /// its current credential, and prepares the pinned transport.
    async fn prepare(&self) -> Result<(), &'static str>;

    /// Reloads the shared connection record and reports whether it is
    /// unchanged since [`Self::prepare`].
    async fn reload(&self) -> bool;

    /// Counts this submission in flight, before its final reload. An admin
    /// change waits for this process's count to reach zero.
    fn enter(&self) {}

    /// Ends the count [`Self::enter`] took, once the entry is recorded.
    fn leave(&self) {}

    /// Leases the credential.
    async fn lease(&self) -> Option<Self::Lease>;

    /// Whether the leased secret starts with a declared prefix. The secret
    /// never leaves the lease.
    fn secret_admitted(&self, lease: &Self::Lease, guard: &GuardChecks) -> bool;

    /// The connection record's account commitment.
    fn account_commitment(&self) -> Option<[u8; 32]>;

    /// Whether entry is still within the deadline after `evaluated_at`, on
    /// the gateway clock and on the monotonic clock started with the
    /// submission.
    fn within_entry_deadline(&self, evaluated_at: u64) -> bool;

    /// Sends the one write under `lease`.
    async fn write(
        &self,
        lease: &Self::Lease,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError>;

    /// Performs one bounded GET of an action read or observation under
    /// `lease`.
    async fn action_read(
        &self,
        lease: &Self::Lease,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse>;

    /// Performs one credential read under `lease`.
    async fn credential_read(
        &self,
        lease: &Self::Lease,
        read: &ClosedCredentialRead,
    ) -> Option<ProviderResponse>;
}

/// The installation one submission runs against.
pub(crate) struct SubmitContext<'a> {
    pub(crate) recipe: &'a CompiledRecipe,
    pub(crate) attempts: &'a GatewayAttempts,
    pub(crate) context: &'a TrustedContext,
    pub(crate) observer: Option<&'a GatewayObserver>,
}

/// The step-machine plan of a recipe.
pub(crate) fn plan(recipe: &CompiledRecipe) -> SubmitPlan {
    let guard = recipe.guard_checks();
    let ceiling = recipe.ceiling_check();
    SubmitPlan {
        account_scope: recipe.declares_account_scope(),
        account_read: guard
            .as_ref()
            .is_some_and(|guard| guard.account_pointer.is_some()),
        denied_reads: guard.map_or(0, |guard| {
            u8::try_from(guard.denied_refused.len()).unwrap_or(u8::MAX)
        }),
        pre_entry: recipe.pre_entry_pointers().is_some(),
        relative_ceiling: ceiling.is_some(),
        basis_points: ceiling.map_or(0, |ceiling| ceiling.basis_points),
    }
}

/// The recorded code of each refusal after the claim.
pub(crate) const fn refusal_code(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::ConnectionChanged => "gateway.connection.changed",
        Refusal::CredentialUnavailable => "gateway.credential.unavailable",
        Refusal::ModeGuard => "gateway.credential.mode-guard",
        Refusal::AccountMismatch => "gateway.credential.account-mismatch",
        Refusal::AccountUnavailable => "gateway.credential.account-unavailable",
        Refusal::CapabilityExcess => "gateway.credential.capability-excess",
        Refusal::CapabilityUnavailable => "gateway.credential.capability-unavailable",
        Refusal::PreEntryConditionFalse => "gateway.pre-entry.condition-false",
        Refusal::PreEntryUnavailable => "gateway.pre-entry.unavailable",
        Refusal::CeilingAbove => "gateway.relative-ceiling.above",
        Refusal::CeilingBindingMismatch => "gateway.relative-ceiling.binding-mismatch",
        Refusal::CeilingUnavailable => "gateway.relative-ceiling.unavailable",
        Refusal::EntryDeadline => "gateway.attempt.entry-deadline",
        Refusal::TransportNotEntered => "gateway.transport.not-entered",
    }
}

/// SHA-256 of the account domain and `label`: the commitment `install`
/// records, and what the account read compares with it.
pub(crate) fn account_commitment(label: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ACCOUNT_DOMAIN);
    hash.update(label.as_bytes());
    hash.finalize().into()
}

/// The account a complete 2xx JSON response with no version mismatch
/// names at `pointer`: a JSON string of 1–256 bytes.
pub(crate) fn account_label(response: Option<&ProviderResponse>, pointer: &str) -> Option<String> {
    let body = response?.usable_body()?;
    match serde_json::from_slice::<Value>(body)
        .ok()?
        .pointer(pointer)?
    {
        Value::String(label) if !label.is_empty() && label.len() <= MAX_ACCOUNT_BYTES => {
            Some(label.clone())
        }
        _ => None,
    }
}

/// The account read's result against the connection record's commitment,
/// compared in constant time.
pub(crate) fn account_result(
    response: Option<&ProviderResponse>,
    pointer: &str,
    expected: Option<[u8; 32]>,
) -> AccountResult {
    let (Some(expected), Some(label)) = (expected, account_label(response, pointer)) else {
        return AccountResult::Unavailable;
    };
    if bool::from(account_commitment(&label).ct_eq(&expected)) {
        AccountResult::Equal
    } else {
        AccountResult::Mismatch
    }
}

/// One denied read's result: refused with a declared status, answered with
/// a success status, or anything else, including a version mismatch.
pub(crate) fn denied_result(response: Option<&ProviderResponse>, refused: &[u16]) -> DeniedResult {
    match response {
        Some(response) if response.version_ok && refused.contains(&response.status) => {
            DeniedResult::Refused
        }
        Some(response) if response.version_ok && response.success() => DeniedResult::Answered,
        _ => DeniedResult::Unavailable,
    }
}

/// Ends the in-flight count of one entry when dropped, so a count taken
/// before the final reload is released on every path.
struct InFlight<'a, I: SubmitIo> {
    io: &'a I,
}

impl<I: SubmitIo> Drop for InFlight<'_, I> {
    fn drop(&mut self) {
        self.io.leave();
    }
}

/// What one run has learned so far.
struct Run<'a, I: SubmitIo> {
    cx: &'a SubmitContext<'a>,
    io: &'a I,
    guard: Option<GuardChecks>,
    ceiling: Option<CeilingCheck>,
    evaluated_at: u64,
    verified: Option<VerifiedCommand>,
    selected: Vec<SelectedRequirement>,
    claim: Option<ClaimedGatewayAttempt>,
    observable: Option<ObservableGatewayAttempt>,
    lease: Option<I::Lease>,
    pre_entry: GatewayPreEntry,
    written: Option<(u16, [u8; 32], Vec<u8>, bool)>,
    refusal: Option<&'static str>,
    result: Option<GatewaySubmitResult>,
    in_flight: Option<InFlight<'a, I>>,
}

impl<'a, I: SubmitIo> Run<'a, I> {
    fn new(cx: &'a SubmitContext<'a>, io: &'a I) -> Self {
        Self {
            cx,
            io,
            guard: cx.recipe.guard_checks(),
            ceiling: cx.recipe.ceiling_check(),
            evaluated_at: 0,
            verified: None,
            selected: Vec::new(),
            claim: None,
            observable: None,
            lease: None,
            pre_entry: GatewayPreEntry::default(),
            written: None,
            refusal: None,
            result: None,
            in_flight: None,
        }
    }

    /// Performs each action `decision` names until the machine stops.
    async fn drive(&mut self, mut decision: SubmitDecision) -> Stop {
        for _ in 0..MAX_STEPS {
            let event = match decision.action {
                SubmitAction::Stop(stop) => return stop,
                // Each step runs on the heap so a submission's future stays
                // small wherever it is spawned.
                action => Box::pin(self.perform(action)).await,
            };
            decision = next_step(decision.state, event);
        }
        Stop::Halted
    }
}

/// Runs one submission to its stop.
pub(crate) async fn run<I: SubmitIo>(cx: &SubmitContext<'_>, io: &I) -> GatewaySubmitResult {
    let mut state = Run::new(cx, io);
    let stop = state
        .drive(next_step(start(plan(cx.recipe)), SubmitEvent::Start))
        .await;
    state.finish(stop)
}

/// Runs the operator's read-only re-observation of `attempt`, which
/// [`GatewayAttempts::resume_observable_operation`] reopened, through the
/// same step machine a replay takes: a reload, a fresh lease that passes
/// every credential check, and one read-back from the stored plan. The
/// caller has already prepared the entry. Returns the recorded result, or
/// `None` when the read-back recorded nothing.
pub(crate) async fn reobserve<I: SubmitIo>(
    cx: &SubmitContext<'_>,
    io: &I,
    attempt: ObservableGatewayAttempt,
) -> Option<GatewaySubmitResult> {
    let mut state = Run::new(cx, io);
    state.observable = Some(attempt);
    let resumed = SubmitState {
        plan: plan(cx.recipe),
        phase: Phase::Resume,
        argument: 0,
    };
    match state
        .drive(next_step(resumed, SubmitEvent::Resume(true)))
        .await
    {
        Stop::Observed => state.result,
        _ => None,
    }
}

impl<I: SubmitIo> Run<'_, I> {
    fn refuse_before_claim(&mut self, result: GatewaySubmitResult) {
        self.result = Some(result);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per action keeps the action-to-event mapping in one place"
    )]
    async fn perform(&mut self, action: SubmitAction) -> SubmitEvent {
        match action {
            SubmitAction::ReadClock => {
                let clock = self.io.clock();
                if let Some(now) = clock {
                    self.evaluated_at = now;
                } else {
                    self.refuse_before_claim(GatewaySubmitResult::Indeterminate {
                        code: "gateway.verify.clock-unavailable".to_owned(),
                    });
                }
                SubmitEvent::Clock(clock.is_some())
            }
            SubmitAction::Verify => SubmitEvent::Verification(self.verify()),
            SubmitAction::Admit => SubmitEvent::Admission(self.admit()),
            SubmitAction::BindScope => {
                let bound = match &self.verified {
                    Some(verified) => self.io.bind_scope(verified),
                    None => Err("gateway.attempt.unavailable"),
                };
                if let Err(code) = bound {
                    self.refuse_before_claim(not_entered(code));
                }
                SubmitEvent::Scope(bound.is_ok())
            }
            SubmitAction::Prepare => {
                let prepared = self.io.prepare().await;
                if let Err(code) = prepared {
                    self.refuse_before_claim(not_entered(code));
                }
                SubmitEvent::Preparation(prepared.is_ok())
            }
            SubmitAction::Claim => SubmitEvent::Claim(self.claim().await),
            SubmitAction::Resume => SubmitEvent::Resume(self.resume().await),
            SubmitAction::Reload(_) => SubmitEvent::Reload(self.io.reload().await),
            SubmitAction::ReloadBeforeEntry => {
                // Counted before the reload, so an admin change committed
                // after this point is seen by the reload, and one committed
                // before it waits for this entry.
                self.io.enter();
                self.in_flight = Some(InFlight { io: self.io });
                SubmitEvent::Reload(self.io.reload().await)
            }
            SubmitAction::Lease(_) => {
                self.lease = self.io.lease().await;
                SubmitEvent::Lease(self.lease.is_some())
            }
            SubmitAction::CheckPrefix(_) => SubmitEvent::Prefix(match (&self.guard, &self.lease) {
                (None, Some(_)) => true,
                (Some(guard), Some(lease)) => self.io.secret_admitted(lease, guard),
                (_, None) => false,
            }),
            SubmitAction::ReadAccount(_) => SubmitEvent::Account(self.read_account().await),
            SubmitAction::DeniedRead(_, index) => {
                SubmitEvent::Denied(self.denied_read(usize::from(index)).await)
            }
            SubmitAction::PreEntryRead => SubmitEvent::PreEntry(self.pre_entry_read().await),
            SubmitAction::CeilingRead => SubmitEvent::Ceiling(self.ceiling_read().await),
            SubmitAction::RecordCheckpoint => SubmitEvent::Recorded(match self.claim.take() {
                Some(claim) => match claim.record_checkpoint(&self.pre_entry).await {
                    Ok(claim) => {
                        self.claim = Some(claim);
                        true
                    }
                    Err(_) => false,
                },
                None => false,
            }),
            SubmitAction::CheckDeadline => {
                SubmitEvent::Deadline(self.io.within_entry_deadline(self.evaluated_at))
            }
            SubmitAction::Send => SubmitEvent::Write(self.send().await),
            SubmitAction::RecordResponse => {
                let recorded = self.record_response().await;
                self.in_flight = None;
                SubmitEvent::Response(recorded)
            }
            SubmitAction::RecordUnknown => {
                let recorded = match self.claim.take() {
                    Some(claim) => claim.record_unknown().await.is_ok(),
                    None => false,
                };
                self.in_flight = None;
                SubmitEvent::Recorded(recorded)
            }
            SubmitAction::RecordNotEntered(refusal) => {
                let recorded = self.record_not_entered(refusal).await;
                self.in_flight = None;
                SubmitEvent::Recorded(recorded)
            }
            SubmitAction::ReadBack(mode) => SubmitEvent::Recorded(self.read_back(mode).await),
            SubmitAction::Stop(_) => SubmitEvent::Start,
        }
    }

    fn verify(&mut self) -> Verification {
        let verified = match self.io.verify(self.evaluated_at) {
            Ok(verified) => verified,
            Err(result) => {
                self.refuse_before_claim(result);
                return Verification::Refused;
            }
        };
        let argument = match &self.ceiling {
            None => 0,
            Some(ceiling) => {
                let Some(argument) = ceiling.argument_value(&verified.arguments) else {
                    self.refuse_before_claim(not_entered("gateway.policy.argument-unavailable"));
                    return Verification::Refused;
                };
                argument
            }
        };
        self.verified = Some(verified);
        Verification::Authorized { argument }
    }

    /// The retention rule, then pre-entry selection; nothing is stored.
    fn admit(&mut self) -> bool {
        let Some(verified) = &self.verified else {
            return false;
        };
        if let Some(retention) = self.cx.recipe.idempotency_retention()
            && verified
                .validity_seconds
                .saturating_add(crate::recipe::ENTRY_DEADLINE_SECONDS)
                > retention
        {
            self.refuse_before_claim(not_entered("gateway.idempotency.window-exceeds-retention"));
            return false;
        }
        let (Some(pointers), Some(read)) = (
            self.cx.recipe.pre_entry_pointers(),
            verified.request.pre_entry_read(),
        ) else {
            return true;
        };
        let covers = |namespace: &ResourceId, subject: &ResourceId| {
            crate::engine::resource_covers(self.cx.context, namespace, subject)
        };
        match pre_entry::select(
            &verified.requirements,
            &verified.canonical_action,
            self.cx.context,
            self.cx.observer.map(GatewayObserver::principal),
            read,
            pointers,
            covers,
        ) {
            Ok(selected) => {
                self.selected = selected;
                true
            }
            Err(refusal) => {
                self.refuse_before_claim(not_entered(refusal.code()));
                false
            }
        }
    }

    async fn claim(&mut self) -> ClaimResult {
        let Some(verified) = &self.verified else {
            return ClaimResult::Unavailable;
        };
        let attempts = self.cx.attempts;
        let claim = match attempts
            .claim(
                &verified.request,
                *self.cx.recipe.digest(),
                self.evaluated_at,
            )
            .await
        {
            Ok(claim) => claim,
            Err(GatewayAttemptError::Replay) => return ClaimResult::Replay,
            Err(_) => {
                self.refuse_before_claim(not_entered("gateway.attempt.unavailable"));
                return ClaimResult::Unavailable;
            }
        };
        let Some(bound) = &verified.bound else {
            self.claim = Some(claim);
            return ClaimResult::Inserted;
        };
        match attempts
            .reserve_window(bound, verified.request.operation_id())
            .await
        {
            Ok(()) => {
                self.claim = Some(claim);
                ClaimResult::Inserted
            }
            Err(refusal) => {
                self.result = Some(match claim.record_not_entered(refusal.code(), None).await {
                    Ok(_) => not_entered(refusal.code()),
                    Err(_) => GatewaySubmitResult::Unknown,
                });
                ClaimResult::Refused
            }
        }
    }

    async fn resume(&mut self) -> bool {
        let Some(verified) = &self.verified else {
            return false;
        };
        match self
            .cx
            .attempts
            .resume_observable(&verified.request, *self.cx.recipe.digest())
            .await
        {
            Ok(Some(attempt)) => {
                self.observable = Some(attempt);
                true
            }
            Ok(None) | Err(_) => false,
        }
    }

    async fn read_account(&self) -> AccountResult {
        let (Some(lease), Some(pointer)) = (
            &self.lease,
            self.guard
                .as_ref()
                .and_then(|guard| guard.account_pointer.as_deref()),
        ) else {
            return AccountResult::Unavailable;
        };
        let Ok(reads) = self.cx.recipe.credential_reads() else {
            return AccountResult::Unavailable;
        };
        let Some(read) = reads.account() else {
            return AccountResult::Unavailable;
        };
        let response = self.io.credential_read(lease, read).await;
        account_result(response.as_ref(), pointer, self.io.account_commitment())
    }

    async fn denied_read(&self, index: usize) -> DeniedResult {
        let (Some(lease), Some(refused)) = (
            &self.lease,
            self.guard
                .as_ref()
                .and_then(|guard| guard.denied_refused.get(index)),
        ) else {
            return DeniedResult::Unavailable;
        };
        let Ok(reads) = self.cx.recipe.credential_reads() else {
            return DeniedResult::Unavailable;
        };
        let Some(read) = reads.denied().get(index) else {
            return DeniedResult::Unavailable;
        };
        let response = self.io.credential_read(lease, read).await;
        denied_result(response.as_ref(), refused)
    }

    async fn pre_entry_read(&mut self) -> PreEntryResult {
        let (Some(lease), Some(verified), Some(observer), Some(pointers)) = (
            &self.lease,
            &self.verified,
            self.cx.observer,
            self.cx.recipe.pre_entry_pointers(),
        ) else {
            return PreEntryResult::Unavailable;
        };
        let Some(read) = verified.request.pre_entry_read() else {
            return PreEntryResult::Unavailable;
        };
        let Some(observed_at) = self.io.clock() else {
            return PreEntryResult::Unavailable;
        };
        let response = self
            .io
            .action_read(
                lease,
                read.url(),
                read.headers(),
                read.maximum_response_bytes(),
            )
            .await;
        let Some(observations) = response
            .as_ref()
            .and_then(ProviderResponse::usable_body)
            .and_then(|body| {
                pre_entry::sign_observations(observer, read, pointers, body, observed_at)
            })
        else {
            return PreEntryResult::Unavailable;
        };
        let Some(now) = self.io.clock() else {
            return PreEntryResult::Unavailable;
        };
        let result = pre_entry::evaluate(&self.selected, &observations, now);
        if result != PreEntryResult::Unavailable {
            self.pre_entry.observations = observations
                .into_iter()
                .map(|observation: PreEntryObservation| observation.bytes)
                .collect();
        }
        result
    }

    async fn ceiling_read(&mut self) -> CeilingRead {
        let (Some(lease), Some(verified), Some(ceiling)) =
            (&self.lease, &self.verified, &self.ceiling)
        else {
            return CeilingRead::Unavailable;
        };
        let Some(read) = verified.request.relative_ceiling_read() else {
            return CeilingRead::Unavailable;
        };
        let Some(read_at) = self.io.clock() else {
            return CeilingRead::Unavailable;
        };
        let response = self
            .io
            .action_read(
                lease,
                read.url(),
                read.headers(),
                read.maximum_response_bytes(),
            )
            .await;
        let Some(body) = response.as_ref().and_then(ProviderResponse::usable_body) else {
            return CeilingRead::Unavailable;
        };
        match ceiling.read(body, &verified.arguments) {
            CeilingReading::Read { basis, binds_equal } => {
                self.pre_entry.basis = Some(GatewayRelativeBasis {
                    value: basis,
                    response_digest: Sha256::digest(body).into(),
                    read_at,
                });
                CeilingRead::Read { basis, binds_equal }
            }
            CeilingReading::Unavailable => CeilingRead::Unavailable,
        }
    }

    async fn send(&mut self) -> WriteResult {
        let (Some(lease), Some(verified)) = (&self.lease, &self.verified) else {
            return WriteResult::NotEntered;
        };
        match self.io.write(lease, &verified.request).await {
            Err(_) => WriteResult::NotEntered,
            Ok(WriteTransportOutcome::Unknown) => WriteResult::Unknown,
            Ok(WriteTransportOutcome::ResponseRecorded {
                status,
                digest,
                body,
                version_ok,
            }) => {
                self.written = Some((status, digest, body, version_ok));
                WriteResult::Response
            }
        }
    }

    async fn record_response(&mut self) -> ResponseRecord {
        let (Some(claim), Some((status, digest, body, version_ok)), Some(verified)) =
            (self.claim.take(), self.written.take(), &self.verified)
        else {
            return ResponseRecord::Failed;
        };
        let locator = verified
            .request
            .observation_template()
            .filter(|template| template.has_response_fields())
            .filter(|_| version_ok && (200..300).contains(&status))
            .and_then(|template| template.extract_locator(&body));
        match claim.record_response(status, digest, locator).await {
            Ok(observable) => {
                let can_observe = observable.observation_request().is_some();
                self.result = Some(GatewaySubmitResult::ResponseRecorded { status });
                self.observable = Some(observable);
                ResponseRecord::Recorded {
                    observable: can_observe,
                }
            }
            Err(_) => ResponseRecord::Failed,
        }
    }

    async fn record_not_entered(&mut self, refusal: Refusal) -> bool {
        let Some(claim) = self.claim.take() else {
            return false;
        };
        let code = refusal_code(refusal);
        let pre_entry = (!self.pre_entry.is_empty()).then_some(&self.pre_entry);
        let recorded = claim.record_not_entered(code, pre_entry).await.is_ok();
        if recorded {
            self.refusal = Some(code);
        }
        recorded
    }

    /// One read-only observation from the stored plan, recording only what
    /// the stored stage admits. The token comes from the stored commitment,
    /// never from this submission.
    async fn read_back(&mut self, _mode: Mode) -> bool {
        let (Some(lease), Some(attempt)) = (&self.lease, self.observable.take()) else {
            return false;
        };
        let Some(observation) = attempt.observation_request() else {
            return false;
        };
        let Some(bytes) = self
            .io
            .action_read(
                lease,
                observation.url(),
                observation.headers(),
                observation.maximum_response_bytes(),
            )
            .await
            .as_ref()
            .and_then(ProviderResponse::usable_body)
            .map(<[u8]>::to_vec)
        else {
            return false;
        };
        let token = attempt.echo_token();
        let Some(reading) = observation.read_back(token.as_deref(), &bytes) else {
            return false;
        };
        let Ok(snapshot) = attempt.snapshot() else {
            return false;
        };
        let status = snapshot.response_status();
        let result = match reading {
            ReadBack::EchoMatched => {
                let Some(observed_at) = self.io.clock() else {
                    return false;
                };
                attempt
                    .record_provider_evidence(&bytes, observed_at)
                    .await
                    .ok()
                    .and_then(|snapshot| {
                        snapshot.provider_evidence().map(|evidence| {
                            GatewaySubmitResult::ObservedByProvider {
                                status,
                                evidence: evidence.into(),
                            }
                        })
                    })
            }
            ReadBack::Value { matched } => match status {
                Some(status) => attempt
                    .record_observation(matched)
                    .await
                    .ok()
                    .map(|_| GatewaySubmitResult::Observed { status, matched }),
                None => None,
            },
            ReadBack::EchoMismatch => match status {
                Some(status) => attempt.record_echo_mismatch().await.ok().map(|_| {
                    GatewaySubmitResult::Observed {
                        status,
                        matched: false,
                    }
                }),
                None => None,
            },
        };
        match result {
            Some(result) => {
                self.result = Some(result);
                true
            }
            None => false,
        }
    }

    fn finish(self, stop: Stop) -> GatewaySubmitResult {
        match stop {
            Stop::Refused => self
                .result
                .unwrap_or_else(|| not_entered("gateway.attempt.unavailable")),
            Stop::StoreUnavailable => not_entered("gateway.attempt.unavailable"),
            Stop::ClaimRefused | Stop::Response | Stop::Observed => {
                self.result.unwrap_or(GatewaySubmitResult::Unknown)
            }
            Stop::NotEntered => self
                .refusal
                .map_or(GatewaySubmitResult::Unknown, not_entered),
            Stop::Unknown | Stop::Halted => GatewaySubmitResult::Unknown,
            Stop::ReplayRefused => replay_refused(),
        }
    }
}

/// The lease-time credential checks of a read outside a submission (an
/// observation request): the prefix guard, the account read, and each
/// denied read in declaration order, stopping at the first failure.
pub(crate) async fn lease_checks<P: ProviderPort>(
    recipe: &CompiledRecipe,
    provider: &P,
    prefix_admitted: bool,
    expected: Option<[u8; 32]>,
) -> bool {
    let Some(guard) = recipe.guard_checks() else {
        return true;
    };
    if !prefix_admitted {
        return false;
    }
    let Ok(reads) = recipe.credential_reads() else {
        return false;
    };
    if let (Some(pointer), Some(read)) = (&guard.account_pointer, reads.account()) {
        let response = provider.credential_read(read).await;
        if account_result(response.as_ref(), pointer, expected) != AccountResult::Equal {
            return false;
        }
    }
    for (read, refused) in reads.denied().iter().zip(&guard.denied_refused) {
        let response = provider.credential_read(read).await;
        if denied_result(response.as_ref(), refused) != DeniedResult::Refused {
            return false;
        }
    }
    true
}
