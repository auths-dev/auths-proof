use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    ChargeId, CredentialProvider, Currency, CustomerId, MerchantConnectAccount, MerchantOperation,
    MerchantProviderProjection, MerchantReservationRecord, PaymentCaptureCredential,
    PaymentCaptureCredentialScope, PaymentCaptureEffect, PaymentCaptureEvidenceInput,
    PaymentCaptureEvidenceV1, PaymentCaptureGateway, PaymentCaptureProviderProjection,
    PaymentCaptureReconciliationOutcome, PaymentIntentId, PaymentMethodId, PortError,
    StripeAccountId, VerifiedPaymentCaptureCommand,
    canonical::{canonical_json, sha256},
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde_json::{Value, json};

const AUTHORIZED_AMOUNT_MINOR: u64 = 1_000;

/// Real manual-capture authorization created as repository-owned session setup.
pub struct CaptureFixture {
    /// Stripe Customer.
    pub customer_id: CustomerId,
    /// Attached test `PaymentMethod`.
    pub payment_method_id: PaymentMethodId,
    /// Exact pre-capture `PaymentIntent` and Charge projection.
    pub authorization_provider: MerchantProviderProjection,
    /// Exact protected order.
    pub order_scope: String,
}

/// Public diagnostic counters contain no credential or response data.
#[derive(Clone, Copy, Debug)]
pub struct EnvironmentDiagnostics {
    /// Capture credential broker invocations after durable claim.
    pub credential_requests: u64,
    /// Protected Stripe reads/writes after capture credential acquisition.
    pub provider_calls: u64,
}

/// Capture-specific provider surface used by the application.
pub trait DemoPaymentCaptureEnvironment:
    CredentialProvider<PaymentCaptureCredentialScope> + PaymentCaptureGateway + Send + Sync
{
    /// Creates a repository-owned manual-capture authorization fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when fixture creation or projection fails.
    fn seed_capture(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CaptureFixture, PortError>;

    /// Arms one lost-response experiment after actual Stripe delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when the experiment cannot be recorded safely.
    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError>;

    /// Configured account.
    fn account_id(&self) -> &StripeAccountId;

    /// Pinned API version.
    fn api_version(&self) -> &str;

    /// Truthful mode label.
    fn execution_mode(&self) -> &'static str;

    /// Non-secret boundary counters.
    fn diagnostics(&self) -> EnvironmentDiagnostics;
}

/// Real Stripe test-mode final-capture environment.
pub struct LivePaymentCaptureEnvironment {
    http: StripeHttp<PaymentCaptureCredentialScope>,
    ambiguous_once: Mutex<HashSet<String>>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
}

impl LivePaymentCaptureEnvironment {
    /// Loads strict Stripe test-mode deployment configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when fixture or capture credentials are unavailable.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_PAYMENT_CAPTURE_SECRET_KEY")?,
            ambiguous_once: Mutex::new(HashSet::new()),
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
        })
    }

    fn protected_get(
        &self,
        path: &str,
        credential: &PaymentCaptureCredential,
        connect: &MerchantConnectAccount,
    ) -> Result<auths_stripe_payment_demo_common::StripeHttpResponse, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        self.http.protected_get(path, credential, connect)
    }

    fn retrieve_capture_projection(
        &self,
        payment_intent_id: &PaymentIntentId,
        credential: &PaymentCaptureCredential,
        connect: &MerchantConnectAccount,
        now: u64,
    ) -> Result<PaymentCaptureProviderProjection, PortError> {
        let response = self.protected_get(
            &format!(
                "/v1/payment_intents/{payment_intent_id}?expand[]=latest_charge.balance_transaction"
            ),
            credential,
            connect,
        )?;
        capture_projection(&response.value, response.request_id, now, "retrieve")
    }

    fn fresh_capture_evidence(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEvidenceV1, PortError> {
        let response = self.protected_get(
            &format!(
                "/v1/payment_intents/{}?expand[]=latest_charge",
                command.action().payment_intent_id()
            ),
            credential,
            command.action().connect_account(),
        )?;
        let provider = authorization_projection(&response.value, response.request_id, now)?;
        let charge_id = provider.charge_id.clone().ok_or(PortError::Malformed)?;
        PaymentCaptureEvidenceV1::new(PaymentCaptureEvidenceInput {
            stripe_account_id: command.action().stripe_account_id().clone(),
            connect_account: command.action().connect_account().clone(),
            payment_intent_id: provider.payment_intent_id,
            latest_charge_id: charge_id,
            customer_id: command.action().customer_id().clone(),
            order_scope: command.action().order_scope().into(),
            authorized_amount_minor: provider.amount_minor,
            amount_capturable_minor: provider.amount_capturable_minor,
            amount_captured_minor: provider.amount_received_minor,
            currency: provider.currency,
            payment_intent_status: provider.status,
            capture_before: provider.capture_before.ok_or(PortError::Malformed)?,
            livemode: false,
            stripe_api_version: self.http.api_version().into(),
            authorization_workflow_id: command.evidence().authorization_workflow_id().into(),
            authorization_action_digest: command.evidence().authorization_action_digest().clone(),
            authorization_reservation_id: command.evidence().authorization_reservation_id().clone(),
            authorization_state: command.evidence().authorization_state(),
            authorization_created_at: command.evidence().authorization_created_at(),
            observed_at: now,
            source: "retrieve".into(),
            response_commitment: provider.response_digest,
        })
        .map_err(|_| PortError::Malformed)
    }
}

impl CredentialProvider<PaymentCaptureCredentialScope> for LivePaymentCaptureEnvironment {
    fn credential(&self, account: &StripeAccountId) -> Result<PaymentCaptureCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.credential(account)
    }
}

impl DemoPaymentCaptureEnvironment for LivePaymentCaptureEnvironment {
    fn seed_capture(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CaptureFixture, PortError> {
        if !valid_local(workflow_id) || !valid_local(order_scope) {
            return Err(PortError::Malformed);
        }
        let connect = MerchantConnectAccount::Platform;
        let customer = self.http.fixture_post(
            "/v1/customers",
            &[
                (
                    "description".into(),
                    "Auths bounded final-capture demo".into(),
                ),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-capture-customer-{workflow_id}"),
            &connect,
        )?;
        let customer_id =
            CustomerId::parse(string(&customer.value, "id")?).map_err(|_| PortError::Malformed)?;
        let method = self.http.fixture_post(
            "/v1/payment_methods",
            &[
                ("type".into(), "card".into()),
                ("card[token]".into(), "tok_visa".into()),
            ],
            &format!("auths-capture-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method_id = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method_id}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-capture-attach-{workflow_id}"),
            &connect,
        )?;
        let authorization = self.http.fixture_post(
            "/v1/payment_intents",
            &[
                ("amount".into(), AUTHORIZED_AMOUNT_MINOR.to_string()),
                ("currency".into(), "usd".into()),
                ("customer".into(), customer_id.to_string()),
                ("payment_method".into(), payment_method_id.to_string()),
                ("payment_method_types[]".into(), "card".into()),
                ("confirm".into(), "true".into()),
                ("confirmation_method".into(), "manual".into()),
                ("capture_method".into(), "manual".into()),
                ("off_session".into(), "false".into()),
                ("error_on_requires_action".into(), "true".into()),
                ("statement_descriptor_suffix".into(), "AUTHS DEMO".into()),
                (
                    "metadata[auths_profile]".into(),
                    auths_stripe::PAYMENT_AUTHORIZE_PROFILE.into(),
                ),
                ("metadata[auths_order_scope]".into(), order_scope.into()),
                ("metadata[auths_workflow]".into(), workflow_id.into()),
                ("expand[]".into(), "latest_charge".into()),
            ],
            &format!("auths-capture-authorization-{workflow_id}"),
            &connect,
        )?;
        let authorization_provider =
            authorization_projection(&authorization.value, authorization.request_id, now)?;
        if authorization_provider.status != "requires_capture"
            || authorization_provider.amount_capturable_minor != AUTHORIZED_AMOUNT_MINOR
            || authorization_provider.amount_received_minor != 0
            || authorization_provider.charge_id.is_none()
            || authorization_provider.capture_before.is_none()
        {
            return Err(PortError::Malformed);
        }
        Ok(CaptureFixture {
            customer_id,
            payment_method_id,
            authorization_provider,
            order_scope: order_scope.into(),
        })
    }

    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError> {
        self.ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .insert(workflow_id.into());
        Ok(())
    }

    fn account_id(&self) -> &StripeAccountId {
        self.http.account_id()
    }

    fn api_version(&self) -> &str {
        self.http.api_version()
    }

    fn execution_mode(&self) -> &'static str {
        "stripe-test-mode"
    }

    fn diagnostics(&self) -> EnvironmentDiagnostics {
        EnvironmentDiagnostics {
            credential_requests: self.credential_requests.load(Ordering::Relaxed),
            provider_calls: self.provider_calls.load(Ordering::Relaxed),
        }
    }
}

impl PaymentCaptureGateway for LivePaymentCaptureEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEvidenceV1, PortError> {
        self.fresh_capture_evidence(command, credential, now)
    }

    fn capture(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEffect, PortError> {
        let request = command.provider_request();
        let parameters = vec![
            (
                "amount_to_capture".into(),
                request.amount_to_capture_minor().to_string(),
            ),
            // `true` is Stripe's default final-capture behavior. Passing the
            // parameter is rejected when multicapture is unavailable, so V1
            // enforces `true` in the action/command and omits the optional
            // wire field. A `false` command cannot be constructed.
            ("metadata[auths_profile]".into(), request.profile().into()),
            (
                "metadata[auths_order_scope]".into(),
                request.order_scope().into(),
            ),
            (
                "metadata[auths_policy]".into(),
                request.policy_digest().into(),
            ),
            (
                "metadata[auths_workflow]".into(),
                request.workflow_id().into(),
            ),
            (
                "metadata[auths_authorization_reservation]".into(),
                request.authorization_reservation_id().into(),
            ),
            (
                "expand[]".into(),
                "latest_charge.balance_transaction".into(),
            ),
        ];
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let response = match self.http.protected_post(
            &format!(
                "/v1/payment_intents/{}/capture",
                request.payment_intent_id()
            ),
            &parameters,
            command.idempotency_key(),
            credential,
            command.action().connect_account(),
        ) {
            Ok(response) => response,
            Err(PortError::Execution) => {
                return Ok(PaymentCaptureEffect::Declined {
                    code: "stripe-capture-declined".into(),
                });
            }
            Err(PortError::OutcomeUnknown) => {
                return Ok(PaymentCaptureEffect::OutcomeUnknown(None));
            }
            Err(error) => return Err(error),
        };
        let provider = capture_projection(
            &response.value,
            response.request_id,
            now,
            "capture-response",
        )?;
        let ambiguous = self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id());
        if ambiguous {
            return Ok(PaymentCaptureEffect::OutcomeUnknown(Some(provider)));
        }
        if provider.status == "succeeded"
            && provider.captured_amount_minor == command.action().amount_to_capture_minor()
        {
            Ok(PaymentCaptureEffect::Accepted(provider))
        } else {
            Ok(PaymentCaptureEffect::OutcomeUnknown(Some(provider)))
        }
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureProviderProjection, PortError> {
        self.retrieve_capture_projection(
            command.action().payment_intent_id(),
            credential,
            command.action().connect_account(),
            now,
        )
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureReconciliationOutcome, PortError> {
        if record.operation() != MerchantOperation::Capture {
            return Err(PortError::Malformed);
        }
        let payment_intent_id = record
            .capture_payment_intent_id()
            .ok_or(PortError::Malformed)?;
        let observed = self.retrieve_capture_projection(
            payment_intent_id,
            credential,
            record.connect_account(),
            now,
        )?;
        if observed.status == "succeeded"
            && observed.captured_amount_minor == record.amount_minor()
            && observed.amount_capturable_minor == 0
            && observed.balance_transaction_id.is_some()
        {
            Ok(PaymentCaptureReconciliationOutcome::Committed(observed))
        } else if observed.status == "requires_capture"
            && observed.captured_amount_minor == 0
            && observed.amount_capturable_minor == record.authorization_release_minor().unwrap_or(0)
        {
            Ok(PaymentCaptureReconciliationOutcome::Released(Some(
                observed,
            )))
        } else {
            Ok(PaymentCaptureReconciliationOutcome::OutcomeUnknown(Some(
                observed,
            )))
        }
    }
}

fn authorization_projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
) -> Result<MerchantProviderProjection, PortError> {
    if boolean(value, "livemode")? {
        return Err(PortError::Malformed);
    }
    let payment_intent_id =
        PaymentIntentId::parse(string(value, "id")?).map_err(|_| PortError::Malformed)?;
    let charge_id = charge_id(value)?;
    let status = string(value, "status")?.to_owned();
    let amount_minor = unsigned(value, "amount")?;
    let currency = Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?;
    let amount_capturable_minor = unsigned(value, "amount_capturable")?;
    let amount_received_minor = unsigned(value, "amount_received")?;
    let capture_before = capture_before(value);
    let sanitized = json!({
        "schema": "auths.stripe.capture-fixture-authorization/1",
        "payment_intent_id": payment_intent_id,
        "charge_id": charge_id,
        "status": status,
        "amount_minor": amount_minor,
        "currency": currency,
        "amount_capturable_minor": amount_capturable_minor,
        "amount_received_minor": amount_received_minor,
        "capture_before": capture_before,
    });
    Ok(MerchantProviderProjection {
        payment_intent_id,
        charge_id,
        status,
        amount_minor,
        currency,
        amount_capturable_minor,
        amount_received_minor,
        capture_before,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: "create-response".into(),
    })
}

fn capture_projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<PaymentCaptureProviderProjection, PortError> {
    if boolean(value, "livemode")? {
        return Err(PortError::Malformed);
    }
    let payment_intent_id =
        PaymentIntentId::parse(string(value, "id")?).map_err(|_| PortError::Malformed)?;
    let charge_id = charge_id(value)?.ok_or(PortError::Malformed)?;
    let balance_transaction_id = value
        .get("latest_charge")
        .and_then(|charge| charge.get("balance_transaction"))
        .and_then(|transaction| {
            transaction
                .as_str()
                .or_else(|| transaction.get("id").and_then(Value::as_str))
        })
        .map(str::to_owned);
    let status = string(value, "status")?.to_owned();
    let authorized_amount_minor = unsigned(value, "amount")?;
    let captured_amount_minor = unsigned(value, "amount_received")?;
    let currency = Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?;
    let amount_capturable_minor = unsigned(value, "amount_capturable")?;
    let capture_before = capture_before(value);
    let sanitized = json!({
        "schema": "auths.stripe.payment-capture-provider-projection/1",
        "payment_intent_id": payment_intent_id,
        "charge_id": charge_id,
        "balance_transaction_id": balance_transaction_id,
        "status": status,
        "authorized_amount_minor": authorized_amount_minor,
        "captured_amount_minor": captured_amount_minor,
        "currency": currency,
        "amount_capturable_minor": amount_capturable_minor,
        "amount_received_minor": captured_amount_minor,
        "capture_before": capture_before,
    });
    Ok(PaymentCaptureProviderProjection {
        payment_intent_id,
        charge_id,
        balance_transaction_id,
        status,
        authorized_amount_minor,
        captured_amount_minor,
        currency,
        amount_capturable_minor,
        amount_received_minor: captured_amount_minor,
        capture_before,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: source.into(),
    })
}

fn charge_id(value: &Value) -> Result<Option<ChargeId>, PortError> {
    value
        .get("latest_charge")
        .and_then(|charge| {
            charge
                .as_str()
                .or_else(|| charge.get("id").and_then(Value::as_str))
        })
        .map(ChargeId::parse)
        .transpose()
        .map_err(|_| PortError::Malformed)
}

fn capture_before(value: &Value) -> Option<u64> {
    value
        .get("latest_charge")
        .and_then(|charge| charge.get("payment_method_details"))
        .and_then(|details| details.get("card"))
        .and_then(|card| card.get("capture_before"))
        .and_then(Value::as_u64)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PortError::Malformed)
}

fn boolean(value: &Value, key: &str) -> Result<bool, PortError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(PortError::Malformed)
}

fn unsigned(value: &Value, key: &str) -> Result<u64, PortError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(PortError::Malformed)
}

fn valid_local(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
