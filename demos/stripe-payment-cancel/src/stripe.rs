use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    ChargeId, CredentialProvider, Currency, CustomerId, MerchantConnectAccount, MerchantOperation,
    MerchantProviderProjection, MerchantReservationRecord, PaymentCancelCredential,
    PaymentCancelCredentialScope, PaymentCancelEffect, PaymentCancelEvidenceInput,
    PaymentCancelEvidenceV1, PaymentCancelGateway, PaymentCancelProviderProjection,
    PaymentCancelReconciliationOutcome, PaymentCancellationReason, PaymentIntentId,
    PaymentMethodId, PortError, StripeAccountId, VerifiedPaymentCancelCommand,
    canonical::{canonical_json, sha256},
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde_json::{Value, json};

const AUTHORIZED_AMOUNT_MINOR: u64 = 1_000;

/// Real manual-cancel authorization created as repository-owned session setup.
pub struct CancellationFixture {
    /// Stripe Customer.
    pub customer_id: CustomerId,
    /// Attached test `PaymentMethod`.
    pub payment_method_id: PaymentMethodId,
    /// Exact pre-cancel `PaymentIntent` and Charge projection.
    pub authorization_provider: MerchantProviderProjection,
    /// Exact protected order.
    pub order_scope: String,
}

/// Public diagnostic counters contain no credential or response data.
#[derive(Clone, Copy, Debug)]
pub struct EnvironmentDiagnostics {
    /// Cancellation credential broker invocations after durable claim.
    pub credential_requests: u64,
    /// Protected Stripe reads/writes after cancel credential acquisition.
    pub provider_calls: u64,
}

/// Cancellation-specific provider surface used by the application.
pub trait DemoPaymentCancelEnvironment:
    CredentialProvider<PaymentCancelCredentialScope> + PaymentCancelGateway + Send + Sync
{
    /// Creates a repository-owned manual-cancel authorization fixture.
    ///
    /// # Errors
    ///
    /// Returns an error when fixture creation or projection fails.
    fn seed_cancel(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CancellationFixture, PortError>;

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

/// Real Stripe test-mode payment-cancellation environment.
pub struct LivePaymentCancelEnvironment {
    http: StripeHttp<PaymentCancelCredentialScope>,
    ambiguous_once: Mutex<HashSet<String>>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
}

impl LivePaymentCancelEnvironment {
    /// Loads strict Stripe test-mode deployment configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when fixture or cancel credentials are unavailable.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_PAYMENT_CANCEL_SECRET_KEY")?,
            ambiguous_once: Mutex::new(HashSet::new()),
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
        })
    }

    fn protected_get(
        &self,
        path: &str,
        credential: &PaymentCancelCredential,
        connect: &MerchantConnectAccount,
    ) -> Result<auths_stripe_payment_demo_common::StripeHttpResponse, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        self.http.protected_get(path, credential, connect)
    }

    fn retrieve_cancel_projection(
        &self,
        payment_intent_id: &PaymentIntentId,
        credential: &PaymentCancelCredential,
        connect: &MerchantConnectAccount,
        now: u64,
    ) -> Result<PaymentCancelProviderProjection, PortError> {
        let response = self.protected_get(
            &format!(
                "/v1/payment_intents/{payment_intent_id}?expand[]=latest_charge.balance_transaction"
            ),
            credential,
            connect,
        )?;
        cancel_projection(&response.value, response.request_id, now, "retrieve")
    }

    fn fresh_cancel_evidence(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEvidenceV1, PortError> {
        let response = self.protected_get(
            &format!(
                "/v1/payment_intents/{}?expand[]=latest_charge",
                command.action().payment_intent_id()
            ),
            credential,
            command.action().connect_account(),
        )?;
        let provider = authorization_projection(&response.value, response.request_id, now)?;
        PaymentCancelEvidenceV1::new(PaymentCancelEvidenceInput {
            stripe_account_id: command.action().stripe_account_id().clone(),
            connect_account: command.action().connect_account().clone(),
            payment_intent_id: provider.payment_intent_id,
            latest_charge_id: provider.charge_id,
            customer_id: command.action().customer_id().clone(),
            order_scope: command.action().order_scope().into(),
            amount_minor: provider.amount_minor,
            amount_capturable_minor: provider.amount_capturable_minor,
            currency: provider.currency,
            payment_intent_status: provider.status,
            cancellation_eligible: true,
            livemode: false,
            stripe_api_version: self.http.api_version().into(),
            authorization_workflow_id: command
                .evidence()
                .authorization_workflow_id()
                .map(str::to_owned),
            authorization_action_digest: command.evidence().authorization_action_digest().cloned(),
            authorization_reservation_id: command
                .evidence()
                .authorization_reservation_id()
                .cloned(),
            authorization_state: command.evidence().authorization_state(),
            authorization_created_at: command.evidence().authorization_created_at(),
            observed_at: now,
            source: "retrieve".into(),
            response_commitment: provider.response_digest,
        })
        .map_err(|_| PortError::Malformed)
    }
}

impl CredentialProvider<PaymentCancelCredentialScope> for LivePaymentCancelEnvironment {
    fn credential(&self, account: &StripeAccountId) -> Result<PaymentCancelCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.credential(account)
    }
}

impl DemoPaymentCancelEnvironment for LivePaymentCancelEnvironment {
    fn seed_cancel(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CancellationFixture, PortError> {
        if !valid_local(workflow_id) || !valid_local(order_scope) {
            return Err(PortError::Malformed);
        }
        let connect = MerchantConnectAccount::Platform;
        let customer = self.http.fixture_post(
            "/v1/customers",
            &[
                (
                    "description".into(),
                    "Auths bounded payment-cancellation demo".into(),
                ),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-cancel-customer-{workflow_id}"),
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
            &format!("auths-cancel-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method_id = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method_id}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-cancel-attach-{workflow_id}"),
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
            &format!("auths-cancel-authorization-{workflow_id}"),
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
        Ok(CancellationFixture {
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

impl PaymentCancelGateway for LivePaymentCancelEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEvidenceV1, PortError> {
        self.fresh_cancel_evidence(command, credential, now)
    }

    fn cancel(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEffect, PortError> {
        let request = command.provider_request();
        let parameters = vec![(
            "cancellation_reason".into(),
            request.cancellation_reason().as_str().into(),
        )];
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let response = match self.http.protected_post(
            &format!("/v1/payment_intents/{}/cancel", request.payment_intent_id()),
            &parameters,
            command.idempotency_key(),
            credential,
            command.action().connect_account(),
        ) {
            Ok(response) => response,
            Err(PortError::Execution) => {
                return Ok(PaymentCancelEffect::Declined {
                    code: "stripe-cancel-declined".into(),
                });
            }
            Err(PortError::OutcomeUnknown) => {
                return Ok(PaymentCancelEffect::OutcomeUnknown(None));
            }
            Err(error) => return Err(error),
        };
        let provider =
            cancel_projection(&response.value, response.request_id, now, "cancel-response")?;
        let ambiguous = self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id());
        if ambiguous {
            return Ok(PaymentCancelEffect::OutcomeUnknown(Some(provider)));
        }
        if provider.status == "canceled"
            && provider.cancellation_reason == Some(command.action().cancellation_reason())
        {
            Ok(PaymentCancelEffect::Accepted(provider))
        } else if provider.status == "succeeded" || provider.charge_captured == Some(true) {
            Ok(PaymentCancelEffect::CaptureConflict(provider))
        } else {
            Ok(PaymentCancelEffect::OutcomeUnknown(Some(provider)))
        }
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelProviderProjection, PortError> {
        self.retrieve_cancel_projection(
            command.action().payment_intent_id(),
            credential,
            command.action().connect_account(),
            now,
        )
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelReconciliationOutcome, PortError> {
        if record.operation() != MerchantOperation::Cancel {
            return Err(PortError::Malformed);
        }
        let payment_intent_id = record
            .cancel_payment_intent_id()
            .ok_or(PortError::Malformed)?;
        let observed = self.retrieve_cancel_projection(
            payment_intent_id,
            credential,
            record.connect_account(),
            now,
        )?;
        if observed.status == "canceled"
            && observed.cancellation_reason == record.cancellation_reason()
            && observed.amount_capturable_minor == 0
            && observed.amount_received_minor == 0
        {
            Ok(PaymentCancelReconciliationOutcome::Canceled(observed))
        } else if observed.status == "succeeded" || observed.charge_captured == Some(true) {
            Ok(PaymentCancelReconciliationOutcome::CaptureConflict(
                observed,
            ))
        } else if observed.status == record.cancel_pre_status().ok_or(PortError::Malformed)?
            && observed.amount_received_minor == 0
            && observed.amount_capturable_minor == record.authorization_release_minor().unwrap_or(0)
        {
            Ok(PaymentCancelReconciliationOutcome::Released(Some(observed)))
        } else {
            Ok(PaymentCancelReconciliationOutcome::OutcomeUnknown(Some(
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
        "schema": "auths.stripe.cancel-fixture-authorization/1",
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

fn cancel_projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<PaymentCancelProviderProjection, PortError> {
    if boolean(value, "livemode")? {
        return Err(PortError::Malformed);
    }
    let payment_intent_id =
        PaymentIntentId::parse(string(value, "id")?).map_err(|_| PortError::Malformed)?;
    let latest_charge_id = charge_id(value)?;
    let status = string(value, "status")?.to_owned();
    let amount_minor = unsigned(value, "amount")?;
    let amount_received_minor = unsigned(value, "amount_received")?;
    let currency = Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?;
    let amount_capturable_minor = unsigned(value, "amount_capturable")?;
    let cancellation_reason = value
        .get("cancellation_reason")
        .and_then(Value::as_str)
        .map(parse_cancellation_reason)
        .transpose()?;
    let charge_captured = value
        .get("latest_charge")
        .filter(|charge| !charge.is_null())
        .and_then(|charge| charge.get("captured"))
        .and_then(Value::as_bool);
    let sanitized = json!({
        "schema": "auths.stripe.payment-cancel-provider-projection/1",
        "payment_intent_id": payment_intent_id,
        "latest_charge_id": latest_charge_id,
        "status": status,
        "cancellation_reason": cancellation_reason,
        "amount_minor": amount_minor,
        "currency": currency,
        "amount_capturable_minor": amount_capturable_minor,
        "amount_received_minor": amount_received_minor,
        "charge_captured": charge_captured,
    });
    Ok(PaymentCancelProviderProjection {
        payment_intent_id,
        latest_charge_id,
        status,
        cancellation_reason,
        amount_minor,
        currency,
        amount_capturable_minor,
        amount_received_minor,
        charge_captured,
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

fn parse_cancellation_reason(value: &str) -> Result<PaymentCancellationReason, PortError> {
    match value {
        "duplicate" => Ok(PaymentCancellationReason::Duplicate),
        "fraudulent" => Ok(PaymentCancellationReason::Fraudulent),
        "requested_by_customer" => Ok(PaymentCancellationReason::RequestedByCustomer),
        "abandoned" => Ok(PaymentCancellationReason::Abandoned),
        _ => Err(PortError::Malformed),
    }
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
