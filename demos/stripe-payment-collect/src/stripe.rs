use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    ChargeId, CredentialProvider, Currency, CustomerId, MerchantConnectAccount, MerchantOperation,
    MerchantPaymentEvidenceInput, MerchantPaymentEvidenceV1, MerchantProviderProjection,
    MerchantReservationRecord, PaymentCollectEffect, PaymentCollectGateway,
    PaymentCollectReconciliationOutcome, PaymentIntentId, PaymentMethodId, PortError,
    PriorMerchantPayment, PriorMerchantPaymentState, StripeAccountId, StripeCredential,
    VerifiedPaymentCollectCommand,
    canonical::{canonical_json, sha256},
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde_json::{Value, json};

/// Fresh fixture returned before an exact collection action is created.
pub struct CollectionFixture {
    /// Protected provider evidence.
    pub evidence: MerchantPaymentEvidenceV1,
    /// Exact protected order identity.
    pub order_scope: String,
}

/// Public diagnostic counters contain no credential or response data.
#[derive(Clone, Copy, Debug)]
pub struct EnvironmentDiagnostics {
    /// Credential broker invocations after durable claim.
    pub credential_requests: u64,
    /// Protected Stripe calls after credential acquisition.
    pub provider_calls: u64,
}

/// Collection-specific provider surface used by the application.
pub trait DemoPaymentCollectEnvironment:
    CredentialProvider + PaymentCollectGateway + Send + Sync
{
    /// Creates one Customer and attached test PaymentMethod.
    fn seed_collection(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CollectionFixture, PortError>;

    /// Arms one lost-response experiment after actual Stripe delivery.
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

/// Real Stripe test-mode collection environment.
pub struct LivePaymentCollectEnvironment {
    http: StripeHttp,
    ambiguous_once: Mutex<HashSet<String>>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
}

impl LivePaymentCollectEnvironment {
    /// Loads the established ignored `.env` secret path and strict deployment
    /// configuration.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_PAYMENT_COLLECT_SECRET_KEY")?,
            ambiguous_once: Mutex::new(HashSet::new()),
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
        })
    }

    fn protected_get(
        &self,
        path: &str,
        credential: &StripeCredential,
        connect: &MerchantConnectAccount,
    ) -> Result<auths_stripe_payment_demo_common::StripeHttpResponse, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        self.http.protected_get(path, credential, connect)
    }

    fn evidence(
        &self,
        customer_id: &CustomerId,
        payment_method_id: &PaymentMethodId,
        order_scope: &str,
        connect: &MerchantConnectAccount,
        credential: Option<&StripeCredential>,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError> {
        let payment_method_path = format!("/v1/payment_methods/{payment_method_id}");
        let payment_method = match credential {
            Some(credential) => {
                self.protected_get(&payment_method_path, credential, connect)?
                    .value
            }
            None => self.http.fixture_get(&payment_method_path, connect)?.value,
        };
        let attached_customer_id = PaymentMethodId::parse(string(&payment_method, "id")?)
            .map_err(|_| PortError::Malformed)?;
        if &attached_customer_id != payment_method_id {
            return Err(PortError::Malformed);
        }
        let attached_customer = payment_method
            .get("customer")
            .and_then(Value::as_str)
            .ok_or(PortError::Malformed)
            .and_then(|value| CustomerId::parse(value).map_err(|_| PortError::Malformed))?;
        let payment_method_type = string(&payment_method, "type")?.to_owned();
        let livemode = boolean(&payment_method, "livemode")?;
        let list_path = format!("/v1/payment_intents?customer={customer_id}&limit=100");
        let list = match credential {
            Some(credential) => self.protected_get(&list_path, credential, connect)?.value,
            None => self.http.fixture_get(&list_path, connect)?.value,
        };
        let prior_payments = prior_payments(&list, order_scope)?;
        let sanitized = json!({
            "schema": "auths.stripe.payment-evidence-source/1",
            "customer_id": customer_id,
            "payment_method_id": payment_method_id,
            "payment_method_type": payment_method_type,
            "attached_customer_id": attached_customer,
            "livemode": livemode,
            "order_scope": order_scope,
            "prior_payments": prior_payments,
        });
        let response_commitment =
            sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?);
        MerchantPaymentEvidenceV1::new(MerchantPaymentEvidenceInput {
            stripe_account_id: self.http.account_id().clone(),
            connect_account: connect.clone(),
            customer_id: customer_id.clone(),
            payment_method_id: payment_method_id.clone(),
            payment_method_type,
            attached_customer_id: attached_customer,
            livemode,
            stripe_api_version: self.http.api_version().into(),
            order_scope: order_scope.into(),
            consent_order_commitment: consent_order_commitment(order_scope),
            supports_manual_capture: true,
            prior_payments,
            observed_at: now,
            source: "stripe-api-and-order-store".into(),
            response_commitment,
        })
        .map_err(|_| PortError::Malformed)
    }

    fn retrieve_projection(
        &self,
        payment_intent_id: &PaymentIntentId,
        credential: &StripeCredential,
        connect: &MerchantConnectAccount,
        now: u64,
    ) -> Result<MerchantProviderProjection, PortError> {
        let response = self.protected_get(
            &format!("/v1/payment_intents/{payment_intent_id}?expand[]=latest_charge"),
            credential,
            connect,
        )?;
        projection(&response.value, response.request_id, now, "retrieve")
    }
}

impl CredentialProvider for LivePaymentCollectEnvironment {
    fn mutation_credential(
        &self,
        account: &StripeAccountId,
    ) -> Result<StripeCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.mutation_credential(account)
    }
}

impl DemoPaymentCollectEnvironment for LivePaymentCollectEnvironment {
    fn seed_collection(
        &self,
        workflow_id: &str,
        order_scope: &str,
        now: u64,
    ) -> Result<CollectionFixture, PortError> {
        if !valid_local(workflow_id) || !valid_local(order_scope) {
            return Err(PortError::Malformed);
        }
        let connect = MerchantConnectAccount::Platform;
        let customer = self.http.fixture_post(
            "/v1/customers",
            &[
                ("description".into(), "Auths bounded collection demo".into()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-customer-{workflow_id}"),
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
            &format!("auths-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method_id = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method_id}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-attach-{workflow_id}"),
            &connect,
        )?;
        let evidence = self.evidence(
            &customer_id,
            &payment_method_id,
            order_scope,
            &connect,
            None,
            now,
        )?;
        Ok(CollectionFixture {
            evidence,
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

impl PaymentCollectGateway for LivePaymentCollectEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<MerchantPaymentEvidenceV1, PortError> {
        self.evidence(
            command.action().customer_id(),
            command.action().payment_method_id(),
            command.action().order_scope(),
            command.action().connect_account(),
            Some(credential),
            now,
        )
    }

    fn collect(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<PaymentCollectEffect, PortError> {
        let action = command.action();
        let parameters = vec![
            ("amount".into(), action.amount_minor().to_string()),
            ("currency".into(), action.currency().to_string()),
            ("customer".into(), action.customer_id().to_string()),
            (
                "payment_method".into(),
                action.payment_method_id().to_string(),
            ),
            (
                "payment_method_types[]".into(),
                action.payment_method_type().into(),
            ),
            ("confirm".into(), "true".into()),
            (
                "confirmation_method".into(),
                action.confirmation_method().into(),
            ),
            ("capture_method".into(), action.capture_method().into()),
            ("off_session".into(), "false".into()),
            ("error_on_requires_action".into(), "true".into()),
            (
                "statement_descriptor_suffix".into(),
                command.statement_descriptor().into(),
            ),
            ("metadata[auths_profile]".into(), action.profile().into()),
            (
                "metadata[auths_order_scope]".into(),
                action.order_scope().into(),
            ),
            (
                "metadata[auths_policy]".into(),
                command.policy_digest().to_string(),
            ),
            (
                "metadata[auths_workflow]".into(),
                command.workflow_id().into(),
            ),
            ("expand[]".into(), "latest_charge".into()),
        ];
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let response = match self.http.protected_post(
            "/v1/payment_intents",
            &parameters,
            command.idempotency_key(),
            credential,
            action.connect_account(),
        ) {
            Ok(response) => response,
            Err(PortError::Execution) => {
                return Ok(PaymentCollectEffect::Declined {
                    code: "stripe-declined".into(),
                });
            }
            Err(PortError::OutcomeUnknown) => {
                return Ok(PaymentCollectEffect::OutcomeUnknown(None));
            }
            Err(error) => return Err(error),
        };
        let provider = projection(&response.value, response.request_id, now, "create-response")?;
        let ambiguous = self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id());
        if ambiguous {
            return Ok(PaymentCollectEffect::OutcomeUnknown(Some(provider)));
        }
        Ok(match provider.status.as_str() {
            "succeeded" => PaymentCollectEffect::Accepted(provider),
            "processing" => PaymentCollectEffect::Processing(provider),
            "requires_action" => PaymentCollectEffect::CustomerActionRequired(provider),
            "requires_payment_method" | "canceled" => PaymentCollectEffect::Declined {
                code: "stripe-declined".into(),
            },
            _ => PaymentCollectEffect::OutcomeUnknown(Some(provider)),
        })
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCollectCommand,
        credential: &StripeCredential,
        payment_intent: &PaymentIntentId,
        now: u64,
    ) -> Result<MerchantProviderProjection, PortError> {
        self.retrieve_projection(
            payment_intent,
            credential,
            command.action().connect_account(),
            now,
        )
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<PaymentCollectReconciliationOutcome, PortError> {
        if record.operation() != MerchantOperation::Collect {
            return Err(PortError::Malformed);
        }
        if let Some(provider) = record.provider() {
            let observed = self.retrieve_projection(
                &provider.payment_intent_id,
                credential,
                record.connect_account(),
                now,
            )?;
            return Ok(reconciled_collection(observed));
        }
        let response = self.protected_get(
            &format!(
                "/v1/payment_intents?customer={}&limit=100",
                record.customer_id()
            ),
            credential,
            record.connect_account(),
        )?;
        let found = data(&response.value)?.iter().find(|payment_intent| {
            metadata(payment_intent, "auths_workflow") == Some(record.workflow_id())
                && metadata(payment_intent, "auths_order_scope") == Some(record.order_scope())
                && metadata(payment_intent, "auths_profile") == Some(record.exact_action_profile())
                && metadata(payment_intent, "auths_policy") == Some(record.policy_digest().as_str())
        });
        let Some(found) = found else {
            return Ok(PaymentCollectReconciliationOutcome::Released(None));
        };
        let payment_intent_id =
            PaymentIntentId::parse(string(found, "id")?).map_err(|_| PortError::Malformed)?;
        let observed = self.retrieve_projection(
            &payment_intent_id,
            credential,
            record.connect_account(),
            now,
        )?;
        Ok(reconciled_collection(observed))
    }
}

fn reconciled_collection(
    provider: MerchantProviderProjection,
) -> PaymentCollectReconciliationOutcome {
    match provider.status.as_str() {
        "succeeded" => PaymentCollectReconciliationOutcome::Committed(provider),
        "requires_payment_method" | "canceled" => {
            PaymentCollectReconciliationOutcome::Released(Some(provider))
        }
        _ => PaymentCollectReconciliationOutcome::OutcomeUnknown(Some(provider)),
    }
}

fn projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<MerchantProviderProjection, PortError> {
    if boolean(value, "livemode")? {
        return Err(PortError::Malformed);
    }
    let payment_intent_id =
        PaymentIntentId::parse(string(value, "id")?).map_err(|_| PortError::Malformed)?;
    let latest_charge = value.get("latest_charge");
    let charge_id = latest_charge
        .and_then(|charge| {
            charge
                .as_str()
                .or_else(|| charge.get("id").and_then(Value::as_str))
        })
        .map(ChargeId::parse)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    let amount_minor = unsigned(value, "amount")?;
    let amount_capturable_minor = unsigned(value, "amount_capturable")?;
    let amount_received_minor = unsigned(value, "amount_received")?;
    let currency = Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?;
    let status = string(value, "status")?.to_owned();
    let sanitized = json!({
        "schema": "auths.stripe.payment-intent-projection/1",
        "payment_intent_id": payment_intent_id,
        "charge_id": charge_id,
        "status": status,
        "amount_minor": amount_minor,
        "currency": currency,
        "amount_capturable_minor": amount_capturable_minor,
        "amount_received_minor": amount_received_minor,
    });
    Ok(MerchantProviderProjection {
        payment_intent_id,
        charge_id,
        status,
        amount_minor,
        currency,
        amount_capturable_minor,
        amount_received_minor,
        capture_before: None,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: source.into(),
    })
}

fn prior_payments(
    value: &Value,
    order_scope: &str,
) -> Result<Vec<PriorMerchantPayment>, PortError> {
    data(value)?
        .iter()
        .filter(|payment_intent| metadata(payment_intent, "auths_order_scope") == Some(order_scope))
        .map(|payment_intent| {
            let profile = metadata(payment_intent, "auths_profile").ok_or(PortError::Malformed)?;
            let operation = match profile {
                auths_stripe::PAYMENT_COLLECT_PROFILE => MerchantOperation::Collect,
                auths_stripe::PAYMENT_AUTHORIZE_PROFILE => MerchantOperation::Authorize,
                _ => return Err(PortError::Malformed),
            };
            let state = match string(payment_intent, "status")? {
                "succeeded" => PriorMerchantPaymentState::Succeeded,
                "requires_capture" => PriorMerchantPaymentState::RequiresCapture,
                "processing" => PriorMerchantPaymentState::Processing,
                "canceled" => PriorMerchantPaymentState::Canceled,
                "requires_payment_method" => PriorMerchantPaymentState::Failed,
                _ => PriorMerchantPaymentState::OutcomeUnknown,
            };
            PriorMerchantPayment::new(
                Some(
                    PaymentIntentId::parse(string(payment_intent, "id")?)
                        .map_err(|_| PortError::Malformed)?,
                ),
                order_scope,
                operation,
                state,
                unsigned(payment_intent, "amount")?,
                Currency::parse(string(payment_intent, "currency")?)
                    .map_err(|_| PortError::Malformed)?,
                None,
            )
            .map_err(|_| PortError::Malformed)
        })
        .collect()
}

fn consent_order_commitment(order_scope: &str) -> auths_stripe::DigestHex {
    sha256(format!("auths-order-consent-v1:{order_scope}").as_bytes())
}

fn metadata<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
}

fn data(value: &Value) -> Result<&[Value], PortError> {
    value
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(PortError::Malformed)
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
