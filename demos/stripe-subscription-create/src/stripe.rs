use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    CredentialProvider, CustomerId, InMemoryPaymentMandateStore, InvoiceId, MandateAmountType,
    MandateConnectAccount, MandateId, MandateInterval, MandateUsage, PaymentIntentId,
    PaymentMandateCapabilityState, PaymentMandateObservationReceipt,
    PaymentMandateProviderProjection, PaymentMandateReceipt, PaymentMandateStore, PaymentMethodId,
    PortError, PriceId, ProductId, ReservePaymentMandateRequest, ReservePaymentMandateResult,
    SetupAttemptId, SetupIntentId, StripeAccountId, StripeExactPaymentMandateInput,
    StripeExactPaymentMandateV1, SubscriptionCatalogItemEvidence, SubscriptionConnectAccount,
    SubscriptionCreateCredential, SubscriptionCreateCredentialScope, SubscriptionCreateEffect,
    SubscriptionCreateEvidenceV1, SubscriptionCreateGateway,
    SubscriptionCreateReconciliationOutcome, SubscriptionId, SubscriptionInterval,
    SubscriptionLiabilityRecord, SubscriptionPaymentBehavior, SubscriptionPreviewLine,
    SubscriptionProviderProjection, TestClockId, VerifiedSubscriptionCreateCommand,
    canonical::{canonical_digest, canonical_json, sha256},
    merchant::MerchantConnectAccount,
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde::Serialize;
use serde_json::{Value, json};

const WEEK_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Repository-owned Stripe test-clock fixture and typed mandate dependency.
pub struct SubscriptionFixture {
    pub evidence: SubscriptionCreateEvidenceV1,
    pub billing_cycle_anchor: u64,
    pub cancel_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct EnvironmentDiagnostics {
    pub credential_requests: u64,
    pub provider_calls: u64,
}

pub trait DemoSubscriptionCreateEnvironment:
    SubscriptionCreateGateway + CredentialProvider<SubscriptionCreateCredentialScope> + Send + Sync
{
    /// Creates repository-owned Customer, Price, clock, preview, and mandate evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed provider or evidence failure.
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<SubscriptionFixture, PortError>;
    /// Arms a single post-create lost-response simulation.
    ///
    /// # Errors
    ///
    /// Returns a closed state failure.
    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError>;
    /// Advances only a repository-owned test clock.
    ///
    /// # Errors
    ///
    /// Returns a closed provider failure.
    fn advance_clock(&self, test_clock: &TestClockId, frozen_time: u64)
    -> Result<Value, PortError>;
    /// Reads one sanitized repository-owned subscription timeline.
    ///
    /// # Errors
    ///
    /// Returns a closed provider or evidence failure.
    fn timeline(
        &self,
        subscription: &SubscriptionId,
        now: u64,
    ) -> Result<SubscriptionProviderProjection, PortError>;
    fn account_id(&self) -> &StripeAccountId;
    fn api_version(&self) -> &str;
    fn diagnostics(&self) -> EnvironmentDiagnostics;
}

pub struct LiveSubscriptionCreateEnvironment {
    http: StripeHttp<SubscriptionCreateCredentialScope>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
    ambiguous_once: Mutex<BTreeSet<String>>,
}

impl LiveSubscriptionCreateEnvironment {
    /// Loads test-only fixture and create-scoped credentials.
    ///
    /// # Errors
    ///
    /// Rejects missing or unsafe environment/provider configuration.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_SUBSCRIPTION_CREATE_SECRET_KEY")?,
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
            ambiguous_once: Mutex::new(BTreeSet::new()),
        })
    }

    fn create_evidence(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEvidenceV1, PortError> {
        let action = command.action();
        let connect = MerchantConnectAccount::Platform;
        let price_response = self.http.protected_get(
            &format!(
                "/v1/prices/{}?expand[]=product",
                action.items()[0].price_id()
            ),
            credential,
            &connect,
        )?;
        let preview = self.preview(
            action.customer_id(),
            action.items()[0].price_id(),
            action.items()[0].quantity(),
            action.cancel_at(),
            Some(credential),
            command.idempotency_key(),
        )?;
        let subscriptions = self.http.protected_get(
            &format!(
                "/v1/subscriptions?customer={}&status=all&limit=100",
                action.customer_id()
            ),
            credential,
            &connect,
        )?;
        evidence_from_values(
            action.stripe_account_id().clone(),
            action.customer_id().clone(),
            action.default_payment_method_id().clone(),
            action.test_clock_id().clone(),
            command.evidence().mandate_action.clone(),
            command.evidence().mandate_capability.clone(),
            command.evidence().mandate_receipt.clone(),
            price_response.value,
            preview,
            subscriptions.value,
            action.billing_cycle_anchor(),
            action.cancel_at(),
            self.api_version(),
            now,
        )
    }

    fn preview(
        &self,
        customer: &CustomerId,
        price: &PriceId,
        quantity: u32,
        cancel_at: u64,
        credential: Option<&SubscriptionCreateCredential>,
        key: &str,
    ) -> Result<Value, PortError> {
        let parameters = vec![
            ("customer".into(), customer.to_string()),
            (
                "subscription_details[items][0][price]".into(),
                price.to_string(),
            ),
            (
                "subscription_details[items][0][quantity]".into(),
                quantity.to_string(),
            ),
            (
                "subscription_details[billing_cycle_anchor]".into(),
                "now".into(),
            ),
            (
                "subscription_details[cancel_at]".into(),
                cancel_at.to_string(),
            ),
            (
                "subscription_details[proration_behavior]".into(),
                "none".into(),
            ),
            ("automatic_tax[enabled]".into(), "false".into()),
        ];
        let response = match credential {
            Some(value) => self.http.protected_post(
                "/v1/invoices/create_preview",
                &parameters,
                &format!("{key}-preview"),
                value,
                &MerchantConnectAccount::Platform,
            )?,
            None => self.http.fixture_post(
                "/v1/invoices/create_preview",
                &parameters,
                &format!("{key}-preview"),
                &MerchantConnectAccount::Platform,
            )?,
        };
        Ok(response.value)
    }

    fn retrieve(
        &self,
        subscription_id: &SubscriptionId,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionProviderProjection, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let response = self.http.protected_get(
            &format!("/v1/subscriptions/{subscription_id}?expand[]=latest_invoice.payment_intent"),
            credential,
            &MerchantConnectAccount::Platform,
        )?;
        projection(
            &response.value,
            response.request_id,
            now,
            "subscription-retrieve",
        )
    }
}

impl CredentialProvider<SubscriptionCreateCredentialScope> for LiveSubscriptionCreateEnvironment {
    fn credential(
        &self,
        account: &StripeAccountId,
    ) -> Result<SubscriptionCreateCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.credential(account)
    }
}

impl DemoSubscriptionCreateEnvironment for LiveSubscriptionCreateEnvironment {
    #[allow(
        clippy::too_many_lines,
        reason = "all repository-owned Stripe fixture objects stay explicit"
    )]
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<SubscriptionFixture, PortError> {
        let connect = MerchantConnectAccount::Platform;
        let clock_response = self.http.fixture_post(
            "/v1/test_helpers/test_clocks",
            &[
                ("frozen_time".into(), now.to_string()),
                ("name".into(), format!("Auths {workflow_id}")),
            ],
            &format!("auths-sub-clock-{workflow_id}"),
            &connect,
        )?;
        let test_clock_id = TestClockId::parse(string(&clock_response.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        let frozen_time = integer(&clock_response.value, "frozen_time")?;
        let billing_cycle_anchor = frozen_time;
        let cancel_at = frozen_time
            .checked_add(3 * WEEK_SECONDS)
            .ok_or(PortError::Malformed)?;

        let customer_response = self.http.fixture_post(
            "/v1/customers",
            &[
                (
                    "description".into(),
                    "Auths bounded subscription demo".into(),
                ),
                ("test_clock".into(), test_clock_id.to_string()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-sub-customer-{workflow_id}"),
            &connect,
        )?;
        let customer_id = CustomerId::parse(string(&customer_response.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        let method_response = self.http.fixture_post(
            "/v1/payment_methods",
            &[
                ("type".into(), "card".into()),
                ("card[token]".into(), "tok_visa".into()),
            ],
            &format!("auths-sub-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method_id = PaymentMethodId::parse(string(&method_response.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method_id}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-sub-attach-{workflow_id}"),
            &connect,
        )?;
        let product_response = self.http.fixture_post(
            "/v1/products",
            &[
                ("name".into(), "Auths bounded weekly membership".into()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-sub-product-{workflow_id}"),
            &connect,
        )?;
        let product_id = ProductId::parse(string(&product_response.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        let price_response = self.http.fixture_post(
            "/v1/prices",
            &[
                ("currency".into(), "usd".into()),
                ("unit_amount".into(), "500".into()),
                ("recurring[interval]".into(), "week".into()),
                ("recurring[interval_count]".into(), "1".into()),
                ("recurring[usage_type]".into(), "licensed".into()),
                ("product".into(), product_id.to_string()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-sub-price-{workflow_id}"),
            &connect,
        )?;
        let price_id = PriceId::parse(string(&price_response.value, "id")?)
            .map_err(|_| PortError::Malformed)?;

        let setup = self.http.fixture_post(
            "/v1/setup_intents",
            &[
                ("customer".into(), customer_id.to_string()),
                ("payment_method".into(), payment_method_id.to_string()),
                ("usage".into(), "off_session".into()),
                ("confirm".into(), "true".into()),
                ("payment_method_types[0]".into(), "card".into()),
                (
                    "metadata[auths_workflow_id]".into(),
                    format!("{workflow_id}-mandate"),
                ),
            ],
            &format!("auths-sub-mandate-{workflow_id}"),
            &connect,
        )?;
        let mandate = typed_mandate(
            self.account_id().clone(),
            customer_id.clone(),
            payment_method_id.clone(),
            &setup.value,
            setup.request_id,
            workflow_id,
            self.api_version(),
            now,
        )?;

        let preview = self.preview(
            &customer_id,
            &price_id,
            1,
            cancel_at,
            None,
            &format!("auths-sub-seed-{workflow_id}"),
        )?;
        let subscriptions = self.http.fixture_get(
            &format!("/v1/subscriptions?customer={customer_id}&status=all&limit=100"),
            &connect,
        )?;
        let evidence = evidence_from_values(
            self.account_id().clone(),
            customer_id,
            payment_method_id,
            test_clock_id,
            mandate.action,
            mandate.capability,
            mandate.receipt,
            price_response.value,
            preview,
            subscriptions.value,
            billing_cycle_anchor,
            cancel_at,
            self.api_version(),
            now,
        )?;
        Ok(SubscriptionFixture {
            evidence,
            billing_cycle_anchor,
            cancel_at,
        })
    }

    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError> {
        self.ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .insert(workflow_id.into());
        Ok(())
    }

    fn advance_clock(
        &self,
        test_clock: &TestClockId,
        frozen_time: u64,
    ) -> Result<Value, PortError> {
        Ok(self
            .http
            .fixture_post(
                &format!("/v1/test_helpers/test_clocks/{test_clock}/advance"),
                &[("frozen_time".into(), frozen_time.to_string())],
                &format!("auths-sub-advance-{test_clock}-{frozen_time}"),
                &MerchantConnectAccount::Platform,
            )?
            .value)
    }

    fn timeline(
        &self,
        subscription: &SubscriptionId,
        now: u64,
    ) -> Result<SubscriptionProviderProjection, PortError> {
        let response = self.http.fixture_get(
            &format!("/v1/subscriptions/{subscription}?expand[]=latest_invoice.payment_intent"),
            &MerchantConnectAccount::Platform,
        )?;
        projection(
            &response.value,
            response.request_id,
            now,
            "test-clock-timeline",
        )
    }

    fn account_id(&self) -> &StripeAccountId {
        self.http.account_id()
    }
    fn api_version(&self) -> &str {
        self.http.api_version()
    }
    fn diagnostics(&self) -> EnvironmentDiagnostics {
        EnvironmentDiagnostics {
            credential_requests: self.credential_requests.load(Ordering::Relaxed),
            provider_calls: self.provider_calls.load(Ordering::Relaxed),
        }
    }
}

impl SubscriptionCreateGateway for LiveSubscriptionCreateEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEvidenceV1, PortError> {
        self.create_evidence(command, credential, now)
    }

    fn create(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEffect, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let action = command.action();
        let mut parameters = vec![
            ("customer".into(), action.customer_id().to_string()),
            (
                "items[0][price]".into(),
                action.items()[0].price_id().to_string(),
            ),
            (
                "items[0][quantity]".into(),
                action.items()[0].quantity().to_string(),
            ),
            ("collection_method".into(), "charge_automatically".into()),
            (
                "default_payment_method".into(),
                action.default_payment_method_id().to_string(),
            ),
            (
                "payment_behavior".into(),
                payment_behavior(action.payment_behavior()).into(),
            ),
            ("proration_behavior".into(), "none".into()),
            ("automatic_tax[enabled]".into(), "false".into()),
            ("cancel_at".into(), action.cancel_at().to_string()),
            (
                "metadata[auths_workflow_id]".into(),
                command.workflow_id().into(),
            ),
            (
                "metadata[auths_action_digest]".into(),
                command.liability().action_digest().to_string(),
            ),
            ("expand[0]".into(), "latest_invoice.payment_intent".into()),
        ];
        for (index, _) in action.items().iter().enumerate().skip(1) {
            parameters.push((
                format!("items[{index}][price]"),
                action.items()[index].price_id().to_string(),
            ));
            parameters.push((
                format!("items[{index}][quantity]"),
                action.items()[index].quantity().to_string(),
            ));
        }
        let response = self.http.protected_post(
            "/v1/subscriptions",
            &parameters,
            command.idempotency_key(),
            credential,
            &MerchantConnectAccount::Platform,
        )?;
        let provider = projection(
            &response.value,
            response.request_id,
            now,
            "subscription-create",
        )?;
        let ambiguous = self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id());
        if ambiguous {
            return Ok(SubscriptionCreateEffect::OutcomeUnknown(None));
        }
        Ok(effect(provider))
    }

    fn reconcile(
        &self,
        liability: &SubscriptionLiabilityRecord,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateReconciliationOutcome, PortError> {
        let provider = if let Some(provider) = liability.provider() {
            self.retrieve(&provider.subscription_id, credential, now)?
        } else {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            let response = self.http.protected_get(
                &format!("/v1/subscriptions?customer={}&status=all&limit=100&expand[]=data.latest_invoice.payment_intent", liability.customer_id()),
                credential,
                &MerchantConnectAccount::Platform,
            )?;
            let matches: Vec<_> = response
                .value
                .get("data")
                .and_then(Value::as_array)
                .ok_or(PortError::Malformed)?
                .iter()
                .filter(|value| {
                    value
                        .pointer("/metadata/auths_workflow_id")
                        .and_then(Value::as_str)
                        == Some(liability.workflow_id())
                })
                .collect();
            if matches.len() != 1 {
                return if matches.is_empty() {
                    Ok(SubscriptionCreateReconciliationOutcome::StillUnknown(None))
                } else {
                    Err(PortError::Malformed)
                };
            }
            projection(
                matches[0],
                response.request_id,
                now,
                "reconcile-workflow-search",
            )?
        };
        Ok(match effect(provider) {
            SubscriptionCreateEffect::Active(value) => {
                SubscriptionCreateReconciliationOutcome::Active(value)
            }
            SubscriptionCreateEffect::Trialing(value) => {
                SubscriptionCreateReconciliationOutcome::Trialing(value)
            }
            SubscriptionCreateEffect::Incomplete(value) => {
                SubscriptionCreateReconciliationOutcome::Incomplete(value)
            }
            SubscriptionCreateEffect::IncompleteExpired(value) => {
                SubscriptionCreateReconciliationOutcome::IncompleteExpired(value)
            }
            SubscriptionCreateEffect::KnownFailure {
                projection: None, ..
            } => SubscriptionCreateReconciliationOutcome::KnownNoEffect,
            SubscriptionCreateEffect::KnownFailure {
                projection: Some(value),
                ..
            }
            | SubscriptionCreateEffect::OutcomeUnknown(Some(value)) => {
                SubscriptionCreateReconciliationOutcome::StillUnknown(Some(value))
            }
            SubscriptionCreateEffect::OutcomeUnknown(None) => {
                SubscriptionCreateReconciliationOutcome::StillUnknown(None)
            }
        })
    }
}

struct TypedMandate {
    action: StripeExactPaymentMandateV1,
    capability: auths_stripe::PaymentMandateCapabilityRecord,
    receipt: PaymentMandateReceipt,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "typed prerequisite construction exposes every mandate link"
)]
fn typed_mandate(
    account: StripeAccountId,
    customer: CustomerId,
    payment_method: PaymentMethodId,
    setup: &Value,
    request_id: Option<String>,
    workflow_id: &str,
    api_version: &str,
    now: u64,
) -> Result<TypedMandate, PortError> {
    let action = StripeExactPaymentMandateV1::new(StripeExactPaymentMandateInput {
        stripe_account_id: account.clone(),
        connect_account: MandateConnectAccount::Platform,
        customer_id: customer.clone(),
        payment_method_id: payment_method.clone(),
        payment_method_type: "card".into(),
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: 500,
        currency: auths_stripe::Currency::parse("usd").map_err(|_| PortError::Malformed)?,
        interval: MandateInterval::Weekly,
        reference: format!("weekly-{workflow_id}"),
        consent_evidence_digest: sha256(format!("consent-{workflow_id}").as_bytes()),
        displayed_terms_digest: sha256(b"Auths bounded weekly subscription terms"),
        on_behalf_of: None,
        return_url_commitment: None,
        stripe_api_version: api_version.into(),
        required_policy_digest: sha256(b"demo-mandate-policy"),
        required_configuration_digest: sha256(b"demo-mandate-configuration"),
        executor_audience: "https://stripe-subscription-create.auths.dev".into(),
        expires_at: now + 300,
        nonce: sha256(format!("mandate-{workflow_id}").as_bytes()),
    })
    .map_err(|_| PortError::Malformed)?;
    let provider = PaymentMandateProviderProjection {
        setup_intent_id: SetupIntentId::parse(string(setup, "id")?)
            .map_err(|_| PortError::Malformed)?,
        latest_setup_attempt_id: object_or_string_id(
            setup.get("latest_attempt"),
            SetupAttemptId::parse,
        )?,
        mandate_id: object_or_string_id(setup.get("mandate"), MandateId::parse)?,
        customer_id: customer.clone(),
        payment_method_id: payment_method.clone(),
        usage: string(setup, "usage")?.into(),
        status: string(setup, "status")?.into(),
        livemode: boolean(setup, "livemode")?,
        stripe_request_id: request_id,
        response_digest: sha256(
            &canonical_json(&json!({
                "id": setup.get("id"),
                "mandate": setup.get("mandate"),
                "payment_method": setup.get("payment_method"),
                "status": setup.get("status"),
                "usage": setup.get("usage")
            }))
            .map_err(|_| PortError::Malformed)?,
        ),
        observed_at: now,
        source: "subscription-fixture-setup-intent".into(),
    };
    if provider.status != "succeeded" {
        return Err(PortError::Execution);
    }
    let decision_digest = sha256(format!("mandate-decision-{workflow_id}").as_bytes());
    let store = InMemoryPaymentMandateStore::default();
    let ReservePaymentMandateResult::Reserved(reserved) = store
        .reserve(ReservePaymentMandateRequest {
            workflow_id: format!("{workflow_id}-mandate"),
            stripe_account_id: account,
            customer_id: customer,
            payment_method_id: payment_method,
            reference: format!("weekly-{workflow_id}"),
            action_digest: action.digest().map_err(|_| PortError::Malformed)?,
            policy_digest: sha256(b"demo-mandate-policy"),
            consent_digest: sha256(format!("consent-{workflow_id}").as_bytes()),
            decision_receipt_digest: decision_digest.clone(),
            maximum_active: 1,
            provider_active: 0,
            now,
        })
        .map_err(|_| PortError::Persistence)?
    else {
        return Err(PortError::Persistence);
    };
    let claimed = store
        .transition(
            reserved.workflow_id(),
            PaymentMandateCapabilityState::Reserved,
            PaymentMandateCapabilityState::Claimed,
            None,
            now,
        )
        .map_err(|_| PortError::Persistence)?;
    let attempting = store
        .transition(
            claimed.workflow_id(),
            PaymentMandateCapabilityState::Claimed,
            PaymentMandateCapabilityState::Attempting,
            None,
            now,
        )
        .map_err(|_| PortError::Persistence)?;
    let capability = store
        .transition(
            attempting.workflow_id(),
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::Committed,
            Some(provider.clone()),
            now,
        )
        .map_err(|_| PortError::Persistence)?;
    let receipt = PaymentMandateReceipt::Observation(Box::new(PaymentMandateObservationReceipt {
        schema: "auths.stripe.payment-mandate-observation-receipt/1".into(),
        workflow_id: capability.workflow_id().into(),
        action_digest: capability.action_digest().clone(),
        policy_digest: capability.policy_digest().clone(),
        decision_receipt_digest: decision_digest,
        capability_id: capability.capability_id().clone(),
        provider,
        exact_provider_equality: true,
        reconciled: false,
        client_secret_exposed: false,
        no_immediate_charge: true,
        residual_assumptions: vec![],
        recorded_at: now,
    }));
    Ok(TypedMandate {
        action,
        capability,
        receipt,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    reason = "normalization keeps independent Stripe responses explicit"
)]
fn evidence_from_values(
    account: StripeAccountId,
    customer: CustomerId,
    payment_method: PaymentMethodId,
    test_clock: TestClockId,
    mandate_action: StripeExactPaymentMandateV1,
    mandate_capability: auths_stripe::PaymentMandateCapabilityRecord,
    mandate_receipt: PaymentMandateReceipt,
    price: Value,
    preview: Value,
    subscriptions: Value,
    billing_cycle_anchor: u64,
    cancel_at: u64,
    api_version: &str,
    now: u64,
) -> Result<SubscriptionCreateEvidenceV1, PortError> {
    let price_id = PriceId::parse(string(&price, "id")?).map_err(|_| PortError::Malformed)?;
    let product_id = ProductId::parse(match price.get("product") {
        Some(Value::String(value)) => value.clone(),
        Some(value) => string(value, "id")?.into(),
        None => return Err(PortError::Malformed),
    })
    .map_err(|_| PortError::Malformed)?;
    let recurring = price.get("recurring").ok_or(PortError::Malformed)?;
    let interval = match string(recurring, "interval")? {
        "week" => SubscriptionInterval::Week,
        "month" => SubscriptionInterval::Month,
        "year" => SubscriptionInterval::Year,
        _ => return Err(PortError::Malformed),
    };
    let quantity = preview
        .pointer("/lines/data/0/quantity")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let amount_due = integer_signed(&preview, "amount_due")?;
    let preview_line = SubscriptionPreviewLine {
        price_id: price_id.clone(),
        quantity: u32::try_from(quantity).map_err(|_| PortError::Malformed)?,
        amount_minor: amount_due,
        proration: preview
            .pointer("/lines/data/0/proration")
            .and_then(Value::as_bool)
            .or_else(|| {
                preview
                    .pointer("/lines/data/0/parent/subscription_item_details/proration")
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false),
    };
    let preview_commitment = json!({
        "amount_due_minor": amount_due,
        "currency": preview.get("currency"),
        "lines": [&preview_line],
    });
    let active_subscriptions = subscriptions
        .get("data")
        .and_then(Value::as_array)
        .ok_or(PortError::Malformed)?
        .iter()
        .filter(|value| {
            matches!(
                value.get("status").and_then(Value::as_str),
                Some("active" | "trialing" | "incomplete")
            )
        })
        .count();
    let mandate_receipt_digest =
        canonical_digest(&mandate_receipt).map_err(|_| PortError::Malformed)?;
    let evidence = SubscriptionCreateEvidenceV1 {
        schema: "auths.stripe.subscription-create-evidence/1".into(),
        stripe_account_id: account,
        connect_account: SubscriptionConnectAccount::Platform,
        customer_id: customer,
        payment_method_id: payment_method,
        test_clock_id: test_clock,
        mandate_action,
        mandate_capability,
        mandate_receipt,
        mandate_receipt_digest,
        catalog: vec![SubscriptionCatalogItemEvidence {
            price_id,
            product_id,
            currency: auths_stripe::Currency::parse(string(&price, "currency")?)
                .map_err(|_| PortError::Malformed)?,
            unit_amount_minor: integer(&price, "unit_amount")?,
            interval,
            interval_count: u32::try_from(integer(recurring, "interval_count")?)
                .map_err(|_| PortError::Malformed)?,
            licensed: recurring
                .get("usage_type")
                .and_then(Value::as_str)
                .unwrap_or("licensed")
                == "licensed",
            active: boolean(&price, "active")?,
        }],
        preview_lines: vec![preview_line],
        preview_digest: sha256(
            &canonical_json(&preview_commitment).map_err(|_| PortError::Malformed)?,
        ),
        preview_amount_due_minor: amount_due,
        preview_valid_until: now + 120,
        cycle_anchors: vec![
            billing_cycle_anchor,
            billing_cycle_anchor
                .checked_add(WEEK_SECONDS)
                .ok_or(PortError::Malformed)?,
            billing_cycle_anchor
                .checked_add(2 * WEEK_SECONDS)
                .ok_or(PortError::Malformed)?,
        ],
        active_subscriptions: u32::try_from(active_subscriptions)
            .map_err(|_| PortError::Malformed)?,
        livemode: boolean(&price, "livemode")?,
        stripe_api_version: api_version.into(),
        observed_at: now,
        response_digest: sha256(
            &canonical_json(&json!({
                "price": price,
                "preview": preview,
                "subscription_count": active_subscriptions
            }))
            .map_err(|_| PortError::Malformed)?,
        ),
        source: "stripe-catalog-preview-test-clock".into(),
    };
    evidence.validate().map_err(|_| PortError::Malformed)?;
    if cancel_at != billing_cycle_anchor + 3 * WEEK_SECONDS {
        return Err(PortError::Malformed);
    }
    Ok(evidence)
}

fn projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<SubscriptionProviderProjection, PortError> {
    let latest_invoice = value.get("latest_invoice");
    let invoice_id = object_or_string_id(latest_invoice, InvoiceId::parse)?;
    let payment_intent_id = latest_invoice
        .and_then(|invoice| match invoice {
            Value::Object(_) => invoice.get("payment_intent"),
            _ => None,
        })
        .map_or(Ok(None), |item| {
            object_or_string_id(Some(item), PaymentIntentId::parse)
        })?;
    let amount_paid_minor = latest_invoice
        .and_then(|invoice| invoice.get("amount_paid"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let invoice_status = latest_invoice
        .and_then(|invoice| invoice.get("status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let current_period_end = value
        .get("current_period_end")
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .pointer("/items/data/0/current_period_end")
                .and_then(Value::as_u64)
        })
        .unwrap_or(0);
    let sanitized = json!({
        "cancel_at": value.get("cancel_at"),
        "customer": value.get("customer"),
        "ended_at": value.get("ended_at"),
        "id": value.get("id"),
        "latest_invoice": invoice_id,
        "status": value.get("status"),
        "test_clock": value.get("test_clock")
    });
    Ok(SubscriptionProviderProjection {
        subscription_id: SubscriptionId::parse(string(value, "id")?)
            .map_err(|_| PortError::Malformed)?,
        latest_invoice_id: invoice_id,
        payment_intent_id,
        customer_id: CustomerId::parse(string(value, "customer")?)
            .map_err(|_| PortError::Malformed)?,
        test_clock_id: TestClockId::parse(string(value, "test_clock")?)
            .map_err(|_| PortError::Malformed)?,
        status: string(value, "status")?.into(),
        invoice_status,
        amount_paid_minor,
        current_period_end,
        cancel_at: integer(value, "cancel_at")?,
        ended_at: value.get("ended_at").and_then(Value::as_u64),
        livemode: boolean(value, "livemode")?,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: source.into(),
    })
}

fn effect(provider: SubscriptionProviderProjection) -> SubscriptionCreateEffect {
    match provider.status.as_str() {
        "active" => SubscriptionCreateEffect::Active(provider),
        "trialing" => SubscriptionCreateEffect::Trialing(provider),
        "incomplete" => SubscriptionCreateEffect::Incomplete(provider),
        "incomplete_expired" => SubscriptionCreateEffect::IncompleteExpired(provider),
        "canceled" => SubscriptionCreateEffect::KnownFailure {
            code: "subscription-canceled".into(),
            projection: Some(provider),
        },
        _ => SubscriptionCreateEffect::OutcomeUnknown(Some(provider)),
    }
}

fn payment_behavior(value: SubscriptionPaymentBehavior) -> &'static str {
    match value {
        SubscriptionPaymentBehavior::DefaultIncomplete => "default_incomplete",
        SubscriptionPaymentBehavior::ErrorIfIncomplete => "error_if_incomplete",
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PortError::Malformed)
}
fn integer(value: &Value, key: &str) -> Result<u64, PortError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(PortError::Malformed)
}
fn integer_signed(value: &Value, key: &str) -> Result<i64, PortError> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(PortError::Malformed)
}
fn boolean(value: &Value, key: &str) -> Result<bool, PortError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(PortError::Malformed)
}
fn object_or_string_id<T>(
    value: Option<&Value>,
    parse: impl FnOnce(String) -> Result<T, auths_stripe::types::TypeError>,
) -> Result<Option<T>, PortError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let id = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.get("id").and_then(Value::as_str).map(str::to_owned))
        .ok_or(PortError::Malformed)?;
    parse(id).map(Some).map_err(|_| PortError::Malformed)
}
