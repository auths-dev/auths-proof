use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    CredentialProvider, CustomerId, InvoiceId, PaymentIntentId, PaymentMethodId, PortError,
    PriceId, ProductId, StripeAccountId, SubscriptionCatalogItemEvidence,
    SubscriptionCollectionMethod, SubscriptionConnectAccount, SubscriptionId, SubscriptionInterval,
    SubscriptionItemId, SubscriptionModificationRecord, SubscriptionModifyCredential,
    SubscriptionModifyCredentialScope, SubscriptionModifyEffect, SubscriptionModifyEvidenceV1,
    SubscriptionModifyGateway, SubscriptionModifyItem, SubscriptionModifyProviderProjection,
    SubscriptionModifyReconciliationOutcome, SubscriptionPreviewLine, TestClockId,
    VerifiedSubscriptionModifyCommand,
    canonical::{canonical_digest, canonical_json, sha256},
    merchant::MerchantConnectAccount,
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde::Serialize;
use serde_json::{Value, json};

const WEEK_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Repository-owned active Subscription plus exact update preview.
pub struct SubscriptionFixture {
    pub evidence: SubscriptionModifyEvidenceV1,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct EnvironmentDiagnostics {
    pub credential_requests: u64,
    pub provider_calls: u64,
}

#[allow(
    clippy::missing_errors_doc,
    reason = "the demo port methods uniformly return PortError and are documented by their names"
)]
pub trait DemoSubscriptionModifyEnvironment:
    SubscriptionModifyGateway + CredentialProvider<SubscriptionModifyCredentialScope> + Send + Sync
{
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<SubscriptionFixture, PortError>;
    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError>;
    fn advance_clock(&self, test_clock: &TestClockId, frozen_time: u64)
    -> Result<Value, PortError>;
    fn timeline(
        &self,
        subscription: &SubscriptionId,
        now: u64,
    ) -> Result<SubscriptionModifyProviderProjection, PortError>;
    fn account_id(&self) -> &StripeAccountId;
    fn api_version(&self) -> &str;
    fn diagnostics(&self) -> EnvironmentDiagnostics;
}

pub struct LiveSubscriptionModifyEnvironment {
    http: StripeHttp<SubscriptionModifyCredentialScope>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
    ambiguous_once: Mutex<BTreeSet<String>>,
}

impl LiveSubscriptionModifyEnvironment {
    /// Builds the live adapter from the subscription-modify credential environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the required credential or Stripe account configuration is absent.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_SUBSCRIPTION_MODIFY_SECRET_KEY")?,
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
            ambiguous_once: Mutex::new(BTreeSet::new()),
        })
    }

    fn preview_modify(
        &self,
        subscription: &SubscriptionId,
        item: &SubscriptionItemId,
        quantity: u32,
        proration_date: u64,
        credential: Option<&SubscriptionModifyCredential>,
        idempotency_key: &str,
    ) -> Result<Value, PortError> {
        let parameters = vec![
            ("subscription".into(), subscription.to_string()),
            (
                "subscription_details[items][0][id]".into(),
                item.to_string(),
            ),
            (
                "subscription_details[items][0][quantity]".into(),
                quantity.to_string(),
            ),
            (
                "subscription_details[proration_behavior]".into(),
                "always_invoice".into(),
            ),
            (
                "subscription_details[proration_date]".into(),
                proration_date.to_string(),
            ),
        ];
        match credential {
            Some(value) => self.http.protected_post(
                "/v1/invoices/create_preview",
                &parameters,
                &format!("{idempotency_key}-preview"),
                value,
                &MerchantConnectAccount::Platform,
            ),
            None => self.http.fixture_post(
                "/v1/invoices/create_preview",
                &parameters,
                &format!("{idempotency_key}-preview"),
                &MerchantConnectAccount::Platform,
            ),
        }
        .map(|response| response.value)
    }

    fn reread_evidence(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEvidenceV1, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let action = command.action();
        let subscription = self.http.protected_get(
            &format!(
                "/v1/subscriptions/{}?expand[]=items.data.price.product&expand[]=latest_invoice.payment_intent",
                action.subscription_id()
            ),
            credential,
            &MerchantConnectAccount::Platform,
        )?;
        let price = self.http.protected_get(
            &format!(
                "/v1/prices/{}?expand[]=product",
                action.after_items()[0].price_id()
            ),
            credential,
            &MerchantConnectAccount::Platform,
        )?;
        let preview = self.preview_modify(
            action.subscription_id(),
            action.after_items()[0].subscription_item_id(),
            action.after_items()[0].quantity(),
            action.proration_date(),
            Some(credential),
            command.idempotency_key(),
        )?;
        evidence_from_values(
            action.stripe_account_id().clone(),
            action.mandate_receipt_digest().clone(),
            action.test_clock_id().clone(),
            &price.value,
            &subscription.value,
            &preview,
            self.api_version(),
            now,
        )
    }

    fn retrieve_projection(
        &self,
        subscription: &SubscriptionId,
        expected_items: Option<&[SubscriptionModifyItem]>,
        credential: Option<&SubscriptionModifyCredential>,
        now: u64,
        source: &str,
    ) -> Result<SubscriptionModifyProviderProjection, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let path = format!(
            "/v1/subscriptions/{subscription}?expand[]=items.data.price.product&expand[]=latest_invoice.payment_intent"
        );
        let response = match credential {
            Some(value) => {
                self.http
                    .protected_get(&path, value, &MerchantConnectAccount::Platform)?
            }
            None => self
                .http
                .fixture_get(&path, &MerchantConnectAccount::Platform)?,
        };
        projection(
            &response.value,
            expected_items,
            response.request_id,
            now,
            source,
        )
    }
}

impl CredentialProvider<SubscriptionModifyCredentialScope> for LiveSubscriptionModifyEnvironment {
    fn credential(
        &self,
        account: &StripeAccountId,
    ) -> Result<SubscriptionModifyCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.credential(account)
    }
}

impl DemoSubscriptionModifyEnvironment for LiveSubscriptionModifyEnvironment {
    #[allow(
        clippy::too_many_lines,
        reason = "all repository-owned Stripe fixture objects remain explicit"
    )]
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<SubscriptionFixture, PortError> {
        let connect = MerchantConnectAccount::Platform;
        let clock = self.http.fixture_post(
            "/v1/test_helpers/test_clocks",
            &[
                ("frozen_time".into(), now.to_string()),
                ("name".into(), format!("Auths modify {workflow_id}")),
            ],
            &format!("auths-sub-modify-clock-{workflow_id}"),
            &connect,
        )?;
        let test_clock =
            TestClockId::parse(string(&clock.value, "id")?).map_err(|_| PortError::Malformed)?;
        let frozen_time = integer(&clock.value, "frozen_time")?;
        let cancel_at = frozen_time
            .checked_add(3 * WEEK_SECONDS)
            .ok_or(PortError::Malformed)?;

        let customer = self.http.fixture_post(
            "/v1/customers",
            &[
                (
                    "description".into(),
                    "Auths bounded subscription modify demo".into(),
                ),
                ("test_clock".into(), test_clock.to_string()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-sub-modify-customer-{workflow_id}"),
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
            &format!("auths-sub-modify-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-sub-modify-attach-{workflow_id}"),
            &connect,
        )?;
        let setup = self.http.fixture_post(
            "/v1/setup_intents",
            &[
                ("customer".into(), customer_id.to_string()),
                ("payment_method".into(), payment_method.to_string()),
                ("usage".into(), "off_session".into()),
                ("confirm".into(), "true".into()),
                ("payment_method_types[0]".into(), "card".into()),
                (
                    "metadata[auths_workflow_id]".into(),
                    format!("{workflow_id}-mandate"),
                ),
            ],
            &format!("auths-sub-modify-mandate-{workflow_id}"),
            &connect,
        )?;
        let mandate_receipt_digest = canonical_digest(&json!({
            "schema": "auths.stripe.payment-mandate-observation/1",
            "stripe_account_id": self.account_id(),
            "customer_id": customer_id,
            "payment_method_id": payment_method,
            "setup_intent_id": setup.value.get("id"),
            "status": setup.value.get("status"),
            "usage": setup.value.get("usage"),
            "livemode": setup.value.get("livemode"),
            "stripe_api_version": self.api_version()
        }))
        .map_err(|_| PortError::Malformed)?;

        let product = self.http.fixture_post(
            "/v1/products",
            &[
                ("name".into(), "Auths bounded weekly membership".into()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-sub-modify-product-{workflow_id}"),
            &connect,
        )?;
        let product_id =
            ProductId::parse(string(&product.value, "id")?).map_err(|_| PortError::Malformed)?;
        let price = self.http.fixture_post(
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
            &format!("auths-sub-modify-price-{workflow_id}"),
            &connect,
        )?;
        let price_id =
            PriceId::parse(string(&price.value, "id")?).map_err(|_| PortError::Malformed)?;

        let subscription = self.http.fixture_post(
            "/v1/subscriptions",
            &[
                ("customer".into(), customer_id.to_string()),
                ("items[0][price]".into(), price_id.to_string()),
                ("items[0][quantity]".into(), "1".into()),
                ("collection_method".into(), "charge_automatically".into()),
                ("default_payment_method".into(), payment_method.to_string()),
                ("payment_behavior".into(), "error_if_incomplete".into()),
                ("proration_behavior".into(), "none".into()),
                ("automatic_tax[enabled]".into(), "false".into()),
                ("cancel_at".into(), cancel_at.to_string()),
                (
                    "metadata[auths_workflow_id]".into(),
                    format!("{workflow_id}-source"),
                ),
                ("expand[0]".into(), "items.data.price.product".into()),
                ("expand[1]".into(), "latest_invoice.payment_intent".into()),
            ],
            &format!("auths-sub-modify-source-{workflow_id}"),
            &connect,
        )?;
        let subscription_id = SubscriptionId::parse(string(&subscription.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        let item_id = SubscriptionItemId::parse(
            subscription
                .value
                .pointer("/items/data/0/id")
                .and_then(Value::as_str)
                .ok_or(PortError::Malformed)?,
        )
        .map_err(|_| PortError::Malformed)?;
        let proration_date = integer_or_pointer(
            &subscription.value,
            "current_period_start",
            "/items/data/0/current_period_start",
        )?;
        let preview = self.preview_modify(
            &subscription_id,
            &item_id,
            2,
            proration_date,
            None,
            &format!("auths-sub-modify-seed-{workflow_id}"),
        )?;
        let evidence = evidence_from_values(
            self.account_id().clone(),
            mandate_receipt_digest,
            test_clock,
            &price.value,
            &subscription.value,
            &preview,
            self.api_version(),
            now,
        )?;
        Ok(SubscriptionFixture { evidence })
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
                &format!("auths-sub-modify-advance-{test_clock}-{frozen_time}"),
                &MerchantConnectAccount::Platform,
            )?
            .value)
    }

    fn timeline(
        &self,
        subscription: &SubscriptionId,
        now: u64,
    ) -> Result<SubscriptionModifyProviderProjection, PortError> {
        self.retrieve_projection(subscription, None, None, now, "test-clock-timeline")
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

impl SubscriptionModifyGateway for LiveSubscriptionModifyEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEvidenceV1, PortError> {
        self.reread_evidence(command, credential, now)
    }

    fn modify(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEffect, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let action = command.action();
        let mut parameters = vec![
            ("payment_behavior".into(), "pending_if_incomplete".into()),
            ("proration_behavior".into(), "always_invoice".into()),
            ("proration_date".into(), action.proration_date().to_string()),
            ("expand[0]".into(), "items.data.price.product".into()),
            ("expand[1]".into(), "latest_invoice.payment_intent".into()),
        ];
        for (index, item) in action.after_items().iter().enumerate() {
            parameters.push((
                format!("items[{index}][id]"),
                item.subscription_item_id().to_string(),
            ));
            parameters.push((
                format!("items[{index}][price]"),
                item.price_id().to_string(),
            ));
            parameters.push((
                format!("items[{index}][quantity]"),
                item.quantity().to_string(),
            ));
        }
        let response = match self.http.protected_post(
            &format!("/v1/subscriptions/{}", action.subscription_id()),
            &parameters,
            command.idempotency_key(),
            credential,
            &MerchantConnectAccount::Platform,
        ) {
            Ok(value) => value,
            Err(PortError::Execution) => {
                return Ok(SubscriptionModifyEffect::KnownFailure {
                    code: "stripe-update-rejected".into(),
                    projection: None,
                });
            }
            Err(error) => return Err(error),
        };
        let provider = projection(
            &response.value,
            Some(action.after_items()),
            response.request_id,
            now,
            "subscription-modify",
        )?;
        if self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id())
        {
            return Ok(SubscriptionModifyEffect::OutcomeUnknown(None));
        }
        if provider.applied {
            Ok(SubscriptionModifyEffect::Applied(provider))
        } else if provider.pending_update_digest.is_some() || provider.payment_incomplete {
            Ok(SubscriptionModifyEffect::PendingPayment(provider))
        } else {
            Ok(SubscriptionModifyEffect::OutcomeUnknown(Some(provider)))
        }
    }

    fn reconcile(
        &self,
        modification: &SubscriptionModificationRecord,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyReconciliationOutcome, PortError> {
        let provider = self.retrieve_projection(
            modification.subscription_id(),
            Some(modification.after_items()),
            Some(credential),
            now,
            "subscription-modify-reconcile",
        )?;
        if provider.applied {
            Ok(SubscriptionModifyReconciliationOutcome::Applied(provider))
        } else if provider.pending_update_digest.is_some() || provider.payment_incomplete {
            Ok(SubscriptionModifyReconciliationOutcome::PendingPayment(
                provider,
            ))
        } else if modification.provider().is_some() {
            Ok(SubscriptionModifyReconciliationOutcome::ExpiredOrVoided(
                provider,
            ))
        } else {
            Ok(SubscriptionModifyReconciliationOutcome::StillUnknown(Some(
                provider,
            )))
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the evidence builder keeps every provider input explicit and constructs one auditable projection"
)]
fn evidence_from_values(
    account: StripeAccountId,
    mandate_receipt_digest: auths_stripe::DigestHex,
    test_clock: TestClockId,
    price: &Value,
    subscription: &Value,
    preview: &Value,
    api_version: &str,
    now: u64,
) -> Result<SubscriptionModifyEvidenceV1, PortError> {
    let subscription_id =
        SubscriptionId::parse(string(subscription, "id")?).map_err(|_| PortError::Malformed)?;
    let customer_id =
        CustomerId::parse(string(subscription, "customer")?).map_err(|_| PortError::Malformed)?;
    let payment_method_id = object_or_string_id(
        subscription.get("default_payment_method"),
        PaymentMethodId::parse,
    )?
    .ok_or(PortError::Malformed)?;
    let current_items = subscription_items(subscription)?;
    let price_id = PriceId::parse(string(price, "id")?).map_err(|_| PortError::Malformed)?;
    let product_id =
        ProductId::parse(object_or_string(price, "product")?).map_err(|_| PortError::Malformed)?;
    let recurring = price.get("recurring").ok_or(PortError::Malformed)?;
    let interval = parse_interval(string(recurring, "interval")?)?;
    let unit_amount = integer(price, "unit_amount")?;
    let currency = auths_stripe::Currency::parse(string(price, "currency")?)
        .map_err(|_| PortError::Malformed)?;
    let catalog = vec![SubscriptionCatalogItemEvidence {
        price_id,
        product_id,
        currency: currency.clone(),
        unit_amount_minor: unit_amount,
        interval,
        interval_count: u32::try_from(integer(recurring, "interval_count")?)
            .map_err(|_| PortError::Malformed)?,
        licensed: recurring
            .get("usage_type")
            .and_then(Value::as_str)
            .unwrap_or("licensed")
            == "licensed",
        active: boolean(price, "active")?,
    }];
    let mut preview_lines = preview_lines(preview, &catalog[0].price_id)?;
    preview_lines.sort();
    let preview_digest = canonical_digest(&preview_lines).map_err(|_| PortError::Malformed)?;
    let (proration_debit_minor, proration_credit_minor) = preview_lines
        .iter()
        .filter(|line| line.proration)
        .try_fold((0_u64, 0_u64), |(debit, credit), line| {
            if line.amount_minor >= 0 {
                debit
                    .checked_add(line.amount_minor.unsigned_abs())
                    .map(|value| (value, credit))
            } else {
                credit
                    .checked_add(line.amount_minor.unsigned_abs())
                    .map(|value| (debit, value))
            }
        })
        .ok_or(PortError::Malformed)?;
    let before_recurring_minor = current_items
        .iter()
        .try_fold(0_u64, |total, item| {
            unit_amount
                .checked_mul(u64::from(item.quantity()))
                .and_then(|amount| total.checked_add(amount))
        })
        .ok_or(PortError::Malformed)?;
    let after_recurring_minor = current_items
        .iter()
        .try_fold(0_u64, |total, _| {
            unit_amount
                .checked_mul(2)
                .and_then(|amount| total.checked_add(amount))
        })
        .ok_or(PortError::Malformed)?;
    let billing_cycle_anchor = integer(subscription, "billing_cycle_anchor")?;
    let current_period_start = integer_or_pointer(
        subscription,
        "current_period_start",
        "/items/data/0/current_period_start",
    )?;
    let current_period_end = integer_or_pointer(
        subscription,
        "current_period_end",
        "/items/data/0/current_period_end",
    )?;
    let cancel_at = integer(subscription, "cancel_at")?;
    let remaining_cycle_count = u32::try_from(
        cancel_at
            .checked_sub(current_period_end)
            .ok_or(PortError::Malformed)?
            / WEEK_SECONDS,
    )
    .map_err(|_| PortError::Malformed)?;
    let pending_update_digest = subscription
        .get("pending_update")
        .filter(|value| !value.is_null())
        .map(canonical_digest)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    let latest_invoice = subscription.get("latest_invoice");
    let latest_invoice_id = object_or_string_id(latest_invoice, InvoiceId::parse)?;
    let latest_payment_intent_id = latest_invoice
        .and_then(|value| value.get("payment_intent"))
        .map_or(Ok(None), |value| {
            object_or_string_id(Some(value), PaymentIntentId::parse)
        })?;
    let invoice_status = latest_invoice
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let payment_status = latest_invoice
        .and_then(|value| value.pointer("/payment_intent/status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut evidence = SubscriptionModifyEvidenceV1 {
        schema: "auths.stripe.subscription-modify-evidence/1".into(),
        stripe_account_id: account,
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id,
        customer_id,
        current_items,
        currency,
        collection_method: match string(subscription, "collection_method")? {
            "charge_automatically" => SubscriptionCollectionMethod::ChargeAutomatically,
            _ => return Err(PortError::Malformed),
        },
        payment_method_id,
        billing_cycle_anchor,
        current_period_start,
        current_period_end,
        cancel_at,
        mandate_receipt_digest,
        test_clock_id: test_clock,
        before_subscription_digest: auths_stripe::DigestHex::parse("0".repeat(64))
            .map_err(|_| PortError::Malformed)?,
        pending_update_digest,
        catalog,
        preview_lines,
        preview_digest,
        proration_date: current_period_start,
        proration_debit_minor,
        proration_credit_minor,
        before_recurring_minor,
        after_recurring_minor,
        remaining_cycle_count,
        latest_invoice_id,
        latest_payment_intent_id,
        invoice_status,
        payment_status,
        preview_valid_until: now.checked_add(120).ok_or(PortError::Malformed)?,
        livemode: boolean(subscription, "livemode")?,
        stripe_api_version: api_version.into(),
        observed_at: now,
        response_digest: sha256(
            &canonical_json(&json!({
                "price": price,
                "subscription": subscription,
                "preview": preview
            }))
            .map_err(|_| PortError::Malformed)?,
        ),
        source: "stripe-subscription-current-state-and-preview".into(),
    };
    evidence.before_subscription_digest =
        evidence.before_digest().map_err(|_| PortError::Malformed)?;
    evidence.validate().map_err(|_| PortError::Malformed)?;
    Ok(evidence)
}

fn projection(
    value: &Value,
    expected_items: Option<&[SubscriptionModifyItem]>,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<SubscriptionModifyProviderProjection, PortError> {
    let mut items = subscription_items(value)?;
    items.sort();
    let item_set_digest = canonical_digest(&items).map_err(|_| PortError::Malformed)?;
    let pending_update_digest = value
        .get("pending_update")
        .filter(|item| !item.is_null())
        .map(canonical_digest)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    let latest_invoice = value.get("latest_invoice");
    let latest_invoice_id = object_or_string_id(latest_invoice, InvoiceId::parse)?;
    let payment_intent_id = latest_invoice
        .and_then(|invoice| invoice.get("payment_intent"))
        .map_or(Ok(None), |item| {
            object_or_string_id(Some(item), PaymentIntentId::parse)
        })?;
    let invoice_status = latest_invoice
        .and_then(|invoice| invoice.get("status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let payment_status = latest_invoice
        .and_then(|invoice| invoice.pointer("/payment_intent/status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let applied =
        expected_items.is_some_and(|expected| expected == items) && pending_update_digest.is_none();
    let payment_incomplete = pending_update_digest.is_some()
        || matches!(
            payment_status.as_deref(),
            Some("requires_action" | "requires_payment_method" | "processing")
        );
    let sanitized = json!({
        "id": value.get("id"),
        "customer": value.get("customer"),
        "items": items,
        "pending_update": pending_update_digest,
        "latest_invoice": latest_invoice_id,
        "billing_cycle_anchor": value.get("billing_cycle_anchor"),
        "cancel_at": value.get("cancel_at")
    });
    Ok(SubscriptionModifyProviderProjection {
        subscription_id: SubscriptionId::parse(string(value, "id")?)
            .map_err(|_| PortError::Malformed)?,
        customer_id: CustomerId::parse(string(value, "customer")?)
            .map_err(|_| PortError::Malformed)?,
        items,
        item_set_digest,
        pending_update_digest,
        latest_invoice_id,
        payment_intent_id,
        invoice_status,
        payment_status,
        applied,
        payment_incomplete,
        amount_paid_minor: latest_invoice
            .and_then(|invoice| invoice.get("amount_paid"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        billing_cycle_anchor: integer(value, "billing_cycle_anchor")?,
        cancel_at: integer(value, "cancel_at")?,
        livemode: boolean(value, "livemode")?,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(&sanitized).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: source.into(),
    })
}

fn subscription_items(value: &Value) -> Result<Vec<SubscriptionModifyItem>, PortError> {
    let values = value
        .pointer("/items/data")
        .and_then(Value::as_array)
        .ok_or(PortError::Malformed)?;
    if values.is_empty() || values.len() > 32 {
        return Err(PortError::Malformed);
    }
    let mut items = values
        .iter()
        .map(|item| {
            let price = item.get("price").ok_or(PortError::Malformed)?;
            let product = price.get("product").ok_or(PortError::Malformed)?;
            SubscriptionModifyItem::new(
                SubscriptionItemId::parse(string(item, "id")?).map_err(|_| PortError::Malformed)?,
                PriceId::parse(object_or_string_value(price)?).map_err(|_| PortError::Malformed)?,
                ProductId::parse(object_or_string_value(product)?)
                    .map_err(|_| PortError::Malformed)?,
                u32::try_from(integer(item, "quantity")?).map_err(|_| PortError::Malformed)?,
            )
            .map_err(|_| PortError::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    items.sort();
    Ok(items)
}

fn preview_lines(
    preview: &Value,
    fallback_price: &PriceId,
) -> Result<Vec<SubscriptionPreviewLine>, PortError> {
    let values = preview
        .pointer("/lines/data")
        .and_then(Value::as_array)
        .ok_or(PortError::Malformed)?;
    if values.len() > 64 {
        return Err(PortError::LimitExceeded);
    }
    values
        .iter()
        .filter(|line| {
            line.get("proration")
                .and_then(Value::as_bool)
                .or_else(|| {
                    line.pointer("/parent/subscription_item_details/proration")
                        .and_then(Value::as_bool)
                })
                .unwrap_or(false)
        })
        .map(|line| {
            let price_id = line
                .pointer("/pricing/price_details/price")
                .and_then(Value::as_str)
                .or_else(|| line.pointer("/price/id").and_then(Value::as_str))
                .map_or_else(
                    || Ok(fallback_price.clone()),
                    |value| PriceId::parse(value).map_err(|_| PortError::Malformed),
                )?;
            Ok(SubscriptionPreviewLine {
                price_id,
                quantity: u32::try_from(line.get("quantity").and_then(Value::as_u64).unwrap_or(1))
                    .map_err(|_| PortError::Malformed)?,
                amount_minor: integer_signed(line, "amount")?,
                proration: true,
            })
        })
        .collect()
}

fn parse_interval(value: &str) -> Result<SubscriptionInterval, PortError> {
    match value {
        "week" => Ok(SubscriptionInterval::Week),
        "month" => Ok(SubscriptionInterval::Month),
        "year" => Ok(SubscriptionInterval::Year),
        _ => Err(PortError::Malformed),
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

fn integer_or_pointer(value: &Value, key: &str, pointer: &str) -> Result<u64, PortError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .or_else(|| value.pointer(pointer).and_then(Value::as_u64))
        .ok_or(PortError::Malformed)
}

fn boolean(value: &Value, key: &str) -> Result<bool, PortError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(PortError::Malformed)
}

fn object_or_string(value: &Value, key: &str) -> Result<String, PortError> {
    value
        .get(key)
        .ok_or(PortError::Malformed)
        .and_then(object_or_string_value)
}

fn object_or_string_value(value: &Value) -> Result<String, PortError> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.get("id").and_then(Value::as_str).map(str::to_owned))
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
    parse(object_or_string_value(value)?)
        .map(Some)
        .map_err(|_| PortError::Malformed)
}
