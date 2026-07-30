//! Validated Stripe identifiers and closed exact-refund objects.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::{CanonicalError, canonical_digest, canonical_json, sha256};

/// Exact Auths profile identifier.
pub const PROFILE_ID: &str = "auths.stripe.exact-refund";
/// Exact profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact refund capability.
pub const REFUND_CAPABILITY: &str = "stripe.refund/create";
/// Canonical media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.stripe.exact-refund.v1+json";
/// Maximum accepted canonical action size.
pub const MAX_ACTION_BYTES: usize = 64 * 1024;
/// Maximum accepted metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 4;
/// Maximum evidence age accepted by the type itself.
pub const HARD_MAX_EVIDENCE_AGE_SECONDS: u64 = 15 * 60;
/// Maximum authorization lifetime accepted by the type itself.
pub const HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 60 * 60;

macro_rules! validated_string {
    ($name:ident, $variant:ident, $validator:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses one canonical identifier.
            ///
            /// # Errors
            ///
            /// Returns a closed validation error for malformed input.
            pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(TypeError::$variant);
                }
                Ok(Self(value))
            }

            /// Returns the canonical string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = TypeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn valid_prefixed(value: &str, prefix: &str, maximum: usize) -> bool {
    value.starts_with(prefix)
        && (prefix.len() + 8..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_account(value: &str) -> bool {
    valid_prefixed(value, "acct_", 64)
}

fn valid_charge(value: &str) -> bool {
    valid_prefixed(value, "ch_", 96)
}

fn valid_customer(value: &str) -> bool {
    valid_prefixed(value, "cus_", 96)
}

fn valid_payment_method(value: &str) -> bool {
    valid_prefixed(value, "pm_", 96)
}

fn valid_payment_intent(value: &str) -> bool {
    valid_prefixed(value, "pi_", 96)
}

fn valid_setup_intent(value: &str) -> bool {
    valid_prefixed(value, "seti_", 96)
}

fn valid_setup_attempt(value: &str) -> bool {
    valid_prefixed(value, "setatt_", 96)
}

fn valid_mandate(value: &str) -> bool {
    valid_prefixed(value, "mandate_", 96)
}

fn valid_product(value: &str) -> bool {
    valid_prefixed(value, "prod_", 96)
}

fn valid_price(value: &str) -> bool {
    valid_prefixed(value, "price_", 96)
}

fn valid_subscription(value: &str) -> bool {
    valid_prefixed(value, "sub_", 96)
}

fn valid_subscription_item(value: &str) -> bool {
    valid_prefixed(value, "si_", 96)
}

fn valid_invoice(value: &str) -> bool {
    valid_prefixed(value, "in_", 96)
}

fn valid_test_clock(value: &str) -> bool {
    valid_prefixed(value, "clock_", 96)
}

fn valid_event(value: &str) -> bool {
    valid_prefixed(value, "evt_", 96)
}

fn valid_issuing_authorization(value: &str) -> bool {
    valid_prefixed(value, "iauth_", 96)
}

fn valid_issuing_cardholder(value: &str) -> bool {
    valid_prefixed(value, "ich_", 96)
}

fn valid_issuing_card(value: &str) -> bool {
    valid_prefixed(value, "ic_", 96)
}

fn valid_transfer(value: &str) -> bool {
    valid_prefixed(value, "tr_", 96)
}

fn valid_balance_transaction(value: &str) -> bool {
    valid_prefixed(value, "txn_", 96)
}

fn valid_refund(value: &str) -> bool {
    valid_prefixed(value, "re_", 96)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_lowercase())
}

validated_string!(StripeAccountId, StripeAccountId, valid_account);
validated_string!(ChargeId, ChargeId, valid_charge);
validated_string!(CustomerId, CustomerId, valid_customer);
validated_string!(PaymentMethodId, PaymentMethodId, valid_payment_method);
validated_string!(PaymentIntentId, PaymentIntentId, valid_payment_intent);
validated_string!(SetupIntentId, SetupIntentId, valid_setup_intent);
validated_string!(SetupAttemptId, SetupAttemptId, valid_setup_attempt);
validated_string!(MandateId, MandateId, valid_mandate);
validated_string!(ProductId, ProductId, valid_product);
validated_string!(PriceId, PriceId, valid_price);
validated_string!(SubscriptionId, SubscriptionId, valid_subscription);
validated_string!(
    SubscriptionItemId,
    SubscriptionItemId,
    valid_subscription_item
);
validated_string!(InvoiceId, InvoiceId, valid_invoice);
validated_string!(TestClockId, TestClockId, valid_test_clock);
validated_string!(EventId, EventId, valid_event);
validated_string!(
    IssuingAuthorizationId,
    IssuingAuthorizationId,
    valid_issuing_authorization
);
validated_string!(
    IssuingCardholderId,
    IssuingCardholderId,
    valid_issuing_cardholder
);
validated_string!(IssuingCardId, IssuingCardId, valid_issuing_card);
validated_string!(TransferId, TransferId, valid_transfer);
validated_string!(
    BalanceTransactionId,
    BalanceTransactionId,
    valid_balance_transaction
);
validated_string!(RefundId, RefundId, valid_refund);
validated_string!(DigestHex, DigestHex, valid_digest);
validated_string!(Currency, Currency, valid_currency);

impl DigestHex {
    /// Constructs a digest from exact SHA-256 bytes.
    #[must_use]
    pub fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// Closed identifier validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TypeError {
    /// Invalid Stripe account.
    #[error("invalid Stripe account identifier")]
    StripeAccountId,
    /// Invalid Charge.
    #[error("invalid Stripe Charge identifier")]
    ChargeId,
    /// Invalid Customer.
    #[error("invalid Stripe Customer identifier")]
    CustomerId,
    /// Invalid `PaymentMethod`.
    #[error("invalid Stripe PaymentMethod identifier")]
    PaymentMethodId,
    /// Invalid `PaymentIntent`.
    #[error("invalid Stripe PaymentIntent identifier")]
    PaymentIntentId,
    /// Invalid `SetupIntent`.
    #[error("invalid Stripe SetupIntent identifier")]
    SetupIntentId,
    /// Invalid `SetupAttempt`.
    #[error("invalid Stripe SetupAttempt identifier")]
    SetupAttemptId,
    /// Invalid Mandate.
    #[error("invalid Stripe Mandate identifier")]
    MandateId,
    /// Invalid Product.
    #[error("invalid Stripe Product identifier")]
    ProductId,
    /// Invalid Price.
    #[error("invalid Stripe Price identifier")]
    PriceId,
    /// Invalid Subscription.
    #[error("invalid Stripe Subscription identifier")]
    SubscriptionId,
    /// Invalid Subscription Item.
    #[error("invalid Stripe Subscription Item identifier")]
    SubscriptionItemId,
    /// Invalid Invoice.
    #[error("invalid Stripe Invoice identifier")]
    InvoiceId,
    /// Invalid billing test clock.
    #[error("invalid Stripe test clock identifier")]
    TestClockId,
    /// Invalid Event.
    #[error("invalid Stripe Event identifier")]
    EventId,
    /// Invalid Issuing Authorization.
    #[error("invalid Stripe Issuing Authorization identifier")]
    IssuingAuthorizationId,
    /// Invalid Issuing Cardholder.
    #[error("invalid Stripe Issuing Cardholder identifier")]
    IssuingCardholderId,
    /// Invalid Issuing Card.
    #[error("invalid Stripe Issuing Card identifier")]
    IssuingCardId,
    /// Invalid Connect Transfer.
    #[error("invalid Stripe Connect Transfer identifier")]
    TransferId,
    /// Invalid balance transaction.
    #[error("invalid Stripe balance transaction identifier")]
    BalanceTransactionId,
    /// Invalid Refund.
    #[error("invalid Stripe Refund identifier")]
    RefundId,
    /// Invalid digest.
    #[error("invalid lowercase SHA-256 digest")]
    DigestHex,
    /// Invalid currency.
    #[error("invalid canonical currency")]
    Currency,
}

/// Exact money value. Amount is always in the currency's minor unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Money {
    currency: Currency,
    amount_minor: u64,
}

impl Money {
    /// Creates one positive bounded money value.
    ///
    /// # Errors
    ///
    /// Zero and values outside Stripe's signed integer range are rejected.
    pub fn new(currency: Currency, amount_minor: u64) -> Result<Self, ValidationError> {
        if amount_minor == 0 || amount_minor > i64::MAX as u64 {
            return Err(ValidationError::InvalidMoney);
        }
        Ok(Self {
            currency,
            amount_minor,
        })
    }

    /// Returns the currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Returns integer minor units.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }
}

/// Verifier configuration required by the authorization and loaded by the executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StripeVerifierConfiguration {
    profile: String,
    canonicalization_version: String,
    allowed_test_account_ids: Vec<StripeAccountId>,
    allowed_api_versions: Vec<String>,
    allowed_currencies: Vec<Currency>,
    maximum_refund_minor_by_currency: BTreeMap<Currency, u64>,
    allowed_reasons: Vec<String>,
    maximum_evidence_age_seconds: u64,
    maximum_authorization_lifetime_seconds: u64,
    allow_partial_refunds: bool,
    allow_refund_application_fee: bool,
    allow_reverse_transfer: bool,
    allowed_metadata_keys: Vec<String>,
    executor_audience: String,
    receipt_schema_version: String,
}

/// Input for validated verifier configuration.
pub struct StripeVerifierConfigurationInput {
    /// Allowed Stripe test accounts.
    pub allowed_test_account_ids: Vec<StripeAccountId>,
    /// Allowed pinned Stripe API versions.
    pub allowed_api_versions: Vec<String>,
    /// Allowed currencies.
    pub allowed_currencies: Vec<Currency>,
    /// Maximum refund in minor units per currency.
    pub maximum_refund_minor_by_currency: BTreeMap<Currency, u64>,
    /// Allowed Stripe refund reasons.
    pub allowed_reasons: Vec<String>,
    /// Freshness ceiling.
    pub maximum_evidence_age_seconds: u64,
    /// Authorization lifetime ceiling.
    pub maximum_authorization_lifetime_seconds: u64,
    /// Whether partial refunds are permitted.
    pub allow_partial_refunds: bool,
    /// Whether application-fee refunds are permitted.
    pub allow_refund_application_fee: bool,
    /// Whether transfer reversal is permitted.
    pub allow_reverse_transfer: bool,
    /// Metadata key allowlist.
    pub allowed_metadata_keys: Vec<String>,
    /// Auths executor audience.
    pub executor_audience: String,
    /// Receipt schema.
    pub receipt_schema_version: String,
}

impl StripeVerifierConfiguration {
    /// Builds a validated, canonically ordered configuration.
    ///
    /// # Errors
    ///
    /// Returns a closed error when a limit or allowlist is unsafe.
    pub fn new(mut input: StripeVerifierConfigurationInput) -> Result<Self, ValidationError> {
        input.allowed_test_account_ids.sort();
        input.allowed_api_versions.sort();
        input.allowed_currencies.sort();
        input.allowed_reasons.sort();
        input.allowed_metadata_keys.sort();
        let profile = format!("{PROFILE_ID}/{PROFILE_VERSION}");
        let configuration = Self {
            profile,
            canonicalization_version: "rfc8785-sha256-v1".into(),
            allowed_test_account_ids: input.allowed_test_account_ids,
            allowed_api_versions: input.allowed_api_versions,
            allowed_currencies: input.allowed_currencies,
            maximum_refund_minor_by_currency: input.maximum_refund_minor_by_currency,
            allowed_reasons: input.allowed_reasons,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_authorization_lifetime_seconds: input.maximum_authorization_lifetime_seconds,
            allow_partial_refunds: input.allow_partial_refunds,
            allow_refund_application_fee: input.allow_refund_application_fee,
            allow_reverse_transfer: input.allow_reverse_transfer,
            allowed_metadata_keys: input.allowed_metadata_keys,
            executor_audience: input.executor_audience,
            receipt_schema_version: input.receipt_schema_version,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Validates a deserialized configuration and canonical ordering.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration failure.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.canonicalization_version != "rfc8785-sha256-v1"
            || self.allowed_test_account_ids.is_empty()
            || self.allowed_api_versions.is_empty()
            || self.allowed_currencies.is_empty()
            || self.maximum_evidence_age_seconds == 0
            || self.maximum_evidence_age_seconds > HARD_MAX_EVIDENCE_AGE_SECONDS
            || self.maximum_authorization_lifetime_seconds == 0
            || self.maximum_authorization_lifetime_seconds > HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS
            || self.executor_audience.len() > 256
            || auths_model::Audience::parse(&self.executor_audience).is_err()
            || !valid_version(&self.receipt_schema_version)
            || !valid_version(&self.canonicalization_version)
            || !is_sorted_unique(&self.allowed_test_account_ids)
            || !is_sorted_unique(&self.allowed_api_versions)
            || !is_sorted_unique(&self.allowed_currencies)
            || !is_sorted_unique(&self.allowed_reasons)
            || !is_sorted_unique(&self.allowed_metadata_keys)
            || self
                .allowed_api_versions
                .iter()
                .any(|value| !valid_api_version(value))
            || self
                .allowed_reasons
                .iter()
                .any(|value| !valid_reason(value))
            || self
                .allowed_metadata_keys
                .iter()
                .any(|value| !valid_metadata_key(value))
            || self.maximum_refund_minor_by_currency.len() != self.allowed_currencies.len()
            || self.allowed_currencies.iter().any(|currency| {
                !matches!(
                    self.maximum_refund_minor_by_currency.get(currency),
                    Some(1..=9_999_999_999)
                )
            })
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Returns a canonical configuration digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Returns whether this exact account is allowed.
    #[must_use]
    pub fn allows_account(&self, account: &StripeAccountId) -> bool {
        self.allowed_test_account_ids.contains(account)
    }

    /// Returns whether this exact API version is allowed.
    #[must_use]
    pub fn allows_api_version(&self, version: &str) -> bool {
        self.allowed_api_versions
            .binary_search_by(|value| value.as_str().cmp(version))
            .is_ok()
    }

    /// Returns whether this currency is allowed.
    #[must_use]
    pub fn allows_currency(&self, currency: &Currency) -> bool {
        self.allowed_currencies.contains(currency)
    }

    /// Returns the refund ceiling for a currency.
    #[must_use]
    pub fn maximum_refund_minor(&self, currency: &Currency) -> Option<u64> {
        self.maximum_refund_minor_by_currency.get(currency).copied()
    }

    /// Returns whether the reason is allowed.
    #[must_use]
    pub fn allows_reason(&self, reason: Option<&str>) -> bool {
        reason.is_none_or(|value| self.allowed_reasons.iter().any(|item| item == value))
    }

    /// Returns maximum evidence age.
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }

    /// Returns maximum authorization lifetime.
    #[must_use]
    pub const fn maximum_authorization_lifetime_seconds(&self) -> u64 {
        self.maximum_authorization_lifetime_seconds
    }

    /// Returns whether partial refunds are allowed.
    #[must_use]
    pub const fn allow_partial_refunds(&self) -> bool {
        self.allow_partial_refunds
    }

    /// Returns whether application-fee refunds are allowed.
    #[must_use]
    pub const fn allow_refund_application_fee(&self) -> bool {
        self.allow_refund_application_fee
    }

    /// Returns whether transfer reversals are allowed.
    #[must_use]
    pub const fn allow_reverse_transfer(&self) -> bool {
        self.allow_reverse_transfer
    }

    /// Returns whether the exact metadata key is allowed.
    #[must_use]
    pub fn allows_metadata_key(&self, key: &str) -> bool {
        self.allowed_metadata_keys
            .binary_search_by(|value| value.as_str().cmp(key))
            .is_ok()
    }

    /// Returns the exact executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }

    /// Returns the receipt schema.
    #[must_use]
    pub fn receipt_schema_version(&self) -> &str {
        &self.receipt_schema_version
    }
}

/// Fresh normalized Charge evidence from a protected Stripe read path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Stripe exposes independent paid, captured, refunded, disputed, and livemode facts that must remain separately committed"
)]
pub struct RefundEvidenceV1 {
    schema: String,
    stripe_account_id: StripeAccountId,
    stripe_api_version: String,
    livemode: bool,
    charge_id: ChargeId,
    payment_intent_id: Option<PaymentIntentId>,
    connect_account_id: Option<StripeAccountId>,
    currency: Currency,
    charge_amount_minor: u64,
    captured_amount_minor: u64,
    amount_refunded_minor: u64,
    refundable_amount_minor: u64,
    paid: bool,
    captured: bool,
    charge_refunded: bool,
    disputed: bool,
    observed_at: u64,
    response_commitment: DigestHex,
}

/// Input for normalized Stripe evidence.
#[allow(
    clippy::struct_excessive_bools,
    reason = "input mirrors the separately committed Stripe state facts without collapsing distinct provider meanings"
)]
pub struct RefundEvidenceInput {
    /// Stripe account context.
    pub stripe_account_id: StripeAccountId,
    /// Pinned API version.
    pub stripe_api_version: String,
    /// Provider livemode bit.
    pub livemode: bool,
    /// Charge.
    pub charge_id: ChargeId,
    /// Related `PaymentIntent`.
    pub payment_intent_id: Option<PaymentIntentId>,
    /// Explicit Stripe Connect account context, absent for direct/platform use.
    pub connect_account_id: Option<StripeAccountId>,
    /// Currency.
    pub currency: Currency,
    /// Original amount.
    pub charge_amount_minor: u64,
    /// Amount captured by Stripe.
    pub captured_amount_minor: u64,
    /// Already-refunded amount.
    pub amount_refunded_minor: u64,
    /// Paid bit.
    pub paid: bool,
    /// Captured bit.
    pub captured: bool,
    /// Fully refunded bit.
    pub charge_refunded: bool,
    /// Dispute bit.
    pub disputed: bool,
    /// Trusted observation time.
    pub observed_at: u64,
    /// Commitment to the bounded normalized provider response.
    pub response_commitment: DigestHex,
}

impl RefundEvidenceV1 {
    /// Builds internally consistent Stripe evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for contradictory provider facts.
    pub fn new(input: RefundEvidenceInput) -> Result<Self, ValidationError> {
        if !valid_api_version(&input.stripe_api_version)
            || input.charge_amount_minor == 0
            || input.captured_amount_minor == 0
            || input.captured_amount_minor > input.charge_amount_minor
            || input.amount_refunded_minor > input.charge_amount_minor
            || input.amount_refunded_minor > input.captured_amount_minor
        {
            return Err(ValidationError::InvalidEvidence);
        }
        let refundable_amount_minor = input
            .captured_amount_minor
            .checked_sub(input.amount_refunded_minor)
            .ok_or(ValidationError::InvalidEvidence)?;
        if input.charge_refunded != (refundable_amount_minor == 0) {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(Self {
            schema: "auths.stripe.refund-evidence/1".into(),
            stripe_account_id: input.stripe_account_id,
            stripe_api_version: input.stripe_api_version,
            livemode: input.livemode,
            charge_id: input.charge_id,
            payment_intent_id: input.payment_intent_id,
            connect_account_id: input.connect_account_id,
            currency: input.currency,
            charge_amount_minor: input.charge_amount_minor,
            captured_amount_minor: input.captured_amount_minor,
            amount_refunded_minor: input.amount_refunded_minor,
            refundable_amount_minor,
            paid: input.paid,
            captured: input.captured,
            charge_refunded: input.charge_refunded,
            disputed: input.disputed,
            observed_at: input.observed_at,
            response_commitment: input.response_commitment,
        })
    }

    /// Returns a canonical evidence digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Stripe account.
    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    /// API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Provider livemode bit.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// Charge.
    #[must_use]
    pub const fn charge_id(&self) -> &ChargeId {
        &self.charge_id
    }

    /// Related `PaymentIntent`.
    #[must_use]
    pub const fn payment_intent_id(&self) -> Option<&PaymentIntentId> {
        self.payment_intent_id.as_ref()
    }

    /// Explicit connected-account context.
    #[must_use]
    pub const fn connect_account_id(&self) -> Option<&StripeAccountId> {
        self.connect_account_id.as_ref()
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Original amount.
    #[must_use]
    pub const fn charge_amount_minor(&self) -> u64 {
        self.charge_amount_minor
    }

    /// Captured amount.
    #[must_use]
    pub const fn captured_amount_minor(&self) -> u64 {
        self.captured_amount_minor
    }

    /// Already refunded.
    #[must_use]
    pub const fn amount_refunded_minor(&self) -> u64 {
        self.amount_refunded_minor
    }

    /// Remaining refundable amount.
    #[must_use]
    pub const fn refundable_amount_minor(&self) -> u64 {
        self.refundable_amount_minor
    }

    /// Paid state.
    #[must_use]
    pub const fn paid(&self) -> bool {
        self.paid
    }

    /// Captured state.
    #[must_use]
    pub const fn captured(&self) -> bool {
        self.captured
    }

    /// Fully refunded state.
    #[must_use]
    pub const fn charge_refunded(&self) -> bool {
        self.charge_refunded
    }

    /// Dispute state.
    #[must_use]
    pub const fn disputed(&self) -> bool {
        self.disputed
    }

    /// Observation time.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
}

/// Exact canonical refund action verified by Auths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRefundActionV1 {
    profile: String,
    workflow_id: String,
    executor_audience: String,
    stripe_account_id: StripeAccountId,
    stripe_api_version: String,
    livemode: bool,
    charge_id: ChargeId,
    payment_intent_id: Option<PaymentIntentId>,
    amount: Money,
    reason: Option<String>,
    metadata: BTreeMap<String, String>,
    refund_application_fee: bool,
    reverse_transfer: bool,
    expected_charge_amount_minor: u64,
    expected_amount_refunded_minor: u64,
    expected_refundable_amount_minor: u64,
    evidence_digest: DigestHex,
    required_configuration_digest: DigestHex,
    idempotency_key: String,
    observed_at: u64,
    expires_at: u64,
    nonce: DigestHex,
}

/// Input for an exact refund action.
pub struct ExactRefundActionInput {
    /// Stable workflow identifier.
    pub workflow_id: String,
    /// Executor audience.
    pub executor_audience: String,
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Pinned API version.
    pub stripe_api_version: String,
    /// Must be false in this profile.
    pub livemode: bool,
    /// Charge.
    pub charge_id: ChargeId,
    /// Related `PaymentIntent`.
    pub payment_intent_id: Option<PaymentIntentId>,
    /// Exact refund money.
    pub amount: Money,
    /// Optional allowed reason.
    pub reason: Option<String>,
    /// Fixed metadata.
    pub metadata: BTreeMap<String, String>,
    /// Connect application-fee side effect.
    pub refund_application_fee: bool,
    /// Connect transfer side effect.
    pub reverse_transfer: bool,
    /// Expected original charge amount.
    pub expected_charge_amount_minor: u64,
    /// Expected already-refunded amount.
    pub expected_amount_refunded_minor: u64,
    /// Expected remaining amount.
    pub expected_refundable_amount_minor: u64,
    /// Evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Evidence observation time.
    pub observed_at: u64,
    /// Action expiry.
    pub expires_at: u64,
    /// Unique nonce commitment.
    pub nonce: DigestHex,
}

#[derive(Serialize)]
struct IdempotencyPreimage<'a> {
    domain: &'static str,
    workflow_id: &'a str,
    stripe_account_id: &'a StripeAccountId,
    charge_id: &'a ChargeId,
    amount: &'a Money,
    evidence_digest: &'a DigestHex,
    nonce: &'a DigestHex,
}

impl ExactRefundActionV1 {
    /// Constructs and validates an exact action.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or unsafe fields.
    pub fn new(input: ExactRefundActionInput) -> Result<Self, ValidationError> {
        let idempotency_preimage = IdempotencyPreimage {
            domain: "auths.stripe.idempotency/1",
            workflow_id: &input.workflow_id,
            stripe_account_id: &input.stripe_account_id,
            charge_id: &input.charge_id,
            amount: &input.amount,
            evidence_digest: &input.evidence_digest,
            nonce: &input.nonce,
        };
        let idempotency_key = format!(
            "auths-refund-{}",
            sha256(
                &canonical_json(&idempotency_preimage)
                    .map_err(|_| ValidationError::Canonicalization)?
            )
        );
        let action = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            workflow_id: input.workflow_id,
            executor_audience: input.executor_audience,
            stripe_account_id: input.stripe_account_id,
            stripe_api_version: input.stripe_api_version,
            livemode: input.livemode,
            charge_id: input.charge_id,
            payment_intent_id: input.payment_intent_id,
            amount: input.amount,
            reason: input.reason,
            metadata: input.metadata,
            refund_application_fee: input.refund_application_fee,
            reverse_transfer: input.reverse_transfer,
            expected_charge_amount_minor: input.expected_charge_amount_minor,
            expected_amount_refunded_minor: input.expected_amount_refunded_minor,
            expected_refundable_amount_minor: input.expected_refundable_amount_minor,
            evidence_digest: input.evidence_digest,
            required_configuration_digest: input.required_configuration_digest,
            idempotency_key,
            observed_at: input.observed_at,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        action.validate()?;
        Ok(action)
    }

    /// Decodes and proves canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, invalid, or non-canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let action: Self = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        action.validate()?;
        if action
            .canonical_bytes()
            .map_err(|_| ValidationError::Canonicalization)?
            != bytes
        {
            return Err(ValidationError::NonCanonical);
        }
        Ok(action)
    }

    /// Validates all closed action invariants.
    ///
    /// # Errors
    ///
    /// Returns a stable validation class.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || !valid_workflow_id(&self.workflow_id)
            || auths_model::Audience::parse(&self.executor_audience).is_err()
            || !valid_api_version(&self.stripe_api_version)
            || self.livemode
            || self.amount.currency().as_str().is_empty()
            || self.expected_charge_amount_minor == 0
            || self.expected_amount_refunded_minor > self.expected_charge_amount_minor
            || self.expected_refundable_amount_minor
                > self.expected_charge_amount_minor - self.expected_amount_refunded_minor
            || self.amount.amount_minor() > self.expected_refundable_amount_minor
            || self.refund_application_fee
            || self.reverse_transfer
            || self
                .reason
                .as_deref()
                .is_some_and(|value| !valid_reason(value))
            || self.metadata.len() > MAX_METADATA_ENTRIES
            || self.metadata.iter().any(|(key, value)| {
                !valid_metadata_key(key)
                    || value.is_empty()
                    || value.len() > 128
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS
            || self.idempotency_key.len() != 77
            || !self.idempotency_key.starts_with("auths-refund-")
        {
            return Err(ValidationError::InvalidAction);
        }
        let preimage = IdempotencyPreimage {
            domain: "auths.stripe.idempotency/1",
            workflow_id: &self.workflow_id,
            stripe_account_id: &self.stripe_account_id,
            charge_id: &self.charge_id,
            amount: &self.amount,
            evidence_digest: &self.evidence_digest,
            nonce: &self.nonce,
        };
        let expected = format!(
            "auths-refund-{}",
            sha256(&canonical_json(&preimage).map_err(|_| ValidationError::Canonicalization)?)
        );
        if self.idempotency_key != expected {
            return Err(ValidationError::InvalidAction);
        }
        Ok(())
    }

    /// Returns canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Returns the canonical action digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Workflow identifier.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Executor audience.
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }

    /// Stripe account.
    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    /// API version.
    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    /// Provider livemode bit.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// Charge.
    #[must_use]
    pub const fn charge_id(&self) -> &ChargeId {
        &self.charge_id
    }

    /// `PaymentIntent`.
    #[must_use]
    pub const fn payment_intent_id(&self) -> Option<&PaymentIntentId> {
        self.payment_intent_id.as_ref()
    }

    /// Exact refund amount.
    #[must_use]
    pub const fn amount(&self) -> &Money {
        &self.amount
    }

    /// Refund reason.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Fixed metadata.
    #[must_use]
    pub const fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// Application-fee side effect.
    #[must_use]
    pub const fn refund_application_fee(&self) -> bool {
        self.refund_application_fee
    }

    /// Transfer side effect.
    #[must_use]
    pub const fn reverse_transfer(&self) -> bool {
        self.reverse_transfer
    }

    /// Expected original amount.
    #[must_use]
    pub const fn expected_charge_amount_minor(&self) -> u64 {
        self.expected_charge_amount_minor
    }

    /// Expected already-refunded amount.
    #[must_use]
    pub const fn expected_amount_refunded_minor(&self) -> u64 {
        self.expected_amount_refunded_minor
    }

    /// Expected remaining amount.
    #[must_use]
    pub const fn expected_refundable_amount_minor(&self) -> u64 {
        self.expected_refundable_amount_minor
    }

    /// Evidence commitment.
    #[must_use]
    pub const fn evidence_digest(&self) -> &DigestHex {
        &self.evidence_digest
    }

    /// Required configuration commitment.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Deterministic provider idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Evidence observation time.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Provider result normalized immediately after refund creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundResult {
    /// Stripe refund.
    pub refund_id: RefundId,
    /// Refunded Charge.
    pub charge_id: ChargeId,
    /// Related `PaymentIntent`.
    pub payment_intent_id: Option<PaymentIntentId>,
    /// Amount.
    pub amount: Money,
    /// Provider status.
    pub status: String,
    /// Provider request correlation.
    pub stripe_request_id: String,
    /// Completion time.
    pub observed_at: u64,
}

impl RefundResult {
    /// Validates bounded provider output.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or unsupported output.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !matches!(
            self.status.as_str(),
            "pending" | "requires_action" | "succeeded" | "failed" | "canceled"
        ) || self.stripe_request_id.is_empty()
            || self.stripe_request_id.len() > 128
            || self
                .stripe_request_id
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        {
            return Err(ValidationError::InvalidProviderResult);
        }
        Ok(())
    }
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/'))
}

fn valid_reason(value: &str) -> bool {
    matches!(value, "duplicate" | "fraudulent" | "requested_by_customer")
}

fn valid_metadata_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_workflow_id(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

/// Closed validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    /// Input exceeds a hard profile bound.
    #[error("Stripe profile limit exceeded")]
    LimitExceeded,
    /// JSON or identifier bytes are malformed.
    #[error("malformed Stripe profile input")]
    Malformed,
    /// Input is valid JSON but not canonical.
    #[error("non-canonical Stripe profile input")]
    NonCanonical,
    /// Canonicalization failed.
    #[error("Stripe profile canonicalization failed")]
    Canonicalization,
    /// Money is invalid.
    #[error("invalid money value")]
    InvalidMoney,
    /// Verifier configuration is invalid.
    #[error("invalid Stripe verifier configuration")]
    InvalidConfiguration,
    /// Provider evidence is contradictory.
    #[error("invalid Stripe evidence")]
    InvalidEvidence,
    /// Exact refund action is invalid.
    #[error("invalid exact Stripe refund action")]
    InvalidAction,
    /// Provider output is unsupported or malformed.
    #[error("invalid Stripe provider result")]
    InvalidProviderResult,
}
