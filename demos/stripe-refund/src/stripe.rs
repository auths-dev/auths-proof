use std::{env, io::Read as _, time::Duration};

use auths_stripe::{
    ChargeId, CredentialProvider, Currency, ExactRefundActionV1, Money, PaymentIntentId, PortError,
    RefundEvidenceInput, RefundEvidenceV1, RefundId, RefundResult, StripeAccountId,
    StripeCredential, StripeGateway, VerifiedRefundCommand,
    canonical::{canonical_json, sha256},
};
use reqwest::{
    blocking::{Client, Response},
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;

const DEFAULT_STRIPE_BASE_URL: &str = "https://api.stripe.com";
const DEFAULT_STRIPE_API_VERSION: &str = "2025-04-30.basil";
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;
const FIXTURE_AMOUNT_MINOR: u64 = 2_000;

/// Stripe behavior required by the demo in addition to the protected product ports.
pub trait DemoStripeEnvironment: CredentialProvider + StripeGateway {
    /// Creates a fresh real test payment and returns normalized evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed provider failure.
    fn seed_payment(&self, workflow_id: &str, now: u64) -> Result<RefundEvidenceV1, PortError>;

    /// Returns the configured account.
    fn account_id(&self) -> &StripeAccountId;

    /// Returns the pinned API version.
    fn api_version(&self) -> &str;

    /// Returns a truthful execution mode label.
    fn execution_mode(&self) -> &'static str;

    /// Observes whether Stripe created the exact refund after an ambiguous call.
    ///
    /// # Errors
    ///
    /// Returns a closed provider/evidence failure. `None` means a fresh,
    /// bounded Stripe list proved no matching refund.
    fn reconcile_refund(
        &self,
        action: &ExactRefundActionV1,
        now: u64,
    ) -> Result<Option<RefundResult>, PortError>;
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(value: String) -> Result<Self, PortError> {
        if !(16..=512).contains(&value.len())
            || !value.starts_with("sk_test_")
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self(value.into_bytes()))
    }

    fn from_optional_environment(name: &'static str) -> Option<Self> {
        env::var(name).ok().and_then(|value| Self::new(value).ok())
    }

    fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

/// Real Stripe test-mode environment.
pub struct LiveStripeEnvironment {
    client: Client,
    base_url: String,
    fixture_secret: SecretBytes,
    mutation_secret: SecretBytes,
    account_id: StripeAccountId,
    api_version: String,
}

impl LiveStripeEnvironment {
    /// Loads a strict Stripe test-mode environment.
    ///
    /// Production requires:
    ///
    /// - `AUTHS_STRIPE_FIXTURE_SECRET_KEY`
    /// - `AUTHS_STRIPE_REFUND_SECRET_KEY`
    /// - `AUTHS_STRIPE_ACCOUNT_ID`
    /// - `AUTHS_STRIPE_API_VERSION`
    ///
    /// Local development may instead provide `AUTHS_STRIPE_TEST_SECRET_KEY`.
    /// In that mode the demo pins its API version and discovers the test
    /// account through Stripe.
    ///
    /// # Errors
    ///
    /// Returns a closed startup failure for missing or unsafe configuration.
    pub fn from_environment() -> Result<Self, PortError> {
        let production = env::var("AUTHS_STRIPE_RELEASE").as_deref() == Ok("production");
        let local_secret = SecretBytes::from_optional_environment("AUTHS_STRIPE_TEST_SECRET_KEY");
        let fixture_secret =
            SecretBytes::from_optional_environment("AUTHS_STRIPE_FIXTURE_SECRET_KEY")
                .or_else(|| {
                    if production {
                        None
                    } else {
                        local_secret.as_ref().map(SecretBytes::duplicate)
                    }
                })
                .ok_or(PortError::InvalidConfiguration)?;
        let mutation_secret =
            SecretBytes::from_optional_environment("AUTHS_STRIPE_REFUND_SECRET_KEY")
                .or_else(|| {
                    if production {
                        None
                    } else {
                        local_secret.as_ref().map(SecretBytes::duplicate)
                    }
                })
                .ok_or(PortError::InvalidConfiguration)?;
        let api_version = env::var("AUTHS_STRIPE_API_VERSION")
            .ok()
            .filter(|value| valid_api_version(value))
            .or_else(|| (!production).then(|| DEFAULT_STRIPE_API_VERSION.to_owned()))
            .ok_or(PortError::InvalidConfiguration)?;
        let base_url =
            env::var("AUTHS_STRIPE_BASE_URL").unwrap_or_else(|_| DEFAULT_STRIPE_BASE_URL.into());
        if !(base_url == DEFAULT_STRIPE_BASE_URL
            || base_url.starts_with("http://127.0.0.1:")
            || base_url.starts_with("http://localhost:"))
            || base_url.ends_with('/')
            || base_url.len() > 256
        {
            return Err(PortError::InvalidConfiguration);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("auths-stripe-demo/1")
            .build()
            .map_err(|_| PortError::InvalidConfiguration)?;
        let account_id = env::var("AUTHS_STRIPE_ACCOUNT_ID")
            .ok()
            .and_then(|value| StripeAccountId::parse(value).ok())
            .filter(|value| !value.as_str().contains("replace"))
            .map_or_else(
                || {
                    if production {
                        return Err(PortError::InvalidConfiguration);
                    }
                    let secret = std::str::from_utf8(&fixture_secret.0)
                        .map_err(|_| PortError::InvalidConfiguration)?;
                    let response = client
                        .get(format!("{base_url}/v1/account"))
                        .bearer_auth(secret)
                        .header("Stripe-Version", &api_version)
                        .send()
                        .map_err(|_| PortError::EvidenceUnavailable)?;
                    let (value, _) = Self::read_json(response)?;
                    StripeAccountId::parse(string(&value, "id")?).map_err(|_| PortError::Malformed)
                },
                Ok,
            )?;
        Ok(Self {
            client,
            base_url,
            fixture_secret,
            mutation_secret,
            account_id,
            api_version,
        })
    }

    fn headers(
        &self,
        secret: &[u8],
        idempotency_key: Option<&str>,
        connect_account: Option<&StripeAccountId>,
    ) -> Result<HeaderMap, PortError> {
        let secret = std::str::from_utf8(secret).map_err(|_| PortError::InvalidConfiguration)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {secret}"))
            .map_err(|_| PortError::InvalidConfiguration)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(
            HeaderName::from_static("stripe-version"),
            HeaderValue::from_str(&self.api_version)
                .map_err(|_| PortError::InvalidConfiguration)?,
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if let Some(value) = idempotency_key {
            headers.insert(
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(value).map_err(|_| PortError::InvalidConfiguration)?,
            );
        }
        if let Some(account) = connect_account {
            headers.insert(
                HeaderName::from_static("stripe-account"),
                HeaderValue::from_str(account.as_str())
                    .map_err(|_| PortError::InvalidConfiguration)?,
            );
        }
        Ok(headers)
    }

    fn read_json(response: Response) -> Result<(Value, Option<String>), PortError> {
        let status = response.status();
        let request_id = response
            .headers()
            .get("request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|value| value > MAX_RESPONSE_BYTES)
        {
            return Err(PortError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PortError::EvidenceUnavailable)?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(PortError::LimitExceeded);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| PortError::Malformed)?;
        if !status.is_success() {
            return Err(PortError::Execution);
        }
        Ok((value, request_id))
    }

    fn retrieve_charge(
        &self,
        charge_id: &ChargeId,
        now: u64,
        connect_account: Option<&StripeAccountId>,
    ) -> Result<RefundEvidenceV1, PortError> {
        let response = self
            .client
            .get(format!("{}/v1/charges/{}", self.base_url, charge_id))
            .headers(self.headers(&self.fixture_secret.0, None, connect_account)?)
            .send()
            .map_err(|_| PortError::EvidenceUnavailable)?;
        let (value, _) = Self::read_json(response).map_err(|error| match error {
            PortError::Execution => PortError::EvidenceUnavailable,
            other => other,
        })?;
        evidence_from_charge(
            &value,
            &self.account_id,
            &self.api_version,
            connect_account,
            now,
        )
    }
}

impl DemoStripeEnvironment for LiveStripeEnvironment {
    fn seed_payment(&self, workflow_id: &str, now: u64) -> Result<RefundEvidenceV1, PortError> {
        if !(8..=96).contains(&workflow_id.len())
            || workflow_id
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        {
            return Err(PortError::Malformed);
        }
        let parameters = [
            ("amount".into(), FIXTURE_AMOUNT_MINOR.to_string()),
            ("currency".into(), "usd".into()),
            ("payment_method".into(), "pm_card_visa".into()),
            ("payment_method_types[]".into(), "card".into()),
            ("confirm".into(), "true".into()),
            (
                "description".into(),
                "Auths exact-refund demonstration".into(),
            ),
            ("metadata[auths_workflow]".into(), workflow_id.into()),
        ];
        let body = encode_form(&parameters);
        let response = self
            .client
            .post(format!("{}/v1/payment_intents", self.base_url))
            .headers(self.headers(
                &self.fixture_secret.0,
                Some(&format!("auths-fixture-{workflow_id}")),
                None,
            )?)
            .body(body)
            .send()
            .map_err(|_| PortError::EvidenceUnavailable)?;
        let (value, _) = Self::read_json(response)?;
        if value.get("livemode").and_then(Value::as_bool) != Some(false) {
            return Err(PortError::Malformed);
        }
        let charge_id = value
            .get("latest_charge")
            .and_then(Value::as_str)
            .ok_or(PortError::Malformed)
            .and_then(|value| ChargeId::parse(value).map_err(|_| PortError::Malformed))?;
        self.retrieve_charge(&charge_id, now, None)
    }

    fn account_id(&self) -> &StripeAccountId {
        &self.account_id
    }

    fn api_version(&self) -> &str {
        &self.api_version
    }

    fn execution_mode(&self) -> &'static str {
        "stripe-test-mode"
    }

    fn reconcile_refund(
        &self,
        action: &ExactRefundActionV1,
        now: u64,
    ) -> Result<Option<RefundResult>, PortError> {
        if action.stripe_account_id() != &self.account_id
            || action.stripe_api_version() != self.api_version
            || action.livemode()
        {
            return Err(PortError::InvalidConfiguration);
        }
        let connect_account = connect_account_for_action(action)?;
        let response = self
            .client
            .get(format!(
                "{}/v1/refunds?charge={}&limit=100",
                self.base_url,
                action.charge_id()
            ))
            .headers(self.headers(&self.fixture_secret.0, None, connect_account.as_ref())?)
            .send()
            .map_err(|_| PortError::EvidenceUnavailable)?;
        let (value, request_id) = Self::read_json(response)?;
        let data = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or(PortError::Malformed)?;
        for candidate in data {
            let workflow_matches = candidate
                .get("metadata")
                .and_then(Value::as_object)
                .and_then(|metadata| metadata.get("auths_workflow"))
                .and_then(Value::as_str)
                == Some(action.workflow_id());
            let amount_matches = candidate.get("amount").and_then(Value::as_u64)
                == Some(action.amount().amount_minor());
            let currency_matches = candidate.get("currency").and_then(Value::as_str)
                == Some(action.amount().currency().as_str());
            if workflow_matches && amount_matches && currency_matches {
                return refund_result(candidate, request_id.as_deref(), now).map(Some);
            }
        }
        Ok(None)
    }
}

impl CredentialProvider for LiveStripeEnvironment {
    fn credential(&self, account: &StripeAccountId) -> Result<StripeCredential, PortError> {
        if account != &self.account_id {
            return Err(PortError::InvalidConfiguration);
        }
        StripeCredential::new(self.mutation_secret.0.clone())
    }
}

impl StripeGateway for LiveStripeEnvironment {
    fn create_refund(
        &self,
        command: &VerifiedRefundCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<RefundResult, PortError> {
        let action = command.action();
        if action.stripe_account_id() != &self.account_id
            || action.stripe_api_version() != self.api_version
            || action.livemode()
        {
            return Err(PortError::InvalidConfiguration);
        }
        let connect_account = connect_account_for_action(action)?;
        let fresh = self.retrieve_charge(action.charge_id(), now, connect_account.as_ref())?;
        let authorized = command.evidence();
        if fresh.stripe_account_id() != authorized.stripe_account_id()
            || fresh.stripe_api_version() != authorized.stripe_api_version()
            || fresh.livemode() != authorized.livemode()
            || fresh.charge_id() != authorized.charge_id()
            || fresh.payment_intent_id() != authorized.payment_intent_id()
            || fresh.connect_account_id() != authorized.connect_account_id()
            || fresh.currency() != authorized.currency()
            || fresh.charge_amount_minor() != authorized.charge_amount_minor()
            || fresh.captured_amount_minor() != authorized.captured_amount_minor()
            || fresh.amount_refunded_minor() != authorized.amount_refunded_minor()
            || fresh.refundable_amount_minor() != authorized.refundable_amount_minor()
            || fresh.paid() != authorized.paid()
            || fresh.captured() != authorized.captured()
            || fresh.charge_refunded() != authorized.charge_refunded()
            || fresh.disputed() != authorized.disputed()
        {
            return Err(PortError::Execution);
        }
        let mut parameters = vec![
            ("charge".into(), action.charge_id().to_string()),
            ("amount".into(), action.amount().amount_minor().to_string()),
        ];
        if let Some(reason) = action.reason() {
            parameters.push(("reason".into(), reason.into()));
        }
        for (key, value) in action.metadata() {
            parameters.push((format!("metadata[{key}]"), value.clone()));
        }
        let response = self
            .client
            .post(format!("{}/v1/refunds", self.base_url))
            .headers(self.headers(
                credential.expose(),
                Some(action.idempotency_key()),
                connect_account.as_ref(),
            )?)
            .body(encode_form(&parameters))
            .send()
            .map_err(|_| PortError::OutcomeUnknown)?;
        let (value, request_id) = Self::read_json(response).map_err(|error| {
            if error == PortError::Execution {
                PortError::Execution
            } else {
                PortError::OutcomeUnknown
            }
        })?;
        let result = refund_result(&value, request_id.as_deref(), now)
            .map_err(|_| PortError::OutcomeUnknown)?;
        if result.charge_id != *action.charge_id()
            || result.amount != *action.amount()
            || value.get("object").and_then(Value::as_str) != Some("refund")
        {
            return Err(PortError::OutcomeUnknown);
        }
        Ok(result)
    }
}

fn connect_account_for_action(
    action: &ExactRefundActionV1,
) -> Result<Option<StripeAccountId>, PortError> {
    match action
        .metadata()
        .get("auths_connect_account")
        .map(String::as_str)
    {
        None | Some("platform") => Ok(None),
        Some(value) => StripeAccountId::parse(value)
            .map(Some)
            .map_err(|_| PortError::InvalidConfiguration),
    }
}

fn evidence_from_charge(
    value: &Value,
    account_id: &StripeAccountId,
    api_version: &str,
    connect_account: Option<&StripeAccountId>,
    now: u64,
) -> Result<RefundEvidenceV1, PortError> {
    let charge_id = string_id(value, "id", |value| ChargeId::parse(value.to_owned()))?;
    let payment_intent_id = value
        .get("payment_intent")
        .and_then(Value::as_str)
        .map(PaymentIntentId::parse)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    let currency = Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?;
    let amount = unsigned(value, "amount")?;
    let amount_refunded = unsigned(value, "amount_refunded")?;
    let response_commitment = sha256(&canonical_json(value).map_err(|_| PortError::Malformed)?);
    RefundEvidenceV1::new(RefundEvidenceInput {
        stripe_account_id: account_id.clone(),
        stripe_api_version: api_version.into(),
        livemode: boolean(value, "livemode")?,
        charge_id,
        payment_intent_id,
        connect_account_id: connect_account.cloned(),
        currency,
        charge_amount_minor: amount,
        captured_amount_minor: value
            .get("amount_captured")
            .and_then(Value::as_u64)
            .unwrap_or(amount),
        amount_refunded_minor: amount_refunded,
        paid: boolean(value, "paid")?,
        captured: boolean(value, "captured")?,
        charge_refunded: boolean(value, "refunded")?,
        disputed: value
            .get("disputed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        observed_at: now,
        response_commitment,
    })
    .map_err(|_| PortError::Malformed)
}

fn refund_result(
    value: &Value,
    request_id: Option<&str>,
    now: u64,
) -> Result<RefundResult, PortError> {
    let result = RefundResult {
        refund_id: string_id(value, "id", |value| RefundId::parse(value.to_owned()))?,
        charge_id: string_id(value, "charge", |value| ChargeId::parse(value.to_owned()))?,
        payment_intent_id: value
            .get("payment_intent")
            .and_then(Value::as_str)
            .map(PaymentIntentId::parse)
            .transpose()
            .map_err(|_| PortError::Malformed)?,
        amount: Money::new(
            Currency::parse(string(value, "currency")?).map_err(|_| PortError::Malformed)?,
            unsigned(value, "amount")?,
        )
        .map_err(|_| PortError::Malformed)?,
        status: string(value, "status")?.into(),
        stripe_request_id: request_id.ok_or(PortError::Malformed)?.into(),
        observed_at: now,
    };
    result.validate().map_err(|_| PortError::Malformed)?;
    Ok(result)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PortError::Malformed)
}

fn string_id<T>(
    value: &Value,
    key: &str,
    parse: impl FnOnce(&str) -> Result<T, auths_stripe::types::TypeError>,
) -> Result<T, PortError> {
    parse(string(value, key)?).map_err(|_| PortError::Malformed)
}

fn unsigned(value: &Value, key: &str) -> Result<u64, PortError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(PortError::Malformed)
}

fn boolean(value: &Value, key: &str) -> Result<bool, PortError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(PortError::Malformed)
}

fn encode_form(parameters: &[(String, String)]) -> String {
    parameters
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_is_deterministic_and_escapes_nested_keys() {
        assert_eq!(
            encode_form(&[("metadata[auths_workflow]".into(), "one two".into())]),
            "metadata%5Bauths_workflow%5D=one%20two"
        );
    }

    #[test]
    fn real_refund_shape_does_not_require_a_livemode_field() {
        let value = serde_json::json!({
            "id": "re_authsdemo00000001",
            "object": "refund",
            "charge": "ch_authsdemo00000001",
            "payment_intent": "pi_authsdemo00000001",
            "amount": 1_000,
            "currency": "usd",
            "status": "succeeded"
        });
        let result = refund_result(&value, Some("req_authsdemo00000001"), 1_000)
            .expect("the real Stripe Refund shape should normalize");
        assert_eq!(result.amount.amount_minor(), 1_000);
        assert_eq!(value.get("object").and_then(Value::as_str), Some("refund"));
        assert!(value.get("livemode").is_none());
    }
}
