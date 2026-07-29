use std::{env, io::Read as _, time::Duration};

use auths_stripe::{
    CredentialProvider, PortError, StripeAccountId, StripeCredential,
    merchant::MerchantConnectAccount,
};
use reqwest::{
    blocking::{Client, Response},
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;

const DEFAULT_BASE_URL: &str = "https://api.stripe.com";
const DEFAULT_API_VERSION: &str = "2025-04-30.basil";
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;

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

    fn optional(name: &'static str) -> Option<Self> {
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

/// Sanitized Stripe HTTP result. Secret-bearing response fields remain
/// provider-adapter-local and must not cross into receipts or frontend data.
pub struct StripeHttpResponse {
    /// Parsed bounded JSON.
    pub value: Value,
    /// Stripe request correlation, when present.
    pub request_id: Option<String>,
}

/// Strict test-mode HTTP and credential mechanism shared by the separate
/// collect and authorize provider adapters.
pub struct StripeHttp {
    client: Client,
    base_url: String,
    fixture_secret: SecretBytes,
    mutation_secret: SecretBytes,
    account_id: StripeAccountId,
    api_version: String,
}

impl StripeHttp {
    /// Loads fixed deployment configuration and discovers the account only in
    /// local development. Agent requests never influence these values.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or invalid deployment configuration, an
    /// unavailable Stripe endpoint, or a malformed account response.
    ///
    /// # Panics
    ///
    /// Panics only if the repository-owned placeholder account identifier is
    /// invalid.
    pub fn from_environment(mutation_secret_name: &'static str) -> Result<Self, PortError> {
        let production = env::var("AUTHS_STRIPE_RELEASE").as_deref() == Ok("production");
        let local_secret = SecretBytes::optional("AUTHS_STRIPE_TEST_SECRET_KEY");
        let fixture_secret = SecretBytes::optional("AUTHS_STRIPE_FIXTURE_SECRET_KEY")
            .or_else(|| {
                (!production)
                    .then(|| local_secret.as_ref().map(SecretBytes::duplicate))
                    .flatten()
            })
            .ok_or(PortError::InvalidConfiguration)?;
        let mutation_secret = SecretBytes::optional(mutation_secret_name)
            .or_else(|| {
                (!production)
                    .then(|| local_secret.as_ref().map(SecretBytes::duplicate))
                    .flatten()
            })
            .ok_or(PortError::InvalidConfiguration)?;
        let api_version = env::var("AUTHS_STRIPE_API_VERSION")
            .ok()
            .filter(|value| valid_api_version(value))
            .or_else(|| (!production).then(|| DEFAULT_API_VERSION.to_owned()))
            .ok_or(PortError::InvalidConfiguration)?;
        let base_url =
            env::var("AUTHS_STRIPE_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
        if !(base_url == DEFAULT_BASE_URL
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
            .user_agent("auths-stripe-payment-demo/1")
            .build()
            .map_err(|_| PortError::InvalidConfiguration)?;
        let configured_account = env::var("AUTHS_STRIPE_ACCOUNT_ID")
            .ok()
            .and_then(|value| StripeAccountId::parse(value).ok())
            .filter(|value| !value.as_str().contains("replace"));
        let mut value = Self {
            client,
            base_url,
            fixture_secret,
            mutation_secret,
            account_id: configured_account
                .clone()
                .unwrap_or_else(|| StripeAccountId::parse("acct_pending").expect("static id")),
            api_version,
        };
        if configured_account.is_none() {
            if production {
                return Err(PortError::InvalidConfiguration);
            }
            let response = value.fixture_get("/v1/account", &MerchantConnectAccount::Platform)?;
            value.account_id = StripeAccountId::parse(string(&response.value, "id")?)
                .map_err(|_| PortError::Malformed)?;
        }
        Ok(value)
    }

    /// Configured Stripe account.
    #[must_use]
    pub const fn account_id(&self) -> &StripeAccountId {
        &self.account_id
    }

    /// Pinned Stripe API version.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Fixture-only GET before a protected workflow exists.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, transport failure, or malformed
    /// Stripe response.
    pub fn fixture_get(
        &self,
        path: &str,
        connect: &MerchantConnectAccount,
    ) -> Result<StripeHttpResponse, PortError> {
        self.send(
            self.client.get(self.url(path)?),
            &self.fixture_secret.0,
            None,
            connect,
        )
    }

    /// Fixture-only POST before a protected workflow exists.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, transport failure, or malformed
    /// Stripe response.
    pub fn fixture_post(
        &self,
        path: &str,
        parameters: &[(String, String)],
        idempotency_key: &str,
        connect: &MerchantConnectAccount,
    ) -> Result<StripeHttpResponse, PortError> {
        self.send(
            self.client
                .post(self.url(path)?)
                .body(encode_form(parameters)),
            &self.fixture_secret.0,
            Some(idempotency_key),
            connect,
        )
    }

    /// Credential-gated GET reachable only from a verified provider command.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, transport failure, or malformed
    /// Stripe response.
    pub fn protected_get(
        &self,
        path: &str,
        credential: &StripeCredential,
        connect: &MerchantConnectAccount,
    ) -> Result<StripeHttpResponse, PortError> {
        self.send(
            self.client.get(self.url(path)?),
            credential.expose(),
            None,
            connect,
        )
    }

    /// Credential-gated POST reachable only from a verified provider command.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, transport failure, or malformed
    /// Stripe response.
    pub fn protected_post(
        &self,
        path: &str,
        parameters: &[(String, String)],
        idempotency_key: &str,
        credential: &StripeCredential,
        connect: &MerchantConnectAccount,
    ) -> Result<StripeHttpResponse, PortError> {
        self.send(
            self.client
                .post(self.url(path)?)
                .body(encode_form(parameters)),
            credential.expose(),
            Some(idempotency_key),
            connect,
        )
    }

    fn url(&self, path: &str) -> Result<String, PortError> {
        if !path.starts_with("/v1/")
            || path.contains("://")
            || path.bytes().any(|byte| byte.is_ascii_whitespace())
            || path.len() > 512
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(format!("{}{}", self.base_url, path))
    }

    fn send(
        &self,
        request: reqwest::blocking::RequestBuilder,
        secret: &[u8],
        idempotency_key: Option<&str>,
        connect: &MerchantConnectAccount,
    ) -> Result<StripeHttpResponse, PortError> {
        let response = request
            .headers(self.headers(secret, idempotency_key, connect)?)
            .send()
            .map_err(|_| PortError::OutcomeUnknown)?;
        read_json(response)
    }

    fn headers(
        &self,
        secret: &[u8],
        idempotency_key: Option<&str>,
        connect: &MerchantConnectAccount,
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
            if !(8..=255).contains(&value.len())
                || value
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
            {
                return Err(PortError::InvalidConfiguration);
            }
            headers.insert(
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(value).map_err(|_| PortError::InvalidConfiguration)?,
            );
        }
        if let Some(account) = connect.connected_account_id() {
            headers.insert(
                HeaderName::from_static("stripe-account"),
                HeaderValue::from_str(account.as_str())
                    .map_err(|_| PortError::InvalidConfiguration)?,
            );
        }
        Ok(headers)
    }
}

impl CredentialProvider for StripeHttp {
    fn mutation_credential(
        &self,
        account: &StripeAccountId,
    ) -> Result<StripeCredential, PortError> {
        if account != &self.account_id {
            return Err(PortError::InvalidConfiguration);
        }
        StripeCredential::new(self.mutation_secret.0.clone())
    }
}

fn read_json(response: Response) -> Result<StripeHttpResponse, PortError> {
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
        .map_err(|_| PortError::OutcomeUnknown)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(PortError::LimitExceeded);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| PortError::Malformed)?;
    if !status.is_success() {
        return Err(PortError::Execution);
    }
    Ok(StripeHttpResponse { value, request_id })
}

fn encode_form(parameters: &[(String, String)]) -> String {
    parameters
        .iter()
        .map(|(key, value)| format!("{}={}", form_component(key), form_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PortError::Malformed)
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}
