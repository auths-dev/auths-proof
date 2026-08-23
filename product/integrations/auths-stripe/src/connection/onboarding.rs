use super::StripeConnectionDescriptor;
use auths_connections::{ConnectionAdapterError, CredentialStoreError, SecretBytes};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use serde::Deserialize;
use std::{io::Read as _, time::Duration};

const STRIPE_ACCOUNT_ENDPOINT: &str = "https://api.stripe.com/v1/account";
const MAX_ACCOUNT_RESPONSE_BYTES: u64 = 65_536;

/// Validates a noninteractive Stripe test credential read from protected administration input.
///
/// # Errors
///
/// Rejects live-mode, empty, non-ASCII, or oversized secret material.
pub fn validate_static_secret(bytes: Vec<u8>) -> Result<SecretBytes, CredentialStoreError> {
    if !valid_static_secret(&bytes) {
        return Err(CredentialStoreError::InvalidSecret);
    }
    SecretBytes::new(bytes)
}

/// Proves that a protected Stripe test key resolves to the descriptor's exact
/// account before the connection record and credential generation are made
/// durable.
///
/// # Errors
///
/// Returns [`ConnectionAdapterError`] when the descriptor, credential, HTTPS
/// exchange, or discovered Stripe account identity fails closed.
pub fn validate_onboarding(
    descriptor: &[u8],
    bytes: Vec<u8>,
) -> Result<SecretBytes, ConnectionAdapterError> {
    let descriptor = StripeConnectionDescriptor::from_canonical_bytes(descriptor)?;
    let candidate = CandidateSecret::new(bytes)?;
    let credential = std::str::from_utf8(candidate.expose())
        .map_err(|_| ConnectionAdapterError::CredentialUnavailable)?;
    let client = Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| ConnectionAdapterError::PreparationFailed)?;
    let response = client
        .get(STRIPE_ACCOUNT_ENDPOINT)
        .bearer_auth(credential)
        .header("Accept", "application/json")
        .header("Stripe-Version", descriptor.api_version())
        .send()
        .map_err(|_| ConnectionAdapterError::PreparationFailed)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(ConnectionAdapterError::CredentialUnavailable);
        }
        _ => return Err(ConnectionAdapterError::PreparationFailed),
    }
    if response
        .headers()
        .get("Stripe-Version")
        .and_then(|value| value.to_str().ok())
        != Some(descriptor.api_version())
        || response
            .content_length()
            .is_some_and(|length| length > MAX_ACCOUNT_RESPONSE_BYTES)
    {
        return Err(ConnectionAdapterError::PreparationFailed);
    }
    let mut body = Vec::new();
    response
        .take(MAX_ACCOUNT_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| ConnectionAdapterError::PreparationFailed)?;
    if body.is_empty() || body.len() as u64 > MAX_ACCOUNT_RESPONSE_BYTES {
        return Err(ConnectionAdapterError::PreparationFailed);
    }
    verify_account_response(&descriptor, &body)?;
    candidate.into_secret()
}

fn valid_static_secret(bytes: &[u8]) -> bool {
    bytes.starts_with(b"rk_test_")
        && (16..=256).contains(&bytes.len())
        && bytes.iter().all(u8::is_ascii_graphic)
}

fn verify_account_response(
    descriptor: &StripeConnectionDescriptor,
    bytes: &[u8],
) -> Result<(), ConnectionAdapterError> {
    let account: StripeAccountResponse =
        serde_json::from_slice(bytes).map_err(|_| ConnectionAdapterError::PreparationFailed)?;
    if account.object != "account"
        || account.id != descriptor.account_id()
        || descriptor.livemode()
        || account.livemode == Some(true)
    {
        return Err(ConnectionAdapterError::AccountSubstitution);
    }
    Ok(())
}

#[derive(Deserialize)]
struct StripeAccountResponse {
    id: String,
    object: String,
    #[serde(default)]
    livemode: Option<bool>,
}

struct CandidateSecret(Vec<u8>);

impl CandidateSecret {
    fn new(bytes: Vec<u8>) -> Result<Self, ConnectionAdapterError> {
        if !valid_static_secret(&bytes) {
            return Err(ConnectionAdapterError::CredentialUnavailable);
        }
        Ok(Self(bytes))
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }

    fn into_secret(mut self) -> Result<SecretBytes, ConnectionAdapterError> {
        SecretBytes::new(std::mem::take(&mut self.0))
            .map_err(|_| ConnectionAdapterError::CredentialUnavailable)
    }
}

impl Drop for CandidateSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> StripeConnectionDescriptor {
        StripeConnectionDescriptor::from_canonical_bytes(include_bytes!(
            "../../fixtures/connection/v1/valid.json"
        ))
        .unwrap()
    }

    #[test]
    fn account_discovery_must_match_the_committed_test_account() {
        let descriptor = descriptor();
        verify_account_response(
            &descriptor,
            br#"{"id":"acct_test_primary","livemode":false,"object":"account","charges_enabled":true}"#,
        )
        .unwrap();
        assert_eq!(
            verify_account_response(
                &descriptor,
                br#"{"id":"acct_substituted","livemode":false,"object":"account"}"#,
            ),
            Err(ConnectionAdapterError::AccountSubstitution)
        );
        assert_eq!(
            verify_account_response(
                &descriptor,
                br#"{"id":"acct_test_primary","livemode":true,"object":"account"}"#,
            ),
            Err(ConnectionAdapterError::AccountSubstitution)
        );
    }
}
