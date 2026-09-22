//! Credential-bearing HTTPS transport. Only the gateway process may call this.

// These matches separate definite pre-entry failure from ambiguous network entry.
#![allow(clippy::manual_let_else)]

use crate::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
};
use auths_connections::StoredSecretLease;
use reqwest::{
    Client,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use sha2::{Digest as _, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as _},
    time::{Duration, Instant},
};
use thiserror::Error;
use url::Url;

const MAX_WRITE_RESPONSE_BYTES: usize = 65_536;
const MAX_SECRET_BYTES: usize = 4_096;

/// Secret-free transport failure. `Unknown` is possible after network entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub(crate) enum GatewayTransportError {
    /// DNS, binding, or request construction failed before network entry.
    #[error("transport was not entered")]
    NotEntered,
}

/// Write transport evidence, never provider-effect confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteTransportOutcome {
    /// The request may have entered, but a complete response was not recorded.
    Unknown,
    /// A complete bounded HTTP response was received.
    ResponseRecorded { status: u16, digest: [u8; 32] },
}

/// One DNS-pinned, no-proxy, no-redirect client for an operator-approved origin.
/// An IPv6-only destination is rejected in this first version.
pub(crate) struct GatewayHttpTransport {
    client: Client,
    origin: String,
    requirement: CredentialRequirement,
}

impl GatewayHttpTransport {
    /// Resolves and pins a public IPv4 address before claim or secret access.
    pub(crate) fn prepare(
        recipe: &CompiledRecipe,
        connection_requirement: &CredentialRequirement,
    ) -> Result<Self, GatewayTransportError> {
        let review = recipe.review();
        if review.credential() != connection_requirement {
            return Err(GatewayTransportError::NotEntered);
        }
        let origin = review.origin();
        let parsed = Url::parse(origin).map_err(|_| GatewayTransportError::NotEntered)?;
        if parsed.scheme() != "https" || parsed.port_or_known_default() != Some(443) {
            return Err(GatewayTransportError::NotEntered);
        }
        let hostname = parsed.host_str().ok_or(GatewayTransportError::NotEntered)?;
        let addresses: Vec<SocketAddr> = (hostname, 443)
            .to_socket_addrs()
            .map_err(|_| GatewayTransportError::NotEntered)?
            .collect();
        if addresses.is_empty()
            || addresses.iter().any(|address| match address.ip() {
                IpAddr::V4(ip) => !public_ipv4(ip),
                IpAddr::V6(_) => false,
            })
        {
            return Err(GatewayTransportError::NotEntered);
        }
        let pinned = addresses
            .iter()
            .find(|address| matches!(address.ip(), IpAddr::V4(_)))
            .copied()
            .ok_or(GatewayTransportError::NotEntered)?;
        let client = pinned_client(hostname, pinned)?;
        Ok(Self {
            client,
            origin: origin.to_owned(),
            requirement: connection_requirement.clone(),
        })
    }

    /// Sends one request after a durable claim. Any incomplete response is
    /// conservatively unknown, even when the error occurred before a socket
    /// connected; it never authorizes a retry.
    pub(crate) async fn write(
        &self,
        request: &ClosedProviderRequest,
        lease: &StoredSecretLease,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        if request.credential_requirement() != &self.requirement || !self.owns_url(request.url()) {
            return Err(GatewayTransportError::NotEntered);
        }
        let headers = credential_headers(&self.requirement, lease)?;
        let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let outbound = self
            .client
            .request(method, request.url())
            .headers(headers)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, request.content_type())
            .body(request.body().to_vec())
            .build()
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let mut response = match self.client.execute(outbound).await {
            Ok(response) => response,
            Err(_) => return Ok(WriteTransportOutcome::Unknown),
        };
        let status = response.status().as_u16();
        let Some(bytes) = read_bounded(&mut response, MAX_WRITE_RESPONSE_BYTES).await else {
            return Ok(WriteTransportOutcome::Unknown);
        };
        Ok(WriteTransportOutcome::ResponseRecorded {
            status,
            digest: Sha256::digest(bytes).into(),
        })
    }

    /// Performs a separate bounded read-only equality check. Failure leaves
    /// the write stage unchanged and does not license a second write.
    pub(crate) async fn observe(
        &self,
        request: &ClosedObservationRequest,
        lease: &StoredSecretLease,
    ) -> Option<bool> {
        if !self.owns_url(request.url()) {
            return None;
        }
        let headers = credential_headers(&self.requirement, lease).ok()?;
        let outbound = self
            .client
            .get(request.url())
            .headers(headers)
            .header(ACCEPT, "application/json")
            .build()
            .ok()?;
        let mut response = self.client.execute(outbound).await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = read_bounded(&mut response, request.maximum_response_bytes()).await?;
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        decoded
            .pointer(request.json_pointer())
            .map(|value| value == request.expected())
    }

    fn owns_url(&self, candidate: &str) -> bool {
        candidate.starts_with(&self.origin)
            && candidate.as_bytes().get(self.origin.len()) == Some(&b'/')
            && Url::parse(candidate).is_ok_and(|url| {
                url.origin().ascii_serialization() == self.origin
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none()
            })
    }
}

fn pinned_client(hostname: &str, pinned: SocketAddr) -> Result<Client, GatewayTransportError> {
    Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(0)
        .resolve(hostname, pinned)
        .build()
        .map_err(|_| GatewayTransportError::NotEntered)
}

fn credential_headers(
    requirement: &CredentialRequirement,
    lease: &StoredSecretLease,
) -> Result<HeaderMap, GatewayTransportError> {
    let secret = lease
        .expose(Instant::now())
        .map_err(|_| GatewayTransportError::NotEntered)?;
    if secret.is_empty()
        || secret.len() > MAX_SECRET_BYTES
        || !secret.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(GatewayTransportError::NotEntered);
    }
    let (name, value) = match requirement {
        CredentialRequirement::Bearer => {
            let mut value = b"Bearer ".to_vec();
            value.extend_from_slice(secret);
            (AUTHORIZATION, value)
        }
        CredentialRequirement::HeaderApiKey { header } => {
            let name = HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| GatewayTransportError::NotEntered)?;
            (name, secret.to_vec())
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        name,
        HeaderValue::from_bytes(&value).map_err(|_| GatewayTransportError::NotEntered)?,
    );
    Ok(headers)
}

async fn read_bounded(response: &mut reqwest::Response, maximum: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len().checked_add(chunk.len())? > maximum {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(matches!(a, 0 | 10 | 127 | 224..=255)
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254)
        && !(a == 172 && (16..=31).contains(&b))
        && !(a == 192 && matches!(b, 0 | 168))
        && !(a == 198 && matches!(b, 18 | 19 | 51) && (b != 51 || c == 100))
        && !(a == 203 && b == 0 && c == 113)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn async_client_drops_on_runtime_worker_without_nested_runtime_panic() {
        let pinned = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        let client = pinned_client("api.example.com", pinned).expect("client");
        drop(client);
    }

    #[test]
    fn private_and_documentation_destinations_are_rejected() {
        let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/transport-scenarios.json"
        ))
        .expect("transport scenarios");
        assert_eq!(cases["schema"], "auths.gateway-transport-scenarios/1");
        assert_eq!(cases["cases"].as_array().expect("cases").len(), 11);
        for address in [
            [0, 0, 0, 0],
            [10, 1, 2, 3],
            [100, 64, 0, 1],
            [127, 0, 0, 1],
            [169, 254, 169, 254],
            [172, 16, 0, 1],
            [192, 168, 1, 1],
            [198, 18, 0, 1],
            [203, 0, 113, 1],
            [224, 0, 0, 1],
        ] {
            assert!(!public_ipv4(Ipv4Addr::from(address)));
        }
        assert!(public_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
