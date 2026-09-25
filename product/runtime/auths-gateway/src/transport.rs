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
use zeroize::Zeroizing;

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

/// Provider entry used by the execution path. The production implementation
/// is the pinned HTTPS transport holding one credential lease; tests supply a
/// counting provider. Neither method may retry a write.
pub(crate) trait ProviderPort {
    /// Sends one closed write after a durable claim.
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError>;

    /// Performs one bounded read-only observation and returns its exact bytes.
    async fn read_back(&self, request: &ClosedObservationRequest) -> Option<Vec<u8>>;
}

/// The pinned transport paired with the exact credential lease for one call.
pub(crate) struct LeasedTransport<'a> {
    pub(crate) transport: &'a GatewayHttpTransport,
    pub(crate) lease: &'a StoredSecretLease,
}

impl ProviderPort for LeasedTransport<'_> {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.transport.write(request, self.lease).await
    }

    async fn read_back(&self, request: &ClosedObservationRequest) -> Option<Vec<u8>> {
        self.transport.read_back(request, self.lease).await
    }
}

/// One DNS-pinned, no-proxy, no-redirect client for an operator-approved origin.
/// An IPv6-only destination is rejected in this first version.
pub(crate) struct GatewayHttpTransport {
    client: Client,
    origin: String,
    /// Where requests for `origin` are sent: `origin` itself except in a
    /// `loopback-provider` development build.
    target_origin: String,
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
            target_origin: origin.to_owned(),
            requirement: connection_requirement.clone(),
        })
    }

    /// Development-only transport that sends requests for the approved
    /// origin to a plain-HTTP provider double on `127.0.0.1:port`. URL
    /// ownership is still checked against the approved origin first.
    #[cfg(feature = "loopback-provider")]
    pub(crate) fn prepare_loopback(
        recipe: &CompiledRecipe,
        connection_requirement: &CredentialRequirement,
        port: u16,
    ) -> Result<Self, GatewayTransportError> {
        let review = recipe.review();
        if review.credential() != connection_requirement || port == 0 {
            return Err(GatewayTransportError::NotEntered);
        }
        let origin = review.origin();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| GatewayTransportError::NotEntered)?;
        Ok(Self {
            client,
            origin: origin.to_owned(),
            target_origin: format!("http://{}:{port}", Ipv4Addr::LOCALHOST),
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
            .request(method, self.target(request.url()))
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

    /// Performs a separate bounded read-only GET and returns the exact 2xx
    /// response bytes. Failure leaves the write stage unchanged and does not
    /// license a second write. The bytes are never logged.
    pub(crate) async fn read_back(
        &self,
        request: &ClosedObservationRequest,
        lease: &StoredSecretLease,
    ) -> Option<Vec<u8>> {
        if !self.owns_url(request.url()) {
            return None;
        }
        let headers = credential_headers(&self.requirement, lease).ok()?;
        let outbound = self
            .client
            .get(self.target(request.url()))
            .headers(headers)
            .header(ACCEPT, "application/json")
            .build()
            .ok()?;
        let mut response = self.client.execute(outbound).await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        read_bounded(&mut response, request.maximum_response_bytes()).await
    }

    /// Maps an owned URL onto the transport's target origin.
    fn target(&self, owned: &str) -> String {
        format!("{}{}", self.target_origin, &owned[self.origin.len()..])
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
    let (name, prefix): (HeaderName, &[u8]) = match requirement {
        CredentialRequirement::Bearer => (AUTHORIZATION, b"Bearer "),
        CredentialRequirement::HeaderApiKey { header } => (
            HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| GatewayTransportError::NotEntered)?,
            b"",
        ),
    };
    // Sized up front so no reallocation strands an unwiped copy. `HeaderValue`
    // keeps its own copy, which the request owns and `http` cannot zeroize.
    let mut value = Zeroizing::new(Vec::with_capacity(prefix.len() + secret.len()));
    value.extend_from_slice(prefix);
    value.extend_from_slice(secret);
    let mut header =
        HeaderValue::from_bytes(&value).map_err(|_| GatewayTransportError::NotEntered)?;
    // `Debug` then prints `Sensitive`, and an HTTP/2 encoder never indexes it.
    header.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(name, header);
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

    #[tokio::test]
    async fn credential_headers_are_marked_sensitive() {
        let lease = leased_secret(b"not-a-real-secret").await;
        for (requirement, name, expected) in [
            (
                CredentialRequirement::Bearer,
                AUTHORIZATION,
                b"Bearer not-a-real-secret".as_slice(),
            ),
            (
                CredentialRequirement::HeaderApiKey {
                    header: "x-api-key".to_owned(),
                },
                HeaderName::from_static("x-api-key"),
                b"not-a-real-secret".as_slice(),
            ),
        ] {
            let headers = credential_headers(&requirement, &lease).expect("credential headers");
            assert_eq!(headers.len(), 1);
            let value = headers.get(&name).expect("credential header");
            assert!(value.is_sensitive());
            assert_eq!(value.as_bytes(), expected);
            assert!(!format!("{headers:?}").contains("not-a-real-secret"));
        }
    }

    /// Leases `secret` through the public credential-store path.
    async fn leased_secret(secret: &[u8]) -> StoredSecretLease {
        use auths_connections::{
            ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
            ConnectionRecord, ConnectionState, InMemoryCredentialStore, ProviderKind, SecretBytes,
            SemanticId,
        };
        use std::num::NonZeroU64;

        let store = InMemoryCredentialStore::new(1, 1_024).expect("store");
        let connection_id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
        let generation = NonZeroU64::MIN;
        let secret = SecretBytes::new(secret.to_vec()).expect("secret");
        let commitment = store
            .install(&connection_id, generation, secret)
            .await
            .expect("install");
        let profile = ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2)
            .expect("profile");
        let record = ConnectionRecord::new(
            ProviderKind::parse("example").expect("provider"),
            ConnectionAlias::parse("default").expect("alias"),
            connection_id,
            SemanticId::parse("auths.gateway-operation/1").expect("contract"),
            SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
            b"descriptor".to_vec(),
            [2; 32],
            *commitment.as_bytes(),
            generation,
            ConnectionState::Active,
            vec!["gateway".to_owned()],
            vec![profile],
            10,
            10,
            None,
        )
        .expect("record");
        let binding = record
            .binding_for_recovery(generation, commitment)
            .expect("binding");
        store
            .lease_secret(&binding, Instant::now() + Duration::from_secs(30))
            .await
            .expect("lease")
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
