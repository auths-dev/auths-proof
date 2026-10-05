//! Credential-bearing HTTPS transport. Only the gateway process may call this.

// These matches separate definite pre-entry failure from ambiguous network entry.
#![allow(clippy::manual_let_else)]

use crate::{
    ClosedCredentialRead, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
    RequestHeader,
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
/// The longest credential the transport injects into a header. A credential
/// store accepts longer secrets; one above this bound is never sent.
pub(crate) const MAX_SECRET_BYTES: usize = 4_096;

/// The longest one provider request may run once it has entered transport.
///
/// A superseded credential generation is kept for longer than this, so an
/// attempt that entered under it always finishes with the credential it
/// leased. Changing this value changes what a qualification was run against.
pub const MAX_TRANSPORT_DURATION: Duration = Duration::from_secs(15);

/// Secret-free transport failure. `Unknown` is possible after network entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub(crate) enum GatewayTransportError {
    /// DNS, binding, or request construction failed before network entry.
    #[error("transport was not entered")]
    NotEntered,
}

/// Write transport evidence, never provider-effect confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WriteTransportOutcome {
    /// The request may have entered, but a complete response was not recorded.
    Unknown,
    /// A complete bounded HTTP response was received. The body is kept only
    /// long enough to read a response locator; only its digest is stored.
    ResponseRecorded {
        status: u16,
        digest: [u8; 32],
        body: Vec<u8>,
        version_ok: bool,
    },
}

/// One complete bounded provider response to a read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderResponse {
    /// The HTTP status.
    pub(crate) status: u16,
    /// Whether every version header the recipe requires the provider to
    /// echo came back with its declared value.
    pub(crate) version_ok: bool,
    /// The response body.
    pub(crate) body: Vec<u8>,
}

impl ProviderResponse {
    /// Whether the status is 2xx.
    pub(crate) const fn success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The body of a 2xx response with no version mismatch; any other
    /// response is unavailable and is not compared, signed, or recorded.
    pub(crate) fn usable_body(&self) -> Option<&[u8]> {
        (self.success() && self.version_ok).then_some(self.body.as_slice())
    }
}

/// Provider entry used by the execution path. The production implementation
/// is the pinned HTTPS transport holding one credential lease; tests supply a
/// counting provider. No method may retry a write.
pub(crate) trait ProviderPort {
    /// Sends one closed write after a durable claim.
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError>;

    /// Performs one bounded GET of an action read or observation and returns
    /// the complete response, or `None` after a transport failure or an
    /// oversized body.
    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse>;

    /// Performs one credential read with the leased secret.
    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse>;
}

/// A borrowed provider is the provider.
impl<P: ProviderPort> ProviderPort for &P {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        (**self).write(request).await
    }

    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        (**self)
            .action_read(url, headers, maximum_response_bytes)
            .await
    }

    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        (**self).credential_read(read).await
    }
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

    async fn action_read(
        &self,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        let secret = self.lease.expose(Instant::now()).ok()?;
        self.transport
            .read(
                reqwest::Method::GET,
                url,
                headers,
                maximum_response_bytes,
                secret,
            )
            .await
    }

    async fn credential_read(&self, read: &ClosedCredentialRead) -> Option<ProviderResponse> {
        let secret = self.lease.expose(Instant::now()).ok()?;
        self.transport.credential_read(read, secret).await
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
    /// Version headers every response must echo with these values.
    required_versions: Vec<(String, String)>,
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
            required_versions: recipe.required_response_versions(),
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
            .timeout(MAX_TRANSPORT_DURATION)
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| GatewayTransportError::NotEntered)?;
        Ok(Self {
            client,
            origin: origin.to_owned(),
            target_origin: format!("http://{}:{port}", Ipv4Addr::LOCALHOST),
            requirement: connection_requirement.clone(),
            required_versions: recipe.required_response_versions(),
        })
    }

    /// Sends one request after a durable claim. Any incomplete response is
    /// conservatively unknown, even when the error occurred before a socket
    /// connected; it never authorizes a retry. The closed request's headers
    /// (version headers, the account-scope header, and the derived
    /// `Idempotency-Key`, each only when declared) are sent as built. A
    /// version mismatch is reported with the response, which is recorded as
    /// usual because the gateway never interprets a write body.
    pub(crate) async fn write(
        &self,
        request: &ClosedProviderRequest,
        lease: &StoredSecretLease,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        if request.credential_requirement() != &self.requirement || !self.owns_url(request.url()) {
            return Err(GatewayTransportError::NotEntered);
        }
        let secret = lease
            .expose(Instant::now())
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let headers = credential_headers(&self.requirement, secret)?;
        let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let mut outbound = self
            .client
            .request(method, self.target(request.url()))
            .headers(headers)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, request.content_type());
        for header in request.headers() {
            outbound = outbound.header(
                provider_header_name(header)?,
                provider_header_value(header)?,
            );
        }
        let outbound = outbound
            .body(request.body().to_vec())
            .build()
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let mut response = match self.client.execute(outbound).await {
            Ok(response) => response,
            Err(_) => return Ok(WriteTransportOutcome::Unknown),
        };
        let status = response.status().as_u16();
        let version_ok = self.versions_echoed(response.headers());
        let Some(bytes) = read_bounded(&mut response, MAX_WRITE_RESPONSE_BYTES).await else {
            return Ok(WriteTransportOutcome::Unknown);
        };
        Ok(WriteTransportOutcome::ResponseRecorded {
            status,
            digest: Sha256::digest(&bytes).into(),
            body: bytes,
            version_ok,
        })
    }

    /// Performs one credential read with `secret`: the leased secret at a
    /// lease, or the candidate secret at onboarding. It carries only the
    /// version headers.
    pub(crate) async fn credential_read(
        &self,
        read: &ClosedCredentialRead,
        secret: &[u8],
    ) -> Option<ProviderResponse> {
        let method = match read.method() {
            crate::CredentialReadMethod::Get => reqwest::Method::GET,
            crate::CredentialReadMethod::Head => reqwest::Method::HEAD,
        };
        self.read(
            method,
            read.url(),
            read.headers(),
            read.maximum_response_bytes(),
            secret,
        )
        .await
    }

    /// One bounded read with `secret`: the complete response of any status,
    /// or `None` after a transport failure or an oversized body. Redirects
    /// are never followed, so a 3xx comes back as its own status.
    pub(crate) async fn read(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
        secret: &[u8],
    ) -> Option<ProviderResponse> {
        if !self.owns_url(url) {
            return None;
        }
        let credential = credential_headers(&self.requirement, secret).ok()?;
        let mut outbound = self
            .client
            .request(method, self.target(url))
            .headers(credential)
            .header(ACCEPT, "application/json");
        for header in headers {
            outbound = outbound.header(
                provider_header_name(header).ok()?,
                provider_header_value(header).ok()?,
            );
        }
        let outbound = outbound.build().ok()?;
        let mut response = self.client.execute(outbound).await.ok()?;
        let status = response.status().as_u16();
        let version_ok = self.versions_echoed(response.headers());
        let body = read_bounded(&mut response, maximum_response_bytes).await?;
        Some(ProviderResponse {
            status,
            version_ok,
            body,
        })
    }

    /// Whether every required version header came back with its value.
    fn versions_echoed(&self, headers: &HeaderMap) -> bool {
        self.required_versions.iter().all(|(name, value)| {
            let mut values = headers.get_all(name.as_str()).iter();
            values
                .next()
                .is_some_and(|found| found.as_bytes() == value.as_bytes())
                && values.next().is_none()
        })
    }

    /// A transport that sends requests for the recipe's origin to a
    /// plain-HTTP double on `127.0.0.1:port`, for tests.
    #[cfg(test)]
    pub(crate) fn for_loopback_test(recipe: &CompiledRecipe, port: u16) -> Self {
        let review = recipe.review();
        Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .build()
                .expect("loopback test client"),
            origin: review.origin().to_owned(),
            target_origin: format!("http://{}:{port}", Ipv4Addr::LOCALHOST),
            requirement: review.credential().clone(),
            required_versions: recipe.required_response_versions(),
        }
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

/// A constructed provider header name. The compiler admits only registered
/// names and `Idempotency-Key`, so a parse failure is refused before entry.
fn provider_header_name(header: &RequestHeader) -> Result<HeaderName, GatewayTransportError> {
    HeaderName::from_bytes(header.name().as_bytes()).map_err(|_| GatewayTransportError::NotEntered)
}

fn provider_header_value(header: &RequestHeader) -> Result<HeaderValue, GatewayTransportError> {
    HeaderValue::from_str(header.value()).map_err(|_| GatewayTransportError::NotEntered)
}

fn pinned_client(hostname: &str, pinned: SocketAddr) -> Result<Client, GatewayTransportError> {
    Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(MAX_TRANSPORT_DURATION)
        .pool_max_idle_per_host(0)
        .resolve(hostname, pinned)
        .build()
        .map_err(|_| GatewayTransportError::NotEntered)
}

fn credential_headers(
    requirement: &CredentialRequirement,
    secret: &[u8],
) -> Result<HeaderMap, GatewayTransportError> {
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
    use crate::{LogicalOperationId, idempotency_key};
    use auths_connections::{
        ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
        ConnectionRecord, ConnectionState, InMemoryCredentialStore, ProviderKind, SecretBytes,
        SemanticId,
    };
    use serde_json::{Value, json};
    use std::num::NonZeroU64;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// A lease on a one-generation in-memory credential.
    async fn test_lease() -> StoredSecretLease {
        let store = InMemoryCredentialStore::new(1, 64).expect("store");
        let connection = ConnectionId::generate().expect("connection ID");
        let secret = SecretBytes::new(b"test-only-not-a-credential".to_vec()).expect("secret");
        let commitment = store
            .install(&connection, NonZeroU64::MIN, secret)
            .await
            .expect("install");
        let profile = ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2)
            .expect("profile");
        let record = ConnectionRecord::new(
            ProviderKind::parse("airtable").expect("provider"),
            ConnectionAlias::parse("test").expect("alias"),
            connection,
            SemanticId::parse("auths.gateway-operation/1").expect("contract"),
            SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
            b"{}".to_vec(),
            [0; 32],
            *commitment.as_bytes(),
            NonZeroU64::MIN,
            ConnectionState::Active,
            vec!["gateway".to_owned()],
            vec![profile],
            1,
            1,
            None,
        )
        .expect("record");
        let binding = record
            .binding_for_recovery(NonZeroU64::MIN, NonZeroU64::MIN, commitment)
            .expect("binding");
        store
            .lease_secret(
                &binding.credential(),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .expect("lease")
    }

    /// Answers `count` loopback HTTP/1.1 requests with one small JSON record
    /// and returns each lowercased request head in arrival order.
    async fn capture_heads(listener: &TcpListener, count: usize) -> Vec<String> {
        const RECORD: &[u8] = br#"{"id":"recTEST0000000001","fields":{"DemoStatus":"Approved"}}"#;
        let mut heads = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4_096];
            let end = loop {
                let read = stream.read(&mut buffer).await.expect("read head");
                assert!(read > 0, "request head ended early");
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end;
                }
            };
            let head = String::from_utf8(bytes[..end].to_vec())
                .expect("ASCII head")
                .to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
            while bytes.len() < end + 4 + length {
                let read = stream.read(&mut buffer).await.expect("read body");
                assert!(read > 0, "request body ended early");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let status = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                RECORD.len()
            );
            stream.write_all(status.as_bytes()).await.expect("respond");
            stream.write_all(RECORD).await.expect("respond");
            heads.push(head);
        }
        heads
    }

    fn idempotency_values(head: &str) -> Vec<&str> {
        head.lines()
            .filter_map(|line| line.strip_prefix("idempotency-key:"))
            .map(str::trim)
            .collect()
    }

    #[tokio::test]
    async fn write_sends_the_derived_idempotency_key_only_when_declared_and_read_back_never_does() {
        let lease = test_lease().await;
        let lock =
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
        for declared in [true, false] {
            let mut source: Value = serde_json::from_slice(include_bytes!(
                "../../../../bindings/fixtures/gateway/airtable/recipe.json"
            ))
            .expect("source");
            if declared {
                source["write"]["idempotency"] =
                    json!({"kind": "derived-header", "retention_seconds": 86_400});
            }
            let recipe =
                CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock)
                    .expect("recipe");
            let arguments = json!({"operation_id": "run-1", "record_id": "recTEST0000000001",
                "replacement": "Approved", "operator_namespace": recipe.namespace().as_str(),
                "recipe_digest": recipe.digest_hex()});
            let request = recipe
                .closed_request_from_arguments(arguments.as_object().expect("arguments"), [1; 32])
                .expect("request");
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            let port = listener.local_addr().expect("address").port();
            let provider = tokio::spawn(async move { capture_heads(&listener, 2).await });
            let transport = GatewayHttpTransport {
                client: Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .pool_max_idle_per_host(0)
                    .build()
                    .expect("client"),
                origin: recipe.review().origin().to_owned(),
                target_origin: format!("http://{}:{port}", Ipv4Addr::LOCALHOST),
                requirement: recipe.review().credential().clone(),
                required_versions: Vec::new(),
            };
            assert!(matches!(
                transport.write(&request, &lease).await,
                Ok(WriteTransportOutcome::ResponseRecorded { status: 200, .. })
            ));
            let observation = request.observation().expect("observation");
            let secret = lease.expose(Instant::now()).expect("lease");
            assert!(
                transport
                    .read(
                        reqwest::Method::GET,
                        observation.url(),
                        observation.headers(),
                        observation.maximum_response_bytes(),
                        secret,
                    )
                    .await
                    .and_then(|response| response.usable_body().map(<[u8]>::to_vec))
                    .is_some()
            );
            let heads = provider.await.expect("provider");
            assert!(heads[0].starts_with("patch /v0/"), "{}", heads[0]);
            assert!(heads[1].starts_with("get /v0/"), "{}", heads[1]);
            let expected = idempotency_key(
                recipe.namespace(),
                &LogicalOperationId::parse("run-1").expect("operation"),
            );
            let sent = if declared {
                vec![expected.as_str()]
            } else {
                Vec::new()
            };
            assert_eq!(idempotency_values(&heads[0]), sent, "declared={declared}");
            assert!(
                idempotency_values(&heads[1]).is_empty(),
                "the read-back never sends the key"
            );
        }
    }

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
            let secret = lease.expose(Instant::now()).expect("lease");
            let headers = credential_headers(&requirement, secret).expect("credential headers");
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
            .binding_for_recovery(generation, generation, commitment)
            .expect("binding");
        store
            .lease_secret(
                &binding.credential(),
                Instant::now() + Duration::from_secs(30),
            )
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
