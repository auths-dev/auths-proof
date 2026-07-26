//! Native, policy-constrained HTTPS acquisition of bundled `did:web`
//! evidence.
//!
//! This effectful crate fetches and packages immutable bytes. It does not
//! establish principal control, construct authority, or select trust anchors.

#![forbid(unsafe_code)]

use auths_codec::evidence_id;
use auths_did_web::DidWebEvidence;
use auths_model::{EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, PrincipalId, Timestamp};
use reqwest::{
    blocking::Client,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    redirect,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fmt,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    time::Duration,
};

pub use auths_did_web::{DID_WEB_MEDIA_TYPE, DID_WEB_V1 as DID_WEB_EVIDENCE_V1};
const DEFAULT_MAX_BYTES: usize = 32 * 1024;
const MAX_CONFIGURED_BYTES: usize = 32 * 1024;

/// Parsed, lower-case `did:web` identifier and exact resolution target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidWebId {
    principal: PrincipalId,
    host: String,
    port: Option<u16>,
    path: Vec<String>,
}

impl DidWebId {
    /// Parses the target V1 `did:web` subset.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::InvalidDid`] for unsupported authority or path
    /// syntax.
    pub fn parse(value: &str) -> Result<Self, ResolveError> {
        let specific = value
            .strip_prefix("did:web:")
            .ok_or(ResolveError::InvalidDid)?;
        let mut parts = specific.split(':');
        let authority = parts.next().ok_or(ResolveError::InvalidDid)?;
        let path = parts
            .map(|part| {
                if part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                    })
                {
                    Err(ResolveError::InvalidDid)
                } else {
                    Ok(part.to_owned())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (host, port) = parse_authority(authority)?;
        Ok(Self {
            principal: PrincipalId::parse(value).map_err(|_| ResolveError::InvalidDid)?,
            host,
            port,
            path,
        })
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    #[must_use]
    pub fn resolution_url(&self) -> String {
        let authority = self
            .port
            .map_or_else(|| self.host.clone(), |port| format!("{}:{port}", self.host));
        if self.path.is_empty() {
            format!("https://{authority}/.well-known/did.json")
        } else {
            format!("https://{authority}/{}/did.json", self.path.join("/"))
        }
    }
}

/// Explicit SSRF, timeout, and response-size policy.
#[derive(Clone, Debug)]
pub struct ResolverPolicy {
    allowed_hosts: BTreeSet<String>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl ResolverPolicy {
    /// Constructs an exact, non-empty lower-case host allow-list.
    ///
    /// # Errors
    ///
    /// Returns a policy error for malformed or empty host sets.
    pub fn new(allowed_hosts: impl IntoIterator<Item = String>) -> Result<Self, ResolveError> {
        let allowed_hosts: BTreeSet<String> = allowed_hosts.into_iter().collect();
        if allowed_hosts.is_empty()
            || allowed_hosts.iter().any(|host| {
                host.is_empty()
                    || host != &host.to_ascii_lowercase()
                    || parse_authority(host).is_err()
            })
        {
            return Err(ResolveError::InvalidPolicy);
        }
        Ok(Self {
            allowed_hosts,
            timeout: Duration::from_secs(10),
            max_response_bytes: DEFAULT_MAX_BYTES,
        })
    }

    /// Sets a bounded request timeout.
    ///
    /// # Errors
    ///
    /// Returns a policy error outside `(0, 60s]`.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, ResolveError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ResolveError::InvalidPolicy);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Sets the maximum accepted document size.
    ///
    /// # Errors
    ///
    /// Returns a policy error outside the target bound.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self, ResolveError> {
        if bytes == 0 || bytes > MAX_CONFIGURED_BYTES {
            return Err(ResolveError::InvalidPolicy);
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }

    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        self.allowed_hosts.contains(host)
    }
}

/// Blocking native HTTPS resolver kept outside the pure kernel.
pub struct DidWebHttpResolver {
    policy: ResolverPolicy,
}

impl DidWebHttpResolver {
    #[must_use]
    pub const fn new(policy: ResolverPolicy) -> Self {
        Self { policy }
    }

    /// Fetches, canonicalizes, and content-addresses current DID document
    /// bytes.
    ///
    /// `observed_at` and `valid_until` remain explicit acquisition metadata;
    /// only a registered pure principal method may establish their assurance
    /// meaning.
    ///
    /// # Errors
    ///
    /// Returns a typed policy, DNS, HTTPS, content, canonicalization, or
    /// resource-limit error.
    pub fn resolve_current(
        &self,
        did: &str,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<ResolvedDidWebEvidence, ResolveError> {
        if observed_at > valid_until {
            return Err(ResolveError::InvalidObservationWindow);
        }
        let did = DidWebId::parse(did)?;
        if !self.policy.allows(did.host()) {
            return Err(ResolveError::HostNotAllowed);
        }
        let port = did.port().unwrap_or(443);
        let addresses = resolve_public_addresses(did.host(), port)?;
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(self.policy.timeout)
            .resolve_to_addrs(did.host(), &addresses)
            .build()
            .map_err(|_| ResolveError::Transport)?;
        let response = client
            .get(did.resolution_url())
            .header(
                "Accept",
                "application/did+json, application/did+ld+json, application/json",
            )
            .send()
            .map_err(|_| ResolveError::Transport)?;
        if !response.status().is_success() {
            return Err(ResolveError::HttpStatus);
        }
        validate_content_type(&response)?;
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > self.policy.max_response_bytes)
        {
            return Err(ResolveError::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        response
            .take((self.policy.max_response_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ResolveError::Transport)?;
        if bytes.len() > self.policy.max_response_bytes {
            return Err(ResolveError::ResponseTooLarge);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ResolveError::InvalidDocument)?;
        if value.get("id").and_then(Value::as_str) != Some(did.principal().as_str()) {
            return Err(ResolveError::InvalidDocument);
        }
        let document =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| ResolveError::InvalidDocument)?;
        let bundled = DidWebEvidence::from_canonical(did.principal().clone(), document.clone())
            .map_err(|_| ResolveError::InvalidDocument)?;
        let evidence_bytes = bundled
            .encode()
            .map_err(|_| ResolveError::InvalidDocument)?;
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            EvidenceTypeId::parse(DID_WEB_EVIDENCE_V1)
                .map_err(|_| ResolveError::InvalidDocument)?,
            MediaType::parse(DID_WEB_MEDIA_TYPE).map_err(|_| ResolveError::InvalidDocument)?,
            evidence_bytes,
        )
        .map_err(|_| ResolveError::InvalidDocument)?;
        let evidence = EvidenceObject::new(
            evidence_id(&unaddressed).map_err(|_| ResolveError::InvalidDocument)?,
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .map_err(|_| ResolveError::InvalidDocument)?;
        Ok(ResolvedDidWebEvidence {
            document,
            evidence,
            observed_at,
            valid_until,
        })
    }
}

fn parse_authority(value: &str) -> Result<(String, Option<u16>), ResolveError> {
    let mut pieces = value.split("%3A");
    let host = pieces.next().ok_or(ResolveError::InvalidDid)?;
    let port = pieces
        .next()
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(ResolveError::InvalidDid)
        })
        .transpose()?;
    if pieces.next().is_some()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || !host.contains('.')
        || host.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
        })
        || host.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
        || host
            .split('.')
            .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ResolveError::InvalidDid);
    }
    Ok((host.to_owned(), port))
}

fn validate_content_type(response: &reqwest::blocking::Response) -> Result<(), ResolveError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if matches!(
        content_type,
        Some(
            "application/json"
                | "application/did+json"
                | "application/did+ld+json"
                | "application/ld+json"
        )
    ) {
        Ok(())
    } else {
        Err(ResolveError::UnsupportedMediaType)
    }
}

fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| ResolveError::Dns)?
        .collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public(address.ip())) {
        return Err(ResolveError::NonPublicAddress);
    }
    Ok(addresses)
}

fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = address.segments();
    (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// Immutable acquisition output for later pure verification.
pub struct ResolvedDidWebEvidence {
    pub document: Vec<u8>,
    pub evidence: EvidenceObject,
    pub observed_at: Timestamp,
    pub valid_until: Timestamp,
}

/// Live resolver failure, separate from proof verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    InvalidDid,
    InvalidDocument,
    InvalidPolicy,
    InvalidObservationWindow,
    HostNotAllowed,
    Dns,
    NonPublicAddress,
    Transport,
    HttpStatus,
    UnsupportedMediaType,
    ResponseTooLarge,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDid => "invalid did:web identifier",
            Self::InvalidDocument => "invalid did:web document",
            Self::InvalidPolicy => "invalid resolver policy",
            Self::InvalidObservationWindow => "invalid observation window",
            Self::HostNotAllowed => "did:web host is not allowlisted",
            Self::Dns => "did:web DNS resolution failed",
            Self::NonPublicAddress => "did:web resolved to a non-public address",
            Self::Transport => "did:web HTTPS transport failed",
            Self::HttpStatus => "did:web endpoint returned an unsuccessful status",
            Self::UnsupportedMediaType => "did:web endpoint returned an unsupported media type",
            Self::ResponseTooLarge => "did:web response exceeded the configured limit",
        })
    }
}

impl std::error::Error for ResolveError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_and_documentation_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public(address.parse().expect("address")), "{address}");
        }
        assert!(is_public("8.8.8.8".parse().expect("address")));
        assert!(is_public("2606:4700:4700::1111".parse().expect("address")));
    }

    #[test]
    fn policy_is_an_exact_host_allowlist() {
        let policy = ResolverPolicy::new(["example.com".to_owned()]).expect("policy");
        assert!(policy.allows("example.com"));
        assert!(!policy.allows("evil.example.com"));
    }

    #[test]
    fn did_resolution_paths_are_exact() {
        assert_eq!(
            DidWebId::parse("did:web:example.com")
                .unwrap()
                .resolution_url(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            DidWebId::parse("did:web:example.com:users:alice")
                .unwrap()
                .resolution_url(),
            "https://example.com/users/alice/did.json"
        );
    }
}
