//! Native, policy-constrained HTTPS retrieval for `did:web` evidence.
//!
//! This crate performs I/O but never verifies authority. Its output is an
//! immutable evidence entry plus an explicit current-state trust record for a
//! host application to pass to the pure `did:web` adapter.

#![forbid(unsafe_code)]

use auths_proof_did_web::{DidWebError, DidWebEvidence, DidWebId, DidWebTrustRecord};
use auths_proof_model::{PrincipalEvidenceEntry, Timestamp};
use reqwest::{
    blocking::Client,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    redirect,
};
use std::{
    collections::BTreeSet,
    fmt,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    time::Duration,
};

const DEFAULT_MAX_BYTES: usize = 128 * 1024;
const MAX_CONFIGURED_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ResolverPolicy {
    allowed_hosts: BTreeSet<String>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl ResolverPolicy {
    pub fn new(allowed_hosts: impl IntoIterator<Item = String>) -> Result<Self, ResolveError> {
        let allowed_hosts: BTreeSet<String> = allowed_hosts.into_iter().collect();
        if allowed_hosts.is_empty()
            || allowed_hosts
                .iter()
                .any(|host| host.is_empty() || host != &host.to_ascii_lowercase())
        {
            return Err(ResolveError::InvalidPolicy);
        }
        Ok(Self {
            allowed_hosts,
            timeout: Duration::from_secs(10),
            max_response_bytes: DEFAULT_MAX_BYTES,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, ResolveError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ResolveError::InvalidPolicy);
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self, ResolveError> {
        if bytes == 0 || bytes > MAX_CONFIGURED_BYTES {
            return Err(ResolveError::InvalidPolicy);
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }

    pub fn allows(&self, host: &str) -> bool {
        self.allowed_hosts.contains(host)
    }
}

pub struct DidWebHttpResolver {
    policy: ResolverPolicy,
}

impl DidWebHttpResolver {
    pub const fn new(policy: ResolverPolicy) -> Self {
        Self { policy }
    }

    pub fn resolve_current(
        &self,
        did: &str,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<ResolvedDidWebEvidence, ResolveError> {
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
        let evidence = DidWebEvidence::canonicalize(&bytes)?;
        evidence.validate_for(did.principal())?;
        let trust = DidWebTrustRecord::current(
            did.principal().clone(),
            evidence.document_digest(),
            observed_at,
            valid_until,
        )?;
        let evidence_entry = evidence.evidence_entry()?;
        Ok(ResolvedDidWebEvidence {
            evidence,
            evidence_entry,
            trust,
        })
    }
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

pub struct ResolvedDidWebEvidence {
    pub evidence: DidWebEvidence,
    pub evidence_entry: PrincipalEvidenceEntry,
    pub trust: DidWebTrustRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    DidWeb(DidWebError),
    InvalidPolicy,
    HostNotAllowed,
    Dns,
    NonPublicAddress,
    Transport,
    HttpStatus,
    UnsupportedMediaType,
    ResponseTooLarge,
}

impl From<DidWebError> for ResolveError {
    fn from(error: DidWebError) -> Self {
        Self::DidWeb(error)
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DidWeb(_) => "invalid did:web data",
            Self::InvalidPolicy => "invalid resolver policy",
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
    fn policy_is_exact_host_allowlist() {
        let policy = ResolverPolicy::new(["example.com".to_string()]).expect("policy");
        assert!(policy.allows("example.com"));
        assert!(!policy.allows("evil.example.com"));
    }
}
