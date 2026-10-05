//! Workload identity: where the gateway gets short-lived credentials.
//!
//! Three sources exist and none falls back to another. Each returns session
//! credentials that expire. A long-lived access key in the process
//! environment is not a source: it is a secret in exactly the place this
//! store exists to remove one from.

use crate::SecretsApiError;
use crate::clock::parse_utc;
use crate::http::{Region, bounded, pinned_client, unix_now};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroizing;

/// The largest identity token or credential response read.
const MAXIMUM_IDENTITY_BYTES: usize = 16 * 1024;
/// How long requested session credentials last.
const SESSION_SECONDS: u64 = 900;
/// The link-local address of the instance metadata service.
const METADATA_ORIGIN: &str = "http://169.254.169.254";

/// Short-lived credentials for one workload.
pub struct SessionCredentials {
    /// The access key identifier.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: Zeroizing<String>,
    /// The session token.
    pub session_token: Zeroizing<String>,
    /// When the credentials stop working.
    pub expires_at_unix_seconds: u64,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCredentials([REDACTED])")
    }
}

/// One source of session credentials.
#[async_trait]
pub trait WorkloadIdentity: Send + Sync {
    /// Obtains fresh session credentials before `deadline`.
    async fn session(&self, deadline: Instant) -> Result<SessionCredentials, SecretsApiError>;
}

fn text(value: &mut Value, member: &str) -> Option<String> {
    match value.get_mut(member)?.take() {
        Value::String(text) if !text.is_empty() => Some(text),
        _ => None,
    }
}

/// Reads the credentials object the token service returns. The expiry is
/// the lifetime that was requested, counted from `now`.
fn session_from_token_service(body: &[u8], now: u64) -> Option<SessionCredentials> {
    let mut document: Value = serde_json::from_slice(body).ok()?;
    let credentials = document
        .get_mut("AssumeRoleWithWebIdentityResponse")?
        .get_mut("AssumeRoleWithWebIdentityResult")?
        .get_mut("Credentials")?;
    Some(SessionCredentials {
        access_key_id: text(credentials, "AccessKeyId")?,
        secret_access_key: Zeroizing::new(text(credentials, "SecretAccessKey")?),
        session_token: Zeroizing::new(text(credentials, "SessionToken")?),
        expires_at_unix_seconds: now.checked_add(SESSION_SECONDS)?,
    })
}

/// Reads the credentials object a container endpoint or the metadata
/// service returns. Credentials without a readable expiry are refused.
fn session_from_endpoint(body: &[u8]) -> Option<SessionCredentials> {
    let mut document: Value = serde_json::from_slice(body).ok()?;
    let expires = parse_utc(document.get("Expiration")?.as_str()?)?;
    Some(SessionCredentials {
        access_key_id: text(&mut document, "AccessKeyId")?,
        secret_access_key: Zeroizing::new(text(&mut document, "SecretAccessKey")?),
        session_token: Zeroizing::new(text(&mut document, "Token")?),
        expires_at_unix_seconds: expires,
    })
}

fn read_token(path: &PathBuf) -> Result<Zeroizing<String>, SecretsApiError> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| SecretsApiError::Unavailable)?);
    if bytes.is_empty() || bytes.len() > MAXIMUM_IDENTITY_BYTES {
        return Err(SecretsApiError::Unavailable);
    }
    let token = std::str::from_utf8(&bytes).map_err(|_| SecretsApiError::Unavailable)?;
    Ok(Zeroizing::new(token.trim().to_owned()))
}

/// A projected web identity token exchanged with the regional token
/// service for a role's session credentials.
pub struct WebIdentity {
    client: Client,
    endpoint: String,
    role_arn: String,
    token_file: PathBuf,
}

impl WebIdentity {
    /// Uses the token at `token_file` to assume `role_arn` in `region`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsApiError::Unavailable`] when the client cannot be
    /// built or the role name contains anything but the characters of a
    /// role resource name.
    pub fn new(
        region: &Region,
        role_arn: impl Into<String>,
        token_file: impl Into<PathBuf>,
    ) -> Result<Self, SecretsApiError> {
        let role_arn = role_arn.into();
        let valid = role_arn.starts_with("arn:")
            && role_arn.len() <= 2_048
            && role_arn
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":/+=,.@_-".contains(&byte));
        if !valid {
            return Err(SecretsApiError::Unavailable);
        }
        Ok(Self {
            client: pinned_client(true)?,
            endpoint: format!("https://sts.{}.amazonaws.com/", region.as_str()),
            role_arn,
            token_file: token_file.into(),
        })
    }
}

#[async_trait]
impl WorkloadIdentity for WebIdentity {
    async fn session(&self, deadline: Instant) -> Result<SessionCredentials, SecretsApiError> {
        let token = read_token(&self.token_file)?;
        let duration = SESSION_SECONDS.to_string();
        let form = [
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", self.role_arn.as_str()),
            ("RoleSessionName", "auths-gateway"),
            ("DurationSeconds", duration.as_str()),
            ("WebIdentityToken", token.as_str()),
        ];
        let request = self
            .client
            .post(&self.endpoint)
            .header("accept", "application/json")
            .form(&form);
        let (status, body) = bounded(request, deadline, MAXIMUM_IDENTITY_BYTES).await?;
        if status != 200 {
            return Err(SecretsApiError::Unavailable);
        }
        session_from_token_service(&body, unix_now()?).ok_or(SecretsApiError::Unavailable)
    }
}

/// Whether `uri` is one of the fixed link-local container credential
/// endpoints. No other host is ever sent the authorization token.
fn is_container_endpoint(uri: &str) -> bool {
    ["http://169.254.170.2/", "http://169.254.170.23/"]
        .iter()
        .any(|origin| uri.starts_with(origin))
        && uri.len() <= 2_048
        && uri.bytes().all(|byte| byte.is_ascii_graphic())
}

/// The container credentials endpoint of the platform the gateway runs on.
pub struct ContainerEndpoint {
    client: Client,
    uri: String,
    token_file: PathBuf,
}

impl ContainerEndpoint {
    /// Reads credentials from `uri`, authorized by the token at
    /// `token_file`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsApiError::Unavailable`] for an endpoint other than
    /// the platform's fixed link-local addresses.
    pub fn new(
        uri: impl Into<String>,
        token_file: impl Into<PathBuf>,
    ) -> Result<Self, SecretsApiError> {
        let uri = uri.into();
        if !is_container_endpoint(&uri) {
            return Err(SecretsApiError::Unavailable);
        }
        Ok(Self {
            client: pinned_client(false)?,
            uri,
            token_file: token_file.into(),
        })
    }
}

#[async_trait]
impl WorkloadIdentity for ContainerEndpoint {
    async fn session(&self, deadline: Instant) -> Result<SessionCredentials, SecretsApiError> {
        let token = read_token(&self.token_file)?;
        let request = self
            .client
            .get(&self.uri)
            .header("authorization", token.as_str());
        let (status, body) = bounded(request, deadline, MAXIMUM_IDENTITY_BYTES).await?;
        if status != 200 {
            return Err(SecretsApiError::Unavailable);
        }
        session_from_endpoint(&body).ok_or(SecretsApiError::Unavailable)
    }
}

/// The instance metadata service, session-oriented version only.
pub struct InstanceMetadata {
    client: Client,
}

impl InstanceMetadata {
    /// Uses the instance's role.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsApiError::Unavailable`] when the client cannot be
    /// built.
    pub fn new() -> Result<Self, SecretsApiError> {
        Ok(Self {
            client: pinned_client(false)?,
        })
    }
}

/// Whether `name` can be a role name in a metadata path.
fn is_role_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@_-".contains(&byte))
}

#[async_trait]
impl WorkloadIdentity for InstanceMetadata {
    async fn session(&self, deadline: Instant) -> Result<SessionCredentials, SecretsApiError> {
        let token_request = self
            .client
            .put(format!("{METADATA_ORIGIN}/latest/api/token"))
            .header("x-aws-ec2-metadata-token-ttl-seconds", "60");
        let (status, token) = bounded(token_request, deadline, MAXIMUM_IDENTITY_BYTES).await?;
        let token = Zeroizing::new(String::from_utf8(token.to_vec()).unwrap_or_default());
        if status != 200 || token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(SecretsApiError::Unavailable);
        }
        let roles = format!("{METADATA_ORIGIN}/latest/meta-data/iam/security-credentials/");
        let role_request = self
            .client
            .get(&roles)
            .header("x-aws-ec2-metadata-token", token.as_str());
        let (status, role) = bounded(role_request, deadline, MAXIMUM_IDENTITY_BYTES).await?;
        let role = String::from_utf8(role.to_vec()).unwrap_or_default();
        let role = role.lines().next().unwrap_or_default().trim();
        if status != 200 || !is_role_name(role) {
            return Err(SecretsApiError::Unavailable);
        }
        let request = self
            .client
            .get(format!("{roles}{role}"))
            .header("x-aws-ec2-metadata-token", token.as_str());
        let (status, body) = bounded(request, deadline, MAXIMUM_IDENTITY_BYTES).await?;
        if status != 200 {
            return Err(SecretsApiError::Unavailable);
        }
        session_from_endpoint(&body).ok_or(SecretsApiError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_service_credentials_are_read_and_expire_as_requested() {
        let body = br#"{"AssumeRoleWithWebIdentityResponse":{"AssumeRoleWithWebIdentityResult":
            {"Credentials":{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"example-secret",
            "SessionToken":"example-token","Expiration":1.79E9}}}}"#;
        let session = session_from_token_service(body, 1_000).expect("session");
        assert_eq!(session.access_key_id, "ASIAEXAMPLE");
        assert_eq!(session.secret_access_key.as_str(), "example-secret");
        assert_eq!(session.session_token.as_str(), "example-token");
        assert_eq!(session.expires_at_unix_seconds, 1_900);
        assert_eq!(format!("{session:?}"), "SessionCredentials([REDACTED])");
        for incomplete in [
            &b"{}"[..],
            br#"{"AssumeRoleWithWebIdentityResponse":{}}"#,
            br#"{"AssumeRoleWithWebIdentityResponse":{"AssumeRoleWithWebIdentityResult":
                {"Credentials":{"AccessKeyId":"A","SecretAccessKey":"","SessionToken":"t"}}}}"#,
            b"<ErrorResponse/>",
        ] {
            assert!(session_from_token_service(incomplete, 1_000).is_none());
        }
    }

    #[test]
    fn endpoint_credentials_need_every_member_and_an_expiry() {
        let body = br#"{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"example-secret",
            "Token":"example-token","Expiration":"2026-09-21T14:13:20Z"}"#;
        let session = session_from_endpoint(body).expect("session");
        assert_eq!(session.expires_at_unix_seconds, 1_790_000_000);
        assert_eq!(session.session_token.as_str(), "example-token");
        for incomplete in [
            &br#"{"AccessKeyId":"A","SecretAccessKey":"s","Token":"t"}"#[..],
            br#"{"AccessKeyId":"A","SecretAccessKey":"s","Token":"t","Expiration":"soon"}"#,
            br#"{"AccessKeyId":"A","SecretAccessKey":"s","Expiration":"2026-09-21T14:13:20Z"}"#,
        ] {
            assert!(session_from_endpoint(incomplete).is_none());
        }
    }

    #[test]
    fn only_the_fixed_container_endpoints_are_accepted() {
        for accepted in [
            "http://169.254.170.2/v2/credentials/abc",
            "http://169.254.170.23/v1/credentials",
        ] {
            assert!(is_container_endpoint(accepted), "{accepted}");
        }
        for refused in [
            "http://169.254.170.2.example.com/",
            "https://example.com/credentials",
            "http://169.254.169.254/latest/",
            "http://localhost/",
            "http://169.254.170.2",
            "http://169.254.170.2/ a",
        ] {
            assert!(!is_container_endpoint(refused), "{refused}");
            assert!(
                ContainerEndpoint::new(refused, "/token").is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn role_names_cannot_extend_a_metadata_path() {
        assert!(is_role_name("auths-gateway-custody-runtime"));
        for refused in ["", "a/b", "../x", "a b", "a?b", &"a".repeat(65)] {
            assert!(!is_role_name(refused), "{refused}");
        }
    }
}
