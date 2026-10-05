//! The network implementation of the three service calls.

use crate::clock::amz_date;
use crate::identity::{SessionCredentials, WorkloadIdentity};
use crate::sigv4::{SigningInput, sign};
use crate::{FetchedSecret, SecretsApi, SecretsApiError};
use async_trait::async_trait;
use base64ct::{Base64, Encoding as _};
use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

/// The largest service response read.
const MAXIMUM_RESPONSE_BYTES: usize = 128 * 1024;
/// How long before expiry session credentials are replaced.
const REFRESH_MARGIN_SECONDS: u64 = 60;
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// A region or key identifier outside its grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("invalid deployment setting")]
pub struct InvalidDeployment;

/// A region: lowercase letters, digits, and hyphens, such as `eu-west-1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region(String);

impl Region {
    /// Parses a region.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDeployment`] for anything that could not be one
    /// label of a host name.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidDeployment> {
        let value = value.into();
        let valid = (1..=32).contains(&value.len())
            && value.starts_with(|first: char| first.is_ascii_lowercase())
            && !value.ends_with('-')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidDeployment)
        }
    }

    /// Returns the region.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn unix_now() -> Result<u64, SecretsApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| SecretsApiError::Unavailable)
}

/// A client that follows no redirect, uses no proxy, keeps no idle
/// connection, and, for the service endpoints, speaks only HTTPS.
pub(crate) fn pinned_client(https_only: bool) -> Result<Client, SecretsApiError> {
    Client::builder()
        .https_only(https_only)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|_| SecretsApiError::Unavailable)
}

/// Sends one request once, bounded by `deadline` and by `maximum` response
/// bytes. There is no retry.
pub(crate) async fn bounded(
    request: RequestBuilder,
    deadline: Instant,
    maximum: usize,
) -> Result<(u16, Zeroizing<Vec<u8>>), SecretsApiError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(SecretsApiError::Unavailable)?;
    let mut response = request
        .timeout(remaining)
        .send()
        .await
        .map_err(|_| SecretsApiError::Unavailable)?;
    let status = response.status().as_u16();
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SecretsApiError::Unavailable)?
    {
        if body.len() + chunk.len() > maximum {
            return Err(SecretsApiError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// Whether `value` needs no escaping inside a JSON string.
fn is_plain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2_048
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":/_-".contains(&byte))
}

/// The body of a create call. Every interpolated value is plain, so the
/// body is built without a JSON value that would keep an unzeroized copy of
/// the secret.
fn create_body(
    name: &str,
    version: &str,
    secret: &[u8],
    key: Option<&str>,
) -> Option<Zeroizing<Vec<u8>>> {
    if !is_plain(name) || !is_plain(version) || key.is_some_and(|key| !is_plain(key)) {
        return None;
    }
    let encoded = Zeroizing::new(Base64::encode_string(secret));
    let mut body = Zeroizing::new(Vec::new());
    body.extend_from_slice(b"{\"ClientRequestToken\":\"");
    body.extend_from_slice(version.as_bytes());
    if let Some(key) = key {
        body.extend_from_slice(b"\",\"KmsKeyId\":\"");
        body.extend_from_slice(key.as_bytes());
    }
    body.extend_from_slice(b"\",\"Name\":\"");
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(b"\",\"SecretBinary\":\"");
    body.extend_from_slice(encoded.as_bytes());
    body.extend_from_slice(b"\"}");
    Some(body)
}

fn get_body(name: &str, version: &str) -> Option<Vec<u8>> {
    (is_plain(name) && is_plain(version))
        .then(|| format!("{{\"SecretId\":\"{name}\",\"VersionId\":\"{version}\"}}").into_bytes())
}

fn delete_body(name: &str) -> Option<Vec<u8>> {
    is_plain(name).then(|| {
        format!("{{\"ForceDeleteWithoutRecovery\":true,\"SecretId\":\"{name}\"}}").into_bytes()
    })
}

/// Reads one secret version from a successful read response.
fn fetched(body: &[u8]) -> Option<FetchedSecret> {
    let mut document: Value = serde_json::from_slice(body).ok()?;
    let version = document.get("VersionId")?.as_str()?.to_owned();
    let Value::String(encoded) = document.get_mut("SecretBinary")?.take() else {
        return None;
    };
    let encoded = Zeroizing::new(encoded);
    let bytes = Zeroizing::new(Base64::decode_vec(&encoded).ok()?);
    Some(FetchedSecret { version, bytes })
}

/// Classifies a response that is not a success. Only the error type the
/// service names is read; its message is never kept.
fn refusal(body: &[u8]) -> SecretsApiError {
    let kind = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|document| document.get("__type")?.as_str().map(str::to_owned))
        .unwrap_or_default();
    if kind.ends_with("ResourceExistsException") {
        SecretsApiError::Exists
    } else if kind.ends_with("ResourceNotFoundException") {
        SecretsApiError::NotFound
    } else {
        SecretsApiError::Unavailable
    }
}

/// The service over HTTPS in one region, signed with a workload identity's
/// session credentials.
pub struct HttpSecretsApi<I> {
    client: Client,
    region: Region,
    host: String,
    key: Option<String>,
    identity: I,
    session: Mutex<Option<std::sync::Arc<SessionCredentials>>>,
}

impl<I: WorkloadIdentity> HttpSecretsApi<I> {
    /// Calls the service in `region` as `identity`, encrypting new secrets
    /// under `key` when one is given.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDeployment`] for a key identifier with characters
    /// outside a key resource name, or when the client cannot be built.
    pub fn new(
        region: Region,
        key: Option<String>,
        identity: I,
    ) -> Result<Self, InvalidDeployment> {
        if key.as_deref().is_some_and(|key| !is_plain(key)) {
            return Err(InvalidDeployment);
        }
        Ok(Self {
            client: pinned_client(true).map_err(|_| InvalidDeployment)?,
            host: format!("secretsmanager.{}.amazonaws.com", region.as_str()),
            region,
            key,
            identity,
            session: Mutex::new(None),
        })
    }

    /// Session credentials that are still valid for a margin, from the
    /// cache or from the identity source.
    async fn credentials(
        &self,
        deadline: Instant,
    ) -> Result<std::sync::Arc<SessionCredentials>, SecretsApiError> {
        let now = unix_now()?;
        let cached = self
            .session
            .lock()
            .map_err(|_| SecretsApiError::Unavailable)?
            .clone();
        if let Some(session) = cached
            && session.expires_at_unix_seconds > now.saturating_add(REFRESH_MARGIN_SECONDS)
        {
            return Ok(session);
        }
        let fresh = std::sync::Arc::new(self.identity.session(deadline).await?);
        *self
            .session
            .lock()
            .map_err(|_| SecretsApiError::Unavailable)? = Some(std::sync::Arc::clone(&fresh));
        Ok(fresh)
    }

    async fn call(
        &self,
        operation: &str,
        body: &[u8],
        deadline: Instant,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), SecretsApiError> {
        let session = self.credentials(deadline).await?;
        let date = amz_date(unix_now()?);
        let target = format!("secretsmanager.{operation}");
        let headers = [
            ("content-type", CONTENT_TYPE),
            ("host", self.host.as_str()),
            ("x-amz-date", date.as_str()),
            ("x-amz-security-token", session.session_token.as_str()),
            ("x-amz-target", target.as_str()),
        ];
        let signed = sign(&SigningInput {
            method: "POST",
            canonical_uri: "/",
            canonical_query: "",
            headers: &headers,
            payload: body,
            region: self.region.as_str(),
            service: "secretsmanager",
            access_key_id: &session.access_key_id,
            secret_access_key: session.secret_access_key.as_bytes(),
            amz_date: &date,
        });
        let request = self
            .client
            .post(format!("https://{}/", self.host))
            .header("content-type", CONTENT_TYPE)
            .header("x-amz-date", date.as_str())
            .header("x-amz-security-token", session.session_token.as_str())
            .header("x-amz-target", target.as_str())
            .header("authorization", signed.authorization)
            .body(body.to_vec());
        bounded(request, deadline, MAXIMUM_RESPONSE_BYTES).await
    }
}

#[async_trait]
impl<I: WorkloadIdentity> SecretsApi for HttpSecretsApi<I> {
    async fn create(
        &self,
        name: &str,
        version: &str,
        secret: &[u8],
        deadline: Instant,
    ) -> Result<(), SecretsApiError> {
        let body = create_body(name, version, secret, self.key.as_deref())
            .ok_or(SecretsApiError::Unavailable)?;
        let (status, response) = self.call("CreateSecret", &body, deadline).await?;
        if status != 200 {
            return Err(refusal(&response));
        }
        // The version must be the one requested, or a later read of the
        // derived version would find nothing.
        let created = serde_json::from_slice::<Value>(&response)
            .ok()
            .and_then(|document| document.get("VersionId")?.as_str().map(str::to_owned));
        if created.as_deref() == Some(version) {
            Ok(())
        } else {
            Err(SecretsApiError::Unavailable)
        }
    }

    async fn get(
        &self,
        name: &str,
        version: &str,
        deadline: Instant,
    ) -> Result<FetchedSecret, SecretsApiError> {
        let body = get_body(name, version).ok_or(SecretsApiError::Unavailable)?;
        let (status, response) = self.call("GetSecretValue", &body, deadline).await?;
        if status != 200 {
            return Err(refusal(&response));
        }
        fetched(&response).ok_or(SecretsApiError::Unavailable)
    }

    async fn delete(&self, name: &str, deadline: Instant) -> Result<(), SecretsApiError> {
        let body = delete_body(name).ok_or(SecretsApiError::Unavailable)?;
        let (status, response) = self.call("DeleteSecret", &body, deadline).await?;
        if status == 200 {
            Ok(())
        } else {
            Err(refusal(&response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_are_one_host_label() {
        for valid in ["eu-west-1", "us-east-1", "ap-southeast-2"] {
            assert_eq!(Region::parse(valid).expect("region").as_str(), valid);
        }
        for invalid in [
            "",
            "EU-WEST-1",
            "eu-west-1.example.com",
            "eu_west_1",
            "-eu",
            "eu-",
            "1eu",
            "eu/west",
        ] {
            assert_eq!(Region::parse(invalid), Err(InvalidDeployment), "{invalid}");
        }
    }

    #[test]
    fn request_bodies_are_exact_and_refuse_values_that_need_escaping() {
        let name = "auths-gateway/00ff";
        let version = "ab".repeat(32);
        let body = create_body(
            name,
            &version,
            b"\x00\xffsecret",
            Some("arn:aws:kms:eu-west-1:1:key/k"),
        )
        .expect("body");
        let document: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(document["Name"], name);
        assert_eq!(document["ClientRequestToken"], version);
        assert_eq!(document["KmsKeyId"], "arn:aws:kms:eu-west-1:1:key/k");
        assert_eq!(
            Base64::decode_vec(document["SecretBinary"].as_str().expect("binary")).expect("base64"),
            b"\x00\xffsecret"
        );
        assert_eq!(document.as_object().expect("object").len(), 4);
        assert!(create_body(name, &version, b"s", None).is_some());
        assert_eq!(
            get_body(name, &version).expect("body"),
            format!("{{\"SecretId\":\"{name}\",\"VersionId\":\"{version}\"}}").into_bytes()
        );
        let delete: Value =
            serde_json::from_slice(&delete_body(name).expect("body")).expect("JSON");
        assert_eq!(delete["ForceDeleteWithoutRecovery"], true);
        for hostile in ["a\"b", "a\\b", "a b", "", "AWSCURRENT\",\"x\":\""] {
            assert!(
                create_body(hostile, &version, b"s", None).is_none(),
                "{hostile}"
            );
            assert!(
                create_body(name, hostile, b"s", None).is_none(),
                "{hostile}"
            );
            assert!(
                create_body(name, &version, b"s", Some(hostile)).is_none(),
                "{hostile}"
            );
            assert!(get_body(hostile, &version).is_none(), "{hostile}");
            assert!(delete_body(hostile).is_none(), "{hostile}");
        }
    }

    #[test]
    fn read_responses_yield_the_version_and_bytes_or_nothing() {
        let body = br#"{"ARN":"arn:x","Name":"n","SecretBinary":"AP9zZWNyZXQ=","VersionId":"v1"}"#;
        let secret = fetched(body).expect("secret");
        assert_eq!(secret.version, "v1");
        assert_eq!(secret.bytes.as_slice(), b"\x00\xffsecret");
        for incomplete in [
            &br#"{"SecretBinary":"AP9zZWNyZXQ="}"#[..],
            br#"{"VersionId":"v1"}"#,
            br#"{"VersionId":"v1","SecretString":"text"}"#,
            br#"{"VersionId":"v1","SecretBinary":"not base64!"}"#,
            br#"{"VersionId":"v1","SecretBinary":"AP9zZWNyZXQ"#,
        ] {
            assert!(fetched(incomplete).is_none());
        }
    }

    #[test]
    fn refusals_are_classified_by_type_only() {
        assert_eq!(
            refusal(br#"{"__type":"ResourceExistsException","Message":"detail"}"#),
            SecretsApiError::Exists
        );
        assert_eq!(
            refusal(br#"{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException"}"#),
            SecretsApiError::NotFound
        );
        for other in [
            &br#"{"__type":"AccessDeniedException"}"#[..],
            br#"{"__type":"ThrottlingException"}"#,
            b"<html>",
            b"",
        ] {
            assert_eq!(refusal(other), SecretsApiError::Unavailable);
        }
    }
}
