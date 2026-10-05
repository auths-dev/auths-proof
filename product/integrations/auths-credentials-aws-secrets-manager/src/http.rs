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
    /// The URL every call is sent to: the regional service endpoint.
    endpoint: String,
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
            endpoint: format!("https://secretsmanager.{}.amazonaws.com/", region.as_str()),
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
            .post(&self.endpoint)
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
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};

    /// A workload identity with fixed, plainly fake session credentials.
    struct FixedIdentity;

    #[async_trait]
    impl WorkloadIdentity for FixedIdentity {
        async fn session(&self, _deadline: Instant) -> Result<SessionCredentials, SecretsApiError> {
            Ok(SessionCredentials {
                access_key_id: "ASIAEXAMPLE".to_owned(),
                secret_access_key: Zeroizing::new("example-secret".to_owned()),
                session_token: Zeroizing::new("example-token".to_owned()),
                expires_at_unix_seconds: u64::MAX,
            })
        }
    }

    /// How the loopback service answers its one request.
    enum Reply {
        /// A complete response with this status and body.
        Complete(u16, Vec<u8>),
        /// Declares more bytes than it sends, then closes.
        Truncated,
        /// Answers only after this long.
        Late(Duration),
    }

    /// Serves one request on a loopback port and returns the request it
    /// received. Plain HTTP: only this test module can point a client here.
    fn serve_once(reply: Reply) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}/", listener.local_addr().expect("address"));
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_request(&mut stream);
            match reply {
                Reply::Complete(status, body) => {
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                }
                Reply::Truncated => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 X\r\ncontent-length: 500\r\nconnection: close\r\n\r\n{\"Ver",
                    );
                }
                Reply::Late(delay) => {
                    std::thread::sleep(delay);
                    let _ = stream.write_all(b"HTTP/1.1 200 X\r\ncontent-length: 2\r\n\r\n{}");
                }
            }
            request
        });
        (endpoint, handle)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut received = Vec::new();
        let mut buffer = [0_u8; 4_096];
        loop {
            let count = stream.read(&mut buffer).expect("read");
            received.extend_from_slice(&buffer[..count]);
            let text = String::from_utf8_lossy(&received).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if body.len() >= length || count == 0 {
                    return text;
                }
            }
            if count == 0 {
                return text;
            }
        }
    }

    fn client(endpoint: String) -> HttpSecretsApi<FixedIdentity> {
        HttpSecretsApi {
            client: pinned_client(false).expect("client"),
            region: Region::parse("eu-west-1").expect("region"),
            host: "secretsmanager.eu-west-1.amazonaws.com".to_owned(),
            endpoint,
            key: None,
            identity: FixedIdentity,
            session: Mutex::new(None),
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test]
    async fn a_read_is_signed_and_addressed_to_one_exact_version() {
        let version = "ab".repeat(32);
        let body = format!(r#"{{"SecretBinary":"AP9zZWNyZXQ=","VersionId":"{version}"}}"#);
        let (endpoint, served) = serve_once(Reply::Complete(200, body.into_bytes()));
        let secret = client(endpoint)
            .get("auths-gateway/00ff", &version, soon())
            .await
            .expect("secret");
        assert_eq!(secret.version, version);
        assert_eq!(secret.bytes.as_slice(), b"\x00\xffsecret");
        let request = served.join().expect("request").to_ascii_lowercase();
        assert!(request.starts_with("post / http/1.1"));
        assert!(request.contains("x-amz-target: secretsmanager.getsecretvalue"));
        assert!(request.contains("authorization: aws4-hmac-sha256 credential=asiaexample/"));
        assert!(request.contains(
            "signedheaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
        ));
        assert!(request.contains(&format!(
            r#"{{"secretid":"auths-gateway/00ff","versionid":"{version}"}}"#
        )));
        assert!(!request.contains("awscurrent"));
    }

    /// Every reply the service could wrongly give is one refusal, and none
    /// yields a secret.
    #[tokio::test]
    async fn hostile_replies_yield_no_secret() {
        let version = "ab".repeat(32);
        let oversized = format!(
            r#"{{"SecretBinary":"{}","VersionId":"{version}"}}"#,
            "A".repeat(MAXIMUM_RESPONSE_BYTES)
        );
        let replies = [
            ("truncated", Reply::Truncated, SecretsApiError::Unavailable),
            (
                "oversized",
                Reply::Complete(200, oversized.into_bytes()),
                SecretsApiError::Unavailable,
            ),
            (
                "not json",
                Reply::Complete(200, b"<html>".to_vec()),
                SecretsApiError::Unavailable,
            ),
            (
                "no secret",
                Reply::Complete(200, br#"{"VersionId":"v"}"#.to_vec()),
                SecretsApiError::Unavailable,
            ),
            (
                "redirect",
                Reply::Complete(
                    307,
                    br#"{"SecretBinary":"AP9zZWNyZXQ=","VersionId":"v"}"#.to_vec(),
                ),
                SecretsApiError::Unavailable,
            ),
            (
                "not found",
                Reply::Complete(400, br#"{"__type":"ResourceNotFoundException"}"#.to_vec()),
                SecretsApiError::NotFound,
            ),
            (
                "denied",
                Reply::Complete(
                    400,
                    br#"{"__type":"AccessDeniedException","Message":"detail"}"#.to_vec(),
                ),
                SecretsApiError::Unavailable,
            ),
            (
                "server error",
                Reply::Complete(500, Vec::new()),
                SecretsApiError::Unavailable,
            ),
        ];
        for (name, reply, refusal) in replies {
            let (endpoint, served) = serve_once(reply);
            let outcome = client(endpoint)
                .get("auths-gateway/00ff", &version, soon())
                .await;
            assert_eq!(outcome.map(drop), Err(refusal), "{name}");
            served.join().expect("request");
        }
    }

    #[tokio::test]
    async fn a_reply_after_the_deadline_is_refused_and_not_retried() {
        let (endpoint, served) = serve_once(Reply::Late(Duration::from_millis(600)));
        let started = Instant::now();
        let outcome = client(endpoint)
            .get(
                "auths-gateway/00ff",
                &"ab".repeat(32),
                Instant::now() + Duration::from_millis(150),
            )
            .await;
        assert_eq!(outcome.map(drop), Err(SecretsApiError::Unavailable));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the call ended at its deadline"
        );
        // The service saw exactly one request: a second would hang the join.
        served.join().expect("one request");
    }

    #[tokio::test]
    async fn a_create_that_reports_another_version_is_refused() {
        let version = "ab".repeat(32);
        let other = format!(r#"{{"Name":"n","VersionId":"{}"}}"#, "cd".repeat(32));
        let (endpoint, served) = serve_once(Reply::Complete(200, other.into_bytes()));
        let outcome = client(endpoint)
            .create("auths-gateway/00ff", &version, b"s", soon())
            .await;
        assert_eq!(outcome, Err(SecretsApiError::Unavailable));
        served.join().expect("request");

        let same = format!(r#"{{"Name":"n","VersionId":"{version}"}}"#);
        let (endpoint, served) = serve_once(Reply::Complete(200, same.into_bytes()));
        let outcome = client(endpoint)
            .create("auths-gateway/00ff", &version, b"s", soon())
            .await;
        assert_eq!(outcome, Ok(()));
        assert!(
            served
                .join()
                .expect("request")
                .contains(r#""SecretBinary":"cw==""#)
        );

        let exists = br#"{"__type":"ResourceExistsException"}"#.to_vec();
        let (endpoint, served) = serve_once(Reply::Complete(400, exists));
        let outcome = client(endpoint)
            .create("auths-gateway/00ff", &version, b"s", soon())
            .await;
        assert_eq!(outcome, Err(SecretsApiError::Exists));
        served.join().expect("request");
    }

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
