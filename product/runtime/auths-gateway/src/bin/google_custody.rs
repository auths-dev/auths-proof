//! Google employee grant custody for the development task gateway.
//!
//! This vertical implements the generic post-reservation materializer port.
//! It never constructs a Docs or Drive request; reviewed recipes continue to
//! own those effects. The saved refresh grant stays in an owner-private file.

use async_trait::async_trait;
use auths_connections::StoredSecretLease;
use auths_gateway::{
    CredentialMaterializationContext, CredentialMaterializationError, CredentialMaterializer,
    CredentialRequestKind, MATERIALIZER_SOURCE_PREFIX, MaterializedCredential,
};
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

const SCHEMA: &str = "auths.google-credential-materializer/1";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const SCOPES: [&str; 3] = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/drive.file",
];
const MAX_PRIVATE_FILE: u64 = 65_536;

/// Operator-reviewed inputs. No token, refresh token or client secret is in
/// this configuration; every path is rechecked on each admitted operation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GoogleCustodyPins {
    pub schema: String,
    pub connection_id: String,
    pub connection_generation: u64,
    pub source_generation: u64,
    pub source_ref: String,
    pub producer_evidence_file: PathBuf,
    pub producer_evidence_sha256: String,
    pub grant_file: PathBuf,
    pub oauth_client_file: PathBuf,
    pub company: String,
    pub instance: String,
    pub definition_hash: String,
    pub customer_id: String,
    pub client_id: String,
    pub subject: String,
    pub email: String,
    pub hosted_domain: String,
    pub recipe_digests: Vec<String>,
    pub allowed_kinds: Vec<String>,
}

impl GoogleCustodyPins {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        let source = self.source_ref.as_bytes();
        let expected_source = format!(
            "{}demo-co-local-secret://{}/{}/google-write-person-jules.json#evidence={}",
            std::str::from_utf8(MATERIALIZER_SOURCE_PREFIX)
                .map_err(|_| "gateway.materializer.invalid-google-pins")?,
            self.instance,
            self.company,
            self.producer_evidence_sha256,
        );
        if self.schema != SCHEMA
            || auths_connections::ConnectionId::parse(&self.connection_id).is_err()
            || self.connection_generation == 0
            || self.source_generation == 0
            || self.source_generation > self.connection_generation
            || !source.starts_with(MATERIALIZER_SOURCE_PREFIX)
            || source.len() <= MATERIALIZER_SOURCE_PREFIX.len()
            || source.len() > 1_024
            || !source.iter().all(u8::is_ascii_graphic)
            || self.source_ref != expected_source
            || !self.producer_evidence_file.is_absolute()
            || !self.grant_file.is_absolute()
            || !self.oauth_client_file.is_absolute()
            || !hex64(&self.producer_evidence_sha256)
            || !hex64(&self.definition_hash)
            || [
                &self.company,
                &self.instance,
                &self.customer_id,
                &self.client_id,
                &self.subject,
                &self.email,
                &self.hosted_domain,
            ]
            .iter()
            .any(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || self.recipe_digests.is_empty()
            || self.recipe_digests.len() > 4
            || self.recipe_digests.iter().any(|digest| !hex64(digest))
            || self
                .recipe_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.allowed_kinds.is_empty()
            || self.allowed_kinds.len() > 2
            || self
                .allowed_kinds
                .iter()
                .any(|kind| kind != "read-release" && kind != "write-effect")
            || self.allowed_kinds.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("gateway.materializer.invalid-google-pins");
        }
        Ok(())
    }

    fn authority_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"auths.google-custody-authority/1\0");
        for value in [
            self.client_id.as_str(),
            self.subject.as_str(),
            self.email.as_str(),
            self.hosted_domain.as_str(),
            self.source_ref.as_str(),
            self.producer_evidence_sha256.as_str(),
        ] {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
        for scope in SCOPES {
            digest.update(scope.as_bytes());
            digest.update([0]);
        }
        for digest_value in &self.recipe_digests {
            digest.update(digest_value.as_bytes());
            digest.update([0]);
        }
        for kind in &self.allowed_kinds {
            digest.update(kind.as_bytes());
            digest.update([0]);
        }
        digest.finalize().into()
    }
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct GoogleGrant {
    token: String,
    refresh_token: String,
    client_secret: String,
    client_id: String,
    token_uri: String,
    universe_domain: String,
    account: String,
    scopes: Vec<String>,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct OAuthClientFile {
    installed: OAuthClientSettings,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct OAuthClientSettings {
    client_id: String,
    client_secret: String,
    token_uri: String,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct RefreshResponse {
    access_token: String,
    expires_in: u64,
    scope: Option<String>,
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: String,
    email_verified: bool,
    hd: String,
}

pub(super) struct GoogleCustodyMaterializer {
    pins: GoogleCustodyPins,
    client: Client,
    authority_digest: [u8; 32],
    token_url: String,
    userinfo_url: String,
}

impl GoogleCustodyMaterializer {
    pub(super) fn new(pins: GoogleCustodyPins) -> Result<Self, &'static str> {
        pins.validate()?;
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| "gateway.materializer.http-unavailable")?;
        let authority_digest = pins.authority_digest();
        let adapter = Self {
            pins,
            client,
            authority_digest,
            token_url: TOKEN_URL.to_owned(),
            userinfo_url: USERINFO_URL.to_owned(),
        };
        // Refuse a broken operator installation before any human task is
        // signed. Every actual lease repeats these checks after admission.
        adapter
            .checked_grant()
            .map_err(|_| "gateway.materializer.invalid-local-source")?;
        Ok(adapter)
    }

    pub(super) const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }

    pub(super) fn connection_id(&self) -> &str {
        &self.pins.connection_id
    }

    fn evidence_valid(&self) -> bool {
        let Ok(raw) = private_file(&self.pins.producer_evidence_file) else {
            return false;
        };
        let actual: [u8; 32] = Sha256::digest(&*raw).into();
        let Ok(expected) = hex::decode(&self.pins.producer_evidence_sha256) else {
            return false;
        };
        if !bool::from(actual.ct_eq(expected.as_slice())) {
            return false;
        }
        let Ok(evidence) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            return false;
        };
        let scopes = evidence["granted_scopes"].as_array();
        evidence["schema_version"] == "demo-co/google-write-verification/v1"
            && evidence["status"] == "ready"
            && evidence["company"] == self.pins.company
            && evidence["instance"] == self.pins.instance
            && evidence["definition_hash"] == self.pins.definition_hash
            && evidence["customer_id"] == self.pins.customer_id
            && evidence["jules_subject"] == self.pins.subject
            && evidence["jules_email"] == self.pins.email
            && scopes.is_some_and(|values| {
                values.len() == 3
                    && values.iter().all(serde_json::Value::is_string)
                    && exact_scope_values(values.iter().filter_map(serde_json::Value::as_str))
            })
            && evidence["folder_can_add_children"] == true
            && evidence["document_can_edit"] == true
            && evidence["probe_created_as_jules"] == true
            && evidence["probe_edited_as_jules"] == true
            && evidence["project_b_write_capability_denied"] == true
            && evidence["canonical_documents_mutated"] == false
    }

    fn checked_grant(&self) -> Result<GoogleGrant, CredentialMaterializationError> {
        if !self.evidence_valid() {
            return Err(CredentialMaterializationError);
        }
        let raw =
            private_file(&self.pins.grant_file).map_err(|()| CredentialMaterializationError)?;
        let grant: GoogleGrant =
            serde_json::from_slice(&raw).map_err(|_| CredentialMaterializationError)?;
        let client_raw = private_file(&self.pins.oauth_client_file)
            .map_err(|()| CredentialMaterializationError)?;
        let client_file: OAuthClientFile =
            serde_json::from_slice(&client_raw).map_err(|_| CredentialMaterializationError)?;
        if grant.token_uri != TOKEN_URL
            || grant.universe_domain != "googleapis.com"
            || grant.client_id != self.pins.client_id
            // Google's authorized-user file may leave `account` empty. The
            // live UserInfo check supplies the subject/email binding.
            || (!grant.account.is_empty() && grant.account != self.pins.email)
            || grant.client_secret.is_empty()
            || grant.refresh_token.is_empty()
            || client_file.installed.token_uri != TOKEN_URL
            || client_file.installed.client_id != self.pins.client_id
            || client_file.installed.client_secret.len() != grant.client_secret.len()
            || !bool::from(
                client_file
                    .installed
                    .client_secret
                    .as_bytes()
                    .ct_eq(grant.client_secret.as_bytes()),
            )
            || !exact_scope_values(grant.scopes.iter().map(String::as_str))
        {
            return Err(CredentialMaterializationError);
        }
        Ok(grant)
    }

    async fn fresh_token(
        &self,
        grant: &GoogleGrant,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), CredentialMaterializationError> {
        let response = self
            .client
            .post(self.token_url.as_str())
            .form(&[
                ("client_id", grant.client_id.as_str()),
                ("client_secret", grant.client_secret.as_str()),
                ("refresh_token", grant.refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| CredentialMaterializationError)?;
        if !response.status().is_success() {
            return Err(CredentialMaterializationError);
        }
        let raw = bounded_body(response, 16_384).await?;
        let mut refreshed: RefreshResponse =
            serde_json::from_slice(&raw).map_err(|_| CredentialMaterializationError)?;
        if refreshed.access_token.is_empty()
            || refreshed.access_token.len() > 16_384
            || !(90..=86_400).contains(&refreshed.expires_in)
            || refreshed
                .token_type
                .as_deref()
                .is_some_and(|kind| kind != "Bearer")
            || refreshed
                .scope
                .as_deref()
                .is_some_and(|scope| !exact_scope_values(scope.split_whitespace()))
        {
            return Err(CredentialMaterializationError);
        }
        let token = Zeroizing::new(std::mem::take(&mut refreshed.access_token).into_bytes());
        Ok((token, refreshed.expires_in))
    }

    async fn userinfo_valid(&self, token: &[u8]) -> bool {
        let Ok(token) = std::str::from_utf8(token) else {
            return false;
        };
        let Ok(response) = self
            .client
            .get(self.userinfo_url.as_str())
            .bearer_auth(token)
            .send()
            .await
        else {
            return false;
        };
        if !response.status().is_success() {
            return false;
        }
        let Ok(raw) = bounded_body(response, 4_096).await else {
            return false;
        };
        let Ok(info) = serde_json::from_slice::<UserInfo>(&raw) else {
            return false;
        };
        info.sub == self.pins.subject
            && info.email == self.pins.email
            && info.email_verified
            && info.hd == self.pins.hosted_domain
    }
}

#[async_trait]
impl CredentialMaterializer for GoogleCustodyMaterializer {
    async fn materialize(
        &self,
        context: &CredentialMaterializationContext,
        source: &StoredSecretLease,
        deadline: Instant,
    ) -> Result<MaterializedCredential, CredentialMaterializationError> {
        let expected = self.pins.source_ref.as_bytes();
        let actual = source
            .expose(Instant::now())
            .map_err(|_| CredentialMaterializationError)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CredentialMaterializationError)?
            .as_secs();
        let kind = match context.kind {
            CredentialRequestKind::ReadRelease => "read-release",
            CredentialRequestKind::WriteEffect => "write-effect",
        };
        if context.connection_id != self.pins.connection_id
            || context.connection_generation != self.pins.connection_generation
            || context.source_generation != self.pins.source_generation
            || context.account_subject != self.pins.subject
            || !self.pins.recipe_digests.contains(&context.recipe_digest)
            || !self
                .pins
                .allowed_kinds
                .iter()
                .any(|allowed| allowed == kind)
            || context.task_id.is_empty()
            || context.operation_id.is_empty()
            || context.task_expires_at <= now
            || actual.len() != expected.len()
            || !bool::from(actual.ct_eq(expected))
        {
            return Err(CredentialMaterializationError);
        }
        let grant = self.checked_grant()?;
        let (token, seconds) = self.fresh_token(&grant).await?;
        if !self.userinfo_valid(&token).await {
            return Err(CredentialMaterializationError);
        }
        let provider_deadline = Instant::now()
            .checked_add(Duration::from_secs(seconds.saturating_sub(30)))
            .ok_or(CredentialMaterializationError)?;
        let deadline = deadline.min(provider_deadline);
        Ok(MaterializedCredential {
            lease: StoredSecretLease::from_store(token, deadline),
            account_subject: self.pins.subject.clone(),
            effective_authority_digest: self.authority_digest,
        })
    }
}

fn exact_scope_values<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut scopes: Vec<&str> = values.collect();
    scopes.sort_unstable();
    let mut expected = SCOPES;
    expected.sort_unstable();
    scopes == expected
}

async fn bounded_body(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, CredentialMaterializationError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CredentialMaterializationError);
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CredentialMaterializationError)?
    {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Err(CredentialMaterializationError);
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err(CredentialMaterializationError);
    }
    Ok(body)
}

fn private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ()> {
    let parent = path.parent().ok_or(())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ())?;
    if !parent_meta.is_dir()
        || parent_meta.uid() != rustix::process::geteuid().as_raw()
        || parent_meta.permissions().mode() & 0o077 != 0
    {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
        .map_err(|_| ())?;
    let meta = file.metadata().map_err(|_| ())?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() > MAX_PRIVATE_FILE
    {
        return Err(());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PRIVATE_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVATE_FILE {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_gateway::CredentialRequestKind;
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn fixture() -> (tempfile::TempDir, GoogleCustodyPins) {
        let directory = tempfile::tempdir().expect("private fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let evidence_path = directory.path().join("evidence.json");
        let grant_path = directory.path().join("grant.json");
        let client_path = directory.path().join("oauth-client.json");
        let evidence = json!({
            "schema_version": "demo-co/google-write-verification/v1",
            "status": "ready", "company": "atlas-studio", "instance": "test-instance",
            "definition_hash": "a".repeat(64), "customer_id": "customer-1",
            "jules_subject": "subject-1", "jules_email": "jules@example.test",
            "granted_scopes": SCOPES, "folder_can_add_children": true,
            "document_can_edit": true, "probe_created_as_jules": true,
            "probe_edited_as_jules": true, "project_b_write_capability_denied": true,
            "canonical_documents_mutated": false,
        });
        let raw = serde_json::to_vec(&evidence).expect("evidence");
        fs::write(&evidence_path, &raw).expect("evidence file");
        fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let evidence_sha256 = hex::encode(Sha256::digest(&raw));
        let grant = json!({
            "token": "synthetic-stale", "refresh_token": "synthetic-refresh",
            "client_secret": "synthetic-client-secret", "client_id": "client-1",
            "token_uri": TOKEN_URL, "universe_domain": "googleapis.com",
            "account": "", "scopes": SCOPES,
        });
        fs::write(&grant_path, serde_json::to_vec(&grant).expect("grant")).expect("grant file");
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let client_file = json!({"installed": {"client_id": "client-1",
            "client_secret": "synthetic-client-secret", "token_uri": TOKEN_URL}});
        fs::write(
            &client_path,
            serde_json::to_vec(&client_file).expect("client"),
        )
        .expect("client file");
        fs::set_permissions(&client_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let pins = GoogleCustodyPins {
            schema: SCHEMA.to_owned(),
            connection_id: "conn_AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            connection_generation: 1,
            source_generation: 1,
            source_ref: format!(
                "auths.materializer-source/1:demo-co-local-secret://test-instance/atlas-studio/google-write-person-jules.json#evidence={evidence_sha256}"
            ),
            producer_evidence_file: evidence_path,
            producer_evidence_sha256: evidence_sha256,
            grant_file: grant_path,
            oauth_client_file: client_path,
            company: "atlas-studio".to_owned(),
            instance: "test-instance".to_owned(),
            definition_hash: "a".repeat(64),
            customer_id: "customer-1".to_owned(),
            client_id: "client-1".to_owned(),
            subject: "subject-1".to_owned(),
            email: "jules@example.test".to_owned(),
            hosted_domain: "example.test".to_owned(),
            recipe_digests: vec!["b".repeat(64)],
            allowed_kinds: vec!["write-effect".to_owned()],
        };
        (directory, pins)
    }

    fn request(pins: &GoogleCustodyPins) -> CredentialMaterializationContext {
        CredentialMaterializationContext {
            task_id: "task-1".to_owned(),
            operation_id: "effect-1".to_owned(),
            connection_id: pins.connection_id.clone(),
            connection_generation: pins.connection_generation,
            source_generation: pins.source_generation,
            account_subject: pins.subject.clone(),
            recipe_digest: pins.recipe_digests[0].clone(),
            task_expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
            kind: CredentialRequestKind::WriteEffect,
        }
    }

    fn source(pins: &GoogleCustodyPins) -> StoredSecretLease {
        StoredSecretLease::from_store(
            Zeroizing::new(pins.source_ref.as_bytes().to_vec()),
            Instant::now() + Duration::from_secs(30),
        )
    }

    #[test]
    fn invalid_saved_grant_is_refused_before_installation() {
        let (_directory, pins) = fixture();
        let mut grant: serde_json::Value =
            serde_json::from_slice(&fs::read(&pins.grant_file).unwrap()).unwrap();
        grant["scopes"] = json!(["openid"]);
        fs::write(&pins.grant_file, serde_json::to_vec(&grant).unwrap()).unwrap();
        assert!(GoogleCustodyMaterializer::new(pins).is_err());
    }

    #[tokio::test]
    async fn refreshes_after_reservation_and_checks_google_subject() {
        let (_directory, pins) = fixture();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("provider double");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            for (path, body) in [
                (
                    "/token",
                    json!({"access_token": "synthetic-fresh", "expires_in": 3600,
                    "scope": SCOPES.join(" "), "token_type": "Bearer"}),
                ),
                (
                    "/userinfo",
                    json!({"sub": "subject-1", "email": "jules@example.test",
                    "email_verified": true, "hd": "example.test"}),
                ),
            ] {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buf = [0_u8; 4096];
                let size = stream.read(&mut buf).await.expect("request");
                let request = String::from_utf8_lossy(&buf[..size]);
                assert!(request.lines().next().unwrap_or_default().contains(path));
                if path == "/userinfo" {
                    assert!(request.contains("Bearer synthetic-fresh"));
                }
                let body = body.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
            }
        });
        let mut adapter = GoogleCustodyMaterializer::new(pins.clone()).expect("pins");
        assert!(
            private_file(&pins.producer_evidence_file).is_ok(),
            "private evidence fixture"
        );
        assert!(adapter.evidence_valid(), "synthetic evidence pin");
        assert!(
            private_file(&pins.grant_file).is_ok(),
            "private grant fixture"
        );
        adapter.token_url = format!("http://{address}/token");
        adapter.userinfo_url = format!("http://{address}/userinfo");
        let context = request(&pins);
        let lease = adapter
            .materialize(
                &context,
                &source(&pins),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .expect("checked token");
        assert_eq!(
            lease.lease.expose(Instant::now()).unwrap(),
            b"synthetic-fresh"
        );
        assert_eq!(lease.account_subject, pins.subject);
        assert_eq!(lease.effective_authority_digest, adapter.authority_digest());
        server.await.expect("provider double");
    }

    #[tokio::test]
    async fn changed_scope_recipe_source_or_private_file_refuses_before_http() {
        let (_directory, pins) = fixture();
        let adapter = GoogleCustodyMaterializer::new(pins.clone()).expect("pins");
        let mut wrong_recipe = request(&pins);
        wrong_recipe.recipe_digest = "c".repeat(64);
        assert!(
            adapter
                .materialize(
                    &wrong_recipe,
                    &source(&pins),
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        let mut wrong_kind = request(&pins);
        wrong_kind.kind = CredentialRequestKind::ReadRelease;
        assert!(
            adapter
                .materialize(
                    &wrong_kind,
                    &source(&pins),
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        let wrong_source = StoredSecretLease::from_store(
            Zeroizing::new(b"auths.materializer-source/1:other".to_vec()),
            Instant::now() + Duration::from_secs(30),
        );
        assert!(
            adapter
                .materialize(
                    &request(&pins),
                    &wrong_source,
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        let mut grant: serde_json::Value =
            serde_json::from_slice(&fs::read(&pins.grant_file).unwrap()).unwrap();
        grant["scopes"] = json!([
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/drive"
        ]);
        fs::write(&pins.grant_file, serde_json::to_vec(&grant).unwrap()).unwrap();
        assert!(
            adapter
                .materialize(
                    &request(&pins),
                    &source(&pins),
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        grant["scopes"] = json!(SCOPES);
        grant["account"] = json!("other@example.test");
        fs::write(&pins.grant_file, serde_json::to_vec(&grant).unwrap()).unwrap();
        assert!(
            adapter
                .materialize(
                    &request(&pins),
                    &source(&pins),
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        grant["account"] = json!("");
        fs::write(&pins.grant_file, serde_json::to_vec(&grant).unwrap()).unwrap();
        let mut client: serde_json::Value =
            serde_json::from_slice(&fs::read(&pins.oauth_client_file).unwrap()).unwrap();
        client["installed"]["client_secret"] = json!("different-client-secret");
        fs::write(
            &pins.oauth_client_file,
            serde_json::to_vec(&client).unwrap(),
        )
        .unwrap();
        assert!(
            adapter
                .materialize(
                    &request(&pins),
                    &source(&pins),
                    Instant::now() + Duration::from_secs(30)
                )
                .await
                .is_err()
        );
        fs::set_permissions(&pins.grant_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&pins.grant_file).is_err());
    }

    #[tokio::test]
    async fn refreshed_wider_scope_and_changed_userinfo_subject_are_refused() {
        for wrong_scope in [true, false] {
            let (_directory, pins) = fixture();
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("provider double");
            let address = listener.local_addr().expect("address");
            let server = tokio::spawn(async move {
                let requests = if wrong_scope { 1 } else { 2 };
                for index in 0..requests {
                    let (mut stream, _) = listener.accept().await.expect("accept");
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request).await.expect("request");
                    let body = if index == 0 {
                        json!({"access_token": "synthetic-fresh", "expires_in": 3600,
                            "scope": if wrong_scope {
                                "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive"
                            } else {
                                "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file"
                            }, "token_type": "Bearer"})
                    } else {
                        json!({"sub": "other-subject", "email": "jules@example.test",
                            "email_verified": true, "hd": "example.test"})
                    }.to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
                }
            });
            let mut adapter = GoogleCustodyMaterializer::new(pins.clone()).expect("pins");
            adapter.token_url = format!("http://{address}/token");
            adapter.userinfo_url = format!("http://{address}/userinfo");
            assert!(
                adapter
                    .materialize(
                        &request(&pins),
                        &source(&pins),
                        Instant::now() + Duration::from_secs(30)
                    )
                    .await
                    .is_err()
            );
            server.await.expect("provider double");
        }
    }
}
