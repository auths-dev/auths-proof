//! The store against the real service, in a protected account.
//!
//! Ignored by default. The custody live workflow runs it with a web
//! identity token and two roles: an operator role that may create and
//! delete secrets, and a runtime role that may only read them. It writes
//! only disposable secrets under a namespace unique to the run and deletes
//! what it created. The secret values are fixed test bytes.

use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
    ConnectionRecord, ConnectionState, CredentialBinding, CredentialReferenceCommitment,
    CredentialStoreError, ProviderKind, SecretBytes, SemanticId,
};
use auths_credentials_aws_secrets_manager::{
    AwsSecretsManagerStore, DeploymentNamespace, HttpSecretsApi, Region, WebIdentity,
    WorkloadIdentity as _,
};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn store(role: &str) -> AwsSecretsManagerStore<HttpSecretsApi<WebIdentity>> {
    let region = Region::parse(setting("AUTHS_CUSTODY_LIVE_REGION")).expect("region");
    let identity = WebIdentity::new(
        &region,
        setting(role),
        setting("AUTHS_CUSTODY_LIVE_TOKEN_FILE"),
    )
    .expect("identity");
    let key = std::env::var("AUTHS_CUSTODY_LIVE_KMS_KEY").ok();
    let api = HttpSecretsApi::new(region, key, identity).expect("client");
    let namespace =
        DeploymentNamespace::parse(setting("AUTHS_CUSTODY_LIVE_NAMESPACE")).expect("namespace");
    AwsSecretsManagerStore::new(api, namespace)
}

fn generation(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("generation")
}

fn secret(bytes: &[u8]) -> SecretBytes {
    SecretBytes::new(bytes.to_vec()).expect("secret")
}

/// The store's view of a record at `generation_value` whose credential was
/// stored at `credential` with `commitment`.
fn binding(
    connection: &ConnectionId,
    generation_value: u64,
    credential: u64,
    commitment: CredentialReferenceCommitment,
) -> CredentialBinding {
    let profile =
        ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2).expect("profile");
    let mut record = ConnectionRecord::new(
        ProviderKind::parse("example").expect("provider"),
        ConnectionAlias::parse("default").expect("alias"),
        connection.clone(),
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        b"descriptor".to_vec(),
        [2; 32],
        *commitment.as_bytes(),
        generation(credential),
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![profile],
        10,
        10,
        None,
    )
    .expect("record");
    while record.generation().get() < generation_value {
        let next = if record.state() == ConnectionState::Active {
            ConnectionState::Disabled
        } else {
            ConnectionState::Active
        };
        record = record.transition_state(next, 11).expect("state change");
    }
    record.credential_binding()
}

async fn leased(
    store: &AwsSecretsManagerStore<HttpSecretsApi<WebIdentity>>,
    binding: &CredentialBinding,
) -> Result<Vec<u8>, CredentialStoreError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let lease = store.lease_secret(binding, deadline).await?;
    lease.expose(Instant::now()).map(<[u8]>::to_vec)
}

#[tokio::test]
#[ignore = "needs the protected account's roles and a web identity token"]
async fn the_store_holds_its_contract_against_the_service() {
    // First, apart from any secret: each role yields session credentials.
    let region = Region::parse(setting("AUTHS_CUSTODY_LIVE_REGION")).expect("region");
    for role in [
        "AUTHS_CUSTODY_LIVE_OPERATOR_ROLE",
        "AUTHS_CUSTODY_LIVE_RUNTIME_ROLE",
    ] {
        let identity = WebIdentity::new(
            &region,
            setting(role),
            setting("AUTHS_CUSTODY_LIVE_TOKEN_FILE"),
        )
        .expect("identity");
        let session = identity
            .session(Instant::now() + Duration::from_secs(15))
            .await;
        assert!(
            session.is_ok(),
            "{role}: the token exchange did not yield session credentials"
        );
    }
    let operator = store("AUTHS_CUSTODY_LIVE_OPERATOR_ROLE");
    let runtime = store("AUTHS_CUSTODY_LIVE_RUNTIME_ROLE");
    let connection = ConnectionId::generate().expect("connection");
    // Generation 9 is the write the runtime role must be refused; it is
    // listed so that a role that was wrongly allowed leaves nothing behind.
    let known = [generation(1), generation(2), generation(9)];

    // Install with the operator role; the derived version must be accepted
    // as the secret's only version, or nothing below can pass.
    let first = operator
        .install(
            &connection,
            generation(1),
            secret(b"auths-live-first-not-a-secret"),
        )
        .await
        .expect("install: the service accepted the derived version identifier");
    let outcome = async {
        // The runtime role reads exactly what was installed, at a later
        // connection generation too.
        let serving = binding(&connection, 3, 1, first);
        assert_eq!(
            leased(&runtime, &serving).await?,
            b"auths-live-first-not-a-secret"
        );
        runtime.holds(&serving).await?;

        // Another commitment names another version, which does not exist.
        let other = CredentialReferenceCommitment::of(&connection, generation(1), b"other");
        assert_eq!(
            leased(&runtime, &binding(&connection, 1, 1, other)).await,
            Err(CredentialStoreError::Unavailable)
        );

        // The runtime role cannot write.
        let refused = runtime
            .install(&connection, generation(9), secret(b"auths-live-refused"))
            .await;
        assert_eq!(refused.map(drop), Err(CredentialStoreError::Unavailable));

        // A second install of the same generation conflicts.
        let again = operator
            .install(&connection, generation(1), secret(b"auths-live-again"))
            .await;
        assert_eq!(again.map(drop), Err(CredentialStoreError::Conflict));

        // Rotation: the old generation is kept until it is revoked, and a
        // revoked generation is never answered by its successor.
        let second = operator
            .replace(
                &connection,
                generation(1),
                generation(2),
                secret(b"auths-live-second-not-a-secret"),
            )
            .await?;
        let old = binding(&connection, 1, 1, first);
        let new = binding(&connection, 2, 2, second);
        assert_eq!(
            leased(&runtime, &old).await?,
            b"auths-live-first-not-a-secret"
        );
        assert_eq!(
            leased(&runtime, &new).await?,
            b"auths-live-second-not-a-secret"
        );
        operator.revoke(&connection, generation(1)).await?;
        assert_eq!(
            leased(&runtime, &old).await,
            Err(CredentialStoreError::Unavailable)
        );
        assert_eq!(
            leased(&runtime, &new).await?,
            b"auths-live-second-not-a-secret"
        );
        Ok::<(), CredentialStoreError>(())
    }
    .await;

    // Delete everything this run created, whatever happened above.
    let cleaned = operator.delete_connection(&connection, &known).await;
    outcome.expect("the store contract holds against the service");
    cleaned.expect("cleanup");
    assert_eq!(
        operator.delete_connection(&connection, &known).await,
        Ok(()),
        "deleting again succeeds with nothing stored"
    );
}
