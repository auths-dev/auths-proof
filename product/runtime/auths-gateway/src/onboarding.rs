//! Credential checks at onboarding: `install` and admin `rotate` test a
//! candidate secret before anything is stored.
//!
//! In order: the secret starts with a declared prefix; the probe finds its
//! declared value; the account read names the expected account; and each
//! denied read is refused with a declared status. Every read shares one
//! 20-second deadline and goes over the pinned transport with the version
//! headers and never an account-scope header. The candidate secret is read
//! only to build the credential header and is never logged or returned.

use crate::submit::{account_commitment, account_label, denied_result};
use crate::transport::{GatewayHttpTransport, ProviderResponse};
use crate::{CompiledRecipe, CredentialRequirement};
use auths_gateway_kernel::order::DeniedResult;
use serde_json::Value;
use std::time::Duration;
use subtle::ConstantTimeEq as _;
use tokio::time::Instant;

/// Every onboarding read shares this deadline.
const ONBOARDING_DEADLINE: Duration = Duration::from_secs(20);

/// The account a candidate secret must name.
#[derive(Clone, Copy, Debug)]
pub enum OnboardingAccount<'a> {
    /// A first install: the account read must equal the operator's label.
    Label(&'a str),
    /// A rotation: the account read must hash to the connection record's
    /// commitment.
    Commitment([u8; 32]),
}

/// Why a candidate secret was refused; nothing was stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnboardingFailure {
    /// The secret starts with no declared prefix.
    Guard,
    /// The probe did not find its declared value.
    Probe,
    /// The account read did not name the expected account.
    Account,
    /// A denied read was not refused with a declared status.
    Capability,
}

impl OnboardingFailure {
    /// The stable code at `install`.
    #[must_use]
    pub const fn install_code(self) -> &'static str {
        match self {
            Self::Guard => "gateway.install.credential-guard",
            Self::Probe => "gateway.install.credential-probe",
            Self::Account => "gateway.install.credential-account",
            Self::Capability => "gateway.install.credential-capability",
        }
    }

    /// The stable code at admin `rotate`.
    #[must_use]
    pub const fn admin_code(self) -> &'static str {
        match self {
            Self::Guard => "gateway.admin.credential-guard",
            Self::Probe => "gateway.admin.credential-probe",
            Self::Account => "gateway.admin.credential-account",
            Self::Capability => "gateway.admin.credential-capability",
        }
    }
}

/// Runs every declared credential check on `secret` before it is stored.
/// A recipe without a guard passes without any read, so its first install
/// stays offline.
///
/// # Errors
///
/// Returns the first failed check. A transport that cannot be prepared, a
/// read that fails, and the shared deadline all fail the check they reach.
pub async fn check_candidate_credential(
    recipe: &CompiledRecipe,
    requirement: &CredentialRequirement,
    secret: &[u8],
    account: OnboardingAccount<'_>,
) -> Result<(), OnboardingFailure> {
    check_with_transport(
        recipe,
        || GatewayHttpTransport::prepare(recipe, requirement).ok(),
        secret,
        account,
    )
    .await
}

/// [`check_candidate_credential`] against a plain-HTTP provider double on
/// `127.0.0.1:port`, in a `loopback-provider` development build. The checks,
/// their order, and the shared deadline are the same; only the destination
/// of the reads differs.
///
/// # Errors
///
/// As [`check_candidate_credential`].
#[cfg(feature = "loopback-provider")]
pub async fn check_candidate_credential_loopback(
    recipe: &CompiledRecipe,
    requirement: &CredentialRequirement,
    secret: &[u8],
    account: OnboardingAccount<'_>,
    port: u16,
) -> Result<(), OnboardingFailure> {
    check_with_transport(
        recipe,
        || GatewayHttpTransport::prepare_loopback(recipe, requirement, port).ok(),
        secret,
        account,
    )
    .await
}

/// [`check_candidate_credential`] over the transport `prepare` returns, which
/// is prepared only when a check needs the network.
async fn check_with_transport(
    recipe: &CompiledRecipe,
    prepare: impl FnOnce() -> Option<GatewayHttpTransport>,
    secret: &[u8],
    account: OnboardingAccount<'_>,
) -> Result<(), OnboardingFailure> {
    let Some(guard) = recipe.guard_checks() else {
        return Ok(());
    };
    if !guard.admits_secret(secret) {
        return Err(OnboardingFailure::Guard);
    }
    let reads = recipe
        .credential_reads()
        .map_err(|_| OnboardingFailure::Probe)?;
    let first_network = if reads.probe().is_some() {
        OnboardingFailure::Probe
    } else if reads.account().is_some() {
        OnboardingFailure::Account
    } else if reads.denied().is_empty() {
        return Ok(());
    } else {
        OnboardingFailure::Capability
    };
    let transport = prepare().ok_or(first_network)?;
    let deadline = Instant::now() + ONBOARDING_DEADLINE;
    let read = |read: &crate::ClosedCredentialRead| {
        let transport = &transport;
        let read = read.clone();
        async move {
            tokio::time::timeout_at(deadline, transport.credential_read(&read, secret))
                .await
                .ok()
                .flatten()
        }
    };
    if let (Some(probe), Some((pointer, equals))) = (reads.probe(), &guard.probe) {
        let response = read(probe).await;
        if !probe_passes(response.as_ref(), pointer, equals) {
            return Err(OnboardingFailure::Probe);
        }
    }
    if let (Some(account_read), Some(pointer)) = (reads.account(), &guard.account_pointer) {
        let response = read(account_read).await;
        let label = account_label(response.as_ref(), pointer).ok_or(OnboardingFailure::Account)?;
        let equal = match account {
            OnboardingAccount::Label(expected) => label.as_bytes() == expected.as_bytes(),
            OnboardingAccount::Commitment(expected) => {
                bool::from(account_commitment(&label).ct_eq(&expected))
            }
        };
        if !equal {
            return Err(OnboardingFailure::Account);
        }
    }
    for (denied, refused) in reads.denied().iter().zip(&guard.denied_refused) {
        let response = read(denied).await;
        if denied_result(response.as_ref(), refused) != DeniedResult::Refused {
            return Err(OnboardingFailure::Capability);
        }
    }
    Ok(())
}

/// A complete 2xx JSON response with no version mismatch whose pointer
/// holds exactly the declared value.
fn probe_passes(response: Option<&ProviderResponse>, pointer: &str, equals: &Value) -> bool {
    response
        .and_then(ProviderResponse::usable_body)
        .and_then(|body| serde_json::from_slice::<Value>(body).ok())
        .is_some_and(|document| document.pointer(pointer) == Some(equals))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    const VERSION: &str = "2025-03-31.basil";
    const PLATFORM: &str = "acct_TESTPLATFORM1";

    fn stripe() -> CompiledRecipe {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
        ))
        .expect("corpus");
        let base = &corpus["bases"]["stripe"];
        CompiledRecipe::compile(
            &serde_json::to_vec(&base["recipe"]).expect("recipe"),
            &serde_json::to_vec(&base["lock"]).expect("lock"),
        )
        .expect("stripe recipe")
    }

    /// The Stripe double when every onboarding check passes.
    fn answers() -> BTreeMap<String, (u16, bool, Value)> {
        BTreeMap::from([
            (
                "GET /v1/balance".to_owned(),
                (200, true, json!({"livemode": false})),
            ),
            (
                "GET /v1/account".to_owned(),
                (200, true, json!({"id": PLATFORM})),
            ),
            ("GET /v1/customers".to_owned(), (403, true, Value::Null)),
            ("GET /v1/payouts".to_owned(), (403, true, Value::Null)),
        ])
    }

    /// Answers each request from `answers` until the listener is dropped.
    async fn serve(listener: TcpListener, answers: BTreeMap<String, (u16, bool, Value)>) {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4_096];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => bytes.extend_from_slice(&buffer[..read]),
                }
            }
            let head = String::from_utf8_lossy(&bytes).to_string();
            let key = head
                .lines()
                .next()
                .and_then(|line| line.rsplit_once(' ').map(|(key, _)| key.to_owned()))
                .unwrap_or_default();
            let (status, versioned, body) =
                answers
                    .get(&key)
                    .cloned()
                    .unwrap_or((404, true, Value::Null));
            let body = serde_json::to_vec(&body).expect("body");
            let version = if versioned {
                format!("stripe-version: {VERSION}\r\n")
            } else {
                String::new()
            };
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{version}content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    }

    async fn check(
        answers: BTreeMap<String, (u16, bool, Value)>,
        secret: &str,
        account: OnboardingAccount<'_>,
    ) -> Result<(), OnboardingFailure> {
        let recipe = stripe();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("address").port();
        let server = tokio::spawn(serve(listener, answers));
        let result = check_with_transport(
            &recipe,
            || Some(GatewayHttpTransport::for_loopback_test(&recipe, port)),
            secret.as_bytes(),
            account,
        )
        .await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn onboarding_runs_every_declared_check_in_order() {
        let secret = "rk_test_not-a-real-credential";
        assert_eq!(
            check(answers(), secret, OnboardingAccount::Label(PLATFORM)).await,
            Ok(())
        );
        assert_eq!(
            check(
                answers(),
                secret,
                OnboardingAccount::Commitment(crate::submit::account_commitment(PLATFORM))
            )
            .await,
            Ok(())
        );
        assert_eq!(
            check(
                answers(),
                "sk_test_not-a-real-credential",
                OnboardingAccount::Label(PLATFORM)
            )
            .await,
            Err(OnboardingFailure::Guard),
            "the prefix is checked before any read"
        );
        let mut live = answers();
        live.insert(
            "GET /v1/balance".to_owned(),
            (200, true, json!({"livemode": true})),
        );
        assert_eq!(
            check(live, secret, OnboardingAccount::Label(PLATFORM)).await,
            Err(OnboardingFailure::Probe)
        );
        let mut unversioned = answers();
        unversioned.insert(
            "GET /v1/balance".to_owned(),
            (200, false, json!({"livemode": false})),
        );
        assert_eq!(
            check(unversioned, secret, OnboardingAccount::Label(PLATFORM)).await,
            Err(OnboardingFailure::Probe),
            "a version mismatch makes the probe unavailable"
        );
        assert_eq!(
            check(
                answers(),
                secret,
                OnboardingAccount::Label("acct_TESTOTHER0001")
            )
            .await,
            Err(OnboardingFailure::Account)
        );
        assert_eq!(
            check(
                answers(),
                secret,
                OnboardingAccount::Commitment(crate::submit::account_commitment(
                    "acct_TESTOTHER0001"
                ))
            )
            .await,
            Err(OnboardingFailure::Account)
        );
        let mut answered = answers();
        answered.insert(
            "GET /v1/payouts".to_owned(),
            (200, true, json!({"data": []})),
        );
        assert_eq!(
            check(answered, secret, OnboardingAccount::Label(PLATFORM)).await,
            Err(OnboardingFailure::Capability)
        );
        assert_eq!(
            OnboardingFailure::Capability.install_code(),
            "gateway.install.credential-capability"
        );
        assert_eq!(
            OnboardingFailure::Probe.admin_code(),
            "gateway.admin.credential-probe"
        );
    }

    /// The development build's install reaches the double with the same
    /// checks, in the same order, as the default build reaches the origin.
    #[cfg(feature = "loopback-provider")]
    #[tokio::test]
    async fn the_loopback_build_runs_the_same_onboarding_checks() {
        let recipe = stripe();
        for (answers, secret, expected) in [
            (answers(), "rk_test_not-a-real-credential", Ok(())),
            (
                answers(),
                "rk_live_not-a-real-credential",
                Err(OnboardingFailure::Guard),
            ),
            (
                {
                    let mut answered = answers();
                    answered.insert(
                        "GET /v1/customers".to_owned(),
                        (200, true, json!({"data": []})),
                    );
                    answered
                },
                "rk_test_not-a-real-credential",
                Err(OnboardingFailure::Capability),
            ),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            let port = listener.local_addr().expect("address").port();
            let server = tokio::spawn(serve(listener, answers));
            let result = check_candidate_credential_loopback(
                &recipe,
                recipe.review().credential(),
                secret.as_bytes(),
                OnboardingAccount::Label(PLATFORM),
                port,
            )
            .await;
            server.abort();
            assert_eq!(result, expected, "{secret}");
        }
    }

    #[tokio::test]
    async fn a_recipe_without_a_guard_needs_no_network() {
        let recipe = CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("recipe");
        assert_eq!(
            check_with_transport(
                &recipe,
                || panic!("no transport is prepared"),
                b"pat-anything",
                OnboardingAccount::Label("anything"),
            )
            .await,
            Ok(())
        );
    }
}
