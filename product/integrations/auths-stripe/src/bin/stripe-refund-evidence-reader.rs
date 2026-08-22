//! Protected, read-only Stripe evidence producer for the bounded refund profile.

#![forbid(unsafe_code)]

use auths_stripe::{
    ChargeId, Currency, DigestHex, PaymentIntentId, ProtectedRefundEvidenceSnapshotV1,
    RefundEvidenceInput, RefundEvidenceV1, StripeAccountId, StripeRefundEvidenceRequestV1,
    StripeRefundLocalAgentConfigurationV1,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode, redirect::Policy};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
};
use zeroize::Zeroizing;

const MAX_CONFIGURATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_SECRET_BYTES: usize = 4096;
const MAX_PROVIDER_BYTES: usize = 512 * 1024;
const STRIPE_ORIGIN: &str = "https://api.stripe.com";

#[derive(Deserialize)]
struct StripeAccount {
    id: String,
}

#[derive(Deserialize)]
struct StripePaymentIntent {
    id: String,
    object: String,
    amount: u64,
    currency: String,
    livemode: bool,
    latest_charge: Option<String>,
}

#[derive(Deserialize)]
struct StripeCharge {
    id: String,
    object: String,
    amount: u64,
    amount_captured: u64,
    amount_refunded: u64,
    currency: String,
    captured: bool,
    paid: bool,
    refunded: bool,
    disputed: bool,
    livemode: bool,
    payment_intent: Option<String>,
}

struct Arguments {
    configuration: PathBuf,
    api_version: String,
    credential_file: PathBuf,
    reader_seed_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = arguments()?;
    let configuration_bytes =
        read_stable_regular(&arguments.configuration, MAX_CONFIGURATION_BYTES, false)?;
    let configuration =
        StripeRefundLocalAgentConfigurationV1::from_canonical_bytes(&configuration_bytes)?;
    if !configuration
        .exact_configuration()
        .allows_api_version(&arguments.api_version)
    {
        return Err(invalid("unconfigured Stripe API version"));
    }
    let credential_bytes = Zeroizing::new(read_stable_regular(
        &arguments.credential_file,
        MAX_SECRET_BYTES,
        true,
    )?);
    let credential = one_line_secret(&credential_bytes)?;
    if !credential.starts_with("rk_test_")
        || credential.len() > 256
        || !credential.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid(
            "runtime-read credential must be a restricted Stripe key",
        ));
    }
    let seed_bytes = Zeroizing::new(read_stable_regular(&arguments.reader_seed_file, 128, true)?);
    let seed_text = one_line_secret(&seed_bytes)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    Base64UrlUnpadded::decode(seed_text, &mut *seed)
        .map_err(|_| invalid("invalid reader signing seed"))?;
    if Base64UrlUnpadded::encode_string(&*seed) != seed_text {
        return Err(invalid("non-canonical reader signing seed"));
    }
    let signing_key = SigningKey::from_bytes(&*seed);
    let client = Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?;
    #[cfg(not(unix))]
    return Err(invalid(
        "protected Stripe broker requires Unix peer credentials",
    ));
    #[cfg(unix)]
    {
        if rustix::process::geteuid().as_raw() != configuration.evidence_store().broker_uid() {
            return Err(invalid("protected Stripe broker has the wrong OS identity"));
        }
        let socket_path = configuration.evidence_store().broker_socket_path();
        if std::fs::symlink_metadata(socket_path).is_ok() {
            return Err(invalid("protected Stripe broker socket already exists"));
        }
        let listener = UnixListener::bind(socket_path)
            .map_err(|_| invalid("protected Stripe broker bind failed closed"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
                .map_err(|_| invalid("protected Stripe broker mode failed closed"))?;
        }
        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|_| invalid("protected Stripe broker accept failed closed"))?;
            if stream.peer_cred().map(|value| value.uid()).ok()
                != Some(configuration.evidence_store().agent_uid())
            {
                continue;
            }
            let request_timeout = Duration::from_millis(u64::from(
                configuration
                    .evidence_store()
                    .request_timeout_milliseconds(),
            ));
            let result = tokio::time::timeout(
                request_timeout,
                serve_one(
                    &mut stream,
                    &configuration,
                    &client,
                    credential,
                    &arguments.api_version,
                    &signing_key,
                ),
            )
            .await;
            if !matches!(result, Ok(Ok(()))) {
                let _ = stream.shutdown().await;
            }
        }
    }
}

async fn serve_one(
    stream: &mut UnixStream,
    configuration: &StripeRefundLocalAgentConfigurationV1,
    client: &Client,
    credential: &str,
    api_version: &str,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > 4096 {
        return Err(invalid(
            "protected Stripe broker request exceeded its bound",
        ));
    }
    let mut request_bytes = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut request_bytes).await?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(invalid(
            "protected Stripe broker request has trailing bytes",
        ));
    }
    let request = StripeRefundEvidenceRequestV1::from_canonical_bytes(&request_bytes)?;
    if request.store_identity_sha256() != configuration.evidence_store().store_identity_sha256()
        || request.stripe_api_version() != api_version
        || !configuration
            .exact_configuration()
            .allows_api_version(request.stripe_api_version())
    {
        return Err(invalid("protected Stripe broker request binding mismatch"));
    }
    let payment_intent = request.payment_intent_id()?;
    let snapshot = fetch_snapshot(
        configuration,
        client,
        credential,
        api_version,
        signing_key,
        &request,
        payment_intent,
    )
    .await?;
    let bytes = snapshot.canonical_bytes()?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| invalid("protected Stripe broker response exceeded its bound"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn fetch_snapshot(
    configuration: &StripeRefundLocalAgentConfigurationV1,
    client: &Client,
    credential: &str,
    api_version: &str,
    signing_key: &SigningKey,
    request: &StripeRefundEvidenceRequestV1,
    payment_intent: PaymentIntentId,
) -> Result<ProtectedRefundEvidenceSnapshotV1, Box<dyn Error>> {
    // A pre-entry snapshot is required to be strictly newer than the durable
    // command boundary. With the v1 second-granularity wire, wait before any
    // provider read until the trusted clock has crossed that boundary. The
    // server's total transaction timeout bounds this wait together with all
    // three reads and the response write.
    if let Some(observed_after) = request.observed_after_unix_seconds() {
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if now > observed_after {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let (account, account_bytes): (StripeAccount, Zeroizing<Vec<u8>>) =
        get_json(client, credential, api_version, "/v1/account").await?;
    let account_id = StripeAccountId::parse(account.id)?;
    if !configuration
        .exact_configuration()
        .allows_account(&account_id)
    {
        return Err(invalid(
            "Stripe account is outside the configured test roster",
        ));
    }
    let intent_path = format!("/v1/payment_intents/{payment_intent}");
    let (intent, intent_bytes): (StripePaymentIntent, Zeroizing<Vec<u8>>) =
        get_json(client, credential, api_version, &intent_path).await?;
    if intent.object != "payment_intent" || intent.id != payment_intent.as_str() || intent.livemode
    {
        return Err(invalid("Stripe PaymentIntent identity or mode mismatch"));
    }
    let charge_id = ChargeId::parse(
        intent
            .latest_charge
            .ok_or_else(|| invalid("PaymentIntent has no exact latest Charge"))?,
    )?;
    let charge_path = format!("/v1/charges/{charge_id}");
    let (charge, charge_bytes): (StripeCharge, Zeroizing<Vec<u8>>) =
        get_json(client, credential, api_version, &charge_path).await?;
    if charge.object != "charge"
        || charge.id != charge_id.as_str()
        || charge.payment_intent.as_deref() != Some(payment_intent.as_str())
        || charge.livemode
        || charge.amount != intent.amount
        || charge.currency != intent.currency
    {
        return Err(invalid(
            "Stripe Charge and PaymentIntent do not form one exact target",
        ));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let response_commitment = response_commitment(&[&account_bytes, &intent_bytes, &charge_bytes]);
    let evidence = RefundEvidenceV1::new(RefundEvidenceInput {
        stripe_account_id: account_id,
        stripe_api_version: api_version.into(),
        livemode: charge.livemode,
        charge_id,
        payment_intent_id: Some(payment_intent),
        connect_account_id: None,
        currency: Currency::parse(charge.currency)?,
        charge_amount_minor: charge.amount,
        captured_amount_minor: charge.amount_captured,
        amount_refunded_minor: charge.amount_refunded,
        paid: charge.paid,
        captured: charge.captured,
        charge_refunded: charge.refunded,
        disputed: charge.disputed,
        observed_at: now,
        response_commitment,
    })?;
    let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
        configuration.evidence_store(),
        request.workflow_id(),
        request.phase(),
        request.sealed_command_sha256().cloned(),
        evidence,
        &signing_key,
    )?;
    Ok(snapshot)
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    credential: &str,
    api_version: &str,
    path: &str,
) -> Result<(T, Zeroizing<Vec<u8>>), Box<dyn Error>> {
    let response = client
        .get(format!("{STRIPE_ORIGIN}{path}"))
        .bearer_auth(credential)
        .header("Accept", "application/json")
        .header("Stripe-Version", api_version)
        .send()
        .await
        .map_err(|_| invalid("Stripe runtime-read transport failed closed"))?;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get("Stripe-Version")
            .and_then(|value| value.to_str().ok())
            != Some(api_version)
        || response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_BYTES as u64)
    {
        return Err(invalid("Stripe runtime-read request failed closed"));
    }
    let mut response = response;
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("Stripe runtime-read body failed closed"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_BYTES {
            return Err(invalid("Stripe runtime-read response exceeded its bound"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(invalid("Stripe runtime-read response exceeded its bound"));
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Stripe runtime-read response was invalid"))?;
    Ok((value, bytes))
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut values = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| invalid("missing argument value"))?;
        if !matches!(
            flag.as_str(),
            "--configuration" | "--api-version" | "--credential-file" | "--reader-seed-file"
        ) || values.insert(flag, value).is_some()
        {
            return Err(invalid("unknown or duplicate argument"));
        }
    }
    if values.len() != 4 {
        return Err(invalid("incomplete protected reader arguments"));
    }
    Ok(Arguments {
        configuration: PathBuf::from(take(&mut values, "--configuration")?),
        api_version: take(&mut values, "--api-version")?,
        credential_file: PathBuf::from(take(&mut values, "--credential-file")?),
        reader_seed_file: PathBuf::from(take(&mut values, "--reader-seed-file")?),
    })
}

fn take(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, Box<dyn Error>> {
    values
        .remove(key)
        .ok_or_else(|| invalid("missing argument"))
}

fn one_line_secret(bytes: &[u8]) -> Result<&str, Box<dyn Error>> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(invalid("secret file is not one line"));
    }
    Ok(std::str::from_utf8(bytes)?)
}

#[cfg(unix)]
fn read_stable_regular(
    path: &Path,
    maximum: usize,
    owner_only: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file: File = fd.into();
    let before = file.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || before.nlink() != 1
        || (before.uid() != 0 && before.uid() != uid)
        || owner_only && before.mode() & 0o077 != 0
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(invalid("unsafe protected reader input"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
    std::io::Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || after.len() != bytes.len() as u64
    {
        return Err(invalid("unstable protected reader input"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_stable_regular(
    _path: &Path,
    _maximum: usize,
    _owner_only: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Err(invalid("protected reader requires Unix"))
}

fn response_commitment(parts: &[&[u8]]) -> DigestHex {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-STRIPE-RUNTIME-READ-RESPONSES\0\x01");
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    DigestHex::from_digest_bytes(digest.finalize().into())
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}
