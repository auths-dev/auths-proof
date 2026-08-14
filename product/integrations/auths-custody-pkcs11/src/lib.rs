//! Closed PKCS#11 P-256 custody adapter.

#![forbid(unsafe_code)]

use auths_custody::{
    CustodyAdapterId, CustodyDescriptor, CustodyKind, CustodyProviderError, ExternalSigner,
    KeyLifecycleState, KeyVersionId, P256SignatureVerifier, RawSigningResponse, SigningIntent,
    UntrustedSigningResponse,
};
use auths_model::{
    PrincipalId, PrincipalMethodId, SignatureDescriptor, SignatureSuiteId, VerificationMethod,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
use std::{path::PathBuf, time::Duration};

const ADAPTER_ID: &str = "pkcs11-p256-v1";
const SUITE_ID: &str = "p256-sha256-v1";

pub struct SecretPin(Box<[u8]>);

impl SecretPin {
    /// Parses a bounded PKCS#11 PIN secret.
    ///
    /// # Errors
    ///
    /// Returns invalid-secret for an empty or oversized value.
    pub fn parse(value: Vec<u8>) -> Result<Self, Pkcs11ConfigurationError> {
        if value.is_empty() || value.len() > 1_024 {
            return Err(Pkcs11ConfigurationError::InvalidSecret);
        }
        Ok(Self(value.into_boxed_slice()))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretPin {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub trait Pkcs11SecretProvider: Send + Sync {
    /// Acquires the PIN for one bounded provider operation.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded acquisition failure.
    fn acquire(&self) -> Result<SecretPin, Pkcs11Failure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs11TokenId(String);

impl Pkcs11TokenId {
    /// Parses a bounded token identity.
    ///
    /// # Errors
    ///
    /// Returns invalid-token for a non-canonical identifier.
    pub fn parse(value: &str) -> Result<Self, Pkcs11ConfigurationError> {
        if !valid_identifier(value) {
            return Err(Pkcs11ConfigurationError::InvalidToken);
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs11ObjectId(Vec<u8>);

impl Pkcs11ObjectId {
    /// Parses a bounded object identity.
    ///
    /// # Errors
    ///
    /// Returns invalid-object for an empty or oversized value.
    pub fn parse(value: Vec<u8>) -> Result<Self, Pkcs11ConfigurationError> {
        if value.is_empty() || value.len() > 128 {
            return Err(Pkcs11ConfigurationError::InvalidObject);
        }
        Ok(Self(value))
    }
}

pub struct Pkcs11Configuration {
    module: PathBuf,
    token: Pkcs11TokenId,
    object: Pkcs11ObjectId,
    session_limit: usize,
    operation_timeout: Duration,
}

impl Pkcs11Configuration {
    /// Creates one bounded PKCS#11 adapter configuration.
    ///
    /// # Errors
    ///
    /// Returns invalid-bounds for a relative module path or unsupported
    /// session and timeout limits.
    pub fn new(
        module: PathBuf,
        token: Pkcs11TokenId,
        object: Pkcs11ObjectId,
        session_limit: usize,
        operation_timeout: Duration,
    ) -> Result<Self, Pkcs11ConfigurationError> {
        if !module.is_absolute()
            || session_limit == 0
            || session_limit > 64
            || operation_timeout.is_zero()
            || operation_timeout > Duration::from_secs(30)
        {
            return Err(Pkcs11ConfigurationError::InvalidBounds);
        }
        Ok(Self {
            module,
            token,
            object,
            session_limit,
            operation_timeout,
        })
    }
}

pub struct Pkcs11Selector<'a> {
    pub module: &'a std::path::Path,
    pub token: &'a str,
    pub object: &'a [u8],
    pub session_limit: usize,
    pub operation_timeout: Duration,
}

pub struct Pkcs11KeyDescription {
    pub public_key_sec1: Vec<u8>,
    pub p256: bool,
    pub sign: bool,
    pub enabled: bool,
}

pub struct Pkcs11SignOutput {
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pkcs11Failure {
    AccessDenied,
    Cancelled,
    Throttled,
    Unavailable,
    Disabled,
    Revoked,
    TokenRemoved,
    SessionLost,
    WrongPin,
    WrongObject,
    Unknown,
    InvalidResponse,
}

pub trait Pkcs11Api: Send + Sync {
    /// Reads the selected public-key attributes.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded inspection failure.
    fn inspect(
        &self,
        selector: &Pkcs11Selector<'_>,
        pin: &SecretPin,
    ) -> Result<Pkcs11KeyDescription, Pkcs11Failure>;

    /// Signs one exact message with the selected P-256 object.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded signing failure.
    fn sign_sha256(
        &self,
        selector: &Pkcs11Selector<'_>,
        pin: &SecretPin,
        message: &[u8],
    ) -> Result<Pkcs11SignOutput, Pkcs11Failure>;
}

pub struct Pkcs11P256Adapter<C, S> {
    client: C,
    secrets: S,
    configuration: Pkcs11Configuration,
    descriptor: CustodyDescriptor,
    verifier: P256SignatureVerifier,
}

impl<C: Pkcs11Api, S: Pkcs11SecretProvider> Pkcs11P256Adapter<C, S> {
    /// Connects to and validates the configured P-256 signing object.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when secret acquisition, inspection,
    /// public-key parsing, or key policy validation fails.
    pub fn connect(
        client: C,
        secrets: S,
        configuration: Pkcs11Configuration,
    ) -> Result<Self, Pkcs11ConfigurationError> {
        let pin = secrets
            .acquire()
            .map_err(Pkcs11ConfigurationError::Provider)?;
        let selector = selector(&configuration);
        let description = client
            .inspect(&selector, &pin)
            .map_err(Pkcs11ConfigurationError::Provider)?;
        if !description.p256 || !description.sign || !description.enabled {
            return Err(Pkcs11ConfigurationError::KeyPolicyMismatch);
        }
        let verifier = P256SignatureVerifier::from_sec1_bytes(&description.public_key_sec1)
            .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?;
        let principal = principal(&description.public_key_sec1)?;
        let signature = SignatureDescriptor::new(
            PrincipalMethodId::parse("raw-key-v1")
                .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?,
            VerificationMethod::parse(principal.as_str())
                .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?,
            SignatureSuiteId::parse(SUITE_ID)
                .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?,
        );
        let key_version = key_version(&configuration, &description.public_key_sec1)?;
        let descriptor = CustodyDescriptor::new(
            CustodyKind::Pkcs11,
            CustodyAdapterId::parse(ADAPTER_ID)
                .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?,
            principal,
            signature,
            key_version,
            KeyLifecycleState::ActiveCurrent,
        )
        .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)?;
        Ok(Self {
            client,
            secrets,
            configuration,
            descriptor,
            verifier,
        })
    }

    #[must_use]
    pub const fn verifier(&self) -> &P256SignatureVerifier {
        &self.verifier
    }

    #[must_use]
    pub fn readiness(&self) -> Pkcs11Readiness {
        Pkcs11Readiness {
            adapter_id: ADAPTER_ID,
            suite_id: SUITE_ID,
            key_version: self.descriptor.key_version().clone(),
            lifecycle: self.descriptor.lifecycle(),
        }
    }
}

impl<C: Pkcs11Api, S: Pkcs11SecretProvider> ExternalSigner for Pkcs11P256Adapter<C, S> {
    fn descriptor(&self) -> &CustodyDescriptor {
        &self.descriptor
    }

    fn sign(
        &self,
        request: &SigningIntent<'_>,
    ) -> Result<UntrustedSigningResponse, CustodyProviderError> {
        if request.descriptor() != &self.descriptor {
            return Err(CustodyProviderError::Denied);
        }
        let pin = self.secrets.acquire().map_err(provider_error)?;
        let output = self
            .client
            .sign_sha256(
                &selector(&self.configuration),
                &pin,
                request.signing_preimage(),
            )
            .map_err(provider_error)?;
        UntrustedSigningResponse::parse(RawSigningResponse {
            request_id: request.request_id().to_owned(),
            principal: self.descriptor.principal().clone(),
            descriptor: self.descriptor.signature().clone(),
            signature: output.signature,
            provider_key_version: self.descriptor.key_version().clone(),
            evidence: Vec::new(),
            transaction_digest: *request.transaction_digest(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs11Readiness {
    adapter_id: &'static str,
    suite_id: &'static str,
    key_version: KeyVersionId,
    lifecycle: KeyLifecycleState,
}

impl Pkcs11Readiness {
    #[must_use]
    pub const fn adapter_id(&self) -> &'static str {
        self.adapter_id
    }

    #[must_use]
    pub const fn suite_id(&self) -> &'static str {
        self.suite_id
    }

    #[must_use]
    pub const fn key_version(&self) -> &KeyVersionId {
        &self.key_version
    }

    #[must_use]
    pub const fn lifecycle(&self) -> KeyLifecycleState {
        self.lifecycle
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pkcs11ConfigurationError {
    InvalidSecret,
    InvalidToken,
    InvalidObject,
    InvalidBounds,
    Provider(Pkcs11Failure),
    KeyPolicyMismatch,
    InvalidPublicKey,
}

fn selector(configuration: &Pkcs11Configuration) -> Pkcs11Selector<'_> {
    Pkcs11Selector {
        module: &configuration.module,
        token: &configuration.token.0,
        object: &configuration.object.0,
        session_limit: configuration.session_limit,
        operation_timeout: configuration.operation_timeout,
    }
}

fn principal(public_key: &[u8]) -> Result<PrincipalId, Pkcs11ConfigurationError> {
    let digest: [u8; 32] = Sha256::digest(public_key).into();
    PrincipalId::parse(&format!(
        "key:sha256:{}",
        Base64UrlUnpadded::encode_string(&digest)
    ))
    .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)
}

fn key_version(
    configuration: &Pkcs11Configuration,
    public_key: &[u8],
) -> Result<KeyVersionId, Pkcs11ConfigurationError> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-PKCS11-KEY-VERSION\x00\x01");
    hasher.update(configuration.token.0.as_bytes());
    hasher.update(&configuration.object.0);
    hasher.update(public_key);
    KeyVersionId::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|_| Pkcs11ConfigurationError::InvalidPublicKey)
}

const fn provider_error(error: Pkcs11Failure) -> CustodyProviderError {
    match error {
        Pkcs11Failure::AccessDenied | Pkcs11Failure::WrongPin | Pkcs11Failure::WrongObject => {
            CustodyProviderError::Denied
        }
        Pkcs11Failure::Cancelled => CustodyProviderError::Cancelled,
        Pkcs11Failure::Throttled => CustodyProviderError::Throttled,
        Pkcs11Failure::Unavailable | Pkcs11Failure::TokenRemoved | Pkcs11Failure::SessionLost => {
            CustodyProviderError::Unavailable
        }
        Pkcs11Failure::Disabled => CustodyProviderError::DisabledKey,
        Pkcs11Failure::Revoked => CustodyProviderError::RevokedKey,
        Pkcs11Failure::Unknown => CustodyProviderError::ProviderUnknown,
        Pkcs11Failure::InvalidResponse => CustodyProviderError::InvalidProviderResponse,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

    struct FixedSecret;

    impl Pkcs11SecretProvider for FixedSecret {
        fn acquire(&self) -> Result<SecretPin, Pkcs11Failure> {
            SecretPin::parse(b"test-pin".to_vec()).map_err(|_| Pkcs11Failure::WrongPin)
        }
    }

    struct FakeToken {
        key: SigningKey,
    }

    impl Pkcs11Api for FakeToken {
        fn inspect(
            &self,
            _selector: &Pkcs11Selector<'_>,
            _pin: &SecretPin,
        ) -> Result<Pkcs11KeyDescription, Pkcs11Failure> {
            Ok(Pkcs11KeyDescription {
                public_key_sec1: self
                    .key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                p256: true,
                sign: true,
                enabled: true,
            })
        }

        fn sign_sha256(
            &self,
            _selector: &Pkcs11Selector<'_>,
            _pin: &SecretPin,
            message: &[u8],
        ) -> Result<Pkcs11SignOutput, Pkcs11Failure> {
            let signature: Signature = self.key.sign(message);
            let signature = signature.normalize_s().unwrap_or(signature);
            Ok(Pkcs11SignOutput {
                signature: signature.to_bytes().to_vec(),
            })
        }
    }

    fn configuration() -> Pkcs11Configuration {
        Pkcs11Configuration::new(
            PathBuf::from("/opt/softhsm/lib/softhsm2.so"),
            Pkcs11TokenId::parse("auths-ci").unwrap(),
            Pkcs11ObjectId::parse(vec![1, 2, 3]).unwrap(),
            4,
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[test]
    fn startup_freezes_public_descriptor_and_safe_readiness() {
        let adapter = Pkcs11P256Adapter::connect(
            FakeToken {
                key: SigningKey::from_slice(&[9; 32]).unwrap(),
            },
            FixedSecret,
            configuration(),
        )
        .unwrap();
        assert_eq!(adapter.readiness().adapter_id(), ADAPTER_ID);
        assert_eq!(adapter.readiness().suite_id(), SUITE_ID);
        assert_eq!(
            adapter.readiness().lifecycle(),
            KeyLifecycleState::ActiveCurrent
        );
    }

    #[test]
    fn configuration_rejects_unbounded_sessions() {
        assert!(matches!(
            Pkcs11Configuration::new(
                PathBuf::from("/opt/lib.so"),
                Pkcs11TokenId::parse("token").unwrap(),
                Pkcs11ObjectId::parse(vec![1]).unwrap(),
                65,
                Duration::from_secs(2),
            ),
            Err(Pkcs11ConfigurationError::InvalidBounds)
        ));
    }
}
