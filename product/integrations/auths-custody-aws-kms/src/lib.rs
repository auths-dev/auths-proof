//! Closed AWS KMS P-256 custody adapter.

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
use p256::{EncodedPoint, pkcs8::DecodePublicKey as _};
use sha2::{Digest as _, Sha256};

const ADAPTER_ID: &str = "aws-kms-p256-v1";
const SUITE_ID: &str = "p256-sha256-v1";

pub struct SecretKeyArn(Box<[u8]>);

impl SecretKeyArn {
    /// Parses one bounded AWS KMS key ARN.
    ///
    /// # Errors
    ///
    /// Returns invalid-key-ARN when the partition, service, region, account,
    /// or key resource shape is invalid.
    pub fn parse(value: String) -> Result<Self, AwsKmsConfigurationError> {
        let parts = value.split(':').collect::<Vec<_>>();
        if value.len() > 2_048
            || parts.len() != 6
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "kms"
            || parts[3].is_empty()
            || parts[4].len() != 12
            || !parts[4].bytes().all(|byte| byte.is_ascii_digit())
            || !parts[5].starts_with("key/")
        {
            return Err(AwsKmsConfigurationError::InvalidKeyArn);
        }
        Ok(Self(value.into_bytes().into_boxed_slice()))
    }

    fn expose(&self) -> Result<&str, CustodyProviderError> {
        std::str::from_utf8(&self.0).map_err(|_| CustodyProviderError::InvalidProviderResponse)
    }
}

impl Drop for SecretKeyArn {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRegion(String);

impl AwsRegion {
    /// Parses one bounded AWS region identifier.
    ///
    /// # Errors
    ///
    /// Returns invalid-region for a non-canonical identifier.
    pub fn parse(value: &str) -> Result<Self, AwsKmsConfigurationError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsKmsConfigurationError::InvalidRegion);
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    /// Parses one twelve-digit AWS account identity.
    ///
    /// # Errors
    ///
    /// Returns invalid-account unless the value is exactly twelve digits.
    pub fn parse(value: &str) -> Result<Self, AwsKmsConfigurationError> {
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsKmsConfigurationError::InvalidAccount);
        }
        Ok(Self(value.to_owned()))
    }
}

pub struct AwsKmsConfiguration {
    key_arn: SecretKeyArn,
    region: AwsRegion,
    account: AwsAccountId,
}

impl AwsKmsConfiguration {
    #[must_use]
    pub const fn new(key_arn: SecretKeyArn, region: AwsRegion, account: AwsAccountId) -> Self {
        Self {
            key_arn,
            region,
            account,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsKmsKeySpec {
    EccNistP256,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsKmsKeyUsage {
    SignVerify,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsKmsSigningAlgorithm {
    EcdsaSha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsKmsMessageType {
    Raw,
}

pub struct AwsKmsKeyDescription {
    pub key_arn: String,
    pub region: String,
    pub account: String,
    pub key_spec: AwsKmsKeySpec,
    pub key_usage: AwsKmsKeyUsage,
    pub enabled: bool,
    pub pending_deletion: bool,
    pub algorithms: Vec<AwsKmsSigningAlgorithm>,
}

pub struct AwsKmsSignOutput {
    pub key_arn: String,
    pub algorithm: AwsKmsSigningAlgorithm,
    pub signature_der: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsKmsFailure {
    AccessDenied,
    Cancelled,
    Throttled,
    Unavailable,
    Disabled,
    PendingDeletion,
    Unknown,
    InvalidResponse,
}

pub trait AwsKmsApi: Send + Sync {
    /// Reads the configured key's policy-relevant attributes.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded description failure.
    fn describe_key(&self, key_arn: &str) -> Result<AwsKmsKeyDescription, AwsKmsFailure>;

    /// Reads the configured key's public verification material.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded public-key failure.
    fn get_public_key(&self, key_arn: &str) -> Result<Vec<u8>, AwsKmsFailure>;

    /// Signs one exact message with the configured KMS key.
    ///
    /// # Errors
    ///
    /// Returns the provider's bounded signing failure.
    fn sign(
        &self,
        key_arn: &str,
        message: &[u8],
        algorithm: AwsKmsSigningAlgorithm,
        message_type: AwsKmsMessageType,
    ) -> Result<AwsKmsSignOutput, AwsKmsFailure>;
}

pub struct AwsKmsP256Adapter<C> {
    client: C,
    key_arn: SecretKeyArn,
    descriptor: CustodyDescriptor,
    verifier: P256SignatureVerifier,
}

impl<C: AwsKmsApi> AwsKmsP256Adapter<C> {
    /// Connects to and validates the configured AWS KMS P-256 key.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when description, public-key parsing, or
    /// key policy validation fails.
    pub fn connect(
        client: C,
        configuration: AwsKmsConfiguration,
    ) -> Result<Self, AwsKmsConfigurationError> {
        let key_arn = configuration
            .key_arn
            .expose()
            .map_err(|_| AwsKmsConfigurationError::ProviderUnavailable)?;
        let description = client
            .describe_key(key_arn)
            .map_err(AwsKmsConfigurationError::Provider)?;
        if description.key_arn != key_arn
            || description.region != configuration.region.0
            || description.account != configuration.account.0
            || description.key_spec != AwsKmsKeySpec::EccNistP256
            || description.key_usage != AwsKmsKeyUsage::SignVerify
            || !description.enabled
            || description.pending_deletion
            || !description
                .algorithms
                .contains(&AwsKmsSigningAlgorithm::EcdsaSha256)
        {
            return Err(AwsKmsConfigurationError::KeyPolicyMismatch);
        }
        let public_key_der = client
            .get_public_key(key_arn)
            .map_err(AwsKmsConfigurationError::Provider)?;
        let key = p256::PublicKey::from_public_key_der(&public_key_der)
            .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?;
        let sec1 = EncodedPoint::from(key).compress();
        let principal = principal(&sec1)?;
        let signature = SignatureDescriptor::new(
            PrincipalMethodId::parse("raw-key-v1")
                .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?,
            VerificationMethod::parse(principal.as_str())
                .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?,
            SignatureSuiteId::parse(SUITE_ID)
                .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?,
        );
        let key_version = key_version(key_arn, &public_key_der)?;
        let descriptor = CustodyDescriptor::new(
            CustodyKind::Kms,
            CustodyAdapterId::parse(ADAPTER_ID)
                .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?,
            principal,
            signature,
            key_version,
            KeyLifecycleState::ActiveCurrent,
        )
        .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?;
        let verifier = P256SignatureVerifier::from_sec1_bytes(sec1.as_bytes())
            .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)?;
        Ok(Self {
            client,
            key_arn: configuration.key_arn,
            descriptor,
            verifier,
        })
    }

    #[must_use]
    pub const fn verifier(&self) -> &P256SignatureVerifier {
        &self.verifier
    }

    #[must_use]
    pub fn readiness(&self) -> AwsKmsReadiness {
        AwsKmsReadiness {
            adapter_id: ADAPTER_ID,
            suite_id: SUITE_ID,
            key_version: self.descriptor.key_version().clone(),
            lifecycle: self.descriptor.lifecycle(),
        }
    }
}

impl<C: AwsKmsApi> ExternalSigner for AwsKmsP256Adapter<C> {
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
        let key_arn = self.key_arn.expose()?;
        let output = self
            .client
            .sign(
                key_arn,
                request.signing_preimage(),
                AwsKmsSigningAlgorithm::EcdsaSha256,
                AwsKmsMessageType::Raw,
            )
            .map_err(provider_error)?;
        if output.key_arn != key_arn || output.algorithm != AwsKmsSigningAlgorithm::EcdsaSha256 {
            return Err(CustodyProviderError::InvalidProviderResponse);
        }
        UntrustedSigningResponse::parse(RawSigningResponse {
            request_id: request.request_id().to_owned(),
            principal: self.descriptor.principal().clone(),
            descriptor: self.descriptor.signature().clone(),
            signature: output.signature_der,
            provider_key_version: self.descriptor.key_version().clone(),
            evidence: Vec::new(),
            transaction_digest: *request.transaction_digest(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsReadiness {
    adapter_id: &'static str,
    suite_id: &'static str,
    key_version: KeyVersionId,
    lifecycle: KeyLifecycleState,
}

impl AwsKmsReadiness {
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
pub enum AwsKmsConfigurationError {
    InvalidKeyArn,
    InvalidRegion,
    InvalidAccount,
    Provider(AwsKmsFailure),
    ProviderUnavailable,
    KeyPolicyMismatch,
    InvalidPublicKey,
}

fn principal(public_key: &EncodedPoint) -> Result<PrincipalId, AwsKmsConfigurationError> {
    let digest: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    PrincipalId::parse(&format!(
        "key:sha256:{}",
        Base64UrlUnpadded::encode_string(&digest)
    ))
    .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)
}

fn key_version(
    key_arn: &str,
    public_key_der: &[u8],
) -> Result<KeyVersionId, AwsKmsConfigurationError> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-AWS-KMS-KEY-VERSION\x00\x01");
    hasher.update(key_arn.as_bytes());
    hasher.update(public_key_der);
    KeyVersionId::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|_| AwsKmsConfigurationError::InvalidPublicKey)
}

const fn provider_error(error: AwsKmsFailure) -> CustodyProviderError {
    match error {
        AwsKmsFailure::AccessDenied => CustodyProviderError::Denied,
        AwsKmsFailure::Cancelled => CustodyProviderError::Cancelled,
        AwsKmsFailure::Throttled => CustodyProviderError::Throttled,
        AwsKmsFailure::Unavailable => CustodyProviderError::Unavailable,
        AwsKmsFailure::Disabled => CustodyProviderError::DisabledKey,
        AwsKmsFailure::PendingDeletion => CustodyProviderError::RevokedKey,
        AwsKmsFailure::Unknown => CustodyProviderError::ProviderUnknown,
        AwsKmsFailure::InvalidResponse => CustodyProviderError::InvalidProviderResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use p256::pkcs8::EncodePublicKey as _;

    struct FakeKms {
        key: SigningKey,
        arn: String,
    }

    impl AwsKmsApi for FakeKms {
        fn describe_key(&self, _key_arn: &str) -> Result<AwsKmsKeyDescription, AwsKmsFailure> {
            Ok(AwsKmsKeyDescription {
                key_arn: self.arn.clone(),
                region: "eu-west-2".to_owned(),
                account: "123456789012".to_owned(),
                key_spec: AwsKmsKeySpec::EccNistP256,
                key_usage: AwsKmsKeyUsage::SignVerify,
                enabled: true,
                pending_deletion: false,
                algorithms: vec![AwsKmsSigningAlgorithm::EcdsaSha256],
            })
        }

        fn get_public_key(&self, _key_arn: &str) -> Result<Vec<u8>, AwsKmsFailure> {
            let encoded = self.key.verifying_key().to_encoded_point(false);
            Ok(p256::PublicKey::from_sec1_bytes(encoded.as_bytes())
                .unwrap()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec())
        }

        fn sign(
            &self,
            _key_arn: &str,
            message: &[u8],
            algorithm: AwsKmsSigningAlgorithm,
            _message_type: AwsKmsMessageType,
        ) -> Result<AwsKmsSignOutput, AwsKmsFailure> {
            let signature: Signature = self.key.sign(message);
            let signature = signature.normalize_s().unwrap_or(signature);
            Ok(AwsKmsSignOutput {
                key_arn: self.arn.clone(),
                algorithm,
                signature_der: signature.to_der().as_bytes().to_vec(),
            })
        }
    }

    #[test]
    fn startup_rejects_account_or_region_substitution() {
        let arn = "arn:aws:kms:eu-west-2:123456789012:key/test".to_owned();
        let client = FakeKms {
            key: SigningKey::from_slice(&[7; 32]).unwrap(),
            arn: arn.clone(),
        };
        let config = AwsKmsConfiguration::new(
            SecretKeyArn::parse(arn).unwrap(),
            AwsRegion::parse("eu-west-1").unwrap(),
            AwsAccountId::parse("123456789012").unwrap(),
        );
        assert!(matches!(
            AwsKmsP256Adapter::connect(client, config),
            Err(AwsKmsConfigurationError::KeyPolicyMismatch)
        ));
    }

    #[test]
    fn readiness_contains_no_arn_account_or_region() {
        let arn = "arn:aws:kms:eu-west-2:123456789012:key/test".to_owned();
        let client = FakeKms {
            key: SigningKey::from_slice(&[7; 32]).unwrap(),
            arn: arn.clone(),
        };
        let config = AwsKmsConfiguration::new(
            SecretKeyArn::parse(arn).unwrap(),
            AwsRegion::parse("eu-west-2").unwrap(),
            AwsAccountId::parse("123456789012").unwrap(),
        );
        let adapter = AwsKmsP256Adapter::connect(client, config).unwrap();
        assert_eq!(adapter.readiness().adapter_id(), ADAPTER_ID);
        assert_eq!(adapter.readiness().suite_id(), SUITE_ID);
    }
}
