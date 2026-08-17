//! Strict target V1 application configuration.

#![forbid(unsafe_code)]

mod production;

pub use production::{
    CustodyAdapterFamily, EvidenceRequirement, ProductionCandidate, ProductionCandidateInput,
    ProductionCandidateSummary, ProductionConfigError, ProductionConfigErrorCode,
    ProductionExclusion, ProductionProfileId, ProductionTopologyClass, SdkLanguage,
};

use auths_codec::context_digest;
use auths_model::{
    ChannelBindingId, ContextDigest, Digest, LimitKind, PROTOCOL_V1, ProfileId, ProfileRef,
    RegistryManifestId, TrustedContext, VerifierConfigurationId,
};
use auths_proof_exchange_model::{ChannelBindingPolicy, MAX_BODY_BYTES, MAX_PROOF_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fmt, time::Duration};

const MAX_PROFILES: usize = 64;
const MAX_DID_WEB_HOSTS: usize = 256;

/// Complete non-secret application configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthsConfig {
    protocol: u16,
    profiles: Vec<ProfileConfig>,
    runtime: RuntimeConfig,
    stores: StoreConfig,
    #[serde(default)]
    did_web_allowed_hosts: Vec<String>,
}

impl AuthsConfig {
    /// Parses and validates a complete TOML configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed TOML, unknown fields, unsupported
    /// protocol/profile selections, duplicates, or invalid bounds.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(|_| ConfigError::Malformed)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates all cross-field invariants.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unsupported values, duplicates, or invalid
    /// bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.protocol != PROTOCOL_V1
            || self.profiles.is_empty()
            || self.profiles.len() > MAX_PROFILES
        {
            return Err(ConfigError::UnsupportedProtocolOrProfile);
        }
        let mut profiles = BTreeSet::new();
        for profile in &self.profiles {
            let parsed = profile.profile_ref()?;
            if !known_profile(&parsed) || !profiles.insert(parsed) {
                return Err(ConfigError::UnsupportedProtocolOrProfile);
            }
        }
        self.runtime.validate()?;
        self.stores.validate()?;
        if self.did_web_allowed_hosts.len() > MAX_DID_WEB_HOSTS {
            return Err(ConfigError::InvalidResolverPolicy);
        }
        let mut hosts = BTreeSet::new();
        for host in &self.did_web_allowed_hosts {
            if host.is_empty()
                || host != &host.to_ascii_lowercase()
                || host.bytes().any(|byte| {
                    !(byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'.'))
                })
                || !hosts.insert(host)
            {
                return Err(ConfigError::InvalidResolverPolicy);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn protocol(&self) -> u16 {
        self.protocol
    }

    #[must_use]
    pub fn profiles(&self) -> &[ProfileConfig] {
        &self.profiles
    }

    #[must_use]
    pub const fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    #[must_use]
    pub const fn stores(&self) -> &StoreConfig {
        &self.stores
    }

    #[must_use]
    pub fn did_web_allowed_hosts(&self) -> &[String] {
        &self.did_web_allowed_hosts
    }

    /// Compiles validated declarative values into immutable startup inputs.
    ///
    /// # Errors
    ///
    /// Returns the same closed validation failures as [`Self::validate`].
    pub fn compile(&self) -> Result<CompiledConfig, ConfigError> {
        self.validate()?;
        let mut profiles = self
            .profiles
            .iter()
            .map(ProfileConfig::profile_ref)
            .collect::<Result<Vec<_>, _>>()?;
        profiles.sort();
        let mut digest = Sha256::new();
        digest.update(b"AUTHS-APPS-CONFIG\x00\x01");
        digest.update(self.protocol.to_be_bytes());
        digest.update((profiles.len() as u64).to_be_bytes());
        for profile in &profiles {
            hash_field(&mut digest, profile.id().as_str().as_bytes());
            digest.update(profile.version().to_be_bytes());
        }
        digest.update(self.runtime.challenge_ttl_seconds.to_be_bytes());
        digest.update(self.runtime.max_body_bytes.to_be_bytes());
        digest.update(self.runtime.max_proof_bytes.to_be_bytes());
        hash_field(
            &mut digest,
            self.runtime
                .signed_channel_binding_id()?
                .as_str()
                .as_bytes(),
        );
        digest.update((self.did_web_allowed_hosts.len() as u64).to_be_bytes());
        for host in &self.did_web_allowed_hosts {
            hash_field(&mut digest, host.as_bytes());
        }
        digest.update((self.stores.replay_capacity as u64).to_be_bytes());
        digest.update((self.stores.verification_cache_capacity as u64).to_be_bytes());
        digest.update([match self.stores.receipt_policy {
            ReceiptPolicy::FailClosed => 0,
            ReceiptPolicy::LocalSpool => 1,
        }]);
        Ok(CompiledConfig {
            digest: Digest::new(digest.finalize().into()),
            profiles,
            signed_channel_binding: self.runtime.signed_channel_binding_id()?,
            max_body_bytes: self.runtime.max_body_bytes,
            max_proof_bytes: self.runtime.max_proof_bytes,
        })
    }
}

/// Exact enabled profile.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    id: String,
    version: u16,
}

impl ProfileConfig {
    /// Returns the validated model profile reference.
    ///
    /// # Errors
    ///
    /// Returns an unsupported-profile error for invalid syntax or version.
    pub fn profile_ref(&self) -> Result<ProfileRef, ConfigError> {
        ProfileRef::new(
            ProfileId::parse(&self.id).map_err(|_| ConfigError::UnsupportedProtocolOrProfile)?,
            self.version,
        )
        .map_err(|_| ConfigError::UnsupportedProtocolOrProfile)
    }
}

/// Runtime bounds and channel policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    challenge_ttl_seconds: u64,
    max_body_bytes: u32,
    max_proof_bytes: u32,
    channel_policy: ChannelPolicyConfig,
}

impl RuntimeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.challenge_ttl_seconds == 0
            || self.challenge_ttl_seconds > 300
            || self.max_body_bytes == 0
            || self.max_body_bytes > MAX_BODY_BYTES
            || self.max_proof_bytes == 0
            || self.max_proof_bytes > MAX_PROOF_BYTES
        {
            return Err(ConfigError::InvalidRuntime);
        }
        Ok(())
    }

    #[must_use]
    pub const fn challenge_ttl(&self) -> Duration {
        Duration::from_secs(self.challenge_ttl_seconds)
    }

    #[must_use]
    pub const fn max_body_bytes(&self) -> u32 {
        self.max_body_bytes
    }

    #[must_use]
    pub const fn max_proof_bytes(&self) -> u32 {
        self.max_proof_bytes
    }

    #[must_use]
    pub const fn channel_policy(&self) -> ChannelBindingPolicy {
        match self.channel_policy {
            ChannelPolicyConfig::None => ChannelBindingPolicy::None,
            ChannelPolicyConfig::AuthenticatedPeer => {
                ChannelBindingPolicy::RequireAuthenticatedPeer
            }
            ChannelPolicyConfig::SignedSender => ChannelBindingPolicy::RequireSignedSenderBinding,
            ChannelPolicyConfig::SignedRecipient => {
                ChannelBindingPolicy::RequireSignedRecipientBinding
            }
        }
    }

    fn signed_channel_binding_id(&self) -> Result<ChannelBindingId, ConfigError> {
        let identifier = match self.channel_policy {
            ChannelPolicyConfig::None | ChannelPolicyConfig::AuthenticatedPeer => "none-v1",
            ChannelPolicyConfig::SignedSender => "iroh-sender-v1",
            ChannelPolicyConfig::SignedRecipient => "iroh-recipient-v1",
        };
        ChannelBindingId::parse(identifier).map_err(|_| ConfigError::InvalidRuntime)
    }
}

/// Closed channel-policy configuration values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelPolicyConfig {
    /// Accepts any transport, including unauthenticated ones.
    None,
    /// Requires the transport to supply concrete peer material for the caller
    /// that submitted the action: an Iroh endpoint identifier, a mutual-TLS
    /// certificate digest, or operating-system peer credentials. Observations
    /// that only authenticate the remote *server*, and free-form opaque
    /// assertions, are refused.
    AuthenticatedPeer,
    /// Requires a signed sender channel binding over an Iroh endpoint.
    SignedSender,
    /// Requires a signed recipient channel binding over an Iroh endpoint.
    SignedRecipient,
}

/// Stateful-store capacities and receipt failure policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    replay_capacity: usize,
    verification_cache_capacity: usize,
    receipt_policy: ReceiptPolicy,
}

impl StoreConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.replay_capacity == 0
            || self.replay_capacity > 1_000_000
            || self.verification_cache_capacity > 1_000_000
        {
            return Err(ConfigError::InvalidStores);
        }
        Ok(())
    }

    #[must_use]
    pub const fn replay_capacity(&self) -> usize {
        self.replay_capacity
    }

    #[must_use]
    pub const fn verification_cache_capacity(&self) -> usize {
        self.verification_cache_capacity
    }

    #[must_use]
    pub const fn receipt_policy(&self) -> ReceiptPolicy {
        self.receipt_policy
    }
}

/// Receipt unavailability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptPolicy {
    FailClosed,
    LocalSpool,
}

/// Validated, immutable application configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    digest: Digest,
    profiles: Vec<ProfileRef>,
    signed_channel_binding: ChannelBindingId,
    max_body_bytes: u32,
    max_proof_bytes: u32,
}

impl CompiledConfig {
    /// Returns the deterministic non-secret configuration digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns enabled exact profiles in canonical order.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRef] {
        &self.profiles
    }

    /// Returns the signed channel-binding requirement.
    #[must_use]
    pub const fn signed_channel_binding(&self) -> &ChannelBindingId {
        &self.signed_channel_binding
    }

    /// Binds this configuration to one immutable pure trusted context.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed diagnostic if profile, channel, byte-limit, or
    /// required/executed verifier configuration disagrees with the context.
    pub fn bind_context(
        &self,
        context: &TrustedContext,
        executed_configuration: VerifierConfigurationId,
    ) -> Result<BoundConfiguration, ConfigError> {
        if self
            .profiles
            .iter()
            .any(|profile| !context.accepted_registries().accepts_profile(profile))
            || context.channel_policy() != &self.signed_channel_binding
            || context.limits().get(LimitKind::CanonicalBodyBytes) > self.max_body_bytes as usize
            || context.limits().get(LimitKind::BundleBytes) > self.max_proof_bytes as usize
            || context.configuration() != executed_configuration
        {
            return Err(ConfigError::ContextMismatch);
        }
        Ok(BoundConfiguration {
            config_digest: self.digest,
            context_digest: context_digest(context).map_err(|_| ConfigError::ContextMismatch)?,
            registry_manifest: context.accepted_registries().manifest_id(),
            required_configuration: context.configuration(),
            executed_configuration,
            profiles: self.profiles.clone(),
        })
    }
}

/// Startup-ready binding of configuration, registries, and trusted context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundConfiguration {
    config_digest: Digest,
    context_digest: ContextDigest,
    registry_manifest: RegistryManifestId,
    required_configuration: VerifierConfigurationId,
    executed_configuration: VerifierConfigurationId,
    profiles: Vec<ProfileRef>,
}

impl BoundConfiguration {
    /// Returns the declarative configuration digest.
    #[must_use]
    pub const fn config_digest(&self) -> Digest {
        self.config_digest
    }

    /// Returns the complete pure trusted-context digest.
    #[must_use]
    pub const fn context_digest(&self) -> ContextDigest {
        self.context_digest
    }

    /// Returns the pinned accepted-registry manifest.
    #[must_use]
    pub const fn registry_manifest(&self) -> RegistryManifestId {
        self.registry_manifest
    }

    /// Returns the verifier configuration required by the trusted context.
    #[must_use]
    pub const fn required_configuration(&self) -> VerifierConfigurationId {
        self.required_configuration
    }

    /// Returns the verifier configuration actually installed at startup.
    #[must_use]
    pub const fn executed_configuration(&self) -> VerifierConfigurationId {
        self.executed_configuration
    }

    /// Returns enabled exact application profiles.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRef] {
        &self.profiles
    }
}

fn hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn known_profile(profile: &ProfileRef) -> bool {
    profile.version() == 1
        && matches!(
            profile.id().as_str(),
            "auths.mcp"
                | "auths.http"
                | "auths.git"
                | "auths.deploy"
                | "auths.supply-chain"
                | "auths.edge"
        )
}

/// Configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Malformed,
    UnsupportedProtocolOrProfile,
    InvalidRuntime,
    InvalidStores,
    InvalidResolverPolicy,
    ContextMismatch,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed Auths configuration",
            Self::UnsupportedProtocolOrProfile => "unsupported Auths protocol or profile",
            Self::InvalidRuntime => "invalid Auths runtime configuration",
            Self::InvalidStores => "invalid Auths store configuration",
            Self::InvalidResolverPolicy => "invalid did:web resolver policy",
            Self::ContextMismatch => "configuration and verifier context disagree",
        })
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIGURATION: &str = r#"
protocol = 1
did_web_allowed_hosts = ["identity.example.com"]

[[profiles]]
id = "auths.mcp"
version = 1

[runtime]
challenge_ttl_seconds = 30
max_body_bytes = 1048576
max_proof_bytes = 16777216
channel_policy = "none"

[stores]
replay_capacity = 4096
verification_cache_capacity = 1024
receipt_policy = "fail-closed"
"#;

    #[test]
    fn strict_target_configuration_parses() {
        let config = AuthsConfig::from_toml(CONFIGURATION).unwrap();
        assert_eq!(config.protocol(), 1);
        assert_eq!(config.profiles().len(), 1);
        let compiled = config.compile().unwrap();
        assert_eq!(compiled.profiles().len(), 1);
        assert_eq!(compiled.signed_channel_binding().as_str(), "none-v1");
    }

    #[test]
    fn startup_binding_reports_required_and_executed_configurations() {
        let context = auths_codec::decode_verifier_context(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../core/fixtures/v1/valid/raw-key-chain.context.cbor"
        )))
        .unwrap();
        let compiled = AuthsConfig::from_toml(CONFIGURATION)
            .unwrap()
            .compile()
            .unwrap();
        let required = context.configuration();
        let bound = compiled.bind_context(&context, required).unwrap();
        assert_eq!(bound.required_configuration(), required);
        assert_eq!(bound.executed_configuration(), required);
        assert_eq!(
            bound.registry_manifest(),
            context.accepted_registries().manifest_id()
        );
        assert_eq!(
            compiled.bind_context(&context, VerifierConfigurationId::new([0xa5; 32])),
            Err(ConfigError::ContextMismatch)
        );
    }

    #[test]
    fn duplicate_or_unknown_profiles_fail_closed() {
        let input = r#"
protocol = 1
profiles = [{ id = "auths.mcp", version = 1 }, { id = "auths.mcp", version = 1 }]
[runtime]
challenge_ttl_seconds = 30
max_body_bytes = 1024
max_proof_bytes = 4096
channel_policy = "none"
[stores]
replay_capacity = 1
verification_cache_capacity = 0
receipt_policy = "fail-closed"
"#;
        assert_eq!(
            AuthsConfig::from_toml(input),
            Err(ConfigError::UnsupportedProtocolOrProfile)
        );
    }
}
