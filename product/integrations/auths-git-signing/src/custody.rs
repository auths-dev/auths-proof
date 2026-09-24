//! Custody for `did:key` signers.
//!
//! [`SoftwareKey`] is the development path: the Ed25519 seed lives in one
//! file readable only by its owner. Loading refuses a file that group or
//! other can access. The seed never appears in arguments, the environment,
//! output, or Git configuration, and it is zeroized when the key is dropped.
//! Signatures report custody as `software`, so nobody mistakes this for
//! hardware protection.
//!
//! [`CustodyKeySigner`] is the production path for roots: a P-256 key held
//! behind `auths-custody` (KMS or PKCS#11). The private key never enters this
//! process, and grants and revocation records go through the same
//! transaction-bound request and response check as all other custody.

use crate::sign::{GitProofSigner, SignError, local_action, local_grant};
use auths_author::{ExternalSigningRequest, address_evidence};
use auths_custody::{CustodyKey, CustodyPrincipalForm};
use auths_did_key::{DID_KEY_MEDIA_TYPE, DID_KEY_V1, DidKeyEvidence};
use auths_model::{
    ActionEnvelope, EvidenceObject, EvidenceTypeId, GrantStatement, MediaType, PrincipalId,
    PrincipalMethodId, SignatureBytes, SignatureDescriptor, SignatureSuiteId, SignedAction,
    SignedGrant,
};
use auths_multikey::{Multikey, MultikeyType};
use auths_signature::ED25519_V1;
use ed25519_dalek::{Signer as _, SigningKey};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

/// Custody label reported for keys held by this module.
pub const SOFTWARE_CUSTODY: &str = "software";

/// A `did:key` Ed25519 signer whose seed is held in a local file.
pub struct SoftwareKey {
    key: SigningKey,
    evidence: DidKeyEvidence,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    control: EvidenceObject,
}

/// Why a key could not be created or loaded.
#[derive(Debug, Error)]
pub enum CustodyError {
    /// The key file already exists.
    #[error("a key already exists at this label")]
    Exists,
    /// The key file is missing or unreadable.
    #[error("could not read the key file")]
    Unreadable,
    /// The key file is accessible to group or other users.
    #[error("the key file must be readable only by its owner (mode 0600)")]
    Permissions,
    /// The key file does not hold exactly one 32-byte seed.
    #[error("the key file is malformed")]
    Malformed,
    /// Randomness or file creation failed.
    #[error("could not create the key: {0}")]
    Create(String),
    /// A `did:key` identifier could not be derived.
    #[error("could not derive the did:key identity")]
    Identity,
}

impl SoftwareKey {
    /// Generates a new key and writes its seed to `path` with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Exists`] rather than overwrite a key, and
    /// [`CustodyError::Create`] when randomness or the file cannot be created.
    pub fn generate(path: &Path) -> Result<Self, CustodyError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|error| CustodyError::Create(error.to_string()))?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CustodyError::Exists
            } else {
                CustodyError::Create(error.to_string())
            }
        })?;
        file.write_all(seed.as_ref())
            .and_then(|()| file.sync_all())
            .map_err(|error| CustodyError::Create(error.to_string()))?;
        Self::from_seed(&seed)
    }

    /// Loads the key whose seed is stored at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Permissions`] for a file group or other can
    /// access, and [`CustodyError::Malformed`] unless it holds exactly 32
    /// bytes.
    pub fn load(path: &Path) -> Result<Self, CustodyError> {
        let metadata = fs::metadata(path).map_err(|_| CustodyError::Unreadable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(CustodyError::Permissions);
            }
        }
        if metadata.len() != 32 {
            return Err(CustodyError::Malformed);
        }
        let bytes = Zeroizing::new(fs::read(path).map_err(|_| CustodyError::Unreadable)?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| CustodyError::Malformed)?,
        );
        Self::from_seed(&seed)
    }

    fn from_seed(seed: &[u8; 32]) -> Result<Self, CustodyError> {
        let key = SigningKey::from_bytes(seed);
        let evidence = DidKeyEvidence::new(
            Multikey::from_public_key(
                MultikeyType::Ed25519,
                key.verifying_key().to_bytes().to_vec(),
            )
            .map_err(|_| CustodyError::Identity)?,
        );
        let principal = evidence.principal().map_err(|_| CustodyError::Identity)?;
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(DID_KEY_V1).map_err(|_| CustodyError::Identity)?,
            evidence
                .verification_method()
                .map_err(|_| CustodyError::Identity)?,
            SignatureSuiteId::parse(ED25519_V1).map_err(|_| CustodyError::Identity)?,
        );
        let control = address_evidence(
            EvidenceTypeId::parse(DID_KEY_V1).map_err(|_| CustodyError::Identity)?,
            MediaType::parse(DID_KEY_MEDIA_TYPE).map_err(|_| CustodyError::Identity)?,
            evidence.encode().map_err(|_| CustodyError::Identity)?,
        )
        .map_err(|_| CustodyError::Identity)?;
        Ok(Self {
            key,
            evidence,
            principal,
            descriptor,
            control,
        })
    }

    /// Builds a key from a fixed seed so tests reproduce with identical keys.
    #[cfg(test)]
    pub(crate) fn from_test_seed(seed: u8) -> Self {
        Self::from_seed(&[seed; 32]).expect("a fixed seed yields a key")
    }

    /// Returns the `did:key` public evidence.
    #[must_use]
    pub const fn evidence(&self) -> &DidKeyEvidence {
        &self.evidence
    }
}

impl GitProofSigner for SoftwareKey {
    fn principal(&self) -> PrincipalId {
        self.principal.clone()
    }

    fn descriptor(&self) -> SignatureDescriptor {
        self.descriptor.clone()
    }

    fn control_evidence(&self) -> Vec<EvidenceObject> {
        vec![self.control.clone()]
    }

    fn custody(&self) -> &'static str {
        SOFTWARE_CUSTODY
    }

    fn sign_grant(
        &self,
        request: ExternalSigningRequest<GrantStatement>,
    ) -> Result<SignedGrant, SignError> {
        local_grant(request, |preimage| self.sign_preimage(preimage))
    }

    fn sign_action(
        &self,
        request: ExternalSigningRequest<ActionEnvelope>,
    ) -> Result<SignedAction, SignError> {
        local_action(request, |preimage| self.sign_preimage(preimage))
    }
}

impl SoftwareKey {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<SignatureBytes, SignError> {
        SignatureBytes::new(self.key.sign(preimage).to_bytes().to_vec())
            .map_err(|_| SignError::Signer)
    }
}

/// A `did:key` signer whose P-256 key is held behind `auths-custody`.
pub struct CustodyKeySigner {
    key: CustodyKey,
}

impl CustodyKeySigner {
    /// Uses a custody-held key presented as `did:key`, the method Git trust
    /// pins roots under.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Identity`] for a key presented under another
    /// principal method.
    pub fn new(key: CustodyKey) -> Result<Self, CustodyError> {
        if key.identity().form() != CustodyPrincipalForm::DidKeyV1 {
            return Err(CustodyError::Identity);
        }
        Ok(Self { key })
    }
}

impl GitProofSigner for CustodyKeySigner {
    fn principal(&self) -> PrincipalId {
        self.key.identity().principal().clone()
    }

    fn descriptor(&self) -> SignatureDescriptor {
        self.key.identity().signature().clone()
    }

    fn control_evidence(&self) -> Vec<EvidenceObject> {
        vec![self.key.identity().control_evidence().clone()]
    }

    fn custody(&self) -> &'static str {
        self.key.kind().label()
    }

    fn sign_grant(
        &self,
        request: ExternalSigningRequest<GrantStatement>,
    ) -> Result<SignedGrant, SignError> {
        self.key.sign_grant(request).map_err(SignError::Custody)
    }

    fn sign_action(
        &self,
        request: ExternalSigningRequest<ActionEnvelope>,
    ) -> Result<SignedAction, SignError> {
        self.key.sign_action(request).map_err(SignError::Custody)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn software_keys_are_owner_only_and_never_overwritten() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("agent.seed");
        let created = SoftwareKey::generate(&path).expect("generate");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(matches!(
            SoftwareKey::generate(&path),
            Err(CustodyError::Exists)
        ));
        let loaded = SoftwareKey::load(&path).expect("load");
        assert_eq!(loaded.principal(), created.principal());
        assert!(loaded.principal().as_str().starts_with("did:key:z"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            SoftwareKey::load(&path),
            Err(CustodyError::Permissions)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::write(&path, [0_u8; 31]).expect("truncate");
        assert!(matches!(
            SoftwareKey::load(&path),
            Err(CustodyError::Malformed)
        ));
    }
}
