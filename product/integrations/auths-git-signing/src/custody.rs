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
use std::path::{Path, PathBuf};
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
    /// Publication may have succeeded, but its durable acknowledgement failed.
    /// Load the complete key at the requested path; never replace its identity.
    #[error("key publication is unconfirmed; load the existing key before retrying: {0}")]
    PublicationUncertain(String),
    /// A `did:key` identifier could not be derived.
    #[error("could not derive the did:key identity")]
    Identity,
}

/// Observation boundaries of the single creation owner, used for interruption
/// evidence without placing process-global fault controls on the public API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyPublicationPoint {
    StagingCreated,
    SeedWritten,
    ContentsSynchronized,
    Published,
    StagingRemoved,
    ParentSynchronized,
    Acknowledged,
}

/// Owns only an unpublished sibling name. Dropping this owner must never unlink
/// the installed pathname, including after an uncertain publication result.
struct StagedSoftwareKey {
    path: PathBuf,
    file: fs::File,
}

impl StagedSoftwareKey {
    fn create(parent: &Path) -> Result<Self, CustodyError> {
        let mut identifier = [0_u8; 16];
        getrandom::fill(&mut identifier)
            .map_err(|error| CustodyError::Create(error.to_string()))?;
        let path = parent.join(format!(".auths-key-staging-{}", hex::encode(identifier)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|error| CustodyError::Create(error.to_string()))?;
        Ok(Self { path, file })
    }
}

impl Drop for StagedSoftwareKey {
    fn drop(&mut self) {
        // An interrupted pre-publication operation may require manual removal
        // of this private file. Cleanup never changes a published identity.
        let _ = fs::remove_file(&self.path);
    }
}

impl SoftwareKey {
    /// Publishes a complete new key at `path` with mode 0600.
    ///
    /// A private sibling owns staging until its contents are synchronized.
    /// Exclusive publication never replaces another identity. The parent
    /// directory is synchronized before success is acknowledged. A terminated
    /// creator may leave a private staging file, which is never loaded as a key.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyError::Exists`] rather than overwrite a key, and
    /// [`CustodyError::Create`] before publication. After publication may have
    /// succeeded, [`CustodyError::PublicationUncertain`] requires loading and
    /// verifying that exact installed key instead of creating a replacement.
    pub fn generate(path: &Path) -> Result<Self, CustodyError> {
        Self::generate_observed(path, |_| Ok(()))
    }

    fn generate_observed(
        path: &Path,
        mut observe: impl FnMut(KeyPublicationPoint) -> std::io::Result<()>,
    ) -> Result<Self, CustodyError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|error| CustodyError::Create(error.to_string()))?;
        let key = Self::from_seed(&seed)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staging = StagedSoftwareKey::create(parent)?;
        let before_publication = |error: std::io::Error| CustodyError::Create(error.to_string());
        observe(KeyPublicationPoint::StagingCreated).map_err(before_publication)?;
        staging
            .file
            .write_all(seed.as_ref())
            .map_err(before_publication)?;
        observe(KeyPublicationPoint::SeedWritten).map_err(before_publication)?;
        staging.file.sync_all().map_err(before_publication)?;
        observe(KeyPublicationPoint::ContentsSynchronized).map_err(before_publication)?;
        // A hard link is an atomic no-replacement publication on the same
        // filesystem. The installed pathname can only name the complete seed.
        fs::hard_link(&staging.path, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                CustodyError::Exists
            } else {
                // Conservatively include a lost filesystem acknowledgement.
                CustodyError::PublicationUncertain(error.to_string())
            }
        })?;
        let after_publication =
            |error: std::io::Error| CustodyError::PublicationUncertain(error.to_string());
        observe(KeyPublicationPoint::Published).map_err(after_publication)?;
        fs::remove_file(&staging.path).map_err(after_publication)?;
        observe(KeyPublicationPoint::StagingRemoved).map_err(after_publication)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(after_publication)?;
        observe(KeyPublicationPoint::ParentSynchronized).map_err(after_publication)?;
        observe(KeyPublicationPoint::Acknowledged).map_err(after_publication)?;
        Ok(key)
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
    use std::io::{BufRead as _, Read as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;

    const PUBLICATION_POINTS: &[KeyPublicationPoint] = &[
        KeyPublicationPoint::StagingCreated,
        KeyPublicationPoint::SeedWritten,
        KeyPublicationPoint::ContentsSynchronized,
        KeyPublicationPoint::Published,
        KeyPublicationPoint::StagingRemoved,
        KeyPublicationPoint::ParentSynchronized,
        KeyPublicationPoint::Acknowledged,
    ];

    fn published(point: KeyPublicationPoint) -> bool {
        matches!(
            point,
            KeyPublicationPoint::Published
                | KeyPublicationPoint::StagingRemoved
                | KeyPublicationPoint::ParentSynchronized
                | KeyPublicationPoint::Acknowledged
        )
    }

    #[test]
    fn software_key_publication_faults_never_expose_partial_or_replace_existing_keys() {
        for &point in PUBLICATION_POINTS {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("agent.seed");
            let result = SoftwareKey::generate_observed(&path, |current| {
                for entry in fs::read_dir(directory.path())? {
                    assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
                }
                if published(current) {
                    SoftwareKey::load(&path).expect("published keys are complete");
                } else {
                    assert!(!path.exists(), "staging is not an installed identity");
                }
                if current == point {
                    Err(std::io::Error::other("injected publication failure"))
                } else {
                    Ok(())
                }
            });
            if published(point) {
                assert!(matches!(result, Err(CustodyError::PublicationUncertain(_))));
                let identity = SoftwareKey::load(&path)
                    .expect("load uncertain publication")
                    .principal();
                assert!(matches!(
                    SoftwareKey::generate(&path),
                    Err(CustodyError::Exists)
                ));
                assert_eq!(
                    SoftwareKey::load(&path).expect("same key").principal(),
                    identity
                );
            } else {
                assert!(matches!(result, Err(CustodyError::Create(_))));
                assert!(!path.exists());
                SoftwareKey::generate(&path).expect("safe fresh creation before publication");
            }
            assert_eq!(fs::read_dir(directory.path()).expect("entries").count(), 1);
        }
    }

    #[test]
    fn competing_software_key_creators_publish_exactly_one_complete_identity() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("agent.seed");
        let barrier = Arc::new((Mutex::new(0), Condvar::new()));
        let creators: Vec<_> =
            (0..2)
                .map(|_| {
                    let path = path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        SoftwareKey::generate_observed(&path, |point| {
                if point == KeyPublicationPoint::ContentsSynchronized {
                    assert!(!path.exists());
                    let (arrivals, ready) = &*barrier;
                    let mut arrived = arrivals.lock()
                        .map_err(|_| std::io::Error::other("creator barrier poisoned"))?;
                    *arrived += 1;
                    ready.notify_all();
                    let (_arrived, waited) = ready.wait_timeout_while(
                        arrived, Duration::from_secs(20), |arrived| *arrived < 2,
                    ).map_err(|_| std::io::Error::other("creator barrier poisoned"))?;
                    if waited.timed_out() {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut,
                            "competing creator failed to reach synchronized publication"));
                    }
                }
                Ok(())
            }).map(|key| key.principal())
                    })
                })
                .collect();
        let mut identities = Vec::new();
        let mut conflicts = 0;
        for creator in creators {
            match creator.join().expect("creator") {
                Ok(identity) => identities.push(identity),
                Err(CustodyError::Exists) => conflicts += 1,
                Err(error) => panic!("unexpected creation result: {error}"),
            }
        }
        assert_eq!(conflicts, 1);
        assert_eq!(
            identities,
            vec![SoftwareKey::load(&path).expect("installed key").principal()]
        );
        assert_eq!(fs::read_dir(directory.path()).expect("entries").count(), 1);
    }

    struct InterruptedCreator(Child);

    impl Drop for InterruptedCreator {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn publication_child(path: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "custody::tests::software_key_publication_child",
                "--nocapture",
            ])
            .env("AUTHS_TEST_KEY_PUBLICATION_PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        command
    }

    #[test]
    fn software_key_publication_child() {
        let Some(path) = std::env::var_os("AUTHS_TEST_KEY_PUBLICATION_PATH") else {
            return;
        };
        let path = Path::new(&path);
        if std::env::var_os("AUTHS_TEST_KEY_CALLER_ACKNOWLEDGEMENT").is_some() {
            // This gate is outside generate: the caller has actually received
            // Ok and can acknowledge its installed identity before termination.
            let installed = SoftwareKey::generate(path).expect("caller received success");
            println!(
                "PUBLICATION_ACKNOWLEDGED {}",
                installed.principal().as_str()
            );
            std::io::stdout()
                .flush()
                .expect("acknowledgement delivered");
            std::io::stdin().read_exact(&mut [0]).expect("caller gate");
        } else if let Ok(boundary) = std::env::var("AUTHS_TEST_KEY_PUBLICATION_POINT") {
            SoftwareKey::generate_observed(path, |point| {
                if format!("{point:?}") == boundary {
                    println!("PUBLICATION_BOUNDARY {boundary}");
                    std::io::stdout().flush()?;
                    std::io::stdin().read_exact(&mut [0])?;
                }
                Ok(())
            })
            .expect("child publication");
        } else {
            println!(
                "INSTALLED_PRINCIPAL {}",
                SoftwareKey::load(path)
                    .expect("reopened complete key")
                    .principal()
                    .as_str()
            );
        }
    }

    #[test]
    fn caller_acknowledged_software_key_survives_process_termination_and_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("agent.seed");
        let mut child = InterruptedCreator(
            publication_child(&path)
                .env("AUTHS_TEST_KEY_CALLER_ACKNOWLEDGEMENT", "1")
                .spawn()
                .expect("creator process"),
        );
        let stdout = child.0.stdout.take().expect("stdout");
        let (sent, received) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.expect("child output");
                if let Some(principal) = line.strip_prefix("PUBLICATION_ACKNOWLEDGED ") {
                    let _ = sent.send(principal.to_owned());
                    break;
                }
            }
        });
        let acknowledged = received
            .recv_timeout(Duration::from_secs(20))
            .expect("caller acknowledged successful publication");
        child
            .0
            .kill()
            .expect("terminate after caller observed success");
        child.0.wait().expect("join creator");
        reader.join().expect("acknowledgement reader");
        let reopened = publication_child(&path).output().expect("restart reader");
        assert!(reopened.status.success());
        assert!(
            String::from_utf8(reopened.stdout)
                .expect("reader output")
                .contains(&format!("INSTALLED_PRINCIPAL {acknowledged}"))
        );
        assert_eq!(
            SoftwareKey::load(&path)
                .expect("same acknowledged key")
                .principal()
                .as_str(),
            acknowledged
        );
        assert!(matches!(
            SoftwareKey::generate(&path),
            Err(CustodyError::Exists)
        ));
        assert_eq!(fs::read_dir(directory.path()).expect("entries").count(), 1);
    }

    #[test]
    fn software_key_publication_process_interruption_matrix() {
        for &point in PUBLICATION_POINTS {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("agent.seed");
            let mut child = InterruptedCreator(
                publication_child(&path)
                    .env("AUTHS_TEST_KEY_PUBLICATION_POINT", format!("{point:?}"))
                    .spawn()
                    .expect("creator process"),
            );
            let stdout = child.0.stdout.take().expect("stdout");
            let (sent, received) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    let line = line.expect("child output");
                    if line.starts_with("PUBLICATION_BOUNDARY ") {
                        let _ = sent.send(line);
                        break;
                    }
                }
            });
            received
                .recv_timeout(Duration::from_secs(20))
                .expect("owned publication barrier");
            child.0.kill().expect("terminate at exact boundary");
            child.0.wait().expect("join terminated creator");
            reader.join().expect("reader");
            if published(point) {
                let principal = SoftwareKey::load(&path)
                    .expect("complete published key")
                    .principal();
                let reopened = publication_child(&path).output().expect("restart reader");
                assert!(reopened.status.success());
                assert!(
                    String::from_utf8(reopened.stdout)
                        .expect("output")
                        .contains(&format!("INSTALLED_PRINCIPAL {}", principal.as_str()))
                );
                assert!(matches!(
                    SoftwareKey::generate(&path),
                    Err(CustodyError::Exists)
                ));
                assert_eq!(
                    SoftwareKey::load(&path)
                        .expect("unchanged identity")
                        .principal(),
                    principal
                );
            } else {
                assert!(!path.exists());
                SoftwareKey::generate(&path).expect("restart creates first installed key");
            }
            // SIGKILL can leave private staging files; none becomes the final
            // identity. This is process-interruption, not power-loss evidence.
            for entry in fs::read_dir(directory.path()).expect("entries") {
                assert_eq!(
                    entry
                        .expect("entry")
                        .metadata()
                        .expect("metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

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
        assert!(matches!(
            SoftwareKey::generate(&path),
            Err(CustodyError::Exists)
        ));
        assert_eq!(
            fs::read(&path).expect("malformed identity remains untouched"),
            [0_u8; 31]
        );
    }
}
