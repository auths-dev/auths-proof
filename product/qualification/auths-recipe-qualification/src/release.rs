//! Release policy: the offline trust root, the signer it authorizes, the
//! revocations it issues, and the attestations and index a signer issues.
//!
//! A trust root signs signer certificates and revocation lists. A release
//! signer signs qualification attestations and the release index, and
//! nothing else: it cannot sign a certificate, a revocation, or a root. Each
//! signature covers the artifact's schema, a NUL byte, and its canonical
//! statement, so a signature made for one kind of artifact never verifies as
//! another.

use crate::canonical::{self, Artifact, Canonical, Sealed};
use crate::model::MAX_QUALIFICATION_SECONDS;
use crate::{
    PublicKeyB64, QualificationFormatError, QualificationId, QualificationRootId,
    QualificationSignerId, Sha256Digest, SignatureB64,
};
use serde::{Deserialize, Serialize};

/// The schema of a qualification trust root.
pub const TRUST_ROOT_SCHEMA: &str = "auths.qualification-trust-root/1";
/// The schema of a signer certificate.
pub const SIGNER_CERTIFICATE_SCHEMA: &str = "auths.qualification-signer-certificate/1";
/// The schema of a revocation list.
pub const REVOCATION_LIST_SCHEMA: &str = "auths.qualification-revocation-list/1";
/// The schema of a release index.
pub const RELEASE_INDEX_SCHEMA: &str = "auths.qualification-release-index/1";
/// The schema of a qualification attestation.
pub const ATTESTATION_SCHEMA: &str = "auths.recipe-qualification-attestation/1";

/// The largest trust root accepted.
pub const MAX_TRUST_ROOT_BYTES: usize = 1024;
/// The largest signer certificate accepted.
pub const MAX_SIGNER_CERTIFICATE_BYTES: usize = 4 * 1024;
/// The largest revocation list accepted.
pub const MAX_REVOCATION_LIST_BYTES: usize = 64 * 1024;
/// The largest release index accepted.
pub const MAX_RELEASE_INDEX_BYTES: usize = 128 * 1024;
/// The largest attestation accepted.
pub const MAX_ATTESTATION_BYTES: usize = 4 * 1024;
/// The most revoked signers a revocation list names.
pub const MAX_REVOKED_SIGNERS: usize = 64;
/// The most revoked qualifications a revocation list names.
pub const MAX_REVOKED_QUALIFICATIONS: usize = 1024;
/// The most entries a release index holds.
pub const MAX_INDEX_ENTRIES: usize = 256;
/// The longest validity window of a signer certificate: 365 days.
pub const MAX_SIGNER_SECONDS: u64 = 365 * 24 * 60 * 60;
/// The longest a revocation list stays fresh: 72 hours.
pub const MAX_REVOCATION_SECONDS: u64 = 72 * 60 * 60;
/// The largest sequence number, the largest integer JSON carries exactly.
const MAX_SEQUENCE: u64 = (1 << 53) - 1;

/// The signature suites a qualification artifact may name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualificationSignatureSuite {
    /// Ed25519 over the artifact's signing preimage.
    #[serde(rename = "ed25519-v1")]
    Ed25519V1,
}

/// How a release signer's private key is held.
///
/// Invariant `honest-custody-label`: launch permits exactly a protected
/// software release key. The label claims neither hardware protection nor
/// non-exportability, and no other kind decodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualificationSignerKind {
    /// A software key injected into the protected release environment after
    /// manual approval and removed when the run ends.
    #[serde(rename = "protected-software-release-key-v1")]
    ProtectedSoftwareReleaseKeyV1,
}

/// The kinds of artifact a release signer may be permitted to sign.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationArtifactKind {
    /// A bounded first-qualification run, never a completed qualification.
    QualificationCommissioningPermit,
    /// The release index.
    QualificationReleaseIndex,
    /// A qualification attestation.
    RecipeQualificationAttestation,
}

/// The body of a qualification trust root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRootBody {
    /// Exactly [`TRUST_ROOT_SCHEMA`].
    pub schema: String,
    /// The root's identifier.
    pub root_id: QualificationRootId,
    /// The suite the root signs with.
    pub signature_suite: QualificationSignatureSuite,
    /// The root's public key.
    pub public_key_b64: PublicKeyB64,
}

impl Sealed for TrustRootBody {}

impl Artifact for TrustRootBody {
    const SCHEMA: &'static str = TRUST_ROOT_SCHEMA;
    const MAX_BYTES: usize = MAX_TRUST_ROOT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        Ok(())
    }
}

/// A decoded qualification trust root.
///
/// Invariant `offline-trust-root`: the value holds an identifier and a
/// public key and nothing else. The release verifier pins it; the matching
/// private key is absent from repositories and from pull-request and
/// qualification runners.
pub type QualificationTrustRoot = Canonical<TrustRootBody>;

/// The statement a trust root signs about one release signer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCertificateStatement {
    /// Exactly [`SIGNER_CERTIFICATE_SCHEMA`].
    pub schema: String,
    /// The signer's identifier.
    pub signer_id: QualificationSignerId,
    /// How the signer's key is held.
    pub signer_kind: QualificationSignerKind,
    /// The suite the signer signs with.
    pub signature_suite: QualificationSignatureSuite,
    /// The signer's public key.
    pub public_key_b64: PublicKeyB64,
    /// When the root issued the certificate.
    pub issued_at: u64,
    /// The start of the validity window.
    pub not_before: u64,
    /// The end of the validity window, at most 365 days after its start.
    pub not_after: u64,
    /// The artifact kinds the signer may sign, sorted and unique.
    pub permitted_artifact_kinds: Vec<QualificationArtifactKind>,
    /// The root that issued the certificate.
    pub root_id: QualificationRootId,
}

/// A signer certificate: the statement and the root's signature over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCertificateBody {
    /// The signed statement.
    pub statement: SignerCertificateStatement,
    /// The root's signature over [`SignerCertificateBody::signing_preimage`].
    pub root_signature_b64: SignatureB64,
}

impl SignerCertificateBody {
    /// The exact bytes the trust root signs.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] when the statement
    /// cannot be canonicalized.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, QualificationFormatError> {
        Ok(canonical::preimage(
            SIGNER_CERTIFICATE_SCHEMA,
            &canonical::canonical_bytes(&self.statement)?,
        ))
    }
}

impl Sealed for SignerCertificateBody {}

impl Artifact for SignerCertificateBody {
    const SCHEMA: &'static str = SIGNER_CERTIFICATE_SCHEMA;
    const MAX_BYTES: usize = MAX_SIGNER_CERTIFICATE_BYTES;

    fn schema(&self) -> &str {
        &self.statement.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        let statement = &self.statement;
        canonical::valid_window(
            statement.issued_at,
            statement.not_before,
            statement.not_after,
            MAX_SIGNER_SECONDS,
        )?;
        if statement.permitted_artifact_kinds.is_empty() {
            return Err(QualificationFormatError::ListBound);
        }
        canonical::strictly_ascending(&statement.permitted_artifact_kinds)
    }
}

/// A decoded signer certificate.
///
/// Invariant `root-authorized-signer`: the value binds one signer
/// identifier, key, kind, validity window of at most 365 days, and permitted
/// artifact kinds under one root identifier, with the root's signature over
/// exactly those members.
pub type QualificationSignerCertificate = Canonical<SignerCertificateBody>;

/// The statement a trust root signs about revocations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationListStatement {
    /// Exactly [`REVOCATION_LIST_SCHEMA`].
    pub schema: String,
    /// The list's sequence number; a later list has a larger one.
    pub sequence: u64,
    /// When the root issued the list.
    pub issued_at: u64,
    /// When the list stops being fresh, at most 72 hours after issue.
    pub next_update: u64,
    /// Revoked signers, sorted and unique.
    pub revoked_signers: Vec<QualificationSignerId>,
    /// Revoked qualifications, sorted and unique.
    pub revoked_qualifications: Vec<QualificationId>,
    /// The root that issued the list.
    pub root_id: QualificationRootId,
}

/// A revocation list: the statement and the root's signature over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationListBody {
    /// The signed statement.
    pub statement: RevocationListStatement,
    /// The root's signature over [`RevocationListBody::signing_preimage`].
    pub root_signature_b64: SignatureB64,
}

impl RevocationListBody {
    /// The exact bytes the trust root signs.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] when the statement
    /// cannot be canonicalized.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, QualificationFormatError> {
        Ok(canonical::preimage(
            REVOCATION_LIST_SCHEMA,
            &canonical::canonical_bytes(&self.statement)?,
        ))
    }
}

impl Sealed for RevocationListBody {}

impl Artifact for RevocationListBody {
    const SCHEMA: &'static str = REVOCATION_LIST_SCHEMA;
    const MAX_BYTES: usize = MAX_REVOCATION_LIST_BYTES;

    fn schema(&self) -> &str {
        &self.statement.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        let statement = &self.statement;
        if statement.sequence == 0 || statement.sequence > MAX_SEQUENCE {
            return Err(QualificationFormatError::Malformed);
        }
        canonical::valid_window(
            statement.issued_at,
            statement.issued_at,
            statement.next_update,
            MAX_REVOCATION_SECONDS,
        )?;
        if statement.revoked_signers.len() > MAX_REVOKED_SIGNERS
            || statement.revoked_qualifications.len() > MAX_REVOKED_QUALIFICATIONS
        {
            return Err(QualificationFormatError::ListBound);
        }
        canonical::strictly_ascending(&statement.revoked_signers)?;
        canonical::strictly_ascending(&statement.revoked_qualifications)
    }
}

/// A decoded revocation list.
///
/// Invariant `root-signed-freshness`: the value carries the root's signature
/// over sorted, unique revoked signers and qualifications with an exact
/// issue time and a next-update time at most 72 hours later. No other input
/// can extend how long it is fresh.
pub type QualificationRevocationList = Canonical<RevocationListBody>;

/// One qualification the release index lists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndexEntry {
    /// The qualification.
    pub qualification_id: QualificationId,
    /// The digest of its record.
    pub record_sha256: Sha256Digest,
    /// The digest of its attestation.
    pub attestation_sha256: Sha256Digest,
}

/// The statement a release signer signs about the qualifications of one
/// release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndexStatement {
    /// Exactly [`RELEASE_INDEX_SCHEMA`].
    pub schema: String,
    /// When the signer issued the index. The index has no freshness of its
    /// own: it is usable only while its signer certificate, the revocation
    /// list, and each referenced attestation are current.
    pub issued_at: u64,
    /// The listed qualifications, sorted by identifier and unique.
    pub entries: Vec<ReleaseIndexEntry>,
    /// The signer that issued the index.
    pub signer_id: QualificationSignerId,
    /// The suite the signature uses.
    pub signature_suite: QualificationSignatureSuite,
}

/// A release index: the statement and the signer's signature over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndexBody {
    /// The signed statement.
    pub statement: ReleaseIndexStatement,
    /// The signer's signature over [`ReleaseIndexBody::signing_preimage`].
    pub signature_b64: SignatureB64,
}

impl ReleaseIndexBody {
    /// The exact bytes the release signer signs.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] when the statement
    /// cannot be canonicalized.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, QualificationFormatError> {
        Ok(canonical::preimage(
            RELEASE_INDEX_SCHEMA,
            &canonical::canonical_bytes(&self.statement)?,
        ))
    }
}

impl Sealed for ReleaseIndexBody {}

impl Artifact for ReleaseIndexBody {
    const SCHEMA: &'static str = RELEASE_INDEX_SCHEMA;
    const MAX_BYTES: usize = MAX_RELEASE_INDEX_BYTES;

    fn schema(&self) -> &str {
        &self.statement.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        let statement = &self.statement;
        if statement.issued_at > canonical::MAX_TIMESTAMP {
            return Err(QualificationFormatError::InvalidTimeWindow);
        }
        if statement.entries.len() > MAX_INDEX_ENTRIES {
            return Err(QualificationFormatError::ListBound);
        }
        let identifiers: Vec<&QualificationId> = statement
            .entries
            .iter()
            .map(|entry| &entry.qualification_id)
            .collect();
        canonical::strictly_ascending(&identifiers)
    }
}

/// A decoded release index.
pub type QualificationReleaseIndex = Canonical<ReleaseIndexBody>;

/// The statement a release signer signs about one qualification record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationStatement {
    /// Exactly [`ATTESTATION_SCHEMA`].
    pub schema: String,
    /// The qualification attested.
    pub qualification_id: QualificationId,
    /// The digest of the canonical record attested.
    pub record_sha256: Sha256Digest,
    /// The signer that issued the attestation.
    pub signer_id: QualificationSignerId,
    /// The suite the signature uses.
    pub signature_suite: QualificationSignatureSuite,
    /// When the signer issued the attestation.
    pub issued_at: u64,
    /// The start of the validity window.
    pub not_before: u64,
    /// The end of the validity window, at most 90 days after its start.
    pub not_after: u64,
}

/// A detached attestation: the statement and the signer's signature over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBody {
    /// The signed statement.
    pub statement: AttestationStatement,
    /// The signer's signature over [`AttestationBody::signing_preimage`].
    pub signature_b64: SignatureB64,
}

impl AttestationBody {
    /// The exact bytes the release signer signs.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] when the statement
    /// cannot be canonicalized.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, QualificationFormatError> {
        Ok(canonical::preimage(
            ATTESTATION_SCHEMA,
            &canonical::canonical_bytes(&self.statement)?,
        ))
    }
}

impl Sealed for AttestationBody {}

impl Artifact for AttestationBody {
    const SCHEMA: &'static str = ATTESTATION_SCHEMA;
    const MAX_BYTES: usize = MAX_ATTESTATION_BYTES;

    fn schema(&self) -> &str {
        &self.statement.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        canonical::valid_window(
            self.statement.issued_at,
            self.statement.not_before,
            self.statement.not_after,
            MAX_QUALIFICATION_SECONDS,
        )
    }
}

/// A decoded qualification attestation.
///
/// Invariant `trusted-expiring-signature`: the value names one record digest,
/// one signer, and a validity window of at most 90 days, with a signature
/// over exactly those members. It becomes a qualification only when the
/// release verifier also finds the record canonical, the signer trusted and
/// permitted, the window current, nothing revoked, and the target equal.
pub type RecipeQualificationAttestation = Canonical<AttestationBody>;
