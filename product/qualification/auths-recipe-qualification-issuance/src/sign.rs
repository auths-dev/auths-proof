//! The two signing roles. A trust root signs signer certificates and
//! revocation lists. A release signer signs attestations and the release
//! index. Neither type has a method for the other's artifacts.

use crate::{IssuanceError, QualificationProposal};
use auths_recipe_qualification::{
    ATTESTATION_SCHEMA, AttestationBody, AttestationStatement, PublicKeyB64,
    QualificationArtifactKind, QualificationId, QualificationReleaseIndex,
    QualificationRevocationList, QualificationRootId, QualificationSignatureSuite,
    QualificationSignerCertificate, QualificationSignerId, QualificationSignerKind,
    QualificationTrustRoot, RELEASE_INDEX_SCHEMA, REVOCATION_LIST_SCHEMA,
    RecipeQualificationAttestation, RecipeQualificationRecord, ReleaseIndexBody, ReleaseIndexEntry,
    ReleaseIndexStatement, RevocationListBody, RevocationListStatement, SIGNER_CERTIFICATE_SCHEMA,
    SignatureB64, SignerCertificateBody, SignerCertificateStatement, TRUST_ROOT_SCHEMA,
    TrustRootBody,
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::fmt;
use zeroize::Zeroizing;

/// The 32 secret bytes an Ed25519 key is derived from.
///
/// The bytes are zeroized when the value is dropped and are never printed.
pub struct SigningSeed(Zeroizing<[u8; 32]>);

impl SigningSeed {
    /// Wraps seed bytes the caller already holds.
    #[must_use]
    pub const fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Draws a new seed from the operating system.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Randomness`] when the operating system
    /// supplies none.
    pub fn generate() -> Result<Self, IssuanceError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| IssuanceError::Randomness)?;
        Ok(Self(bytes))
    }

    /// The seed bytes, for writing to the one private file that holds them.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// The public key this seed signs under.
    #[must_use]
    pub fn public_key(&self) -> PublicKeyB64 {
        PublicKeyB64::from_bytes(&self.key().verifying_key().to_bytes())
    }

    fn key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for SigningSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningSeed(<redacted>)")
    }
}

fn signature(key: &SigningKey, preimage: &[u8]) -> SignatureB64 {
    SignatureB64::from_bytes(&key.sign(preimage).to_bytes())
}

/// What a trust root is asked to certify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateRequest {
    /// The signer's identifier.
    pub signer_id: QualificationSignerId,
    /// The signer's public key.
    pub public_key_b64: PublicKeyB64,
    /// When the certificate is issued.
    pub issued_at: u64,
    /// The start of the validity window.
    pub not_before: u64,
    /// The end of the validity window.
    pub not_after: u64,
}

/// The offline qualification trust root.
pub struct RootSigner {
    key: SigningKey,
    root: QualificationTrustRoot,
}

impl RootSigner {
    /// Creates a root named `root_id` over `seed`.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Format`] when the trust root cannot be
    /// encoded.
    pub fn create(seed: &SigningSeed, root_id: QualificationRootId) -> Result<Self, IssuanceError> {
        let root = QualificationTrustRoot::from_body(&TrustRootBody {
            schema: TRUST_ROOT_SCHEMA.to_owned(),
            root_id,
            signature_suite: QualificationSignatureSuite::Ed25519V1,
            public_key_b64: seed.public_key(),
        })?;
        Ok(Self {
            key: seed.key(),
            root,
        })
    }

    /// Opens an existing root with its seed.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::KeyMismatch`] when `seed` is not the key
    /// `root` names.
    pub fn open(seed: &SigningSeed, root: QualificationTrustRoot) -> Result<Self, IssuanceError> {
        if seed.public_key() != root.body().public_key_b64 {
            return Err(IssuanceError::KeyMismatch);
        }
        Ok(Self {
            key: seed.key(),
            root,
        })
    }

    /// The public trust root a verifier pins.
    #[must_use]
    pub const fn trust_root(&self) -> &QualificationTrustRoot {
        &self.root
    }

    /// Certifies one release signer for attestations and the release index.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Format`] when the certificate breaks a
    /// structural rule, such as a window longer than 365 days.
    pub fn certify(
        &self,
        request: CertificateRequest,
    ) -> Result<QualificationSignerCertificate, IssuanceError> {
        let mut body = SignerCertificateBody {
            statement: SignerCertificateStatement {
                schema: SIGNER_CERTIFICATE_SCHEMA.to_owned(),
                signer_id: request.signer_id,
                signer_kind: QualificationSignerKind::ProtectedSoftwareReleaseKeyV1,
                signature_suite: QualificationSignatureSuite::Ed25519V1,
                public_key_b64: request.public_key_b64,
                issued_at: request.issued_at,
                not_before: request.not_before,
                not_after: request.not_after,
                permitted_artifact_kinds: vec![
                    QualificationArtifactKind::QualificationReleaseIndex,
                    QualificationArtifactKind::RecipeQualificationAttestation,
                ],
                root_id: self.root.body().root_id.clone(),
            },
            root_signature_b64: SignatureB64::from_bytes(&[0; 64]),
        };
        body.root_signature_b64 = signature(&self.key, &body.signing_preimage()?);
        Ok(QualificationSignerCertificate::from_body(&body)?)
    }

    /// Issues the revocation list with `sequence`, naming every signer and
    /// qualification that is revoked.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Format`] when the list breaks a structural
    /// rule, such as a next update more than 72 hours after issue.
    pub fn revoke(
        &self,
        sequence: u64,
        issued_at: u64,
        next_update: u64,
        mut revoked_signers: Vec<QualificationSignerId>,
        mut revoked_qualifications: Vec<QualificationId>,
    ) -> Result<QualificationRevocationList, IssuanceError> {
        revoked_signers.sort_unstable();
        revoked_signers.dedup();
        revoked_qualifications.sort_unstable();
        revoked_qualifications.dedup();
        let mut body = RevocationListBody {
            statement: RevocationListStatement {
                schema: REVOCATION_LIST_SCHEMA.to_owned(),
                sequence,
                issued_at,
                next_update,
                revoked_signers,
                revoked_qualifications,
                root_id: self.root.body().root_id.clone(),
            },
            root_signature_b64: SignatureB64::from_bytes(&[0; 64]),
        };
        body.root_signature_b64 = signature(&self.key, &body.signing_preimage()?);
        Ok(QualificationRevocationList::from_body(&body)?)
    }
}

impl fmt::Debug for RootSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootSigner")
            .field("root_id", &self.root.body().root_id)
            .finish_non_exhaustive()
    }
}

/// A release signer: the key a certificate names, able to sign attestations
/// and the release index and nothing else.
pub struct ReleaseSigner {
    key: SigningKey,
    certificate: QualificationSignerCertificate,
}

impl ReleaseSigner {
    /// Opens the signer `certificate` names with its seed.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::KeyMismatch`] when `seed` is not the key the
    /// certificate names.
    pub fn open(
        seed: &SigningSeed,
        certificate: QualificationSignerCertificate,
    ) -> Result<Self, IssuanceError> {
        if seed.public_key() != certificate.body().statement.public_key_b64 {
            return Err(IssuanceError::KeyMismatch);
        }
        Ok(Self {
            key: seed.key(),
            certificate,
        })
    }

    /// The certificate this signer signs under.
    #[must_use]
    pub const fn certificate(&self) -> &QualificationSignerCertificate {
        &self.certificate
    }

    fn permitted(&self, kind: QualificationArtifactKind) -> Result<(), IssuanceError> {
        if self
            .certificate
            .body()
            .statement
            .permitted_artifact_kinds
            .contains(&kind)
        {
            Ok(())
        } else {
            Err(IssuanceError::NotPermitted)
        }
    }

    /// Attests the record of a proposal, whose evidence closure the
    /// proposal's construction verified.
    ///
    /// The same call is how a new signer re-signs a still-current record
    /// after a rotation: it needs the evidence, not a provider.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::NotPermitted`] when the certificate does not
    /// permit attestations, [`IssuanceError::Window`] when the window is not
    /// within both the record's and the certificate's or the issue time is
    /// outside the certificate's, and [`IssuanceError::Format`] when the
    /// attestation breaks a structural rule.
    pub fn attest(
        &self,
        proposal: &QualificationProposal,
        issued_at: u64,
        not_before: u64,
        not_after: u64,
    ) -> Result<RecipeQualificationAttestation, IssuanceError> {
        self.permitted(QualificationArtifactKind::RecipeQualificationAttestation)?;
        let certificate = &self.certificate.body().statement;
        let record = proposal.record().body();
        let within = |start: u64, end: u64| not_before >= start && not_after <= end;
        if !within(record.not_before, record.not_after)
            || !within(certificate.not_before, certificate.not_after)
            || issued_at < certificate.not_before
            || issued_at > certificate.not_after
        {
            return Err(IssuanceError::Window);
        }
        let mut body = AttestationBody {
            statement: AttestationStatement {
                schema: ATTESTATION_SCHEMA.to_owned(),
                qualification_id: record.qualification_id.clone(),
                record_sha256: proposal.record().digest(),
                signer_id: certificate.signer_id.clone(),
                signature_suite: QualificationSignatureSuite::Ed25519V1,
                issued_at,
                not_before,
                not_after,
            },
            signature_b64: SignatureB64::from_bytes(&[0; 64]),
        };
        body.signature_b64 = signature(&self.key, &body.signing_preimage()?);
        Ok(RecipeQualificationAttestation::from_body(&body)?)
    }

    /// Signs the release index listing exactly `listed`.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::NotPermitted`] when the certificate does not
    /// permit the index, [`IssuanceError::IndexEntry`] when an attestation
    /// does not name its record or was issued by another signer, and
    /// [`IssuanceError::Format`] when the index breaks a structural rule,
    /// which includes a repeated qualification.
    pub fn index(
        &self,
        issued_at: u64,
        listed: &[(&RecipeQualificationRecord, &RecipeQualificationAttestation)],
    ) -> Result<QualificationReleaseIndex, IssuanceError> {
        self.permitted(QualificationArtifactKind::QualificationReleaseIndex)?;
        let signer_id = &self.certificate.body().statement.signer_id;
        let mut entries = listed
            .iter()
            .map(|(record, attestation)| {
                let statement = &attestation.body().statement;
                if statement.record_sha256 != record.digest()
                    || statement.qualification_id != record.body().qualification_id
                    || statement.signer_id != *signer_id
                {
                    return Err(IssuanceError::IndexEntry);
                }
                Ok(ReleaseIndexEntry {
                    qualification_id: statement.qualification_id.clone(),
                    record_sha256: statement.record_sha256,
                    attestation_sha256: attestation.digest(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| left.qualification_id.cmp(&right.qualification_id));
        let mut body = ReleaseIndexBody {
            statement: ReleaseIndexStatement {
                schema: RELEASE_INDEX_SCHEMA.to_owned(),
                issued_at,
                entries,
                signer_id: signer_id.clone(),
                signature_suite: QualificationSignatureSuite::Ed25519V1,
            },
            signature_b64: SignatureB64::from_bytes(&[0; 64]),
        };
        body.signature_b64 = signature(&self.key, &body.signing_preimage()?);
        Ok(QualificationReleaseIndex::from_body(&body)?)
    }
}

impl fmt::Debug for ReleaseSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseSigner")
            .field("signer_id", &self.certificate.body().statement.signer_id)
            .finish_non_exhaustive()
    }
}
