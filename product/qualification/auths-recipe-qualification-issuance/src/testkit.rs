//! A synthetic candidate and release hierarchy for tests of anything that
//! reads qualifications. Every key is a constant of this module and
//! protects nothing; no shipped build enables the feature that exposes it.

use crate::{CertificateRequest, QualificationProposal, ReleaseSigner, RootSigner, SigningSeed};
use auths_recipe_qualification::{
    CapabilityKind, QualificationId, QualificationRootId, QualificationSignerId,
    QualificationTrustRoot, QualificationTuple, RELEASE_ATTESTATIONS_DIRECTORY, RELEASE_INDEX_FILE,
    RELEASE_RECORDS_DIRECTORY, RELEASE_REVOCATION_LIST_FILE, RELEASE_SIGNER_CERTIFICATE_FILE,
};
use std::path::Path;
use zeroize::Zeroizing;

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

/// The capabilities the synthetic family does not have.
pub const ABSENT: [CapabilityKind; 2] = crate::stages::PLACEHOLDER_ABSENT;

pub use crate::stages::placeholder_cases as cases;

/// A closed proposal for `tuple` under qualification `index`, valid for 90
/// days from two hours before `now`.
///
/// # Panics
///
/// When the synthetic candidate does not assemble, which is a defect in
/// this crate.
#[must_use]
pub fn proposal(index: u8, tuple: &QualificationTuple, now: u64) -> QualificationProposal {
    crate::stages::synthetic_proposal(index, tuple, now).expect("proposal")
}

fn seed(byte: u8) -> SigningSeed {
    SigningSeed::from_bytes(Zeroizing::new([byte; 32]))
}

/// The bytes of one release, as a release directory holds them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBytes {
    /// The signer certificate.
    pub signer_certificate: Vec<u8>,
    /// The revocation list.
    pub revocation_list: Vec<u8>,
    /// The release index.
    pub release_index: Vec<u8>,
    /// The records.
    pub records: Vec<Vec<u8>>,
    /// The attestations.
    pub attestations: Vec<Vec<u8>>,
}

impl ReleaseBytes {
    /// Writes the release as a release directory at `directory`.
    ///
    /// # Errors
    ///
    /// Returns the first file-system error.
    pub fn write_to(&self, directory: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(directory.join(RELEASE_RECORDS_DIRECTORY))?;
        std::fs::create_dir_all(directory.join(RELEASE_ATTESTATIONS_DIRECTORY))?;
        std::fs::write(
            directory.join(RELEASE_SIGNER_CERTIFICATE_FILE),
            &self.signer_certificate,
        )?;
        std::fs::write(
            directory.join(RELEASE_REVOCATION_LIST_FILE),
            &self.revocation_list,
        )?;
        std::fs::write(directory.join(RELEASE_INDEX_FILE), &self.release_index)?;
        for (name, members) in [
            (RELEASE_RECORDS_DIRECTORY, &self.records),
            (RELEASE_ATTESTATIONS_DIRECTORY, &self.attestations),
        ] {
            for (position, member) in members.iter().enumerate() {
                std::fs::write(
                    directory.join(name).join(format!("{position:04}.json")),
                    member,
                )?;
            }
        }
        Ok(())
    }
}

/// A test release hierarchy: one root and one release signer it certified.
#[derive(Debug)]
pub struct TestRelease {
    root: RootSigner,
    signer: ReleaseSigner,
    now: u64,
}

impl TestRelease {
    /// A hierarchy whose certificate is valid from a day before `now`.
    ///
    /// # Panics
    ///
    /// When the fixed hierarchy cannot be built, which is a defect in this
    /// module.
    #[must_use]
    pub fn new(now: u64) -> Self {
        let root = RootSigner::create(
            &seed(0x61),
            QualificationRootId::parse("test-root").expect("root"),
        )
        .expect("root");
        let certificate = root
            .certify(CertificateRequest {
                signer_id: QualificationSignerId::parse("test-signer").expect("signer"),
                public_key_b64: seed(0x62).public_key(),
                issued_at: now - DAY,
                not_before: now - DAY,
                not_after: now + 180 * DAY,
            })
            .expect("certificate");
        let signer = ReleaseSigner::open(&seed(0x62), certificate).expect("signer");
        Self { root, signer, now }
    }

    /// The trust root a verifier of this hierarchy pins.
    #[must_use]
    pub fn pinned(&self) -> QualificationTrustRoot {
        self.root.trust_root().clone()
    }

    /// Another root with the same identifier and a different key.
    ///
    /// # Panics
    ///
    /// Never for the fixed identifier used here.
    #[must_use]
    pub fn foreign_root() -> QualificationTrustRoot {
        RootSigner::create(
            &seed(0x71),
            QualificationRootId::parse("test-root").expect("root"),
        )
        .expect("root")
        .trust_root()
        .clone()
    }

    /// The revocation list `sequence`, issued an hour before `at` and fresh
    /// for 47 hours after it.
    ///
    /// # Panics
    ///
    /// When `sequence` is zero.
    #[must_use]
    pub fn list(&self, sequence: u64, at: u64, revoked: &[&QualificationId]) -> Vec<u8> {
        self.root
            .revoke(
                sequence,
                at - HOUR,
                at + 47 * HOUR,
                Vec::new(),
                revoked.iter().map(|id| (*id).clone()).collect(),
            )
            .expect("list")
            .canonical_bytes()
            .to_vec()
    }

    /// A release attesting `proposals` from an hour before the hierarchy's
    /// time, with revocation list 1.
    ///
    /// # Panics
    ///
    /// When a proposal's window does not contain the hierarchy's time.
    #[must_use]
    pub fn release(&self, proposals: &[&QualificationProposal]) -> ReleaseBytes {
        let issued = self.now - HOUR;
        let attestations: Vec<_> = proposals
            .iter()
            .map(|proposal| {
                self.signer
                    .attest(proposal, issued, issued, proposal.record().body().not_after)
                    .expect("attestation")
            })
            .collect();
        let listed: Vec<_> = proposals
            .iter()
            .map(|proposal| proposal.record())
            .zip(&attestations)
            .collect();
        let index = self.signer.index(issued, &listed).expect("index");
        ReleaseBytes {
            signer_certificate: self.signer.certificate().canonical_bytes().to_vec(),
            revocation_list: self.list(1, self.now, &[]),
            release_index: index.canonical_bytes().to_vec(),
            records: proposals
                .iter()
                .map(|proposal| proposal.record().canonical_bytes().to_vec())
                .collect(),
            attestations: attestations
                .iter()
                .map(|attestation| attestation.canonical_bytes().to_vec())
                .collect(),
        }
    }
}
