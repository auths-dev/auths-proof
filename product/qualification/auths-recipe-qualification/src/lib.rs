//! Recipe-scoped provider qualification: the record a protected run produces
//! about one pinned recipe and provider contract, and the release trust
//! artifacts that say who may attest to it.
//!
//! This crate owns the types, canonical schemas, and bounds, and the release
//! verifier. A decoder turns an artifact into a sealed value whose every
//! structural rule already holds. The verifier checks signatures under a
//! pinned trust root once, then derives a deployment's qualification state
//! from those verified inputs, a time, and what earlier inputs revoked. The
//! crate reads no clock and performs no I/O: its caller supplies both.
//!
//! Every artifact is RFC 8785 canonical JSON. A decoder accepts only the
//! canonical bytes, refuses unknown members and unknown enumeration values,
//! and checks its size limit before parsing. Provider meaning never enters:
//! a provider contract is an opaque digest here.

#![forbid(unsafe_code)]

mod canonical;
mod error;
mod ids;
mod model;
mod release;
mod verify;

#[cfg(test)]
mod vectors;

pub use canonical::{Artifact, Canonical};
pub use error::QualificationFormatError;
pub use ids::{
    BoundedText, GitCommit, InvalidIdentifier, PublicKeyB64, QualificationId, QualificationRootId,
    QualificationSignerId, RecipeFamilyId, Sha256Digest, SignatureB64,
};
pub use model::{
    CapabilityKind, CapabilityResult, ContractDeclarations, EvidenceMember, EvidenceMemberKind,
    EvidenceResult, ExercisedCapability, InstalledPackage, LifecycleStoreKind, LiveEffects,
    MAX_INSTALLED_PACKAGES, MAX_MANUAL_ASSUMPTIONS, MAX_PROVIDER_CONTRACT_BYTES,
    MAX_PROVIDER_RESOURCES, MAX_QUALIFICATION_SECONDS, MAX_RECORD_BYTES, MAX_RECORD_STATEMENTS,
    PROVIDER_CONTRACT_SCHEMA, Provenance, ProviderContract, ProviderContractBody,
    ProviderContractId, ProviderEnvironmentClass, QUALIFICATION_RECORD_SCHEMA, QualificationTarget,
    QualificationTuple, RecipeQualificationRecord, RecipeQualificationState, RecordBody,
    TargetArch, TargetOs,
};
pub use release::{
    ATTESTATION_SCHEMA, AttestationBody, AttestationStatement, MAX_ATTESTATION_BYTES,
    MAX_INDEX_ENTRIES, MAX_RELEASE_INDEX_BYTES, MAX_REVOCATION_LIST_BYTES, MAX_REVOCATION_SECONDS,
    MAX_REVOKED_QUALIFICATIONS, MAX_REVOKED_SIGNERS, MAX_SIGNER_CERTIFICATE_BYTES,
    MAX_SIGNER_SECONDS, MAX_TRUST_ROOT_BYTES, QualificationArtifactKind, QualificationReleaseIndex,
    QualificationRevocationList, QualificationSignatureSuite, QualificationSignerCertificate,
    QualificationSignerKind, QualificationTrustRoot, RELEASE_INDEX_SCHEMA, REVOCATION_LIST_SCHEMA,
    RecipeQualificationAttestation, ReleaseIndexBody, ReleaseIndexEntry, ReleaseIndexStatement,
    RevocationListBody, RevocationListStatement, SIGNER_CERTIFICATE_SCHEMA, SignerCertificateBody,
    SignerCertificateStatement, TRUST_ROOT_SCHEMA, TrustRootBody,
};
pub use verify::{
    QualificationInputs, QualificationRefusal, QualificationVerdict, VerifiedQualifications,
    VerifierState,
};
