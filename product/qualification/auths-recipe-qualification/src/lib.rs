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
mod closure;
mod error;
mod evidence;
mod ids;
mod model;
mod release;
mod verify;

#[cfg(test)]
mod vectors;

/// The file a release directory keeps its signer certificate in.
pub const RELEASE_SIGNER_CERTIFICATE_FILE: &str = "signer-certificate.json";
/// The file a release directory keeps its revocation list in.
pub const RELEASE_REVOCATION_LIST_FILE: &str = "revocation-list.json";
/// The file a release directory keeps its release index in.
pub const RELEASE_INDEX_FILE: &str = "release-index.json";
/// The directory a release directory keeps its records in, one file per
/// qualification named `<qualification id>.json`.
pub const RELEASE_RECORDS_DIRECTORY: &str = "records";
/// The directory a release directory keeps its attestations in, one file
/// per qualification named `<qualification id>.json`.
pub const RELEASE_ATTESTATIONS_DIRECTORY: &str = "attestations";

pub use canonical::{Artifact, Canonical};
pub use closure::{
    GatewaySemanticClosure, MAX_SEMANTIC_CLOSURE_BYTES, MAX_SEMANTIC_CLOSURE_FILES,
    SEMANTIC_CLOSURE_SCHEMA, SemanticClosureBody, SemanticClosureFile,
};
pub use error::QualificationFormatError;
pub use evidence::{
    ClosureFault, EVIDENCE_SCHEMA, EvidenceBody, EvidenceCase, MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_CASES, QualificationEvidence, Scenario, TUPLE_DIGEST_DOMAIN, WallRow,
    verify_evidence_closure,
};
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
