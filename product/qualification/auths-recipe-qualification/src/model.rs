//! The qualification model: what was qualified, against which contract, on
//! which target, and the evidence that closes the claim.

use crate::canonical::{self, Artifact, Canonical, Sealed};
use crate::{
    BoundedText, GitCommit, QualificationFormatError, QualificationId, RecipeFamilyId, Sha256Digest,
};
use auths_connections::{CredentialStoreKind, ProviderKind};
use serde::{Deserialize, Serialize};

/// The schema of a provider contract.
pub const PROVIDER_CONTRACT_SCHEMA: &str = "auths.provider-contract/1";
/// The schema of a qualification record.
pub const QUALIFICATION_RECORD_SCHEMA: &str = "auths.recipe-qualification/1";
/// The largest provider contract accepted.
pub const MAX_PROVIDER_CONTRACT_BYTES: usize = 16 * 1024;
/// The largest qualification record accepted.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// The most manually reviewed assumptions a provider contract lists.
pub const MAX_MANUAL_ASSUMPTIONS: usize = 32;
/// The most installed packages a record lists.
pub const MAX_INSTALLED_PACKAGES: usize = 8;
/// The most sanitized provider resources a record lists.
pub const MAX_PROVIDER_RESOURCES: usize = 32;
/// The most residual assumptions, and the most excluded claims, a record
/// lists.
pub const MAX_RECORD_STATEMENTS: usize = 32;
/// The longest validity window of a qualification: 90 days.
pub const MAX_QUALIFICATION_SECONDS: u64 = 90 * 24 * 60 * 60;

mod credential_store_kind {
    use auths_connections::CredentialStoreKind;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde passes a field to its serializer by reference"
    )]
    pub(super) fn serialize<S: Serializer>(
        kind: &CredentialStoreKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(kind.as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<CredentialStoreKind, D::Error> {
        let token = String::deserialize(deserializer)?;
        CredentialStoreKind::parse(&token).map_err(D::Error::custom)
    }
}

mod provider_kind {
    use auths_connections::ProviderKind;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(
        kind: &ProviderKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(kind.as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ProviderKind, D::Error> {
        let token = String::deserialize(deserializer)?;
        ProviderKind::parse(token).map_err(D::Error::custom)
    }
}

/// The identifier of one provider contract: the domain-separated digest of
/// its bounded inputs.
///
/// Invariant `pinned-contract`: the only way to compute the value is
/// [`ProviderContract::contract_id`] on a decoded contract. A record or a
/// deployment tuple may also carry one as a claimed digest; such a value is
/// compared for equality and never interpreted. A gateway learns no
/// provider meaning from it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderContractId(Sha256Digest);

impl ProviderContractId {
    /// Returns the digest.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// The class of provider environment a qualification ran against.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderEnvironmentClass {
    /// A mode the provider offers for testing, separate from live data.
    ProviderTestMode,
    /// Disposable resources in a live account created for qualification.
    DisposableLiveResources,
}

/// Digests of the declarations a recipe makes about its provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDeclarations {
    /// The declared idempotency assumptions.
    pub idempotency_sha256: Sha256Digest,
    /// The declared observation assumptions.
    pub observation_sha256: Sha256Digest,
    /// The declared recovery assumptions.
    pub recovery_sha256: Sha256Digest,
    /// The declared retention assumptions.
    pub retention_sha256: Sha256Digest,
}

/// The bounded inputs that define one provider contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContractBody {
    /// Exactly [`PROVIDER_CONTRACT_SCHEMA`].
    pub schema: String,
    /// The provider, as an opaque identifier.
    pub provider: BoundedText<64>,
    /// The provider's API release, as an opaque identifier.
    pub api_release: BoundedText<64>,
    /// The exact `OpenAPI` slice with every resolved member, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi_slice_sha256: Option<Sha256Digest>,
    /// Manually reviewed assumptions an `OpenAPI` document cannot express,
    /// sorted and unique.
    pub manual_assumptions: Vec<BoundedText<256>>,
    /// The class of environment the corpus runs against.
    pub environment_class: ProviderEnvironmentClass,
    /// The corpus manifest.
    pub corpus_manifest_sha256: Sha256Digest,
    /// The version of the pure test oracle.
    pub oracle_version: BoundedText<64>,
    /// The recipe's declared provider assumptions.
    pub declarations: ContractDeclarations,
}

impl Sealed for ProviderContractBody {}

impl Artifact for ProviderContractBody {
    const SCHEMA: &'static str = PROVIDER_CONTRACT_SCHEMA;
    const MAX_BYTES: usize = MAX_PROVIDER_CONTRACT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        if self.manual_assumptions.len() > MAX_MANUAL_ASSUMPTIONS {
            return Err(QualificationFormatError::ListBound);
        }
        canonical::strictly_ascending(&self.manual_assumptions)
    }
}

/// A decoded provider contract.
pub type ProviderContract = Canonical<ProviderContractBody>;

impl Canonical<ProviderContractBody> {
    /// The contract's identifier: SHA-256 of the schema, a NUL byte, and the
    /// canonical contract. Any change to any input changes it.
    #[must_use]
    pub fn contract_id(&self) -> ProviderContractId {
        ProviderContractId(self.digest())
    }
}

/// The operating system of a qualified target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetOs {
    /// Linux.
    Linux,
    /// macOS.
    Macos,
}

/// The architecture of a qualified target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TargetArch {
    /// 64-bit x86.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit ARM.
    #[serde(rename = "aarch64")]
    Aarch64,
}

/// The kind of lifecycle store a qualified target runs on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LifecycleStoreKind {
    /// The multi-host `PostgreSQL` store.
    #[serde(rename = "postgresql-v1")]
    PostgresqlV1,
    /// The development shared-file store.
    #[serde(rename = "shared-file-v1")]
    SharedFileV1,
}

/// The exact deployment target of a qualification.
///
/// Invariant `exact-target`: operating system, architecture, gateway package
/// and build, store kind and schema, and credential-store kind are each one
/// exact value. Nothing is a range, a prefix, or a wildcard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTarget {
    /// The operating system.
    pub os: TargetOs,
    /// The architecture.
    pub arch: TargetArch,
    /// The gateway package name.
    pub gateway_package: BoundedText<64>,
    /// The gateway package version.
    pub gateway_version: BoundedText<64>,
    /// The installed gateway build.
    pub gateway_build_sha256: Sha256Digest,
    /// The lifecycle store kind.
    pub store_kind: LifecycleStoreKind,
    /// The lifecycle store schema.
    pub store_schema: BoundedText<128>,
    /// The provider-secret credential-store kind.
    #[serde(with = "credential_store_kind")]
    pub credential_store_kind: CredentialStoreKind,
}

/// What a qualification belongs to. Changing any member makes an issued
/// qualification stale.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTuple {
    /// The recipe family.
    pub recipe_family: RecipeFamilyId,
    /// The compiled recipe.
    pub compiled_recipe_sha256: Sha256Digest,
    /// The profile lock.
    pub profile_lock_sha256: Sha256Digest,
    /// The provider contract.
    pub provider_contract_id: ProviderContractId,
    /// The gateway semantic closure.
    pub gateway_semantic_closure_sha256: Sha256Digest,
    /// The deployment target.
    pub target: QualificationTarget,
}

/// The qualification state of one recipe.
///
/// Invariant `closed-derived-state`: the state is exactly one of the five
/// values below and is derived only by the release verifier from signed
/// inputs. The type has no parser, so a recipe, a connection, an SDK, a
/// configuration value, or an operator flag cannot supply one.
///
/// An attestation is *usable* when the signed release index lists it and its
/// record, its signature and its signer's certificate verify, it names that
/// record, and its window has started and lies within the record's.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecipeQualificationState {
    /// The signer certificate or release index cannot be used, or the index
    /// lists no closed record for the recipe's family.
    Unqualified,
    /// The index lists a closed record for the family and no usable
    /// attestation exists for it.
    Candidate,
    /// A usable, current, unrevoked attestation covers the exact tuple.
    Qualified,
    /// A usable attestation exists but a tuple member differs, a validity
    /// window has ended, the clock cannot be trusted, or the revocation
    /// list cannot be used or is no longer fresh.
    Stale,
    /// The qualification or the signer of its attestation is revoked.
    Revoked,
}

impl RecipeQualificationState {
    /// Every state.
    pub const ALL: [Self; 5] = [
        Self::Unqualified,
        Self::Candidate,
        Self::Qualified,
        Self::Stale,
        Self::Revoked,
    ];

    /// Returns the canonical token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unqualified => "unqualified",
            Self::Candidate => "candidate",
            Self::Qualified => "qualified",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }

    /// Whether one qualification in this state may next be in `next`, as the
    /// release process issues, expires, and revokes it.
    ///
    /// Revocation is terminal and reaches every state that has evidence: a
    /// revoked qualification never becomes anything else, and a stale one can
    /// still be revoked. A new qualification of the same recipe, with its own
    /// identifier or a new signer's attestation, starts its own lifecycle.
    ///
    /// This is not a constraint on successive values a gateway derives. A
    /// gateway derives the state afresh from its current verified inputs, so
    /// removing an index entry returns a recipe to unqualified.
    #[must_use]
    pub const fn may_become(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Unqualified, Self::Candidate)
                | (
                    Self::Candidate | Self::Stale,
                    Self::Qualified | Self::Revoked
                )
                | (Self::Qualified, Self::Stale | Self::Revoked)
        )
    }

    /// Whether a production connection may lease a credential in this state.
    #[must_use]
    pub const fn permits_lease(self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// One member of the evidence wall.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceMemberKind {
    /// Compiler and interpreter vectors and closed-enumeration hostile cases.
    Conformance,
    /// Agreement of the pure oracle and the gateway on the whole corpus.
    Differential,
    /// Forgery, replay, direct-provider, and credential-isolation attempts.
    Hostile,
    /// Live writes against the provider, each confirmed by read-back.
    Live,
    /// Response loss and delayed visibility under the declared recovery.
    Recovery,
    /// Provider-secret and signer rotation.
    Rotation,
    /// Restart and crash at every stage.
    Restart,
    /// Two gateway instances racing.
    MultiInstance,
    /// Secret and provider-data scans of every emitted artifact.
    Redaction,
    /// The documented journey from an installed consumer package.
    InstalledConsumer,
}

impl EvidenceMemberKind {
    /// Every member, in the order a record lists them.
    pub const ALL: [Self; 10] = [
        Self::Conformance,
        Self::Differential,
        Self::Hostile,
        Self::Live,
        Self::Recovery,
        Self::Rotation,
        Self::Restart,
        Self::MultiInstance,
        Self::Redaction,
        Self::InstalledConsumer,
    ];
}

/// The result of one evidence member. A record exists only when every member
/// passed, so no other value is representable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceResult {
    /// Every case of the member passed on the release candidate.
    Passed,
}

/// One evidence member with its digest and bounded counters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMember {
    /// Which member this is.
    pub member: EvidenceMemberKind,
    /// The member's result.
    pub result: EvidenceResult,
    /// The digest of the member's evidence artifact.
    pub evidence_sha256: Sha256Digest,
    /// The cases the member ran; at least one.
    pub cases: u32,
    /// Provider entries no exact authorized action accounts for; always zero.
    pub unauthorized_provider_entries: u32,
}

/// One declared recipe capability the evidence wall accounts for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// The credential guard.
    CredentialGuard,
    /// The provider version pin.
    VersionPin,
    /// The account binding.
    AccountBinding,
    /// The denied credential reads.
    DeniedReads,
    /// The argument and relative ceilings.
    Ceiling,
    /// The count and sum budgets.
    Budget,
    /// The provider idempotency key.
    Idempotency,
    /// The response locator.
    ResponseLocator,
    /// The echo field.
    Echo,
    /// The read-back observation.
    Observation,
    /// The declared recovery capability.
    Recovery,
    /// Observer signing-key rotation.
    ObserverRotation,
}

impl CapabilityKind {
    /// Every capability, in the order a record lists them.
    pub const ALL: [Self; 12] = [
        Self::CredentialGuard,
        Self::VersionPin,
        Self::AccountBinding,
        Self::DeniedReads,
        Self::Ceiling,
        Self::Budget,
        Self::Idempotency,
        Self::ResponseLocator,
        Self::Echo,
        Self::Observation,
        Self::Recovery,
        Self::ObserverRotation,
    ];
}

/// Whether a capability was exercised.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityResult {
    /// The recipe or target declares the capability and the run exercised it.
    Exercised,
    /// The recipe or target does not declare the capability.
    NotApplicable,
}

/// One capability with its result. A capability is never omitted: one the
/// recipe lacks is listed as not applicable with the reason its decision
/// record fixes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExercisedCapability {
    /// Which capability this is.
    pub capability: CapabilityKind,
    /// Whether it was exercised.
    pub result: CapabilityResult,
    /// Why it does not apply; present exactly when it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<BoundedText<128>>,
}

/// Live provider effects and their read-back confirmations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveEffects {
    /// Authorized writes that entered the provider; at least one.
    pub entered: u32,
    /// Entered writes confirmed by the declared fresh read-back; always
    /// equal to `entered`. A complete HTTP response is not a confirmation.
    pub confirmed_by_read_back: u32,
}

/// Where a qualification was produced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The repository.
    pub repository: BoundedText<128>,
    /// The immutable commit.
    pub commit: GitCommit,
    /// The protected workflow.
    pub workflow: BoundedText<128>,
    /// The protected environment.
    pub environment: BoundedText<64>,
}

/// One installed package the run exercised.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPackage {
    /// The package name.
    pub name: BoundedText<64>,
    /// The package version.
    pub version: BoundedText<64>,
    /// The installed artifact.
    pub sha256: Sha256Digest,
}

/// The body of a qualification record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordBody {
    /// Exactly [`QUALIFICATION_RECORD_SCHEMA`].
    pub schema: String,
    /// The qualification's identifier.
    pub qualification_id: QualificationId,
    /// The existing provider kind the recipe's connection uses.
    #[serde(with = "provider_kind")]
    pub provider_kind: ProviderKind,
    /// What the qualification belongs to.
    pub tuple: QualificationTuple,
    /// The start of the validity window.
    pub not_before: u64,
    /// The end of the validity window, at most 90 days after its start.
    pub not_after: u64,
    /// Where the record was produced.
    pub provenance: Provenance,
    /// The source closure of the release candidate.
    pub source_closure_sha256: Sha256Digest,
    /// The generated artifacts of the release candidate.
    pub generated_artifacts_sha256: Sha256Digest,
    /// The gateway and every exercised SDK client, sorted by name.
    pub installed_packages: Vec<InstalledPackage>,
    /// The recipe family's decision record.
    pub recipe_decision_record_sha256: Sha256Digest,
    /// The corpus manifest.
    pub corpus_manifest_sha256: Sha256Digest,
    /// Every evidence member, in [`EvidenceMemberKind::ALL`] order.
    pub evidence: Vec<EvidenceMember>,
    /// Every capability, in [`CapabilityKind::ALL`] order.
    pub capabilities: Vec<ExercisedCapability>,
    /// Live effects and their confirmations.
    pub live_effects: LiveEffects,
    /// Sanitized identifiers of the disposable provider resources, sorted
    /// and unique.
    pub provider_resources: Vec<BoundedText<96>>,
    /// The provider-secret custody the run used, described without any
    /// location.
    pub custody_descriptor: BoundedText<128>,
    /// The lifecycle store the run used, described without any location.
    pub store_descriptor: BoundedText<128>,
    /// Assumptions the evidence does not remove, sorted and unique.
    pub residual_assumptions: Vec<BoundedText<256>>,
    /// Claims the qualification does not make, sorted and unique.
    pub excluded_claims: Vec<BoundedText<256>>,
}

impl RecordBody {
    fn evidence_closes(&self) -> bool {
        let members_listed = self.evidence.len() == EvidenceMemberKind::ALL.len()
            && self
                .evidence
                .iter()
                .zip(EvidenceMemberKind::ALL)
                .all(|(listed, expected)| listed.member == expected);
        let members_hold = self
            .evidence
            .iter()
            .all(|member| member.cases >= 1 && member.unauthorized_provider_entries == 0);
        let capabilities_listed = self.capabilities.len() == CapabilityKind::ALL.len()
            && self
                .capabilities
                .iter()
                .zip(CapabilityKind::ALL)
                .all(|(listed, expected)| listed.capability == expected);
        let capabilities_hold = self.capabilities.iter().all(|capability| {
            (capability.result == CapabilityResult::NotApplicable) == capability.reason.is_some()
        });
        // A live write counts only when the declared read-back confirmed it,
        // so a record cannot close for a recipe that declares no observation.
        let observation_exercised = self.capabilities.iter().any(|capability| {
            capability.capability == CapabilityKind::Observation
                && capability.result == CapabilityResult::Exercised
        });
        let live_holds = observation_exercised
            && self.live_effects.entered >= 1
            && self.live_effects.confirmed_by_read_back == self.live_effects.entered;
        members_listed && members_hold && capabilities_listed && capabilities_hold && live_holds
    }
}

impl Sealed for RecordBody {}

impl Artifact for RecordBody {
    const SCHEMA: &'static str = QUALIFICATION_RECORD_SCHEMA;
    const MAX_BYTES: usize = MAX_RECORD_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        canonical::valid_window(
            self.not_before,
            self.not_before,
            self.not_after,
            MAX_QUALIFICATION_SECONDS,
        )?;
        if self.installed_packages.is_empty()
            || self.installed_packages.len() > MAX_INSTALLED_PACKAGES
            || self.provider_resources.is_empty()
            || self.provider_resources.len() > MAX_PROVIDER_RESOURCES
            || self.residual_assumptions.len() > MAX_RECORD_STATEMENTS
            || self.excluded_claims.len() > MAX_RECORD_STATEMENTS
        {
            return Err(QualificationFormatError::ListBound);
        }
        let package_names: Vec<&BoundedText<64>> = self
            .installed_packages
            .iter()
            .map(|package| &package.name)
            .collect();
        canonical::strictly_ascending(&package_names)?;
        canonical::strictly_ascending(&self.provider_resources)?;
        canonical::strictly_ascending(&self.residual_assumptions)?;
        canonical::strictly_ascending(&self.excluded_claims)?;
        if self.evidence_closes() {
            Ok(())
        } else {
            Err(QualificationFormatError::InvalidEvidence)
        }
    }
}

/// A decoded qualification record.
///
/// Invariant `evidence-closed`: every evidence member and every capability
/// is listed exactly once, every member carries its digest and passed at
/// least one case with zero unauthorized provider entries, the observation
/// capability was exercised and every live effect has its read-back, and the
/// validity window is at most 90 days.
pub type RecipeQualificationRecord = Canonical<RecordBody>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_derived_state_follows_only_its_transitions() {
        use RecipeQualificationState::{Candidate, Qualified, Revoked, Stale, Unqualified};
        let allowed = [
            (Unqualified, Candidate),
            (Candidate, Qualified),
            (Candidate, Revoked),
            (Qualified, Stale),
            (Qualified, Revoked),
            (Stale, Qualified),
            (Stale, Revoked),
        ];
        for from in RecipeQualificationState::ALL {
            for to in RecipeQualificationState::ALL {
                assert_eq!(
                    from.may_become(to),
                    allowed.contains(&(from, to)),
                    "{} -> {}",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
        for state in RecipeQualificationState::ALL {
            assert!(!Revoked.may_become(state), "revocation is terminal");
            assert_eq!(state.permits_lease(), state == Qualified);
        }
    }

    #[test]
    fn state_tokens_are_distinct() {
        let mut tokens: Vec<&str> = RecipeQualificationState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), 5);
    }
}
