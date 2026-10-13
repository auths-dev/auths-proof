//! Evidence artifacts: what one member of a protected run showed, case by
//! case, and the check that a record's claims are exactly what its evidence
//! holds.
//!
//! A record carries only a digest, a case count, and a counter per member.
//! The artifact behind each digest lists the cases. A record *closes over*
//! its artifacts when every digest, count, counter, capability, and live
//! effect it states can be recomputed from them, they were produced on the
//! record's commit for the record's tuple, and every scenario the evidence
//! wall requires has a case in the member that scenario belongs to.

use crate::canonical::{self, Artifact, Canonical, Sealed};
use crate::model::{
    CapabilityKind, CapabilityResult, EvidenceMemberKind, LiveEffects, QualificationTuple,
    RecipeQualificationRecord,
};
use crate::{BoundedText, GitCommit, QualificationFormatError, Sha256Digest};
use serde::{Deserialize, Serialize};

/// The schema of an evidence artifact.
pub const EVIDENCE_SCHEMA: &str = "auths.qualification-evidence/1";
/// The domain of a tuple digest.
pub const TUPLE_DIGEST_DOMAIN: &str = "auths.qualification-tuple/1";
/// The largest evidence artifact accepted.
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
/// The most cases one evidence artifact lists.
pub const MAX_EVIDENCE_CASES: usize = 256;

/// One row of the evidence wall a protected run must pass.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WallRow {
    /// Source and generated artifacts are clean and the recipe digest
    /// rederives.
    CleanSource,
    /// Compiler and interpreter vectors and closed-enumeration hostile cases
    /// pass.
    RecipeVectors,
    /// The pure oracle and the gateway agree on every corpus member.
    OracleAgreement,
    /// An application process without a credential cannot read secret
    /// material.
    SecretIsolation,
    /// Forgery, replay, direct attempts, races, restarts, crashes, and
    /// ambiguous responses produce no unauthorized provider entry.
    UnauthorizedEntry,
    /// Store kind, generation, commitment, or external version drift fails
    /// before provider entry.
    CustodyDrift,
    /// Provider-secret and qualification-signer rotations keep their typed
    /// generation and trust transitions.
    Rotation,
    /// Every declared provider capability is exercised.
    DeclaredCapabilities,
    /// A successful live action is confirmed by the declared read-back.
    ReadBack,
    /// Response loss and delayed visibility converge only under the declared
    /// recovery capability.
    Recovery,
    /// Logs, traces, metrics, support bundles, and evidence pass secret and
    /// provider-data scans.
    Redaction,
    /// An installed consumer completes the journey without repository source
    /// or a provider token.
    InstalledConsumer,
}

impl WallRow {
    /// Every row, in the wall's order.
    pub const ALL: [Self; 12] = [
        Self::CleanSource,
        Self::RecipeVectors,
        Self::OracleAgreement,
        Self::SecretIsolation,
        Self::UnauthorizedEntry,
        Self::CustodyDrift,
        Self::Rotation,
        Self::DeclaredCapabilities,
        Self::ReadBack,
        Self::Recovery,
        Self::Redaction,
        Self::InstalledConsumer,
    ];
}

/// One thing a protected run must show. Every case is evidence for exactly
/// one scenario, and every scenario belongs to one wall row and one member.
///
/// The set is closed and names no provider: a scenario says what kind of
/// attempt or check was made, and the family's harness decides how to make
/// it against its own provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    /// Source and generated artifacts are unmodified.
    CleanSource,
    /// The compiled recipe digest rederives from the installed source.
    RecipeDigestRederives,
    /// The recipe compiler and interpreter vectors pass.
    RecipeVectors,
    /// The closed-enumeration hostile recipe cases are refused.
    ClosedEnumerationHostile,
    /// The oracle and the gateway both accept a corpus member.
    OracleAccepts,
    /// The oracle and the gateway both reject a corpus member.
    OracleRejects,
    /// An application process without a credential cannot read secret
    /// material.
    ApplicationCannotReadSecret,
    /// All required typed production doctor checks pass. Required for the
    /// stable launch projection, never inferred from development readiness.
    ProductionReadiness,
    /// A forged proof enters no provider.
    ForgedProof,
    /// An action altered after approval enters no provider.
    AlteredAction,
    /// A replayed proof enters no provider a second time.
    ProofReplay,
    /// A fresh challenge for the same logical operation enters no provider a
    /// second time.
    FreshChallengeReplay,
    /// A direct attempt on the provider without the gateway does not
    /// succeed.
    DirectProviderAttempt,
    /// An ambiguous provider response causes no second entry.
    AmbiguousResponse,
    /// Two gateway instances racing one operation enter the provider once.
    TwoInstanceRace,
    /// A restart mid-operation causes no unauthorized entry.
    Restart,
    /// A crash at a stage boundary causes no unauthorized entry.
    Crash,
    /// A changed credential-store kind fails before provider entry.
    StoreKindDrift,
    /// A changed credential generation fails before provider entry.
    GenerationDrift,
    /// A changed reference commitment fails before provider entry.
    CommitmentDrift,
    /// A changed pinned external version fails before provider entry.
    ExternalVersionDrift,
    /// A provider-secret rotation keeps its typed generation transitions.
    ProviderSecretRotation,
    /// A qualification-signer rotation keeps its trust transitions.
    SignerRotation,
    /// The signed time bounds of the release inputs are enforced.
    Freshness,
    /// An observer rotation keeps its trust transitions; required only when
    /// the target declares an observer.
    ObserverRotation,
    /// A declared provider capability is exercised.
    DeclaredCapability,
    /// A successful live write is confirmed by the declared read-back.
    ReadBackConfirmsWrite,
    /// A lost response converges only under the declared recovery
    /// capability and otherwise stays unknown.
    ResponseLoss,
    /// Delayed visibility converges only under the declared recovery
    /// capability and otherwise stays unknown.
    DelayedVisibility,
    /// Logs hold no planted secret or provider datum.
    LogScan,
    /// Traces hold no planted secret or provider datum.
    TraceScan,
    /// Metrics hold no planted secret or provider datum.
    MetricScan,
    /// Support bundles hold no planted secret or provider datum.
    SupportBundleScan,
    /// Evidence artifacts hold no planted secret or provider datum.
    EvidenceScan,
    /// An installed consumer completes the documented journey.
    InstalledJourney,
    /// The installed consumer imports no repository source.
    NoRepositoryImport,
    /// The installed consumer receives no provider token.
    NoProviderToken,
}

impl Scenario {
    /// Every scenario, in the wall's order.
    pub const ALL: [Self; 37] = [
        Self::CleanSource,
        Self::RecipeDigestRederives,
        Self::RecipeVectors,
        Self::ClosedEnumerationHostile,
        Self::OracleAccepts,
        Self::OracleRejects,
        Self::ApplicationCannotReadSecret,
        Self::ProductionReadiness,
        Self::ForgedProof,
        Self::AlteredAction,
        Self::ProofReplay,
        Self::FreshChallengeReplay,
        Self::DirectProviderAttempt,
        Self::AmbiguousResponse,
        Self::TwoInstanceRace,
        Self::Restart,
        Self::Crash,
        Self::StoreKindDrift,
        Self::GenerationDrift,
        Self::CommitmentDrift,
        Self::ExternalVersionDrift,
        Self::ProviderSecretRotation,
        Self::SignerRotation,
        Self::Freshness,
        Self::ObserverRotation,
        Self::DeclaredCapability,
        Self::ReadBackConfirmsWrite,
        Self::ResponseLoss,
        Self::DelayedVisibility,
        Self::LogScan,
        Self::TraceScan,
        Self::MetricScan,
        Self::SupportBundleScan,
        Self::EvidenceScan,
        Self::InstalledJourney,
        Self::NoRepositoryImport,
        Self::NoProviderToken,
    ];

    /// The wall row this scenario is evidence for.
    #[must_use]
    pub const fn row(self) -> WallRow {
        match self {
            Self::CleanSource | Self::RecipeDigestRederives => WallRow::CleanSource,
            Self::RecipeVectors | Self::ClosedEnumerationHostile => WallRow::RecipeVectors,
            Self::OracleAccepts | Self::OracleRejects => WallRow::OracleAgreement,
            Self::ApplicationCannotReadSecret | Self::ProductionReadiness => {
                WallRow::SecretIsolation
            }
            Self::ForgedProof
            | Self::AlteredAction
            | Self::ProofReplay
            | Self::FreshChallengeReplay
            | Self::DirectProviderAttempt
            | Self::AmbiguousResponse
            | Self::TwoInstanceRace
            | Self::Restart
            | Self::Crash => WallRow::UnauthorizedEntry,
            Self::StoreKindDrift
            | Self::GenerationDrift
            | Self::CommitmentDrift
            | Self::ExternalVersionDrift => WallRow::CustodyDrift,
            Self::ProviderSecretRotation
            | Self::SignerRotation
            | Self::Freshness
            | Self::ObserverRotation => WallRow::Rotation,
            Self::DeclaredCapability => WallRow::DeclaredCapabilities,
            Self::ReadBackConfirmsWrite => WallRow::ReadBack,
            Self::ResponseLoss | Self::DelayedVisibility => WallRow::Recovery,
            Self::LogScan
            | Self::TraceScan
            | Self::MetricScan
            | Self::SupportBundleScan
            | Self::EvidenceScan => WallRow::Redaction,
            Self::InstalledJourney | Self::NoRepositoryImport | Self::NoProviderToken => {
                WallRow::InstalledConsumer
            }
        }
    }

    /// The one member whose artifact holds this scenario's cases.
    #[must_use]
    pub const fn member(self) -> EvidenceMemberKind {
        use EvidenceMemberKind as Member;
        match self {
            Self::TwoInstanceRace => Member::MultiInstance,
            Self::Restart | Self::Crash => Member::Restart,
            _ => match self.row() {
                WallRow::CleanSource | WallRow::RecipeVectors => Member::Conformance,
                WallRow::OracleAgreement => Member::Differential,
                WallRow::SecretIsolation | WallRow::UnauthorizedEntry => Member::Hostile,
                WallRow::CustodyDrift | WallRow::Rotation => Member::Rotation,
                WallRow::DeclaredCapabilities | WallRow::ReadBack => Member::Live,
                WallRow::Recovery => Member::Recovery,
                WallRow::Redaction => Member::Redaction,
                WallRow::InstalledConsumer => Member::InstalledConsumer,
            },
        }
    }

    /// Whether every record needs a case for this scenario. Capability cases
    /// are required when declared; production readiness is additionally
    /// required by the stable launch projection.
    #[must_use]
    pub const fn always_required(self) -> bool {
        !matches!(
            self,
            Self::ObserverRotation | Self::DeclaredCapability | Self::ProductionReadiness
        )
    }

    /// Whether a case for this scenario may show `capability` exercised.
    #[must_use]
    pub const fn may_show(self, capability: CapabilityKind) -> bool {
        match capability {
            CapabilityKind::Recovery => {
                matches!(self, Self::ResponseLoss | Self::DelayedVisibility)
            }
            CapabilityKind::ObserverRotation => matches!(self, Self::ObserverRotation),
            _ => matches!(self, Self::DeclaredCapability),
        }
    }
}

impl CapabilityKind {
    /// The one member whose cases may show this capability exercised.
    #[must_use]
    pub const fn member(self) -> EvidenceMemberKind {
        match self {
            Self::Recovery => EvidenceMemberKind::Recovery,
            Self::ObserverRotation => EvidenceMemberKind::Rotation,
            Self::CredentialGuard
            | Self::VersionPin
            | Self::AccountBinding
            | Self::DeniedReads
            | Self::Ceiling
            | Self::Budget
            | Self::Idempotency
            | Self::ResponseLocator
            | Self::Echo
            | Self::Observation => EvidenceMemberKind::Live,
        }
    }
}

/// One case that passed. A case that did not pass has no representation: a
/// run with one produces no artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCase {
    /// The case's identifier within its member.
    pub id: BoundedText<96>,
    /// What the case shows.
    pub scenario: Scenario,
    /// The capabilities the case exercised, sorted and unique.
    pub capabilities: Vec<CapabilityKind>,
    /// Provider entries the case observed that no approval authorized.
    pub unauthorized_provider_entries: u32,
}

/// The body of an evidence artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBody {
    /// Exactly [`EVIDENCE_SCHEMA`].
    pub schema: String,
    /// The member this artifact is.
    pub member: EvidenceMemberKind,
    /// The commit of the release candidate the cases ran on.
    pub commit: GitCommit,
    /// The digest of the tuple the cases ran for.
    pub tuple_sha256: Sha256Digest,
    /// The cases, sorted by identifier and unique.
    pub cases: Vec<EvidenceCase>,
    /// Live writes and their read-backs; present exactly for the live
    /// member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_effects: Option<LiveEffects>,
}

impl Sealed for EvidenceBody {}

impl Artifact for EvidenceBody {
    const SCHEMA: &'static str = EVIDENCE_SCHEMA;
    const MAX_BYTES: usize = MAX_EVIDENCE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        if self.cases.is_empty() || self.cases.len() > MAX_EVIDENCE_CASES {
            return Err(QualificationFormatError::ListBound);
        }
        let identifiers: Vec<&BoundedText<96>> = self.cases.iter().map(|case| &case.id).collect();
        canonical::strictly_ascending(&identifiers)?;
        for case in &self.cases {
            canonical::strictly_ascending(&case.capabilities)?;
            let belongs = case.scenario.member() == self.member;
            let capabilities_belong = case
                .capabilities
                .iter()
                .all(|capability| case.scenario.may_show(*capability));
            // A capability case that shows no capability is evidence of
            // nothing.
            let shows_something = !matches!(
                case.scenario,
                Scenario::DeclaredCapability | Scenario::ObserverRotation
            ) || !case.capabilities.is_empty();
            if !belongs || !capabilities_belong || !shows_something {
                return Err(QualificationFormatError::InvalidEvidence);
            }
        }
        let live_holds = match (self.member, self.live_effects) {
            (EvidenceMemberKind::Live, Some(effects)) => {
                effects.entered >= 1 && effects.confirmed_by_read_back == effects.entered
            }
            (EvidenceMemberKind::Live, None) => false,
            (_, effects) => effects.is_none(),
        };
        if live_holds {
            Ok(())
        } else {
            Err(QualificationFormatError::InvalidEvidence)
        }
    }
}

/// A decoded evidence artifact.
///
/// Invariant `passed-cases-only`: the value lists between 1 and 256 cases
/// that passed, each for a scenario that belongs to its member and
/// capabilities that scenario may show, on one commit and for one tuple. A failed case cannot be
/// represented.
pub type QualificationEvidence = Canonical<EvidenceBody>;

impl QualificationTuple {
    /// SHA-256 of [`TUPLE_DIGEST_DOMAIN`], a NUL byte, and the canonical
    /// tuple.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] when the tuple cannot
    /// be canonicalized.
    pub fn digest(&self) -> Result<Sha256Digest, QualificationFormatError> {
        Ok(canonical::domain_digest(
            TUPLE_DIGEST_DOMAIN,
            &canonical::canonical_bytes(self)?,
        ))
    }
}

/// Why a record does not close over a set of evidence artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClosureFault {
    /// The artifacts are not exactly one per member, in the record's order.
    #[error("the evidence is not one artifact per member")]
    MemberSet,
    /// An artifact's digest is not the one the record states.
    #[error("an evidence digest differs from the record")]
    Digest,
    /// An artifact's case count or counter is not the one the record states.
    #[error("an evidence counter differs from the record")]
    Counter,
    /// An artifact was produced on another commit or for another tuple.
    #[error("evidence was produced for another candidate")]
    Candidate,
    /// A required scenario has no case.
    #[error("a required scenario has no evidence")]
    Scenario,
    /// A capability's result is not what the cases show.
    #[error("a capability result differs from the evidence")]
    Capability,
    /// The record's live effects are not the live member's.
    #[error("the live effects differ from the evidence")]
    LiveEffects,
}

impl ClosureFault {
    /// The stable token of this fault.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemberSet => "member-set",
            Self::Digest => "digest",
            Self::Counter => "counter",
            Self::Candidate => "candidate",
            Self::Scenario => "scenario",
            Self::Capability => "capability",
            Self::LiveEffects => "live-effects",
        }
    }
}

/// Requires `record` to close over `evidence`.
///
/// The record is already known to be structurally closed. This check adds
/// that each stated digest is the digest of a presented artifact, that the
/// counts, counters, capability results, and live effects are the ones the
/// cases show, that every artifact was produced on the record's commit for
/// the record's tuple, and that every scenario the wall always requires has
/// a case.
///
/// # Errors
///
/// Returns the first [`ClosureFault`] found.
pub fn verify_evidence_closure(
    record: &RecipeQualificationRecord,
    evidence: &[QualificationEvidence],
) -> Result<(), ClosureFault> {
    let body = record.body();
    if evidence.len() != body.evidence.len() {
        return Err(ClosureFault::MemberSet);
    }
    let tuple_sha256 = body.tuple.digest().map_err(|_| ClosureFault::Candidate)?;
    for (stated, artifact) in body.evidence.iter().zip(evidence) {
        let shown = artifact.body();
        if shown.member != stated.member {
            return Err(ClosureFault::MemberSet);
        }
        if artifact.digest() != stated.evidence_sha256 {
            return Err(ClosureFault::Digest);
        }
        let unauthorized = shown
            .cases
            .iter()
            .try_fold(0_u32, |sum, case| {
                sum.checked_add(case.unauthorized_provider_entries)
            })
            .ok_or(ClosureFault::Counter)?;
        if u32::try_from(shown.cases.len()) != Ok(stated.cases)
            || unauthorized != stated.unauthorized_provider_entries
        {
            return Err(ClosureFault::Counter);
        }
        if shown.commit != body.provenance.commit || shown.tuple_sha256 != tuple_sha256 {
            return Err(ClosureFault::Candidate);
        }
    }
    let has_case = |scenario: Scenario| {
        evidence.iter().any(|artifact| {
            artifact
                .body()
                .cases
                .iter()
                .any(|case| case.scenario == scenario)
        })
    };
    let wall_whole = Scenario::ALL
        .into_iter()
        .filter(|scenario| scenario.always_required())
        .all(has_case);
    if !wall_whole {
        return Err(ClosureFault::Scenario);
    }
    let exercised = |capability: CapabilityKind| {
        evidence.iter().any(|artifact| {
            artifact
                .body()
                .cases
                .iter()
                .any(|case| case.capabilities.contains(&capability))
        })
    };
    let capabilities_shown = body.capabilities.iter().all(|stated| {
        (stated.result == CapabilityResult::Exercised) == exercised(stated.capability)
    });
    if !capabilities_shown {
        return Err(ClosureFault::Capability);
    }
    let live = evidence
        .iter()
        .find_map(|artifact| artifact.body().live_effects);
    if live != Some(body.live_effects) {
        return Err(ClosureFault::LiveEffects);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every row of the wall is reached by a scenario every record needs,
    /// every member holds one, and the tokens are distinct.
    #[test]
    fn the_scenario_catalogue_covers_every_wall_row_and_member() {
        let required: Vec<Scenario> = Scenario::ALL
            .into_iter()
            .filter(|scenario| scenario.always_required())
            .collect();
        assert_eq!(required.len(), 34);
        let rows: BTreeSet<WallRow> = required.iter().map(|scenario| scenario.row()).collect();
        let every_row: BTreeSet<WallRow> = WallRow::ALL
            .into_iter()
            .filter(|row| *row != WallRow::DeclaredCapabilities)
            .collect();
        assert_eq!(
            rows, every_row,
            "the capability row is required per capability"
        );
        let members: BTreeSet<EvidenceMemberKind> =
            required.iter().map(|scenario| scenario.member()).collect();
        assert_eq!(members.len(), EvidenceMemberKind::ALL.len());
        let tokens: BTreeSet<String> = Scenario::ALL
            .into_iter()
            .map(|scenario| serde_json::to_string(&scenario).expect("token"))
            .collect();
        assert_eq!(tokens.len(), Scenario::ALL.len());
    }

    /// A capability is shown only by a scenario of the member that
    /// capability belongs to.
    #[test]
    fn a_capability_is_shown_only_in_its_own_member() {
        for capability in CapabilityKind::ALL {
            let showing: Vec<Scenario> = Scenario::ALL
                .into_iter()
                .filter(|scenario| scenario.may_show(capability))
                .collect();
            assert!(!showing.is_empty(), "{capability:?} can be shown");
            for scenario in showing {
                assert_eq!(scenario.member(), capability.member(), "{capability:?}");
            }
        }
    }
}
