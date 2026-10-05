//! Evidence artifacts: what one member of a protected run showed, case by
//! case, and the check that a record's claims are exactly what its evidence
//! holds.
//!
//! A record carries only a digest, a case count, and a counter per member.
//! The artifact behind each digest lists the cases. A record *closes over*
//! its artifacts when every digest, count, counter, capability, and live
//! effect it states can be recomputed from them, they were produced on the
//! record's commit for the record's tuple, and every row of the evidence
//! wall has a case in each member that row belongs to.

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

    /// The members that must each hold a case for this row.
    #[must_use]
    pub const fn members(self) -> &'static [EvidenceMemberKind] {
        use EvidenceMemberKind as Member;
        match self {
            Self::CleanSource | Self::RecipeVectors => &[Member::Conformance],
            Self::OracleAgreement => &[Member::Differential],
            Self::SecretIsolation => &[Member::Hostile],
            Self::UnauthorizedEntry => &[Member::Hostile, Member::Restart, Member::MultiInstance],
            Self::CustodyDrift | Self::Rotation => &[Member::Rotation],
            Self::DeclaredCapabilities | Self::ReadBack => &[Member::Live],
            Self::Recovery => &[Member::Recovery],
            Self::Redaction => &[Member::Redaction],
            Self::InstalledConsumer => &[Member::InstalledConsumer],
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
    /// The wall row the case is evidence for.
    pub wall_row: WallRow,
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
            let row_belongs = case.wall_row.members().contains(&self.member);
            let capabilities_belong = case
                .capabilities
                .iter()
                .all(|capability| capability.member() == self.member);
            if !row_belongs || !capabilities_belong {
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
/// that passed, each for a wall row and capabilities that belong to its
/// member, on one commit and for one tuple. A failed case cannot be
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
    /// A wall row has no case in a member it belongs to.
    #[error("a wall row has no evidence")]
    WallRow,
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
            Self::WallRow => "wall-row",
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
/// the record's tuple, and that every wall row has a case in each member it
/// belongs to.
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
    let has_case = |member: EvidenceMemberKind, row: WallRow| {
        evidence
            .iter()
            .filter(|artifact| artifact.body().member == member)
            .any(|artifact| {
                artifact
                    .body()
                    .cases
                    .iter()
                    .any(|case| case.wall_row == row)
            })
    };
    let rows_covered = WallRow::ALL
        .into_iter()
        .all(|row| row.members().iter().all(|member| has_case(*member, row)));
    if !rows_covered {
        return Err(ClosureFault::WallRow);
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
