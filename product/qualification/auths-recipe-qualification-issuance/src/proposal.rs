//! A proposal: a record together with the evidence it closes over.

use crate::IssuanceError;
use auths_connections::ProviderKind;
use auths_recipe_qualification::{
    BoundedText, CapabilityKind, CapabilityResult, EVIDENCE_SCHEMA, EvidenceBody, EvidenceCase,
    EvidenceMember, EvidenceMemberKind, EvidenceResult, ExercisedCapability, GitCommit,
    InstalledPackage, LiveEffects, Provenance, QUALIFICATION_RECORD_SCHEMA, QualificationEvidence,
    QualificationId, QualificationTuple, RecipeQualificationRecord, RecordBody, Scenario,
    Sha256Digest, verify_evidence_closure,
};
use serde::{Deserialize, Serialize};

/// What one case of a stage reported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReport {
    /// The case's identifier within its member.
    pub id: BoundedText<96>,
    /// What the case shows.
    pub scenario: Scenario,
    /// The capabilities the case exercised.
    #[serde(default)]
    pub capabilities: Vec<CapabilityKind>,
    /// Whether the case passed.
    pub passed: bool,
    /// Provider entries the case observed that no approval authorized.
    #[serde(default)]
    pub unauthorized_provider_entries: u32,
}

impl CaseReport {
    /// A case for `scenario` that passed or did not, with no capability and
    /// no unauthorized entry.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Format`] when `id` is not bounded printable
    /// text.
    pub fn new(id: &str, scenario: Scenario, passed: bool) -> Result<Self, IssuanceError> {
        Ok(Self {
            id: BoundedText::parse(id)
                .map_err(|_| auths_recipe_qualification::QualificationFormatError::Malformed)?,
            scenario,
            capabilities: Vec::new(),
            passed,
            unauthorized_provider_entries: 0,
        })
    }
}

/// Builds one member's evidence artifact from the cases a stage reported.
///
/// # Errors
///
/// Returns [`IssuanceError::CaseFailed`] when any case did not pass or
/// observed an unauthorized provider entry: such a run produces no artifact.
/// Returns [`IssuanceError::Format`] when the cases break the artifact's
/// structural rules.
pub fn evidence(
    member: EvidenceMemberKind,
    commit: &GitCommit,
    tuple: &QualificationTuple,
    mut cases: Vec<CaseReport>,
    live_effects: Option<LiveEffects>,
) -> Result<QualificationEvidence, IssuanceError> {
    if cases
        .iter()
        .any(|case| !case.passed || case.unauthorized_provider_entries != 0)
    {
        return Err(IssuanceError::CaseFailed);
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    let cases = cases
        .into_iter()
        .map(|mut case| {
            case.capabilities.sort_unstable();
            case.capabilities.dedup();
            EvidenceCase {
                id: case.id,
                scenario: case.scenario,
                capabilities: case.capabilities,
                unauthorized_provider_entries: 0,
            }
        })
        .collect();
    Ok(QualificationEvidence::from_body(&EvidenceBody {
        schema: EVIDENCE_SCHEMA.to_owned(),
        member,
        commit: commit.clone(),
        tuple_sha256: tuple.digest()?,
        cases,
        live_effects,
    })?)
}

/// A capability the family's decision record says does not apply, and why.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotApplicable {
    /// The capability.
    pub capability: CapabilityKind,
    /// The reason the decision record fixes.
    pub reason: BoundedText<128>,
}

/// Everything a record states that its evidence does not determine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordDraft {
    /// The qualification's identifier.
    pub qualification_id: QualificationId,
    /// The connection provider kind the record names.
    pub provider_kind: String,
    /// What is qualified.
    pub tuple: QualificationTuple,
    /// The start of the record's validity window.
    pub not_before: u64,
    /// The end of the record's validity window.
    pub not_after: u64,
    /// Where and on what the run happened.
    pub provenance: Provenance,
    /// The digest of the run's source closure.
    pub source_closure_sha256: Sha256Digest,
    /// The digest of the run's generated artifacts.
    pub generated_artifacts_sha256: Sha256Digest,
    /// The installed packages the run exercised.
    pub installed_packages: Vec<InstalledPackage>,
    /// The digest of the family's decision record.
    pub recipe_decision_record_sha256: Sha256Digest,
    /// The digest of the corpus manifest.
    pub corpus_manifest_sha256: Sha256Digest,
    /// The capabilities that do not apply to the family.
    pub not_applicable: Vec<NotApplicable>,
    /// Sanitized identifiers of the disposable provider resources.
    pub provider_resources: Vec<BoundedText<96>>,
    /// The custody descriptor.
    pub custody_descriptor: BoundedText<128>,
    /// The store descriptor.
    pub store_descriptor: BoundedText<128>,
    /// Assumptions the run did not test.
    pub residual_assumptions: Vec<BoundedText<256>>,
    /// Claims the qualification does not make.
    pub excluded_claims: Vec<BoundedText<256>>,
}

/// A record and the evidence it closes over. It carries no signature.
///
/// Both constructors verify the closure, so holding a proposal is proof
/// that every digest, count, capability, and live effect the record states
/// was recomputed from the evidence held beside it. A signer accepts only a
/// proposal, which is how a signature is never made over a record whose
/// evidence was not re-verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationProposal {
    record: RecipeQualificationRecord,
    evidence: Vec<QualificationEvidence>,
}

impl QualificationProposal {
    /// Assembles the record `draft` and `evidence` determine.
    ///
    /// The evidence may arrive in any order. Each capability is stated
    /// `exercised` when a case shows it and `not-applicable` with the
    /// draft's reason otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Capability`] when a capability no case shows
    /// has no reason, or one a case shows has a reason;
    /// [`IssuanceError::Format`] when the record breaks a structural rule,
    /// which includes a missing member, an unauthorized entry, and a live
    /// write without its read-back; and [`IssuanceError::Closure`] when the
    /// record does not close over the evidence.
    pub fn assemble(
        draft: RecordDraft,
        mut evidence: Vec<QualificationEvidence>,
    ) -> Result<Self, IssuanceError> {
        evidence.sort_by_key(|artifact| artifact.body().member);
        let shown = |capability: CapabilityKind| {
            evidence.iter().any(|artifact| {
                artifact
                    .body()
                    .cases
                    .iter()
                    .any(|case| case.capabilities.contains(&capability))
            })
        };
        let mut capabilities = Vec::with_capacity(CapabilityKind::ALL.len());
        for capability in CapabilityKind::ALL {
            let mut reasons = draft
                .not_applicable
                .iter()
                .filter(|declared| declared.capability == capability);
            let reason = reasons.next().map(|declared| declared.reason.clone());
            if reasons.next().is_some() || shown(capability) == reason.is_some() {
                return Err(IssuanceError::Capability);
            }
            capabilities.push(ExercisedCapability {
                capability,
                result: if reason.is_some() {
                    CapabilityResult::NotApplicable
                } else {
                    CapabilityResult::Exercised
                },
                reason,
            });
        }
        let members = evidence
            .iter()
            .map(|artifact| {
                let body = artifact.body();
                Ok(EvidenceMember {
                    member: body.member,
                    result: EvidenceResult::Passed,
                    evidence_sha256: artifact.digest(),
                    cases: u32::try_from(body.cases.len())
                        .map_err(|_| IssuanceError::CaseFailed)?,
                    unauthorized_provider_entries: body
                        .cases
                        .iter()
                        .map(|case| case.unauthorized_provider_entries)
                        .sum(),
                })
            })
            .collect::<Result<Vec<_>, IssuanceError>>()?;
        let live_effects = evidence
            .iter()
            .find_map(|artifact| artifact.body().live_effects)
            .ok_or(auths_recipe_qualification::ClosureFault::LiveEffects)?;
        let record = RecipeQualificationRecord::from_body(&RecordBody {
            schema: QUALIFICATION_RECORD_SCHEMA.to_owned(),
            qualification_id: draft.qualification_id,
            provider_kind: ProviderKind::parse(draft.provider_kind)
                .map_err(|_| auths_recipe_qualification::QualificationFormatError::Malformed)?,
            tuple: draft.tuple,
            not_before: draft.not_before,
            not_after: draft.not_after,
            provenance: draft.provenance,
            source_closure_sha256: draft.source_closure_sha256,
            generated_artifacts_sha256: draft.generated_artifacts_sha256,
            installed_packages: draft.installed_packages,
            recipe_decision_record_sha256: draft.recipe_decision_record_sha256,
            corpus_manifest_sha256: draft.corpus_manifest_sha256,
            evidence: members,
            capabilities,
            live_effects,
            provider_resources: draft.provider_resources,
            custody_descriptor: draft.custody_descriptor,
            store_descriptor: draft.store_descriptor,
            residual_assumptions: draft.residual_assumptions,
            excluded_claims: draft.excluded_claims,
        })?;
        verify_evidence_closure(&record, &evidence)?;
        Ok(Self { record, evidence })
    }

    /// Decodes a record and its evidence and verifies the closure.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Format`] for an artifact that does not
    /// decode and [`IssuanceError::Closure`] when the record does not close
    /// over the evidence.
    pub fn from_parts(record: &[u8], evidence: &[&[u8]]) -> Result<Self, IssuanceError> {
        let record = RecipeQualificationRecord::from_canonical_json(record)?;
        let mut evidence = evidence
            .iter()
            .map(|bytes| QualificationEvidence::from_canonical_json(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        evidence.sort_by_key(|artifact| artifact.body().member);
        verify_evidence_closure(&record, &evidence)?;
        Ok(Self { record, evidence })
    }

    /// The record.
    #[must_use]
    pub const fn record(&self) -> &RecipeQualificationRecord {
        &self.record
    }

    /// The evidence, one artifact per member in the record's order.
    #[must_use]
    pub fn evidence(&self) -> &[QualificationEvidence] {
        &self.evidence
    }
}
