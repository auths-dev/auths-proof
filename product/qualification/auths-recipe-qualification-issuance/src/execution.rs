//! Executable qualification stages over a family's reviewed corpus.
//!
//! The release runner, rather than a harness's `passed` flag, decides each
//! case from observations of the candidate. A family owns the provider
//! meaning and implements the operations; neither this module nor a gateway
//! selects a provider. Execution and observations are bounded and tied to the
//! exact deployment tuple.

use crate::{CaseReport, IssuanceError};
use auths_recipe_qualification::{
    BoundedText, CapabilityKind, LiveEffects, QualificationTuple, Scenario, Sha256Digest,
};
use serde::{Deserialize, Serialize};

/// Largest reviewed corpus the runner accepts.
pub const MAX_RUN_CASES: usize = 256;
/// Largest sequence of operations within one case.
pub const MAX_CASE_STEPS: usize = 32;
/// Schema of the reviewed executable corpus.
pub const CORPUS_SCHEMA: &str = "auths.qualification-corpus/2";

/// Where an operation may execute. Live cases never execute on a pull request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunPhase {
    /// No provider credential; an offline provider double is permitted.
    Offline,
    /// First-run production evidence through finite private operator authority.
    /// Ordinary installed clients must still demonstrate qualification refusal.
    Commissioning,
    /// Disposable provider resources in a protected environment.
    Live,
}

/// Release-only operations a reviewed family harness implements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    /// Evaluate the family's pure request/evidence oracle.
    Oracle,
    /// Submit through the candidate gateway's application socket.
    Submit,
    /// Replay the same logical operation, possibly with a fresh challenge.
    Replay,
    /// Submit the same operation concurrently to two gateway instances.
    Race,
    /// Stop and restart the gateway over its persisted state.
    Restart,
    /// Kill the gateway at the corpus's declared crash boundary.
    Crash,
    /// Lose the provider response after entry.
    DropResponse,
    /// Delay visibility at the declared read-back boundary.
    DelayVisibility,
    /// Read the effect back through the declared observation capability.
    ReadBack,
    /// Rotate the provider secret or the configured observer.
    Rotate,
    /// Exercise a hostile input, custody mutation, or isolation probe.
    Probe,
    /// Run the installed SDK journey outside the repository.
    InstalledConsumer,
}

/// Closed outcomes from the application, provider witness, or pure oracle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunOutcome {
    /// Refused with a stable code.
    Refused,
    /// A complete response is recorded; no effect claim follows.
    ResponseRecorded,
    /// The effect's fresh read-back agrees with its declaration.
    Observed,
    /// The effect is ambiguous and remains unknown.
    Unknown,
    /// An administrative or isolation operation completed.
    Complete,
}

/// The exact verdict and commitments an oracle or gateway returns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunVerdict {
    /// Closed state; an HTTP success is not `observed`.
    pub outcome: RunOutcome,
    /// Stable code, or the explicitly declared success token.
    pub code: BoundedText<96>,
    /// Digest of the closed request when the corpus exercises mapping.
    pub request_sha256: Option<Sha256Digest>,
    /// Digest of the declared evidence when the corpus exercises evidence.
    pub evidence_sha256: Option<Sha256Digest>,
}

/// What an operation must show, fixed by the reviewed corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedObservation {
    /// Expected verdict and optional request/evidence commitments.
    pub verdict: RunVerdict,
    /// Exact credential-store lease calls during this operation.
    pub credential_leases: u32,
    /// Exact provider entries during this operation.
    pub provider_entries: u32,
    /// Writes independently confirmed by fresh read-back.
    pub confirmed_by_read_back: u32,
}

/// One actual observation. There is deliberately no `passed` member.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservation {
    /// The tuple printed by the installed candidate, hashed canonically.
    pub tuple_sha256: Sha256Digest,
    /// Facts compared with the corpus, including independently measured counters.
    pub observed: ExpectedObservation,
    /// Provider entries not authorized by the exact action.
    pub unauthorized_provider_entries: u32,
    /// Whether the application or exported outputs exposed a secret.
    pub secret_exposed: bool,
    /// Whether the installed consumer imported repository source.
    pub repository_imported: bool,
    /// Whether the installed consumer received a provider token.
    pub provider_token_received: bool,
}

/// One executable step, with its expected observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunStep {
    /// Operation executed by the family harness on the candidate.
    pub operation: Operation,
    /// Assertions made by the release runner, not the family harness.
    pub expected: ExpectedObservation,
}

/// One bounded case in the reviewed corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunCase {
    /// Case identifier, passed as data rather than a shell command.
    pub id: BoundedText<96>,
    /// Evidence wall scenario this sequence exercises.
    pub scenario: Scenario,
    /// Capabilities exercised by this case.
    pub capabilities: Vec<CapabilityKind>,
    /// Offline or protected live execution.
    pub phase: RunPhase,
    /// Ordered operations, including recovery and process transitions.
    pub steps: Vec<RunStep>,
}

/// A family's executable qualification corpus, separate from runtime recipes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunCorpus {
    /// Exactly [`CORPUS_SCHEMA`].
    pub schema: String,
    /// Unique cases in deterministic execution order.
    pub cases: Vec<RunCase>,
}

impl RunCorpus {
    /// Validate bounds, scenario coverage, capabilities, and operation sequences.
    ///
    /// # Errors
    /// Returns [`IssuanceError::CaseFailed`] for an incomplete or inconsistent corpus.
    pub fn validate(&self) -> Result<(), IssuanceError> {
        if self.schema != CORPUS_SCHEMA || self.cases.is_empty() || self.cases.len() > MAX_RUN_CASES
        {
            return Err(IssuanceError::CaseFailed);
        }
        for (index, case) in self.cases.iter().enumerate() {
            if self.cases[..index].iter().any(|other| other.id == case.id) {
                return Err(IssuanceError::CaseFailed);
            }
            case.validate()?;
        }
        // Trust transitions and redaction are run by release tooling; all
        // remaining always-required scenarios need executable corpus cases.
        for scenario in Scenario::ALL {
            if scenario.always_required()
                && harness_scenario(scenario)
                && !self.cases.iter().any(|case| case.scenario == scenario)
            {
                return Err(IssuanceError::CaseFailed);
            }
        }
        Ok(())
    }
}

/// Whether a scenario executes through the family's candidate harness.
#[must_use]
pub const fn harness_scenario(scenario: Scenario) -> bool {
    !matches!(
        scenario,
        Scenario::SignerRotation
            | Scenario::Freshness
            | Scenario::LogScan
            | Scenario::TraceScan
            | Scenario::MetricScan
            | Scenario::SupportBundleScan
            | Scenario::EvidenceScan
    )
}

impl RunCase {
    fn validate(&self) -> Result<(), IssuanceError> {
        use Operation as Op;
        use Scenario as S;
        let has = |operation| self.steps.iter().any(|step| step.operation == operation);
        let before = |first, second| match (
            self.steps.iter().position(|step| step.operation == first),
            self.steps.iter().position(|step| step.operation == second),
        ) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        };
        let required = match self.scenario {
            S::OracleAccepts | S::OracleRejects => before(Op::Oracle, Op::Submit),
            S::ProofReplay | S::FreshChallengeReplay => before(Op::Submit, Op::Replay),
            S::TwoInstanceRace => has(Op::Race),
            S::Restart => before(Op::Submit, Op::Restart) && before(Op::Restart, Op::Replay),
            S::Crash => before(Op::Submit, Op::Crash) && before(Op::Crash, Op::Replay),
            S::AmbiguousResponse => before(Op::DropResponse, Op::Replay),
            S::ResponseLoss => before(Op::DropResponse, Op::ReadBack),
            S::DelayedVisibility => before(Op::DelayVisibility, Op::ReadBack),
            S::ProviderSecretRotation | S::ObserverRotation => before(Op::Rotate, Op::Submit),
            S::ReadBackConfirmsWrite => before(Op::Submit, Op::ReadBack),
            S::InstalledJourney | S::NoRepositoryImport | S::NoProviderToken => {
                has(Op::InstalledConsumer)
            }
            S::DeclaredCapability => has(Op::Submit) || has(Op::Probe),
            S::ProductionReadiness => {
                self.phase == RunPhase::Live
                    && has(Op::Probe)
                    && self.steps.iter().all(|step| {
                        step.operation == Op::Probe
                            && step.expected.verdict.outcome == RunOutcome::Complete
                            && step.expected.verdict.code.as_str() == "production-readiness-passed"
                            && step.expected.verdict.request_sha256.is_none()
                            && step.expected.verdict.evidence_sha256.is_some()
                            && step.expected.credential_leases == 0
                            && step.expected.provider_entries == 0
                            && step.expected.confirmed_by_read_back == 0
                    })
            }
            _ => has(Op::Probe),
        };
        let live_only = matches!(
            self.scenario,
            S::ReadBackConfirmsWrite
                | S::DeclaredCapability
                | S::ResponseLoss
                | S::DelayedVisibility
                | S::InstalledJourney
                | S::NoRepositoryImport
                | S::NoProviderToken
                | S::ProductionReadiness
        );
        if !harness_scenario(self.scenario)
            || !required
            || self.steps.is_empty()
            || self.steps.len() > MAX_CASE_STEPS
            || (live_only && self.phase == RunPhase::Offline)
            || (has(Op::Oracle) && self.phase != RunPhase::Offline)
            || self
                .capabilities
                .iter()
                .enumerate()
                .any(|(index, capability)| {
                    !self.scenario.may_show(*capability)
                        || self.capabilities[..index].contains(capability)
                })
            || (matches!(self.scenario, S::DeclaredCapability | S::ObserverRotation)
                && self.capabilities.is_empty())
        {
            return Err(IssuanceError::CaseFailed);
        }
        Ok(())
    }

    /// Execute this stage's operations and derive a report from measured facts.
    ///
    /// The caller performs bounded I/O against the candidate for each step.
    /// Differential cases independently execute the oracle and the gateway.
    /// Recovery cases execute the loss/delay and read-back operations; without
    /// the recovery capability they must remain `unknown`. No automatic
    /// submission is synthesized by the runner.
    ///
    /// # Errors
    /// Returns [`IssuanceError::CaseFailed`] on mismatch, exposure, unauthorized
    /// entry, changed candidate, an invalid sequence, or failed execution.
    pub fn execute(
        &self,
        tuple: &QualificationTuple,
        mut observe: impl FnMut(usize, &RunStep) -> Result<RunObservation, IssuanceError>,
    ) -> Result<(CaseReport, LiveEffects), IssuanceError> {
        self.validate()?;
        if (self.scenario == Scenario::ProductionReadiness || self.phase == RunPhase::Commissioning)
            && (tuple.target.store_kind
                != auths_recipe_qualification::LifecycleStoreKind::PostgresqlV1
                || !tuple.target.credential_store_kind.is_production())
        {
            return Err(IssuanceError::CaseFailed);
        }
        let tuple_digest = tuple.digest()?;
        let mut observations = Vec::with_capacity(self.steps.len());
        let mut effects = LiveEffects {
            entered: 0,
            confirmed_by_read_back: 0,
        };
        for (index, step) in self.steps.iter().enumerate() {
            let actual = observe(index, step)?;
            if actual.tuple_sha256 != tuple_digest
                || actual.observed != step.expected
                || actual.unauthorized_provider_entries != 0
                || actual.secret_exposed
                || actual.repository_imported
                || actual.provider_token_received
                || (actual.observed.confirmed_by_read_back > 0
                    && (actual.observed.verdict.outcome != RunOutcome::Observed
                        || actual.observed.verdict.evidence_sha256.is_none()))
                || (step.operation == Operation::Oracle
                    && (actual.observed.credential_leases != 0
                        || actual.observed.provider_entries != 0
                        || actual.observed.confirmed_by_read_back != 0))
            {
                return Err(IssuanceError::CaseFailed);
            }
            if step.operation != Operation::Oracle {
                effects.entered = effects
                    .entered
                    .checked_add(actual.observed.provider_entries)
                    .ok_or(IssuanceError::CaseFailed)?;
                effects.confirmed_by_read_back = effects
                    .confirmed_by_read_back
                    .checked_add(actual.observed.confirmed_by_read_back)
                    .ok_or(IssuanceError::CaseFailed)?;
            }
            observations.push(actual.observed);
        }
        self.check_semantics(&observations, effects)?;
        let mut report = CaseReport::new(self.id.as_str(), self.scenario, true)?;
        report.capabilities.clone_from(&self.capabilities);
        Ok((report, effects))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed scenario invariants are reviewed together"
    )]
    fn check_semantics(
        &self,
        observations: &[ExpectedObservation],
        effects: LiveEffects,
    ) -> Result<(), IssuanceError> {
        use Scenario as S;
        if self.scenario == S::InstalledJourney {
            let ordinary_effect = self.phase == RunPhase::Live
                && effects.entered > 0
                && effects.entered == effects.confirmed_by_read_back
                && self.steps.iter().zip(observations).any(|(step, actual)| {
                    step.operation == Operation::InstalledConsumer
                        && actual.verdict.outcome == RunOutcome::Observed
                        && actual.provider_entries > 0
                        && actual.provider_entries == actual.confirmed_by_read_back
                });
            let first_run_refusal = self.phase == RunPhase::Commissioning
                && observations.iter().all(|actual| {
                    actual.verdict.outcome == RunOutcome::Refused
                        && matches!(
                            actual.verdict.code.as_str(),
                            "gateway.qualification.unavailable" | "gateway.qualification.missing"
                        )
                        && actual.credential_leases == 0
                        && actual.provider_entries == 0
                        && actual.confirmed_by_read_back == 0
                });
            if !ordinary_effect && !first_run_refusal {
                return Err(IssuanceError::CaseFailed);
            }
        }
        let no_entry = matches!(
            self.scenario,
            S::ApplicationCannotReadSecret
                | S::ForgedProof
                | S::AlteredAction
                | S::DirectProviderAttempt
                | S::StoreKindDrift
                | S::GenerationDrift
                | S::CommitmentDrift
                | S::ExternalVersionDrift
        );
        if no_entry
            && observations
                .iter()
                .any(|actual| actual.provider_entries != 0)
        {
            return Err(IssuanceError::CaseFailed);
        }
        if matches!(self.scenario, S::ForgedProof | S::AlteredAction)
            && observations.iter().any(|actual| {
                actual.credential_leases != 0 || actual.verdict.outcome != RunOutcome::Refused
            })
        {
            return Err(IssuanceError::CaseFailed);
        }
        let mut unresolved = false;
        for (step, actual) in self.steps.iter().zip(observations) {
            if step.operation == Operation::Replay {
                let read_only_completion = unresolved
                    && actual.credential_leases <= 1
                    && matches!(
                        actual.verdict.outcome,
                        RunOutcome::Unknown | RunOutcome::ResponseRecorded | RunOutcome::Observed
                    );
                if actual.provider_entries != 0
                    || (actual.credential_leases != 0 && !read_only_completion)
                {
                    return Err(IssuanceError::CaseFailed);
                }
            }
            if step.operation != Operation::Oracle {
                if actual.provider_entries > 0 {
                    unresolved = matches!(
                        actual.verdict.outcome,
                        RunOutcome::Unknown | RunOutcome::ResponseRecorded
                    );
                } else if actual.verdict.outcome == RunOutcome::Observed {
                    unresolved = false;
                }
            }
        }
        if matches!(
            self.scenario,
            S::ProofReplay
                | S::FreshChallengeReplay
                | S::TwoInstanceRace
                | S::Restart
                | S::Crash
                | S::AmbiguousResponse
                | S::ResponseLoss
                | S::DelayedVisibility
        ) && effects.entered != 1
        {
            return Err(IssuanceError::CaseFailed);
        }
        if matches!(self.scenario, S::OracleAccepts | S::OracleRejects) {
            let verdict = |operation| {
                self.steps
                    .iter()
                    .zip(observations)
                    .find(|(step, _)| step.operation == operation)
                    .map(|(_, actual)| &actual.verdict)
            };
            let oracle = verdict(Operation::Oracle).ok_or(IssuanceError::CaseFailed)?;
            if Some(oracle) != verdict(Operation::Submit)
                || (oracle.outcome == RunOutcome::Refused) != (self.scenario == S::OracleRejects)
                || (self.scenario == S::OracleAccepts && oracle.request_sha256.is_none())
            {
                return Err(IssuanceError::CaseFailed);
            }
        }
        if self.scenario == S::ReadBackConfirmsWrite
            && (effects.entered == 0 || effects.entered != effects.confirmed_by_read_back)
        {
            return Err(IssuanceError::CaseFailed);
        }
        if matches!(self.scenario, S::ResponseLoss | S::DelayedVisibility) {
            let last = observations.last().ok_or(IssuanceError::CaseFailed)?;
            let recovery = self.capabilities.contains(&CapabilityKind::Recovery);
            if (recovery
                && (last.verdict.outcome != RunOutcome::Observed
                    || effects.confirmed_by_read_back != 1))
                || (!recovery
                    && (last.verdict.outcome != RunOutcome::Unknown
                        || effects.confirmed_by_read_back != 0))
            {
                return Err(IssuanceError::CaseFailed);
            }
        }
        Ok(())
    }
}
