//! Privacy-preserving causal explanation report.

use auths_codec::{body_digest, context_digest, encode_canonical_action};
use auths_model::{CanonicalAction, VerificationCode, VerificationDecision, VerifierContext};
use auths_registries::ImmutableRegistries;
use auths_verifier::{
    ExplainedVerification, VerificationOutcome,
    causal::{Contribution, causal_slice},
    trace::{FactKind, FactOrigin, FactResult, FactValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Explicit diagnostic disclosure policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisclosurePolicy {
    Summary,
    Operator,
    Audit,
}

/// Stable bindings preventing report/result confusion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplanationBindings {
    pub proof: String,
    pub action: String,
    pub context: String,
    pub result: String,
    pub registry_manifest: String,
    pub required_configuration: String,
    pub local_configuration: String,
}

/// One sanitized fact in the deterministic causal slice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplainedFact {
    pub id: u32,
    pub stage: String,
    pub kind: String,
    pub origin: String,
    pub result: String,
    pub contribution: String,
    pub value: String,
    pub code: Option<String>,
    pub parents: Vec<u32>,
}

/// Deterministic explanation bound to one verifier execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplanationReport {
    pub schema: String,
    pub explanation_id: String,
    pub decision: String,
    pub code: String,
    pub stage: String,
    pub bindings: ExplanationBindings,
    pub summary: String,
    pub facts: Vec<ExplainedFact>,
    pub remediation: Vec<String>,
    pub disclosure: DisclosurePolicy,
}

/// Explanation construction or encoding error.
#[derive(Debug)]
pub enum ExplanationError {
    Encoding(String),
    MissingFinalFact,
}

impl core::fmt::Display for ExplanationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(message) => formatter.write_str(message),
            Self::MissingFinalFact => formatter.write_str("verification trace has no final fact"),
        }
    }
}

impl std::error::Error for ExplanationError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decision(verification: &ExplainedVerification) -> (VerificationDecision, VerificationCode) {
    match verification.outcome() {
        VerificationOutcome::Authorized(_) => (
            VerificationDecision::Authorized,
            VerificationCode::Authorized,
        ),
        VerificationOutcome::Denied(reason) => (
            VerificationDecision::Denied,
            VerificationCode::Denied(*reason),
        ),
        VerificationOutcome::Indeterminate(requirement) => (
            VerificationDecision::Indeterminate,
            VerificationCode::Indeterminate(*requirement),
        ),
    }
}

fn fact_value(value: FactValue) -> String {
    match value {
        FactValue::Present(value) => format!("present={value}"),
        FactValue::Equal(value) => format!("equal={value}"),
        FactValue::Count { actual, required } => format!("{actual}>={required}"),
        FactValue::Redacted => "redacted".to_owned(),
    }
}

/// Builds a deterministic report without re-running verification.
///
/// # Errors
///
/// Returns a typed error if canonical public inputs cannot be encoded or the
/// trace has no final node.
pub fn explain(
    verification: &ExplainedVerification,
    proof: &[u8],
    action: &CanonicalAction,
    context: &VerifierContext,
    registries: &ImmutableRegistries<'_>,
    disclosure: DisclosurePolicy,
) -> Result<ExplanationReport, ExplanationError> {
    let (decision, code) = decision(verification);
    let final_fact = verification
        .trace()
        .events()
        .last()
        .ok_or(ExplanationError::MissingFinalFact)?;
    let action_bytes = encode_canonical_action(action)
        .map_err(|error| ExplanationError::Encoding(error.to_string()))?;
    let required_configuration = context.configuration();
    let context =
        context_digest(context).map_err(|error| ExplanationError::Encoding(error.to_string()))?;
    let proof = body_digest(proof);
    let action = body_digest(&action_bytes);
    let result_material = [
        decision_code(decision).as_bytes(),
        code.code().as_bytes(),
        proof.as_bytes(),
        action.as_bytes(),
        context.as_bytes(),
    ]
    .concat();
    let result = Sha256::digest(result_material);
    let bindings = ExplanationBindings {
        proof: format!("sha256:{}", hex(proof.as_bytes())),
        action: format!("sha256:{}", hex(action.as_bytes())),
        context: format!("sha256:{}", hex(context.as_bytes())),
        result: format!("sha256:{}", hex(&result)),
        registry_manifest: format!("sha256:{}", hex(registries.manifest_id().as_bytes())),
        required_configuration: format!("sha256:{}", hex(required_configuration.as_bytes())),
        local_configuration: format!("sha256:{}", hex(registries.configuration_id().as_bytes())),
    };
    let mut facts = causal_slice(verification.trace())
        .into_iter()
        .map(|causal| ExplainedFact {
            id: causal.fact.sequence(),
            stage: stage_code(causal.fact.stage()).to_owned(),
            kind: causal.fact.kind().code().to_owned(),
            origin: match causal.fact.origin() {
                FactOrigin::TrustedContext => "trusted-context",
                FactOrigin::Proof => "proof",
                FactOrigin::ExecutableRegistry => "executable-registry",
                FactOrigin::Derived => "derived",
            }
            .to_owned(),
            result: match causal.fact.result() {
                FactResult::Satisfied => "satisfied",
                FactResult::Contradicted => "contradicted",
                FactResult::Unavailable => "unavailable",
                FactResult::NotEvaluated => "not-evaluated",
            }
            .to_owned(),
            contribution: match causal.contribution {
                Contribution::Decisive => "decisive",
                Contribution::NecessarySupport => "necessary-support",
                Contribution::SufficientAlternative => "sufficient-alternative",
                Contribution::ContributingBlocker => "contributing-blocker",
                Contribution::ContextConstraint => "context-constraint",
                Contribution::Informational => "informational",
            }
            .to_owned(),
            value: fact_value(causal.fact.value()),
            code: causal.fact.code().map(|value| value.code().to_owned()),
            parents: causal.fact.parents().to_vec(),
        })
        .collect::<Vec<_>>();
    for kind in [
        FactKind::ContextConfigurationMatches,
        FactKind::RegistryManifestAccepted,
        FactKind::ExpectedPlanMatches,
        FactKind::TrustAnchorAcceptedMethod,
        FactKind::TrustAnchorProfile,
        FactKind::ActionValidity,
        FactKind::ActionAudience,
        FactKind::ActionChallenge,
        FactKind::PrincipalStatus,
        FactKind::GrantStatus,
        FactKind::AssuranceRequirement,
        FactKind::ResourceNamespace,
        FactKind::ProfilePolicy,
        FactKind::ChannelBinding,
        FactKind::MinimumAuthorizedBranches,
        FactKind::MinimumDistinctActors,
        FactKind::MinimumDistinctRoots,
        FactKind::WorkReservation,
    ] {
        if facts.iter().any(|fact| fact.kind == kind.code()) {
            continue;
        }
        facts.push(ExplainedFact {
            id: u32::try_from(facts.len()).unwrap_or(u32::MAX),
            stage: "complete".to_owned(),
            kind: kind.code().to_owned(),
            origin: "trusted-context".to_owned(),
            result: "not-evaluated".to_owned(),
            contribution: "informational".to_owned(),
            value: "redacted".to_owned(),
            code: None,
            parents: Vec::new(),
        });
    }
    let remediation = match code {
        VerificationCode::Indeterminate(requirement) => vec![format!(
            "provide the trusted fact required by {} at the same evaluation boundary",
            requirement.code()
        )],
        VerificationCode::Denied(auths_model::DenialReason::VerifierConfigurationMismatch) => {
            vec!["load the exact verifier configuration committed by the context".to_owned()]
        }
        _ => Vec::new(),
    };
    let summary = format!(
        "{} at {}: {}",
        decision_code(decision),
        stage_code(final_fact.stage()),
        code.code()
    );
    let mut report = ExplanationReport {
        schema: "auths-proof-explanation/v1".to_owned(),
        explanation_id: String::new(),
        decision: decision_code(decision).to_owned(),
        code: code.code().to_owned(),
        stage: stage_code(final_fact.stage()).to_owned(),
        bindings,
        summary,
        facts,
        remediation,
        disclosure,
    };
    let body = serde_json::to_vec(&report)
        .map_err(|error| ExplanationError::Encoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-EXPLANATION\0\x01");
    hasher.update(&body);
    report.explanation_id = format!("sha256:{}", hex(&hasher.finalize()));
    Ok(report)
}

fn decision_code(decision: VerificationDecision) -> &'static str {
    match decision {
        VerificationDecision::Authorized => "authorized",
        VerificationDecision::Denied => "denied",
        VerificationDecision::Indeterminate => "indeterminate",
    }
}

fn stage_code(stage: auths_model::VerificationStage) -> &'static str {
    match stage {
        auths_model::VerificationStage::Decode => "decode",
        auths_model::VerificationStage::Resolve => "resolve",
        auths_model::VerificationStage::PrincipalControl => "principal-control",
        auths_model::VerificationStage::Authority => "authority",
        auths_model::VerificationStage::Complete => "complete",
    }
}

/// Encodes the canonical JSON projection.
///
/// # Errors
///
/// Returns a typed serialization error.
pub fn encode_explanation(report: &ExplanationReport) -> Result<Vec<u8>, ExplanationError> {
    serde_json::to_vec(report).map_err(|error| ExplanationError::Encoding(error.to_string()))
}
