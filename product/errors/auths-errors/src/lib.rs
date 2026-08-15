//! Stable, bounded error and recovery semantics for Auths products.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub const REGISTRY_SCHEMA: &str = "auths.error-registry/1";
pub const ENVELOPE_SCHEMA: &str = "auths.error/1";
pub const MAX_TOKEN_BYTES: usize = 128;
pub const MAX_SUMMARY_BYTES: usize = 256;
pub const MAX_CAUSES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorFamily {
    Configuration,
    Input,
    Runtime,
    Profile,
    Provider,
    State,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetryClass {
    Never,
    Safe,
    Conditional,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectState {
    NotApplied,
    Possible,
    Applied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendedAction {
    CorrectInput,
    CorrectConfiguration,
    InstallCompatibleRuntime,
    RetryExecution,
    SatisfyCondition,
    ResumeAndReconcile,
    InspectReceipt,
    ContactSupport,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CauseCategory {
    Cancelled,
    Conflict,
    CorruptState,
    InvalidResponse,
    LimitExceeded,
    Timeout,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedOutcome {
    pub retry: RetryClass,
    pub effect: EffectState,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDefinition {
    pub code: &'static str,
    pub family: ErrorFamily,
    pub owner: &'static str,
    pub owner_version: u16,
    pub operation: &'static str,
    pub stages: &'static [&'static str],
    pub outcomes: &'static [AllowedOutcome],
    pub recommended_action: RecommendedAction,
    pub allows_execution_reference: bool,
    pub allows_decision_reference: bool,
    pub allows_receipt_reference: bool,
    pub title: &'static str,
    pub explanation: &'static str,
    pub fixture_id: &'static str,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EnteredBoundaries {
    pub approval: bool,
    pub signer: bool,
    pub state: bool,
    pub credential: bool,
    pub provider: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorEnvelopeInput {
    pub code: String,
    pub operation: String,
    pub stage: String,
    pub summary: String,
    pub correlation_id: String,
    pub retry: RetryClass,
    pub effect: EffectState,
    pub entered: EnteredBoundaries,
    pub recommended_action: RecommendedAction,
    pub execution_reference: Option<String>,
    pub decision_reference: Option<String>,
    pub receipt_reference: Option<String>,
    pub causes: Vec<CauseCategory>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub schema: String,
    pub family: ErrorFamily,
    pub code: String,
    pub operation: String,
    pub stage: String,
    pub summary: String,
    pub correlation_id: String,
    pub retry: RetryClass,
    pub effect: EffectState,
    pub entered: EnteredBoundaries,
    pub recommended_action: RecommendedAction,
    pub execution_reference: Option<String>,
    pub decision_reference: Option<String>,
    pub receipt_reference: Option<String>,
    pub causes: Vec<CauseCategory>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorContractError {
    DuplicateCode,
    InvalidNamespace,
    InvalidOwnerVersion,
    InvalidDefinition,
    UnknownCode,
    InvalidField,
    UnsupportedStage,
    UnsupportedOutcome,
    InvalidReference,
    UnsafeRetry,
}

impl ErrorEnvelope {
    /// Parses a registry-bound bounded error projection.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorContractError`] when a field is invalid or the recovery
    /// classification is not allowed by the stable code.
    pub fn parse(input: ErrorEnvelopeInput) -> Result<Self, ErrorContractError> {
        let definition = registry()
            .find(|candidate| candidate.code == input.code)
            .ok_or(ErrorContractError::UnknownCode)?;
        for value in [
            input.code.as_str(),
            input.operation.as_str(),
            input.stage.as_str(),
            input.correlation_id.as_str(),
        ] {
            parse_token(value)?;
        }
        if input.summary.is_empty() || input.summary.len() > MAX_SUMMARY_BYTES {
            return Err(ErrorContractError::InvalidField);
        }
        if input.operation != definition.operation
            || !definition.stages.contains(&input.stage.as_str())
        {
            return Err(ErrorContractError::UnsupportedStage);
        }
        if !definition.outcomes.contains(&AllowedOutcome {
            retry: input.retry,
            effect: input.effect,
        }) {
            return Err(ErrorContractError::UnsupportedOutcome);
        }
        if input.recommended_action != definition.recommended_action {
            return Err(ErrorContractError::InvalidField);
        }
        validate_references(definition, &input)?;
        validate_recovery(&input)?;
        if input.causes.len() > MAX_CAUSES {
            return Err(ErrorContractError::InvalidField);
        }
        Ok(Self {
            schema: ENVELOPE_SCHEMA.into(),
            family: definition.family,
            code: input.code,
            operation: input.operation,
            stage: input.stage,
            summary: input.summary,
            correlation_id: input.correlation_id,
            retry: input.retry,
            effect: input.effect,
            entered: input.entered,
            recommended_action: input.recommended_action,
            execution_reference: input.execution_reference,
            decision_reference: input.decision_reference,
            receipt_reference: input.receipt_reference,
            causes: input.causes,
        })
    }
}

pub fn registry() -> impl Iterator<Item = &'static ErrorDefinition> {
    CORE_ERRORS
        .iter()
        .chain(MCP_ERRORS)
        .chain(PLAN_ERRORS)
        .chain(CUSTODY_ERRORS)
}

/// Operation reported for a code this build's registry does not contain.
pub const UNRECOGNIZED_CODE_OPERATION: &str = "execute";
/// Stage reported for a code this build's registry does not contain.
pub const UNRECOGNIZED_CODE_STAGE: &str = "unrecognized-code";

/// The registry's own classification of one stable code.
///
/// This is the single owner of the answer to "what does this code mean?".
/// Transports and language bindings project it; they never recompute it, and
/// they never define a fourth [`EffectState`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeClassification {
    /// False when this build's registry does not contain the code.
    pub known: bool,
    pub family: ErrorFamily,
    pub operation: &'static str,
    pub stages: &'static [&'static str],
    pub retry: RetryClass,
    pub effect: EffectState,
    pub recommended_action: RecommendedAction,
}

impl CodeClassification {
    /// Reports the first declared stage, which is the only stage for every
    /// single-stage definition and the default for the rest.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        self.stages
            .first()
            .copied()
            .unwrap_or(UNRECOGNIZED_CODE_STAGE)
    }
}

/// Classifies one stable code, failing closed for a code this build does not
/// know.
///
/// An unrecognized code is reported as [`EffectState::Possible`] with
/// [`RetryClass::Unknown`] and [`RecommendedAction::ResumeAndReconcile`]. A
/// newer code minted by a newer Auths build therefore reaches the caller
/// intact and is never swallowed, never downgraded to
/// [`EffectState::NotApplied`], and never renamed to a fourth effect value.
///
/// When a definition permits several outcomes the projection reports the one a
/// caller must plan for: `Possible` dominates `Applied`, which dominates
/// `NotApplied`, because a caller who must reconcile has strictly more work
/// than one who must not repeat, who in turn has strictly more work than one
/// for whom nothing happened.
#[must_use]
pub fn classify(code: &str) -> CodeClassification {
    let Some(definition) = registry().find(|candidate| candidate.code == code) else {
        return CodeClassification {
            known: false,
            family: ErrorFamily::Runtime,
            operation: UNRECOGNIZED_CODE_OPERATION,
            stages: UNRECOGNIZED_CODE_STAGES,
            retry: RetryClass::Unknown,
            effect: EffectState::Possible,
            recommended_action: RecommendedAction::ResumeAndReconcile,
        };
    };
    let mut dominant = definition.outcomes[0];
    for outcome in definition.outcomes {
        if effect_rank(outcome.effect) > effect_rank(dominant.effect) {
            dominant = *outcome;
        }
    }
    CodeClassification {
        known: true,
        family: definition.family,
        operation: definition.operation,
        stages: definition.stages,
        retry: dominant.retry,
        effect: dominant.effect,
        recommended_action: definition.recommended_action,
    }
}

const UNRECOGNIZED_CODE_STAGES: &[&str] = &[UNRECOGNIZED_CODE_STAGE];

const fn effect_rank(effect: EffectState) -> u8 {
    match effect {
        EffectState::NotApplied => 0,
        EffectState::Applied => 1,
        EffectState::Possible => 2,
    }
}

/// Validates namespaces, identities, bounds, and recovery combinations.
///
/// # Errors
///
/// Returns [`ErrorContractError`] for the first invalid registry obligation.
pub fn validate_registry() -> Result<(), ErrorContractError> {
    let mut codes = BTreeSet::new();
    for definition in registry() {
        if !codes.insert(definition.code) {
            return Err(ErrorContractError::DuplicateCode);
        }
        if definition.owner_version == 0 {
            return Err(ErrorContractError::InvalidOwnerVersion);
        }
        if !definition.code.starts_with(definition.owner)
            || definition.code.as_bytes().get(definition.owner.len()) != Some(&b'.')
        {
            return Err(ErrorContractError::InvalidNamespace);
        }
        if definition.stages.is_empty()
            || definition.outcomes.is_empty()
            || definition.title.is_empty()
            || definition.explanation.is_empty()
            || definition.fixture_id.is_empty()
        {
            return Err(ErrorContractError::InvalidDefinition);
        }
        parse_token(definition.code)?;
        parse_token(definition.owner)?;
        parse_token(definition.operation)?;
        for stage in definition.stages {
            parse_token(stage)?;
        }
        for outcome in definition.outcomes {
            if outcome.retry == RetryClass::Safe && outcome.effect != EffectState::NotApplied {
                return Err(ErrorContractError::UnsafeRetry);
            }
            if outcome.effect == EffectState::Possible
                && (outcome.retry != RetryClass::Unknown
                    || definition.recommended_action != RecommendedAction::ResumeAndReconcile
                    || !definition.allows_execution_reference)
            {
                return Err(ErrorContractError::UnsafeRetry);
            }
        }
    }
    Ok(())
}

fn parse_token(value: &str) -> Result<(), ErrorContractError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        return Err(ErrorContractError::InvalidField);
    }
    Ok(())
}

fn validate_references(
    definition: &ErrorDefinition,
    input: &ErrorEnvelopeInput,
) -> Result<(), ErrorContractError> {
    for value in [
        input.execution_reference.as_deref(),
        input.decision_reference.as_deref(),
        input.receipt_reference.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        parse_token(value)?;
    }
    if input.execution_reference.is_some() != definition.allows_execution_reference
        || (input.decision_reference.is_some() && !definition.allows_decision_reference)
        || (input.receipt_reference.is_some() && !definition.allows_receipt_reference)
    {
        return Err(ErrorContractError::InvalidReference);
    }
    Ok(())
}

fn validate_recovery(input: &ErrorEnvelopeInput) -> Result<(), ErrorContractError> {
    if input.retry == RetryClass::Safe && input.effect != EffectState::NotApplied {
        return Err(ErrorContractError::UnsafeRetry);
    }
    if input.effect == EffectState::Possible
        && (input.retry != RetryClass::Unknown
            || input.recommended_action != RecommendedAction::ResumeAndReconcile
            || input.execution_reference.is_none()
            || !input.entered.provider
            || input.receipt_reference.is_some())
    {
        return Err(ErrorContractError::UnsafeRetry);
    }
    if input.effect == EffectState::NotApplied && input.receipt_reference.is_some() {
        return Err(ErrorContractError::InvalidReference);
    }
    Ok(())
}

const NOT_APPLIED_NEVER: &[AllowedOutcome] = &[AllowedOutcome {
    retry: RetryClass::Never,
    effect: EffectState::NotApplied,
}];
const NOT_APPLIED_SAFE: &[AllowedOutcome] = &[AllowedOutcome {
    retry: RetryClass::Safe,
    effect: EffectState::NotApplied,
}];
const NOT_APPLIED_CONDITIONAL: &[AllowedOutcome] = &[AllowedOutcome {
    retry: RetryClass::Conditional,
    effect: EffectState::NotApplied,
}];
const POSSIBLE_UNKNOWN: &[AllowedOutcome] = &[AllowedOutcome {
    retry: RetryClass::Unknown,
    effect: EffectState::Possible,
}];
const APPLIED_CONDITIONAL: &[AllowedOutcome] = &[AllowedOutcome {
    retry: RetryClass::Conditional,
    effect: EffectState::Applied,
}];

const CORE_ERRORS: &[ErrorDefinition] = &[
    definition(
        "core.invalid-configuration",
        ErrorFamily::Configuration,
        "core",
        "create",
        &["configuration"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectConfiguration,
        false,
        "Invalid configuration",
        "A bounded configuration value is invalid.",
        "core-invalid-configuration",
    ),
    definition(
        "core.unsupported-abi",
        ErrorFamily::Runtime,
        "core",
        "create",
        &["runtime"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InstallCompatibleRuntime,
        false,
        "Unsupported ABI",
        "The installed language package and native runtime do not share an ABI.",
        "core-unsupported-abi",
    ),
    definition(
        "core.unsupported-semantic-subject",
        ErrorFamily::Runtime,
        "core",
        "create",
        &["runtime"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InstallCompatibleRuntime,
        false,
        "Unsupported semantic subject",
        "The installed artifacts do not implement the same Auths meaning.",
        "core-unsupported-semantic-subject",
    ),
    definition(
        "core.malformed-input",
        ErrorFamily::Input,
        "core",
        "verify",
        &["parse"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectInput,
        false,
        "Malformed bounded input",
        "The supplied bounded value could not be parsed.",
        "core-malformed-input",
    ),
    definition(
        "core.native-runtime-unavailable",
        ErrorFamily::Runtime,
        "core",
        "create",
        &["runtime"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        false,
        "Native runtime unavailable",
        "The packaged Auths runtime could not be initialized.",
        "core-native-runtime-unavailable",
    ),
    definition(
        "core.forged-execution-reference",
        ErrorFamily::State,
        "core",
        "resume",
        &["reference"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectInput,
        false,
        "Invalid execution reference",
        "The execution reference is malformed, unauthenticated, or bound to different state.",
        "core-forged-execution-reference",
    ),
    definition(
        "core.runtime-conflict",
        ErrorFamily::State,
        "core",
        "execute",
        &["lifecycle-store"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::SatisfyCondition,
        false,
        "Runtime state conflict",
        "A concurrent operation changed the exact workflow state.",
        "core-runtime-conflict",
    ),
    definition(
        "core.runtime-unavailable",
        ErrorFamily::Runtime,
        "core",
        "execute",
        &["lifecycle-store"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        false,
        "Runtime unavailable",
        "The durable runtime could not complete an operation before provider entry.",
        "core-runtime-unavailable",
    ),
    definition(
        "core.runtime-cancelled",
        ErrorFamily::State,
        "core",
        "execute",
        &["cancellation"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        false,
        "Workflow cancelled",
        "The workflow was cancelled with definite non-effect evidence.",
        "core-runtime-cancelled",
    ),
    definition(
        "core.outcome-unknown",
        ErrorFamily::Provider,
        "core",
        "execute",
        &["provider-result"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Provider outcome unknown",
        "The exact effect may have occurred and must be observed before retry.",
        "core-outcome-unknown",
    ),
    definition(
        "core.observation-pending",
        ErrorFamily::Provider,
        "core",
        "resume",
        &["reconciliation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Observation pending",
        "The provider has not exposed conclusive evidence for the exact effect.",
        "core-observation-pending",
    ),
    definition(
        "core.observation-inconclusive",
        ErrorFamily::Provider,
        "core",
        "resume",
        &["reconciliation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Observation inconclusive",
        "Available evidence cannot prove effect or non-effect for the exact request.",
        "core-observation-inconclusive",
    ),
    definition(
        "core.workflow-terminal",
        ErrorFamily::State,
        "core",
        "resume",
        &["lifecycle"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InspectReceipt,
        false,
        "Workflow already terminal",
        "The workflow has already reached an immutable terminal state.",
        "core-workflow-terminal",
    ),
    definition(
        "core.internal-invariant",
        ErrorFamily::Internal,
        "core",
        "execute",
        &["internal"],
        NOT_APPLIED_NEVER,
        RecommendedAction::ContactSupport,
        false,
        "Internal invariant failure",
        "Auths rejected an impossible internal state before an effect.",
        "core-internal-invariant",
    ),
    definition(
        "core.authorization-denied",
        ErrorFamily::Input,
        "core",
        "verify",
        &["authorization"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Authorization denied",
        "Available facts prove the supplied proof does not authorize the exact action.",
        "core-authorization-denied",
    ),
    definition(
        "core.authorization-indeterminate",
        ErrorFamily::State,
        "core",
        "verify",
        &["authorization"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::SatisfyCondition,
        false,
        "Authorization indeterminate",
        "A required authorization fact was unavailable, so no decision was reached before any effect.",
        "core-authorization-indeterminate",
    ),
    definition(
        "core.unauthenticated-principal",
        ErrorFamily::Input,
        "core",
        "create",
        &["authentication"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectInput,
        false,
        "Unauthenticated principal",
        "The request asserts a principal the runtime cannot authenticate, so no authority is issued.",
        "core-unauthenticated-principal",
    ),
];

const MCP_ERRORS: &[ErrorDefinition] = &[
    definition(
        "mcp.invalid-handler-output",
        ErrorFamily::Profile,
        "mcp",
        "execute",
        &["handler-result"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Invalid MCP handler output",
        "The invoked handler returned an invalid or oversized bounded result.",
        "mcp-invalid-handler-output",
    ),
    definition(
        "mcp.handler-failed",
        ErrorFamily::Provider,
        "mcp",
        "execute",
        &["handler"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "MCP handler failed",
        "The invoked handler failed without conclusive no-effect evidence.",
        "mcp-handler-failed",
    ),
    definition(
        "mcp.handler-timeout",
        ErrorFamily::Provider,
        "mcp",
        "execute",
        &["handler"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "MCP handler timed out",
        "The invoked handler did not produce conclusive effect evidence before its deadline.",
        "mcp-handler-timeout",
    ),
    definition(
        "mcp.cancelled-before-entry",
        ErrorFamily::Profile,
        "mcp",
        "execute",
        &["reservation"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        false,
        "MCP execution cancelled",
        "Execution was cancelled before the handler was entered.",
        "mcp-cancelled-before-entry",
    ),
    definition(
        "mcp.reservation-conflict",
        ErrorFamily::State,
        "mcp",
        "execute",
        &["reservation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "MCP reservation conflict",
        "A different committed request already owns the execution record.",
        "mcp-reservation-conflict",
    ),
    definition(
        "mcp.replay",
        ErrorFamily::State,
        "mcp",
        "execute",
        &["reservation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InspectReceipt,
        false,
        "MCP replay blocked",
        "The committed MCP execution has already reached a terminal state.",
        "mcp-replay",
    ),
    definition(
        "mcp.receipt-persist-failed",
        ErrorFamily::State,
        "mcp",
        "execute",
        &["receipt"],
        APPLIED_CONDITIONAL,
        RecommendedAction::ContactSupport,
        true,
        "MCP receipt persistence failed",
        "The effect was observed but its execution receipt was not durably persisted.",
        "mcp-receipt-persist-failed",
    ),
    definition(
        "mcp.reconciliation-pending",
        ErrorFamily::Provider,
        "mcp",
        "resume",
        &["reconciliation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "MCP reconciliation pending",
        "The profile still lacks conclusive effect evidence.",
        "mcp-reconciliation-pending",
    ),
];

const PLAN_ERRORS: &[ErrorDefinition] = &[
    definition(
        "plan.member-interrupted",
        ErrorFamily::Provider,
        "plan",
        "execute",
        &["plan-member"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Plan member interrupted",
        "The current ordered member may have applied and later members remain blocked.",
        "plan-member-interrupted",
    ),
    definition(
        "plan.member-failed-before-entry",
        ErrorFamily::Profile,
        "plan",
        "execute",
        &["plan-member"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::SatisfyCondition,
        false,
        "Plan member blocked",
        "The current ordered member failed before provider entry.",
        "plan-member-failed-before-entry",
    ),
    definition(
        "plan.resume-reference-invalid",
        ErrorFamily::State,
        "plan",
        "resume",
        &["reference"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectInput,
        false,
        "Plan reference invalid",
        "The supplied reference is not bound to this ordered plan execution.",
        "plan-resume-reference-invalid",
    ),
    definition(
        "plan.reconciliation-pending",
        ErrorFamily::Provider,
        "plan",
        "resume",
        &["reconciliation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Plan reconciliation pending",
        "The current member remains outcome-unknown and later members remain blocked.",
        "plan-reconciliation-pending",
    ),
    definition(
        "plan.action-substituted",
        ErrorFamily::Input,
        "plan",
        "execute",
        &["plan-commitment"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectInput,
        false,
        "Plan action substituted",
        "The current ordered member does not match the approved plan commitment.",
        "plan-action-substituted",
    ),
];

const CUSTODY_ERRORS: &[ErrorDefinition] = &[
    definition(
        "custody.denied",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody request denied",
        "The configured custody provider denied the exact signing request.",
        "custody-denied",
    ),
    definition(
        "custody.cancelled",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody request cancelled",
        "The exact signing request was cancelled before Auths accepted a signature.",
        "custody-cancelled",
    ),
    definition(
        "custody.throttled",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody provider throttled",
        "The custody provider refused the request under its current rate policy.",
        "custody-throttled",
    ),
    definition(
        "custody.unavailable",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody provider unavailable",
        "The custody provider could not conclusively service the exact signing request.",
        "custody-unavailable",
    ),
    definition(
        "custody.revoked-key",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["key-lifecycle"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectConfiguration,
        false,
        "Custody key revoked",
        "The configured key version is permanently barred from new signing.",
        "custody-revoked-key",
    ),
    definition(
        "custody.disabled-key",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["key-lifecycle"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody key disabled",
        "The configured key version is not permitted to create new signatures.",
        "custody-disabled-key",
    ),
    definition(
        "custody.provider-unknown",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::ContactSupport,
        false,
        "Custody outcome unknown",
        "The provider did not prove whether it produced a signature for the exact request.",
        "custody-provider-unknown",
    ),
    definition(
        "custody.invalid-provider-response",
        ErrorFamily::Provider,
        "custody",
        "sign",
        &["provider-response"],
        NOT_APPLIED_NEVER,
        RecommendedAction::ContactSupport,
        false,
        "Invalid custody response",
        "The provider response could not be parsed as a bounded signing response.",
        "custody-invalid-provider-response",
    ),
    custody_validation(
        "custody.request-mismatch",
        "Signing request mismatch",
        "The provider response names a different signing request.",
        "custody-request-mismatch",
    ),
    custody_validation(
        "custody.principal-mismatch",
        "Signing principal mismatch",
        "The provider response names a different signing principal.",
        "custody-principal-mismatch",
    ),
    custody_validation(
        "custody.descriptor-mismatch",
        "Signing descriptor mismatch",
        "The response signature method or suite differs from the frozen descriptor.",
        "custody-descriptor-mismatch",
    ),
    custody_validation(
        "custody.key-version-mismatch",
        "Signing key version mismatch",
        "The provider response names a different key version.",
        "custody-key-version-mismatch",
    ),
    custody_validation(
        "custody.transaction-mismatch",
        "Signing transaction mismatch",
        "The provider response is bound to a different Auths transaction.",
        "custody-transaction-mismatch",
    ),
    custody_validation(
        "custody.malformed-signature",
        "Malformed provider signature",
        "The returned signature is not a bounded encoding accepted by its suite.",
        "custody-malformed-signature",
    ),
    custody_validation(
        "custody.non-canonical-signature",
        "Non-canonical provider signature",
        "The returned signature has a different canonical representation.",
        "custody-non-canonical-signature",
    ),
    custody_validation(
        "custody.signature-verification-failed",
        "Provider signature invalid",
        "The returned signature does not verify over the exact Auths preimage.",
        "custody-signature-verification-failed",
    ),
    custody_validation(
        "custody.evidence-mismatch",
        "Custody evidence mismatch",
        "The returned evidence does not match the frozen custody descriptor.",
        "custody-evidence-mismatch",
    ),
    definition(
        "custody.lifecycle-not-permitted",
        ErrorFamily::State,
        "custody",
        "sign",
        &["key-lifecycle"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Custody lifecycle blocks signing",
        "The exact key lifecycle state does not permit new signatures.",
        "custody-lifecycle-not-permitted",
    ),
];

const fn custody_validation(
    code: &'static str,
    title: &'static str,
    explanation: &'static str,
    fixture_id: &'static str,
) -> ErrorDefinition {
    definition(
        code,
        ErrorFamily::Input,
        "custody",
        "sign",
        &["central-validation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::ContactSupport,
        false,
        title,
        explanation,
        fixture_id,
    )
}

#[allow(clippy::too_many_arguments)]
const fn definition(
    code: &'static str,
    family: ErrorFamily,
    owner: &'static str,
    operation: &'static str,
    stages: &'static [&'static str],
    outcomes: &'static [AllowedOutcome],
    recommended_action: RecommendedAction,
    allows_execution_reference: bool,
    title: &'static str,
    explanation: &'static str,
    fixture_id: &'static str,
) -> ErrorDefinition {
    ErrorDefinition {
        code,
        family,
        owner,
        owner_version: 1,
        operation,
        stages,
        outcomes,
        recommended_action,
        allows_execution_reference,
        allows_decision_reference: false,
        allows_receipt_reference: false,
        title,
        explanation,
        fixture_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn input(code: &str) -> ErrorEnvelopeInput {
        let definition = registry().find(|entry| entry.code == code).unwrap();
        let outcome = definition.outcomes[0];
        ErrorEnvelopeInput {
            code: code.into(),
            operation: definition.operation.into(),
            stage: definition.stages[0].into(),
            summary: definition.title.into(),
            correlation_id: "correlation-1".into(),
            retry: outcome.retry,
            effect: outcome.effect,
            entered: EnteredBoundaries {
                provider: outcome.effect == EffectState::Possible,
                ..EnteredBoundaries::default()
            },
            recommended_action: definition.recommended_action,
            execution_reference: definition
                .allows_execution_reference
                .then(|| "execution-reference-1".into()),
            decision_reference: None,
            receipt_reference: None,
            causes: vec![CauseCategory::Unknown],
        }
    }

    #[test]
    fn registry_is_closed_and_valid() {
        assert_eq!(validate_registry(), Ok(()));
        for definition in registry() {
            assert!(ErrorEnvelope::parse(input(definition.code)).is_ok());
        }
    }

    #[test]
    fn unknown_effect_never_claims_safe_retry() {
        let mut value = input("mcp.handler-timeout");
        value.retry = RetryClass::Safe;
        assert_eq!(
            ErrorEnvelope::parse(value),
            Err(ErrorContractError::UnsupportedOutcome)
        );
    }

    #[test]
    fn classify_projects_the_registry_for_every_known_code() {
        for definition in registry() {
            let classification = classify(definition.code);
            assert!(
                classification.known,
                "{} is in the registry",
                definition.code
            );
            assert_eq!(classification.family, definition.family);
            assert_eq!(classification.operation, definition.operation);
            assert_eq!(classification.stages, definition.stages);
            assert_eq!(
                classification.recommended_action,
                definition.recommended_action
            );
            assert!(
                definition.outcomes.contains(&AllowedOutcome {
                    retry: classification.retry,
                    effect: classification.effect,
                }),
                "{} projected an outcome it does not declare",
                definition.code
            );
            for outcome in definition.outcomes {
                assert!(
                    effect_rank(outcome.effect) <= effect_rank(classification.effect),
                    "{} projected a less demanding effect than it permits",
                    definition.code
                );
            }
        }
    }

    #[test]
    fn classify_fails_closed_for_a_code_this_build_does_not_know() {
        let classification = classify("future.not-yet-invented");
        assert!(!classification.known);
        assert_eq!(classification.effect, EffectState::Possible);
        assert_eq!(classification.retry, RetryClass::Unknown);
        assert_eq!(
            classification.recommended_action,
            RecommendedAction::ResumeAndReconcile
        );
        assert_eq!(classification.operation, UNRECOGNIZED_CODE_OPERATION);
        assert_eq!(classification.stage(), UNRECOGNIZED_CODE_STAGE);
    }

    #[test]
    fn classify_never_downgrades_an_unknown_code_to_not_applied() {
        for code in [
            "",
            "core.",
            "mcp.handler-failed-v2",
            "x".repeat(200).as_str(),
        ] {
            let classification = classify(code);
            if !classification.known {
                assert_eq!(
                    classification.effect,
                    EffectState::Possible,
                    "unknown code {code:?} must fail closed"
                );
            }
        }
    }

    #[test]
    fn possible_effect_requires_provider_entry_and_reference() {
        let mut value = input("mcp.handler-failed");
        value.entered.provider = false;
        assert_eq!(
            ErrorEnvelope::parse(value),
            Err(ErrorContractError::UnsafeRetry)
        );
    }
}
