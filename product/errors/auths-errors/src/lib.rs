//! Stable, bounded error and recovery semantics for Auths products.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use minicbor::{Decoder, Encoder, data::Type};
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
    /// Decodes and byte-canonicalizes one bounded `auths.error/1` projection.
    ///
    /// This is the inverse of [`Self::to_canonical_cbor`]. It deliberately
    /// parses the fixed key order rather than accepting a generic CBOR map so
    /// protected readers can reject duplicate, reordered, or unknown fields.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorContractError`] when the input is oversized, malformed,
    /// noncanonical, or violates the stable error contract.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErrorContractError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(ErrorContractError::InvalidField);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.map().map_err(decode_field)? != Some(15) {
            return Err(ErrorContractError::InvalidField);
        }
        expect_text_key(&mut decoder, "code")?;
        let code = decode_text(&mut decoder)?;
        expect_text_key(&mut decoder, "retry")?;
        let retry = parse_retry(&decode_text(&mut decoder)?)?;
        expect_text_key(&mut decoder, "stage")?;
        let stage = decode_text(&mut decoder)?;
        expect_text_key(&mut decoder, "causes")?;
        let cause_count = decoder
            .array()
            .map_err(decode_field)?
            .ok_or(ErrorContractError::InvalidField)?;
        if cause_count > MAX_CAUSES as u64 {
            return Err(ErrorContractError::InvalidField);
        }
        let causes = (0..cause_count)
            .map(|_| parse_cause(&decode_text(&mut decoder)?))
            .collect::<Result<Vec<_>, _>>()?;
        expect_text_key(&mut decoder, "effect")?;
        let effect = parse_effect(&decode_text(&mut decoder)?)?;
        expect_text_key(&mut decoder, "family")?;
        let family = parse_family(&decode_text(&mut decoder)?)?;
        expect_text_key(&mut decoder, "schema")?;
        if decode_text(&mut decoder)? != ENVELOPE_SCHEMA {
            return Err(ErrorContractError::InvalidField);
        }
        expect_text_key(&mut decoder, "entered")?;
        if decoder.map().map_err(decode_field)? != Some(5) {
            return Err(ErrorContractError::InvalidField);
        }
        expect_text_key(&mut decoder, "state")?;
        let entered_state = decoder.bool().map_err(decode_field)?;
        expect_text_key(&mut decoder, "signer")?;
        let signer = decoder.bool().map_err(decode_field)?;
        expect_text_key(&mut decoder, "approval")?;
        let approval = decoder.bool().map_err(decode_field)?;
        expect_text_key(&mut decoder, "provider")?;
        let provider = decoder.bool().map_err(decode_field)?;
        expect_text_key(&mut decoder, "credential")?;
        let credential = decoder.bool().map_err(decode_field)?;
        expect_text_key(&mut decoder, "summary")?;
        let summary = decode_text(&mut decoder)?;
        expect_text_key(&mut decoder, "operation")?;
        let operation = decode_text(&mut decoder)?;
        expect_text_key(&mut decoder, "correlationId")?;
        let correlation_id = decode_text(&mut decoder)?;
        expect_text_key(&mut decoder, "receiptReference")?;
        let receipt_reference = decode_optional_text(&mut decoder)?;
        expect_text_key(&mut decoder, "decisionReference")?;
        let decision_reference = decode_optional_text(&mut decoder)?;
        expect_text_key(&mut decoder, "recommendedAction")?;
        let recommended_action = parse_action(&decode_text(&mut decoder)?)?;
        expect_text_key(&mut decoder, "executionReference")?;
        let execution_reference = decode_optional_text(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(ErrorContractError::InvalidField);
        }
        let value = Self::parse(ErrorEnvelopeInput {
            code,
            operation,
            stage,
            summary,
            correlation_id,
            retry,
            effect,
            entered: EnteredBoundaries {
                approval,
                signer,
                state: entered_state,
                credential,
                provider,
            },
            recommended_action,
            execution_reference,
            decision_reference,
            receipt_reference,
            causes,
        })?;
        if value.family != family || value.to_canonical_cbor()?.as_slice() != bytes {
            return Err(ErrorContractError::InvalidField);
        }
        Ok(value)
    }

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

    /// Encodes the exact canonical `auths.error/1` CBOR wire projection.
    ///
    /// Optional references are present as canonical nulls. Host-only display
    /// fields are never serialized.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorContractError`] when this value no longer matches the
    /// closed registry or cannot be encoded within the canonical bounds.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErrorContractError> {
        // Re-parse to ensure callers cannot serialize a deserialized value
        // whose fields no longer match the active closed registry.
        Self::parse(ErrorEnvelopeInput {
            code: self.code.clone(),
            operation: self.operation.clone(),
            stage: self.stage.clone(),
            summary: self.summary.clone(),
            correlation_id: self.correlation_id.clone(),
            retry: self.retry,
            effect: self.effect,
            entered: self.entered,
            recommended_action: self.recommended_action,
            execution_reference: self.execution_reference.clone(),
            decision_reference: self.decision_reference.clone(),
            receipt_reference: self.receipt_reference.clone(),
            causes: self.causes.clone(),
        })?;
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .map(15)
            .map_err(|_| ErrorContractError::InvalidField)?;
        // Canonical CBOR text-key order: encoded length, then byte order.
        text_pair(&mut encoder, "code", &self.code)?;
        text_pair(&mut encoder, "retry", retry_text(self.retry))?;
        text_pair(&mut encoder, "stage", &self.stage)?;
        encoder
            .str("causes")
            .and_then(|value| value.array(self.causes.len() as u64))
            .map_err(|_| ErrorContractError::InvalidField)?;
        for cause in &self.causes {
            encoder
                .str(cause_text(*cause))
                .map_err(|_| ErrorContractError::InvalidField)?;
        }
        text_pair(&mut encoder, "effect", effect_text(self.effect))?;
        text_pair(&mut encoder, "family", family_text(self.family))?;
        text_pair(&mut encoder, "schema", &self.schema)?;
        encoder
            .str("entered")
            .and_then(|value| value.map(5))
            .map_err(|_| ErrorContractError::InvalidField)?;
        bool_pair(&mut encoder, "state", self.entered.state)?;
        bool_pair(&mut encoder, "signer", self.entered.signer)?;
        bool_pair(&mut encoder, "approval", self.entered.approval)?;
        bool_pair(&mut encoder, "provider", self.entered.provider)?;
        bool_pair(&mut encoder, "credential", self.entered.credential)?;
        text_pair(&mut encoder, "summary", &self.summary)?;
        text_pair(&mut encoder, "operation", &self.operation)?;
        text_pair(&mut encoder, "correlationId", &self.correlation_id)?;
        optional_text_pair(
            &mut encoder,
            "receiptReference",
            self.receipt_reference.as_deref(),
        )?;
        optional_text_pair(
            &mut encoder,
            "decisionReference",
            self.decision_reference.as_deref(),
        )?;
        text_pair(
            &mut encoder,
            "recommendedAction",
            action_text(self.recommended_action),
        )?;
        optional_text_pair(
            &mut encoder,
            "executionReference",
            self.execution_reference.as_deref(),
        )?;
        let bytes = encoder.into_writer();
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(ErrorContractError::InvalidField);
        }
        Ok(bytes)
    }
}

fn decode_field(_error: minicbor::decode::Error) -> ErrorContractError {
    ErrorContractError::InvalidField
}

fn expect_text_key(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), ErrorContractError> {
    if decoder.str().map_err(decode_field)? != expected {
        return Err(ErrorContractError::InvalidField);
    }
    Ok(())
}

fn decode_text(decoder: &mut Decoder<'_>) -> Result<String, ErrorContractError> {
    decoder.str().map(String::from).map_err(decode_field)
}

fn decode_optional_text(decoder: &mut Decoder<'_>) -> Result<Option<String>, ErrorContractError> {
    if decoder.datatype().map_err(decode_field)? == Type::Null {
        decoder.null().map_err(decode_field)?;
        Ok(None)
    } else {
        decode_text(decoder).map(Some)
    }
}

fn parse_family(value: &str) -> Result<ErrorFamily, ErrorContractError> {
    match value {
        "configuration" => Ok(ErrorFamily::Configuration),
        "input" => Ok(ErrorFamily::Input),
        "runtime" => Ok(ErrorFamily::Runtime),
        "profile" => Ok(ErrorFamily::Profile),
        "provider" => Ok(ErrorFamily::Provider),
        "state" => Ok(ErrorFamily::State),
        "internal" => Ok(ErrorFamily::Internal),
        _ => Err(ErrorContractError::InvalidField),
    }
}

fn parse_retry(value: &str) -> Result<RetryClass, ErrorContractError> {
    match value {
        "never" => Ok(RetryClass::Never),
        "safe" => Ok(RetryClass::Safe),
        "conditional" => Ok(RetryClass::Conditional),
        "unknown" => Ok(RetryClass::Unknown),
        _ => Err(ErrorContractError::InvalidField),
    }
}

fn parse_effect(value: &str) -> Result<EffectState, ErrorContractError> {
    match value {
        "not-applied" => Ok(EffectState::NotApplied),
        "possible" => Ok(EffectState::Possible),
        "applied" => Ok(EffectState::Applied),
        _ => Err(ErrorContractError::InvalidField),
    }
}

fn parse_action(value: &str) -> Result<RecommendedAction, ErrorContractError> {
    match value {
        "correct-input" => Ok(RecommendedAction::CorrectInput),
        "correct-configuration" => Ok(RecommendedAction::CorrectConfiguration),
        "install-compatible-runtime" => Ok(RecommendedAction::InstallCompatibleRuntime),
        "retry-execution" => Ok(RecommendedAction::RetryExecution),
        "satisfy-condition" => Ok(RecommendedAction::SatisfyCondition),
        "resume-and-reconcile" => Ok(RecommendedAction::ResumeAndReconcile),
        "inspect-receipt" => Ok(RecommendedAction::InspectReceipt),
        "contact-support" => Ok(RecommendedAction::ContactSupport),
        _ => Err(ErrorContractError::InvalidField),
    }
}

fn parse_cause(value: &str) -> Result<CauseCategory, ErrorContractError> {
    match value {
        "cancelled" => Ok(CauseCategory::Cancelled),
        "conflict" => Ok(CauseCategory::Conflict),
        "corrupt-state" => Ok(CauseCategory::CorruptState),
        "invalid-response" => Ok(CauseCategory::InvalidResponse),
        "limit-exceeded" => Ok(CauseCategory::LimitExceeded),
        "timeout" => Ok(CauseCategory::Timeout),
        "unavailable" => Ok(CauseCategory::Unavailable),
        "unknown" => Ok(CauseCategory::Unknown),
        _ => Err(ErrorContractError::InvalidField),
    }
}

fn text_pair(
    encoder: &mut Encoder<Vec<u8>>,
    key: &str,
    value: &str,
) -> Result<(), ErrorContractError> {
    encoder
        .str(key)
        .and_then(|encoder| encoder.str(value))
        .map_err(|_| ErrorContractError::InvalidField)?;
    Ok(())
}

fn bool_pair(
    encoder: &mut Encoder<Vec<u8>>,
    key: &str,
    value: bool,
) -> Result<(), ErrorContractError> {
    encoder
        .str(key)
        .and_then(|encoder| encoder.bool(value))
        .map_err(|_| ErrorContractError::InvalidField)?;
    Ok(())
}

fn optional_text_pair(
    encoder: &mut Encoder<Vec<u8>>,
    key: &str,
    value: Option<&str>,
) -> Result<(), ErrorContractError> {
    encoder
        .str(key)
        .map_err(|_| ErrorContractError::InvalidField)?;
    match value {
        Some(value) => {
            encoder
                .str(value)
                .map_err(|_| ErrorContractError::InvalidField)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| ErrorContractError::InvalidField)?;
        }
    }
    Ok(())
}

const fn family_text(value: ErrorFamily) -> &'static str {
    match value {
        ErrorFamily::Configuration => "configuration",
        ErrorFamily::Input => "input",
        ErrorFamily::Runtime => "runtime",
        ErrorFamily::Profile => "profile",
        ErrorFamily::Provider => "provider",
        ErrorFamily::State => "state",
        ErrorFamily::Internal => "internal",
    }
}

const fn retry_text(value: RetryClass) -> &'static str {
    match value {
        RetryClass::Never => "never",
        RetryClass::Safe => "safe",
        RetryClass::Conditional => "conditional",
        RetryClass::Unknown => "unknown",
    }
}

const fn effect_text(value: EffectState) -> &'static str {
    match value {
        EffectState::NotApplied => "not-applied",
        EffectState::Possible => "possible",
        EffectState::Applied => "applied",
    }
}

const fn action_text(value: RecommendedAction) -> &'static str {
    match value {
        RecommendedAction::CorrectInput => "correct-input",
        RecommendedAction::CorrectConfiguration => "correct-configuration",
        RecommendedAction::InstallCompatibleRuntime => "install-compatible-runtime",
        RecommendedAction::RetryExecution => "retry-execution",
        RecommendedAction::SatisfyCondition => "satisfy-condition",
        RecommendedAction::ResumeAndReconcile => "resume-and-reconcile",
        RecommendedAction::InspectReceipt => "inspect-receipt",
        RecommendedAction::ContactSupport => "contact-support",
    }
}

const fn cause_text(value: CauseCategory) -> &'static str {
    match value {
        CauseCategory::Cancelled => "cancelled",
        CauseCategory::Conflict => "conflict",
        CauseCategory::CorruptState => "corrupt-state",
        CauseCategory::InvalidResponse => "invalid-response",
        CauseCategory::LimitExceeded => "limit-exceeded",
        CauseCategory::Timeout => "timeout",
        CauseCategory::Unavailable => "unavailable",
        CauseCategory::Unknown => "unknown",
    }
}

pub fn registry() -> impl Iterator<Item = &'static ErrorDefinition> {
    CORE_ERRORS
        .iter()
        .chain(PROFILE_CLIENT_ERRORS)
        .chain(PROFILE_DOMAIN_ERRORS)
        .chain(PUBLIC_API_ERRORS)
        .chain(IDENTITY_ERRORS)
        .chain(GITHUB_ERRORS)
        .chain(MCP_ERRORS)
        .chain(PLAN_ERRORS)
        .chain(CUSTODY_ERRORS)
}

/// Registry code carried by an authorization outcome that denied the request.
pub const AUTHORIZATION_DENIED_CODE: &str = "core.authorization-denied";
/// Registry code carried by an authorization outcome the verifier could not decide.
pub const AUTHORIZATION_INDETERMINATE_CODE: &str = "core.authorization-indeterminate";

/// The stable registry codes for outcomes that do not carry one themselves.
///
/// A verifier verdict names itself with a kernel diagnostic (`permission-not-granted`)
/// and a runtime outcome names itself with a state word (`denied`). Neither is a
/// registry code, so something has to say which registry code the outcome
/// carries. That answer is here, once, and every consumer — the reference
/// runtime, and both language bindings through the generated projection — reads
/// it rather than restating it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeCodes {
    pub denied: &'static str,
    pub indeterminate: &'static str,
}

#[must_use]
pub const fn outcome_codes() -> OutcomeCodes {
    OutcomeCodes {
        denied: AUTHORIZATION_DENIED_CODE,
        indeterminate: AUTHORIZATION_INDETERMINATE_CODE,
    }
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
        let code_namespace = definition
            .owner
            .split_once('-')
            .map_or(definition.owner, |(domain, _)| domain);
        let owned_namespace = definition.code.starts_with(code_namespace)
            && definition.code.as_bytes().get(code_namespace.len()) == Some(&b'.');
        let profile_client_namespace = definition.owner == "profile-client"
            && ["client.", "connection.", "operation."]
                .iter()
                .any(|prefix| definition.code.starts_with(prefix));
        if !owned_namespace && !profile_client_namespace {
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
            let ordinary_recovery = outcome.effect != EffectState::Possible
                || outcome.retry == RetryClass::Unknown
                    && definition.recommended_action == RecommendedAction::ResumeAndReconcile
                    && definition.allows_execution_reference;
            let terminal_integrity_failure = outcome.effect == EffectState::Possible
                && definition.code == "core.terminal-receipt-integrity-failed"
                && outcome.retry == RetryClass::Never
                && definition.recommended_action == RecommendedAction::ContactSupport
                && definition.allows_execution_reference;
            if !ordinary_recovery && !terminal_integrity_failure {
                return Err(ErrorContractError::UnsafeRetry);
            }
        }
    }
    Ok(())
}

fn parse_token(value: &str) -> Result<(), ErrorContractError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
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
    if input.effect == EffectState::Possible {
        let ordinary_recovery = input.retry == RetryClass::Unknown
            && input.recommended_action == RecommendedAction::ResumeAndReconcile
            && input.execution_reference.is_some()
            && input.entered.provider
            && input.receipt_reference.is_none();
        let terminal_integrity_failure = input.code == "core.terminal-receipt-integrity-failed"
            && input.retry == RetryClass::Never
            && input.recommended_action == RecommendedAction::ContactSupport
            && input.execution_reference.is_some()
            && input.entered.provider;
        if !ordinary_recovery && !terminal_integrity_failure {
            return Err(ErrorContractError::UnsafeRetry);
        }
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
const TERMINAL_RECEIPT_INTEGRITY: &[AllowedOutcome] = &[
    AllowedOutcome {
        retry: RetryClass::Never,
        effect: EffectState::NotApplied,
    },
    AllowedOutcome {
        retry: RetryClass::Never,
        effect: EffectState::Possible,
    },
    AllowedOutcome {
        retry: RetryClass::Never,
        effect: EffectState::Applied,
    },
];

const PROFILE_CLIENT_ERRORS: &[ErrorDefinition] = &[
    profile_client_error(
        "client.agent-unavailable",
        ErrorFamily::Runtime,
        "connect",
        &["local-agent"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::CorrectConfiguration,
        false,
        false,
        false,
        "Local Auths agent unavailable",
        "The SDK could not establish an authenticated local-agent session.",
        "client-agent-unavailable",
    ),
    profile_client_error(
        "client.profile-unavailable",
        ErrorFamily::Configuration,
        "connect",
        &["negotiation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InstallCompatibleRuntime,
        false,
        false,
        false,
        "Profile unavailable",
        "The local agent did not advertise the required profile and version.",
        "client-profile-unavailable",
    ),
    profile_client_error(
        "client.profile-contract-mismatch",
        ErrorFamily::Configuration,
        "connect",
        &["negotiation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InstallCompatibleRuntime,
        false,
        false,
        false,
        "Profile contract mismatch",
        "The generated client and runtime do not share the same profile contract digest.",
        "client-profile-contract-mismatch",
    ),
    profile_client_error(
        "connection.contract-mismatch",
        ErrorFamily::Configuration,
        "execute",
        &["connection-resolution"],
        NOT_APPLIED_NEVER,
        RecommendedAction::InstallCompatibleRuntime,
        false,
        false,
        false,
        "Provider connection contract mismatch",
        "The profile runtime and selected provider connection do not share the required immutable connection contract.",
        "connection-contract-mismatch",
    ),
    profile_client_error(
        "connection.credential-unavailable",
        ErrorFamily::Runtime,
        "execute",
        &["credential"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        true,
        true,
        true,
        "Provider credential unavailable before entry",
        "The bound provider credential could not be leased and durable state proves that the provider was not entered.",
        "connection-credential-unavailable",
    ),
    profile_client_error(
        "connection.unavailable",
        ErrorFamily::Configuration,
        "execute",
        &["connection-resolution"],
        NOT_APPLIED_NEVER,
        RecommendedAction::CorrectConfiguration,
        false,
        false,
        false,
        "Provider connection unavailable",
        "No active provider connection matching the requested or default alias is authorized for this workload and profile.",
        "connection-unavailable",
    ),
    profile_client_error(
        "operation.admission-exhausted",
        ErrorFamily::State,
        "execute",
        &["admission"],
        NOT_APPLIED_CONDITIONAL,
        RecommendedAction::RetryExecution,
        false,
        false,
        false,
        "Operation admission exhausted",
        "The bounded operation capacity was exhausted before provider entry.",
        "operation-admission-exhausted",
    ),
    profile_client_error(
        "operation.idempotency-conflict",
        ErrorFamily::State,
        "execute",
        &["reservation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        true,
        true,
        "Idempotency commitment conflict",
        "The key names an existing operation with a different commitment; recover that operation.",
        "operation-idempotency-conflict",
    ),
    profile_client_error(
        "operation.outcome-unknown",
        ErrorFamily::State,
        "execute",
        &["provider"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        true,
        true,
        "Operation outcome unknown",
        "The provider may have applied the exact operation; recover it instead of retrying.",
        "operation-outcome-unknown",
    ),
    profile_client_error(
        "operation.recovery-unavailable",
        ErrorFamily::State,
        "recover",
        &["reconciliation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        true,
        true,
        "Operation recovery unavailable",
        "Recovery could not establish the effect and the original operation remains possible.",
        "operation-recovery-unavailable",
    ),
    profile_client_error(
        "operation.timed-out",
        ErrorFamily::Runtime,
        "execute",
        &["pre-provider"],
        NOT_APPLIED_SAFE,
        RecommendedAction::RetryExecution,
        true,
        true,
        true,
        "Operation timed out before provider entry",
        "The bounded deadline expired and durable state proves that the provider was not entered.",
        "operation-timed-out",
    ),
];

// Generated-profile fragments are selected by the build-time package roster.
// This prelaunch cut keeps the Rust projection explicit until the fragment
// generator replaces this table atomically; the stable codes and axes already
// match the checked-in fragment sources.
const PROFILE_DOMAIN_ERRORS: &[ErrorDefinition] = &[
    definition(
        "opentofu.plan-preflight-denied",
        ErrorFamily::Profile,
        "opentofu-plan-preflight",
        "execute",
        &["profile-evaluation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "OpenTofu plan preflight denied",
        "The OpenTofu plan preflight failed its exact profile evaluation or protected-planner checks.",
        "opentofu-plan-preflight-denied",
    ),
    definition(
        "opentofu.plan-preflight-outcome-unknown",
        ErrorFamily::Provider,
        "opentofu-plan-preflight",
        "execute",
        &["provider-observation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "OpenTofu plan preflight outcome unknown",
        "Recovery must establish whether the OpenTofu prepared-plan record and artifact became ready.",
        "opentofu-plan-preflight-outcome-unknown",
    ),
    definition(
        "opentofu.saved-plan-denied",
        ErrorFamily::Profile,
        "opentofu-saved-plan",
        "execute",
        &["profile-evaluation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "OpenTofu saved plan denied",
        "The saved plan failed its exact OpenTofu profile evaluation.",
        "opentofu-saved-plan-denied",
    ),
    definition(
        "opentofu.apply-outcome-unknown",
        ErrorFamily::Provider,
        "opentofu-saved-plan",
        "execute",
        &["provider-observation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "OpenTofu apply outcome unknown",
        "The OpenTofu apply must be reconciled before another execution.",
        "opentofu-apply-outcome-unknown",
    ),
    definition(
        "postgresql.preflight-denied",
        ErrorFamily::Profile,
        "postgresql-update-preflight",
        "execute",
        &["profile-evaluation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "PostgreSQL update preflight denied",
        "The PostgreSQL update preflight failed its exact profile evaluation or protected discovery checks.",
        "postgresql-update-preflight-denied",
    ),
    definition(
        "postgresql.preflight-outcome-unknown",
        ErrorFamily::Provider,
        "postgresql-update-preflight",
        "execute",
        &["provider-observation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "PostgreSQL update preflight outcome unknown",
        "Recovery must establish whether the PostgreSQL prepared-update record became ready.",
        "postgresql-update-preflight-outcome-unknown",
    ),
    definition(
        "postgresql.update-denied",
        ErrorFamily::Profile,
        "postgresql-bounded-update",
        "execute",
        &["profile-evaluation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "PostgreSQL update denied",
        "The bounded PostgreSQL update failed its exact profile evaluation.",
        "postgresql-update-denied",
    ),
    definition(
        "postgresql.update-outcome-unknown",
        ErrorFamily::Provider,
        "postgresql-bounded-update",
        "execute",
        &["provider-observation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "PostgreSQL update outcome unknown",
        "The PostgreSQL transaction outcome must be reconciled before another execution.",
        "postgresql-update-outcome-unknown",
    ),
    definition(
        "stripe.refund-denied",
        ErrorFamily::Profile,
        "stripe-refund",
        "execute",
        &["profile-evaluation"],
        NOT_APPLIED_NEVER,
        RecommendedAction::SatisfyCondition,
        false,
        "Stripe refund denied",
        "The exact Stripe refund was not authorized by the bounded profile.",
        "stripe-refund-denied",
    ),
    definition(
        "stripe.refund-outcome-unknown",
        ErrorFamily::Provider,
        "stripe-refund",
        "execute",
        &["provider-observation"],
        POSSIBLE_UNKNOWN,
        RecommendedAction::ResumeAndReconcile,
        true,
        "Stripe refund outcome unknown",
        "The Stripe refund outcome requires recovery before another execution.",
        "stripe-refund-outcome-unknown",
    ),
];

#[allow(clippy::too_many_arguments)]
const fn profile_client_error(
    code: &'static str,
    family: ErrorFamily,
    operation: &'static str,
    stages: &'static [&'static str],
    outcomes: &'static [AllowedOutcome],
    recommended_action: RecommendedAction,
    allows_execution_reference: bool,
    allows_decision_reference: bool,
    allows_receipt_reference: bool,
    title: &'static str,
    explanation: &'static str,
    fixture_id: &'static str,
) -> ErrorDefinition {
    ErrorDefinition {
        code,
        family,
        owner: "profile-client",
        owner_version: 1,
        operation,
        stages,
        outcomes,
        recommended_action,
        allows_execution_reference,
        allows_decision_reference,
        allows_receipt_reference,
        title,
        explanation,
        fixture_id,
    }
}

macro_rules! public_error {
    (
        $code:literal, $family:ident, $owner:literal, $operation:literal,
        $stage:literal, $outcomes:ident, $action:ident,
        $execution:literal, $decision:literal, $receipt:literal
    ) => {
        ErrorDefinition {
            code: $code,
            family: ErrorFamily::$family,
            owner: $owner,
            owner_version: 1,
            operation: $operation,
            stages: &[$stage],
            outcomes: $outcomes,
            recommended_action: RecommendedAction::$action,
            allows_execution_reference: $execution,
            allows_decision_reference: $decision,
            allows_receipt_reference: $receipt,
            title: $code,
            explanation: "The registered Auths contract rejected or classified this bounded operation.",
            fixture_id: $code,
        }
    };
}

const PUBLIC_API_ERRORS: &[ErrorDefinition] = &[
    public_error!(
        "core.receipt-malformed",
        Input,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "core.receipt-signature-invalid",
        Input,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_NEVER,
        InspectReceipt,
        false,
        false,
        false
    ),
    public_error!(
        "core.receipt-signer-untrusted",
        Profile,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        false,
        false
    ),
    public_error!(
        "core.receipt-profile-denied",
        Profile,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        false,
        false
    ),
    public_error!(
        "core.receipt-expired",
        State,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_NEVER,
        InspectReceipt,
        false,
        false,
        false
    ),
    public_error!(
        "core.receipt-trust-indeterminate",
        Runtime,
        "core",
        "verify",
        "receipt",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        false,
        false,
        false
    ),
    public_error!(
        "core.verification-capacity",
        Runtime,
        "core",
        "verify",
        "admission",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "remote.authentication-failed",
        Configuration,
        "remote",
        "verify",
        "channel-authentication",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        false,
        false
    ),
    public_error!(
        "remote.response-malformed",
        Runtime,
        "remote",
        "verify",
        "remote-response",
        NOT_APPLIED_NEVER,
        ContactSupport,
        false,
        false,
        false
    ),
    public_error!(
        "remote.transport-unavailable",
        Runtime,
        "remote",
        "verify",
        "transport",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "remote.timeout",
        Runtime,
        "remote",
        "verify",
        "transport",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "mcp.receipt-invalid",
        Input,
        "mcp",
        "verify",
        "receipt-profile-payload",
        NOT_APPLIED_NEVER,
        InspectReceipt,
        false,
        false,
        false
    ),
    public_error!(
        "mcp.admission-capacity",
        Runtime,
        "mcp",
        "execute",
        "admission",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "mcp.delegation-capacity",
        Runtime,
        "mcp",
        "delegate",
        "admission",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "mcp.recovery-not-found",
        Input,
        "mcp",
        "resume",
        "lifecycle-store",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "mcp.recovery-kind-mismatch",
        Input,
        "mcp",
        "resume",
        "lifecycle-store",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
];

const IDENTITY_ERRORS: &[ErrorDefinition] = &[
    public_error!(
        "identity.packet-malformed",
        Input,
        "identity",
        "decode",
        "identity-packet",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.method-unsupported",
        Configuration,
        "identity",
        "decode",
        "identity-method",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        false,
        false
    ),
    public_error!(
        "identity.not-found",
        Profile,
        "identity",
        "resolve",
        "identity-resolution",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.resolution-rejected",
        Profile,
        "identity",
        "resolve",
        "identity-resolution",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.resolution-indeterminate",
        Runtime,
        "identity",
        "resolve",
        "identity-resolution",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "identity.evidence-expired",
        State,
        "identity",
        "validate",
        "identity-evidence",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        false,
        false,
        false
    ),
    public_error!(
        "identity.validation-rejected",
        Profile,
        "identity",
        "validate",
        "identity-validation",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.validation-indeterminate",
        Runtime,
        "identity",
        "validate",
        "identity-validation",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "identity.relationship-denied",
        Profile,
        "identity",
        "authenticate",
        "identity-relationship",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.signature-invalid",
        Input,
        "identity",
        "authenticate",
        "identity-signature",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "identity.authentication-indeterminate",
        Runtime,
        "identity",
        "authenticate",
        "identity-authenticator",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
];

const GITHUB_ERRORS: &[ErrorDefinition] = &[
    public_error!(
        "github.boundary-invalid",
        Configuration,
        "github",
        "create",
        "boundary",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        false,
        false
    ),
    public_error!(
        "github.attenuation-denied",
        Profile,
        "github",
        "delegate",
        "delegation",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.delegation-outcome-unknown",
        State,
        "github",
        "delegate",
        "delegation",
        POSSIBLE_UNKNOWN,
        ResumeAndReconcile,
        true,
        true,
        false
    ),
    public_error!(
        "github.workflow-proof-invalid",
        Input,
        "github",
        "execute",
        "workflow-proof",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        true,
        false
    ),
    public_error!(
        "github.workflow-expired",
        State,
        "github",
        "execute",
        "expiry",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.workflow-cancelled",
        State,
        "github",
        "execute",
        "cancellation",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.executor-audience-mismatch",
        Profile,
        "github",
        "execute",
        "audience",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        true,
        false
    ),
    public_error!(
        "github.repository-mismatch",
        Profile,
        "github",
        "execute",
        "repository-boundary",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        true,
        false
    ),
    public_error!(
        "github.repository-renamed-or-transferred",
        State,
        "github",
        "execute",
        "repository-boundary",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.issue-mismatch",
        Profile,
        "github",
        "execute",
        "issue-boundary",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        true,
        false
    ),
    public_error!(
        "github.issue-not-open",
        State,
        "github",
        "execute",
        "issue-boundary",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.base-revision-mismatch",
        State,
        "github",
        "execute",
        "base-revision",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.branch-already-exists",
        Provider,
        "github",
        "execute",
        "branch-precondition",
        NOT_APPLIED_NEVER,
        CorrectInput,
        true,
        true,
        false
    ),
    public_error!(
        "github.pull-request-already-exists",
        Provider,
        "github",
        "execute",
        "pull-request-precondition",
        NOT_APPLIED_NEVER,
        CorrectInput,
        true,
        true,
        false
    ),
    public_error!(
        "github.candidate-bundle-malformed",
        Input,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.candidate-limit-exceeded",
        Input,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.candidate-not-descendant",
        Profile,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.merge-commit-denied",
        Profile,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.unsupported-git-object",
        Input,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.path-not-allowed",
        Profile,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.path-explicitly-denied",
        Profile,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.file-mode-denied",
        Profile,
        "github",
        "verify",
        "candidate-inspection",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.repository-automation-policy-mismatch",
        Runtime,
        "github",
        "execute",
        "repository-evidence",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.branch-budget-exhausted",
        State,
        "github",
        "execute",
        "branch-reservation",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.pull-request-budget-exhausted",
        State,
        "github",
        "execute",
        "pull-request-reservation",
        NOT_APPLIED_NEVER,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.evidence-missing",
        Runtime,
        "github",
        "execute",
        "provider-evidence",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.evidence-stale",
        Runtime,
        "github",
        "execute",
        "provider-evidence",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        false,
        true,
        false
    ),
    public_error!(
        "github.verifier-configuration-mismatch",
        Configuration,
        "github",
        "execute",
        "required-executed",
        NOT_APPLIED_NEVER,
        CorrectConfiguration,
        false,
        true,
        false
    ),
    public_error!(
        "github.exact-action-mismatch",
        Input,
        "github",
        "execute",
        "exact-action",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        true,
        false
    ),
    public_error!(
        "github.candidate-substituted",
        Input,
        "github",
        "execute",
        "exact-candidate-claim",
        NOT_APPLIED_NEVER,
        CorrectInput,
        false,
        false,
        false
    ),
    public_error!(
        "github.credential-boundary-failed",
        Internal,
        "github",
        "execute",
        "credential-boundary",
        NOT_APPLIED_NEVER,
        ContactSupport,
        false,
        true,
        false
    ),
    public_error!(
        "github.branch-rejected",
        Provider,
        "github",
        "execute",
        "branch-result",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        true,
        true,
        true
    ),
    public_error!(
        "github.pull-request-rejected",
        Provider,
        "github",
        "execute",
        "pull-request-result",
        NOT_APPLIED_CONDITIONAL,
        SatisfyCondition,
        true,
        true,
        true
    ),
    public_error!(
        "github.delegation-capacity",
        Runtime,
        "github",
        "delegate",
        "admission",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "github.execution-capacity",
        Runtime,
        "github",
        "execute",
        "admission",
        NOT_APPLIED_SAFE,
        RetryExecution,
        false,
        false,
        false
    ),
    public_error!(
        "github.branch-outcome-unknown",
        Provider,
        "github",
        "execute",
        "branch-observation",
        POSSIBLE_UNKNOWN,
        ResumeAndReconcile,
        true,
        true,
        false
    ),
    public_error!(
        "github.pull-request-outcome-unknown",
        Provider,
        "github",
        "execute",
        "pull-request-observation",
        POSSIBLE_UNKNOWN,
        ResumeAndReconcile,
        true,
        true,
        false
    ),
    public_error!(
        "github.workflow-terminal-applied",
        State,
        "github",
        "resume",
        "recovery",
        APPLIED_CONDITIONAL,
        InspectReceipt,
        true,
        true,
        true
    ),
    public_error!(
        "github.workflow-terminal-not-applied",
        State,
        "github",
        "resume",
        "recovery",
        NOT_APPLIED_NEVER,
        InspectReceipt,
        true,
        true,
        true
    ),
    public_error!(
        "github.receipt-invalid",
        Input,
        "github",
        "verify",
        "receipt-profile-payload",
        NOT_APPLIED_NEVER,
        InspectReceipt,
        false,
        false,
        false
    ),
];

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
    public_error!(
        "core.terminal-receipt-integrity-failed",
        Internal,
        "core",
        "resume",
        "receipt",
        TERMINAL_RECEIPT_INTEGRITY,
        ContactSupport,
        true,
        true,
        true
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

    #[test]
    fn canonical_error_envelope_decoder_is_an_exact_inverse() {
        for code in [
            "core.authorization-denied",
            "mcp.handler-timeout",
            "stripe.refund-outcome-unknown",
        ] {
            let value = ErrorEnvelope::parse(input(code)).unwrap();
            let bytes = value.to_canonical_cbor().unwrap();
            assert_eq!(ErrorEnvelope::from_canonical_cbor(&bytes), Ok(value));

            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(
                ErrorEnvelope::from_canonical_cbor(&trailing),
                Err(ErrorContractError::InvalidField)
            );
        }
    }
}
