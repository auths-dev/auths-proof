//! Statically linked local-agent verticals for protected planning and saved-plan apply.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::unused_async
)]

use std::{collections::BTreeMap, time::Instant};

use auths_codec::{decode_verifier_context, encode_canonical_action};
use auths_errors::{
    CauseCategory, EffectState, EnteredBoundaries, ErrorEnvelope, ErrorEnvelopeInput,
    RecommendedAction, RetryClass,
};
#[cfg(feature = "qualification")]
use auths_lifecycle::OperationStateV1;
use auths_lifecycle::{OperationEffectV1, OperationProfileV1};
use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
#[cfg(feature = "qualification")]
use auths_profile_kit::{
    QualificationEffect, QualificationProfileStateFactV1, QualificationProfileStateObservationV1,
};
use auths_profile_runtime::{
    CallProviderInput, ObserveProviderResultInput, PreEntryRecheckInput, PrepareProfileInput,
    ProfileConclusion, ProfileDecisionReceiptFacts, ProfileExecutionReceiptFacts,
    ProfileObservation, ProfilePreEntryRecheck, ProfilePreparation, ProfilePreparationKind,
    ProfileReceiptClaimCommitment, ProfileReceiptInspection, ProfileRuntimeError,
    ReconcileProfileInput, ReleaseProfileCallInput, SealProfileCallInput, SealedProfileCall,
    profile_receipt_claim_digest,
};
#[cfg(feature = "qualification")]
use auths_stores::JournalRecordV1;

/// OpenTofu's current seal functions already persist their protected reread
/// projection. These explicit hooks establish the common post-command durable
/// boundary without permitting runtime-selected callbacks.
pub fn plans_create_recheck_pre_entry(
    input: PreEntryRecheckInput<'_>,
) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {
    unchanged_pre_entry_recheck(input)
}

pub fn saved_plans_apply_recheck_pre_entry(
    input: PreEntryRecheckInput<'_>,
) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {
    unchanged_pre_entry_recheck(input)
}

fn unchanged_pre_entry_recheck(
    input: PreEntryRecheckInput<'_>,
) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {
    if input.record.sealed_command().is_none() || input.record.provider_entered() {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(ProfilePreEntryRecheck {
        profile_state: input.record.profile_state().to_vec(),
    })
}
use auths_receipts::{
    ProfileReceiptClaim, ProfileReceiptClaimPhase, encode_profile_receipt_claims,
};
use auths_sdk::{RequestContext, VerifiedAction, Verifier, VerifyResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    DigestHex, OpenTofuLocalAgentConfigurationV1, OpenTofuSavedPlanProfile, OpenTofuSourceBundleV1,
    PreparedPlanRecordV1, PreparedPlanStore, PreparedPlanStoreError,
    connection::OpenTofuConnectionDescriptor,
    generated::profile_api::{
        ApplyPreparedPlanInput, ApplyResult, PlanPreflightInput, PreparedPlan,
    },
    local_provider::PreparedPlanPayloadV1,
    observe::validate_apply_result,
};

const PREFLIGHT_PROFILE: &str = "auths.opentofu.plan-preflight";
const PREFLIGHT_VERSION: u16 = 1;

/// Rebuilds the exact plan-preflight decision receipt claims.
pub fn plans_create_build_decision_receipt_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Decision,
        plans_create_decision_commitments(facts)?,
    )
}

fn plans_create_decision_commitments(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != PREFLIGHT_PROFILE || facts.binding.profile().version() != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: PlanState = canonical_from_slice(facts.profile_state)?;
    Ok(decision_claims(facts, &canonical_json(&state)?))
}

/// Rebuilds the exact saved-plan-apply decision receipt claims.
pub fn saved_plans_apply_build_decision_receipt_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Decision,
        saved_plans_apply_decision_commitments(facts)?,
    )
}

fn saved_plans_apply_decision_commitments(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != "auths.opentofu.saved-plan-apply"
        || facts.binding.profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: ApplyState = canonical_from_slice(facts.profile_state)?;
    Ok(decision_claims(facts, &canonical_json(&state)?))
}

fn decision_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
    state: &[u8],
) -> Vec<ProfileReceiptClaimCommitment> {
    vec![
        claim("opentofu.dependency-closure", &[state]),
        claim(
            "opentofu.lock-closure",
            &[state, facts.binding.canonical_input_commitment()],
        ),
        claim(
            "opentofu.preparation",
            &[facts.binding.preparation_commitment()],
        ),
        claim(
            "opentofu.sandbox",
            &[facts.binding.configuration_commitment(), state],
        ),
        claim(
            "opentofu.sandbox-policy",
            &[facts.binding.configuration_commitment()],
        ),
        claim(
            "opentofu.tool-identity",
            &[state, facts.binding.configuration_commitment()],
        ),
    ]
}

/// Rebuilds the exact plan-preflight execution receipt claims.
pub fn plans_create_build_execution_receipt_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Execution,
        plans_create_execution_commitments(facts)?,
    )
}

fn plans_create_execution_commitments(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != PREFLIGHT_PROFILE || facts.binding.profile().version() != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: PlanState = canonical_from_slice(facts.profile_state)?;
    let command: PlanCommand = canonical_from_slice(facts.sealed_command)?;
    if let Some(provider) = facts.provider_result {
        let _: PlanProviderResult = canonical_from_slice(provider)?;
    }
    Ok(execution_claims(
        facts,
        command.prepared_plan.as_bytes(),
        &canonical_json(&state)?,
    ))
}

/// Rebuilds the exact saved-plan-apply execution receipt claims.
pub fn saved_plans_apply_build_execution_receipt_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Execution,
        saved_plans_apply_execution_commitments(facts)?,
    )
}

fn saved_plans_apply_execution_commitments(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != "auths.opentofu.saved-plan-apply"
        || facts.binding.profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: ApplyState = canonical_from_slice(facts.profile_state)?;
    let _: ApplyCommand = canonical_from_slice(facts.sealed_command)?;
    if let Some(provider) = facts.provider_result {
        let _: crate::OpenTofuApplyResult = canonical_from_slice(provider)?;
    }
    Ok(execution_claims(
        facts,
        state.prepared_plan.as_bytes(),
        &canonical_json(&state)?,
    ))
}

fn execution_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
    reservation: &[u8],
    state: &[u8],
) -> Vec<ProfileReceiptClaimCommitment> {
    let provider = facts.provider_result.unwrap_or(b"absent");
    let observations = observation_commitment(facts.observations);
    vec![
        claim(
            "opentofu.artifact",
            &[state, facts.sealed_command, provider],
        ),
        claim("opentofu.observation", &[provider, &observations]),
        claim(
            "opentofu.pre-entry-recheck",
            &[facts.sealed_command, facts.binding.preparation_commitment()],
        ),
        claim("opentofu.provider-result", &[provider, &observations]),
        claim(
            "opentofu.reconciliation",
            &[
                facts.operation_id.as_str().as_bytes(),
                facts.sealed_command,
                reservation,
            ],
        ),
        claim("opentofu.reservation", &[reservation, state]),
    ]
}

/// Inspects exact plan-preflight receipt claims against immutable mint facts.
pub fn plans_create_inspect_receipt_claims(
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if inspection.facts.binding().profile().id() != PREFLIGHT_PROFILE
        || inspection.facts.binding().profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    inspect_exact(
        inspection,
        plans_create_build_decision_receipt_claims,
        plans_create_build_execution_receipt_claims,
    )?;
    if inspection.execution_claims.is_none() {
        return Ok(());
    }
    let command: PlanCommand = canonical_from_slice(
        inspection
            .facts
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    if command.operation_id != inspection.facts.operation_id().as_str() {
        return Err(ProfileRuntimeError::Invalid);
    }
    if let Some(provider) = inspection.facts.provider_result() {
        let result: PlanProviderResult = canonical_from_slice(provider)?;
        if result.prepared_plan != command.prepared_plan {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    Ok(())
}

/// Inspects exact saved-plan claims and terminal reconciliation truth.
pub fn saved_plans_apply_inspect_receipt_claims(
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if inspection.facts.binding().profile().id() != "auths.opentofu.saved-plan-apply"
        || inspection.facts.binding().profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    inspect_exact(
        inspection,
        saved_plans_apply_build_decision_receipt_claims,
        saved_plans_apply_build_execution_receipt_claims,
    )?;
    if inspection.execution_claims.is_none() {
        return Ok(());
    }
    let command: ApplyCommand = canonical_from_slice(
        inspection
            .facts
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    if command.operation_id != inspection.facts.operation_id().as_str() {
        return Err(ProfileRuntimeError::Invalid);
    }
    if inspection.facts.completion().is_some() {
        let observation = inspection
            .facts
            .observations()
            .last()
            .ok_or(ProfileRuntimeError::Invalid)?;
        if observation.as_slice() == b"opentofu-state-unchanged" {
            if inspection.facts.projection().effect() != OperationEffectV1::NotApplied {
                return Err(ProfileRuntimeError::Invalid);
            }
        } else {
            let result: crate::OpenTofuApplyResult = canonical_from_slice(observation)?;
            validate_apply_result(&command.payload.action, &result).map_err(invalid)?;
            if !result.state_committed
                || !result.postconditions_observed
                || !result.converged
                || inspection.facts.projection().effect() != OperationEffectV1::Applied
            {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
    }
    Ok(())
}

fn inspect_exact(
    inspection: ProfileReceiptInspection<'_>,
    decision: fn(ProfileDecisionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError>,
    execution: fn(ProfileExecutionReceiptFacts<'_>) -> Result<Vec<u8>, ProfileRuntimeError>,
) -> Result<(), ProfileRuntimeError> {
    if decision(inspection.facts.decision_facts())? != inspection.decision_claims {
        return Err(ProfileRuntimeError::Invalid);
    }
    match (
        inspection.facts.execution_facts(),
        inspection.execution_claims,
    ) {
        (None, None) => Ok(()),
        (Some(facts), Some(actual)) if execution(facts)?.as_slice() == actual => Ok(()),
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

fn encode_claims(
    profile: &OperationProfileV1,
    phase: ProfileReceiptClaimPhase,
    claims: Vec<ProfileReceiptClaimCommitment>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = ProfileRef::new(
        ProfileId::parse(profile.id()).map_err(|_| ProfileRuntimeError::Invalid)?,
        profile.version(),
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let claims = claims
        .into_iter()
        .map(|claim| ProfileReceiptClaim::new(claim.id, claim.sha256))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    encode_profile_receipt_claims(&profile, phase, &claims)
        .map_err(|_| ProfileRuntimeError::Invalid)
}

fn claim(id: &'static str, parts: &[&[u8]]) -> ProfileReceiptClaimCommitment {
    ProfileReceiptClaimCommitment {
        id,
        sha256: profile_receipt_claim_digest(id, parts),
    }
}

fn observation_commitment(observations: &[Vec<u8>]) -> [u8; 32] {
    let parts = observations.iter().map(Vec::as_slice).collect::<Vec<_>>();
    profile_receipt_claim_digest("opentofu.observations", &parts)
}

pub fn validate_profile_configuration(
    binding: &auths_profile_runtime::ProfileConfigurationBinding,
) -> Result<(), ProfileRuntimeError> {
    OpenTofuLocalAgentConfigurationV1::from_binding(binding)
        .map(|_| ())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

pub fn plans_create_prepare(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = PlanPreflightInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("opentofu.plan-preflight-denied", "opentofu-plan-input"))?;
    let bundle = bundle_from_input(generated)?;
    let connection = checked_connection(input.connection)?;
    let descriptor = OpenTofuConnectionDescriptor::from_canonical_bytes(connection.descriptor())
        .map_err(invalid)?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration =
        OpenTofuLocalAgentConfigurationV1::from_binding(binding).map_err(invalid)?;
    let expires_at = input
        .now_unix_seconds
        .checked_add(configuration.planner().prepared_plan_lifetime_seconds())
        .ok_or(ProfileRuntimeError::Invalid)?;
    let action = PlanPreflightActionV1::new(
        &bundle,
        connection,
        &descriptor,
        &configuration,
        binding.sha256(),
        expires_at,
    )?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&action)?)
        .map_err(invalid)?;
    let canonical_action = encode_canonical_action(&canonical).map_err(invalid)?;
    let kind = match verify_authority(
        input.context,
        &canonical,
        &PreflightProfile,
        input.now_unix_seconds,
    )? {
        VerificationClass::Authorized => ProfilePreparationKind::Ready,
        VerificationClass::Denied => ProfilePreparationKind::Denied {
            issue: issue_denied("opentofu.plan-preflight-denied", "opentofu-plan-authority")?,
        },
        VerificationClass::Indeterminate => ProfilePreparationKind::Unavailable {
            issue: issue_indeterminate("opentofu-plan-authority")?,
        },
    };
    Ok(ProfilePreparation {
        canonical_input_commitment: Sha256::digest(input.profile_input).into(),
        canonical_action_commitment: Sha256::digest(&canonical_action).into(),
        configuration_commitment: configuration_commitment(input.context, connection, binding),
        canonical_action,
        decision_reason: match kind {
            ProfilePreparationKind::Ready => "opentofu.plan-preflight-authorized",
            ProfilePreparationKind::Denied { .. } => "opentofu.plan-preflight-denied",
            ProfilePreparationKind::Unavailable { .. } => "core.authorization-indeterminate",
        }
        .into(),
        profile_state: canonical_json(&PlanState {
            action,
            bundle,
            descriptor: connection.descriptor().to_vec(),
            prepared_plan: None,
        })?,
        kind,
    })
}

pub async fn plans_create_seal_provider_call(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let mut state: PlanState = canonical_from_slice(input.record.profile_state())?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration =
        OpenTofuLocalAgentConfigurationV1::from_binding(binding).map_err(invalid)?;
    state.action.validate(&configuration)?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&state.action)?)
        .map_err(invalid)?;
    if verify_authority(
        input.context,
        &canonical,
        &PreflightProfile,
        input.now_unix_seconds,
    )? != VerificationClass::Authorized
    {
        return Err(denied_error(
            "opentofu.plan-preflight-denied",
            input.record.operation_id().as_str(),
        ));
    }
    let store = PreparedPlanStore::open(input.context.profile_state_root()).map_err(invalid)?;
    let token = if let Some(token) = &state.prepared_plan {
        token.clone()
    } else {
        let token = PreparedPlanStore::generate_token().map_err(invalid)?;
        let descriptor = OpenTofuConnectionDescriptor::from_canonical_bytes(&state.descriptor)
            .map_err(invalid)?;
        let action_digest: [u8; 32] = Sha256::digest(canonical.body()).into();
        let tool_digest = decode_digest(configuration.planner().binary_sha256().as_str())?;
        let record = PreparedPlanRecordV1::reserved(
            &token,
            input.record.operation_id().as_str(),
            input.context.principal(),
            &state.action.connection_id,
            state.action.connection_generation,
            &descriptor.account_commitment(),
            &decode_digest(&state.action.descriptor_commitment)?,
            &decode_digest(&state.action.credential_commitment)?,
            &binding.sha256(),
            &tool_digest,
            &action_digest,
            state.action.expires_at,
        )
        .map_err(invalid)?;
        store.reserve(record).map_err(|error| match error {
            PreparedPlanStoreError::Conflict => denied_error(
                "opentofu.plan-preflight-denied",
                input.record.operation_id().as_str(),
            ),
            _ => ProfileRuntimeError::Invalid,
        })?;
        state.prepared_plan = Some(token.clone());
        token
    };
    Ok(SealedProfileCall {
        command: canonical_json(&PlanCommand {
            action: state.action.clone(),
            bundle: state.bundle.clone(),
            descriptor: state.descriptor.clone(),
            prepared_plan: token,
            operation_id: input.record.operation_id().as_str().into(),
        })?,
        profile_state: canonical_json(&state)?,
    })
}

/// Invalidates a reserved prepared-plan capability when the common journal
/// still proves that protected planning never began.
pub fn plans_create_release_pre_entry(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let store = PreparedPlanStore::open(input.context.profile_state_root()).map_err(invalid)?;
    if let Some(bytes) = input.record.sealed_command() {
        let command: PlanCommand = canonical_from_slice(bytes)?;
        store
            .deny_reserved(&command.prepared_plan, &command.operation_id)
            .map_err(invalid)?;
    } else {
        store
            .deny_reserved_by_operation(input.record.operation_id().as_str())
            .map_err(invalid)?;
    }
    Ok(())
}

pub async fn plans_create_call_provider(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: PlanCommand = canonical_from_slice(&input.call.command)?;
    let configuration = configuration(input.context)?;
    let root = input.context.profile_state_root().to_path_buf();
    let result = plans_create_transport(
        root,
        command,
        expose_credential(input.credential)?.to_vec(),
        configuration,
        input.now_unix_seconds,
    )
    .await?;
    canonical_json(&result)
}

async fn plans_create_transport(
    root: std::path::PathBuf,
    command: PlanCommand,
    credential: Vec<u8>,
    configuration: OpenTofuLocalAgentConfigurationV1,
    now: u64,
) -> Result<PlanProviderResult, ProfileRuntimeError> {
    let descriptor =
        OpenTofuConnectionDescriptor::from_canonical_bytes(&command.descriptor).map_err(invalid)?;
    let bundle = command.bundle.clone();
    let nonce = crate::canonical::sha256(command.prepared_plan.as_bytes());
    let payload = tokio::task::spawn_blocking(move || {
        crate::local_provider::plan(
            &root,
            &credential,
            &descriptor,
            &configuration,
            &bundle,
            nonce,
            now,
        )
    })
    .await
    .map_err(|_| {
        possible_error(
            "opentofu.plan-preflight-outcome-unknown",
            &command.operation_id,
        )
    })?
    .map_err(|_| {
        possible_error(
            "opentofu.plan-preflight-outcome-unknown",
            &command.operation_id,
        )
    })?;
    Ok(PlanProviderResult {
        prepared_plan: command.prepared_plan,
        payload,
    })
}

#[cfg(feature = "qualification")]
pub(crate) async fn plans_create_transport_from_bytes(
    root: &std::path::Path,
    command: &[u8],
    credential: &[u8],
    configuration: &[u8],
    now: u64,
) -> Result<(Vec<u8>, Vec<u8>), ProfileRuntimeError> {
    let command: PlanCommand = canonical_from_slice(command)?;
    let configuration =
        OpenTofuLocalAgentConfigurationV1::from_canonical_bytes(configuration).map_err(invalid)?;
    let result = plans_create_transport(
        root.to_path_buf(),
        command,
        credential.to_vec(),
        configuration,
        now,
    )
    .await?;
    let artifact = crate::local_provider::export_artifact(root, &result.payload)?;
    Ok((canonical_json(&result)?, artifact))
}

#[cfg(feature = "qualification")]
pub(crate) fn import_plan_transport_artifact(
    root: &std::path::Path,
    provider_result: &[u8],
    artifact: Vec<u8>,
) -> Result<(), ProfileRuntimeError> {
    let result: PlanProviderResult = canonical_from_slice(provider_result)?;
    crate::local_provider::import_artifact(root, &result.payload, artifact)
}

pub fn plans_create_observe_provider_result(
    input: ObserveProviderResultInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let result: PlanProviderResult = canonical_from_slice(input.provider_result)?;
    result.payload.validate(input.now_unix_seconds)?;
    crate::local_provider::verify_artifact(input.context.profile_state_root(), &result.payload)?;
    let action_digest = result.payload.action.digest().map_err(invalid)?;
    let store = PreparedPlanStore::open(input.context.profile_state_root()).map_err(invalid)?;
    let record = store
        .mark_ready(
            &result.prepared_plan,
            input.record.operation_id().as_str(),
            &decode_digest(action_digest.as_str())?,
            canonical_json(&result.payload)?,
        )
        .map_err(invalid)?;
    let summary = result.payload.action.permitted_change_summary();
    let value = PreparedPlan {
        prepared_plan: result.prepared_plan,
        action_digest: action_digest.to_string(),
        workspace: result.payload.action.workspace().into(),
        prior_state_serial: result.payload.action.state_serial(),
        creates: summary.creates,
        updates: summary.updates,
        reads: summary.reads,
        no_ops: summary.no_ops,
        expires_at: record.expires_at(),
    }
    .to_canonical_cbor()
    .map_err(invalid)?;
    Ok(ProfileObservation {
        bytes: input.provider_result.to_vec(),
        conclusion: ProfileConclusion::Completed {
            value,
            profile_state: input.record.profile_state().to_vec(),
        },
    })
}

pub async fn plans_create_reconcile(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: PlanCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let call = SealedProfileCall {
        command: canonical_json(&command)?,
        profile_state: input.record.profile_state().to_vec(),
    };
    let bytes = plans_create_call_provider(CallProviderInput {
        context: input.context,
        call: &call,
        credential: input.credential,
        now_unix_seconds: input.now_unix_seconds,
    })
    .await?;
    plans_create_observe_provider_result(ObserveProviderResultInput {
        context: input.context,
        record: input.record,
        provider_result: &bytes,
        now_unix_seconds: input.now_unix_seconds,
    })
}

pub fn saved_plans_apply_prepare(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = ApplyPreparedPlanInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("opentofu.saved-plan-denied", "opentofu-apply-input"))?;
    let connection = checked_connection(input.connection)?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration =
        OpenTofuLocalAgentConfigurationV1::from_binding(binding).map_err(invalid)?;
    let store = PreparedPlanStore::open(input.context.profile_state_root()).map_err(invalid)?;
    let record = store
        .load_ready(&generated.prepared_plan, input.now_unix_seconds)
        .map_err(|_| denied_error("opentofu.saved-plan-denied", "opentofu-prepared-plan"))?;
    validate_record(&record, input.context, connection, binding, &configuration)?;
    let payload: PreparedPlanPayloadV1 =
        canonical_from_slice(record.payload().ok_or(ProfileRuntimeError::Invalid)?)?;
    payload.validate(input.now_unix_seconds)?;
    if payload.configuration != configuration
        || payload.action.digest().map_err(invalid)?.as_str() != record.action_digest()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    crate::local_provider::verify_artifact(input.context.profile_state_root(), &payload)?;
    let canonical = OpenTofuSavedPlanProfile
        .canonicalize(&payload.action.canonical_bytes().map_err(invalid)?)
        .map_err(invalid)?;
    let canonical_action = encode_canonical_action(&canonical).map_err(invalid)?;
    let kind = match verify_authority(
        input.context,
        &canonical,
        &OpenTofuSavedPlanProfile,
        input.now_unix_seconds,
    )? {
        VerificationClass::Authorized => ProfilePreparationKind::Ready,
        VerificationClass::Denied => ProfilePreparationKind::Denied {
            issue: issue_denied("opentofu.saved-plan-denied", "opentofu-apply-authority")?,
        },
        VerificationClass::Indeterminate => ProfilePreparationKind::Unavailable {
            issue: issue_indeterminate("opentofu-apply-authority")?,
        },
    };
    Ok(ProfilePreparation {
        canonical_input_commitment: Sha256::digest(input.profile_input).into(),
        canonical_action_commitment: Sha256::digest(&canonical_action).into(),
        configuration_commitment: configuration_commitment(input.context, connection, binding),
        canonical_action,
        decision_reason: match kind {
            ProfilePreparationKind::Ready => "opentofu.saved-plan-authorized",
            ProfilePreparationKind::Denied { .. } => "opentofu.saved-plan-denied",
            ProfilePreparationKind::Unavailable { .. } => "core.authorization-indeterminate",
        }
        .into(),
        profile_state: canonical_json(&ApplyState {
            prepared_plan: generated.prepared_plan,
            payload,
        })?,
        kind,
    })
}

pub async fn saved_plans_apply_seal_provider_call(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let state: ApplyState = canonical_from_slice(input.record.profile_state())?;
    state.payload.validate(input.now_unix_seconds)?;
    let canonical = OpenTofuSavedPlanProfile
        .canonicalize(&state.payload.action.canonical_bytes().map_err(invalid)?)
        .map_err(invalid)?;
    if verify_authority(
        input.context,
        &canonical,
        &OpenTofuSavedPlanProfile,
        input.now_unix_seconds,
    )? != VerificationClass::Authorized
    {
        return Err(denied_error(
            "opentofu.saved-plan-denied",
            input.record.operation_id().as_str(),
        ));
    }
    crate::local_provider::verify_artifact(input.context.profile_state_root(), &state.payload)?;
    PreparedPlanStore::open(input.context.profile_state_root())
        .map_err(invalid)?
        .claim(
            &state.prepared_plan,
            input.record.operation_id().as_str(),
            input.now_unix_seconds,
        )
        .map_err(|_| {
            denied_error(
                "opentofu.saved-plan-denied",
                input.record.operation_id().as_str(),
            )
        })?;
    Ok(SealedProfileCall {
        command: canonical_json(&ApplyCommand {
            prepared_plan: state.prepared_plan,
            payload: state.payload,
            operation_id: input.record.operation_id().as_str().into(),
        })?,
        profile_state: input.record.profile_state().to_vec(),
    })
}

/// Releases a prepared-plan claim only while the common journal still proves
/// that the OpenTofu apply command was never entered.
pub fn saved_plans_apply_release_pre_entry(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let store = PreparedPlanStore::open(input.context.profile_state_root()).map_err(invalid)?;
    if let Some(bytes) = input.record.sealed_command() {
        let command: ApplyCommand = canonical_from_slice(bytes)?;
        store
            .release_claim(&command.prepared_plan, &command.operation_id)
            .map_err(invalid)?;
    } else {
        store
            .release_claim_by_operation(input.record.operation_id().as_str())
            .map_err(invalid)?;
    }
    Ok(())
}

pub async fn saved_plans_apply_call_provider(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: ApplyCommand = canonical_from_slice(&input.call.command)?;
    let root = input.context.profile_state_root().to_path_buf();
    let credential = expose_credential(input.credential)?.to_vec();
    let payload = command.payload.clone();
    let now = input.now_unix_seconds;
    let result = tokio::task::spawn_blocking(move || {
        crate::local_provider::apply(&root, &credential, &payload, now)
    })
    .await
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?;
    canonical_json(&result)
}

#[cfg(feature = "qualification")]
pub(crate) async fn saved_plans_apply_transport_from_bytes(
    root: &std::path::Path,
    command: &[u8],
    credential: &[u8],
    now: u64,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: ApplyCommand = canonical_from_slice(command)?;
    let root = root.to_path_buf();
    let credential = credential.to_vec();
    let payload = command.payload.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::local_provider::apply(&root, &credential, &payload, now)
    })
    .await
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?;
    canonical_json(&result)
}

pub(crate) async fn saved_plans_apply_reconcile_transport_from_bytes(
    root: &std::path::Path,
    command: &[u8],
    credential: &[u8],
    now: u64,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    let command: ApplyCommand = canonical_from_slice(command)?;
    let root = root.to_path_buf();
    let credential = credential.to_vec();
    let payload = command.payload.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::local_provider::reconcile(&root, &credential, &payload, now)
    })
    .await
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?
    .map_err(|_| possible_error("opentofu.apply-outcome-unknown", &command.operation_id))?;
    result.map(|result| canonical_json(&result)).transpose()
}

/// Independently reads the exercised OpenTofu backend and returns only the
/// closed effect plus canonical redacted provider facts. The supplied root is
/// owned by ProviderObserver and contains no candidate-controlled path.
#[cfg(feature = "qualification")]
#[allow(clippy::items_after_statements)]
pub async fn observe_provider_truth_for_qualification(
    record: &JournalRecordV1,
    credential: &[u8],
    observer_root: &std::path::Path,
    now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    if !record.provider_entered() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let profile = format!(
        "{}/{}",
        record.binding().profile().id(),
        record.binding().profile().version()
    );
    let (payload, recorded_apply) = match profile.as_str() {
        "auths.opentofu.plan-preflight/1" => {
            let result: PlanProviderResult = canonical_from_slice(
                record
                    .provider_result()
                    .ok_or(ProfileRuntimeError::Invalid)?,
            )?;
            result
                .payload
                .validate(result.payload.action.planned_at())?;
            (result.payload, None)
        }
        "auths.opentofu.saved-plan-apply/1" => {
            let state: ApplyState = canonical_from_slice(record.profile_state())?;
            state.payload.validate(state.payload.action.planned_at())?;
            let result = record
                .provider_result()
                .map(canonical_from_slice::<crate::OpenTofuApplyResult>)
                .transpose()?;
            (state.payload, result)
        }
        _ => return Err(ProfileRuntimeError::Invalid),
    };
    let current = crate::local_provider::observe_state(
        observer_root,
        credential,
        &payload,
        now_unix_seconds,
    )?;
    let applied = if let Some(result) = recorded_apply.as_ref() {
        if current.state_lineage != result.state_lineage
            || current.state_serial != result.resulting_state_serial
            || current.state_digest != result.resulting_state_digest
            || !result.state_committed
            || !result.postconditions_observed
            || !result.converged
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        true
    } else {
        if current.state_lineage != payload.evidence.state_lineage
            || current.state_serial != payload.evidence.state_serial
            || current.state_digest != payload.evidence.state_digest
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        false
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Truth {
        workspace_sha256: String,
        plan_sha256: String,
        artifact_sha256: String,
        state_lineage_sha256: String,
        before_serial: u64,
        after_serial: u64,
        applied_marker_sha256: Option<String>,
        applied: bool,
    }
    let applied_marker_sha256 = recorded_apply
        .as_ref()
        .map(|result| {
            canonical_json(&(
                record.operation_id().as_str(),
                result.provider_object_commitment.as_str(),
                result.resulting_state_digest.as_str(),
                result.resulting_state_serial,
            ))
            .map(|bytes| hex::encode(Sha256::digest(bytes)))
        })
        .transpose()?;
    let truth = Truth {
        workspace_sha256: hex::encode(Sha256::digest(payload.action.workspace().as_bytes())),
        plan_sha256: payload.action.plan_projection_digest().as_str().to_owned(),
        artifact_sha256: payload.action.opaque_plan_digest().as_str().to_owned(),
        state_lineage_sha256: hex::encode(Sha256::digest(current.state_lineage.as_bytes())),
        before_serial: payload.action.state_serial(),
        after_serial: current.state_serial,
        applied_marker_sha256,
        applied,
    };
    let effect = if applied {
        QualificationEffect::Applied
    } else {
        QualificationEffect::NotApplied
    };
    canonical_json(&truth).map(|bytes| (effect, bytes))
}

pub fn saved_plans_apply_observe_provider_result(
    input: ObserveProviderResultInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: ApplyCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let result: crate::OpenTofuApplyResult = canonical_from_slice(input.provider_result)?;
    validate_apply_result(&command.payload.action, &result).map_err(invalid)?;
    PreparedPlanStore::open(input.context.profile_state_root())
        .map_err(invalid)?
        .consume(&command.prepared_plan, &command.operation_id)
        .map_err(invalid)?;
    let value = ApplyResult {
        workspace: command.payload.action.workspace().into(),
        state_serial: result.resulting_state_serial,
    }
    .to_canonical_cbor()
    .map_err(invalid)?;
    Ok(ProfileObservation {
        bytes: input.provider_result.to_vec(),
        conclusion: ProfileConclusion::Completed {
            value,
            profile_state: input.record.profile_state().to_vec(),
        },
    })
}

pub async fn saved_plans_apply_reconcile(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let credential = expose_credential(input.credential)?.to_vec();
    let result = saved_plans_apply_reconcile_transport_from_bytes(
        input.context.profile_state_root(),
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
        &credential,
        input.now_unix_seconds,
    )
    .await?;
    saved_plans_apply_finalize_reconcile_transport(input, result.as_deref())
}

pub fn saved_plans_apply_finalize_reconcile_transport(
    input: ReconcileProfileInput<'_>,
    result: Option<&[u8]>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: ApplyCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let Some(bytes) = result else {
        PreparedPlanStore::open(input.context.profile_state_root())
            .map_err(invalid)?
            .release_claim(&command.prepared_plan, &command.operation_id)
            .map_err(invalid)?;
        return Ok(ProfileObservation {
            bytes: b"opentofu-state-unchanged".to_vec(),
            conclusion: ProfileConclusion::NotApplied {
                issue: issue_denied(
                    "opentofu.saved-plan-denied",
                    input.record.operation_id().as_str(),
                )?,
                profile_state: input.record.profile_state().to_vec(),
            },
        });
    };
    saved_plans_apply_observe_provider_result(ObserveProviderResultInput {
        context: input.context,
        record: input.record,
        provider_result: bytes,
        now_unix_seconds: input.now_unix_seconds,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanPreflightActionV1 {
    schema: String,
    connection_id: String,
    connection_generation: u64,
    account_commitment: String,
    descriptor_commitment: String,
    credential_commitment: String,
    configuration_commitment: String,
    tool_commitment: String,
    backend_identity: String,
    workspace: String,
    bundle_digest: DigestHex,
    dependency_lock_digest: DigestHex,
    module_manifest_digest: DigestHex,
    variable_commitment: DigestHex,
    expires_at: u64,
}

impl PlanPreflightActionV1 {
    fn new(
        bundle: &OpenTofuSourceBundleV1,
        connection: &auths_connections::ConnectionBinding,
        descriptor: &OpenTofuConnectionDescriptor,
        configuration: &OpenTofuLocalAgentConfigurationV1,
        configuration_commitment: [u8; 32],
        expires_at: u64,
    ) -> Result<Self, ProfileRuntimeError> {
        let value = Self {
            schema: "auths.opentofu.plan-preflight-action/1".into(),
            connection_id: connection.connection_id().as_str().into(),
            connection_generation: connection.generation().get(),
            account_commitment: hex::encode(connection.account_commitment()),
            descriptor_commitment: hex::encode(connection.descriptor_commitment()),
            credential_commitment: hex::encode(connection.credential_reference_commitment()),
            configuration_commitment: hex::encode(configuration_commitment),
            tool_commitment: configuration.planner().binary_sha256().to_string(),
            backend_identity: descriptor.backend_identity().into(),
            workspace: bundle.requested_workspace.clone(),
            bundle_digest: bundle.digest().map_err(invalid)?,
            dependency_lock_digest: crate::canonical::sha256(
                bundle.dependency_lock_file.as_bytes(),
            ),
            module_manifest_digest: crate::bundle::empty_module_manifest_digest()
                .map_err(invalid)?,
            variable_commitment: crate::canonical::canonical_digest(&bundle.variable_values)
                .map_err(invalid)?,
            expires_at,
        };
        value.validate(configuration)?;
        Ok(value)
    }

    fn validate(
        &self,
        configuration: &OpenTofuLocalAgentConfigurationV1,
    ) -> Result<(), ProfileRuntimeError> {
        if self.schema != "auths.opentofu.plan-preflight-action/1"
            || self.connection_id.is_empty()
            || self.connection_generation == 0
            || !lower_hex(&self.account_commitment)
            || !lower_hex(&self.descriptor_commitment)
            || !lower_hex(&self.credential_commitment)
            || !lower_hex(&self.configuration_commitment)
            || !lower_hex(&self.tool_commitment)
            || self.backend_identity.is_empty()
            || self.workspace.is_empty()
            || self.expires_at == 0
            || self.tool_commitment != configuration.planner().binary_sha256().as_str()
            || !configuration
                .verifier()
                .allowed_backend_identities()
                .contains(&self.backend_identity)
            || !configuration
                .verifier()
                .allowed_workspaces()
                .contains(&self.workspace)
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanState {
    action: PlanPreflightActionV1,
    bundle: OpenTofuSourceBundleV1,
    descriptor: Vec<u8>,
    prepared_plan: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanCommand {
    action: PlanPreflightActionV1,
    bundle: OpenTofuSourceBundleV1,
    descriptor: Vec<u8>,
    prepared_plan: String,
    operation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanProviderResult {
    prepared_plan: String,
    payload: PreparedPlanPayloadV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyState {
    prepared_plan: String,
    payload: PreparedPlanPayloadV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyCommand {
    prepared_plan: String,
    payload: PreparedPlanPayloadV1,
    operation_id: String,
}

/// Independently decodes the canonical prepared-plan store and projects only
/// stable, capability-free reservation facts for one exact phase.
#[cfg(feature = "qualification")]
#[allow(clippy::too_many_lines)]
pub fn inspect_profile_state_for_qualification(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    let records =
        crate::prepared_store::decode_qualification_records(store_bytes).map_err(invalid)?;
    let mut facts = Vec::new();
    for reservation in records {
        let preflight = journal.iter().find(|record| {
            record.operation_id().as_str() == reservation.preflight_operation_id()
                && record.binding().profile().id() == PREFLIGHT_PROFILE
                && record.binding().profile().version() == PREFLIGHT_VERSION
        });
        let preflight = preflight.ok_or(ProfileRuntimeError::Invalid)?;
        validate_qualification_preflight_reservation(preflight, &reservation)?;
        if profile == "auths.opentofu.plan-preflight/1" {
            let operation = preflight;
            push_qualification_fact(
                &mut facts,
                operation,
                reservation.token_hash(),
                QualificationProfileStateObservationV1::ReservationDurable {
                    reservation_sha256: reservation.token_hash().to_owned(),
                },
            )?;
            let disposition = match reservation.state() {
                crate::PreparedPlanStateV1::Reserved
                    if operation.projection().effect() == OperationEffectV1::Possible =>
                {
                    Some(
                        QualificationProfileStateObservationV1::ReservationRetained {
                            reservation_sha256: reservation.token_hash().to_owned(),
                        },
                    )
                }
                crate::PreparedPlanStateV1::Reserved => None,
                crate::PreparedPlanStateV1::Expired => Some(
                    QualificationProfileStateObservationV1::ReservationReleased {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                ),
                crate::PreparedPlanStateV1::Ready
                | crate::PreparedPlanStateV1::Claimed { .. }
                | crate::PreparedPlanStateV1::Consumed { .. } => Some(
                    QualificationProfileStateObservationV1::ReservationConsumed {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                ),
            };
            if let Some(observation) = disposition {
                push_qualification_fact(
                    &mut facts,
                    operation,
                    reservation.token_hash(),
                    observation,
                )?;
            }
            continue;
        }
        if profile != "auths.opentofu.saved-plan-apply/1" {
            continue;
        }
        let operation_id = match reservation.state() {
            crate::PreparedPlanStateV1::Claimed { operation_id }
            | crate::PreparedPlanStateV1::Consumed { operation_id } => Some(operation_id.as_str()),
            _ => None,
        };
        let mut effects = journal.iter().filter(|record| {
            let token_matches =
                qualification_effect_token(record).as_deref() == Some(reservation.token_hash());
            let claimed_operation_matches = operation_id == Some(record.operation_id().as_str());
            record.binding().profile().id() == "auths.opentofu.saved-plan-apply"
                && record.binding().profile().version() == 1
                && token_matches
                && (record.sealed_command().is_some()
                    || record.projection().is_terminal()
                    || claimed_operation_matches)
        });
        let Some(operation) = effects.next() else {
            continue;
        };
        if effects.next().is_some() {
            return Err(ProfileRuntimeError::Invalid);
        }
        validate_qualification_effect_reservation(operation, &reservation)?;
        push_qualification_fact(
            &mut facts,
            operation,
            reservation.token_hash(),
            QualificationProfileStateObservationV1::ReservationDurable {
                reservation_sha256: reservation.token_hash().to_owned(),
            },
        )?;
        let disposition = match reservation.state() {
            crate::PreparedPlanStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str()
                    && operation.projection().effect() == OperationEffectV1::Possible =>
            {
                Some(
                    QualificationProfileStateObservationV1::ReservationRetained {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                )
            }
            crate::PreparedPlanStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str() =>
            {
                None
            }
            crate::PreparedPlanStateV1::Consumed { operation_id }
                if operation_id == operation.operation_id().as_str() =>
            {
                Some(
                    QualificationProfileStateObservationV1::ReservationConsumed {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                )
            }
            crate::PreparedPlanStateV1::Ready
                if operation.projection().state() == OperationStateV1::NotApplied
                    && operation.projection().is_terminal() =>
            {
                Some(
                    QualificationProfileStateObservationV1::ReservationReleased {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                )
            }
            _ => return Err(ProfileRuntimeError::Invalid),
        };
        if let Some(observation) = disposition {
            push_qualification_fact(&mut facts, operation, reservation.token_hash(), observation)?;
        }
    }
    facts.sort_by(|left, right| {
        left.operation_id.cmp(&right.operation_id).then_with(|| {
            qualification_observation_order(&left.observation)
                .cmp(&qualification_observation_order(&right.observation))
        })
    });
    Ok(facts)
}

#[cfg(feature = "qualification")]
fn validate_qualification_preflight_reservation(
    operation: &JournalRecordV1,
    reservation: &PreparedPlanRecordV1,
) -> Result<(), ProfileRuntimeError> {
    let state: PlanState = canonical_from_slice(operation.preparation_profile_state())?;
    let connection = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&state.action)?)
        .map_err(invalid)?;
    let expected_action_digest = match reservation.state() {
        crate::PreparedPlanStateV1::Reserved | crate::PreparedPlanStateV1::Expired => {
            hex::encode(Sha256::digest(canonical.body()))
        }
        crate::PreparedPlanStateV1::Ready
        | crate::PreparedPlanStateV1::Claimed { .. }
        | crate::PreparedPlanStateV1::Consumed { .. } => {
            let payload: PreparedPlanPayloadV1 =
                canonical_from_slice(reservation.payload().ok_or(ProfileRuntimeError::Invalid)?)?;
            payload.validate(payload.action.planned_at())?;
            payload.action.digest().map_err(invalid)?.to_string()
        }
    };
    if reservation.principal() != operation.binding().principal()
        || reservation.connection_id() != state.action.connection_id
        || reservation.connection_generation() != state.action.connection_generation
        || reservation.connection_id() != connection.connection_id()
        || reservation.connection_generation() != connection.generation()
        || reservation.account_commitment() != state.action.account_commitment
        || reservation.descriptor_commitment() != state.action.descriptor_commitment
        || reservation.credential_commitment() != state.action.credential_commitment
        || reservation.configuration_commitment() != state.action.configuration_commitment
        || reservation.configuration_commitment()
            != hex::encode(operation.binding().configuration_commitment())
        || reservation.tool_commitment() != state.action.tool_commitment
        || reservation.expires_at() != state.action.expires_at
        || reservation.action_digest() != expected_action_digest
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    if let Some(command) = operation.sealed_command() {
        let command: PlanCommand = canonical_from_slice(command)?;
        if command.action != state.action
            || command.bundle != state.bundle
            || command.descriptor != state.descriptor
            || command.operation_id != operation.operation_id().as_str()
            || hex::encode(Sha256::digest(command.prepared_plan.as_bytes()))
                != reservation.token_hash()
        {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    Ok(())
}

#[cfg(feature = "qualification")]
fn validate_qualification_effect_reservation(
    operation: &JournalRecordV1,
    reservation: &PreparedPlanRecordV1,
) -> Result<(), ProfileRuntimeError> {
    let state: ApplyState = canonical_from_slice(operation.preparation_profile_state())?;
    let connection = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    state.payload.validate(state.payload.action.planned_at())?;
    let command = operation
        .sealed_command()
        .map(canonical_from_slice::<ApplyCommand>)
        .transpose()?;
    let pre_command_claim = command.is_none()
        && operation.revision() == 1
        && operation.projection().state() == OperationStateV1::Ready
        && operation.projection().effect() == OperationEffectV1::NotApplied
        && !operation.projection().is_terminal()
        && matches!(
            reservation.state(),
            crate::PreparedPlanStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str()
        )
        && qualification_effect_token(operation).as_deref() == Some(reservation.token_hash());
    let pre_command_release = command.is_none()
        && operation.projection().state() == OperationStateV1::NotApplied
        && operation.projection().effect() == OperationEffectV1::NotApplied
        && operation.projection().is_terminal()
        && matches!(reservation.state(), crate::PreparedPlanStateV1::Ready)
        && qualification_effect_token(operation).as_deref() == Some(reservation.token_hash());
    if reservation.principal() != operation.binding().principal()
        || reservation.connection_id() != connection.connection_id()
        || reservation.connection_generation() != connection.generation()
        || reservation.account_commitment() != hex::encode(connection.account_commitment())
        || reservation.descriptor_commitment() != hex::encode(connection.descriptor_commitment())
        || reservation.configuration_commitment()
            != hex::encode(operation.binding().configuration_commitment())
        || reservation.payload() != Some(canonical_json(&state.payload)?.as_slice())
        || reservation.action_digest()
            != hex::encode(operation.binding().canonical_action_commitment())
        || reservation.tool_commitment()
            != state
                .payload
                .configuration
                .planner()
                .binary_sha256()
                .as_str()
        || command.as_ref().is_some_and(|command| {
            command.prepared_plan != state.prepared_plan
                || command.payload != state.payload
                || command.operation_id != operation.operation_id().as_str()
                || hex::encode(Sha256::digest(command.prepared_plan.as_bytes()))
                    != reservation.token_hash()
        })
        || (command.is_none() && !pre_command_claim && !pre_command_release)
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

#[cfg(feature = "qualification")]
fn qualification_effect_token(record: &JournalRecordV1) -> Option<String> {
    let prepared_plan = if let Some(command) = record.sealed_command() {
        canonical_from_slice::<ApplyCommand>(command)
            .ok()?
            .prepared_plan
    } else {
        canonical_from_slice::<ApplyState>(record.preparation_profile_state())
            .ok()?
            .prepared_plan
    };
    Some(hex::encode(Sha256::digest(prepared_plan.as_bytes())))
}

#[cfg(feature = "qualification")]
fn push_qualification_fact(
    facts: &mut Vec<QualificationProfileStateFactV1>,
    operation: &JournalRecordV1,
    reservation_sha256: &str,
    observation: QualificationProfileStateObservationV1,
) -> Result<(), ProfileRuntimeError> {
    if reservation_sha256.len() != 64 {
        return Err(ProfileRuntimeError::Invalid);
    }
    facts.push(QualificationProfileStateFactV1 {
        operation_id: operation.operation_id().as_str().to_owned(),
        connection_generation: operation
            .binding()
            .connection()
            .ok_or(ProfileRuntimeError::Invalid)?
            .generation(),
        observation,
    });
    Ok(())
}

#[cfg(feature = "qualification")]
const fn qualification_observation_order(value: &QualificationProfileStateObservationV1) -> u8 {
    match value {
        QualificationProfileStateObservationV1::ReservationDurable { .. } => 0,
        QualificationProfileStateObservationV1::ReservationReleased { .. }
        | QualificationProfileStateObservationV1::ReservationConsumed { .. }
        | QualificationProfileStateObservationV1::ReservationRetained { .. } => 1,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PreflightProfile;

impl ActionProfile for PreflightProfile {
    type Command = PlanPreflightActionV1;
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, bytes: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(ProfileContractError::LimitExceeded);
        }
        let value: PlanPreflightActionV1 =
            serde_json::from_slice(bytes).map_err(|_| ProfileContractError::Malformed)?;
        if canonical_json(&value).map_err(|_| ProfileContractError::Malformed)? != bytes {
            return Err(ProfileContractError::NonCanonical);
        }
        preflight_canonical_action(bytes.to_vec())
    }

    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let value: PlanPreflightActionV1 =
            serde_json::from_slice(action.body()).map_err(|_| ProfileContractError::Malformed)?;
        Ok(ReviewDisplay::new(
            "Prepare one exact OpenTofu saved plan",
            vec![
                ("Backend".into(), value.backend_identity),
                ("Workspace".into(), value.workspace),
            ],
            hex::encode(Sha256::digest(action.body())),
        ))
    }

    fn decode_verified(
        &self,
        action: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        serde_json::from_slice(action.canonical_action().body())
            .map_err(|_| ProfileContractError::Malformed)
    }
}

fn preflight_canonical_action(body: Vec<u8>) -> Result<CanonicalAction, ProfileContractError> {
    let resource = format!(
        "opentofu-plan-preflight://{}",
        hex::encode(Sha256::digest(body.as_slice()))
    );
    CanonicalAction::new(
        ProfileRef::new(
            ProfileId::parse(PREFLIGHT_PROFILE)
                .map_err(|_| ProfileContractError::UnsupportedProfile)?,
            PREFLIGHT_VERSION,
        )
        .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        MediaType::parse("application/json")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        Permission::new(
            CapabilityId::parse("opentofu.plan-preflight.create/1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::MeaningMismatch)
}

fn bundle_from_input(
    input: PlanPreflightInput,
) -> Result<OpenTofuSourceBundleV1, ProfileRuntimeError> {
    if input
        .source_files
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
        || input
            .variables
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let bundle = OpenTofuSourceBundleV1 {
        root_module_files: input
            .source_files
            .into_iter()
            .map(|value| (value.path, value.contents))
            .collect::<BTreeMap<_, _>>(),
        variable_values: input
            .variables
            .into_iter()
            .map(|value| (value.name, value.value))
            .collect::<BTreeMap<_, _>>(),
        dependency_lock_file: input.dependency_lock,
        requested_workspace: input.workspace,
    };
    bundle.validate().map_err(invalid)?;
    Ok(bundle)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VerificationClass {
    Authorized,
    Denied,
    Indeterminate,
}

fn verify_authority<P: ActionProfile>(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    action: &CanonicalAction,
    profile: &P,
    now: u64,
) -> Result<VerificationClass, ProfileRuntimeError> {
    let template = decode_verifier_context(context.trusted_context()).map_err(invalid)?;
    let request = RequestContext::new(
        template.expected_audience().as_str(),
        *template.expected_challenge().as_bytes(),
        now,
    )
    .map_err(invalid)?;
    let verifier_context = template
        .for_request(
            template.expected_audience().clone(),
            template.expected_challenge(),
            auths_model::Timestamp::new(now),
        )
        .map_err(invalid)?;
    let verifier = Verifier::self_contained(verifier_context).map_err(invalid)?;
    match verifier
        .verify(context.authority_proof(), action, &request, profile)
        .map_err(invalid)?
    {
        VerifyResult::Authorized(_) => Ok(VerificationClass::Authorized),
        VerifyResult::Denied(_) => Ok(VerificationClass::Denied),
        VerifyResult::Indeterminate(_) => Ok(VerificationClass::Indeterminate),
    }
}

fn checked_connection(
    value: Option<&auths_connections::ConnectionBinding>,
) -> Result<&auths_connections::ConnectionBinding, ProfileRuntimeError> {
    let value = value.ok_or(ProfileRuntimeError::Invalid)?;
    if value.provider_kind().as_str() != "opentofu"
        || value.contract().as_str() != "auths.opentofu.connection/1"
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    OpenTofuConnectionDescriptor::from_canonical_bytes(value.descriptor()).map_err(invalid)?;
    Ok(value)
}

fn configuration(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
) -> Result<OpenTofuLocalAgentConfigurationV1, ProfileRuntimeError> {
    OpenTofuLocalAgentConfigurationV1::from_binding(
        context
            .configuration()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )
    .map_err(invalid)
}

fn validate_record(
    record: &PreparedPlanRecordV1,
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
    parsed: &OpenTofuLocalAgentConfigurationV1,
) -> Result<(), ProfileRuntimeError> {
    if record.principal() != context.principal()
        || record.connection_id() != connection.connection_id().as_str()
        || record.connection_generation() != connection.generation().get()
        || record.account_commitment() != hex::encode(connection.account_commitment())
        || record.descriptor_commitment() != hex::encode(connection.descriptor_commitment())
        || record.credential_commitment()
            != hex::encode(connection.credential_reference_commitment())
        || record.configuration_commitment() != hex::encode(configuration.sha256())
        || record.tool_commitment() != parsed.planner().binary_sha256().as_str()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn expose_credential(
    value: Option<&auths_connections::ProviderCredentialLease>,
) -> Result<&[u8], ProfileRuntimeError> {
    value
        .ok_or(ProfileRuntimeError::Invalid)?
        .expose(Instant::now())
        .map_err(invalid)
}

fn configuration_commitment(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"auths.opentofu.local-agent-configuration/1\0");
    digest.update(context.authority_commitment());
    digest.update(connection.descriptor_commitment());
    digest.update(connection.account_commitment());
    digest.update(configuration.sha256());
    digest.finalize().into()
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProfileRuntimeError> {
    serde_json_canonicalizer::to_vec(value).map_err(invalid)
}

fn canonical_from_slice<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
) -> Result<T, ProfileRuntimeError> {
    let value: T = serde_json::from_slice(bytes).map_err(invalid)?;
    if canonical_json(&value)? != bytes {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(value)
}

fn decode_digest(value: &str) -> Result<[u8; 32], ProfileRuntimeError> {
    hex::decode(value)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| ProfileRuntimeError::Invalid)
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn invalid<T>(_: T) -> ProfileRuntimeError {
    ProfileRuntimeError::Invalid
}

fn denied_error(code: &'static str, correlation: &str) -> ProfileRuntimeError {
    issue_denied(code, correlation)
        .map_or(ProfileRuntimeError::Invalid, ProfileRuntimeError::PreEntry)
}

fn possible_error(code: &'static str, correlation: &str) -> ProfileRuntimeError {
    issue_unknown(code, correlation)
        .map_or(ProfileRuntimeError::Invalid, ProfileRuntimeError::Possible)
}

fn issue_denied(code: &str, correlation: &str) -> Result<Vec<u8>, ProfileRuntimeError> {
    issue(
        code,
        "profile-evaluation",
        "The exact OpenTofu operation was not authorized.",
        correlation,
        RetryClass::Never,
        EffectState::NotApplied,
        RecommendedAction::SatisfyCondition,
        false,
    )
}

fn issue_indeterminate(correlation: &str) -> Result<Vec<u8>, ProfileRuntimeError> {
    issue(
        "core.authorization-indeterminate",
        "authorization",
        "Required authority evidence was unavailable before OpenTofu entry.",
        correlation,
        RetryClass::Conditional,
        EffectState::NotApplied,
        RecommendedAction::SatisfyCondition,
        false,
    )
}

fn issue_unknown(code: &str, correlation: &str) -> Result<Vec<u8>, ProfileRuntimeError> {
    issue(
        code,
        "provider-observation",
        "OpenTofu recovery must establish the exact durable outcome.",
        correlation,
        RetryClass::Unknown,
        EffectState::Possible,
        RecommendedAction::ResumeAndReconcile,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue(
    code: &str,
    stage: &str,
    summary: &str,
    correlation: &str,
    retry: RetryClass,
    effect: EffectState,
    action: RecommendedAction,
    provider_entered: bool,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    ErrorEnvelope::parse(ErrorEnvelopeInput {
        code: code.into(),
        operation: if code == "core.authorization-indeterminate" {
            "verify".into()
        } else {
            "execute".into()
        },
        stage: stage.into(),
        summary: summary.into(),
        correlation_id: correlation.into(),
        retry,
        effect,
        entered: EnteredBoundaries {
            approval: false,
            signer: false,
            state: provider_entered,
            credential: provider_entered,
            provider: provider_entered,
        },
        recommended_action: action,
        execution_reference: provider_entered.then(|| correlation.into()),
        decision_reference: None,
        receipt_reference: None,
        causes: vec![CauseCategory::Unavailable],
    })
    .and_then(|value| value.to_canonical_cbor())
    .map_err(invalid)
}
