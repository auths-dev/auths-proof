//! Statically linked local-agent verticals for PostgreSQL preflight and update.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::unused_async
)]

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

/// PostgreSQL's current seal functions already persist their protected reread
/// projection. This explicit hook makes the common post-command boundary
/// durable and will own the reread when that domain is migrated independently.
pub fn update_preflights_create_recheck_pre_entry(
    input: PreEntryRecheckInput<'_>,
) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {
    unchanged_pre_entry_recheck(input)
}

pub fn updates_execute_recheck_pre_entry(
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
#[cfg(feature = "qualification")]
use auths_stores::JournalRecordV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::time::Instant;

use crate::{
    DecisionClass as PostgresDecisionClass, EvaluationContext, PostgresBoundedUpdateProfile,
    PostgresLocalAgentConfigurationV1, PostgresPreflightActionV1, PreparedUpdatePayloadV1,
    PreparedUpdateRecordV1, PreparedUpdateStore, PreparedUpdateStoreError, TransactionResult,
    connection::PostgresConnectionDescriptor,
    generated::profile_api::{
        PreparedUpdate, PreparedUpdateInput, UpdatePreflightInput, UpdateResult,
    },
};

const PREFLIGHT_PROFILE: &str = "auths.postgresql.update-preflight";
const PREFLIGHT_VERSION: u16 = 1;

/// Rebuilds the exact preflight decision receipt claims.
pub fn update_preflights_create_build_decision_receipt_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Decision,
        update_preflights_create_decision_commitments(facts)?,
    )
}

fn update_preflights_create_decision_commitments(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != PREFLIGHT_PROFILE || facts.binding.profile().version() != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: PreflightState = canonical_from_slice(facts.profile_state)?;
    decision_claims(facts, &canonical_json(&state)?, &state.descriptor)
}

/// Rebuilds the exact bounded-update decision receipt claims.
pub fn updates_execute_build_decision_receipt_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Decision,
        updates_execute_decision_commitments(facts)?,
    )
}

fn updates_execute_decision_commitments(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != "auths.postgresql.bounded-update"
        || facts.binding.profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: UpdateState = canonical_from_slice(facts.profile_state)?;
    decision_claims(facts, &canonical_json(&state)?, b"prepared-update")
}

fn decision_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
    state: &[u8],
    destination: &[u8],
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    let connection = facts
        .binding
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    Ok(vec![
        claim(
            "postgresql.connection",
            &[
                connection.descriptor_commitment(),
                connection.account_commitment(),
            ],
        ),
        claim(
            "postgresql.decision",
            &[
                &facts.receipt_action_commitment,
                &facts.receipt_context_commitment,
            ],
        ),
        claim("postgresql.destination", &[destination, state]),
        claim(
            "postgresql.evidence",
            &[state, facts.binding.authority_commitment()],
        ),
        claim(
            "postgresql.preparation",
            &[facts.binding.preparation_commitment()],
        ),
    ])
}

/// Rebuilds the exact preflight execution receipt claims.
pub fn update_preflights_create_build_execution_receipt_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Execution,
        update_preflights_create_execution_commitments(facts)?,
    )
}

fn update_preflights_create_execution_commitments(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != PREFLIGHT_PROFILE || facts.binding.profile().version() != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: PreflightState = canonical_from_slice(facts.profile_state)?;
    let command: PreflightCommand = canonical_from_slice(facts.sealed_command)?;
    if let Some(provider) = facts.provider_result {
        let _: PreflightProviderResult = canonical_from_slice(provider)?;
    }
    Ok(execution_claims(
        facts,
        command.prepared_update.as_bytes(),
        &canonical_json(&state)?,
    ))
}

/// Rebuilds the exact bounded-update execution receipt claims.
pub fn updates_execute_build_execution_receipt_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    encode_claims(
        &profile,
        ProfileReceiptClaimPhase::Execution,
        updates_execute_execution_commitments(facts)?,
    )
}

fn updates_execute_execution_commitments(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if facts.binding.profile().id() != "auths.postgresql.bounded-update"
        || facts.binding.profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: UpdateState = canonical_from_slice(facts.profile_state)?;
    let _: UpdateCommand = canonical_from_slice(facts.sealed_command)?;
    if let Some(provider) = facts.provider_result {
        let _: TransactionResult = canonical_from_slice(provider)?;
    }
    Ok(execution_claims(
        facts,
        state.prepared_update.as_bytes(),
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
        claim("postgresql.command", &[facts.sealed_command]),
        claim(
            "postgresql.execution-ledger",
            &[facts.operation_id.as_str().as_bytes(), provider],
        ),
        claim(
            "postgresql.execution-recheck",
            &[facts.sealed_command, &observations],
        ),
        claim("postgresql.prepared-store", &[state, reservation]),
        claim("postgresql.provider-result", &[provider, &observations]),
        claim(
            "postgresql.receipt-payload",
            &[state, facts.sealed_command, provider],
        ),
        claim(
            "postgresql.reconciliation",
            &[
                facts.operation_id.as_str().as_bytes(),
                facts.sealed_command,
                reservation,
            ],
        ),
        claim("postgresql.reservation", &[reservation, state]),
    ]
}

/// Inspects exact preflight receipt claims against immutable mint facts and current truth.
pub fn update_preflights_create_inspect_receipt_claims(
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if inspection.facts.binding().profile().id() != PREFLIGHT_PROFILE
        || inspection.facts.binding().profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    inspect_exact(
        inspection,
        update_preflights_create_build_decision_receipt_claims,
        update_preflights_create_build_execution_receipt_claims,
    )?;
    if inspection.execution_claims.is_none() {
        return Ok(());
    }
    let command: PreflightCommand = canonical_from_slice(
        inspection
            .facts
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    if command.operation_id != inspection.facts.operation_id().as_str() {
        return Err(ProfileRuntimeError::Invalid);
    }
    if let Some(provider) = inspection.facts.provider_result() {
        let result: PreflightProviderResult = canonical_from_slice(provider)?;
        if result.prepared_update != command.prepared_update {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    Ok(())
}

/// Inspects exact bounded-update receipt claims and terminal reconciliation truth.
pub fn updates_execute_inspect_receipt_claims(
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if inspection.facts.binding().profile().id() != "auths.postgresql.bounded-update"
        || inspection.facts.binding().profile().version() != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    inspect_exact(
        inspection,
        updates_execute_build_decision_receipt_claims,
        updates_execute_build_execution_receipt_claims,
    )?;
    if inspection.execution_claims.is_none() {
        return Ok(());
    }
    let command: UpdateCommand = canonical_from_slice(
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
        if observation.as_slice() == b"postgresql-ledger-not-committed" {
            if inspection.facts.projection().effect() != OperationEffectV1::NotApplied {
                return Err(ProfileRuntimeError::Invalid);
            }
        } else {
            let result: TransactionResult = canonical_from_slice(observation)?;
            let reconciled = inspection.facts.completion()
                == Some(auths_stores::JournalCompletionV1::Reconciled);
            if result.reconciled != reconciled
                || result.affected_rows != command.payload.action.intent.expected_row_count
                || result.after_state_digest != command.payload.action.after_state_digest
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
    profile_receipt_claim_digest("postgresql.observations", &parts)
}

pub fn validate_profile_configuration(
    binding: &auths_profile_runtime::ProfileConfigurationBinding,
) -> Result<(), ProfileRuntimeError> {
    PostgresLocalAgentConfigurationV1::from_binding(binding)
        .map(|_| ())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

pub fn update_preflights_create_prepare(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = UpdatePreflightInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("postgresql.preflight-denied", "postgresql-preflight-input"))?;
    let connection = checked_connection(input.connection)?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration = PostgresLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let expires_at = input
        .now_unix_seconds
        .checked_add(configuration.prepared_update_lifetime_seconds())
        .ok_or(ProfileRuntimeError::Invalid)?;
    let action = PostgresPreflightActionV1::from_input(
        &generated,
        connection,
        &configuration,
        binding.sha256(),
        expires_at,
    )
    .map_err(|_| denied_error("postgresql.preflight-denied", "postgresql-preflight-input"))?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&action)?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let canonical_action =
        encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?;
    let kind = match verify_authority(
        input.context,
        &canonical,
        &PreflightProfile,
        input.now_unix_seconds,
    )? {
        VerificationClass::Authorized => ProfilePreparationKind::Ready,
        VerificationClass::Denied => ProfilePreparationKind::Denied {
            issue: issue_denied(
                "postgresql.preflight-denied",
                "postgresql-preflight-authority",
            )?,
        },
        VerificationClass::Indeterminate => ProfilePreparationKind::Unavailable {
            issue: issue_indeterminate("postgresql-preflight-authority")?,
        },
    };
    Ok(ProfilePreparation {
        canonical_input_commitment: Sha256::digest(input.profile_input).into(),
        canonical_action_commitment: Sha256::digest(&canonical_action).into(),
        configuration_commitment: configuration_commitment(input.context, connection, binding),
        canonical_action,
        decision_reason: match kind {
            ProfilePreparationKind::Ready => "postgresql.preflight-authorized",
            ProfilePreparationKind::Denied { .. } => "postgresql.preflight-denied",
            ProfilePreparationKind::Unavailable { .. } => "core.authorization-indeterminate",
        }
        .into(),
        profile_state: canonical_json(&PreflightState {
            action,
            descriptor: connection.descriptor().to_vec(),
            prepared_update: None,
        })?,
        kind,
    })
}

pub async fn update_preflights_create_seal_provider_call(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let mut state: PreflightState = canonical_from_slice(input.record.profile_state())?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration = PostgresLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    state
        .action
        .validate(configuration.verifier())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&state.action)?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if verify_authority(
        input.context,
        &canonical,
        &PreflightProfile,
        input.now_unix_seconds,
    )? != VerificationClass::Authorized
    {
        return Err(denied_error(
            "postgresql.preflight-denied",
            input.record.operation_id().as_str(),
        ));
    }
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let token = if let Some(token) = &state.prepared_update {
        token.clone()
    } else {
        let token =
            PreparedUpdateStore::generate_token().map_err(|_| ProfileRuntimeError::Invalid)?;
        let descriptor = PostgresConnectionDescriptor::from_canonical_bytes(&state.descriptor)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let action_digest: [u8; 32] = Sha256::digest(canonical.body()).into();
        let record = PreparedUpdateRecordV1::reserved(
            &token,
            input.record.operation_id().as_str(),
            input.context.principal(),
            &state.action.connection_id,
            state.action.connection_generation,
            &descriptor.account_commitment(),
            &decode_digest(&state.action.descriptor_commitment)?,
            &decode_digest(&state.action.credential_commitment)?,
            &binding.sha256(),
            &action_digest,
            state.action.expires_at,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        store.reserve(record).map_err(|error| match error {
            PreparedUpdateStoreError::Conflict => denied_error(
                "postgresql.preflight-denied",
                input.record.operation_id().as_str(),
            ),
            _ => ProfileRuntimeError::Invalid,
        })?;
        state.prepared_update = Some(token.clone());
        token
    };
    Ok(SealedProfileCall {
        command: canonical_json(&PreflightCommand {
            action: state.action.clone(),
            descriptor: state.descriptor.clone(),
            prepared_update: token,
            operation_id: input.record.operation_id().as_str().into(),
        })?,
        profile_state: canonical_json(&state)?,
    })
}

/// Invalidates a preflight capability reserved by sealing when the common
/// journal still proves that protected discovery never began.
pub fn update_preflights_create_release_pre_entry(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if let Some(bytes) = input.record.sealed_command() {
        let command: PreflightCommand = canonical_from_slice(bytes)?;
        store
            .deny_reserved(&command.prepared_update, &command.operation_id)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    } else {
        store
            .deny_reserved_by_operation(input.record.operation_id().as_str())
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    }
    Ok(())
}

pub async fn update_preflights_create_call_provider(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: PreflightCommand = canonical_from_slice(&input.call.command)?;
    let descriptor = PostgresConnectionDescriptor::from_canonical_bytes(&command.descriptor)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let configuration = configuration(input.context)?;
    let credential = expose_credential(input.credential)?;
    let payload = crate::local_provider::discover(
        credential,
        &descriptor,
        configuration.verifier(),
        &command.action,
        &command.prepared_update,
        input.now_unix_seconds,
    )
    .await
    .map_err(|_| {
        possible_error(
            "postgresql.preflight-outcome-unknown",
            &command.operation_id,
        )
    })?;
    canonical_json(&PreflightProviderResult {
        prepared_update: command.prepared_update,
        payload,
    })
}

#[cfg(feature = "qualification")]
pub(crate) async fn update_preflights_create_transport_from_bytes(
    command: &[u8],
    credential: &[u8],
    configuration: &[u8],
    now_unix_seconds: u64,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: PreflightCommand = canonical_from_slice(command)?;
    let descriptor = PostgresConnectionDescriptor::from_canonical_bytes(&command.descriptor)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let configuration = PostgresLocalAgentConfigurationV1::from_canonical_bytes(configuration)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let payload = crate::local_provider::discover(
        credential,
        &descriptor,
        configuration.verifier(),
        &command.action,
        &command.prepared_update,
        now_unix_seconds,
    )
    .await
    .map_err(|_| {
        possible_error(
            "postgresql.preflight-outcome-unknown",
            &command.operation_id,
        )
    })?;
    canonical_json(&PreflightProviderResult {
        prepared_update: command.prepared_update,
        payload,
    })
}

pub fn update_preflights_create_observe_provider_result(
    input: ObserveProviderResultInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let result: PreflightProviderResult = canonical_from_slice(input.provider_result)?;
    result
        .payload
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if !payload_is_authorized(&result.payload, input.now_unix_seconds)? {
        let store = PreparedUpdateStore::open(input.context.profile_state_root())
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        store
            .deny_reserved(
                &result.prepared_update,
                input.record.operation_id().as_str(),
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        return Ok(ProfileObservation {
            bytes: input.provider_result.to_vec(),
            conclusion: ProfileConclusion::NotApplied {
                issue: issue_denied(
                    "postgresql.preflight-denied",
                    input.record.operation_id().as_str(),
                )?,
                profile_state: input.record.profile_state().to_vec(),
            },
        });
    }
    let action_digest = result
        .payload
        .action
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let action_digest_bytes = decode_digest(action_digest.as_str())?;
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let record = store
        .mark_ready(
            &result.prepared_update,
            input.record.operation_id().as_str(),
            &action_digest_bytes,
            canonical_json(&result.payload)?,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let value = PreparedUpdate {
        prepared_update: result.prepared_update,
        action_digest: action_digest.to_string(),
        matched_rows: result.payload.action.intent.expected_row_count,
        expires_at: record.expires_at(),
    }
    .to_canonical_cbor()
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(ProfileObservation {
        bytes: input.provider_result.to_vec(),
        conclusion: ProfileConclusion::Completed {
            value,
            profile_state: input.record.profile_state().to_vec(),
        },
    })
}

pub async fn update_preflights_create_reconcile(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: PreflightCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let call = SealedProfileCall {
        command: canonical_json(&command)?,
        profile_state: input.record.profile_state().to_vec(),
    };
    let bytes = update_preflights_create_call_provider(CallProviderInput {
        context: input.context,
        call: &call,
        credential: input.credential,
        now_unix_seconds: input.now_unix_seconds,
    })
    .await?;
    update_preflights_create_observe_provider_result(ObserveProviderResultInput {
        context: input.context,
        record: input.record,
        provider_result: &bytes,
        now_unix_seconds: input.now_unix_seconds,
    })
}

pub fn updates_execute_prepare(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = PreparedUpdateInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("postgresql.update-denied", "postgresql-update-input"))?;
    let connection = checked_connection(input.connection)?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let configuration = PostgresLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let record = store
        .load_ready(&generated.prepared_update, input.now_unix_seconds)
        .map_err(|_| denied_error("postgresql.update-denied", "postgresql-prepared-update"))?;
    validate_record(&record, input.context, connection, binding)?;
    let payload: PreparedUpdatePayloadV1 =
        canonical_from_slice(record.payload().ok_or(ProfileRuntimeError::Invalid)?)?;
    payload
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if !payload_is_authorized(&payload, input.now_unix_seconds)? {
        return Err(denied_error(
            "postgresql.update-denied",
            "postgresql-prepared-update",
        ));
    }
    if payload.configuration != *configuration.verifier()
        || payload
            .action
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?
            .as_str()
            != record.action_digest()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let canonical = PostgresBoundedUpdateProfile
        .canonicalize(
            &payload
                .action
                .canonical_bytes()
                .map_err(|_| ProfileRuntimeError::Invalid)?,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let canonical_action =
        encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?;
    let kind = match verify_authority(
        input.context,
        &canonical,
        &PostgresBoundedUpdateProfile,
        input.now_unix_seconds,
    )? {
        VerificationClass::Authorized => ProfilePreparationKind::Ready,
        VerificationClass::Denied => ProfilePreparationKind::Denied {
            issue: issue_denied("postgresql.update-denied", "postgresql-update-authority")?,
        },
        VerificationClass::Indeterminate => ProfilePreparationKind::Unavailable {
            issue: issue_indeterminate("postgresql-update-authority")?,
        },
    };
    Ok(ProfilePreparation {
        canonical_input_commitment: Sha256::digest(input.profile_input).into(),
        canonical_action_commitment: Sha256::digest(&canonical_action).into(),
        configuration_commitment: configuration_commitment(input.context, connection, binding),
        canonical_action,
        decision_reason: match kind {
            ProfilePreparationKind::Ready => "postgresql.update-authorized",
            ProfilePreparationKind::Denied { .. } => "postgresql.update-denied",
            ProfilePreparationKind::Unavailable { .. } => "core.authorization-indeterminate",
        }
        .into(),
        profile_state: canonical_json(&UpdateState {
            prepared_update: generated.prepared_update,
            payload,
        })?,
        kind,
    })
}

pub async fn updates_execute_seal_provider_call(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let state: UpdateState = canonical_from_slice(input.record.profile_state())?;
    if !payload_is_authorized(&state.payload, input.now_unix_seconds)? {
        return Err(denied_error(
            "postgresql.update-denied",
            input.record.operation_id().as_str(),
        ));
    }
    let canonical = PostgresBoundedUpdateProfile
        .canonicalize(
            &state
                .payload
                .action
                .canonical_bytes()
                .map_err(|_| ProfileRuntimeError::Invalid)?,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if verify_authority(
        input.context,
        &canonical,
        &PostgresBoundedUpdateProfile,
        input.now_unix_seconds,
    )? != VerificationClass::Authorized
    {
        return Err(denied_error(
            "postgresql.update-denied",
            input.record.operation_id().as_str(),
        ));
    }
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    store
        .claim(
            &state.prepared_update,
            input.record.operation_id().as_str(),
            input.now_unix_seconds,
        )
        .map_err(|_| {
            denied_error(
                "postgresql.update-denied",
                input.record.operation_id().as_str(),
            )
        })?;
    Ok(SealedProfileCall {
        command: canonical_json(&UpdateCommand {
            prepared_update: state.prepared_update,
            payload: state.payload,
            operation_id: input.record.operation_id().as_str().into(),
        })?,
        profile_state: input.record.profile_state().to_vec(),
    })
}

/// Releases the single-use prepared update only while the common journal
/// still proves that the PostgreSQL transaction was never entered.
pub fn updates_execute_release_pre_entry(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if let Some(bytes) = input.record.sealed_command() {
        let command: UpdateCommand = canonical_from_slice(bytes)?;
        store
            .release_claim(&command.prepared_update, &command.operation_id)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    } else {
        store
            .release_claim_by_operation(input.record.operation_id().as_str())
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    }
    Ok(())
}

pub async fn updates_execute_call_provider(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: UpdateCommand = canonical_from_slice(&input.call.command)?;
    let credential = expose_credential(input.credential)?;
    let result = crate::local_provider::execute(
        credential,
        &command.payload,
        &command.operation_id,
        input.now_unix_seconds,
    )
    .await
    .map_err(|_| possible_error("postgresql.update-outcome-unknown", &command.operation_id))?;
    canonical_json(&result)
}

#[cfg(feature = "qualification")]
pub(crate) async fn updates_execute_transport_from_bytes(
    command: &[u8],
    credential: &[u8],
    now_unix_seconds: u64,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: UpdateCommand = canonical_from_slice(command)?;
    let result = crate::local_provider::execute(
        credential,
        &command.payload,
        &command.operation_id,
        now_unix_seconds,
    )
    .await
    .map_err(|_| possible_error("postgresql.update-outcome-unknown", &command.operation_id))?;
    canonical_json(&result)
}

pub(crate) async fn updates_execute_reconcile_transport_from_bytes(
    command: &[u8],
    credential: &[u8],
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    let command: UpdateCommand = canonical_from_slice(command)?;
    let result =
        crate::local_provider::reconcile(credential, &command.payload, &command.operation_id)
            .await
            .map_err(|_| {
                possible_error("postgresql.update-outcome-unknown", &command.operation_id)
            })?;
    result
        .map(|mut result| {
            result.reconciled = true;
            canonical_json(&result)
        })
        .transpose()
}

/// Independently reads the exercised PostgreSQL destination and returns only
/// the closed effect plus the canonical redacted facts retained by the
/// ProviderObserver source. This never performs a mutation.
#[cfg(feature = "qualification")]
#[allow(clippy::items_after_statements)]
pub async fn observe_provider_truth_for_qualification(
    record: &JournalRecordV1,
    credential: &[u8],
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
    let operation_id = record.operation_id().as_str();
    let (payload, applied, transaction_sha256, include_rows) = match profile.as_str() {
        "auths.postgresql.update-preflight/1" => {
            let result: PreflightProviderResult = canonical_from_slice(
                record
                    .provider_result()
                    .ok_or(ProfileRuntimeError::Invalid)?,
            )?;
            result
                .payload
                .validate()
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            let command: PreflightCommand = canonical_from_slice(
                record
                    .sealed_command()
                    .ok_or(ProfileRuntimeError::Invalid)?,
            )?;
            let descriptor =
                PostgresConnectionDescriptor::from_canonical_bytes(&command.descriptor)
                    .map_err(|_| ProfileRuntimeError::Invalid)?;
            let fresh = crate::local_provider::discover(
                credential,
                &descriptor,
                &result.payload.configuration,
                &command.action,
                &command.prepared_update,
                now_unix_seconds,
            )
            .await?;
            let original_rows = &result.payload.action.intent.rows;
            let current_rows = &fresh.action.intent.rows;
            if fresh.action.database_server_identity
                != result.payload.action.database_server_identity
                || fresh.action.intent.database_name != result.payload.action.intent.database_name
                || current_rows.len() != original_rows.len()
                || current_rows
                    .iter()
                    .zip(original_rows)
                    .any(|(current, original)| {
                        current.primary_key != original.primary_key
                            || (current.row_version != original.row_version
                                && current.row_version != original.row_version.saturating_add(1))
                    })
            {
                return Err(ProfileRuntimeError::Invalid);
            }
            // The preflight event commits the original provider observation.
            // A paired effect may have advanced the row once before this
            // protected post-seal re-read; return the signed historical facts
            // after independently proving the same destination and key set.
            (result.payload, false, None, false)
        }
        "auths.postgresql.bounded-update/1" => {
            let state: UpdateState = canonical_from_slice(record.profile_state())?;
            state
                .payload
                .validate()
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            let result =
                crate::local_provider::reconcile(credential, &state.payload, operation_id).await?;
            let transaction_sha256 = result
                .as_ref()
                .map(|result| {
                    canonical_json(&(
                        operation_id,
                        result.ledger_commitment.as_str(),
                        result.committed_at,
                    ))
                    .map(|bytes| hex::encode(Sha256::digest(bytes)))
                })
                .transpose()?;
            (state.payload, result.is_some(), transaction_sha256, true)
        }
        _ => return Err(ProfileRuntimeError::Invalid),
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct TruthRow {
        primary_key_sha256: String,
        before_version: u64,
        after_version: u64,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Truth {
        server_identity_sha256: String,
        database_sha256: String,
        transaction_sha256: Option<String>,
        ledger_operation_sha256: String,
        rows: Vec<TruthRow>,
        applied: bool,
    }
    let rows = if include_rows {
        payload
            .action
            .intent
            .rows
            .iter()
            .map(|row| {
                let before_version =
                    u64::try_from(row.row_version).map_err(|_| ProfileRuntimeError::Invalid)?;
                Ok(TruthRow {
                    primary_key_sha256: hex::encode(Sha256::digest(canonical_json(
                        &row.primary_key,
                    )?)),
                    before_version,
                    after_version: before_version.saturating_add(u64::from(applied)),
                })
            })
            .collect::<Result<Vec<_>, ProfileRuntimeError>>()?
    } else {
        Vec::new()
    };
    let truth = Truth {
        server_identity_sha256: hex::encode(Sha256::digest(
            payload.action.database_server_identity.as_bytes(),
        )),
        database_sha256: hex::encode(Sha256::digest(
            payload.action.intent.database_name.as_str().as_bytes(),
        )),
        transaction_sha256,
        ledger_operation_sha256: hex::encode(Sha256::digest(operation_id.as_bytes())),
        rows,
        applied,
    };
    let effect = if applied {
        QualificationEffect::Applied
    } else {
        QualificationEffect::NotApplied
    };
    canonical_json(&truth).map(|bytes| (effect, bytes))
}

pub fn updates_execute_observe_provider_result(
    input: ObserveProviderResultInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: UpdateCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let result: TransactionResult = canonical_from_slice(input.provider_result)?;
    if result.affected_rows != command.payload.action.intent.expected_row_count
        || result.after_state_digest != command.payload.action.after_state_digest
    {
        return Ok(ProfileObservation {
            bytes: input.provider_result.to_vec(),
            conclusion: ProfileConclusion::RecoveryRequired {
                issue: issue_unknown(
                    "postgresql.update-outcome-unknown",
                    input.record.operation_id().as_str(),
                )?,
                progress: None,
                profile_state: input.record.profile_state().to_vec(),
            },
        });
    }
    let store = PreparedUpdateStore::open(input.context.profile_state_root())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    store
        .consume(
            &command.prepared_update,
            input.record.operation_id().as_str(),
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let value = UpdateResult {
        affected_rows: result.affected_rows,
        after_state_digest: result.after_state_digest.to_string(),
    }
    .to_canonical_cbor()
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(ProfileObservation {
        bytes: input.provider_result.to_vec(),
        conclusion: ProfileConclusion::Completed {
            value,
            profile_state: input.record.profile_state().to_vec(),
        },
    })
}

pub async fn updates_execute_reconcile(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let credential = expose_credential(input.credential)?;
    let result = updates_execute_reconcile_transport_from_bytes(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
        credential,
    )
    .await?;
    updates_execute_finalize_reconcile_transport(input, result.as_deref())
}

pub fn updates_execute_finalize_reconcile_transport(
    input: ReconcileProfileInput<'_>,
    result: Option<&[u8]>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let command: UpdateCommand = canonical_from_slice(
        input
            .record
            .sealed_command()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )?;
    let Some(bytes) = result else {
        let store = PreparedUpdateStore::open(input.context.profile_state_root())
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        store
            .release_claim(&command.prepared_update, &command.operation_id)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        return Ok(ProfileObservation {
            bytes: b"postgresql-ledger-not-committed".to_vec(),
            conclusion: ProfileConclusion::NotApplied {
                issue: issue_denied(
                    "postgresql.update-denied",
                    input.record.operation_id().as_str(),
                )?,
                profile_state: input.record.profile_state().to_vec(),
            },
        });
    };
    updates_execute_observe_provider_result(ObserveProviderResultInput {
        context: input.context,
        record: input.record,
        provider_result: bytes,
        now_unix_seconds: input.now_unix_seconds,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreflightState {
    action: PostgresPreflightActionV1,
    descriptor: Vec<u8>,
    prepared_update: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreflightCommand {
    action: PostgresPreflightActionV1,
    descriptor: Vec<u8>,
    prepared_update: String,
    operation_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreflightProviderResult {
    prepared_update: String,
    payload: PreparedUpdatePayloadV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateState {
    prepared_update: String,
    payload: PreparedUpdatePayloadV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateCommand {
    prepared_update: String,
    payload: PreparedUpdatePayloadV1,
    operation_id: String,
}

/// Independently decodes the canonical prepared-update store and projects
/// only the stable, capability-free reservation facts for one exact phase.
#[cfg(feature = "qualification")]
pub fn inspect_profile_state_for_qualification(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    let records = crate::prepared_store::decode_qualification_records(store_bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut facts = Vec::new();
    for reservation in records {
        let preflight = journal.iter().find(|record| {
            record.operation_id().as_str() == reservation.preflight_operation_id()
                && record.binding().profile().id() == PREFLIGHT_PROFILE
                && record.binding().profile().version() == PREFLIGHT_VERSION
        });
        let preflight = preflight.ok_or(ProfileRuntimeError::Invalid)?;
        validate_qualification_preflight_reservation(preflight, &reservation)?;
        if profile == "auths.postgresql.update-preflight/1" {
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
                crate::PreparedUpdateStateV1::Reserved
                    if operation.projection().effect() == OperationEffectV1::Possible =>
                {
                    Some(
                        QualificationProfileStateObservationV1::ReservationRetained {
                            reservation_sha256: reservation.token_hash().to_owned(),
                        },
                    )
                }
                crate::PreparedUpdateStateV1::Reserved => None,
                crate::PreparedUpdateStateV1::Expired => Some(
                    QualificationProfileStateObservationV1::ReservationReleased {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                ),
                crate::PreparedUpdateStateV1::Ready
                | crate::PreparedUpdateStateV1::Claimed { .. }
                | crate::PreparedUpdateStateV1::Consumed { .. } => Some(
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
        if profile != "auths.postgresql.bounded-update/1" {
            continue;
        }
        let operation_id = match reservation.state() {
            crate::PreparedUpdateStateV1::Claimed { operation_id }
            | crate::PreparedUpdateStateV1::Consumed { operation_id } => {
                Some(operation_id.as_str())
            }
            _ => None,
        };
        let mut effects = journal.iter().filter(|record| {
            let token_matches =
                qualification_effect_token(record).as_deref() == Some(reservation.token_hash());
            let claimed_operation_matches = operation_id == Some(record.operation_id().as_str());
            record.binding().profile().id() == "auths.postgresql.bounded-update"
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
            crate::PreparedUpdateStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str()
                    && operation.projection().effect() == OperationEffectV1::Possible =>
            {
                Some(
                    QualificationProfileStateObservationV1::ReservationRetained {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                )
            }
            crate::PreparedUpdateStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str() =>
            {
                None
            }
            crate::PreparedUpdateStateV1::Consumed { operation_id }
                if operation_id == operation.operation_id().as_str() =>
            {
                Some(
                    QualificationProfileStateObservationV1::ReservationConsumed {
                        reservation_sha256: reservation.token_hash().to_owned(),
                    },
                )
            }
            crate::PreparedUpdateStateV1::Ready
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
    reservation: &PreparedUpdateRecordV1,
) -> Result<(), ProfileRuntimeError> {
    let state: PreflightState = canonical_from_slice(operation.preparation_profile_state())?;
    let connection = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let canonical = PreflightProfile
        .canonicalize(&canonical_json(&state.action)?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let expected_action_digest = match reservation.state() {
        crate::PreparedUpdateStateV1::Reserved | crate::PreparedUpdateStateV1::Expired => {
            hex::encode(Sha256::digest(canonical.body()))
        }
        crate::PreparedUpdateStateV1::Ready
        | crate::PreparedUpdateStateV1::Claimed { .. }
        | crate::PreparedUpdateStateV1::Consumed { .. } => {
            let payload: PreparedUpdatePayloadV1 =
                canonical_from_slice(reservation.payload().ok_or(ProfileRuntimeError::Invalid)?)?;
            payload
                .validate()
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            payload
                .action
                .digest()
                .map_err(|_| ProfileRuntimeError::Invalid)?
                .to_string()
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
        || reservation.expires_at() != state.action.expires_at
        || reservation.action_digest() != expected_action_digest
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    if let Some(command) = operation.sealed_command() {
        let command: PreflightCommand = canonical_from_slice(command)?;
        if command.action != state.action
            || command.descriptor != state.descriptor
            || command.operation_id != operation.operation_id().as_str()
            || hex::encode(Sha256::digest(command.prepared_update.as_bytes()))
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
    reservation: &PreparedUpdateRecordV1,
) -> Result<(), ProfileRuntimeError> {
    let state: UpdateState = canonical_from_slice(operation.preparation_profile_state())?;
    let connection = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    state
        .payload
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let command = operation
        .sealed_command()
        .map(canonical_from_slice::<UpdateCommand>)
        .transpose()?;
    let pre_command_claim = command.is_none()
        && operation.revision() == 1
        && operation.projection().state() == OperationStateV1::Ready
        && operation.projection().effect() == OperationEffectV1::NotApplied
        && !operation.projection().is_terminal()
        && matches!(
            reservation.state(),
            crate::PreparedUpdateStateV1::Claimed { operation_id }
                if operation_id == operation.operation_id().as_str()
        )
        && qualification_effect_token(operation).as_deref() == Some(reservation.token_hash());
    let pre_command_release = command.is_none()
        && operation.projection().state() == OperationStateV1::NotApplied
        && operation.projection().effect() == OperationEffectV1::NotApplied
        && operation.projection().is_terminal()
        && matches!(reservation.state(), crate::PreparedUpdateStateV1::Ready)
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
        || command.as_ref().is_some_and(|command| {
            command.prepared_update != state.prepared_update
                || command.payload != state.payload
                || command.operation_id != operation.operation_id().as_str()
                || hex::encode(Sha256::digest(command.prepared_update.as_bytes()))
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
    let prepared_update = if let Some(command) = record.sealed_command() {
        canonical_from_slice::<UpdateCommand>(command)
            .ok()?
            .prepared_update
    } else {
        canonical_from_slice::<UpdateState>(record.preparation_profile_state())
            .ok()?
            .prepared_update
    };
    Some(hex::encode(Sha256::digest(prepared_update.as_bytes())))
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
    let generation = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?
        .generation();
    facts.push(QualificationProfileStateFactV1 {
        operation_id: operation.operation_id().as_str().to_owned(),
        connection_generation: generation,
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
    type Command = PostgresPreflightActionV1;
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;
    fn canonicalize(&self, bytes: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: PostgresPreflightActionV1 =
            serde_json::from_slice(bytes).map_err(|_| ProfileContractError::Malformed)?;
        if canonical_json(&action).map_err(|_| ProfileContractError::Malformed)? != bytes {
            return Err(ProfileContractError::NonCanonical);
        }
        preflight_canonical_action(bytes.to_vec())
    }
    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let value: PostgresPreflightActionV1 =
            serde_json::from_slice(action.body()).map_err(|_| ProfileContractError::Malformed)?;
        Ok(ReviewDisplay::new(
            "Prepare one bounded PostgreSQL update",
            vec![
                ("Relation".into(), value.relation),
                ("Assignments".into(), value.assignments.len().to_string()),
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
        "postgresql-preflight://{}",
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
            CapabilityId::parse("postgresql.update-preflight.create/1")
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
    let template = decode_verifier_context(context.trusted_context())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let request = RequestContext::new(
        template.expected_audience().as_str(),
        *template.expected_challenge().as_bytes(),
        now,
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let verifier_context = template
        .for_request(
            template.expected_audience().clone(),
            template.expected_challenge(),
            auths_model::Timestamp::new(now),
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let verifier =
        Verifier::self_contained(verifier_context).map_err(|_| ProfileRuntimeError::Invalid)?;
    match verifier
        .verify(context.authority_proof(), action, &request, profile)
        .map_err(|_| ProfileRuntimeError::Invalid)?
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
    if value.provider_kind().as_str() != "postgresql"
        || value.contract().as_str() != "auths.postgresql.connection/1"
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    PostgresConnectionDescriptor::from_canonical_bytes(value.descriptor())
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(value)
}
fn configuration(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
) -> Result<PostgresLocalAgentConfigurationV1, ProfileRuntimeError> {
    PostgresLocalAgentConfigurationV1::from_binding(
        context
            .configuration()
            .ok_or(ProfileRuntimeError::Invalid)?,
    )
    .map_err(|_| ProfileRuntimeError::Invalid)
}
fn validate_record(
    record: &PreparedUpdateRecordV1,
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> Result<(), ProfileRuntimeError> {
    if record.principal() != context.principal()
        || record.connection_id() != connection.connection_id().as_str()
        || record.connection_generation() != connection.generation().get()
        || record.account_commitment() != hex::encode(connection.account_commitment())
        || record.descriptor_commitment() != hex::encode(connection.descriptor_commitment())
        || record.credential_commitment()
            != hex::encode(connection.credential_reference_commitment())
        || record.configuration_commitment() != hex::encode(configuration.sha256())
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn payload_is_authorized(
    payload: &PreparedUpdatePayloadV1,
    now: u64,
) -> Result<bool, ProfileRuntimeError> {
    let audience = payload
        .configuration
        .first_database_audience()
        .ok_or(ProfileRuntimeError::Invalid)?;
    Ok(matches!(
        crate::evaluate(&EvaluationContext {
            action: &payload.action,
            evidence: &payload.evidence,
            required_configuration: &payload.configuration,
            executed_configuration: &payload.configuration,
            request_audience: audience,
            now,
        })
        .class,
        PostgresDecisionClass::Authorized
    ))
}

fn expose_credential(
    value: Option<&auths_connections::ProviderCredentialLease>,
) -> Result<&[u8], ProfileRuntimeError> {
    value
        .ok_or(ProfileRuntimeError::Invalid)?
        .expose(Instant::now())
        .map_err(|_| ProfileRuntimeError::Invalid)
}
fn configuration_commitment(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"auths.postgresql.local-agent-configuration/1\0");
    digest.update(context.authority_commitment());
    digest.update(connection.descriptor_commitment());
    digest.update(connection.account_commitment());
    digest.update(configuration.sha256());
    digest.finalize().into()
}
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProfileRuntimeError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ProfileRuntimeError::Invalid)
}
fn canonical_from_slice<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
) -> Result<T, ProfileRuntimeError> {
    let value: T = serde_json::from_slice(bytes).map_err(|_| ProfileRuntimeError::Invalid)?;
    if canonical_json(&value)? != bytes {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(value)
}
fn decode_digest(value: &str) -> Result<[u8; 32], ProfileRuntimeError> {
    let bytes = hex::decode(value).map_err(|_| ProfileRuntimeError::Invalid)?;
    bytes.try_into().map_err(|_| ProfileRuntimeError::Invalid)
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
        if code == "postgresql.preflight-denied" {
            "The protected PostgreSQL update preflight was not authorized."
        } else {
            "The prepared PostgreSQL update was not authorized."
        },
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
        "Required authority evidence was unavailable before PostgreSQL entry.",
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
        "PostgreSQL recovery must establish the exact durable outcome.",
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
        causes: vec![if provider_entered {
            CauseCategory::Unknown
        } else {
            CauseCategory::Unavailable
        }],
    })
    .and_then(|value| value.to_canonical_cbor())
    .map_err(|_| ProfileRuntimeError::Invalid)
}
