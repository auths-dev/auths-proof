//! Statically linked local-agent vertical for one exact Stripe refund.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::unused_async
)]

use crate::generated::profile_api::{Refund, RefundInput, RefundStatus};
use crate::local_configuration::StripeRefundLocalAgentConfigurationV1;
use crate::{
    AggregateBudgetSnapshot, BoundedDecisionClass, BoundedEvaluationContext, BoundedRefundDecision,
    ExactRefundActionInput, ExactRefundActionV1, Money, PaymentIntentId,
    PersistentRefundReservationStore, ProtectedRefundEvidenceSnapshotV1, ReconciledRefundOutcome,
    RefundEvidenceV1, RefundReservationLease, RefundReservationRecord, RefundReservationState,
    RefundReservationStore, ReserveRefundRequest, ReserveRefundResult,
    StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyV1, StripeRefundEvidencePhase,
    StripeRefundEvidenceStoreV1, StripeRefundProfile, StripeVerifierConfiguration,
    evaluate_bounded_refund, read_persistent_refund_snapshot, request_refund_evidence_snapshot,
};
use auths_codec::{decode_verifier_context, encode_canonical_action};
use auths_connections::ProviderCredentialLease;
use auths_errors::{
    CauseCategory, EffectState, EnteredBoundaries, ErrorEnvelope, ErrorEnvelopeInput,
    RecommendedAction, RetryClass,
};
#[cfg(feature = "qualification")]
use auths_lifecycle::OperationEffectV1;
#[cfg(feature = "testkit-agent")]
use auths_model::{BudgetAlgebraId, BudgetCeiling};
use auths_model::{CanonicalAction, ProfileId, ProfileRef};
use auths_model::{CapabilityId, MediaType, Permission, ResourceId};
use auths_profile_api::{
    ActionProfile, ProfileBudgetExpression, ProfileContractError, ReviewDisplay,
};
#[cfg(feature = "qualification")]
use auths_profile_kit::{
    QualificationEffect, QualificationProfileStateFactV1, QualificationProfileStateObservationV1,
};
use auths_profile_runtime::profile_receipt_claim_digest;
use auths_profile_runtime::{
    CallProviderInput, ObserveProviderResultInput, PreEntryRecheckInput,
    PreparationEvidenceAcquisition, PreparationEvidenceAcquisitionInput,
    PreparationEvidenceAuthorizationInput, PrepareProfileInput, ProfileConclusion,
    ProfileConnectionRequirement, ProfileDecisionReceiptFacts, ProfileExecutionReceiptFacts,
    ProfileObservation, ProfilePreEntryRecheck, ProfilePreparation, ProfilePreparationKind,
    ProfileReceiptClaimCommitment, ProfileReceiptInspection, ProfileRuntimeError,
    ReconcileProfileInput, ReleaseProfileCallInput, SealProfileCallInput, SealedProfileCall,
};
use auths_receipts::{
    ProfileReceiptClaim, ProfileReceiptClaimPhase, encode_profile_receipt_claims,
};
use auths_sdk::VerifiedAction;
use auths_sdk::{RequestContext, Verifier, VerifyResult};
use auths_stores::JournalRecordV1;
use minicbor::{Decoder, Encoder};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PROFILE_ID: &str = "auths.stripe.refund";
const PROFILE_VERSION: u16 = 1;
const STRIPE_REFUNDS_ENDPOINT: &str = "https://api.stripe.com/v1/refunds";
const MAX_PROVIDER_RESPONSE_BYTES: usize = 262_144;

/// Builds the exact Stripe decision-claim roster from persisted bounded-vertical facts.
///
/// The production vertical deliberately fails closed until the AP-0012 policy,
/// evidence, and reservation artifacts are persisted in `RefundState`. The
/// disposable testkit route has a distinct, explicitly non-production roster.
pub fn refunds_create_build_decision_receipt_claims(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    let claims = refunds_create_decision_commitments(facts)?;
    encode_claims(&profile, ProfileReceiptClaimPhase::Decision, claims)
}

#[allow(clippy::too_many_lines)]
fn refunds_create_decision_commitments(
    facts: ProfileDecisionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if let Ok(state) = canonical_from_slice::<BoundedRefundState>(facts.profile_state) {
        state
            .action
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        state
            .policy
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        state
            .exact_configuration
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        state
            .bounded_configuration
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let payment_intent = state
            .action
            .payment_intent_id()
            .ok_or(ProfileRuntimeError::Invalid)?;
        state
            .preparation_snapshot
            .verify_binding(
                &state.evidence_store,
                &state.workflow_id,
                StripeRefundEvidencePhase::Preparation,
                None,
                payment_intent,
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if state.preparation_snapshot.evidence() != &state.evidence {
            return Err(ProfileRuntimeError::Invalid);
        }
        let connection = facts
            .binding
            .connection()
            .ok_or(ProfileRuntimeError::Invalid)?;
        let action = state
            .action
            .canonical_bytes()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let policy = canonical_json(&state.policy)?;
        let evidence = canonical_json(&state.evidence)?;
        let decision = canonical_json(&(facts.decision_class, &state.bounded_decision))?;
        let configurations = canonical_json(&(
            &state.exact_configuration,
            &state.bounded_configuration,
            &state.evidence_store,
        ))?;
        return Ok(vec![
            ProfileReceiptClaimCommitment {
                id: "stripe.credential-scope",
                sha256: profile_receipt_claim_digest(
                    "stripe.credential-scope.v1",
                    &[
                        b"stripe.refunds.write/1",
                        connection.descriptor_commitment(),
                        connection.account_commitment(),
                        &facts.receipt_context_commitment,
                    ],
                ),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.decision",
                sha256: profile_receipt_claim_digest(
                    "stripe.decision.v1",
                    &[&action, &decision, &facts.receipt_action_commitment],
                ),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.evidence",
                sha256: profile_receipt_claim_digest("stripe.evidence.v1", &[&evidence]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.policy",
                sha256: profile_receipt_claim_digest(
                    "stripe.policy.v1",
                    &[&policy, &configurations],
                ),
            },
        ]);
    }
    #[cfg(feature = "testkit-agent")]
    {
        let state: RefundState = canonical_from_slice(facts.profile_state)?;
        let action = state.action.canonical_bytes()?;
        return Ok(vec![
            ProfileReceiptClaimCommitment {
                id: "stripe.testkit.action",
                sha256: profile_receipt_claim_digest(
                    "stripe.testkit.action.v1",
                    &[&action, &facts.receipt_action_commitment],
                ),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.testkit.binding",
                sha256: profile_receipt_claim_digest(
                    "stripe.testkit.binding.v1",
                    &[
                        facts.binding.preparation_commitment(),
                        &facts.receipt_context_commitment,
                    ],
                ),
            },
        ]);
    }
    #[allow(unreachable_code)]
    Err(ProfileRuntimeError::Invalid)
}

/// Builds the exact Stripe execution-claim roster from durable operation facts.
pub fn refunds_create_build_execution_receipt_claims(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let profile = facts.binding.profile().clone();
    let claims = refunds_create_execution_commitments(facts)?;
    encode_claims(&profile, ProfileReceiptClaimPhase::Execution, claims)
}

fn refunds_create_execution_commitments(
    facts: ProfileExecutionReceiptFacts<'_>,
) -> Result<Vec<ProfileReceiptClaimCommitment>, ProfileRuntimeError> {
    if let Ok(state) = canonical_from_slice::<BoundedRefundState>(facts.profile_state) {
        let command: BoundedRefundCommand = canonical_from_slice(facts.sealed_command)?;
        validate_bounded_command(&command)?;
        if command.operation_id != facts.operation_id.as_str()
            || command.action != state.action
            || state.pre_entry_evidence.is_none()
            || state
                .pre_entry_bounded_decision
                .as_ref()
                .is_none_or(|decision| decision.class != BoundedDecisionClass::Eligible)
            || state
                .reservation
                .as_ref()
                .is_none_or(|reservation| reservation.reservation_id() != &command.reservation_id)
            || state.pre_entry_snapshot.is_none()
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        validate_pre_entry_snapshot(&state, facts.sealed_command)?;
        let evidence = canonical_json(&state.evidence)?;
        let policy = canonical_json(&(
            &state.policy,
            &state.exact_configuration,
            &state.bounded_configuration,
        ))?;
        let pre_entry = canonical_json(&(
            &state.pre_entry_snapshot,
            &state.pre_entry_evidence,
            &state.pre_entry_aggregate_snapshot,
            &state.pre_entry_bounded_decision,
        ))?;
        let reservation = canonical_json(&state.reservation)?;
        let result = facts.provider_result.unwrap_or(b"absent");
        let observations = canonical_json(&facts.observations.to_vec())?;
        return Ok(vec![
            ProfileReceiptClaimCommitment {
                id: "stripe.command",
                sha256: profile_receipt_claim_digest("stripe.command.v1", &[facts.sealed_command]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.evidence",
                sha256: profile_receipt_claim_digest("stripe.evidence.v1", &[&evidence]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.policy",
                sha256: profile_receipt_claim_digest("stripe.policy.v1", &[&policy]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.pre-entry-recheck",
                sha256: profile_receipt_claim_digest("stripe.pre-entry-recheck.v1", &[&pre_entry]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.provider-result",
                sha256: profile_receipt_claim_digest("stripe.provider-result.v1", &[result]),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.reconciliation",
                sha256: profile_receipt_claim_digest(
                    "stripe.reconciliation.v1",
                    &[
                        state.workflow_id.as_bytes(),
                        state.action.idempotency_key().as_bytes(),
                        command.reservation_id.as_str().as_bytes(),
                        &observations,
                    ],
                ),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.reservation",
                sha256: profile_receipt_claim_digest("stripe.reservation.v1", &[&reservation]),
            },
        ]);
    }
    #[cfg(feature = "testkit-agent")]
    {
        let result = facts.provider_result.unwrap_or(b"absent");
        return Ok(vec![
            ProfileReceiptClaimCommitment {
                id: "stripe.testkit.command",
                sha256: profile_receipt_claim_digest(
                    "stripe.testkit.command.v1",
                    &[facts.sealed_command],
                ),
            },
            ProfileReceiptClaimCommitment {
                id: "stripe.testkit.result",
                sha256: profile_receipt_claim_digest("stripe.testkit.result.v1", &[result]),
            },
        ]);
    }
    #[allow(unreachable_code)]
    Err(ProfileRuntimeError::Invalid)
}

/// Inspects the exact Stripe claim schema and immutable/current operation truth.
pub fn refunds_create_inspect_receipt_claims(
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if refunds_create_build_decision_receipt_claims(inspection.facts.decision_facts())?.as_slice()
        != inspection.decision_claims
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    match (
        inspection.facts.execution_facts(),
        inspection.execution_claims,
    ) {
        (None, None) => return Ok(()),
        (Some(facts), Some(actual))
            if refunds_create_build_execution_receipt_claims(facts)?.as_slice() == actual => {}
        _ => return Err(ProfileRuntimeError::Invalid),
    }
    if canonical_from_slice::<BoundedRefundState>(inspection.facts.profile_state()).is_ok() {
        inspect_bounded_receipt_semantics(inspection.facts)?;
    } else {
        #[cfg(feature = "testkit-agent")]
        {
            let command: RefundCommand = canonical_from_slice(
                inspection
                    .facts
                    .sealed_command()
                    .ok_or(ProfileRuntimeError::Invalid)?,
            )?;
            if command.operation_id != inspection.facts.operation_id().as_str() {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
        #[cfg(not(feature = "testkit-agent"))]
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn encode_claims(
    profile: &auths_lifecycle::OperationProfileV1,
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

/// Returns the immutable connection contract for this concrete vertical.
#[must_use]
pub const fn refunds_create_connection_requirement() -> ProfileConnectionRequirement {
    ProfileConnectionRequirement {
        provider_kind: "stripe",
        contract: "auths.stripe.connection/1",
        descriptor_schema: "auths.stripe.connection-descriptor/1",
        credential_scope: "stripe.refunds.write/1",
    }
}

/// Validates the complete deployment-owned Stripe bounded-refund contract.
pub fn validate_profile_configuration(
    binding: &auths_profile_runtime::ProfileConfigurationBinding,
) -> Result<(), ProfileRuntimeError> {
    StripeRefundLocalAgentConfigurationV1::from_binding(binding)
        .map(|_| ())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

/// Performs the isolated, read-only Stripe evidence phase before pure profile
/// preparation. The production agent supplies only public request bindings;
/// the broker alone holds the restricted runtime-read credential and signing
/// key.
pub fn refunds_create_authorize_preparation_evidence(
    input: PreparationEvidenceAuthorizationInput<'_>,
) -> Result<[u8; 32], ProfileRuntimeError> {
    let canonical = preparation_evidence_action(
        input.context,
        input.workflow_id,
        input.profile_input,
        input.connection,
    )?;
    if verify_preparation_evidence_authority(input.context, &canonical, input.now_unix_seconds)?
        != VerificationClass::Authorized
    {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-evidence-read-authority",
        )?));
    }
    encode_canonical_action(&canonical)
        .map(|bytes| Sha256::digest(bytes).into())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

pub fn refunds_create_acquire_preparation_evidence(
    input: PreparationEvidenceAcquisitionInput<'_>,
) -> Result<PreparationEvidenceAcquisition, ProfileRuntimeError> {
    let generated = RefundInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let connection = input
        .connection
        .ok_or_else(|| denied_error("stripe-refund-connection"))?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let deployment = StripeRefundLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let descriptor = crate::connection::StripeConnectionDescriptor::from_canonical_bytes(
        connection.descriptor(),
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let payment_intent = PaymentIntentId::parse(generated.payment_intent)
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let canonical = preparation_evidence_action(
        input.context,
        input.workflow_id,
        input.profile_input,
        input.connection,
    )?;
    let commitment: [u8; 32] = Sha256::digest(
        encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?,
    )
    .into();
    if commitment != input.authority_action_commitment
        || verify_preparation_evidence_authority(input.context, &canonical, input.now_unix_seconds)?
            != VerificationClass::Authorized
    {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-evidence-read-authority",
        )?));
    }
    let unavailable = issue_indeterminate("stripe-refund-evidence")?;
    let snapshot = request_refund_evidence_snapshot(
        deployment.evidence_store(),
        input.workflow_id,
        StripeRefundEvidencePhase::Preparation,
        None,
        &payment_intent,
        descriptor.api_version(),
        input.now_unix_seconds,
        None,
    )
    .map_err(|_| ProfileRuntimeError::PreEntry(unavailable))?;
    Ok(PreparationEvidenceAcquisition {
        bytes: snapshot
            .canonical_bytes()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        authority_action_commitment: commitment,
    })
}

/// Canonicalizes the generated DTO, verifies exact authority, and emits a durable decision.
#[allow(clippy::too_many_lines)]
pub fn refunds_create_prepare(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = RefundInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let connection = input
        .connection
        .ok_or_else(|| denied_error("stripe-refund-connection"))?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let deployment = StripeRefundLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let descriptor = crate::connection::StripeConnectionDescriptor::from_canonical_bytes(
        connection.descriptor(),
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let payment_intent = PaymentIntentId::parse(generated.payment_intent.clone())
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let protected = ProtectedRefundEvidenceSnapshotV1::from_canonical_bytes(
        input
            .preparation_evidence
            .ok_or(ProfileRuntimeError::Invalid)?,
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    protected
        .verify_binding(
            deployment.evidence_store(),
            input.workflow_id,
            StripeRefundEvidencePhase::Preparation,
            None,
            &payment_intent,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let evidence = protected.evidence().clone();
    if input.now_unix_seconds < evidence.observed_at()
        || input
            .now_unix_seconds
            .saturating_sub(evidence.observed_at())
            > deployment.evidence_store().maximum_age_seconds()
        || descriptor.account_id() != evidence.stripe_account_id().as_str()
        || descriptor.api_version() != evidence.stripe_api_version()
        || descriptor.livemode() != evidence.livemode()
        || connection.account_commitment() != &descriptor.account_commitment()
    {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-evidence-binding",
        )?));
    }
    let currency = crate::Currency::parse(generated.currency.as_str())
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let amount =
        Money::new(currency, generated.amount).map_err(|_| denied_error("stripe-refund-input"))?;
    let policy_digest = deployment
        .policy()
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut metadata = BTreeMap::new();
    metadata.insert("auths_action".into(), "exact-refund".into());
    metadata.insert("auths_connect_account".into(), "platform".into());
    metadata.insert("auths_policy".into(), policy_digest.to_string());
    metadata.insert("auths_workflow".into(), input.workflow_id.into());
    let mut nonce = Sha256::new();
    nonce.update(b"AUTHS-STRIPE-REFUND-NONCE\0\x01");
    nonce.update(input.workflow_id.as_bytes());
    nonce.update(Sha256::digest(input.profile_input));
    nonce.update(
        evidence
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?
            .as_str(),
    );
    nonce.update(binding.sha256());
    let action = ExactRefundActionV1::new(ExactRefundActionInput {
        workflow_id: input.workflow_id.into(),
        executor_audience: deployment.exact_configuration().executor_audience().into(),
        stripe_account_id: evidence.stripe_account_id().clone(),
        stripe_api_version: evidence.stripe_api_version().into(),
        livemode: evidence.livemode(),
        charge_id: evidence.charge_id().clone(),
        payment_intent_id: Some(payment_intent),
        amount,
        reason: Some("requested_by_customer".into()),
        metadata,
        refund_application_fee: false,
        reverse_transfer: false,
        expected_charge_amount_minor: evidence.charge_amount_minor(),
        expected_amount_refunded_minor: evidence.amount_refunded_minor(),
        expected_refundable_amount_minor: evidence.refundable_amount_minor(),
        evidence_digest: evidence
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        required_configuration_digest: deployment
            .exact_configuration()
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        observed_at: evidence.observed_at(),
        expires_at: evidence.observed_at().saturating_add(
            deployment
                .exact_configuration()
                .maximum_authorization_lifetime_seconds(),
        ),
        nonce: crate::DigestHex::from_digest_bytes(nonce.finalize().into()),
    })
    .map_err(|_| denied_error("stripe-refund-action"))?;
    let action_body = action
        .canonical_bytes()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let canonical = StripeRefundProfile
        .canonicalize(&action_body)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let input_commitment = Sha256::digest(input.profile_input).into();
    let canonical_action =
        encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?;
    let action_commitment = Sha256::digest(&canonical_action).into();
    let configuration_commitment = configuration_commitment(input.context, connection, binding);
    let mut state = BoundedRefundState {
        workflow_id: input.workflow_id.into(),
        action,
        policy: deployment.policy().clone(),
        evidence,
        preparation_snapshot: protected,
        prepared_at: input.now_unix_seconds,
        aggregate_snapshot: None,
        bounded_decision: None,
        exact_configuration: deployment.exact_configuration().clone(),
        bounded_configuration: deployment.bounded_configuration().clone(),
        evidence_store: deployment.evidence_store().clone(),
        pre_entry_snapshot: None,
        pre_entry_evidence: None,
        pre_entry_aggregate_snapshot: None,
        pre_entry_bounded_decision: None,
        reservation: None,
    };
    match verify_authority(input.context, &canonical, input.now_unix_seconds)? {
        VerificationClass::Denied => Ok(ProfilePreparation {
            canonical_input_commitment: input_commitment,
            canonical_action_commitment: action_commitment,
            configuration_commitment,
            canonical_action: canonical_action.clone(),
            decision_reason: "stripe.refund-denied".into(),
            profile_state: canonical_json(&state)?,
            kind: ProfilePreparationKind::Denied {
                issue: issue_denied("stripe-refund-authority")?,
            },
        }),
        VerificationClass::Indeterminate => Ok(ProfilePreparation {
            canonical_input_commitment: input_commitment,
            canonical_action_commitment: action_commitment,
            configuration_commitment,
            canonical_action,
            decision_reason: "core.authorization-indeterminate".into(),
            profile_state: canonical_json(&state)?,
            kind: ProfilePreparationKind::Unavailable {
                issue: issue_indeterminate("stripe-refund-authority")?,
            },
        }),
        VerificationClass::Authorized => {
            let Ok(aggregate_snapshot) = read_persistent_refund_snapshot(
                &refund_reservation_store_path(input.context.profile_state_root()),
                deployment.policy(),
                state.evidence.stripe_account_id(),
                input.now_unix_seconds,
            ) else {
                return Err(ProfileRuntimeError::PreEntry(issue_indeterminate(
                    "stripe-refund-budget",
                )?));
            };
            let bounded_decision = evaluate_bounded_refund(&BoundedEvaluationContext {
                policy: deployment.policy(),
                action: &state.action,
                evidence: &state.evidence,
                aggregate_snapshot: &aggregate_snapshot,
                required_exact_configuration: deployment.exact_configuration(),
                executed_exact_configuration: deployment.exact_configuration(),
                required_bounded_configuration: deployment.bounded_configuration(),
                executed_bounded_configuration: deployment.bounded_configuration(),
                request_audience: deployment.exact_configuration().executor_audience(),
                now: input.now_unix_seconds,
            });
            state.aggregate_snapshot = Some(aggregate_snapshot);
            state.bounded_decision = Some(bounded_decision.clone());
            let (decision_reason, kind) = match bounded_decision.class {
                BoundedDecisionClass::Eligible => {
                    ("stripe.authorized".into(), ProfilePreparationKind::Ready)
                }
                BoundedDecisionClass::Denied => (
                    format!("stripe.bounded.{:?}", bounded_decision.code).to_ascii_lowercase(),
                    ProfilePreparationKind::Denied {
                        issue: issue_denied("stripe-refund-policy")?,
                    },
                ),
                BoundedDecisionClass::Indeterminate => (
                    "stripe.bounded.indeterminate".into(),
                    ProfilePreparationKind::Unavailable {
                        issue: issue_indeterminate("stripe-refund-policy")?,
                    },
                ),
            };
            Ok(ProfilePreparation {
                canonical_input_commitment: input_commitment,
                canonical_action_commitment: action_commitment,
                configuration_commitment,
                canonical_action,
                decision_reason,
                profile_state: canonical_json(&state)?,
                kind,
            })
        }
    }
}

/// Performs deterministic synthetic preparation for the separately packaged
/// disposable testkit agent.
///
/// This function is never compiled into the production node. It preserves the
/// exact generated input, connection, action, and journal commitments while
/// replacing only deployment authority verification with the testkit's
/// explicitly synthetic authorization decision.
#[cfg(feature = "testkit-agent")]
pub fn refunds_create_prepare_testkit(
    input: PrepareProfileInput<'_>,
) -> Result<ProfilePreparation, ProfileRuntimeError> {
    let generated = RefundInput::from_canonical_cbor(input.profile_input)
        .map_err(|_| denied_error("stripe-refund-input"))?;
    let connection = input
        .connection
        .ok_or_else(|| denied_error("stripe-refund-connection"))?;
    let action = RefundAction::from_input(&generated, connection)?;
    let action_body = action.canonical_bytes()?;
    let canonical = RefundProfile
        .canonicalize(&action_body)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let canonical_action =
        encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(ProfilePreparation {
        canonical_input_commitment: Sha256::digest(input.profile_input).into(),
        canonical_action_commitment: Sha256::digest(&canonical_action).into(),
        configuration_commitment: testkit_configuration_commitment(input.context, connection),
        canonical_action,
        decision_reason: "testkit.stripe.authorized".into(),
        profile_state: canonical_json(&RefundState { action })?,
        kind: ProfilePreparationKind::Ready,
    })
}

/// Re-verifies authority and seals one credential-free Stripe command.
#[allow(clippy::too_many_lines)]
pub async fn refunds_create_seal_provider_call(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let mut state: BoundedRefundState = canonical_from_slice(input.record.profile_state())?;
    let connection = input
        .record
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let runtime_connection = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let deployment = StripeRefundLocalAgentConfigurationV1::from_binding(runtime_connection)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if state.policy != *deployment.policy()
        || state.exact_configuration != *deployment.exact_configuration()
        || state.bounded_configuration != *deployment.bounded_configuration()
        || state.evidence_store != *deployment.evidence_store()
        || state.workflow_id != state.action.workflow_id()
        || state.pre_entry_snapshot.is_some()
        || state.pre_entry_evidence.is_some()
        || state.reservation.is_some()
        || configuration_commitment_from_record(input.context, connection, runtime_connection)
            != *input.record.binding().configuration_commitment()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let payment_intent = state
        .action
        .payment_intent_id()
        .ok_or(ProfileRuntimeError::Invalid)?;
    state
        .preparation_snapshot
        .verify_binding(
            deployment.evidence_store(),
            &state.workflow_id,
            StripeRefundEvidencePhase::Preparation,
            None,
            payment_intent,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let prepared_snapshot = state
        .aggregate_snapshot
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let prepared_decision = state
        .bounded_decision
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let recomputed_prepared_decision = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &state.policy,
        action: &state.action,
        evidence: &state.evidence,
        aggregate_snapshot: prepared_snapshot,
        required_exact_configuration: &state.exact_configuration,
        executed_exact_configuration: deployment.exact_configuration(),
        required_bounded_configuration: &state.bounded_configuration,
        executed_bounded_configuration: deployment.bounded_configuration(),
        request_audience: deployment.exact_configuration().executor_audience(),
        now: state.prepared_at,
    });
    if &recomputed_prepared_decision != prepared_decision
        || prepared_decision.class != BoundedDecisionClass::Eligible
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let Ok(pre_entry_aggregate_snapshot) = read_persistent_refund_snapshot(
        &refund_reservation_store_path(input.context.profile_state_root()),
        deployment.policy(),
        state.evidence.stripe_account_id(),
        input.now_unix_seconds,
    ) else {
        return Err(ProfileRuntimeError::PreEntry(issue_indeterminate(
            "stripe-refund-pre-entry-budget",
        )?));
    };
    let pre_entry_bounded_decision = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &state.policy,
        action: &state.action,
        evidence: &state.evidence,
        aggregate_snapshot: &pre_entry_aggregate_snapshot,
        required_exact_configuration: &state.exact_configuration,
        executed_exact_configuration: deployment.exact_configuration(),
        required_bounded_configuration: &state.bounded_configuration,
        executed_bounded_configuration: deployment.bounded_configuration(),
        request_audience: deployment.exact_configuration().executor_audience(),
        now: input.now_unix_seconds,
    });
    if pre_entry_bounded_decision.class != BoundedDecisionClass::Eligible {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-pre-entry-budget",
        )?));
    }
    let canonical = StripeRefundProfile
        .canonicalize(
            &state
                .action
                .canonical_bytes()
                .map_err(|_| ProfileRuntimeError::Invalid)?,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if verify_authority(input.context, &canonical, input.now_unix_seconds)?
        != VerificationClass::Authorized
    {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-authority",
        )?));
    }
    let decision_receipt = input
        .record
        .receipts()
        .first()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let eligibility = pre_entry_bounded_decision
        .eligibility
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let action_digest = state
        .action
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let request = ReserveRefundRequest {
        workflow_id: state.workflow_id.clone(),
        action_digest: action_digest.clone(),
        decision_receipt_digest: crate::canonical::sha256(decision_receipt.bytes()),
        policy_digest: state
            .policy
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        evaluator_semantic_id: state.policy.evaluator_semantic_id().into(),
        evaluator_semantic_version: state.policy.evaluator_semantic_version(),
        evidence_digest: state
            .evidence
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        required_configuration_digest: state
            .bounded_configuration
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        executed_configuration_digest: deployment
            .bounded_configuration()
            .digest()
            .map_err(|_| ProfileRuntimeError::Invalid)?,
        stripe_account_id: state.action.stripe_account_id().clone(),
        currency: state.action.amount().currency().clone(),
        amount_minor: state.action.amount().amount_minor(),
        intents: eligibility.reservations.clone(),
        idempotency_key_digest: crate::canonical::sha256(state.action.idempotency_key().as_bytes()),
        now: input.now_unix_seconds,
    };
    let store = PersistentRefundReservationStore::open(refund_reservation_store_path(
        input.context.profile_state_root(),
    ))
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let reservation = match store.reserve_checked(&state.policy, request) {
        ReserveRefundResult::Reserved { record, .. } | ReserveRefundResult::Replay(record)
            if record.state() == RefundReservationState::Reserved =>
        {
            record
        }
        ReserveRefundResult::Conflict(_)
        | ReserveRefundResult::CapacityExceeded { .. }
        | ReserveRefundResult::Reserved { .. }
        | ReserveRefundResult::Replay(_)
        | ReserveRefundResult::Unavailable => {
            return Err(ProfileRuntimeError::PreEntry(issue_denied(
                "stripe-refund-reservation",
            )?));
        }
    };
    let command = BoundedRefundCommand {
        action: state.action.clone(),
        operation_id: input.record.operation_id().as_str().to_owned(),
        reservation_id: reservation.reservation_id().clone(),
    };
    state.pre_entry_aggregate_snapshot = Some(pre_entry_aggregate_snapshot);
    state.pre_entry_bounded_decision = Some(pre_entry_bounded_decision);
    state.reservation = Some(reservation);
    Ok(SealedProfileCall {
        command: canonical_json(&command)?,
        profile_state: canonical_json(&state)?,
    })
}

/// Performs the operation- and command-bound Stripe provider reread only after
/// common code has durably retained the sealed command. No credential exists
/// at this boundary and a missing fresh snapshot leaves the original execute
/// attempt pending without releasing its reservation.
pub fn refunds_create_recheck_pre_entry(
    input: PreEntryRecheckInput<'_>,
) -> Result<ProfilePreEntryRecheck, ProfileRuntimeError> {
    if input.record.provider_entered() || input.record.pre_entry_rechecked() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let command_bytes = input
        .record
        .sealed_command()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let command: BoundedRefundCommand = canonical_from_slice(command_bytes)?;
    validate_bounded_command(&command)?;
    let mut state: BoundedRefundState = canonical_from_slice(input.record.profile_state())?;
    let binding = input
        .context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let deployment = StripeRefundLocalAgentConfigurationV1::from_binding(binding)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let reservation = state
        .reservation
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    validate_reservation_binding(&state, reservation)?;
    if state.evidence_store != *deployment.evidence_store()
        || state.pre_entry_snapshot.is_some()
        || state.pre_entry_evidence.is_some()
        || command.action != state.action
        || command.operation_id != input.record.operation_id().as_str()
        || command.reservation_id != *reservation.reservation_id()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let payment_intent = state
        .action
        .payment_intent_id()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let command_sha256 = crate::DigestHex::from_digest_bytes(Sha256::digest(command_bytes).into());
    let observed_after = state
        .evidence
        .observed_at()
        .max(input.record.updated_at_unix_seconds());
    let snapshot = request_refund_evidence_snapshot(
        deployment.evidence_store(),
        &state.workflow_id,
        StripeRefundEvidencePhase::PreEntry,
        Some(&command_sha256),
        payment_intent,
        state.action.stripe_api_version(),
        input.now_unix_seconds,
        Some(observed_after),
    )
    .map_err(|_| ProfileRuntimeError::PreEntryPending)?;
    // The broker stamps the observation only after its provider reads finish.
    // Evaluate freshness and authority against a trusted time sampled after
    // that response, never against the request-entry timestamp.
    let reread_now = trusted_unix_seconds()?;
    let reread = snapshot.evidence().clone();
    if !critical_evidence_matches(&state.evidence, &reread) {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-critical-evidence-changed",
        )?));
    }
    let aggregate = state
        .pre_entry_aggregate_snapshot
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &state.policy,
        action: &state.action,
        evidence: &state.evidence,
        aggregate_snapshot: aggregate,
        required_exact_configuration: &state.exact_configuration,
        executed_exact_configuration: deployment.exact_configuration(),
        required_bounded_configuration: &state.bounded_configuration,
        executed_bounded_configuration: deployment.bounded_configuration(),
        request_audience: deployment.exact_configuration().executor_audience(),
        now: reread_now,
    });
    if decision.class != BoundedDecisionClass::Eligible
        || state.pre_entry_bounded_decision.as_ref() != Some(&decision)
    {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-pre-entry-policy",
        )?));
    }
    let canonical = StripeRefundProfile
        .canonicalize(
            &state
                .action
                .canonical_bytes()
                .map_err(|_| ProfileRuntimeError::Invalid)?,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if verify_authority(input.context, &canonical, reread_now)? != VerificationClass::Authorized {
        return Err(ProfileRuntimeError::PreEntry(issue_denied(
            "stripe-refund-authority",
        )?));
    }
    state.pre_entry_evidence = Some(reread);
    state.pre_entry_snapshot = Some(snapshot);
    Ok(ProfilePreEntryRecheck {
        profile_state: canonical_json(&state)?,
    })
}

fn trusted_unix_seconds() -> Result<u64, ProfileRuntimeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProfileRuntimeError::Invalid)
}

/// Releases the workflow reservation only while common durable state proves
/// that provider entry never occurred. This also closes the crash window after
/// the domain reservation is durable but before the sealed command reaches the
/// common journal.
pub fn refunds_create_release_pre_entry(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let state: BoundedRefundState = canonical_from_slice(input.record.preparation_profile_state())?;
    let Some(decision) = state.bounded_decision.as_ref() else {
        return Ok(());
    };
    if decision.class != BoundedDecisionClass::Eligible {
        return Ok(());
    }
    let store = PersistentRefundReservationStore::open(refund_reservation_store_path(
        input.context.profile_state_root(),
    ))
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    let Some(reservation) = store
        .get(&state.workflow_id)
        .map_err(|_| ProfileRuntimeError::Invalid)?
    else {
        return Ok(());
    };
    validate_reservation_binding(&state, &reservation)?;
    if input.record.receipts().first().is_none_or(|receipt| {
        &crate::canonical::sha256(receipt.bytes()) != reservation.decision_receipt_digest()
    }) {
        return Err(ProfileRuntimeError::Invalid);
    }
    if reservation.state() == RefundReservationState::Reserved {
        store
            .release(
                &RefundReservationLease::from_record(&reservation),
                input
                    .record
                    .updated_at_unix_seconds()
                    .max(reservation.updated_at())
                    .saturating_add(1),
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        return Ok(());
    }
    if reservation.state() == RefundReservationState::Released {
        return Ok(());
    }
    Err(ProfileRuntimeError::Invalid)
}

/// Releases the synthetic testkit checkpoint. The disposable testkit owns no
/// production refund-budget reservation, but it still validates that the
/// retained state is exactly its closed synthetic schema before acknowledging
/// the common release boundary.
#[cfg(feature = "testkit-agent")]
pub fn refunds_create_release_pre_entry_testkit(
    input: ReleaseProfileCallInput<'_>,
) -> Result<(), ProfileRuntimeError> {
    let state: RefundState = canonical_from_slice(input.record.preparation_profile_state())?;
    state.action.validate()?;
    Ok(())
}

/// Seals the same exact Stripe command without consulting a production
/// authority source. Only the explicit disposable testkit agent calls this.
#[cfg(feature = "testkit-agent")]
pub fn refunds_create_seal_provider_call_testkit(
    input: SealProfileCallInput<'_>,
) -> Result<SealedProfileCall, ProfileRuntimeError> {
    let state: RefundState = canonical_from_slice(input.record.profile_state())?;
    let canonical = RefundProfile
        .canonicalize(&state.action.canonical_bytes()?)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let expected = encode_canonical_action(&canonical).map_err(|_| ProfileRuntimeError::Invalid)?;
    if Sha256::digest(&expected).as_slice() != input.record.binding().canonical_action_commitment()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(SealedProfileCall {
        command: canonical_json(&RefundCommand {
            action: state.action,
            operation_id: input.record.operation_id().as_str().to_owned(),
        })?,
        profile_state: input.record.profile_state().to_vec(),
    })
}

/// Makes exactly one fixed-origin Stripe refund request.
pub async fn refunds_create_call_provider(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: BoundedRefundCommand = canonical_from_slice(&input.call.command)?;
    validate_bounded_command(&command)?;
    let credential = input.credential.ok_or(ProfileRuntimeError::Invalid)?;
    let outcome = refunds_create_transport(&command, credential).await;
    refunds_create_finalize_transport_result(input, outcome)
}

/// Applies the domain-owned outcome-unknown transition after an external
/// transport executor returns. Production and qualification use the same
/// state transition; only the transport owner differs.
pub fn refunds_create_finalize_transport_result(
    input: CallProviderInput<'_>,
    outcome: Result<Vec<u8>, ProfileRuntimeError>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: BoundedRefundCommand = canonical_from_slice(&input.call.command)?;
    validate_bounded_command(&command)?;
    match outcome {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut state: BoundedRefundState = canonical_from_slice(&input.call.profile_state)?;
            if state.action != command.action {
                return Err(ProfileRuntimeError::Invalid);
            }
            let reservation = mark_reservation_outcome_unknown(
                input.context.profile_state_root(),
                &command,
                input.now_unix_seconds,
            )?;
            state.reservation = Some(reservation);
            let issue = match error {
                ProfileRuntimeError::Possible(issue) => issue,
                _ => issue_unknown(&command.operation_id)?,
            };
            Err(ProfileRuntimeError::PossibleWithProfileState {
                issue,
                profile_state: canonical_json(&state)?,
            })
        }
    }
}

async fn refunds_create_transport(
    command: &BoundedRefundCommand,
    credential: &ProviderCredentialLease,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    async {
        let secret = credential
            .expose(Instant::now())
            .map_err(|_| possible_error(&command.operation_id))?;
        let secret =
            std::str::from_utf8(secret).map_err(|_| possible_error(&command.operation_id))?;
        let mut form = vec![
            ("charge".to_owned(), command.action.charge_id().to_string()),
            (
                "amount".to_owned(),
                command.action.amount().amount_minor().to_string(),
            ),
        ];
        if let Some(reason) = command.action.reason() {
            form.push(("reason".into(), reason.into()));
        }
        for (key, value) in command.action.metadata() {
            form.push((format!("metadata[{key}]"), value.clone()));
        }
        form.push((
            "refund_application_fee".into(),
            command.action.refund_application_fee().to_string(),
        ));
        form.push((
            "reverse_transfer".into(),
            command.action.reverse_transfer().to_string(),
        ));
        let client = stripe_client()?;
        let response = client
            .post(STRIPE_REFUNDS_ENDPOINT)
            .bearer_auth(secret)
            .header("Accept", "application/json")
            .header("Stripe-Version", command.action.stripe_api_version())
            .header("Idempotency-Key", command.action.idempotency_key())
            .form(&form)
            .send()
            .await
            .map_err(|_| possible_error(&command.operation_id))?;
        bounded_provider_result(response, command.action.stripe_api_version()).await
    }
    .await
}

#[cfg(feature = "qualification")]
pub(crate) async fn refunds_create_transport_from_bytes(
    command: &[u8],
    credential: &ProviderCredentialLease,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let command: BoundedRefundCommand = canonical_from_slice(command)?;
    validate_bounded_command(&command)?;
    refunds_create_transport(&command, credential).await
}

/// Returns one deterministic synthetic provider response for the disposable
/// testkit agent. A real, generation-pinned credential lease is still required
/// so the test exercises the same connection and credential ordering.
#[cfg(feature = "testkit-agent")]
pub fn refunds_create_call_provider_testkit(
    input: CallProviderInput<'_>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    if input.credential.is_none() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let command: RefundCommand = canonical_from_slice(&input.call.command)?;
    synthetic_provider_result(&command.action, &command.operation_id)
}

/// Classifies only an already durable Stripe response.
pub fn refunds_create_observe_provider_result(
    input: ObserveProviderResultInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    #[cfg(feature = "testkit-agent")]
    if let Ok(state) = canonical_from_slice::<RefundState>(input.record.profile_state()) {
        let response = decode_provider_result(input.provider_result)?;
        let conclusion = classify_testkit_response(input.record, state, &response)?;
        return Ok(ProfileObservation {
            bytes: input.provider_result.to_vec(),
            conclusion,
        });
    }
    let state: BoundedRefundState = canonical_from_slice(input.record.profile_state())?;
    let response = decode_provider_result(input.provider_result)?;
    let conclusion = classify_bounded_response(
        input.context.profile_state_root(),
        input.record,
        state,
        &response,
        input.provider_result,
        input.now_unix_seconds,
        false,
    )?;
    Ok(ProfileObservation {
        bytes: input.provider_result.to_vec(),
        conclusion,
    })
}

/// Observes the original idempotent refund without submitting it again.
pub async fn refunds_create_reconcile(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let credential = input.credential.ok_or(ProfileRuntimeError::Invalid)?;
    let matched_result = refunds_create_reconcile_transport_from_state(
        input.record.profile_state(),
        credential,
        input.record.operation_id().as_str(),
    )
    .await?;
    refunds_create_finalize_reconcile_transport(input, &matched_result)
}

pub(crate) async fn refunds_create_reconcile_transport_from_state(
    profile_state: &[u8],
    credential: &ProviderCredentialLease,
    operation_id: &str,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let (state, matched) =
        refunds_create_matching_refund(profile_state, credential, operation_id).await?;
    let Some(refund) = matched else {
        return Err(ProfileRuntimeError::Possible(issue_unknown(operation_id)?));
    };
    encode_provider_result(
        StatusCode::OK.as_u16(),
        state.action.stripe_api_version(),
        &canonical_json(&refund)?,
    )
}

async fn refunds_create_matching_refund(
    profile_state: &[u8],
    credential: &ProviderCredentialLease,
    operation_id: &str,
) -> Result<(BoundedRefundState, Option<StripeRefundResponse>), ProfileRuntimeError> {
    let secret = credential
        .expose(Instant::now())
        .map_err(|_| possible_error(operation_id))?;
    let secret = std::str::from_utf8(secret).map_err(|_| possible_error(operation_id))?;
    let state: BoundedRefundState = canonical_from_slice(profile_state)?;
    let payment_intent = state
        .action
        .payment_intent_id()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let client = stripe_client()?;
    let response = client
        .get(STRIPE_REFUNDS_ENDPOINT)
        .bearer_auth(secret)
        .header("Accept", "application/json")
        .header("Stripe-Version", state.action.stripe_api_version())
        .query(&[
            ("payment_intent", payment_intent.as_str()),
            ("limit", "100"),
        ])
        .send()
        .await
        .map_err(|_| possible_error(operation_id))?;
    let bytes = bounded_provider_result(response, state.action.stripe_api_version()).await?;
    let result = decode_provider_result(&bytes)?;
    let list: StripeRefundList =
        serde_json::from_slice(&result.body).map_err(|_| possible_error(operation_id))?;
    let matched = list.data.into_iter().find(|refund| {
        refund
            .metadata
            .get("auths_workflow")
            .is_some_and(|value| value == state.workflow_id.as_str())
    });
    Ok((state, matched))
}

#[cfg(feature = "qualification")]
#[allow(clippy::items_after_statements)]
pub async fn refunds_create_observe_provider_truth(
    record: &JournalRecordV1,
    credential: ProviderCredentialLease,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    let (state, matched) = refunds_create_matching_refund(
        record.profile_state(),
        &credential,
        record.operation_id().as_str(),
    )
    .await?;
    let effect = if matched.is_some() {
        QualificationEffect::Applied
    } else {
        QualificationEffect::NotApplied
    };
    let payment_intent = state
        .action
        .payment_intent_id()
        .ok_or(ProfileRuntimeError::Invalid)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Truth<'a> {
        account_sha256: String,
        payment_intent_sha256: String,
        refund_sha256: Option<String>,
        amount: u64,
        currency: &'a str,
        applied: bool,
    }
    let truth = Truth {
        account_sha256: hex::encode(Sha256::digest(
            state.action.stripe_account_id().as_str().as_bytes(),
        )),
        payment_intent_sha256: hex::encode(Sha256::digest(payment_intent.as_str().as_bytes())),
        refund_sha256: matched
            .as_ref()
            .map(|refund| hex::encode(Sha256::digest(refund.id.as_bytes()))),
        amount: state.action.amount().amount_minor(),
        currency: state.action.amount().currency().as_str(),
        applied: matched.is_some(),
    };
    canonical_json(&truth).map(|bytes| (effect, bytes))
}

pub fn refunds_create_finalize_reconcile_transport(
    input: ReconcileProfileInput<'_>,
    matched_result: &[u8],
) -> Result<ProfileObservation, ProfileRuntimeError> {
    let state: BoundedRefundState = canonical_from_slice(input.record.profile_state())?;
    let response = decode_provider_result(matched_result)?;
    let conclusion = classify_bounded_response(
        input.context.profile_state_root(),
        input.record,
        state,
        &response,
        matched_result,
        input.now_unix_seconds,
        true,
    )?;
    Ok(ProfileObservation {
        bytes: matched_result.to_vec(),
        conclusion,
    })
}

/// Reconstructs the deterministic synthetic response for the original
/// operation without issuing another provider mutation.
#[cfg(feature = "testkit-agent")]
pub fn refunds_create_reconcile_testkit(
    input: ReconcileProfileInput<'_>,
) -> Result<ProfileObservation, ProfileRuntimeError> {
    if input.credential.is_none() {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: RefundState = canonical_from_slice(input.record.profile_state())?;
    let bytes = synthetic_provider_result(&state.action, input.record.operation_id().as_str())?;
    refunds_create_observe_provider_result(ObserveProviderResultInput {
        context: input.context,
        record: input.record,
        provider_result: &bytes,
        now_unix_seconds: input.now_unix_seconds,
    })
}

#[cfg(feature = "testkit-agent")]
fn synthetic_provider_result(
    action: &RefundAction,
    operation_id: &str,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let suffix = hex::encode(&Sha256::digest(operation_id.as_bytes())[..12]);
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("auths_operation_id".to_owned(), operation_id.to_owned());
    let refund = StripeRefundResponse {
        id: format!("re_testkit_{suffix}"),
        object: "refund".into(),
        amount: action.amount,
        currency: action.currency.clone(),
        charge: "ch_testkit".into(),
        payment_intent: action.payment_intent.clone(),
        status: "succeeded".into(),
        metadata,
    };
    encode_provider_result(
        StatusCode::OK.as_u16(),
        &action.api_version,
        &canonical_json(&refund)?,
    )
}

#[cfg(feature = "testkit-agent")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundAction {
    schema: String,
    payment_intent: String,
    amount: u64,
    currency: String,
    connection_id: String,
    connection_generation: u64,
    descriptor_commitment: String,
    account_commitment: String,
    api_version: String,
}

#[cfg(feature = "testkit-agent")]
impl RefundAction {
    fn from_input(
        input: &RefundInput,
        connection: &auths_connections::ConnectionBinding,
    ) -> Result<Self, ProfileRuntimeError> {
        let descriptor = crate::connection::StripeConnectionDescriptor::from_canonical_bytes(
            connection.descriptor(),
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        Ok(Self {
            schema: "auths.stripe.refund-action/1".into(),
            payment_intent: input.payment_intent.clone(),
            amount: input.amount,
            currency: input.currency.as_str().into(),
            connection_id: connection.connection_id().as_str().into(),
            connection_generation: connection.generation().get(),
            descriptor_commitment: hex::encode(connection.descriptor_commitment()),
            account_commitment: hex::encode(connection.account_commitment()),
            api_version: descriptor.api_version().into(),
        })
    }

    fn validate(&self) -> Result<(), ProfileRuntimeError> {
        if self.schema != "auths.stripe.refund-action/1"
            || !self.payment_intent.starts_with("pi_")
            || !(1..=100_000_000).contains(&self.amount)
            || !matches!(self.currency.as_str(), "eur" | "gbp" | "usd")
            || self.connection_generation == 0
            || self.descriptor_commitment.len() != 64
            || self.account_commitment.len() != 64
            || self.api_version.len() != 10
        {
            return Err(ProfileRuntimeError::PreEntry(issue_denied(
                "stripe-refund-input",
            )?));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileRuntimeError> {
        self.validate()?;
        canonical_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundedRefundState {
    workflow_id: String,
    action: ExactRefundActionV1,
    policy: StripeBoundedRefundPolicyV1,
    evidence: RefundEvidenceV1,
    preparation_snapshot: ProtectedRefundEvidenceSnapshotV1,
    prepared_at: u64,
    aggregate_snapshot: Option<AggregateBudgetSnapshot>,
    bounded_decision: Option<BoundedRefundDecision>,
    exact_configuration: StripeVerifierConfiguration,
    bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    evidence_store: StripeRefundEvidenceStoreV1,
    pre_entry_snapshot: Option<ProtectedRefundEvidenceSnapshotV1>,
    pre_entry_evidence: Option<RefundEvidenceV1>,
    pre_entry_aggregate_snapshot: Option<AggregateBudgetSnapshot>,
    pre_entry_bounded_decision: Option<BoundedRefundDecision>,
    reservation: Option<RefundReservationRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundedRefundCommand {
    action: ExactRefundActionV1,
    operation_id: String,
    reservation_id: crate::DigestHex,
}

/// Independently decodes the canonical refund-reservation store and projects
/// only the stable reservation commitment and its current durable disposition.
#[cfg(feature = "qualification")]
pub fn inspect_profile_state_for_qualification(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    if profile != "auths.stripe.refund/1" {
        return Err(ProfileRuntimeError::Invalid);
    }
    let operation = journal
        .iter()
        .find(|record| {
            record.binding().profile().id() == "auths.stripe.refund"
                && record.binding().profile().version() == 1
        })
        .ok_or(ProfileRuntimeError::Invalid)?;
    if journal
        .iter()
        .filter(|record| {
            record.binding().profile().id() == "auths.stripe.refund"
                && record.binding().profile().version() == 1
        })
        .count()
        != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let state: BoundedRefundState = canonical_from_slice(operation.preparation_profile_state())?;
    let records = crate::reservation::decode_qualification_records(store_bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if records.len() != 1 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut matching = records
        .iter()
        .filter(|record| record.workflow_id() == state.workflow_id);
    let reservation = matching.next().ok_or(ProfileRuntimeError::Invalid)?;
    if matching.next().is_some() {
        return Err(ProfileRuntimeError::Invalid);
    }
    validate_reservation_binding(&state, reservation)?;
    if operation.receipts().first().is_none_or(|receipt| {
        &crate::canonical::sha256(receipt.bytes()) != reservation.decision_receipt_digest()
    }) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let connection = operation
        .binding()
        .connection()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let mut account_commitment = Sha256::new();
    account_commitment.update(b"auths.stripe.account/1\0");
    account_commitment.update(reservation.stripe_account_id().as_str().as_bytes());
    if account_commitment.finalize().as_slice() != connection.account_commitment() {
        return Err(ProfileRuntimeError::Invalid);
    }
    if let Some(command) = operation.sealed_command() {
        let command: BoundedRefundCommand = canonical_from_slice(command)?;
        if command.operation_id != operation.operation_id().as_str()
            || &command.reservation_id != reservation.reservation_id()
        {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    let reservation_sha256 = reservation.reservation_id().as_str().to_owned();
    let mut facts = vec![QualificationProfileStateFactV1 {
        operation_id: operation.operation_id().as_str().to_owned(),
        connection_generation: connection.generation(),
        observation: QualificationProfileStateObservationV1::ReservationDurable {
            reservation_sha256: reservation_sha256.clone(),
        },
    }];
    let disposition = match reservation.state() {
        RefundReservationState::Committed | RefundReservationState::ReconciledCommitted => {
            Some(QualificationProfileStateObservationV1::ReservationConsumed { reservation_sha256 })
        }
        RefundReservationState::Released | RefundReservationState::ReconciledReleased => {
            Some(QualificationProfileStateObservationV1::ReservationReleased { reservation_sha256 })
        }
        RefundReservationState::OutcomeUnknown
            if operation.projection().effect() == OperationEffectV1::Possible =>
        {
            Some(QualificationProfileStateObservationV1::ReservationRetained { reservation_sha256 })
        }
        RefundReservationState::Reserved | RefundReservationState::OutcomeUnknown => None,
    };
    if let Some(observation) = disposition {
        facts.push(QualificationProfileStateFactV1 {
            operation_id: operation.operation_id().as_str().to_owned(),
            connection_generation: connection.generation(),
            observation,
        });
    }
    Ok(facts)
}

#[cfg(feature = "testkit-agent")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundState {
    action: RefundAction,
}

#[cfg(feature = "testkit-agent")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundCommand {
    action: RefundAction,
    operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
struct StripeRefundResponse {
    id: String,
    object: String,
    amount: u64,
    currency: String,
    charge: String,
    payment_intent: String,
    status: String,
    #[serde(default)]
    metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct StripeRefundList {
    data: Vec<StripeRefundResponse>,
}

struct ProviderResult {
    status: u16,
    api_version: String,
    body: Vec<u8>,
}

#[cfg(feature = "testkit-agent")]
#[derive(Clone, Copy, Debug, Default)]
struct RefundProfile;

#[cfg(feature = "testkit-agent")]
impl ActionProfile for RefundProfile {
    type Command = RefundAction;
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Expressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        let action: RefundAction =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action
            .validate()
            .map_err(|_| ProfileContractError::MeaningMismatch)?;
        if canonical_json(&action).map_err(|_| ProfileContractError::Malformed)? != untrusted {
            return Err(ProfileContractError::NonCanonical);
        }
        canonical_action(&action, untrusted.to_vec())
    }

    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let value = checked_action(action)?;
        Ok(ReviewDisplay::new(
            "Refund one Stripe payment",
            vec![
                ("Payment intent".into(), value.payment_intent),
                ("Amount".into(), value.amount.to_string()),
                ("Currency".into(), value.currency),
            ],
            hex::encode(Sha256::digest(action.body())),
        ))
    }

    fn decode_verified(
        &self,
        action: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        checked_action(action.canonical_action())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VerificationClass {
    Authorized,
    Denied,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundEvidenceReadActionV1 {
    schema: String,
    principal: String,
    workflow_id: String,
    connection_id: String,
    connection_generation: u64,
    account_commitment_sha256: String,
    payment_intent_id: String,
    requested_amount_minor: u64,
    requested_currency: String,
    profile_input_sha256: String,
    configuration_sha256: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct StripeRefundEvidenceReadProfile;

impl ActionProfile for StripeRefundEvidenceReadProfile {
    type Command = RefundEvidenceReadActionV1;
    const BUDGET_EXPRESSION: ProfileBudgetExpression = ProfileBudgetExpression::Inexpressible;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        let value: RefundEvidenceReadActionV1 =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        validate_evidence_read_action(&value)?;
        let canonical = canonical_json(&value).map_err(|_| ProfileContractError::Malformed)?;
        if canonical != untrusted {
            return Err(ProfileContractError::NonCanonical);
        }
        canonical_evidence_read_action(&value, canonical)
    }

    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let value = checked_evidence_read_action(action)?;
        Ok(ReviewDisplay::new(
            "Read protected Stripe refund evidence",
            vec![
                ("Payment intent".into(), value.payment_intent_id),
                ("Connection".into(), value.connection_id),
            ],
            hex::encode(Sha256::digest(action.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        checked_evidence_read_action(verified.canonical_action())
    }
}

fn preparation_evidence_action(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    workflow_id: &str,
    profile_input: &[u8],
    connection: Option<&auths_connections::ConnectionBinding>,
) -> Result<CanonicalAction, ProfileRuntimeError> {
    let generated = RefundInput::from_canonical_cbor(profile_input)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let connection = connection.ok_or(ProfileRuntimeError::Invalid)?;
    let configuration = context
        .configuration()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let value = RefundEvidenceReadActionV1 {
        schema: "auths.stripe.refund-evidence-read-action/1".into(),
        principal: context.principal().into(),
        workflow_id: workflow_id.into(),
        connection_id: connection.connection_id().as_str().into(),
        connection_generation: connection.generation().get(),
        account_commitment_sha256: hex::encode(connection.account_commitment()),
        payment_intent_id: generated.payment_intent,
        requested_amount_minor: generated.amount,
        requested_currency: generated.currency.as_str().into(),
        profile_input_sha256: hex::encode(Sha256::digest(profile_input)),
        configuration_sha256: hex::encode(configuration.sha256()),
    };
    validate_evidence_read_action(&value).map_err(|_| ProfileRuntimeError::Invalid)?;
    let body = canonical_json(&value)?;
    canonical_evidence_read_action(&value, body).map_err(|_| ProfileRuntimeError::Invalid)
}

fn validate_evidence_read_action(
    value: &RefundEvidenceReadActionV1,
) -> Result<(), ProfileContractError> {
    if value.schema != "auths.stripe.refund-evidence-read-action/1"
        || !value.workflow_id.starts_with("wf_")
        || value.workflow_id.len() != 67
        || value.connection_generation == 0
        || PaymentIntentId::parse(value.payment_intent_id.clone()).is_err()
        || Money::new(
            crate::Currency::parse(&value.requested_currency)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            value.requested_amount_minor,
        )
        .is_err()
        || [
            &value.account_commitment_sha256,
            &value.profile_input_sha256,
            &value.configuration_sha256,
        ]
        .into_iter()
        .any(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(())
}

fn canonical_evidence_read_action(
    value: &RefundEvidenceReadActionV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        ProfileRef::new(
            ProfileId::parse(PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
            PROFILE_VERSION,
        )
        .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        MediaType::parse("application/vnd.auths.stripe.refund-evidence-read+json")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        Permission::new(
            CapabilityId::parse("stripe.refund-evidence.read/1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&format!(
                "stripe-test://{}/payment-intents/{}/refund-evidence/{}",
                value.account_commitment_sha256, value.payment_intent_id, value.workflow_id
            ))
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        None,
    )
    .map_err(|_| ProfileContractError::MeaningMismatch)
}

fn checked_evidence_read_action(
    action: &CanonicalAction,
) -> Result<RefundEvidenceReadActionV1, ProfileContractError> {
    let value: RefundEvidenceReadActionV1 =
        serde_json::from_slice(action.body()).map_err(|_| ProfileContractError::Malformed)?;
    validate_evidence_read_action(&value)?;
    let expected = canonical_evidence_read_action(
        &value,
        canonical_json(&value).map_err(|_| ProfileContractError::Malformed)?,
    )?;
    if action.profile() != expected.profile()
        || action.media_type() != expected.media_type()
        || action.permission() != expected.permission()
        || action.requested_budget().is_some()
        || !action.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(value)
}

fn verify_preparation_evidence_authority(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    action: &CanonicalAction,
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
        .verify(
            context.authority_proof(),
            action,
            &request,
            &StripeRefundEvidenceReadProfile,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?
    {
        VerifyResult::Authorized(_) => Ok(VerificationClass::Authorized),
        VerifyResult::Denied(_) => Ok(VerificationClass::Denied),
        VerifyResult::Indeterminate(_) => Ok(VerificationClass::Indeterminate),
    }
}

fn verify_authority(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    action: &CanonicalAction,
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
        .verify(
            context.authority_proof(),
            action,
            &request,
            &StripeRefundProfile,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?
    {
        VerifyResult::Authorized(_) => Ok(VerificationClass::Authorized),
        VerifyResult::Denied(_) => Ok(VerificationClass::Denied),
        VerifyResult::Indeterminate(_) => Ok(VerificationClass::Indeterminate),
    }
}

#[cfg(feature = "testkit-agent")]
fn canonical_action(
    action: &RefundAction,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        ProfileRef::new(
            ProfileId::parse(PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
            PROFILE_VERSION,
        )
        .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        MediaType::parse("application/json")
            .map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        Permission::new(
            CapabilityId::parse("stripe.refunds.write/1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            ResourceId::parse(&format!(
                "stripe://payment-intents/{}/refund",
                action.payment_intent
            ))
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            action.amount,
        )),
    )
    .map_err(|_| ProfileContractError::MeaningMismatch)
}

#[cfg(feature = "testkit-agent")]
fn checked_action(action: &CanonicalAction) -> Result<RefundAction, ProfileContractError> {
    if action.profile().id().as_str() != PROFILE_ID || action.profile().version() != PROFILE_VERSION
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let value: RefundAction =
        serde_json::from_slice(action.body()).map_err(|_| ProfileContractError::Malformed)?;
    let expected = canonical_action(&value, action.body().to_vec())?;
    if expected != *action {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(value)
}

fn configuration_commitment(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> [u8; 32] {
    configuration_commitment_parts(
        context.authority_commitment(),
        connection.descriptor_commitment(),
        connection.account_commitment(),
        configuration,
    )
}

fn configuration_commitment_from_record(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_lifecycle::ConnectionBindingCommitmentsV1,
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> [u8; 32] {
    configuration_commitment_parts(
        context.authority_commitment(),
        connection.descriptor_commitment(),
        connection.account_commitment(),
        configuration,
    )
}

fn configuration_commitment_parts(
    authority_commitment: [u8; 32],
    descriptor_commitment: &[u8; 32],
    account_commitment: &[u8; 32],
    configuration: &auths_profile_runtime::ProfileConfigurationBinding,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"auths.stripe.refund-configuration/1\0");
    digest.update(authority_commitment);
    digest.update(descriptor_commitment);
    digest.update(account_commitment);
    digest.update((configuration.format().len() as u64).to_be_bytes());
    digest.update(configuration.format().as_bytes());
    digest.update(configuration.sha256());
    digest.finalize().into()
}

#[cfg(feature = "testkit-agent")]
fn testkit_configuration_commitment(
    context: auths_profile_runtime::ProfileOperationContext<'_>,
    connection: &auths_connections::ConnectionBinding,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"auths.stripe.testkit-refund-configuration/1\0");
    digest.update(context.authority_commitment());
    digest.update(connection.descriptor_commitment());
    digest.update(connection.account_commitment());
    digest.finalize().into()
}

fn refund_reservation_store_path(profile_state_root: &Path) -> PathBuf {
    profile_state_root
        .join("stripe-refund-reservations-v1")
        .join("state.json")
}

fn critical_evidence_matches(left: &RefundEvidenceV1, right: &RefundEvidenceV1) -> bool {
    left.stripe_account_id() == right.stripe_account_id()
        && left.stripe_api_version() == right.stripe_api_version()
        && left.livemode() == right.livemode()
        && left.charge_id() == right.charge_id()
        && left.payment_intent_id() == right.payment_intent_id()
        && left.connect_account_id() == right.connect_account_id()
        && left.currency() == right.currency()
        && left.charge_amount_minor() == right.charge_amount_minor()
        && left.captured_amount_minor() == right.captured_amount_minor()
        && left.amount_refunded_minor() == right.amount_refunded_minor()
        && left.refundable_amount_minor() == right.refundable_amount_minor()
        && left.paid() == right.paid()
        && left.captured() == right.captured()
        && left.charge_refunded() == right.charge_refunded()
        && left.disputed() == right.disputed()
}

fn validate_pre_entry_snapshot(
    state: &BoundedRefundState,
    sealed_command: &[u8],
) -> Result<(), ProfileRuntimeError> {
    let payment_intent = state
        .action
        .payment_intent_id()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let command_sha256 = crate::DigestHex::from_digest_bytes(Sha256::digest(sealed_command).into());
    let snapshot = state
        .pre_entry_snapshot
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    snapshot
        .verify_binding(
            &state.evidence_store,
            &state.workflow_id,
            StripeRefundEvidencePhase::PreEntry,
            Some(&command_sha256),
            payment_intent,
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if state.pre_entry_evidence.as_ref() != Some(snapshot.evidence())
        || !critical_evidence_matches(&state.evidence, snapshot.evidence())
        || snapshot.evidence().observed_at() <= state.evidence.observed_at()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn validate_bounded_command(command: &BoundedRefundCommand) -> Result<(), ProfileRuntimeError> {
    command
        .action
        .validate()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if command.operation_id.is_empty()
        || command.operation_id.len() > 128
        || command
            .operation_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn inspect_bounded_receipt_semantics(
    record: &auths_profile_runtime::ProfileReceiptInspectionFactsV1,
) -> Result<(), ProfileRuntimeError> {
    let Some(command_bytes) = record.sealed_command() else {
        return Ok(());
    };
    let command: BoundedRefundCommand = canonical_from_slice(command_bytes)?;
    validate_bounded_command(&command)?;
    let state: BoundedRefundState = canonical_from_slice(record.profile_state())?;
    let reservation = state
        .reservation
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?;
    validate_reservation_binding(&state, reservation)?;
    if command.operation_id != record.operation_id().as_str()
        || command.action != state.action
        || command.reservation_id != *reservation.reservation_id()
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    validate_pre_entry_snapshot(&state, command_bytes)?;
    let current_result = record
        .observations()
        .last()
        .map(Vec::as_slice)
        .or_else(|| record.provider_result());
    match record.projection().effect() {
        auths_lifecycle::OperationEffectV1::Applied => {
            let current_result = current_result.ok_or(ProfileRuntimeError::Invalid)?;
            let response = decode_provider_result(current_result)?;
            let (refund_id, _) = validate_successful_refund(&state, &response)
                .ok_or(ProfileRuntimeError::Invalid)?;
            if !matches!(
                reservation.state(),
                RefundReservationState::Committed | RefundReservationState::ReconciledCommitted
            ) || reservation.refund_id() != Some(&refund_id)
                || reservation.result_digest() != Some(&crate::canonical::sha256(current_result))
            {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
        auths_lifecycle::OperationEffectV1::NotApplied if record.provider_entered() => {
            let response =
                decode_provider_result(current_result.ok_or(ProfileRuntimeError::Invalid)?)?;
            if !matches!(response.status, 400 | 401 | 402 | 403 | 404 | 422)
                || !matches!(
                    reservation.state(),
                    RefundReservationState::Released | RefundReservationState::ReconciledReleased
                )
            {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
        auths_lifecycle::OperationEffectV1::NotApplied => {}
        auths_lifecycle::OperationEffectV1::Possible => {
            if reservation.state() != RefundReservationState::OutcomeUnknown {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
    }
    Ok(())
}

fn validate_reservation_binding(
    state: &BoundedRefundState,
    reservation: &RefundReservationRecord,
) -> Result<(), ProfileRuntimeError> {
    let action_digest = state
        .action
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let policy_digest = state
        .policy
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let evidence_digest = state
        .evidence
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let configuration_digest = state
        .bounded_configuration
        .digest()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if reservation.workflow_id() != state.workflow_id
        || reservation.action_digest() != &action_digest
        || reservation.policy_digest() != &policy_digest
        || reservation.evidence_digest() != &evidence_digest
        || reservation.required_configuration_digest() != &configuration_digest
        || reservation.executed_configuration_digest() != &configuration_digest
        || reservation.stripe_account_id() != state.action.stripe_account_id()
        || reservation.currency() != state.action.amount().currency()
        || reservation.amount_minor() != state.action.amount().amount_minor()
        || reservation.idempotency_key_digest()
            != &crate::canonical::sha256(state.action.idempotency_key().as_bytes())
        || state
            .reservation
            .as_ref()
            .is_some_and(|expected| expected.reservation_id() != reservation.reservation_id())
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

fn mark_reservation_outcome_unknown(
    profile_state_root: &Path,
    command: &BoundedRefundCommand,
    now: u64,
) -> Result<RefundReservationRecord, ProfileRuntimeError> {
    let store =
        PersistentRefundReservationStore::open(refund_reservation_store_path(profile_state_root))
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    let reservation = store
        .get(command.action.workflow_id())
        .map_err(|_| ProfileRuntimeError::Invalid)?
        .ok_or(ProfileRuntimeError::Invalid)?;
    if reservation.reservation_id() != &command.reservation_id
        || reservation.action_digest()
            != &command
                .action
                .digest()
                .map_err(|_| ProfileRuntimeError::Invalid)?
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    match reservation.state() {
        RefundReservationState::Reserved => store
            .mark_outcome_unknown(&RefundReservationLease::from_record(&reservation), now)
            .map_err(|_| ProfileRuntimeError::Invalid),
        RefundReservationState::OutcomeUnknown => Ok(reservation),
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

fn validate_successful_refund(
    state: &BoundedRefundState,
    response: &ProviderResult,
) -> Option<(crate::RefundId, RefundStatus)> {
    if !(200..300).contains(&response.status) {
        return None;
    }
    let refund: StripeRefundResponse = serde_json::from_slice(&response.body).ok()?;
    if refund.object != "refund"
        || refund.charge != state.action.charge_id().as_str()
        || state
            .action
            .payment_intent_id()
            .map(PaymentIntentId::as_str)
            != Some(refund.payment_intent.as_str())
        || refund.amount != state.action.amount().amount_minor()
        || refund.currency != state.action.amount().currency().as_str()
        || refund
            .metadata
            .get("auths_workflow")
            .is_none_or(|value| value != &state.workflow_id)
        || !matches!(refund.status.as_str(), "pending" | "succeeded")
    {
        return None;
    }
    let refund_id = crate::RefundId::parse(refund.id).ok()?;
    let status = if refund.status == "pending" {
        RefundStatus::Pending
    } else {
        RefundStatus::Succeeded
    };
    Some((refund_id, status))
}

#[allow(clippy::too_many_arguments)]
fn classify_bounded_response(
    profile_state_root: &Path,
    record: &JournalRecordV1,
    mut state: BoundedRefundState,
    response: &ProviderResult,
    provider_result: &[u8],
    now: u64,
    reconciled: bool,
) -> Result<ProfileConclusion, ProfileRuntimeError> {
    if response.api_version != state.action.stripe_api_version() {
        return Ok(ProfileConclusion::RecoveryRequired {
            issue: issue_unknown(record.operation_id().as_str())?,
            progress: None,
            profile_state: canonical_json(&state)?,
        });
    }
    let reservation = state
        .reservation
        .as_ref()
        .ok_or(ProfileRuntimeError::Invalid)?
        .clone();
    validate_reservation_binding(&state, &reservation)?;
    let store =
        PersistentRefundReservationStore::open(refund_reservation_store_path(profile_state_root))
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    if (200..300).contains(&response.status) {
        let Some((refund_id, status)) = validate_successful_refund(&state, response) else {
            let command = BoundedRefundCommand {
                action: state.action.clone(),
                operation_id: record.operation_id().as_str().into(),
                reservation_id: reservation.reservation_id().clone(),
            };
            state.reservation = Some(mark_reservation_outcome_unknown(
                profile_state_root,
                &command,
                now,
            )?);
            return Ok(ProfileConclusion::RecoveryRequired {
                issue: issue_unknown(record.operation_id().as_str())?,
                progress: None,
                profile_state: canonical_json(&state)?,
            });
        };
        let result_digest = crate::canonical::sha256(provider_result);
        let updated = if reconciled {
            store.reconcile(
                &state.workflow_id,
                reservation.action_digest(),
                ReconciledRefundOutcome::Committed {
                    refund_id: refund_id.clone(),
                    result_digest: result_digest.clone(),
                },
                now,
            )
        } else {
            store.commit(
                &RefundReservationLease::from_record(&reservation),
                &refund_id,
                &result_digest,
                now,
            )
        }
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        state.reservation = Some(updated);
        let value = Refund {
            id: refund_id.to_string(),
            status,
        }
        .to_canonical_cbor()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        return Ok(ProfileConclusion::Completed {
            value,
            profile_state: canonical_json(&state)?,
        });
    }
    if matches!(response.status, 400 | 401 | 402 | 403 | 404 | 422) && !reconciled {
        let updated = store
            .release(&RefundReservationLease::from_record(&reservation), now)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        state.reservation = Some(updated);
        return Ok(ProfileConclusion::NotApplied {
            issue: issue_denied(record.operation_id().as_str())?,
            profile_state: canonical_json(&state)?,
        });
    }
    let command = BoundedRefundCommand {
        action: state.action.clone(),
        operation_id: record.operation_id().as_str().into(),
        reservation_id: reservation.reservation_id().clone(),
    };
    mark_reservation_outcome_unknown(profile_state_root, &command, now)?;
    state.reservation = store
        .get(&state.workflow_id)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(ProfileConclusion::RecoveryRequired {
        issue: issue_unknown(record.operation_id().as_str())?,
        progress: None,
        profile_state: canonical_json(&state)?,
    })
}

#[cfg(feature = "testkit-agent")]
fn classify_testkit_response(
    record: &JournalRecordV1,
    state: RefundState,
    response: &ProviderResult,
) -> Result<ProfileConclusion, ProfileRuntimeError> {
    if response.api_version != state.action.api_version {
        return Ok(ProfileConclusion::RecoveryRequired {
            issue: issue_unknown(record.operation_id().as_str())?,
            progress: None,
            profile_state: record.profile_state().to_vec(),
        });
    }
    if (200..300).contains(&response.status) {
        let refund: StripeRefundResponse = serde_json::from_slice(&response.body)
            .map_err(|_| possible_error(record.operation_id().as_str()))?;
        if refund.object != "refund"
            || refund.payment_intent != state.action.payment_intent
            || refund.amount != state.action.amount
            || refund.currency != state.action.currency
            || !matches!(refund.status.as_str(), "pending" | "succeeded")
        {
            return Ok(ProfileConclusion::RecoveryRequired {
                issue: issue_unknown(record.operation_id().as_str())?,
                progress: None,
                profile_state: record.profile_state().to_vec(),
            });
        }
        let status = if refund.status == "pending" {
            RefundStatus::Pending
        } else {
            RefundStatus::Succeeded
        };
        let value = Refund {
            id: refund.id,
            status,
        }
        .to_canonical_cbor()
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        return Ok(ProfileConclusion::Completed {
            value,
            profile_state: record.profile_state().to_vec(),
        });
    }
    if (400..500).contains(&response.status) {
        return Ok(ProfileConclusion::NotApplied {
            issue: issue_denied(record.operation_id().as_str())?,
            profile_state: record.profile_state().to_vec(),
        });
    }
    Ok(ProfileConclusion::RecoveryRequired {
        issue: issue_unknown(record.operation_id().as_str())?,
        progress: None,
        profile_state: record.profile_state().to_vec(),
    })
}

fn stripe_client() -> Result<Client, ProfileRuntimeError> {
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| ProfileRuntimeError::Invalid)
}

async fn bounded_provider_result(
    response: reqwest::Response,
    expected_api_version: &str,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let status = response.status().as_u16();
    let api_version = response
        .headers()
        .get("Stripe-Version")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| possible_error("stripe-response-api-version"))?
        .to_owned();
    if api_version != expected_api_version
        || response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(ProfileRuntimeError::Possible(issue_unknown(
            "stripe-refund-response",
        )?));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| possible_error("stripe-refund-response"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ProfileRuntimeError::Possible(issue_unknown(
                "stripe-refund-response",
            )?));
        }
        body.extend_from_slice(&chunk);
    }
    encode_provider_result(status, &api_version, &body)
}

fn encode_provider_result(
    status: u16,
    api_version: &str,
    body: &[u8],
) -> Result<Vec<u8>, ProfileRuntimeError> {
    if !valid_provider_api_version(api_version) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(3)
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u16(status))
        .and_then(|value| value.u8(2))
        .and_then(|value| value.str(api_version))
        .and_then(|value| value.u8(3))
        .and_then(|value| value.bytes(body))
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    Ok(encoder.into_writer())
}

fn decode_provider_result(bytes: &[u8]) -> Result<ProviderResult, ProfileRuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_RESPONSE_BYTES + 32 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.map().map_err(|_| ProfileRuntimeError::Invalid)? != Some(3)
        || decoder.u8().map_err(|_| ProfileRuntimeError::Invalid)? != 1
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let status = decoder.u16().map_err(|_| ProfileRuntimeError::Invalid)?;
    if decoder.u8().map_err(|_| ProfileRuntimeError::Invalid)? != 2 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let api_version = decoder
        .str()
        .map_err(|_| ProfileRuntimeError::Invalid)?
        .to_owned();
    if !valid_provider_api_version(&api_version)
        || decoder.u8().map_err(|_| ProfileRuntimeError::Invalid)? != 3
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let body = decoder
        .bytes()
        .map_err(|_| ProfileRuntimeError::Invalid)?
        .to_vec();
    if body.len() > MAX_PROVIDER_RESPONSE_BYTES || decoder.position() != bytes.len() {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(ProviderResult {
        status,
        api_version,
        body,
    })
}

fn valid_provider_api_version(value: &str) -> bool {
    value.len() >= 10
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn issue_denied(correlation: &str) -> Result<Vec<u8>, ProfileRuntimeError> {
    issue(
        "stripe.refund-denied",
        "profile-evaluation",
        "The exact Stripe refund was not authorized.",
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
        "Required authority evidence was unavailable before provider entry.",
        correlation,
        RetryClass::Conditional,
        EffectState::NotApplied,
        RecommendedAction::SatisfyCondition,
        false,
    )
}

fn issue_unknown(correlation: &str) -> Result<Vec<u8>, ProfileRuntimeError> {
    issue(
        "stripe.refund-outcome-unknown",
        "provider-observation",
        "The Stripe refund outcome requires recovery.",
        correlation,
        RetryClass::Unknown,
        EffectState::Possible,
        RecommendedAction::ResumeAndReconcile,
        true,
    )
}

fn denied_error(correlation: &str) -> ProfileRuntimeError {
    issue_denied(correlation).map_or(ProfileRuntimeError::Invalid, ProfileRuntimeError::PreEntry)
}

fn possible_error(correlation: &str) -> ProfileRuntimeError {
    issue_unknown(correlation).map_or(ProfileRuntimeError::Invalid, ProfileRuntimeError::Possible)
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
        correlation_id: safe_correlation(correlation),
        retry,
        effect,
        entered: EnteredBoundaries {
            approval: !provider_entered,
            signer: !provider_entered,
            state: provider_entered,
            credential: provider_entered,
            provider: provider_entered,
        },
        recommended_action: action,
        execution_reference: provider_entered.then(|| safe_correlation(correlation)),
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

fn safe_correlation(value: &str) -> String {
    if !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        value.to_owned()
    } else {
        "stripe-refund".into()
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProfileRuntimeError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ProfileRuntimeError::Invalid)
}

fn canonical_from_slice<T>(bytes: &[u8]) -> Result<T, ProfileRuntimeError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ProfileRuntimeError::Invalid)?;
    if canonical_json(&value)? != bytes {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_result_is_canonical_and_bounded() {
        let bytes = encode_provider_result(200, "2025-04-30.basil", br#"{"id":"re_1"}"#).unwrap();
        let result = decode_provider_result(&bytes).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.api_version, "2025-04-30.basil");
        assert_eq!(result.body, br#"{"id":"re_1"}"#);
        assert!(decode_provider_result(&vec![0; MAX_PROVIDER_RESPONSE_BYTES + 33]).is_err());
    }
}
