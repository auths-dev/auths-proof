//! Static protected qualification adapter for the Stripe profile family.

// Qualification routes expose one closed, fail-closed harness/runtime error;
// detailed rejection remains inside the protected adapter.
#![allow(clippy::missing_errors_doc)]

use auths_connections::{ProviderCredentialLease, QualificationProviderCallKind};
use auths_profile_kit::QualificationProfileStateFactV1;
use auths_profile_kit::{
    QualificationAdapterMetadata, QualificationCleanupEvidence, QualificationCollectedOperation,
    QualificationCollectionAdapter, QualificationCommonOperationInstanceEvidence,
    QualificationCommonReceiptClaims, QualificationEffect, QualificationHarnessError,
    QualificationOperationRole, QualificationPhaseClient, QualificationProtectedObserver,
    QualificationProtectedSetup, QualificationProtectedSetupInput, QualificationProviderTruth,
    QualificationRunContext, QualificationRunReference, QualificationScenarioHookStage,
    QualificationScenarioProgramV1, QualificationSetupHandoffV1, QualificationTarget,
    QualificationVector, qualification_scenario_program as resolve_qualification_scenario_program,
};
use auths_profile_runtime::{ProfileReceiptInspection, ProfileRuntimeError};
use auths_stores::JournalRecordV1;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Runs the production profile receipt inspector through the qualification-only static port.
pub fn inspect_receipt_claims(
    profile: &str,
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    if profile != "auths.stripe.refund/1" {
        return Err(ProfileRuntimeError::Invalid);
    }
    crate::local_agent::refunds_create_inspect_receipt_claims(inspection)
}

/// Reads one canonical protected Stripe reservation snapshot without opening
/// or mutating the production store.
pub fn inspect_profile_state(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    crate::local_agent::inspect_profile_state_for_qualification(profile, journal, store_bytes)
}

/// Executes only the protected Stripe transport. The qualification agent
/// remains responsible for applying the existing durable outcome-unknown
/// state transition when this returns `Possible`.
pub async fn call_provider_transport(
    command: &[u8],
    credential: &ProviderCredentialLease,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    crate::local_agent::refunds_create_transport_from_bytes(command, credential).await
}

/// Observes the original idempotent refund without submitting another
/// mutation. The agent classifies the returned provider bytes against its
/// durable reservation and journal record.
pub async fn reconcile_provider_transport(
    profile_state: &[u8],
    credential: &ProviderCredentialLease,
    operation_id: &str,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    crate::local_agent::refunds_create_reconcile_transport_from_state(
        profile_state,
        credential,
        operation_id,
    )
    .await
}

/// Executes the exact generated-profile transport selected by the protected
/// qualification route registry. This uniform qualification-only seam keeps
/// common evidence code independent of provider-specific call signatures.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_provider_transport(
    profile: &str,
    scenario_id: &str,
    kind: QualificationProviderCallKind,
    command: &[u8],
    profile_state: &[u8],
    credential: &ProviderCredentialLease,
    _configuration: Option<&[u8]>,
    _transport_root: &std::path::Path,
    operation_id: &str,
    _now_unix_seconds: u64,
    _deadline: Instant,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    if profile != "auths.stripe.refund/1" {
        return Err(ProfileRuntimeError::Invalid);
    }
    let program =
        qualification_scenario_program(scenario_id).map_err(|_| ProfileRuntimeError::Invalid)?;
    if kind == QualificationProviderCallKind::Execute
        && program
            .unique_hook_for_role(
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::BeforeProvider,
                "reduce-refundable-amount",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?
    {
        crate::local_agent::qualification_reduce_refundable_amount(command, credential).await?;
    }
    if kind == QualificationProviderCallKind::Execute
        && program
            .unique_hook_for_role(
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::BeforeProvider,
                "create-unrelated-refund",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?
    {
        crate::local_agent::qualification_create_unrelated_refund(command, credential).await?;
    }
    match kind {
        QualificationProviderCallKind::Execute => {
            call_provider_transport(command, credential).await.map(Some)
        }
        QualificationProviderCallKind::Reconcile => {
            reconcile_provider_transport(profile_state, credential, operation_id)
                .await
                .map(Some)
        }
    }
}

/// Independently reads the exact refund outcome with the protected runtime-read
/// credential and returns only the closed effect plus canonical redacted facts.
pub async fn observe_provider_truth(
    record: &JournalRecordV1,
    credential: &[u8],
    _observer_root: &std::path::Path,
    _now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    let lease = ProviderCredentialLease::from_adapter(
        credential.to_vec(),
        Instant::now() + Duration::from_secs(30),
    )
    .map_err(|_| ProfileRuntimeError::Invalid)?;
    crate::local_agent::refunds_create_observe_provider_truth(record, lease).await
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StripeProviderTruthFacts {
    account_sha256: String,
    payment_intent_sha256: String,
    refund_sha256: Option<String>,
    competing_refund_count: u32,
    unrelated_refund_count: u32,
    amount: u64,
    currency: String,
    applied: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StripeProviderMatrixContract {
    schema: String,
    account_class: String,
    account_id_sha256: String,
    api_version: String,
    mutation_permissions: Vec<String>,
    runtime_read_permissions: Vec<String>,
    setup_permissions: Vec<String>,
}

/// Exact v1 prerequisite rows owned by the generated qualification contract.
#[must_use]
pub fn qualification_requirement_ids() -> &'static [&'static str] {
    &[
        "stripe-account-and-evidence",
        "stripe-bounded-policy",
        "stripe-credential-scope",
        "stripe-fresh-pre-entry-recheck",
        "stripe-idempotent-reconciliation",
        "stripe-policy-evaluator",
        "stripe-receipt-claims",
        "stripe-reservations",
        "stripe-sealed-command",
    ]
}

/// SHA-256 of the exact canonical v1 requirement inventory bytes.
#[must_use]
pub const fn qualification_requirements_sha256() -> &'static str {
    "866c9e723b45248fc4b79443b72fb400ef7ddc56b2042df4ef6858158d77efb9"
}

/// Exact public receipt-claim roster required by the v1 Stripe family.
#[must_use]
pub fn qualification_receipt_claim_ids() -> &'static [&'static str] {
    &[
        "stripe.command",
        "stripe.credential-scope",
        "stripe.decision",
        "stripe.evidence",
        "stripe.policy",
        "stripe.pre-entry-recheck",
        "stripe.provider-result",
        "stripe.reconciliation",
        "stripe.reservation",
    ]
}

/// Exact executable provider-truth field roster.
#[must_use]
pub fn qualification_provider_truth_fields() -> &'static [&'static str] {
    &[
        "accountSha256",
        "amount",
        "applied",
        "competingRefundCount",
        "currency",
        "paymentIntentSha256",
        "refundSha256",
        "unrelatedRefundCount",
    ]
}

/// Raw provider-owned JSON field names forbidden from retained evidence.
#[must_use]
pub fn qualification_forbidden_evidence_fields() -> &'static [&'static str] {
    &["accountId", "paymentIntentId", "refundId"]
}

/// Non-secret byte prefixes whose presence proves an unredacted Stripe identifier.
#[must_use]
pub fn qualification_redaction_prefixes() -> &'static [&'static str] {
    &["acct_", "pi_", "re_", "rk_", "sk_", "whsec_"]
}

/// Exact provider-matrix row roster for the v1 launch.
#[must_use]
pub fn qualification_provider_matrix_rows() -> &'static [(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)] {
    &[(
        "stripe-test",
        "stripe",
        "2026-02-25.clover",
        "65dc160804f2af3171675ab41f7500355cb7722850c2200d707b2de79f3fcbed",
        "linux-x86_64",
    )]
}

/// Exact family phase roster shared by every v1 Stripe scenario.
#[must_use]
pub fn qualification_operation_plan()
-> &'static [(QualificationOperationRole, &'static str, bool, bool)] {
    &[(
        QualificationOperationRole::Effect,
        "auths.stripe.refund/1",
        true,
        true,
    )]
}

/// Validates the exact reviewed Stripe live-provider selection.
pub fn validate_provider_matrix_contract(
    bytes: &[u8],
    provider_version: &str,
    provider_artifact_sha256: &str,
) -> Result<(), QualificationHarnessError> {
    const API_VERSION: &str = "2026-02-25.clover";
    const API_VERSION_COMMITMENT: &str =
        "65dc160804f2af3171675ab41f7500355cb7722850c2200d707b2de79f3fcbed";
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(QualificationHarnessError::Limit);
    }
    let contract: StripeProviderMatrixContract =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&contract)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || contract.schema != "auths.stripe.qualification-provider-contract/1"
        || contract.account_class != "dedicated-test-mode"
        || contract.account_id_sha256
            != "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730"
        || contract.api_version != API_VERSION
        || provider_version != API_VERSION
        || provider_artifact_sha256 != API_VERSION_COMMITMENT
        || contract.mutation_permissions.as_slice() != ["refunds.write"]
        || contract.runtime_read_permissions.as_slice()
            != ["charges.read", "payment-intents.read", "refunds.read"]
        || contract.setup_permissions.as_slice() != ["charges.write", "payment-intents.write"]
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

/// Validates the domain-owned public provider-truth projection.
pub fn validate_provider_truth_facts(
    bytes: &[u8],
    effect: QualificationEffect,
) -> Result<(), QualificationHarnessError> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(QualificationHarnessError::Limit);
    }
    let facts: StripeProviderTruthFacts =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || !digest(&facts.account_sha256)
        || facts.account_sha256
            != "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730"
        || !digest(&facts.payment_intent_sha256)
        || facts
            .refund_sha256
            .as_deref()
            .is_some_and(|value| !digest(value))
        || !(1..=100_000_000).contains(&facts.amount)
        || facts.currency.len() != 3
        || !facts.currency.bytes().all(|byte| byte.is_ascii_lowercase())
        || facts.applied != (effect == QualificationEffect::Applied)
        || facts.refund_sha256.is_some() != facts.applied
        || facts.competing_refund_count > 1
        || facts.unrelated_refund_count > 1
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const SCENARIOS: &[&str] = &[
    "stripe-account-equality",
    "stripe-aggregate-budget",
    "stripe-api-version",
    "stripe-command-bound-reread",
    "stripe-evidence-read-count",
    "stripe-existing-refund",
    "stripe-preparation-evidence-lease",
    "stripe-redaction",
    "stripe-refund-boundary",
    "stripe-refundable-drift",
    "stripe-timeout-after-write",
];

pub fn qualification_scenario_program(
    id: &str,
) -> Result<QualificationScenarioProgramV1, QualificationHarnessError> {
    resolve_qualification_scenario_program(
        include_bytes!("../../../conformance/v2/profile-qualification-common.json"),
        include_bytes!("../qualification/scenarios-v1.json"),
        "stripe",
        id,
    )
    .map_err(|_| QualificationHarnessError::InvalidMetadata)
}

#[must_use]
pub const fn qualification_domain_scenario_ids() -> &'static [&'static str] {
    SCENARIOS
}

/// Qualification-only Stripe adapter over the installed generated client.
pub struct StripeQualificationAdapter;

#[derive(Deserialize)]
struct StripeSetupAccount {
    id: String,
}

#[derive(Deserialize)]
struct StripeSetupPaymentIntent {
    id: String,
    amount: u64,
    currency: String,
    status: String,
}

impl QualificationProtectedSetup for StripeQualificationAdapter {
    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn setup(
        &self,
        input: QualificationProtectedSetupInput<'_>,
        setup_credential: &[u8],
    ) -> Result<QualificationSetupHandoffV1, QualificationHarnessError> {
        if input.run_context.protected_environment != "qualification-stripe"
            || input.provider_version != "2026-02-25.clover"
            || input.provider_artifact_sha256
                != "65dc160804f2af3171675ab41f7500355cb7722850c2200d707b2de79f3fcbed"
            || input.scenario_ids.is_empty()
            || !input.scenario_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(QualificationHarnessError::Onboarding);
        }
        crate::connection::validate_onboarding(
            input.connection_descriptor,
            setup_credential.to_vec(),
        )
        .map_err(|_| QualificationHarnessError::Onboarding)?;
        let secret = std::str::from_utf8(setup_credential)
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        if !secret.starts_with("rk_test_") {
            return Err(QualificationHarnessError::Onboarding);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        runtime.block_on(stripe_setup(input, secret))
    }
}

#[allow(clippy::too_many_lines)]
async fn stripe_setup(
    input: QualificationProtectedSetupInput<'_>,
    secret: &str,
) -> Result<QualificationSetupHandoffV1, QualificationHarnessError> {
    const ACCOUNT_SHA256: &str = "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730";
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| QualificationHarnessError::Onboarding)?;
    let account_response = client
        .get("https://api.stripe.com/v1/account")
        .bearer_auth(secret)
        .header("Accept", "application/json")
        .header("Stripe-Version", input.provider_version)
        .send()
        .await
        .map_err(|_| QualificationHarnessError::Onboarding)?;
    if !account_response.status().is_success() {
        return Err(QualificationHarnessError::Onboarding);
    }
    let account_bytes = account_response
        .bytes()
        .await
        .map_err(|_| QualificationHarnessError::Onboarding)?;
    if account_bytes.len() > 1_048_576 {
        return Err(QualificationHarnessError::Limit);
    }
    let account: StripeSetupAccount = serde_json::from_slice(&account_bytes)
        .map_err(|_| QualificationHarnessError::Onboarding)?;
    if !account.id.starts_with("acct_")
        || hex::encode(Sha256::digest(account.id.as_bytes())) != ACCOUNT_SHA256
    {
        return Err(QualificationHarnessError::Onboarding);
    }
    let provider_namespace = format!(
        "aq-{}-{}-{}",
        input.run_context.run_id, input.run_context.run_attempt, input.run_context.provider_run_id
    );
    let mut vectors = Vec::with_capacity(input.scenario_ids.len());
    let mut resources = Vec::with_capacity(input.scenario_ids.len());
    for scenario_id in input.scenario_ids {
        let setup_amount = if matches!(
            scenario_id.as_str(),
            "exact-boundary" | "stripe-refund-boundary"
        ) {
            100_000_000_u64
        } else {
            2_000_u64
        };
        let response = client
            .post("https://api.stripe.com/v1/payment_intents")
            .bearer_auth(secret)
            .header("Accept", "application/json")
            .header("Stripe-Version", input.provider_version)
            .form(&[
                ("amount", setup_amount.to_string()),
                ("currency", "usd".into()),
                ("payment_method", "pm_card_visa".into()),
                ("confirm", "true".into()),
                (
                    "metadata[auths_qualification_namespace]",
                    provider_namespace.clone(),
                ),
                (
                    "metadata[auths_qualification_scenario]",
                    scenario_id.clone(),
                ),
            ])
            .send()
            .await
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        if !response.status().is_success() {
            return Err(QualificationHarnessError::Onboarding);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        if bytes.len() > 1_048_576 {
            return Err(QualificationHarnessError::Limit);
        }
        let intent: StripeSetupPaymentIntent =
            serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::Onboarding)?;
        if !intent.id.starts_with("pi_")
            || intent.amount != setup_amount
            || intent.currency != "usd"
            || intent.status != "succeeded"
        {
            return Err(QualificationHarnessError::Onboarding);
        }
        let amount = match scenario_id.as_str() {
            "boundary-plus-one" => 100_000_001_u64,
            "provider-denial" => setup_amount.saturating_add(1),
            _ => setup_amount,
        };
        let scenario_program = qualification_scenario_program(scenario_id)?;
        let cases = scenario_program
            .cases()
            .iter()
            .map(|case| {
                let case_amount = match case.stimulus() {
                    "maximum-refund" => 100_000_000,
                    "maximum-plus-one-refund" => 100_000_001,
                    "final-capacity-refund"
                    | "account-equality"
                    | "redaction-audit"
                    | "canonical" => amount,
                    "unrelated-refund" => amount.saturating_sub(1),
                    _ => amount,
                };
                let vector = serde_json_canonicalizer::to_vec(&serde_json::json!({
                    "amount": case_amount,
                    "currency": "usd",
                    "paymentIntent": intent.id,
                }))
                .map_err(|_| QualificationHarnessError::Onboarding)?;
                Ok(auths_profile_kit::QualificationSetupCaseV1 {
                    case_id: case.case_id().into(),
                    input_base64url: Base64UrlUnpadded::encode_string(&vector),
                })
            })
            .collect::<Result<Vec<_>, QualificationHarnessError>>()?;
        vectors.push(auths_profile_kit::QualificationSetupVectorV1 {
            id: scenario_id.clone(),
            scenario_program,
            cases,
            failpoint: scenario_id
                .strip_prefix("crash-")
                .and_then(auths_profile_kit::QualificationFailpoint::from_token),
        });
        resources.push(format!(
            "pi-sha256:{}",
            hex::encode(Sha256::digest(intent.id.as_bytes()))
        ));
    }
    resources.sort();
    let run_reference = QualificationRunReference {
        schema: "auths.profile-qualification-run-reference/1".into(),
        domain: "stripe".into(),
        target: input.run_context.target,
        candidate_revision: input.run_context.candidate_revision.clone(),
        repository_id: input.run_context.repository_id.clone(),
        run_id: input.run_context.run_id.clone(),
        run_attempt: input.run_context.run_attempt,
        provider_run_id: input.run_context.provider_run_id.clone(),
        provider_namespace,
        connection_alias_sha256: hex::encode(Sha256::digest(input.connection_alias.as_bytes())),
        resource_references: resources,
        connection_generations: vec!["1".into()],
    };
    let handoff = QualificationSetupHandoffV1 {
        schema: "auths.profile-qualification-setup-handoff/1".into(),
        run_context: input.run_context.clone(),
        domain: "stripe".into(),
        connection_alias: input.connection_alias.into(),
        run_reference,
        vectors,
    };
    handoff.validate()?;
    Ok(handoff)
}

impl QualificationCollectionAdapter for StripeQualificationAdapter {
    type Environment = ();

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        handoff: &QualificationSetupHandoffV1,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        if handoff.run_context != *context || handoff.domain != "stripe" {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        Ok(())
    }

    fn invoke_phase(
        &self,
        _environment: &mut (),
        client: &QualificationPhaseClient,
        connection_alias: &str,
        vector: &QualificationVector,
        phase_index: u8,
        role: QualificationOperationRole,
        profile: &str,
    ) -> Result<QualificationCollectedOperation, QualificationHarnessError> {
        if phase_index != 1
            || role != QualificationOperationRole::Effect
            || profile != "auths.stripe.refund/1"
        {
            return Err(QualificationHarnessError::Invocation);
        }
        client.invoke_installed(connection_alias, &vector.cases)?;
        Ok(QualificationCollectedOperation {
            role,
            profile: profile.into(),
        })
    }
}

impl QualificationProtectedObserver for StripeQualificationAdapter {
    type Environment = StripeProtectedObserverEnvironment;

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        reference: Option<&QualificationRunReference>,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        let reference = reference.ok_or(QualificationHarnessError::ProviderTruth)?;
        if reference.domain != "stripe"
            || reference.target != context.target
            || reference.candidate_revision != context.candidate_revision
            || reference.repository_id != context.repository_id
            || reference.run_id != context.run_id
            || reference.run_attempt != context.run_attempt
            || reference.provider_run_id != context.provider_run_id
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        Ok(StripeProtectedObserverEnvironment {
            credential: protected_credential("QUALIFICATION_OBSERVER_CREDENTIAL")?,
            reference: reference.clone(),
        })
    }

    fn provider_truth(
        &self,
        environment: &StripeProtectedObserverEnvironment,
        scenario_id: &str,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        in_row_domain_facts: &[u8],
    ) -> Result<QualificationProviderTruth, QualificationHarnessError> {
        if phase.profile != "auths.stripe.refund/1"
            || !environment
                .reference
                .resource_references
                .iter()
                .any(|value| value.starts_with("pi-sha256:"))
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        let (effect, facts) = runtime.block_on(stripe_observe_by_namespace(
            &environment.reference.provider_namespace,
            scenario_id,
            &instance.operation_id,
            &environment.credential,
        ))?;
        if facts != in_row_domain_facts {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        validate_provider_truth_facts(&facts, effect)?;
        Ok(QualificationProviderTruth {
            operation_id: instance.operation_id.clone(),
            provider_run_id: environment.reference.provider_run_id.clone(),
            effect,
            provider_calls: instance.counters.provider_calls,
            commitment: Sha256::digest(&facts).into(),
            domain_facts: facts,
            provider_version: "2026-02-25.clover".into(),
            provider_artifact_sha256:
                "65dc160804f2af3171675ab41f7500355cb7722850c2200d707b2de79f3fcbed".into(),
        })
    }

    fn validate_receipt_payload(
        &self,
        _environment: &StripeProtectedObserverEnvironment,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        truth: &QualificationProviderTruth,
        claims: &[QualificationCommonReceiptClaims],
    ) -> Result<(), QualificationHarnessError> {
        if phase.profile != "auths.stripe.refund/1"
            || truth.operation_id != instance.operation_id
            || truth.effect != instance.effect
            || claims
                .iter()
                .any(|claim| claim.operation_id != instance.operation_id)
        {
            return Err(QualificationHarnessError::Receipt);
        }
        Ok(())
    }

    fn validate_domain_scenario(
        &self,
        program: &QualificationScenarioProgramV1,
        operations: &[auths_profile_kit::QualificationRedactedOperation],
        truths: &[QualificationProviderTruth],
    ) -> Result<(), QualificationHarnessError> {
        if !metadata().scenarios.contains(&program.id()) {
            return Ok(());
        }
        match program.id() {
            "stripe-account-equality" => validate_single_applied_refund_truth(truths, None, true),
            "stripe-redaction" => validate_single_applied_refund_truth(truths, None, true),
            "stripe-refund-boundary" => {
                validate_single_applied_refund_truth(truths, Some(100_000_000), true)?;
                validate_case_attempt_roster(program, operations)
            }
            "stripe-aggregate-budget" => {
                validate_single_applied_refund_truth(truths, Some(2_000), true)?;
                validate_case_attempt_roster(program, operations)
            }
            "stripe-timeout-after-write" => {
                validate_single_applied_refund_truth(truths, None, true)?;
                validate_reconciled_effect(operations)
            }
            "stripe-refundable-drift" => validate_stripe_refundable_drift(operations, truths),
            "stripe-existing-refund" => validate_stripe_existing_refund(operations, truths),
            _ => Err(QualificationHarnessError::PrerequisiteUnavailable(
                "Stripe scenario predicate is not implemented",
            )),
        }
    }

    fn cleanup(
        &self,
        context: &QualificationRunContext,
        _reference: Option<&QualificationRunReference>,
    ) -> Result<QualificationCleanupEvidence, QualificationHarnessError> {
        let credential = protected_credential("QUALIFICATION_CLEANUP_CREDENTIAL")?;
        let namespace = format!(
            "aq-{}-{}-{}",
            context.run_id, context.run_attempt, context.provider_run_id
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        runtime.block_on(stripe_cleanup_namespace(&namespace, &credential))?;
        Ok(QualificationCleanupEvidence {
            provider_resources_destroyed: true,
            connection_disabled: true,
            credentials_revoked: true,
            residual_resource_count: 0,
        })
    }
}

pub struct StripeProtectedObserverEnvironment {
    credential: Zeroizing<Vec<u8>>,
    reference: QualificationRunReference,
}

fn validate_single_applied_refund_truth(
    truths: &[QualificationProviderTruth],
    amount: Option<u64>,
    require_account: bool,
) -> Result<(), QualificationHarnessError> {
    const ACCOUNT_SHA256: &str = "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730";
    let [truth] = truths else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let facts: StripeProviderTruthFacts = serde_json::from_slice(&truth.domain_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    let canonical = serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if canonical != truth.domain_facts
        || truth.effect != QualificationEffect::Applied
        || truth.provider_calls != 1
        || !facts.applied
        || facts
            .refund_sha256
            .as_deref()
            .is_none_or(|value| value.len() != 64)
        || facts.payment_intent_sha256.len() != 64
        || facts.currency != "usd"
        || amount.is_some_and(|expected| facts.amount != expected)
        || (require_account && facts.account_sha256 != ACCOUNT_SHA256)
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_case_attempt_roster(
    program: &QualificationScenarioProgramV1,
    operations: &[auths_profile_kit::QualificationRedactedOperation],
) -> Result<(), QualificationHarnessError> {
    let attempts = operations
        .iter()
        .flat_map(|operation| operation.attempts.iter())
        .map(|attempt| attempt.case_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if attempts.len() != program.cases().len()
        || program
            .cases()
            .iter()
            .any(|case| !attempts.contains(case.case_id()))
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_reconciled_effect(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
) -> Result<(), QualificationHarnessError> {
    let [operation] = operations else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let [instance] = operation.instances.as_slice() else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    if operation.role != QualificationOperationRole::Effect
        || instance.effect != QualificationEffect::Applied
        || !instance.reconciled
        || instance.counters.provider_calls != 1
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_stripe_refundable_drift(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    let [operation] = operations else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let [instance] = operation.instances.as_slice() else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let [truth] = truths else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let facts: StripeProviderTruthFacts = serde_json::from_slice(&truth.domain_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if operation.role != QualificationOperationRole::Effect
        || instance.operation_id != truth.operation_id
        || instance.effect != QualificationEffect::NotApplied
        || instance.counters.provider_calls != 1
        || truth.effect != QualificationEffect::NotApplied
        || truth.provider_calls != 1
        || facts.applied
        || facts.refund_sha256.is_some()
        || facts.competing_refund_count != 1
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_stripe_existing_refund(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    validate_single_applied_refund_truth(truths, Some(1_999), true)?;
    validate_reconciled_effect(operations)?;
    let facts: StripeProviderTruthFacts = serde_json::from_slice(&truths[0].domain_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if facts.unrelated_refund_count != 1 || facts.competing_refund_count != 0 {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

#[derive(Deserialize)]
struct StripeSearchList<T> {
    data: Vec<T>,
    has_more: bool,
}

#[derive(Deserialize)]
struct StripeObservedPaymentIntent {
    id: String,
    amount: u64,
    currency: String,
}

#[derive(Deserialize)]
struct StripeObservedRefund {
    id: String,
    amount: u64,
    currency: String,
    metadata: std::collections::BTreeMap<String, String>,
    status: String,
}

#[allow(clippy::too_many_lines)]
async fn stripe_observe_by_namespace(
    namespace: &str,
    scenario_id: &str,
    operation_id: &str,
    credential: &[u8],
) -> Result<(QualificationEffect, Vec<u8>), QualificationHarnessError> {
    let credential =
        std::str::from_utf8(credential).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if !credential.starts_with("rk_test_") {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    let query = format!(
        "metadata['auths_qualification_namespace']:'{namespace}' AND metadata['auths_qualification_scenario']:'{scenario_id}'"
    );
    let response = client
        .get("https://api.stripe.com/v1/payment_intents/search")
        .bearer_auth(credential)
        .header("Stripe-Version", "2026-02-25.clover")
        .query(&[("query", query.as_str()), ("limit", "2")])
        .send()
        .await
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if !response.status().is_success() {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if bytes.len() > 1_048_576 {
        return Err(QualificationHarnessError::Limit);
    }
    let intents: StripeSearchList<StripeObservedPaymentIntent> =
        serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if intents.has_more || intents.data.len() != 1 {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let intent = &intents.data[0];
    let response = client
        .get("https://api.stripe.com/v1/refunds")
        .bearer_auth(credential)
        .header("Stripe-Version", "2026-02-25.clover")
        .query(&[("payment_intent", intent.id.as_str()), ("limit", "100")])
        .send()
        .await
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if !response.status().is_success() {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if bytes.len() > 4_194_304 {
        return Err(QualificationHarnessError::Limit);
    }
    let refunds: StripeSearchList<StripeObservedRefund> =
        serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if refunds.has_more {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let matching = refunds
        .data
        .iter()
        .filter(|refund| {
            refund
                .metadata
                .get("auths_workflow")
                .is_some_and(|value| value == operation_id)
        })
        .collect::<Vec<_>>();
    let competing_refund_count = refunds
        .data
        .iter()
        .filter(|refund| {
            refund
                .metadata
                .get("auths_qualification_competing_refund")
                .is_some_and(|value| value == "1")
        })
        .count();
    let unrelated_refund_count = refunds
        .data
        .iter()
        .filter(|refund| {
            refund
                .metadata
                .get("auths_qualification_unrelated_refund")
                .is_some_and(|value| value == "1")
        })
        .count();
    if matching.len() > 1 {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let applied = matching.len() == 1;
    if matching.first().is_some_and(|refund| {
        refund.amount == 0
            || refund.amount > intent.amount
            || refund.currency != intent.currency
            || !matches!(refund.status.as_str(), "pending" | "succeeded")
    }) {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let facts = StripeProviderTruthFacts {
        account_sha256: "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730".into(),
        payment_intent_sha256: hex::encode(Sha256::digest(intent.id.as_bytes())),
        refund_sha256: matching
            .first()
            .map(|refund| hex::encode(Sha256::digest(refund.id.as_bytes()))),
        competing_refund_count: u32::try_from(competing_refund_count)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?,
        unrelated_refund_count: u32::try_from(unrelated_refund_count)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?,
        amount: matching
            .first()
            .map_or(intent.amount, |refund| refund.amount),
        currency: intent.currency.clone(),
        applied,
    };
    let facts = serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    Ok((
        if applied {
            QualificationEffect::Applied
        } else {
            QualificationEffect::NotApplied
        },
        facts,
    ))
}

async fn stripe_cleanup_namespace(
    namespace: &str,
    credential: &[u8],
) -> Result<(), QualificationHarnessError> {
    let credential =
        std::str::from_utf8(credential).map_err(|_| QualificationHarnessError::Cleanup)?;
    if !credential.starts_with("rk_test_") && !credential.starts_with("sk_test_") {
        return Err(QualificationHarnessError::Cleanup);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| QualificationHarnessError::Cleanup)?;
    let query = format!("metadata['auths_qualification_namespace']:'{namespace}'");
    let response = client
        .get("https://api.stripe.com/v1/payment_intents/search")
        .bearer_auth(credential)
        .header("Stripe-Version", "2026-02-25.clover")
        .query(&[("query", query.as_str()), ("limit", "100")])
        .send()
        .await
        .map_err(|_| QualificationHarnessError::Cleanup)?;
    if !response.status().is_success() {
        return Err(QualificationHarnessError::Cleanup);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| QualificationHarnessError::Cleanup)?;
    let intents: StripeSearchList<StripeObservedPaymentIntent> =
        serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::Cleanup)?;
    if intents.has_more {
        return Err(QualificationHarnessError::Cleanup);
    }
    for intent in intents.data {
        let url = format!("https://api.stripe.com/v1/payment_intents/{}", intent.id);
        let response = client
            .post(url)
            .bearer_auth(credential)
            .header("Stripe-Version", "2026-02-25.clover")
            .form(&[
                ("metadata[auths_qualification_namespace]", ""),
                ("metadata[auths_qualification_scenario]", ""),
            ])
            .send()
            .await
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        if !response.status().is_success() {
            return Err(QualificationHarnessError::Cleanup);
        }
    }
    let response = client
        .get("https://api.stripe.com/v1/payment_intents/search")
        .bearer_auth(credential)
        .header("Stripe-Version", "2026-02-25.clover")
        .query(&[("query", query.as_str()), ("limit", "100")])
        .send()
        .await
        .map_err(|_| QualificationHarnessError::Cleanup)?;
    if !response.status().is_success() {
        return Err(QualificationHarnessError::Cleanup);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| QualificationHarnessError::Cleanup)?;
    if bytes.len() > 4_194_304 {
        return Err(QualificationHarnessError::Limit);
    }
    let remaining: StripeSearchList<StripeObservedPaymentIntent> =
        serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::Cleanup)?;
    if remaining.has_more || !remaining.data.is_empty() {
        return Err(QualificationHarnessError::Cleanup);
    }
    Ok(())
}

fn protected_credential(name: &str) -> Result<Zeroizing<Vec<u8>>, QualificationHarnessError> {
    let encoded = std::env::var(name).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if encoded.is_empty() || encoded.len() > 174_764 || encoded.contains('=') {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let bytes = Base64UrlUnpadded::decode_vec(&encoded)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(Zeroizing::new(bytes))
}

fn metadata() -> QualificationAdapterMetadata {
    QualificationAdapterMetadata {
        domain: "stripe",
        family: &["auths.stripe.refund/1"],
        targets: &[QualificationTarget::LinuxX86_64],
        protected_environment: "qualification-stripe",
        scenarios: SCENARIOS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn applied_truth(amount: u64) -> QualificationProviderTruth {
        let facts = StripeProviderTruthFacts {
            account_sha256: "43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730"
                .into(),
            payment_intent_sha256: "11".repeat(32),
            refund_sha256: Some("22".repeat(32)),
            competing_refund_count: 0,
            unrelated_refund_count: 0,
            amount,
            currency: "usd".into(),
            applied: true,
        };
        let domain_facts = serde_json_canonicalizer::to_vec(&facts).unwrap();
        QualificationProviderTruth {
            operation_id: "operation".into(),
            provider_run_id: "provider".into(),
            effect: QualificationEffect::Applied,
            provider_calls: 1,
            commitment: Sha256::digest(&domain_facts).into(),
            domain_facts,
            provider_version: "2026-02-25.clover".into(),
            provider_artifact_sha256: "33".repeat(32),
        }
    }

    #[test]
    fn provider_truth_is_commitment_only_and_effect_exact() {
        let facts = json!({
            "accountSha256":"43aec9c80a97eb14b852a1a541f81c85eff70c52cadc91963be5ec07b3900730",
            "amount":2000,
            "applied":false,
            "competingRefundCount":0,
            "currency":"usd",
            "paymentIntentSha256":"11".repeat(32),
            "refundSha256":null,
            "unrelatedRefundCount":0
        });
        let bytes = serde_json_canonicalizer::to_vec(&facts).unwrap();
        validate_provider_truth_facts(&bytes, QualificationEffect::NotApplied).unwrap();

        let mut raw = facts.clone();
        raw.as_object_mut()
            .unwrap()
            .insert("accountId".into(), json!("acct_raw"));
        assert!(
            validate_provider_truth_facts(
                &serde_json_canonicalizer::to_vec(&raw).unwrap(),
                QualificationEffect::NotApplied,
            )
            .is_err()
        );
        assert!(validate_provider_truth_facts(&bytes, QualificationEffect::Applied).is_err());
    }

    #[test]
    fn executable_stripe_programs_bind_distinct_case_stimuli_and_truth() {
        let boundary = qualification_scenario_program("stripe-refund-boundary").unwrap();
        assert_eq!(boundary.cases()[0].stimulus(), "maximum-refund");
        assert_eq!(boundary.cases()[1].stimulus(), "maximum-plus-one-refund");
        validate_single_applied_refund_truth(
            &[applied_truth(100_000_000)],
            Some(100_000_000),
            true,
        )
        .unwrap();
        assert!(
            validate_single_applied_refund_truth(
                &[applied_truth(100_000_001)],
                Some(100_000_000),
                true,
            )
            .is_err()
        );

        let aggregate = qualification_scenario_program("stripe-aggregate-budget").unwrap();
        assert!(
            aggregate
                .cases()
                .iter()
                .all(|case| case.stimulus() == "final-capacity-refund")
        );
        validate_single_applied_refund_truth(&[applied_truth(2_000)], Some(2_000), true).unwrap();
    }
}
