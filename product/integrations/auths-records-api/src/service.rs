//! Ordered verification and execution for create and read.

use std::sync::Arc;

use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use crate::{
    CreateEvaluation, CreateRecordProfile, CreateTransition, DecisionClass, DecisionReceipt,
    DeliveryReceipt, EffectReceipt, ObservationReceipt, ReadEvaluation, ReadRecordProfile,
    ReadTransition, ReceiptBundle, RecordProjection, RecordsActionV1,
    RecordsApiVerifierConfigurationV1, RecordsDecision, RecordsError, RecordsLedger,
    RecordsRequestEnvelopeV1, VerifiedCreateRecordCommand, VerifiedReadRecordCommand,
    canonical::{canonical_digest, sha256},
    evaluate_create, evaluate_read,
};

pub enum CreateProofDecision {
    Authorized(Box<Authorized<VerifiedCreateRecordCommand>>),
    Denied(String),
    Indeterminate(String),
}

pub enum ReadProofDecision {
    Authorized(Box<Authorized<VerifiedReadRecordCommand>>),
    Denied(String),
    Indeterminate(String),
}

pub trait RecordsProofVerifier: Send + Sync {
    fn verify_create(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<CreateProofDecision, RecordsError>;

    fn verify_read(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ReadProofDecision, RecordsError>;
}

pub struct SdkRecordsProofVerifier {
    verifier: Arc<Verifier>,
}

impl SdkRecordsProofVerifier {
    #[must_use]
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }

    #[must_use]
    pub const fn from_shared(verifier: Arc<Verifier>) -> Self {
        Self { verifier }
    }
}

impl RecordsProofVerifier for SdkRecordsProofVerifier {
    fn verify_create(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<CreateProofDecision, RecordsError> {
        match self
            .verifier
            .verify(proof, canonical, request, &CreateRecordProfile)
            .map_err(|_| RecordsError::MeaningMismatch)?
        {
            VerifyResult::Authorized(authorized) => Ok(CreateProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => {
                Ok(CreateProofDecision::Denied(explanation.code().into()))
            }
            VerifyResult::Indeterminate(explanation) => Ok(CreateProofDecision::Indeterminate(
                explanation.code().into(),
            )),
        }
    }

    fn verify_read(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ReadProofDecision, RecordsError> {
        match self
            .verifier
            .verify(proof, canonical, request, &ReadRecordProfile)
            .map_err(|_| RecordsError::MeaningMismatch)?
        {
            VerifyResult::Authorized(authorized) => Ok(ReadProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => {
                Ok(ReadProofDecision::Denied(explanation.code().into()))
            }
            VerifyResult::Indeterminate(explanation) => {
                Ok(ReadProofDecision::Indeterminate(explanation.code().into()))
            }
        }
    }
}

pub struct RecordsService<V, L> {
    verifier: V,
    ledger: L,
    executed_configuration: RecordsApiVerifierConfigurationV1,
}

impl<V, L> RecordsService<V, L>
where
    V: RecordsProofVerifier,
    L: RecordsLedger,
{
    #[must_use]
    pub const fn new(
        verifier: V,
        ledger: L,
        executed_configuration: RecordsApiVerifierConfigurationV1,
    ) -> Self {
        Self {
            verifier,
            ledger,
            executed_configuration,
        }
    }

    pub fn execute(
        &self,
        request: &RecordsExecutionRequest,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        request.envelope.validate(
            usize::try_from(request.required_configuration.maximum_proof_bytes)
                .map_err(|_| RecordsError::LimitExceeded)?,
        )?;
        match &request.envelope.canonical_action {
            RecordsActionV1::Create(action) => self.execute_create(request, action),
            RecordsActionV1::Read(action) => self.execute_read(request, action),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered create security pipeline is intentionally visible in one function"
    )]
    fn execute_create(
        &self,
        request: &RecordsExecutionRequest,
        action: &crate::CreateRecordV1,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let proof = request.envelope.proof()?;
        let action_digest = action.digest()?;
        let mut decision = evaluate_create(&CreateEvaluation {
            action,
            policy: &request.policy,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            now: request.now,
        });
        let mut auths_decision = "not-run".to_string();
        let mut auths_code = "not-run".to_string();
        let mut protected_storage_accessed = false;

        if decision.is_authorized()
            && request
                .envelope
                .presentation
                .verify(
                    &proof,
                    request.envelope.canonical_action.operation_id(),
                    &action_digest,
                    request.challenge,
                    &action.executor_audience,
                    request.now,
                    request.policy.maximum_presentation_lifetime_seconds,
                    &request.policy.presenter_principal,
                )
                .is_err()
        {
            decision = RecordsDecision::denied("presentation-invalid", "presentation");
        }

        let canonical = CreateRecordProfile
            .canonicalize(&action.canonical_bytes()?)
            .map_err(|_| RecordsError::MeaningMismatch)?;
        let mut authorized = None;
        if decision.is_authorized() {
            match self
                .verifier
                .verify_create(&proof, &canonical, &request.auths_request)?
            {
                CreateProofDecision::Authorized(value) => {
                    if value.command().action() != action {
                        return Err(RecordsError::MeaningMismatch);
                    }
                    auths_decision = "authorized".into();
                    auths_code = "authorized".into();
                    authorized = Some(value);
                }
                CreateProofDecision::Denied(code) => {
                    auths_decision = "denied".into();
                    auths_code = code;
                    decision = RecordsDecision::denied("proof-invalid", "proof");
                }
                CreateProofDecision::Indeterminate(code) => {
                    auths_decision = "indeterminate".into();
                    auths_code = code;
                    decision = RecordsDecision {
                        class: DecisionClass::Indeterminate,
                        code: "proof-indeterminate".into(),
                        stage: "proof".into(),
                    };
                }
            }
        }
        drop(authorized);
        let mut effect = None;
        let mut replay = false;
        if decision.is_authorized() {
            let preliminary = decision_receipt(
                request,
                &action_digest,
                &proof,
                &decision,
                &auths_decision,
                &auths_code,
                false,
                &self.executed_configuration,
            );
            let digest = canonical_digest(&preliminary)?;
            protected_storage_accessed = true;
            match self
                .ledger
                .create(action, &request.policy, &digest, request.now)?
            {
                CreateTransition::Executed(receipt) => effect = Some(receipt),
                CreateTransition::Replay(receipt) => {
                    effect = Some(receipt);
                    replay = true;
                    decision = RecordsDecision::denied("replay", "claim");
                }
                CreateTransition::Denied(code) => {
                    decision = RecordsDecision::denied(code, "capacity");
                }
            }
        }
        self.finish(
            request,
            &action_digest,
            &proof,
            &decision,
            &auths_decision,
            &auths_code,
            protected_storage_accessed,
            effect,
            None,
            replay,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered read security pipeline is intentionally visible in one function"
    )]
    fn execute_read(
        &self,
        request: &RecordsExecutionRequest,
        action: &crate::ReadRecordV1,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let proof = request.envelope.proof()?;
        let action_digest = action.digest()?;
        let mut decision = evaluate_read(&ReadEvaluation {
            action,
            policy: &request.policy,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            now: request.now,
        });
        let mut auths_decision = "not-run".to_string();
        let mut auths_code = "not-run".to_string();
        let mut protected_storage_accessed = false;
        if decision.is_authorized()
            && request
                .envelope
                .presentation
                .verify(
                    &proof,
                    request.envelope.canonical_action.operation_id(),
                    &action_digest,
                    request.challenge,
                    &action.executor_audience,
                    request.now,
                    request.policy.maximum_presentation_lifetime_seconds,
                    &request.policy.presenter_principal,
                )
                .is_err()
        {
            decision = RecordsDecision::denied("presentation-invalid", "presentation");
        }
        let canonical = ReadRecordProfile
            .canonicalize(&action.canonical_bytes()?)
            .map_err(|_| RecordsError::MeaningMismatch)?;
        let mut authorized = None;
        if decision.is_authorized() {
            match self
                .verifier
                .verify_read(&proof, &canonical, &request.auths_request)?
            {
                ReadProofDecision::Authorized(value) => {
                    if value.command().action() != action {
                        return Err(RecordsError::MeaningMismatch);
                    }
                    auths_decision = "authorized".into();
                    auths_code = "authorized".into();
                    authorized = Some(value);
                }
                ReadProofDecision::Denied(code) => {
                    auths_decision = "denied".into();
                    auths_code = code;
                    decision = RecordsDecision::denied("proof-invalid", "proof");
                }
                ReadProofDecision::Indeterminate(code) => {
                    auths_decision = "indeterminate".into();
                    auths_code = code;
                    decision = RecordsDecision {
                        class: DecisionClass::Indeterminate,
                        code: "proof-indeterminate".into(),
                        stage: "proof".into(),
                    };
                }
            }
        }
        drop(authorized);
        let mut effect = None;
        let mut projection = None;
        let mut replay = false;
        if decision.is_authorized() {
            let preliminary = decision_receipt(
                request,
                &action_digest,
                &proof,
                &decision,
                &auths_decision,
                &auths_code,
                false,
                &self.executed_configuration,
            );
            let digest = canonical_digest(&preliminary)?;
            protected_storage_accessed = true;
            match self
                .ledger
                .read(action, &request.policy, &digest, request.now)?
            {
                ReadTransition::Disclosed {
                    receipt,
                    projection: value,
                } => {
                    effect = Some(receipt);
                    projection = Some(value);
                }
                ReadTransition::Replay {
                    receipt,
                    projection: value,
                } => {
                    effect = Some(receipt);
                    projection = Some(value);
                    replay = true;
                    decision = RecordsDecision::denied("replay", "claim");
                }
                ReadTransition::Denied(code) => {
                    decision = RecordsDecision::denied(code, "disclosure");
                }
            }
        }
        self.finish(
            request,
            &action_digest,
            &proof,
            &decision,
            &auths_decision,
            &auths_code,
            protected_storage_accessed,
            effect,
            projection,
            replay,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "receipt finalization preserves each security-relevant fact explicitly"
    )]
    fn finish(
        &self,
        request: &RecordsExecutionRequest,
        action_digest: &str,
        proof: &[u8],
        decision: &RecordsDecision,
        auths_decision: &str,
        auths_code: &str,
        protected_storage_accessed: bool,
        effect: Option<EffectReceipt>,
        projection: Option<RecordProjection>,
        replay: bool,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let decision_receipt = decision_receipt(
            request,
            action_digest,
            proof,
            decision,
            auths_decision,
            auths_code,
            protected_storage_accessed,
            &self.executed_configuration,
        );
        let observation = if let Some(effect) = &effect {
            Some(ObservationReceipt {
                schema: "auths.records-observation-receipt/1".into(),
                receipt_id: format!("observation-{}", &action_digest[..24]),
                action_digest: action_digest.into(),
                effect_digest: canonical_digest(effect)?,
                state_commitment: self.ledger.state_commitment()?,
                outcome: if replay {
                    "previous-effect-confirmed"
                } else {
                    "effect-observed"
                }
                .into(),
                observed_at: request.now,
            })
        } else {
            None
        };
        let bundle = ReceiptBundle {
            schema: "auths.records-receipt-bundle/1".into(),
            delivery: request.delivery.clone(),
            decision: decision_receipt,
            effect,
            observation,
        };
        self.ledger.append_receipt(bundle.clone())?;
        Ok(RecordsWorkflowOutcome {
            receipt: bundle,
            projection,
            replay,
            reusable_api_key_present: false,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the receipt records each independent security-relevant decision fact"
)]
fn decision_receipt(
    request: &RecordsExecutionRequest,
    action_digest: &str,
    proof: &[u8],
    decision: &RecordsDecision,
    auths_decision: &str,
    auths_code: &str,
    protected_storage_accessed: bool,
    executed_configuration: &RecordsApiVerifierConfigurationV1,
) -> DecisionReceipt {
    let receipt_key =
        sha256(format!("{}:{}", action_digest, request.delivery.delivery_id).as_bytes());
    DecisionReceipt {
        schema: "auths.records-decision-receipt/1".into(),
        receipt_id: format!("decision-{}", &receipt_key[..32]),
        action_digest: action_digest.into(),
        policy_digest: request.policy.digest().unwrap_or_default(),
        proof_digest: sha256(proof),
        presenter_principal: request.policy.presenter_principal.clone(),
        operation_id: request.envelope.operation_id.clone(),
        executor_audience: request.policy.executor_audience.clone(),
        required_configuration: request.required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        decision: decision.clone(),
        auths_decision: auths_decision.into(),
        auths_code: auths_code.into(),
        protected_storage_accessed,
        decided_at: request.now,
    }
}

pub struct RecordsExecutionRequest {
    pub envelope: RecordsRequestEnvelopeV1,
    pub policy: crate::BoundedRecordApiPolicyV1,
    pub required_configuration: RecordsApiVerifierConfigurationV1,
    pub auths_request: RequestContext,
    pub challenge: [u8; 32],
    pub delivery: DeliveryReceipt,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsWorkflowOutcome {
    pub receipt: ReceiptBundle,
    pub projection: Option<RecordProjection>,
    pub replay: bool,
    pub reusable_api_key_present: bool,
}
