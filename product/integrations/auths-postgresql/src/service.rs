//! Linear verify-claim-credential-transaction-observe orchestration.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    action::PostgresBoundedUpdateV1,
    claim::{ClaimRecord, ClaimResult, ClaimStage, ClaimStore},
    compiler::compile_statement,
    decision::DecisionClass,
    evidence::PostgresEvidenceV1,
    executor::VerifiedBoundedUpdateCommand,
    ports::{
        Clock, CredentialProvider, PortError, ProofDecision, ProofVerifier, ReceiptSink,
        Reconciliation, TransactionGateway, TransactionResult,
    },
    profile::PostgresBoundedUpdateProfile,
    receipts::{
        DecisionReceipt, ObservationReceipt, PostgresReceipt, TransactionReceipt, decision_receipt,
        observation_receipt, transaction_receipt,
    },
    schema::{PostgresVerifierConfigurationV1, ValidationError},
};

/// Hostile request plus protected evidence and an Auths proof.
pub struct ExecuteBoundedUpdateRequest {
    pub action: PostgresBoundedUpdateV1,
    pub evidence: PostgresEvidenceV1,
    pub required_configuration: PostgresVerifierConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

/// Explicit dependencies make effect ordering auditable.
pub struct ServiceDependencies<V, C, G, W, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub transaction_gateway: G,
    pub claim_store: W,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: PostgresVerifierConfigurationV1,
}

/// Complete bounded-update service.
pub struct BoundedUpdateService<V, C, G, W, R, T> {
    dependencies: ServiceDependencies<V, C, G, W, R, T>,
}

impl<V, C, G, W, R, T> BoundedUpdateService<V, C, G, W, R, T>
where
    V: ProofVerifier,
    C: CredentialProvider,
    G: TransactionGateway,
    W: ClaimStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one action. Credentials are requested only after policy,
    /// Auths proof, and durable claim have all succeeded.
    pub async fn execute(
        &self,
        request: ExecuteBoundedUpdateRequest,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let mut decision = decision_receipt(
            &request.action,
            &request.evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            request.auths_request.audience().as_str(),
            now,
        )?;
        if decision.decision.class != DecisionClass::Authorized {
            self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = PostgresBoundedUpdateProfile
            .canonicalize(&request.action.canonical_bytes()?)
            .map_err(|_| ServiceError::Profile)?;
        let authorized = match self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )? {
            ProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(ServiceError::Profile);
                }
                decision.auths_decision = Some("authorized".into());
                decision.auths_code = Some("authorized".into());
                *authorized
            }
            ProofDecision::Denied { code } => {
                decision.auths_decision = Some("denied".into());
                decision.auths_code = Some(code);
                decision.decision = crate::decision::Decision::proof_denied();
                self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some("indeterminate".into());
                decision.auths_code = Some(code);
                decision.decision = crate::decision::Decision::proof_indeterminate();
                self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;

        let action_digest = request.action.digest()?;
        let lease = match self.dependencies.claim_store.claim(&action_digest, now) {
            ClaimResult::Claimed(lease) => lease,
            ClaimResult::Replay(record) => return Ok(WorkflowOutcome::Replay { record }),
            ClaimResult::Conflict(record) => return Ok(WorkflowOutcome::Conflict { record }),
            ClaimResult::Unavailable => return Err(ServiceError::ClaimState),
        };
        self.record(&lease, ClaimStage::Claimed, now)?;

        let credential = self
            .dependencies
            .credential_provider
            .mutation_credential(&request.action)?;
        self.record(&lease, ClaimStage::CredentialAcquired, now)?;
        let compiled = compile_statement(
            &request.action.intent,
            &self.dependencies.executed_configuration,
        )?;
        let command =
            VerifiedBoundedUpdateCommand::new(authorized, request.evidence, compiled, lease);
        self.record(command.lease(), ClaimStage::TransactionStarted, now)?;
        let result = match self
            .dependencies
            .transaction_gateway
            .execute(&command, &credential, now)
            .await
        {
            Ok(result) => result,
            Err(PortError::OutcomeUnknown) => {
                self.record(command.lease(), ClaimStage::OutcomeUnknown, now)?;
                match self
                    .dependencies
                    .transaction_gateway
                    .reconcile(&action_digest, &credential)
                    .await?
                {
                    Reconciliation::Committed(mut result) => {
                        result.reconciled = true;
                        self.record(command.lease(), ClaimStage::Reconciled, now)?;
                        result
                    }
                    Reconciliation::NotCommitted => return Err(ServiceError::NotCommitted),
                    Reconciliation::Unavailable => return Err(ServiceError::OutcomeUnknown),
                }
            }
            Err(error) => {
                self.record(command.lease(), ClaimStage::Failed, now)?;
                return Err(ServiceError::Port(error));
            }
        };
        validate_result(command.action(), &result)?;
        self.record(
            command.lease(),
            ClaimStage::MutationCommitted,
            result.committed_at,
        )?;
        self.record(command.lease(), ClaimStage::Observed, result.committed_at)?;
        let transaction = transaction_receipt(
            decision.digest()?,
            command.action(),
            command.claim_id(),
            &result,
        )?;
        let observation = observation_receipt(command.action(), &result);
        self.append(&PostgresReceipt::Transaction(Box::new(transaction.clone())))?;
        self.append(&PostgresReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            transaction: Box::new(transaction),
            observation,
            result: Box::new(result),
        })
    }

    fn append(&self, receipt: &PostgresReceipt) -> Result<(), ServiceError> {
        self.dependencies.receipt_sink.append(receipt)?;
        Ok(())
    }

    fn record(
        &self,
        lease: &crate::claim::ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<(), ServiceError> {
        let record = self
            .dependencies
            .claim_store
            .record_stage(lease, stage, now)
            .map_err(|_| ServiceError::ClaimState)?;
        self.append(&PostgresReceipt::Claim(record))
    }
}

fn validate_result(
    action: &PostgresBoundedUpdateV1,
    result: &TransactionResult,
) -> Result<(), ServiceError> {
    if result.affected_rows != action.intent.expected_row_count {
        return Err(ServiceError::Port(PortError::CardinalityMismatch));
    }
    if result.after_state_digest != action.after_state_digest
        || result.readback_commitment != action.after_state_digest
    {
        return Err(ServiceError::Port(PortError::AfterStateMismatch));
    }
    Ok(())
}

/// Complete workflow outcome.
pub enum WorkflowOutcome {
    Rejected {
        receipt: Box<DecisionReceipt>,
    },
    Replay {
        record: ClaimRecord,
    },
    Conflict {
        record: ClaimRecord,
    },
    Executed {
        decision: Box<DecisionReceipt>,
        transaction: Box<TransactionReceipt>,
        observation: ObservationReceipt,
        result: Box<TransactionResult>,
    },
}

/// Closed service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("PostgreSQL profile failed")]
    Profile,
    #[error("claim state failed")]
    ClaimState,
    #[error("database outcome is unknown")]
    OutcomeUnknown,
    #[error("ledger proves the transaction did not commit")]
    NotCommitted,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Port(#[from] PortError),
}
