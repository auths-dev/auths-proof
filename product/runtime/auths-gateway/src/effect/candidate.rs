//! Effect-free compilation of the exact credential candidate and ordered checks.
//! A target is proposed installation data, never proof of its current predecessor
//! or authority to lease, execute, or publish a credential.

use super::acquisition::{AcquisitionTarget, build_binding, compile_acquisition};
use super::prerequisite::Prerequisite;
use super::*;
use auths_connections::ConnectionState;
use auths_profile_mcp::McpToolCall;
use serde_json::{Value, json};

/// Reserved native operation for bounded candidate credential checks.
pub const CANDIDATE_CHECK_TOOL: &str = "auths_gateway_candidate_check_v1";
const CONTRACT: &str = "auths.gateway-candidate-check/1";
const MAX_CANDIDATE_ATTEMPTS: u64 = 16;

/// Private immutable first-install or rotation proposal, derived only from a
/// validated connection descriptor and the installed recipe's closed reads.
/// There is no decoder and no transport capability. A later transaction must
/// establish the exact predecessor (or absence) before any candidate entry.
#[derive(Clone)]
pub struct CandidateCredentialTarget {
    candidate: ConnectionRecord,
    previous: Option<ConnectionRecord>,
    recipe: [u8; 32],
    namespace: String,
    descriptor: Value,
    prerequisites: Prerequisites,
    last: Prerequisite,
}

impl fmt::Debug for CandidateCredentialTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CandidateCredentialTarget { private: [redacted] }")
    }
}

impl CandidateCredentialTarget {
    /// Compiles a staged candidate and its expected predecessor without I/O.
    /// Rotation preserves the predecessor's descriptor, account, authorization
    /// and state; only the credential reference, generations and time change.
    /// First install starts active at generation one. The final declared read
    /// is the main acquisition; all earlier checks are its ordered prerequisites.
    ///
    /// # Errors
    /// Refuses a wrong descriptor, invalid rotation, revoked predecessor,
    /// noninitial first-install record, or a recipe with no declared reads.
    pub fn new(
        recipe: &CompiledRecipe,
        candidate: &ConnectionRecord,
        previous: Option<&ConnectionRecord>,
    ) -> Result<Self, EffectBindingError> {
        GatewayConnectionDescriptor::from_record(candidate, recipe)
            .map_err(|_| EffectBindingError::Invalid)?;
        if let Some(previous) = previous {
            let expected = previous
                .rotated(
                    previous.descriptor().to_vec(),
                    *previous.account_commitment(),
                    *candidate.credential_reference_commitment(),
                    candidate.updated_at_unix_seconds(),
                )
                .map_err(|_| EffectBindingError::Invalid)?;
            if expected != *candidate {
                return Err(EffectBindingError::Invalid);
            }
        } else if candidate.generation().get() != 1
            || candidate.credential_generation().get() != 1
            || candidate.state() != ConnectionState::Active
            || candidate.created_at_unix_seconds() != candidate.updated_at_unix_seconds()
        {
            return Err(EffectBindingError::Invalid);
        }
        let (prerequisites, last) =
            Prerequisites::candidate(recipe, *candidate.account_commitment())?;
        let target = Self {
            candidate: candidate.clone(),
            previous: previous.cloned(),
            recipe: *recipe.digest(),
            namespace: recipe.namespace().as_str().to_owned(),
            descriptor: serde_json::from_slice(candidate.descriptor())
                .map_err(|_| EffectBindingError::Invalid)?,
            prerequisites,
            last,
        };
        canonical(&target.contract())?;
        Ok(target)
    }

    fn record_commitment(record: &ConnectionRecord) -> Result<[u8; 32], EffectBindingError> {
        let bytes = Zeroizing::new(
            record
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        commitment("auths.effect-installation/1", &bytes)
    }

    pub(super) fn contract(&self) -> Value {
        // Complete connection fields are part of private review, including predecessor
        // state and authorization. Commitments alone would hide review fields.
        let record = |record: &ConnectionRecord| {
            json!({
                "provider": record.provider_kind().as_str(), "alias": record.alias().as_str(),
                "connection_id": record.connection_id().as_str(),
                "contract": record.contract().as_str(), "descriptor_schema": record.descriptor_schema().as_str(),
                "descriptor": self.descriptor,
                "account_commitment": hex::encode(record.account_commitment()),
                "credential_reference_commitment": hex::encode(record.credential_reference_commitment()),
                "generation": record.generation().get(), "credential_generation": record.credential_generation().get(),
                "state": match record.state() { ConnectionState::Active => "active", ConnectionState::Disabled => "disabled", ConnectionState::Revoked => "revoked" },
                "allowed_workloads": record.allowed_workloads(),
                "allowed_profiles": record.allowed_profiles().iter().map(|p| json!({"id": p.id().as_str(), "version": p.version()})).collect::<Vec<_>>(),
                "created_at_unix_seconds": record.created_at_unix_seconds(), "updated_at_unix_seconds": record.updated_at_unix_seconds(),
            })
        };
        json!({
            "schema": CONTRACT, "candidate": record(&self.candidate),
            "expected_previous": self.previous.as_ref().map(record),
            "ordered_prerequisites": self.prerequisites, "final_check": self.last,
            "maximum_attempts": MAX_CANDIDATE_ATTEMPTS, "disclosure": "none",
        })
    }

    pub(super) fn prerequisites(&self) -> &Prerequisites {
        &self.prerequisites
    }

    pub(super) fn request_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        canonical(
            &json!({"request": self.last.request, "prerequisite_acquisitions": self.prerequisites}),
        )
    }

    pub(super) fn method(&self) -> &str {
        match &self.last.request {
            ClosedPrerequisiteRead::Credential(read) => read.method().as_str(),
            ClosedPrerequisiteRead::Action(_) => "GET",
        }
    }

    fn maximum_response_bytes(&self) -> u64 {
        match &self.last.request {
            ClosedPrerequisiteRead::Credential(read) => read.maximum_response_bytes() as u64,
            ClosedPrerequisiteRead::Action(read) => read.maximum_response_bytes() as u64,
        }
    }

    pub(super) fn validate_installation(
        &self,
        installed: &EffectInstallation<'_>,
    ) -> Result<(), EffectBindingError> {
        if installed.connection != &self.candidate
            || *installed.recipe.digest() != self.recipe
            || installed.recipe.namespace().as_str() != self.namespace
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    /// Returns the exact private MCP call requiring separate native authority.
    /// This binds the candidate, predecessor/absence, ordered checks and limits.
    ///
    /// # Errors
    /// Refuses a different recipe or invalid/oversized canonical projection.
    pub fn authorization_call(
        &self,
        recipe: &CompiledRecipe,
        operation: &LogicalOperationId,
    ) -> Result<McpToolCall, EffectBindingError> {
        if *recipe.digest() != self.recipe || recipe.namespace().as_str() != self.namespace {
            return Err(EffectBindingError::Invalid);
        }
        let arguments = json!({
            "operation_id": operation.as_str(), "operator_namespace": self.namespace,
            "recipe_digest": hex::encode(self.recipe),
            "candidate_connection": hex::encode(Self::record_commitment(&self.candidate)?),
            "expected_previous": self.previous.as_ref().map(Self::record_commitment).transpose()?.map(hex::encode),
            "read_contract": hex::encode(commitment(CONTRACT, &canonical(&self.contract())?)?),
            "maximum_response_bytes": self.maximum_response_bytes(),
        }).as_object().cloned().ok_or(EffectBindingError::Invalid)?;
        McpToolCall::new(recipe.service(), CANDIDATE_CHECK_TOOL, arguments)
            .map_err(|_| EffectBindingError::Invalid)
    }

    pub(super) fn binding(
        &self,
        installed: &EffectInstallation<'_>,
        operation: &LogicalOperationId,
        action: [u8; 32],
        authority: [u8; 32],
        bound: Option<&crate::bounds::BoundAdmission>,
    ) -> Result<EffectBinding, GatewaySubmitResult> {
        let invalid = || not_entered("gateway.acquisition.binding");
        let key = |unit| {
            commitment(
                "auths.candidate-capacity/1",
                &canonical(&(
                    self.candidate.connection_id().as_str(),
                    self.candidate.credential_generation().get(),
                    self.candidate.credential_reference_commitment(),
                    unit,
                ))?,
            )
        };
        let capacity = AcquisitionCapacity {
            count_key: key(Unit::AcquisitionCount).map_err(|_| invalid())?,
            bytes_key: key(Unit::ResponseBytes).map_err(|_| invalid())?,
            maximum_bytes: self.maximum_response_bytes(),
            attempts: MAX_CANDIDATE_ATTEMPTS,
        };
        let mut reservations = capacity.reservations();
        reservations.extend(managed_reservations(
            bound,
            Unit::AcquisitionCount,
            Unit::ResponseBytes,
        ));
        reservations.sort_by_key(|entry| (entry.key, entry.unit));
        build_binding(
            installed,
            operation,
            action,
            authority,
            Protocol::Acquisition {
                request: commitment(
                    "auths.effect-acquisition-request/2",
                    &self.request_bytes().map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                projection: commitment(
                    CONTRACT,
                    &canonical(&self.contract()).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                maximum_response_bytes: self.maximum_response_bytes(),
            },
            reservations,
        )
    }
}

/// Verifies native candidate-check authority and compiles the exact approved
/// read plan. Performs no custody, admission, provider I/O or publication.
/// The caller pins the staged candidate in `installed.connection`; current
/// predecessor validation remains an obligation of the entry transaction.
///
/// # Errors
/// Refuses invalid native authority, substituted candidate/recipe/arguments,
/// unsupported bounds/scope or an invalid bound-effect/review projection.
pub fn compile_candidate_credential(
    installed: &EffectInstallation<'_>,
    target: &CandidateCredentialTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    compile_acquisition(
        installed,
        AcquisitionTarget::Candidate(Box::new(target.clone())),
        now,
        proof,
        action,
    )
}
