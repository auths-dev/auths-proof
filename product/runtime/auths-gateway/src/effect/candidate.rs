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

    pub(crate) fn record(&self) -> &ConnectionRecord {
        &self.candidate
    }

    pub(crate) fn predecessor_matches(&self, bytes: Option<&[u8]>) -> bool {
        match (&self.previous, bytes) {
            (None, None) => true,
            (Some(previous), Some(bytes)) => previous
                .to_canonical_cbor()
                .is_ok_and(|expected| expected == bytes),
            _ => false,
        }
    }

    pub(crate) fn previous(&self) -> Option<&ConnectionRecord> {
        self.previous.as_ref()
    }

    pub(crate) fn final_kind(&self) -> PrerequisiteKind {
        self.last.purpose.kind()
    }

    pub(crate) fn final_request(&self) -> &ClosedPrerequisiteRead {
        &self.last.request
    }

    pub(crate) fn journal_plan(&self) -> Result<CandidatePlan, EffectBindingError> {
        Ok(CandidatePlan {
            candidate: hex::encode(
                self.candidate
                    .to_canonical_cbor()
                    .map_err(|_| EffectBindingError::Invalid)?,
            ),
            previous: self
                .previous
                .as_ref()
                .map(|record| record.to_canonical_cbor().map(hex::encode))
                .transpose()
                .map_err(|_| EffectBindingError::Invalid)?,
            transport: String::from_utf8(self.request_bytes()?.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
            contract: String::from_utf8(canonical(&self.contract())?.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
        })
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
        let record = |record: &ConnectionRecord| connection_review(record, &self.descriptor);
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
        let capacity = candidate_capacity(&self.candidate, self.maximum_response_bytes())
            .map_err(|_| invalid())?;
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

fn candidate_capacity(
    candidate: &ConnectionRecord,
    maximum_bytes: u64,
) -> Result<AcquisitionCapacity, EffectBindingError> {
    if !(1..=65_536).contains(&maximum_bytes) {
        return Err(EffectBindingError::Invalid);
    }
    let key = |unit| {
        commitment(
            "auths.candidate-capacity/1",
            &canonical(&(
                candidate.connection_id().as_str(),
                candidate.credential_generation().get(),
                candidate.credential_reference_commitment(),
                unit,
            ))?,
        )
    };
    Ok(AcquisitionCapacity {
        count_key: key(Unit::AcquisitionCount)?,
        bytes_key: key(Unit::ResponseBytes)?,
        maximum_bytes,
        attempts: MAX_CANDIDATE_ATTEMPTS,
    })
}

/// Private immutable audit projection; decoding never creates a transport target.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidatePlan {
    candidate: String,
    previous: Option<String>,
    transport: String,
    contract: String,
}

impl CandidatePlan {
    pub(crate) fn connection(&self) -> Result<ConnectionRecord, EffectBindingError> {
        if self.candidate.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let bytes = hex::decode(&self.candidate).map_err(|_| EffectBindingError::Invalid)?;
        if hex::encode(&bytes) != self.candidate {
            return Err(EffectBindingError::Invalid);
        }
        ConnectionRecord::from_canonical_cbor(&bytes).map_err(|_| EffectBindingError::Invalid)
    }

    pub(crate) fn source_key(&self) -> Result<crate::GatewayAttemptKey, EffectBindingError> {
        let record = self.connection()?;
        Ok(crate::connection_key(
            record.provider_kind(),
            record.alias(),
        ))
    }

    pub(crate) fn source_id(&self) -> Result<[u8; 32], EffectBindingError> {
        let record = self.connection()?;
        commitment(
            "auths.candidate-source/1",
            &canonical(&(
                record.connection_id().as_str(),
                record.credential_generation().get(),
                record.credential_reference_commitment(),
            ))?,
        )
    }

    pub(crate) fn source_matches(
        &self,
        bytes: Option<&[u8]>,
    ) -> Result<(bool, u64), EffectBindingError> {
        match (&self.previous, bytes) {
            (None, None) => Ok((true, self.connection()?.created_at_unix_seconds())),
            (Some(expected), Some(bytes)) => {
                let expected_bytes =
                    hex::decode(expected).map_err(|_| EffectBindingError::Invalid)?;
                let previous = ConnectionRecord::from_canonical_cbor(&expected_bytes)
                    .map_err(|_| EffectBindingError::Invalid)?;
                Ok((
                    expected_bytes == bytes,
                    self.connection()?
                        .updated_at_unix_seconds()
                        .max(previous.updated_at_unix_seconds()),
                ))
            }
            _ => Ok((false, 0)),
        }
    }

    fn witness(&self) -> Result<Value, EffectBindingError> {
        if self.transport.len() > MAX_EFFECT_BYTES
            || self.contract.len() > MAX_EFFECT_BYTES
            || self.candidate.len() > MAX_EFFECT_BYTES
            || self
                .previous
                .as_ref()
                .is_some_and(|v| v.len() > MAX_EFFECT_BYTES)
        {
            return Err(EffectBindingError::Invalid);
        }
        let contract: Value =
            serde_json::from_str(&self.contract).map_err(|_| EffectBindingError::Invalid)?;
        if canonical(&contract)?.as_slice() != self.contract.as_bytes()
            || canonical(&json!({"request": contract["final_check"]["request"], "prerequisite_acquisitions": contract["ordered_prerequisites"]}))?.as_slice() != self.transport.as_bytes() {
            return Err(EffectBindingError::Invalid);
        }
        Ok(contract)
    }

    pub(crate) fn capacity(&self) -> Result<AcquisitionCapacity, EffectBindingError> {
        let contract = self.witness()?;
        candidate_capacity(
            &self.connection()?,
            contract["final_check"]["request"]["maximum_response_bytes"]
                .as_u64()
                .ok_or(EffectBindingError::Invalid)?,
        )
    }

    pub(crate) fn validate(
        &self,
        binding: &EffectBinding,
    ) -> Result<AcquisitionCapacity, EffectBindingError> {
        let capacity = self.capacity()?;
        let candidate = self.connection()?;
        let previous = self
            .previous
            .as_ref()
            .map(|s| hex::decode(s).map_err(|_| EffectBindingError::Invalid))
            .transpose()?;
        // Pin predecessor bytes in the signed contract, including absence. Its
        // actual current value is checked separately under the adapter fence.
        let contract = self.witness()?;
        let proposed = contract["candidate"].clone();
        let validate_record =
            |value: &Value, record: &ConnectionRecord| -> Result<(), EffectBindingError> {
                let descriptor: Value = serde_json::from_slice(record.descriptor())
                    .map_err(|_| EffectBindingError::Invalid)?;
                if *value != connection_review(record, &descriptor) {
                    return Err(EffectBindingError::Invalid);
                }
                Ok(())
            };
        validate_record(&proposed, &candidate)?;
        if let Some(bytes) = previous {
            let previous = ConnectionRecord::from_canonical_cbor(&bytes)
                .map_err(|_| EffectBindingError::Invalid)?;
            validate_record(&contract["expected_previous"], &previous)?;
            if previous
                .rotated(
                    previous.descriptor().to_vec(),
                    *previous.account_commitment(),
                    *candidate.credential_reference_commitment(),
                    candidate.updated_at_unix_seconds(),
                )
                .map_err(|_| EffectBindingError::Invalid)?
                != candidate
            {
                return Err(EffectBindingError::Invalid);
            }
        } else if !contract["expected_previous"].is_null()
            || candidate.generation().get() != 1
            || candidate.state() != ConnectionState::Active
            || candidate.created_at_unix_seconds() != candidate.updated_at_unix_seconds()
        {
            return Err(EffectBindingError::Invalid);
        }
        if contract["schema"] != CONTRACT
            || contract["maximum_attempts"] != MAX_CANDIDATE_ATTEMPTS
            || contract["disclosure"] != "none"
            || binding.wire.connection != CandidateCredentialTarget::record_commitment(&candidate)?
            || binding.wire.credential_generation != candidate.credential_generation().get()
            || binding.wire.protocol
                != (Protocol::Acquisition {
                    request: commitment(
                        "auths.effect-acquisition-request/2",
                        self.transport.as_bytes(),
                    )?,
                    projection: commitment(CONTRACT, self.contract.as_bytes())?,
                    maximum_response_bytes: capacity.maximum_bytes,
                })
            || binding
                .wire
                .reservations
                .iter()
                .filter(|r| r.window == ReservationWindow::SourceLifetime)
                .cloned()
                .collect::<Vec<_>>()
                != capacity.reservations()
            || binding.wire.reservations.iter().any(|r| {
                matches!(r.window, ReservationWindow::Fixed { .. })
                    && match r.unit {
                        Unit::AcquisitionCount => r.amount != 1,
                        Unit::ResponseBytes => r.amount != capacity.maximum_bytes,
                        _ => true,
                    }
            })
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(capacity)
    }
}

fn connection_review(record: &ConnectionRecord, descriptor: &Value) -> Value {
    json!({
        "provider": record.provider_kind().as_str(), "alias": record.alias().as_str(),
        "connection_id": record.connection_id().as_str(),
        "contract": record.contract().as_str(), "descriptor_schema": record.descriptor_schema().as_str(),
        "descriptor": descriptor,
        "account_commitment": hex::encode(record.account_commitment()),
        "credential_reference_commitment": hex::encode(record.credential_reference_commitment()),
        "generation": record.generation().get(), "credential_generation": record.credential_generation().get(),
        "state": match record.state() { ConnectionState::Active => "active", ConnectionState::Disabled => "disabled", ConnectionState::Revoked => "revoked" },
        "allowed_workloads": record.allowed_workloads(),
        "allowed_profiles": record.allowed_profiles().iter().map(|p| json!({"id": p.id().as_str(), "version": p.version()})).collect::<Vec<_>>(),
        "created_at_unix_seconds": record.created_at_unix_seconds(), "updated_at_unix_seconds": record.updated_at_unix_seconds(),
    })
}
