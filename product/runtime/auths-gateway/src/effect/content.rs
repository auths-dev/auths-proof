//! Independent content read compilation from an explicit recipe capability.
//! Compilation does not grant entry, retain a response or release content.

use super::acquisition::{AcquisitionTarget, build_binding, compile_acquisition};
use super::*;
use crate::recipe::ClosedContentRead;
use auths_profile_mcp::McpToolCall;
use serde_json::{Map, Value, json};

/// Reserved native content acquisition tool, never a provider mutation tool.
pub const CONTENT_READ_TOOL: &str = "auths_gateway_content_read_v1";
const CONTRACT: &str = "auths.gateway-content-acquisition/1";
/// Permanent source allowance per installed recipe/resource/credential binding.
const MAX_CONTENT_ATTEMPTS: u64 = 16;

/// Exact resource and compiler-owned content GET on one installed connection.
/// Public construction is data-only; no native authority is inferred from an
/// operator's recipe, a connection record or arbitrary resource parameters.
#[derive(Clone)]
pub struct ContentReadTarget {
    recipe: [u8; 32],
    connection: ConnectionRecord,
    arguments: Map<String, Value>,
    read: ClosedContentRead,
}

impl fmt::Debug for ContentReadTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentReadTarget { private: [redacted] }")
    }
}

impl ContentReadTarget {
    /// Resolves only the declared recipe content capability and exact resource
    /// arguments. The live connection, native proof, exact approval and shared
    /// journal must all be checked later before any external entry.
    ///
    /// # Errors
    /// Refuses an absent/invalid content capability, mismatched connection or
    /// extra/missing/invalid resource arguments. This performs no custody/I/O.
    pub fn new(
        recipe: &CompiledRecipe,
        connection: &ConnectionRecord,
        arguments: Map<String, Value>,
    ) -> Result<Self, EffectBindingError> {
        GatewayConnectionDescriptor::from_record(connection, recipe)
            .map_err(|_| EffectBindingError::Invalid)?;
        let read = recipe
            .content_read(&arguments)
            .map_err(|_| EffectBindingError::Invalid)?;
        let target = Self {
            recipe: *recipe.digest(),
            connection: connection.clone(),
            arguments,
            read,
        };
        canonical(&target.contract()?)?;
        Ok(target)
    }

    fn connection_commitment(&self) -> Result<[u8; 32], EffectBindingError> {
        let bytes = Zeroizing::new(
            self.connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        commitment("auths.effect-installation/1", &bytes)
    }

    pub(super) fn contract(&self) -> Result<Value, EffectBindingError> {
        Ok(json!({
            "schema": CONTRACT,
            "recipe": hex::encode(self.recipe),
            "connection": hex::encode(self.connection_commitment()?),
            "content": self.read.private_contract(),
            "maximum_attempts": MAX_CONTENT_ATTEMPTS,
            "disclosure": "separate-authorization-required",
        }))
    }

    pub(super) fn private_read_review(&self) -> Value {
        self.read.private_contract()
    }

    pub(super) fn request_bytes(
        &self,
        prerequisites: &Prerequisites,
    ) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        canonical(
            &json!({"request": self.read.private_request(), "prerequisite_acquisitions": prerequisites}),
        )
    }

    pub(super) fn validate_installation(
        &self,
        installed: &EffectInstallation<'_>,
    ) -> Result<(), EffectBindingError> {
        let current = Self::new(
            installed.recipe,
            installed.connection,
            self.arguments.clone(),
        )?;
        if self.recipe != *installed.recipe.digest()
            || canonical(&current.contract()?)? != canonical(&self.contract()?)?
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    /// Authors the native read call to be signed/authorized independently of a
    /// mutation or credential check. The resource arguments and full compiler
    /// contract are both bound; no caller URL, projection or byte-limit override
    /// is accepted. Returned data belongs on private authoring/review channels.
    ///
    /// # Errors
    /// Refuses another recipe or unrepresentable canonical arguments.
    pub fn authorization_call(
        &self,
        recipe: &CompiledRecipe,
        operation: &LogicalOperationId,
    ) -> Result<McpToolCall, EffectBindingError> {
        if self.recipe != *recipe.digest() {
            return Err(EffectBindingError::Invalid);
        }
        let arguments = json!({
            "operation_id": operation.as_str(),
            "operator_namespace": recipe.namespace().as_str(),
            "recipe_digest": recipe.digest_hex(),
            "content_contract": hex::encode(commitment(CONTRACT, &canonical(&self.contract()?)?)?),
            "resource_arguments": self.arguments,
            "maximum_response_bytes": self.read.transport().maximum_response_bytes(),
        })
        .as_object()
        .cloned()
        .ok_or(EffectBindingError::Invalid)?;
        McpToolCall::new(recipe.service(), CONTENT_READ_TOOL, arguments)
            .map_err(|_| EffectBindingError::Invalid)
    }

    pub(crate) fn closed_read(&self) -> &ClosedContentRead {
        &self.read
    }

    pub(super) fn journal_plan(
        &self,
        prerequisites: &Prerequisites,
    ) -> Result<ContentPlan, EffectBindingError> {
        let encode = |bytes: Zeroizing<Vec<u8>>| {
            String::from_utf8(bytes.to_vec()).map_err(|_| EffectBindingError::Invalid)
        };
        Ok(ContentPlan {
            recipe: self.recipe,
            connection: hex::encode(
                self.connection
                    .to_canonical_cbor()
                    .map_err(|_| EffectBindingError::Invalid)?,
            ),
            transport: encode(self.request_bytes(prerequisites)?)?,
            contract: encode(canonical(&self.contract()?)?)?,
        })
    }

    pub(super) fn binding(
        &self,
        installed: &EffectInstallation<'_>,
        operation: &LogicalOperationId,
        action_commitment: [u8; 32],
        native_authority: [u8; 32],
        bound: Option<&crate::bounds::BoundAdmission>,
        prerequisites: &Prerequisites,
    ) -> Result<EffectBinding, GatewaySubmitResult> {
        let invalid = || not_entered("gateway.acquisition.binding");
        self.validate_installation(installed)
            .map_err(|_| invalid())?;
        let contract = commitment(
            CONTRACT,
            &canonical(&self.contract().map_err(|_| invalid())?).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let capacity = self
            .journal_plan(prerequisites)
            .and_then(|plan| plan.capacity())
            .map_err(|_| invalid())?;
        let maximum_bytes = capacity.maximum_bytes;
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
            action_commitment,
            native_authority,
            Protocol::Acquisition {
                request: commitment(
                    "auths.effect-acquisition-request/2",
                    &self.request_bytes(prerequisites).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                projection: contract,
                maximum_response_bytes: maximum_bytes,
            },
            reservations,
        )
    }
}

/// Produces an immutable native content acquisition effect from separately
/// verified read authority and the installed recipe/connection. Exact approval
/// and durable admission/entry remain separate. This cannot execute a mutation,
/// acquire credentials, enter transport or disclose any acquired content.
///
/// # Errors
/// Refuses invalid native proof, changed target/installation, extra arguments,
/// unrelated scope or invalid managed acquisition limits.
pub fn compile_content_acquisition(
    installed: &EffectInstallation<'_>,
    target: &ContentReadTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    compile_acquisition(
        installed,
        AcquisitionTarget::Content(Box::new(target.clone())),
        now,
        proof,
        action,
    )
}

/// Immutable reconstruction data, never a transport capability. The signed
/// binding pins the complete contract and request; current connection bytes
/// must also match under the common admission and entry fence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContentPlan {
    recipe: [u8; 32],
    connection: String,
    transport: String,
    contract: String,
}

impl ContentPlan {
    fn connection(&self) -> Result<ConnectionRecord, EffectBindingError> {
        if self.connection.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let bytes =
            Zeroizing::new(hex::decode(&self.connection).map_err(|_| EffectBindingError::Invalid)?);
        if hex::encode(bytes.as_slice()) != self.connection {
            return Err(EffectBindingError::Invalid);
        }
        ConnectionRecord::from_canonical_cbor(&bytes).map_err(|_| EffectBindingError::Invalid)
    }

    pub(crate) fn source_key(&self) -> Result<crate::GatewayAttemptKey, EffectBindingError> {
        let connection = self.connection()?;
        Ok(crate::connection_key(
            connection.provider_kind(),
            connection.alias(),
        ))
    }

    pub(crate) fn source_id(&self) -> Result<[u8; 32], EffectBindingError> {
        commitment("auths.content-source/1", &self.capacity()?.count_key)
    }

    pub(crate) fn source_matches(
        &self,
        bytes: Option<&[u8]>,
    ) -> Result<(bool, u64), EffectBindingError> {
        let connection = self.connection()?;
        let expected = Zeroizing::new(
            connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        Ok((
            bytes == Some(expected.as_slice()),
            connection.updated_at_unix_seconds(),
        ))
    }

    fn witness(&self) -> Result<Value, EffectBindingError> {
        if self.contract.len() > MAX_EFFECT_BYTES || self.transport.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let contract: Value =
            serde_json::from_str(&self.contract).map_err(|_| EffectBindingError::Invalid)?;
        let transport: Value =
            serde_json::from_str(&self.transport).map_err(|_| EffectBindingError::Invalid)?;
        let connection = self.connection()?;
        let bytes = Zeroizing::new(
            connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        if canonical(&contract)?.as_slice() != self.contract.as_bytes()
            || canonical(&transport)?.as_slice() != self.transport.as_bytes()
            || contract["schema"] != CONTRACT
            || contract["recipe"] != hex::encode(self.recipe)
            || contract["connection"]
                != hex::encode(commitment("auths.effect-installation/1", &bytes)?)
            || contract["maximum_attempts"] != MAX_CONTENT_ATTEMPTS
            || contract["disclosure"] != "separate-authorization-required"
            || contract["content"]["schema"] != crate::recipe::CONTENT_READ_SCHEMA
            || transport["request"] != contract["content"]["request"]
            || !contract["content"]["resource_arguments"].is_object()
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(contract)
    }

    pub(crate) fn projection(
        &self,
    ) -> Result<crate::recipe::ContentProjectionSpec, EffectBindingError> {
        crate::recipe::ContentProjectionSpec::from_contract(&self.witness()?["content"])
            .ok_or(EffectBindingError::Invalid)
    }

    pub(crate) fn projection_commitment(&self) -> Result<[u8; 32], EffectBindingError> {
        commitment(CONTRACT, self.contract.as_bytes())
    }

    pub(crate) fn capacity(&self) -> Result<AcquisitionCapacity, EffectBindingError> {
        let contract = self.witness()?;
        let maximum_bytes = contract["content"]["request"]["maximum_response_bytes"]
            .as_u64()
            .filter(|value| (1..=65_536).contains(value))
            .ok_or(EffectBindingError::Invalid)?;
        let connection = self.connection()?;
        // Administrative state/timestamps and logical operations never reset
        // the lifetime allowance for this credential and exact resource.
        let key = |unit| {
            commitment(
                "auths.content-acquisition-capacity/1",
                &canonical(&(
                    self.recipe,
                    connection.connection_id().as_str(),
                    connection.credential_generation().get(),
                    connection.credential_reference_commitment(),
                    &contract["content"]["resource_arguments"],
                    unit,
                ))?,
            )
        };
        Ok(AcquisitionCapacity {
            count_key: key(Unit::AcquisitionCount)?,
            bytes_key: key(Unit::ResponseBytes)?,
            maximum_bytes,
            attempts: MAX_CONTENT_ATTEMPTS,
        })
    }

    pub(crate) fn validate(
        &self,
        binding: &EffectBinding,
    ) -> Result<AcquisitionCapacity, EffectBindingError> {
        let capacity = self.capacity()?;
        self.projection()?;
        let connection = self.connection()?;
        let bytes = Zeroizing::new(
            connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        if binding.wire.recipe != self.recipe
            || binding.wire.connection != commitment("auths.effect-installation/1", &bytes)?
            || binding.wire.credential_generation != connection.credential_generation().get()
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
