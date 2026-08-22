//! Common operation identities and commitment-bound journal projections.
//!
//! This module deliberately owns only cross-profile mechanics. Concrete
//! verticals remain the sole authority for canonical actions, provider-result
//! interpretation, partial effects, reconciliation evidence, and receipts.

use alloc::string::String;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Exact client-generated request identifier retained for one logical call.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientRequestIdV1([u8; 16]);

impl ClientRequestIdV1 {
    /// Constructs the exact identifier from its wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Server-generated durable operation identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OperationIdV1(String);

impl OperationIdV1 {
    /// Parses `op_` followed by canonical unpadded base64url for 16 nonzero bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError::InvalidOperationId`] for malformed,
    /// noncanonical, or all-zero input.
    pub fn parse(value: impl Into<String>) -> Result<Self, PreparationBindingError> {
        let value = value.into();
        let encoded = value
            .strip_prefix("op_")
            .ok_or(PreparationBindingError::InvalidOperationId)?;
        let mut bytes = [0_u8; 16];
        let decoded = Base64UrlUnpadded::decode(encoded, &mut bytes)
            .map_err(|_| PreparationBindingError::InvalidOperationId)?;
        if decoded.len() != 16
            || decoded == [0; 16]
            || Base64UrlUnpadded::encode_string(decoded) != encoded
        {
            return Err(PreparationBindingError::InvalidOperationId);
        }
        Ok(Self(value))
    }

    /// Constructs the canonical identifier from exact random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError::InvalidOperationId`] for all-zero bytes.
    pub fn from_random_bytes(bytes: [u8; 16]) -> Result<Self, PreparationBindingError> {
        if bytes == [0; 16] {
            return Err(PreparationBindingError::InvalidOperationId);
        }
        Self::parse(format_operation_id(&bytes))
    }

    /// Returns the canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn format_operation_id(bytes: &[u8; 16]) -> String {
    let encoded = Base64UrlUnpadded::encode_string(bytes);
    let mut value = String::with_capacity(3 + encoded.len());
    value.push_str("op_");
    value.push_str(&encoded);
    value
}

/// Immutable profile identity stored by the common journal.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OperationProfileV1 {
    id: String,
    version: u16,
    runtime_contract_digest: [u8; 32],
}

impl OperationProfileV1 {
    /// Constructs a validated profile identity and exact runtime digest.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError::InvalidProfile`] when the profile
    /// identifier or version is outside the closed bounds.
    pub fn new(
        id: impl Into<String>,
        version: u16,
        runtime_contract_digest: [u8; 32],
    ) -> Result<Self, PreparationBindingError> {
        let id = id.into();
        if !profile_id(&id) || version == 0 {
            return Err(PreparationBindingError::InvalidProfile);
        }
        Ok(Self {
            id,
            version,
            runtime_contract_digest,
        })
    }

    /// Returns the exact profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the immutable profile version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the generated runtime-contract digest.
    #[must_use]
    pub const fn runtime_contract_digest(&self) -> &[u8; 32] {
        &self.runtime_contract_digest
    }
}

/// Connection identity and commitments captured without credential bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionBindingCommitmentsV1 {
    alias: String,
    connection_id: String,
    generation: u64,
    descriptor_commitment: [u8; 32],
    account_commitment: [u8; 32],
}

impl ConnectionBindingCommitmentsV1 {
    /// Constructs a validated sealed connection projection.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError::InvalidConnection`] for malformed
    /// aliases, identifiers, or a zero generation.
    pub fn new(
        alias: impl Into<String>,
        connection_id: impl Into<String>,
        generation: u64,
        descriptor_commitment: [u8; 32],
        account_commitment: [u8; 32],
    ) -> Result<Self, PreparationBindingError> {
        let alias = alias.into();
        let connection_id = connection_id.into();
        if !lower_token(&alias) || !bounded_ascii_graphic(&connection_id, 160) || generation == 0 {
            return Err(PreparationBindingError::InvalidConnection);
        }
        Ok(Self {
            alias,
            connection_id,
            generation,
            descriptor_commitment,
            account_commitment,
        })
    }

    /// Returns the resolved public alias.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Returns the internal immutable connection identifier.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the pinned connection generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the descriptor commitment.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> &[u8; 32] {
        &self.descriptor_commitment
    }

    /// Returns the provider-account commitment.
    #[must_use]
    pub const fn account_commitment(&self) -> &[u8; 32] {
        &self.account_commitment
    }
}

/// Exact security binding retained before an operation may execute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparationBindingV1 {
    principal: String,
    profile: OperationProfileV1,
    request_id: ClientRequestIdV1,
    idempotency_commitment: Option<[u8; 32]>,
    canonical_input_commitment: [u8; 32],
    preparation_evidence_commitment: Option<[u8; 32]>,
    preparation_evidence_intent_commitment: Option<[u8; 32]>,
    connection: Option<ConnectionBindingCommitmentsV1>,
    canonical_action_commitment: [u8; 32],
    authority_commitment: [u8; 32],
    configuration_commitment: [u8; 32],
    preparation_commitment: [u8; 32],
}

impl PreparationBindingV1 {
    /// Constructs and commits all common preparation facts.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError::InvalidPrincipal`] when the principal
    /// is empty or exceeds the public bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: impl Into<String>,
        profile: OperationProfileV1,
        request_id: ClientRequestIdV1,
        idempotency_commitment: Option<[u8; 32]>,
        canonical_input_commitment: [u8; 32],
        preparation_evidence_commitment: Option<[u8; 32]>,
        preparation_evidence_intent_commitment: Option<[u8; 32]>,
        connection: Option<ConnectionBindingCommitmentsV1>,
        canonical_action_commitment: [u8; 32],
        authority_commitment: [u8; 32],
        configuration_commitment: [u8; 32],
    ) -> Result<Self, PreparationBindingError> {
        let principal = principal.into();
        if !bounded_utf8(&principal, 512) {
            return Err(PreparationBindingError::InvalidPrincipal);
        }
        let preparation_commitment = preparation_commitment(
            &principal,
            &profile,
            &request_id,
            idempotency_commitment.as_ref(),
            &canonical_input_commitment,
            preparation_evidence_commitment.as_ref(),
            preparation_evidence_intent_commitment.as_ref(),
            connection.as_ref(),
            &canonical_action_commitment,
            &authority_commitment,
            &configuration_commitment,
        );
        Ok(Self {
            principal,
            profile,
            request_id,
            idempotency_commitment,
            canonical_input_commitment,
            preparation_evidence_commitment,
            preparation_evidence_intent_commitment,
            connection,
            canonical_action_commitment,
            authority_commitment,
            configuration_commitment,
            preparation_commitment,
        })
    }

    /// Returns the kernel-observed principal.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Returns the exact profile identity.
    #[must_use]
    pub const fn profile(&self) -> &OperationProfileV1 {
        &self.profile
    }

    /// Returns the original client request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestIdV1 {
        self.request_id
    }

    /// Returns only the commitment to the optional raw idempotency key.
    #[must_use]
    pub const fn idempotency_commitment(&self) -> Option<&[u8; 32]> {
        self.idempotency_commitment.as_ref()
    }

    /// Returns the canonical profile-input commitment.
    #[must_use]
    pub const fn canonical_input_commitment(&self) -> &[u8; 32] {
        &self.canonical_input_commitment
    }

    /// Returns the exact protected preparation-evidence commitment, or null
    /// for profiles that declare no companion evidence lease.
    #[must_use]
    pub const fn preparation_evidence_commitment(&self) -> Option<&[u8; 32]> {
        self.preparation_evidence_commitment.as_ref()
    }

    /// Returns the evidence-independent companion admission commitment. This
    /// is retained in full records and compact tombstones so exact replay can
    /// be decided before any provider read.
    #[must_use]
    pub const fn preparation_evidence_intent_commitment(&self) -> Option<&[u8; 32]> {
        self.preparation_evidence_intent_commitment.as_ref()
    }

    /// Returns the sealed connection binding, or canonical null.
    #[must_use]
    pub const fn connection(&self) -> Option<&ConnectionBindingCommitmentsV1> {
        self.connection.as_ref()
    }

    /// Returns the concrete profile action commitment.
    #[must_use]
    pub const fn canonical_action_commitment(&self) -> &[u8; 32] {
        &self.canonical_action_commitment
    }

    /// Returns the sealed workload-authority commitment.
    #[must_use]
    pub const fn authority_commitment(&self) -> &[u8; 32] {
        &self.authority_commitment
    }

    /// Returns the concrete required-configuration commitment.
    #[must_use]
    pub const fn configuration_commitment(&self) -> &[u8; 32] {
        &self.configuration_commitment
    }

    /// Returns the domain-separated commitment over every preparation fact.
    #[must_use]
    pub const fn preparation_commitment(&self) -> &[u8; 32] {
        &self.preparation_commitment
    }

    /// Returns the stable comparison commitment for a caller idempotency key.
    ///
    /// This binds every durable preparation fact except the client request ID,
    /// which identifies one transport attempt rather than the caller's logical
    /// operation. The raw idempotency key remains hidden behind its digest.
    #[must_use]
    pub fn idempotency_replay_commitment(&self) -> [u8; 32] {
        idempotency_replay_commitment(
            &self.principal,
            &self.profile,
            self.idempotency_commitment.as_ref(),
            &self.canonical_input_commitment,
            self.preparation_evidence_commitment.as_ref(),
            self.preparation_evidence_intent_commitment.as_ref(),
            self.connection.as_ref(),
            &self.canonical_action_commitment,
            &self.authority_commitment,
            &self.configuration_commitment,
        )
    }

    /// Revalidates a decoded persisted value and its derived commitment.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationBindingError`] when any persisted field is invalid
    /// or the derived preparation commitment does not match.
    pub fn validate(&self) -> Result<(), PreparationBindingError> {
        let rebuilt = Self::new(
            self.principal.clone(),
            self.profile.clone(),
            self.request_id,
            self.idempotency_commitment,
            self.canonical_input_commitment,
            self.preparation_evidence_commitment,
            self.preparation_evidence_intent_commitment,
            self.connection.clone(),
            self.canonical_action_commitment,
            self.authority_commitment,
            self.configuration_commitment,
        )?;
        if rebuilt.preparation_commitment != self.preparation_commitment {
            return Err(PreparationBindingError::CommitmentMismatch);
        }
        Ok(())
    }
}

/// Closed common operation state vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperationStateV1 {
    /// Effect-free preparation is in progress.
    Preparing,
    /// Concrete policy denied before provider entry.
    Denied,
    /// A required pre-entry dependency was unavailable.
    Unavailable,
    /// Decision, reservation, and sealed command are durable.
    Ready,
    /// Execution is in progress; inspect [`OperationEffectV1`] for entry truth.
    Executing,
    /// Provider entry may have occurred and recovery remains required.
    RecoveryRequired,
    /// The complete profile effect is proven.
    Completed,
    /// A profile-defined subset is proven applied.
    Partial,
    /// Definite provider non-effect is proven.
    NotApplied,
}

/// Closed effect axis independent of operational state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperationEffectV1 {
    /// Provider non-entry or fresh evidence proves absence.
    NotApplied,
    /// Provider entry may have occurred and evidence is inconclusive.
    Possible,
    /// Concrete profile evidence proves an effect or defined subset.
    Applied,
}

/// Validated common state/effect/terminal projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationProjectionV1 {
    state: OperationStateV1,
    effect: OperationEffectV1,
    terminal: bool,
}

impl OperationProjectionV1 {
    /// Constructs exactly one row of the common operation truth table.
    ///
    /// # Errors
    ///
    /// Returns [`OperationProjectionError::ImpossibleCombination`] for a state,
    /// effect, and terminal tuple outside the closed truth table.
    pub const fn new(
        state: OperationStateV1,
        effect: OperationEffectV1,
        terminal: bool,
    ) -> Result<Self, OperationProjectionError> {
        let valid = match state {
            OperationStateV1::Preparing | OperationStateV1::Ready => {
                matches!(effect, OperationEffectV1::NotApplied) && !terminal
            }
            OperationStateV1::Denied
            | OperationStateV1::Unavailable
            | OperationStateV1::NotApplied => {
                matches!(effect, OperationEffectV1::NotApplied) && terminal
            }
            OperationStateV1::Executing => {
                matches!(
                    effect,
                    OperationEffectV1::NotApplied | OperationEffectV1::Possible
                ) && !terminal
            }
            OperationStateV1::RecoveryRequired => {
                matches!(effect, OperationEffectV1::Possible) && !terminal
            }
            OperationStateV1::Completed | OperationStateV1::Partial => {
                matches!(effect, OperationEffectV1::Applied) && terminal
            }
        };
        if !valid {
            return Err(OperationProjectionError::ImpossibleCombination);
        }
        Ok(Self {
            state,
            effect,
            terminal,
        })
    }

    /// Returns the operational state.
    #[must_use]
    pub const fn state(self) -> OperationStateV1 {
        self.state
    }

    /// Returns authoritative effect truth.
    #[must_use]
    pub const fn effect(self) -> OperationEffectV1 {
        self.effect
    }

    /// Returns whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.terminal
    }

    /// Revalidates a deserialized projection.
    ///
    /// # Errors
    ///
    /// Returns [`OperationProjectionError::ImpossibleCombination`] when the
    /// decoded projection is not a row in the closed truth table.
    pub const fn validate(self) -> Result<(), OperationProjectionError> {
        match Self::new(self.state, self.effect, self.terminal) {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Closed invalid preparation classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationBindingError {
    /// Principal is empty or exceeds 512 UTF-8 bytes.
    InvalidPrincipal,
    /// Profile identity or version is invalid.
    InvalidProfile,
    /// Operation identifier is malformed.
    InvalidOperationId,
    /// Connection metadata is malformed.
    InvalidConnection,
    /// A persisted derived commitment does not match its fields.
    CommitmentMismatch,
}

/// Closed invalid common projection classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationProjectionError {
    /// State, effect, and terminal truth do not name one permitted row.
    ImpossibleCombination,
}

#[allow(clippy::too_many_arguments)]
fn preparation_commitment(
    principal: &str,
    profile: &OperationProfileV1,
    request_id: &ClientRequestIdV1,
    idempotency_commitment: Option<&[u8; 32]>,
    canonical_input_commitment: &[u8; 32],
    preparation_evidence_commitment: Option<&[u8; 32]>,
    preparation_evidence_intent_commitment: Option<&[u8; 32]>,
    connection: Option<&ConnectionBindingCommitmentsV1>,
    canonical_action_commitment: &[u8; 32],
    authority_commitment: &[u8; 32],
    configuration_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-PROFILE-OPERATION-PREPARATION\x00\x01");
    update_bytes(&mut digest, principal.as_bytes());
    update_bytes(&mut digest, profile.id.as_bytes());
    digest.update(profile.version.to_be_bytes());
    digest.update(profile.runtime_contract_digest);
    digest.update(request_id.0);
    match idempotency_commitment {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
    }
    digest.update(canonical_input_commitment);
    update_optional_digest(&mut digest, preparation_evidence_commitment);
    update_optional_digest(&mut digest, preparation_evidence_intent_commitment);
    match connection {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            update_bytes(&mut digest, value.alias.as_bytes());
            update_bytes(&mut digest, value.connection_id.as_bytes());
            digest.update(value.generation.to_be_bytes());
            digest.update(value.descriptor_commitment);
            digest.update(value.account_commitment);
        }
    }
    digest.update(canonical_action_commitment);
    digest.update(authority_commitment);
    digest.update(configuration_commitment);
    digest.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn idempotency_replay_commitment(
    principal: &str,
    profile: &OperationProfileV1,
    idempotency_commitment: Option<&[u8; 32]>,
    canonical_input_commitment: &[u8; 32],
    preparation_evidence_commitment: Option<&[u8; 32]>,
    preparation_evidence_intent_commitment: Option<&[u8; 32]>,
    connection: Option<&ConnectionBindingCommitmentsV1>,
    canonical_action_commitment: &[u8; 32],
    authority_commitment: &[u8; 32],
    configuration_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-PROFILE-IDEMPOTENCY-REPLAY\x00\x01");
    update_bytes(&mut digest, principal.as_bytes());
    update_bytes(&mut digest, profile.id.as_bytes());
    digest.update(profile.version.to_be_bytes());
    digest.update(profile.runtime_contract_digest);
    match idempotency_commitment {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
    }
    digest.update(canonical_input_commitment);
    update_optional_digest(&mut digest, preparation_evidence_commitment);
    update_optional_digest(&mut digest, preparation_evidence_intent_commitment);
    match connection {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            update_bytes(&mut digest, value.alias.as_bytes());
            update_bytes(&mut digest, value.connection_id.as_bytes());
            digest.update(value.generation.to_be_bytes());
            digest.update(value.descriptor_commitment);
            digest.update(value.account_commitment);
        }
    }
    digest.update(canonical_action_commitment);
    digest.update(authority_commitment);
    digest.update(configuration_commitment);
    digest.finalize().into()
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn update_optional_digest(digest: &mut Sha256, value: Option<&[u8; 32]>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
    }
}

fn profile_id(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!(parts.next(), Some("auths"))
        && parts.next().is_some_and(lower_token)
        && parts.next().is_some_and(lower_token)
        && parts.next().is_none()
        && value.len() <= 128
}

fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
}

fn bounded_ascii_graphic(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn bounded_utf8(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> PreparationBindingV1 {
        PreparationBindingV1::new(
            "did:key:workload",
            OperationProfileV1::new("auths.stripe.refund", 1, [1; 32]).unwrap(),
            ClientRequestIdV1::from_bytes([2; 16]),
            Some([3; 32]),
            [4; 32],
            None,
            None,
            Some(
                ConnectionBindingCommitmentsV1::new(
                    "billing",
                    "con_01ABCDEFGHJKLMNPQRSTUV",
                    7,
                    [5; 32],
                    [6; 32],
                )
                .unwrap(),
            ),
            [7; 32],
            [8; 32],
            [9; 32],
        )
        .unwrap()
    }

    #[test]
    fn preparation_commitment_binds_every_security_fact() {
        let first = binding();
        let second = PreparationBindingV1::new(
            first.principal(),
            first.profile().clone(),
            first.request_id(),
            first.idempotency_commitment().copied(),
            *first.canonical_input_commitment(),
            first.preparation_evidence_commitment().copied(),
            first.preparation_evidence_intent_commitment().copied(),
            first.connection().cloned(),
            *first.canonical_action_commitment(),
            *first.authority_commitment(),
            [10; 32],
        )
        .unwrap();
        assert_ne!(
            first.preparation_commitment(),
            second.preparation_commitment()
        );
        first.validate().unwrap();
    }

    #[test]
    fn idempotency_replay_commitment_excludes_only_request_identity() {
        let first = binding();
        let second = PreparationBindingV1::new(
            first.principal(),
            first.profile().clone(),
            ClientRequestIdV1::from_bytes([11; 16]),
            first.idempotency_commitment().copied(),
            *first.canonical_input_commitment(),
            first.preparation_evidence_commitment().copied(),
            first.preparation_evidence_intent_commitment().copied(),
            first.connection().cloned(),
            *first.canonical_action_commitment(),
            *first.authority_commitment(),
            *first.configuration_commitment(),
        )
        .unwrap();
        assert_ne!(
            first.preparation_commitment(),
            second.preparation_commitment()
        );
        assert_eq!(
            first.idempotency_replay_commitment(),
            second.idempotency_replay_commitment()
        );

        let changed = PreparationBindingV1::new(
            first.principal(),
            first.profile().clone(),
            ClientRequestIdV1::from_bytes([11; 16]),
            first.idempotency_commitment().copied(),
            [12; 32],
            first.preparation_evidence_commitment().copied(),
            first.preparation_evidence_intent_commitment().copied(),
            first.connection().cloned(),
            *first.canonical_action_commitment(),
            *first.authority_commitment(),
            *first.configuration_commitment(),
        )
        .unwrap();
        assert_ne!(
            first.idempotency_replay_commitment(),
            changed.idempotency_replay_commitment()
        );
    }

    #[test]
    fn public_truth_table_rejects_unsafe_combinations() {
        assert!(
            OperationProjectionV1::new(
                OperationStateV1::Executing,
                OperationEffectV1::Possible,
                false,
            )
            .is_ok()
        );
        assert!(
            OperationProjectionV1::new(
                OperationStateV1::RecoveryRequired,
                OperationEffectV1::NotApplied,
                false,
            )
            .is_err()
        );
        assert!(
            OperationProjectionV1::new(
                OperationStateV1::Completed,
                OperationEffectV1::Applied,
                true,
            )
            .is_ok()
        );
    }

    #[test]
    fn operation_id_requires_canonical_nonzero_random_bytes() {
        let id = OperationIdV1::from_random_bytes([11; 16]).unwrap();
        assert_eq!(OperationIdV1::parse(id.as_str()).unwrap(), id);
        assert!(OperationIdV1::from_random_bytes([0; 16]).is_err());
        assert!(OperationIdV1::parse("op_not/canonical").is_err());
    }
}
