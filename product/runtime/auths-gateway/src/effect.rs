//! Canonical private effect identity and sealed, effect-free compilation.
//!
//! Decoding an [`EffectBinding`] produces audit data, never authority. Only
//! native verification plus the installed recipe and connection can construct
//! a [`BoundEffect`]. Neither type grants custody, provider entry or disclosure.

use crate::engine::{GatewaySubmitResult, VerifiedCommand, not_entered, verify_detailed};
use crate::recipe::ObservationTemplate;
use crate::{
    ClosedProviderRequest, CompiledRecipe, GatewayConnectionDescriptor, LogicalOperationId,
    OperatorNamespace, QualificationPolicy,
};
use auths_connections::ConnectionRecord;
use auths_model::{PortableVerificationResult, Timestamp, TrustedContext, VerificationResources};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

mod acquisition;
mod candidate;
pub use candidate::{
    CANDIDATE_CHECK_TOOL, CandidateCredentialTarget, compile_candidate_credential,
};
mod prerequisite;
pub(crate) use acquisition::{
    AcquisitionCapacity, AcquisitionPlan, MAX_RECOVERY_EVIDENCE_AGE_SECONDS, RECOVERY_READ_TOOL,
    RecoveryPlan,
};
pub use acquisition::{RecoveryReadTarget, compile_recovery_acquisition};
use prerequisite::Prerequisites;
pub(crate) use prerequisite::{
    ClosedPrerequisiteRead, MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS, PrerequisiteKind,
    PrerequisitePlan,
};

/// Only accepted effect binding schema. Old disposable state is rejected.
pub const EFFECT_BINDING_SCHEMA: &str = "auths.bound-effect/3";
/// Maximum private canonical binding or compiler projection bytes.
pub const MAX_EFFECT_BYTES: usize = 65_536;
/// Maximum reservations in one effect, preserving the gateway counter bound.
pub const MAX_EFFECT_RESERVATIONS: usize = 34;
const COMPILER: &str = "auths.gateway-effect-compiler/8";
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const APPROVAL_SCHEMA: &str = "auths.exact-effect-approval/1";
/// Maximum encoded exact human approval, checked before decoding.
pub const MAX_EFFECT_APPROVAL_BYTES: usize = 4_096;
/// Exact approval cannot remain eligible for more than one hour.
pub const MAX_EFFECT_APPROVAL_SECONDS: u64 = 3_600;
/// Private human review can contain the exact body and full binding. Public
/// activity/receipt projections have a different, smaller disclosure contract.
pub const MAX_PRIVATE_EFFECT_REVIEW_BYTES: usize = 131_072;
/// Native full-value, non-markup private review renderer.
pub const LITERAL_REVIEW_RENDERER: &str = "auths.literal-complete-review/1";
/// Maximum canonical operator effect policy, checked before decoding.
pub const MAX_EFFECT_POLICY_BYTES: usize = 4_096;

/// Operator-installed replay partition and human approval authority. This is
/// configuration, never authority supplied by an application submission.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPolicy {
    schema: String,
    partition: String,
    epoch: u64,
    approver: [u8; 32],
}

impl fmt::Debug for EffectPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectPolicy { private: [redacted] }")
    }
}

impl EffectPolicy {
    pub(crate) fn operation_key(
        &self,
        namespace: &OperatorNamespace,
        operation: &LogicalOperationId,
    ) -> Result<[u8; 32], EffectBindingError> {
        self.validate()?;
        commitment(
            "auths.effect-replay-key/1",
            &canonical(&(
                namespace.as_str(),
                &self.partition,
                self.epoch,
                operation.as_str(),
            ))?,
        )
    }

    pub(crate) fn configuration_key(
        &self,
        namespace: &OperatorNamespace,
    ) -> Result<[u8; 32], EffectBindingError> {
        self.validate()?;
        commitment(
            "auths.effect-configuration-key/1",
            &canonical(&(namespace.as_str(), &self.partition, self.epoch))?,
        )
    }

    pub(crate) fn contains(&self, binding: &EffectBinding) -> bool {
        self.partition == binding.wire.partition && self.epoch == binding.wire.epoch
    }
    pub(crate) const fn approver(&self) -> &[u8; 32] {
        &self.approver
    }
    /// Constructs the operator's policy. Epoch changes require deliberate
    /// operator action; they must never be inferred from a missing journal.
    ///
    /// # Errors
    /// Refuses invalid partitions, epochs and weak or malformed approver keys.
    pub fn new(
        partition: String,
        epoch: u64,
        approver: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let policy = Self {
            schema: "auths.effect-policy/1".to_owned(),
            partition,
            epoch,
            approver,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), EffectBindingError> {
        if self.schema != "auths.effect-policy/1" {
            return Err(EffectBindingError::Unsupported);
        }
        if !label(&self.partition)
            || !(1..=MAX_SAFE_INTEGER).contains(&self.epoch)
            || VerifyingKey::from_bytes(&self.approver).map_or(true, |key| key.is_weak())
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    /// Reads a canonical operator policy, with a 4 KiB limit before decoding.
    ///
    /// # Errors
    /// Refuses obsolete, malformed, noncanonical or oversized policy files.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_POLICY_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        policy.validate()?;
        if policy.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(policy)
    }

    /// Canonical private operator configuration, suitable for installation.
    ///
    /// # Errors
    /// Refuses invalid policy data or an encoding failure.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        self.validate()?;
        canonical(self)
    }

    pub(crate) fn installation<'a>(
        &'a self,
        recipe: &'a CompiledRecipe,
        context: &'a TrustedContext,
        connection: &'a ConnectionRecord,
        qualification: QualificationPolicy,
        configuration: [u8; 32],
    ) -> EffectInstallation<'a> {
        EffectInstallation {
            recipe,
            context,
            connection,
            partition: &self.partition,
            epoch: self.epoch,
            qualification,
            configuration,
            approver: self.approver,
        }
    }
}

/// Post-verification driver oracle only. It deliberately does not establish
/// installed native authority, isolation or a real human review. Production
/// builds cannot construct this fixture or select it through an app request.
#[cfg(test)]
pub(crate) fn approve_driver_fixture(
    command: VerifiedCommand,
    recipe_digest: [u8; 32],
    now: u64,
    approval: Option<ExactEffectApproval>,
) -> Result<ApprovedEffect, GatewaySubmitResult> {
    approve_driver_with_plan(
        command,
        recipe_digest,
        now,
        approval,
        Prerequisites::oracle_empty(),
    )
}

#[cfg(any(test, feature = "testkit-harness"))]
pub(crate) fn approve_recipe_fixture(
    command: VerifiedCommand,
    recipe: &CompiledRecipe,
    account: [u8; 32],
    now: u64,
    approval: Option<ExactEffectApproval>,
) -> Result<ApprovedEffect, GatewaySubmitResult> {
    let prerequisites = Prerequisites::compile(recipe, &command, account)
        .map_err(|_| not_entered("test.effect.fixture-invalid"))?;
    approve_driver_with_plan(command, *recipe.digest(), now, approval, prerequisites)
}

#[cfg(any(test, feature = "testkit-harness"))]
fn approve_driver_with_plan(
    command: VerifiedCommand,
    recipe_digest: [u8; 32],
    now: u64,
    approval: Option<ExactEffectApproval>,
    prerequisites: Prerequisites,
) -> Result<ApprovedEffect, GatewaySubmitResult> {
    use auths_connections::{
        ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionState, ProviderKind, SemanticId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    let key = SigningKey::from_bytes(&[29; 32]);
    let public = key.verifying_key().to_bytes();
    let invalid = || not_entered("test.effect.fixture-invalid");
    let connection = ConnectionRecord::new(
        ProviderKind::parse("fixture").map_err(|_| invalid())?,
        ConnectionAlias::parse("driver").map_err(|_| invalid())?,
        ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").map_err(|_| invalid())?,
        SemanticId::parse("auths.gateway-operation/1").map_err(|_| invalid())?,
        SemanticId::parse("auths.gateway-connection-descriptor/1").map_err(|_| invalid())?,
        b"post-verification-driver-fixture".to_vec(),
        [4; 32],
        [5; 32],
        std::num::NonZeroU64::MIN,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![
            ConnectionProfile::new(SemanticId::parse("auths.mcp").map_err(|_| invalid())?, 2)
                .map_err(|_| invalid())?,
        ],
        now,
        now,
        None,
    )
    .map_err(|_| invalid())?;
    let mut binding = store_binding_fixture(
        &command.request,
        recipe_digest,
        command.native_authority,
        &fixture_policy().map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    binding.wire.protocol = Protocol::Mutation {
        request: request_commitment(&command.request, &prerequisites).map_err(|_| invalid())?,
    };
    binding = EffectBinding::new(binding.wire).map_err(|_| invalid())?;
    let effect = BoundEffect {
        review: serde_json::json!({"scope": "synthetic post-verification oracle; no human review claim"}),
        binding,
        command: CompiledEffect::Mutation(Box::new(VerifiedMutation {
            command,
            prerequisites,
        })),
        connection,
        proof: Zeroizing::new(Vec::new()),
        action: Zeroizing::new(Vec::new()),
    };
    if let Some(approval) = approval {
        return effect
            .approve(approval, &public, now)
            .map_err(|_| invalid());
    }
    let request = effect
        .approval_request(now, now.saturating_add(MAX_EFFECT_APPROVAL_SECONDS))
        .map_err(|_| invalid())?;
    let signature = key
        .sign(&request.signing_message().map_err(|_| invalid())?)
        .to_bytes();
    effect
        .approve(request.with_signature(signature), &public, now)
        .map_err(|_| invalid())
}

#[cfg(any(test, feature = "testkit-harness"))]
pub(crate) fn fixture_policy() -> Result<EffectPolicy, EffectBindingError> {
    EffectPolicy::new(
        "test-partition".to_owned(),
        1,
        ed25519_dalek::SigningKey::from_bytes(&[29; 32])
            .verifying_key()
            .to_bytes(),
    )
}

/// Store/driver reference data only; never an installed authorization path.
#[cfg(any(test, feature = "testkit-harness"))]
pub(crate) fn store_binding_fixture(
    request: &ClosedProviderRequest,
    recipe_digest: [u8; 32],
    native_authority: [u8; 32],
    policy: &EffectPolicy,
) -> Result<EffectBinding, EffectBindingError> {
    EffectBinding::new(BindingWire {
        schema: EFFECT_BINDING_SCHEMA.to_owned(),
        namespace: request.namespace().as_str().to_owned(),
        partition: policy.partition.clone(),
        epoch: policy.epoch,
        operation: request.operation_id().as_str().to_owned(),
        action: *request.action_commitment(),
        native_authority,
        scope: Scope::Unscoped,
        recipe: recipe_digest,
        compiler: COMPILER.to_owned(),
        connection: [0; 32],
        credential_generation: 1,
        qualification_policy: "optional".to_owned(),
        configuration: [0; 32],
        approval_policy: ApprovalPolicy::Exact {
            approver: policy.approver,
        },
        reservations: Vec::new(),
        protocol: Protocol::Mutation {
            request: request_commitment(request, &Prerequisites::oracle_empty())?,
        },
    })
}

/// Signs synthetic store oracle data with the fixed test-only approver.
#[cfg(test)]
pub(crate) fn approval_fixture(
    binding: &EffectBinding,
    now: u64,
) -> Result<ExactEffectApproval, EffectBindingError> {
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
    let request = EffectApprovalRequest {
        schema: APPROVAL_SCHEMA.to_owned(),
        effect: *binding.id().as_bytes(),
        approver: key.verifying_key().to_bytes(),
        not_before: now,
        expires_at: now
            .checked_add(MAX_EFFECT_APPROVAL_SECONDS)
            .ok_or(EffectBindingError::Invalid)?,
    };
    let signature = key.sign(&request.signing_message()?).to_bytes();
    Ok(request.with_signature(signature))
}

/// Private audit identity. Do not publish it as a hiding content commitment.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EffectId([u8; 32]);

impl EffectId {
    /// Returns private identity bytes for approval and protected journal use.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EffectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectId([private])")
    }
}

/// Failure contains neither private content nor caller-supplied text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectBindingError {
    /// Empty, oversized, malformed, noncanonical or internally invalid data.
    #[error("invalid effect binding")]
    Invalid,
    /// The schema or compiler semantics are unsupported.
    #[error("unsupported effect binding version")]
    Unsupported,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Scope {
    Unscoped,
    Task { commitment: [u8; 32] },
}

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Unit {
    MutationCount,
    MutationSum,
    AcquisitionCount,
    ResponseBytes,
    DisclosureBytes,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    key: [u8; 32],
    unit: Unit,
    amount: u64,
    ceiling: u64,
    window: ReservationWindow,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ReservationWindow {
    Fixed { index: u64, seconds: u64 },
    SourceLifetime,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Protocol {
    Mutation {
        request: [u8; 32],
    },
    Acquisition {
        request: [u8; 32],
        projection: [u8; 32],
        maximum_response_bytes: u64,
    },
    Disclosure {
        source_effect: [u8; 32],
        protected_content: [u8; 32],
        recipient: String,
        channel: [u8; 32],
        delivery_instance: [u8; 32],
        projection: [u8; 32],
        maximum_bytes: u64,
    },
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ApprovalPolicy {
    Exact { approver: [u8; 32] },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    schema: String,
    namespace: String,
    partition: String,
    epoch: u64,
    operation: String,
    action: [u8; 32],
    native_authority: [u8; 32],
    scope: Scope,
    recipe: [u8; 32],
    compiler: String,
    connection: [u8; 32],
    credential_generation: u64,
    qualification_policy: String,
    configuration: [u8; 32],
    approval_policy: ApprovalPolicy,
    reservations: Vec<Reservation>,
    protocol: Protocol,
}

/// Immutable validated private binding. Its canonical form is native JCS JSON;
/// all integer fields are bounded to the exact JSON integer range. Decoding is
/// data validation only and cannot manufacture a sealed effect or send permit.
#[derive(Clone, Eq, PartialEq)]
pub struct EffectBinding {
    wire: BindingWire,
    id: EffectId,
}

impl fmt::Debug for EffectBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectBinding { private: [redacted] }")
    }
}

fn commitment(domain: &str, bytes: &[u8]) -> Result<[u8; 32], EffectBindingError> {
    auths_codec::domain_commitment(domain, bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| EffectBindingError::Invalid)
}

fn canonical<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
    let bytes = Zeroizing::new(
        serde_json_canonicalizer::to_vec(value).map_err(|_| EffectBindingError::Invalid)?,
    );
    if bytes.len() > MAX_EFFECT_BYTES {
        return Err(EffectBindingError::Invalid);
    }
    Ok(bytes)
}

impl EffectBinding {
    /// Decode-time membership only; fresh window and durable slot checks belong
    /// to the entry fence. Each native policy counter must appear exactly once.
    pub(crate) fn matches_acquisition_counters(
        &self,
        counts: &[[u8; 32]],
        sums: &[[u8; 32]],
    ) -> bool {
        if !matches!(self.wire.protocol, Protocol::Acquisition { .. }) {
            return false;
        }
        let fixed: Vec<_> = self
            .wire
            .reservations
            .iter()
            .filter(|entry| matches!(entry.window, ReservationWindow::Fixed { .. }))
            .collect();
        fixed.len() == counts.len() + sums.len()
            && fixed.iter().all(|entry| {
                let keys = match entry.unit {
                    Unit::AcquisitionCount => counts,
                    Unit::ResponseBytes => sums,
                    _ => return false,
                };
                keys.iter().filter(|key| **key == entry.key).count() == 1
            })
    }

    pub(crate) fn is_mutation(&self) -> bool {
        matches!(self.wire.protocol, Protocol::Mutation { .. })
    }

    pub(crate) fn journal_identity(&self) -> (&str, &str, &[u8; 32], &[u8; 32]) {
        (
            &self.wire.namespace,
            &self.wire.operation,
            &self.wire.action,
            &self.wire.recipe,
        )
    }

    pub(crate) fn validate_recorded_approval(
        &self,
        approval: &ExactEffectApproval,
        at: u64,
    ) -> Result<(), EffectBindingError> {
        let ApprovalPolicy::Exact { approver } = self.wire.approval_policy;
        approval.verify(self.id(), &approver, at)
    }
    fn new(wire: BindingWire) -> Result<Self, EffectBindingError> {
        validate(&wire)?;
        let bytes = canonical(&wire)?;
        let id = EffectId(commitment(EFFECT_BINDING_SCHEMA, &bytes)?);
        Ok(Self { wire, id })
    }

    /// Decodes a canonical binding, rejecting duplicate/unknown fields and
    /// alternate encodings. The total byte limit is checked before allocation.
    ///
    /// # Errors
    /// Returns a closed invalid/unsupported error; never echoes input.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let wire: BindingWire =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        let binding = Self::new(wire)?;
        if binding.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(binding)
    }

    /// Encodes private audit data. The returned buffer is erased on drop.
    /// This is not a public receipt or an executable capability.
    ///
    /// # Errors
    /// Returns `Invalid` if the canonical representation cannot be produced.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        canonical(&self.wire)
    }

    /// Identity approved and compared within the protected boundary.
    #[must_use]
    pub const fn id(&self) -> EffectId {
        self.id
    }

    /// Whether both bindings name the same logical replay key. A true result
    /// with different identities is a conflict, never a new operation.
    #[must_use]
    pub fn same_operation(&self, other: &Self) -> bool {
        self.wire.namespace == other.wire.namespace
            && self.wire.partition == other.wire.partition
            && self.wire.epoch == other.wire.epoch
            && self.wire.operation == other.wire.operation
    }
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn validate(wire: &BindingWire) -> Result<(), EffectBindingError> {
    if wire.schema != EFFECT_BINDING_SCHEMA || wire.compiler != COMPILER {
        return Err(EffectBindingError::Unsupported);
    }
    if OperatorNamespace::parse(&wire.namespace).is_err()
        || LogicalOperationId::parse(&wire.operation).is_err()
        || !label(&wire.partition)
        || !(1..=MAX_SAFE_INTEGER).contains(&wire.epoch)
        || !(1..=MAX_SAFE_INTEGER).contains(&wire.credential_generation)
        || !matches!(wire.qualification_policy.as_str(), "required" | "optional")
        || wire.reservations.len() > MAX_EFFECT_RESERVATIONS
    {
        return Err(EffectBindingError::Invalid);
    }
    let ApprovalPolicy::Exact { approver } = wire.approval_policy;
    if VerifyingKey::from_bytes(&approver).map_or(true, |key| key.is_weak()) {
        return Err(EffectBindingError::Invalid);
    }
    let mut previous = None;
    for reservation in &wire.reservations {
        let key = (reservation.key, reservation.unit);
        if previous.is_some_and(|previous| previous >= key)
            || reservation.ceiling == 0
            || reservation.amount > reservation.ceiling
            || reservation.ceiling > MAX_SAFE_INTEGER
            || match reservation.window {
                ReservationWindow::Fixed { index, seconds } => {
                    index > MAX_SAFE_INTEGER || !(1..=crate::MAX_WINDOW_SECONDS).contains(&seconds)
                }
                ReservationWindow::SourceLifetime => {
                    matches!(wire.protocol, Protocol::Mutation { .. })
                }
            }
        {
            return Err(EffectBindingError::Invalid);
        }
        let unit_allowed = match &wire.protocol {
            Protocol::Mutation { .. } => {
                matches!(reservation.unit, Unit::MutationCount | Unit::MutationSum)
            }
            Protocol::Acquisition { .. } => matches!(
                reservation.unit,
                Unit::AcquisitionCount | Unit::ResponseBytes
            ),
            Protocol::Disclosure { .. } => reservation.unit == Unit::DisclosureBytes,
        };
        if !unit_allowed
            || (matches!(
                reservation.unit,
                Unit::MutationCount | Unit::AcquisitionCount
            ) && reservation.amount != 1)
        {
            return Err(EffectBindingError::Invalid);
        }
        previous = Some(key);
    }
    match &wire.protocol {
        Protocol::Mutation { .. } => {}
        Protocol::Acquisition {
            maximum_response_bytes,
            ..
        } => {
            if !(1..=65_536).contains(maximum_response_bytes) {
                return Err(EffectBindingError::Invalid);
            }
        }
        Protocol::Disclosure {
            recipient,
            maximum_bytes,
            ..
        } => {
            if !label(recipient) || *maximum_bytes > 65_536 {
                return Err(EffectBindingError::Invalid);
            }
        }
    }
    Ok(())
}

/// Closed protocol-specific compiler output. Neither alternative is transport
/// authority, and a mutation-only admission path must refuse an acquisition.
enum CompiledEffect {
    Mutation(Box<VerifiedMutation>),
    Acquisition(Box<acquisition::VerifiedAcquisition>),
}

struct VerifiedMutation {
    command: VerifiedCommand,
    prerequisites: Prerequisites,
}

/// Sealed native compilation result. It owns both the private binding and the
/// exact immutable compiler output. There is no public constructor, clone or
/// deserializer. Compiling this value does not approve it or grant entry.
pub struct BoundEffect {
    review: serde_json::Value,
    binding: EffectBinding,
    command: CompiledEffect,
    connection: ConnectionRecord,
    proof: Zeroizing<Vec<u8>>,
    action: Zeroizing<Vec<u8>>,
}

/// Human review produced entirely by native code from the sealed effect.
/// It includes private request content and must travel only on the authorized
/// review channel. It is not suitable for public receipts or support logs.
#[cfg(unix)]
#[derive(Serialize)]
pub struct PrivateEffectReview {
    schema: &'static str,
    effect_id_hex: String,
    binding_canonical: String,
    binding: BindingWire,
    installation: serde_json::Value,
    native: serde_json::Value,
    semantic: serde_json::Value,
    renderer: &'static str,
}

#[cfg(unix)]
impl fmt::Debug for PrivateEffectReview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateEffectReview { private: [redacted] }")
    }
}

#[cfg(unix)]
impl PrivateEffectReview {
    /// Renders complete private review as literal ASCII JSON. Non-ASCII and
    /// control characters remain escaped data, including bidi controls. A
    /// caller may not substitute a renderer that truncates or interprets markup.
    ///
    /// # Errors
    /// Refuses unsupported renderers, encoding failures or output above 1 MiB.
    pub fn render_literal(&self, renderer: &str) -> Result<Zeroizing<String>, EffectBindingError> {
        use std::fmt::Write as _;
        if renderer != self.renderer {
            return Err(EffectBindingError::Unsupported);
        }
        self.to_private_bytes()?;
        let json = Zeroizing::new(
            serde_json::to_string_pretty(self).map_err(|_| EffectBindingError::Invalid)?,
        );
        let mut rendered = Zeroizing::new(String::new());
        for character in json.chars() {
            if character.is_ascii() {
                rendered.push(character);
            } else {
                let mut units = [0; 2];
                for unit in character.encode_utf16(&mut units) {
                    write!(rendered, "\\u{unit:04x}").map_err(|_| EffectBindingError::Invalid)?;
                }
            }
            if rendered.len() > 1_048_576 {
                return Err(EffectBindingError::Invalid);
            }
        }
        Ok(rendered)
    }

    /// Encodes machine-readable private review without reconstructing identity,
    /// provider bytes or authority facts. Use `render_literal` for human display.
    ///
    /// # Errors
    /// Refuses an encoding failure or a review above the fixed byte limit.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        let bytes = Zeroizing::new(
            serde_json_canonicalizer::to_vec(self).map_err(|_| EffectBindingError::Invalid)?,
        );
        if bytes.len() > MAX_PRIVATE_EFFECT_REVIEW_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        Ok(bytes)
    }
}

impl fmt::Debug for BoundEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundEffect { private: [redacted] }")
    }
}

impl BoundEffect {
    /// Returns immutable audit/approval data, never entry authority.
    #[must_use]
    pub const fn binding(&self) -> &EffectBinding {
        &self.binding
    }

    /// Returns the exact noncredential mutation request for private review,
    /// or `None` for acquisition. This may contain private content; do not log it.
    /// Use the shared private review to render either protocol completely.
    #[must_use]
    pub fn private_request(&self) -> Option<&ClosedProviderRequest> {
        match &self.command {
            CompiledEffect::Mutation(mutation) => Some(&mutation.command.request),
            CompiledEffect::Acquisition(_) => None,
        }
    }

    /// Renders the exact immutable effect reviewed before human approval.
    /// This never reads a provider, leases credentials or reserves capacity.
    ///
    /// # Errors
    /// Returns a closed projection/encoding refusal without private input.
    #[cfg(unix)]
    pub fn private_review(&self) -> Result<PrivateEffectReview, GatewaySubmitResult> {
        let binding = self
            .binding
            .to_private_bytes()
            .map_err(|_| not_entered("gateway.effect.invalid-binding"))?;
        let binding_canonical = std::str::from_utf8(&binding)
            .map_err(|_| not_entered("gateway.effect.invalid-binding"))?
            .to_owned();
        Ok(PrivateEffectReview {
            schema: "auths.private-effect-review/2",
            renderer: LITERAL_REVIEW_RENDERER,
            binding: self.binding.wire.clone(),
            installation: serde_json::json!({
                "provider": self.connection.provider_kind().as_str(),
                "alias": self.connection.alias().as_str(),
                "connection_id": self.connection.connection_id().as_str(),
                "credential_generation": self.connection.credential_generation().get(),
                "connection_contract": self.connection.contract().as_str(),
            }),
            semantic: match &self.command {
                CompiledEffect::Mutation(mutation) => {
                    let mut review = self.review.clone();
                    review["prerequisite_acquisitions"] =
                        serde_json::to_value(&mutation.prerequisites)
                            .map_err(|_| not_entered("gateway.effect.invalid-binding"))?;
                    review
                }
                CompiledEffect::Acquisition(command) => {
                    let mut review = self.review.clone();
                    review["prerequisite_acquisitions"] =
                        serde_json::to_value(&command.prerequisites)
                            .map_err(|_| not_entered("gateway.effect.invalid-binding"))?;
                    review
                }
            },
            effect_id_hex: hex::encode(self.binding.id().as_bytes()),
            binding_canonical,
            native: match &self.command {
                CompiledEffect::Mutation(mutation) => {
                    serde_json::to_value(crate::engine::review_command(&mutation.command)?)
                        .map_err(|_| not_entered("gateway.effect.invalid-binding"))?
                }
                CompiledEffect::Acquisition(command) => command.private_review(),
            },
        })
    }

    /// Constructs the exact private review statement for an installed human
    /// approver. Its signature is deliberately excluded from effect identity.
    ///
    /// # Errors
    /// Refuses an invalid key, time range or approval lifetime.
    pub fn approval_request(
        &self,
        not_before: u64,
        expires_at: u64,
    ) -> Result<EffectApprovalRequest, EffectBindingError> {
        let ApprovalPolicy::Exact { approver } = self.binding.wire.approval_policy;
        let request = EffectApprovalRequest {
            schema: APPROVAL_SCHEMA.to_owned(),
            effect: *self.binding.id().as_bytes(),
            approver,
            not_before,
            expires_at,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates exact approval separately from native resource authority.
    /// The approver key comes from installed human policy, never the envelope.
    /// This effect remains non-executable until fresh transactional admission.
    ///
    /// # Errors
    /// Refuses changed identity, untrusted signer, invalid signature or time.
    pub fn approve(
        self,
        approval: ExactEffectApproval,
        installed_approver: &[u8; 32],
        now: u64,
    ) -> Result<ApprovedEffect, EffectBindingError> {
        if self.binding.wire.approval_policy
            != (ApprovalPolicy::Exact {
                approver: *installed_approver,
            })
        {
            return Err(EffectBindingError::Invalid);
        }
        approval.verify(self.binding.id(), installed_approver, now)?;
        Ok(ApprovedEffect {
            effect: self,
            approval,
        })
    }
}

/// Native exact-effect approval statement. Signing this private projection
/// approves no other operation, installation, request or recipient. It does not
/// supply resource authority. Debug deliberately omits the effect commitment.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectApprovalRequest {
    schema: String,
    effect: [u8; 32],
    approver: [u8; 32],
    not_before: u64,
    expires_at: u64,
}

impl fmt::Debug for EffectApprovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectApprovalRequest { private: [redacted] }")
    }
}

impl EffectApprovalRequest {
    /// Canonical private signing request for an external human signer.
    ///
    /// # Errors
    /// Refuses invalid/obsolete request data or encoding failure.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        self.validate()?;
        canonical(self)
    }

    /// Reads bounded canonical signing data; this grants no authority.
    ///
    /// # Errors
    /// Refuses malformed, duplicate, noncanonical, obsolete or oversized input.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_APPROVAL_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        if request.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(request)
    }

    fn validate(&self) -> Result<(), EffectBindingError> {
        if self.schema != APPROVAL_SCHEMA {
            return Err(EffectBindingError::Unsupported);
        }
        let key =
            VerifyingKey::from_bytes(&self.approver).map_err(|_| EffectBindingError::Invalid)?;
        if key.is_weak()
            || self.expires_at > MAX_SAFE_INTEGER
            || self.expires_at <= self.not_before
            || self.expires_at - self.not_before > MAX_EFFECT_APPROVAL_SECONDS
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    /// Returns the native domain-separated 32-byte message to sign using
    /// Ed25519. Callers must display the associated bound effect before signing;
    /// a signature does not prove that a human actually inspected the display.
    ///
    /// # Errors
    /// Refuses invalid statement fields or unsupported semantics.
    pub fn signing_message(&self) -> Result<[u8; 32], EffectBindingError> {
        self.validate()?;
        commitment(APPROVAL_SCHEMA, &canonical(self)?)
    }

    /// Attaches signature bytes without claiming their validity. Validation
    /// happens when the bound effect is approved against installed policy.
    #[must_use]
    pub fn with_signature(self, signature: [u8; 64]) -> ExactEffectApproval {
        ExactEffectApproval {
            request: self,
            signature_b64: Base64UrlUnpadded::encode_string(&signature),
        }
    }
}

/// Portable approval evidence, not a send token. Replaying this evidence can
/// never recreate a durable entry permit. Only exact approval is supported by
/// this type; bounded acquisition consent will use its own typed contract.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactEffectApproval {
    request: EffectApprovalRequest,
    signature_b64: String,
}

impl fmt::Debug for ExactEffectApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactEffectApproval { private: [redacted] }")
    }
}

impl ExactEffectApproval {
    /// Decodes exact canonical approval data within the fixed byte limit.
    ///
    /// # Errors
    /// Refuses malformed/duplicate/noncanonical/oversized evidence. Successful
    /// decoding does not authenticate the signer or establish authorization.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_APPROVAL_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let approval: Self =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        approval.request.validate()?;
        approval.signature()?;
        if approval.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(approval)
    }

    /// Encodes private approval evidence for the protected channel/journal.
    ///
    /// # Errors
    /// Refuses an oversized or unencodable envelope.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        let bytes = canonical(self)?;
        if bytes.len() > MAX_EFFECT_APPROVAL_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        Ok(bytes)
    }

    fn signature(&self) -> Result<Signature, EffectBindingError> {
        let mut bytes = [0_u8; 64];
        let decoded = Base64UrlUnpadded::decode(&self.signature_b64, &mut bytes)
            .map_err(|_| EffectBindingError::Invalid)?;
        if decoded.len() != 64 || Base64UrlUnpadded::encode_string(decoded) != self.signature_b64 {
            return Err(EffectBindingError::Invalid);
        }
        Ok(Signature::from_bytes(&bytes))
    }

    fn verify(
        &self,
        effect: EffectId,
        installed: &[u8; 32],
        now: u64,
    ) -> Result<(), EffectBindingError> {
        self.request.validate()?;
        if self.request.effect != *effect.as_bytes()
            || self.request.approver != *installed
            || now < self.request.not_before
            || now >= self.request.expires_at
        {
            return Err(EffectBindingError::Invalid);
        }
        VerifyingKey::from_bytes(installed)
            .map_err(|_| EffectBindingError::Invalid)?
            .verify_strict(&self.request.signing_message()?, &self.signature()?)
            .map_err(|_| EffectBindingError::Invalid)
    }
}

/// Native authority and human approval are separate sealed facts. This stage
/// is neither cloneable nor deserializable and still grants no external entry.
pub struct ApprovedEffect {
    effect: BoundEffect,
    approval: ExactEffectApproval,
}

impl ApprovedEffect {
    pub(crate) fn approval(&self) -> &ExactEffectApproval {
        &self.approval
    }
    pub(crate) fn command(&self) -> Option<&VerifiedCommand> {
        match &self.effect.command {
            CompiledEffect::Mutation(mutation) => Some(&mutation.command),
            CompiledEffect::Acquisition(_) => None,
        }
    }

    pub(crate) fn recovery_target(&self) -> Option<&RecoveryReadTarget> {
        match &self.effect.command {
            CompiledEffect::Mutation(_) => None,
            CompiledEffect::Acquisition(command) => match &command.target {
                acquisition::AcquisitionTarget::Recovery(target) => Some(target),
                acquisition::AcquisitionTarget::Candidate(_) => None,
            },
        }
    }

    pub(crate) fn recovery_bound(&self) -> Option<&crate::bounds::BoundAdmission> {
        match &self.effect.command {
            CompiledEffect::Mutation(_) => None,
            CompiledEffect::Acquisition(command) => command.bound.as_ref(),
        }
    }

    pub(crate) fn recovery_plan(&self) -> Result<RecoveryPlan, EffectBindingError> {
        match &self.effect.command {
            CompiledEffect::Acquisition(command) => command.journal_plan(),
            CompiledEffect::Mutation(_) => Err(EffectBindingError::Invalid),
        }
    }

    fn prerequisites(&self) -> &Prerequisites {
        match &self.effect.command {
            CompiledEffect::Mutation(command) => &command.prerequisites,
            CompiledEffect::Acquisition(command) => &command.prerequisites,
        }
    }

    pub(crate) fn prerequisite_plans(&self) -> Result<Vec<PrerequisitePlan>, EffectBindingError> {
        self.prerequisites()
            .kinds()
            .map(|kind| self.prerequisite(kind).map(|(plan, _)| plan))
            .collect()
    }

    pub(crate) fn prerequisite(
        &self,
        kind: PrerequisiteKind,
    ) -> Result<(PrerequisitePlan, ClosedPrerequisiteRead), EffectBindingError> {
        let (index, read) = self.prerequisites().select(kind)?;
        let transport = match &self.effect.command {
            CompiledEffect::Mutation(mutation) => {
                request_bytes(&mutation.command.request, &mutation.prerequisites)?
            }
            CompiledEffect::Acquisition(command) => command.request_bytes()?,
        };
        let plan = PrerequisitePlan::new(self.effect.binding(), index, transport)?;
        Ok((plan, read.clone()))
    }

    pub(crate) fn connection(&self) -> &ConnectionRecord {
        &self.effect.connection
    }
    /// Immutable effect reviewed by the approver.
    #[must_use]
    pub const fn effect(&self) -> &BoundEffect {
        &self.effect
    }

    /// Rechecks the original signed statement at a transaction's sampled time.
    /// This never changes or extends its signed validity interval.
    ///
    /// # Errors
    /// Refuses expired approval or a changed installed approver policy.
    pub fn validate_approval(
        &self,
        installed_approver: &[u8; 32],
        now: u64,
    ) -> Result<(), EffectBindingError> {
        self.approval
            .verify(self.effect.binding.id(), installed_approver, now)
    }

    /// Re-runs the full native verifier on this effect's retained original
    /// proof/action and recompiles against current installation inputs. Every
    /// selected branch, evidence dependency, request and charge must still
    /// produce the original binding. This is the semantic check the admission
    /// transaction must call after acquiring its lock and sampling time; calling
    /// it earlier alone does not fence revocation or configuration changes.
    ///
    /// # Errors
    /// Returns native refusal, changed binding or expired/untrusted approval.
    pub fn validate_for_entry(
        &self,
        installed: &EffectInstallation<'_>,
        now: u64,
    ) -> Result<(), GatewaySubmitResult> {
        self.validate_approval(&installed.approver, now)
            .map_err(|_| not_entered("gateway.effect.approval"))?;
        let fresh = match &self.effect.command {
            CompiledEffect::Mutation(_) => {
                compile_mutation_effect(installed, now, &self.effect.proof, &self.effect.action)?
            }
            CompiledEffect::Acquisition(command) => match &command.target {
                acquisition::AcquisitionTarget::Recovery(target) => compile_recovery_acquisition(
                    installed,
                    target,
                    now,
                    &self.effect.proof,
                    &self.effect.action,
                )?,
                acquisition::AcquisitionTarget::Candidate(target) => compile_candidate_credential(
                    installed,
                    target,
                    now,
                    &self.effect.proof,
                    &self.effect.action,
                )?,
            },
        };
        if fresh.binding != self.effect.binding {
            return Err(not_entered("gateway.effect.binding-changed"));
        }
        Ok(())
    }
}

/// Pinned deployment inputs for effect-free compilation. The caller must be
/// the installation boundary, not an untrusted application request. Epoch is
/// the admission partition epoch, independent of credential/config generations.
pub struct EffectInstallation<'a> {
    /// Reviewed, installed recipe.
    pub recipe: &'a CompiledRecipe,
    /// Installed native trust and configuration.
    pub context: &'a TrustedContext,
    /// Current operator-approved connection; no secret bytes are copied.
    pub connection: &'a ConnectionRecord,
    /// Stable admission partition within the operator namespace.
    pub partition: &'a str,
    /// Independently commissioned partition epoch.
    pub epoch: u64,
    /// Installed recipe qualification requirement.
    pub qualification: QualificationPolicy,
    /// Exact native commitment to the operator's shared installed configuration.
    pub configuration: [u8; 32],
    /// Exact human approver key pinned independently by installation policy.
    pub approver: [u8; 32],
}

/// Verifies natively and compiles one mutation into an immutable bound effect.
/// No I/O, reservation, approval, credential acquisition or entry is performed.
/// `now` is the caller's explicit evaluation input, not an authenticated event.
///
/// # Errors
/// Returns native/profile refusals or a closed installation/binding refusal.
pub fn compile_mutation_effect(
    installed: &EffectInstallation<'_>,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    GatewayConnectionDescriptor::from_record(installed.connection, installed.recipe)
        .map_err(|_| not_entered("gateway.effect.installation"))?;
    let command = verify_detailed(installed.recipe, installed.context, now, proof, action)?;
    bind_mutation(installed, command, proof, action)
        .map_err(|_| not_entered("gateway.effect.invalid-binding"))
}

fn managed_reservations(
    bound: Option<&crate::bounds::BoundAdmission>,
    count_unit: Unit,
    sum_unit: Unit,
) -> Vec<Reservation> {
    let mut reservations = Vec::new();
    if let Some(bound) = bound {
        for count in &bound.counts {
            reservations.push(Reservation {
                key: count.key,
                unit: count_unit,
                amount: 1,
                ceiling: count.capacity,
                window: ReservationWindow::Fixed {
                    index: bound.window_index,
                    seconds: bound.window_seconds,
                },
            });
        }
        for sum in &bound.sums {
            reservations.push(Reservation {
                key: sum.key,
                unit: sum_unit,
                amount: bound.argument,
                ceiling: sum.capacity,
                window: ReservationWindow::Fixed {
                    index: bound.window_index,
                    seconds: bound.window_seconds,
                },
            });
        }
    }
    reservations.sort_by_key(|entry| (entry.key, entry.unit));
    reservations
}

fn bind_mutation(
    installed: &EffectInstallation<'_>,
    command: VerifiedCommand,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, EffectBindingError> {
    let request = &command.request;
    let prerequisites = Prerequisites::compile(
        installed.recipe,
        &command,
        *installed.connection.account_commitment(),
    )?;
    let reservations = managed_reservations(
        command.bound.as_ref(),
        Unit::MutationCount,
        Unit::MutationSum,
    );
    let connection = Zeroizing::new(
        installed
            .connection
            .to_canonical_cbor()
            .map_err(|_| EffectBindingError::Invalid)?,
    );
    let binding = EffectBinding::new(BindingWire {
        schema: EFFECT_BINDING_SCHEMA.to_owned(),
        namespace: request.namespace().as_str().to_owned(),
        partition: installed.partition.to_owned(),
        epoch: installed.epoch,
        operation: request.operation_id().as_str().to_owned(),
        action: *request.action_commitment(),
        native_authority: command.native_authority,
        scope: Scope::Unscoped,
        recipe: *installed.recipe.digest(),
        compiler: COMPILER.to_owned(),
        connection: commitment("auths.effect-installation/1", &connection)?,
        credential_generation: installed.connection.credential_generation().get(),
        qualification_policy: installed.qualification.as_str().to_owned(),
        configuration: installed.configuration,
        approval_policy: ApprovalPolicy::Exact {
            approver: installed.approver,
        },
        reservations,
        protocol: Protocol::Mutation {
            request: request_commitment(request, &prerequisites)?,
        },
    })?;
    let review = serde_json::json!({
        "contract": installed.recipe.effect_review(&command.arguments).map_err(|_| EffectBindingError::Invalid)?,
        "recipe": installed.recipe.review_document(),
        "uncertainty": "Approval does not establish provider entry or outcome. Unknown outcomes do not authorize blind retry or refund.",
    });
    let effect = BoundEffect {
        review,
        binding,
        command: CompiledEffect::Mutation(Box::new(VerifiedMutation {
            command,
            prerequisites,
        })),
        connection: installed.connection.clone(),
        proof: Zeroizing::new(proof.to_vec()),
        action: Zeroizing::new(action.to_vec()),
    };
    #[cfg(unix)]
    effect
        .private_review()
        .map_err(|_| EffectBindingError::Invalid)?
        .to_private_bytes()?;
    Ok(effect)
}

/// Preserve all selected branches and evidence through the existing native
/// codec. Evaluation time and work counters are not authority identities: the
/// full verifier is rerun at a new time, without changing signed event times.
pub(crate) fn native_authority_commitment(
    result: &PortableVerificationResult,
    context: &TrustedContext,
) -> Result<[u8; 32], EffectBindingError> {
    let normalized = context
        .for_request(
            context.expected_audience().clone(),
            context.expected_challenge(),
            Timestamp::new(0),
        )
        .map_err(|_| EffectBindingError::Invalid)?;
    let context_digest =
        auths_codec::context_digest(&normalized).map_err(|_| EffectBindingError::Invalid)?;
    let projection = PortableVerificationResult::new(
        result.decision(),
        result.stage(),
        result.code(),
        result.proof_digest(),
        result.action_digest(),
        context_digest,
        result.plan_id(),
        result.authorized_branches().to_vec(),
        result.assurance().to_vec(),
        result.assurance_satisfactions().to_vec(),
        VerificationResources::new(0, 0, 0, 0, 0, 0, 0),
        result.registry_manifest(),
        result.required_configuration(),
        result.local_configuration(),
    )
    .with_observation_satisfactions(result.observation_satisfactions().to_vec())
    .with_approval_satisfactions(result.approval_satisfactions().to_vec());
    let bytes = Zeroizing::new(
        auths_codec::encode_verification_result(&projection)
            .map_err(|_| EffectBindingError::Invalid)?,
    );
    commitment("auths.effect-native-authority/1", &bytes)
}

#[derive(Serialize)]
struct ReadWire<'a> {
    url: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    maximum_response_bytes: usize,
}

#[derive(Serialize)]
struct RequestWire<'a> {
    method: &'a str,
    url: &'a str,
    media_type: &'a str,
    body: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    credential: &'a crate::CredentialRequirement,
    idempotency: Option<&'a str>,
    echo: Option<&'a str>,
    observation: Option<&'a ObservationTemplate>,
    prerequisite_acquisitions: &'a Prerequisites,
}

fn request_commitment(
    request: &ClosedProviderRequest,
    prerequisites: &Prerequisites,
) -> Result<[u8; 32], EffectBindingError> {
    commitment(
        "auths.effect-transport/1",
        &request_bytes(request, prerequisites)?,
    )
}

fn request_bytes(
    request: &ClosedProviderRequest,
    prerequisites: &Prerequisites,
) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
    let wire = RequestWire {
        method: request.method().as_str(),
        url: request.url(),
        media_type: request.content_type(),
        body: std::str::from_utf8(request.body()).map_err(|_| EffectBindingError::Invalid)?,
        headers: request
            .headers()
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect(),
        credential: request.credential_requirement(),
        idempotency: request.idempotency_key(),
        echo: request.echo_token(),
        observation: request.observation_template(),
        prerequisite_acquisitions: prerequisites,
    };
    canonical(&wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn installed_policy_is_canonical_bounded_and_never_defaults_authority() {
        let public = SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes();
        let policy = EffectPolicy::new("partition".to_owned(), 1, public).expect("policy");
        let encoded = policy.to_private_bytes().expect("canonical policy");
        assert_eq!(
            EffectPolicy::from_private_bytes(&encoded).expect("policy"),
            policy
        );
        assert!(EffectPolicy::new(String::new(), 1, public).is_err());
        assert!(EffectPolicy::new("p".repeat(513), 1, public).is_err());
        assert!(EffectPolicy::new("partition".to_owned(), 0, public).is_err());
        assert!(EffectPolicy::new("partition".to_owned(), MAX_SAFE_INTEGER + 1, public).is_err());
        assert!(EffectPolicy::new("partition".to_owned(), 1, [0; 32]).is_err());
        assert!(EffectPolicy::from_private_bytes(&vec![b' '; 4_097]).is_err());
        let mut spaced = encoded.to_vec();
        spaced.push(b'\n');
        assert!(EffectPolicy::from_private_bytes(&spaced).is_err());
        let mut duplicate = encoded.to_vec();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"epoch\":1}");
        assert!(EffectPolicy::from_private_bytes(&duplicate).is_err());
        for field in ["schema", "partition", "epoch", "approver"] {
            let mut omitted = serde_json::to_value(&policy).expect("value");
            omitted.as_object_mut().expect("object").remove(field);
            assert!(EffectPolicy::from_private_bytes(&canonical(&omitted).expect("JSON")).is_err());
        }
        let mut obsolete = serde_json::to_value(&policy).expect("value");
        obsolete["schema"] = serde_json::json!("auths.effect-policy/0");
        assert_eq!(
            EffectPolicy::from_private_bytes(&canonical(&obsolete).expect("JSON")),
            Err(EffectBindingError::Unsupported)
        );
    }

    fn wire() -> BindingWire {
        BindingWire {
            schema: EFFECT_BINDING_SCHEMA.to_owned(),
            namespace: "synthetic".to_owned(),
            partition: "private-synthetic-partition".to_owned(),
            epoch: 1,
            operation: "operation-1".to_owned(),
            action: [1; 32],
            native_authority: [2; 32],
            scope: Scope::Unscoped,
            recipe: [3; 32],
            compiler: COMPILER.to_owned(),
            connection: [4; 32],
            credential_generation: 1,
            qualification_policy: "required".to_owned(),
            configuration: [12; 32],
            approval_policy: ApprovalPolicy::Exact {
                approver: SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes(),
            },
            reservations: vec![Reservation {
                key: [5; 32],
                unit: Unit::MutationCount,
                amount: 1,
                ceiling: 2,
                window: ReservationWindow::Fixed {
                    index: 0,
                    seconds: 60,
                },
            }],
            protocol: Protocol::Mutation { request: [6; 32] },
        }
    }

    #[test]
    fn canonical_roundtrip_is_data_only_and_debug_is_private() {
        let binding = EffectBinding::new(wire()).expect("binding");
        let bytes = binding.to_private_bytes().expect("encode");
        assert_eq!(
            EffectBinding::from_private_bytes(&bytes).expect("decode"),
            binding
        );
        let printed = format!("{binding:?} {:?}", binding.id());
        assert!(!printed.contains("private-synthetic-partition"));
        assert!(!printed.contains(&hex::encode(binding.id().as_bytes())));
    }

    #[test]
    fn reject_alternate_encodings_duplicates_and_unknown_versions() {
        let binding = EffectBinding::new(wire()).expect("binding");
        let bytes = binding.to_private_bytes().expect("encode");
        let mut padded = bytes.to_vec();
        padded.push(b' ');
        assert_eq!(
            EffectBinding::from_private_bytes(&padded),
            Err(EffectBindingError::Invalid)
        );
        let text = std::str::from_utf8(&bytes).expect("json");
        for invalid in [
            text.replacen("{", "{\"epoch\":1,", 1),
            text.replacen("{", "{\"unknown\":1,", 1),
            text.replace("\"epoch\":1", "\"epoch\":1.0"),
            text.replace("\"epoch\":1", "\"epoch\":0"),
        ] {
            assert_eq!(
                EffectBinding::from_private_bytes(invalid.as_bytes()),
                Err(EffectBindingError::Invalid)
            );
        }
        let mut obsolete = wire();
        obsolete.schema = "auths.bound-effect/0".to_owned();
        assert_eq!(
            EffectBinding::new(obsolete),
            Err(EffectBindingError::Unsupported)
        );
        assert_eq!(
            EffectBinding::from_private_bytes(&vec![b' '; MAX_EFFECT_BYTES + 1]),
            Err(EffectBindingError::Invalid)
        );
    }

    #[test]
    fn every_binding_dimension_changes_identity_without_evading_replay_key() {
        let original = EffectBinding::new(wire()).expect("binding");
        for dimension in 0..14 {
            let mut changed = wire();
            match dimension {
                0 => changed.action[0] ^= 1,
                1 => changed.native_authority[0] ^= 1,
                2 => {
                    changed.scope = Scope::Task {
                        commitment: [7; 32],
                    }
                }
                3 => changed.recipe[0] ^= 1,
                4 => changed.connection[0] ^= 1,
                5 => changed.credential_generation += 1,
                6 => changed.qualification_policy = "optional".to_owned(),
                7 => changed.reservations[0].key[0] ^= 1,
                8 => changed.reservations[0].ceiling += 1,
                9 => {
                    changed.reservations[0].window = ReservationWindow::Fixed {
                        index: 1,
                        seconds: 60,
                    }
                }
                10 => {
                    changed.reservations[0].window = ReservationWindow::Fixed {
                        index: 0,
                        seconds: 61,
                    }
                }
                11 => changed.protocol = Protocol::Mutation { request: [8; 32] },
                12 => changed.configuration[0] ^= 1,
                _ => {
                    changed.approval_policy = ApprovalPolicy::Exact {
                        approver: SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes(),
                    }
                }
            }
            let changed = EffectBinding::new(changed).expect("changed binding");
            assert!(original.same_operation(&changed), "dimension {dimension}");
            assert_ne!(original.id(), changed.id(), "dimension {dimension}");
        }
        for dimension in 0..4 {
            let mut changed = wire();
            match dimension {
                0 => changed.namespace.push('2'),
                1 => changed.partition.push('2'),
                2 => changed.epoch += 1,
                _ => changed.operation.push('2'),
            }
            let changed = EffectBinding::new(changed).expect("new operation");
            assert!(!original.same_operation(&changed));
            assert_ne!(original.id(), changed.id());
        }
    }

    #[test]
    fn reservations_reject_duplicates_mixed_protocols_and_limits() {
        let mut changed = wire();
        changed.reservations.push(changed.reservations[0].clone());
        assert_eq!(
            EffectBinding::new(changed),
            Err(EffectBindingError::Invalid)
        );
        let mut changed = wire();
        changed.reservations[0].unit = Unit::DisclosureBytes;
        assert_eq!(
            EffectBinding::new(changed),
            Err(EffectBindingError::Invalid)
        );
        let mut changed = wire();
        changed.reservations = (0..MAX_EFFECT_RESERVATIONS)
            .map(|index| {
                let mut entry = wire().reservations.remove(0);
                entry.key[0] = u8::try_from(index).expect("bounded index");
                entry
            })
            .collect();
        assert!(EffectBinding::new(changed.clone()).is_ok());
        let mut excess = changed.reservations[0].clone();
        excess.key = [255; 32];
        changed.reservations.push(excess);
        assert_eq!(
            EffectBinding::new(changed),
            Err(EffectBindingError::Invalid)
        );
        let mut changed = wire();
        changed.epoch = MAX_SAFE_INTEGER;
        assert!(EffectBinding::new(changed.clone()).is_ok());
        changed.epoch += 1;
        assert_eq!(
            EffectBinding::new(changed),
            Err(EffectBindingError::Invalid)
        );
    }

    #[test]
    fn exact_approval_cannot_change_identity_signer_or_signed_event_time() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let trusted = key.verifying_key().to_bytes();
        let effect = EffectBinding::new(wire()).expect("binding").id();
        let request = EffectApprovalRequest {
            schema: APPROVAL_SCHEMA.to_owned(),
            effect: *effect.as_bytes(),
            approver: trusted,
            not_before: 100,
            expires_at: 200,
        };
        let signature = key
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        let approval = request.with_signature(signature);
        let encoded = approval.to_private_bytes().expect("encode");
        let approval = ExactEffectApproval::from_private_bytes(&encoded).expect("decode");
        assert!(approval.verify(effect, &trusted, 100).is_ok());
        assert!(approval.verify(effect, &trusted, 199).is_ok());
        assert!(approval.verify(effect, &trusted, 99).is_err());
        assert!(approval.verify(effect, &trusted, 200).is_err());
        assert!(approval.verify(EffectId([99; 32]), &trusted, 150).is_err());
        let other_key = SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes();
        assert!(approval.verify(effect, &other_key, 150).is_err());
        let mut altered = approval.clone();
        altered.request.expires_at += 1;
        assert!(altered.verify(effect, &trusted, 150).is_err());
        assert!(!format!("{approval:?}").contains(&approval.signature_b64));
    }
}
