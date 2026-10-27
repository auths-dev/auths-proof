//! Native authorization and child acceptance of an exact participant enrollment.
//!
//! This boundary performs no enrollment transaction or I/O. The caller supplies
//! authenticated parent/operator pins, then must atomically revalidate that
//! snapshot, claim the enrollment ID and conserve ancestor capacity. A returned
//! witness is not an execution permit. Resource witnesses are verified only;
//! their actions are never sent to a provider by this module.

use crate::GatewaySubmitResult;
use crate::bounds::{AuthorizedBranch, authorized_chains};
use crate::engine::{authorized_action, verify_sealed_for_audience};
use auths_model::{Audience, GrantId, PrincipalId, SignedGrant, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpCommand, McpProfile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

mod audience;
pub use audience::resource_audience;

mod root;
pub use root::{ACTIVATE_ROOT_TOOL, RootEnrollmentProofs, root_enrollment_commitment};

mod tree;
pub use tree::{EnrollmentTree, EnrollmentTreeError};

/// Fixed native MCP service for participant control; callers cannot select it.
pub use crate::control_namespace::PARTICIPANT_SERVICE;
/// Parent-authorized exact enrollment operation.
pub const ENROLL_PARTICIPANT_TOOL: &str = "enroll_participant_v1";
/// Child-authorized acceptance of the enrollment commitment.
pub const ACCEPT_PARTICIPANT_TOOL: &str = "accept_participant_v1";
/// Direct schema for the new enrollment contract.
pub const PARTICIPANT_ENROLLMENT_SCHEMA: &str = "auths.participant-enrollment/1";
pub(crate) const MAX_SCOPES: usize = 16;
// One bounded tree, including the root, with one registered channel per principal.
pub(crate) const MAX_PARTICIPANTS: usize = 16;
const MAX_PROOF_BYTES: usize = 4 * 1_048_576;
const MAX_ACTION_BYTES: usize = 65_536;
// Enrollment travels in the canonical MCP JSON profile. Keep every integer
// exactly representable rather than permitting JCS rounding to alias an epoch.
pub(crate) const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;

/// Independent dimensions of one participant ceiling, never fresh root capacity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantCeilings {
    /// Maximum provider reads across this participant and descendants.
    pub provider_reads: u32,
    /// Maximum disclosures across this participant and descendants.
    pub disclosures: u32,
    /// Maximum disclosed bytes across this participant and descendants.
    pub disclosure_bytes: u64,
    /// Maximum writes across this participant and descendants.
    pub writes: u32,
}

impl ParticipantCeilings {
    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            provider_reads: self.provider_reads.checked_add(other.provider_reads)?,
            disclosures: self.disclosures.checked_add(other.disclosures)?,
            disclosure_bytes: self.disclosure_bytes.checked_add(other.disclosure_bytes)?,
            writes: self.writes.checked_add(other.writes)?,
        })
    }

    pub(crate) fn within(self, parent: Self) -> bool {
        self.provider_reads <= parent.provider_reads
            && self.disclosures <= parent.disclosures
            && self.disclosure_bytes <= parent.disclosure_bytes
            && self.writes <= parent.writes
            && self.provider_reads <= 64
            && self.disclosures <= 64
            && self.writes <= 32
            && self.disclosure_bytes <= 16 * 1_048_576
    }
}

/// One immutable engagement resource scope and its exact native child grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantScopeGrant {
    /// Operator-defined scope identifier, resolved inside the root engagement.
    pub scope_id: String,
    /// Native grant ID, computed by the maintained canonical codec.
    pub grant_id: [u8; 32],
}

/// Unverified enrollment data. Only native verification can mint its witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantEnrollment {
    /// Exactly [`PARTICIPANT_ENROLLMENT_SCHEMA`].
    pub schema: String,
    /// Exact root engagement commitment.
    pub engagement_commitment: [u8; 32],
    /// Current externally commissioned authority-partition generation.
    pub partition_generation: u64,
    /// Existing parent enrollment commitment, not a display name.
    pub parent_enrollment: [u8; 32],
    /// Existing parent's process instance generation.
    pub parent_instance_generation: u64,
    /// Fresh enrollment identifier; durable admission must enforce non-reuse.
    pub enrollment_id: String,
    /// Canonical native principal of the accepting child.
    pub child_principal: String,
    /// Fresh nonzero child instance generation.
    pub child_instance_generation: u64,
    /// Operator-registered channel identifier; never a runtime network address.
    pub delivery_channel: String,
    /// Child's native participant-control grant ID.
    pub control_grant: [u8; 32],
    /// Strictly sorted, unique resource scopes and native resource grants.
    pub scopes: Vec<ParticipantScopeGrant>,
    /// Earliest new admission, as explicit Unix seconds.
    pub not_before: u64,
    /// Exclusive end of new admission eligibility.
    pub expires_at: u64,
    /// Number of further participant edges the child may authorize.
    pub remaining_depth: u16,
    /// Ceilings that narrow every parent's ceiling.
    pub ceilings: ParticipantCeilings,
}

impl ParticipantEnrollment {
    /// Commitment the child accepts after reviewing the complete enrollment.
    /// This computes bytes only; it grants no authority and validates no pins.
    ///
    /// # Errors
    /// Rejects data exceeding the bounded action representation or codec limits.
    pub fn commitment(&self) -> Result<[u8; 32], ParticipantEnrollmentError> {
        if self.scopes.len() > MAX_SCOPES
            || self.schema.len() > 64
            || !identifier(&self.enrollment_id)
            || !identifier(&self.delivery_channel)
            || PrincipalId::parse(&self.child_principal).is_err()
            || self.scopes.iter().any(|scope| !identifier(&scope.scope_id))
            || [
                self.partition_generation,
                self.parent_instance_generation,
                self.child_instance_generation,
                self.not_before,
                self.expires_at,
                self.ceilings.disclosure_bytes,
            ]
            .into_iter()
            .any(|value| value > MAX_JSON_INTEGER)
        {
            return Err(ParticipantEnrollmentError::Invalid);
        }
        let bytes = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ParticipantEnrollmentError::Invalid)?;
        if bytes.len() > MAX_ACTION_BYTES {
            return Err(ParticipantEnrollmentError::Invalid);
        }
        auths_codec::domain_commitment("auths.participant-enrollment.v1", &bytes)
            .map(|digest| *digest.as_bytes())
            .map_err(|_| ParticipantEnrollmentError::Invalid)
    }

    fn validate(
        &self,
        parent: &ParentEnrollmentPins,
        now: u64,
    ) -> Result<(), ParticipantEnrollmentError> {
        if self.schema != PARTICIPANT_ENROLLMENT_SCHEMA
            || self.commitment().is_err()
            || !identifier(&self.enrollment_id)
            || !identifier(&self.delivery_channel)
            || self.child_instance_generation == 0
            || PrincipalId::parse(&self.child_principal).is_err()
            || self.child_principal == parent.principal.as_str()
            || self.scopes.is_empty()
            || self.scopes.len() > MAX_SCOPES
            || self.scopes.iter().any(|scope| !identifier(&scope.scope_id))
            || self
                .scopes
                .windows(2)
                .any(|pair| pair[0].scope_id >= pair[1].scope_id)
            || self.not_before >= self.expires_at
            || now < self.not_before
            || now >= self.expires_at
        {
            return Err(ParticipantEnrollmentError::Invalid);
        }
        if !parent.active
            || self.engagement_commitment != parent.engagement_commitment
            || self.partition_generation != parent.partition_generation
            || self.parent_enrollment != parent.enrollment_commitment
            || self.parent_instance_generation != parent.instance_generation
            || self.not_before < parent.not_before
            || self.expires_at > parent.expires_at
            || self.remaining_depth >= parent.remaining_depth
            || usize::from(self.remaining_depth) >= MAX_PARTICIPANTS
            || !self.ceilings.within(parent.ceilings)
            || parent
                .permitted_channels
                .get(&self.delivery_channel)
                .is_none_or(|channel| {
                    channel.principal.as_str() != self.child_principal
                        || channel.instance_generation != self.child_instance_generation
                })
        {
            return Err(ParticipantEnrollmentError::ParentBinding);
        }
        Ok(())
    }
}

pub(crate) fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Resource identity known now or bound only by verified creation lineage.
/// A deferred witness is not evidence that a child exists or a runtime target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EnrollmentResourceBinding {
    /// A literal resource from the signed task scope.
    Exact {
        /// Opaque, bounded provider handle.
        handle: String,
    },
    /// The sole child of an exact approved create, resolved by the task journal.
    CreatedChild {
        /// Exact producer operation from the signed pending-child proposal.
        create_operation_id: String,
        /// Compiled producer recipe from that proposal.
        create_recipe_digest: String,
        /// Exact signed create scope, including its account and generation.
        parent_scope_id: String,
    },
}

impl EnrollmentResourceBinding {
    fn valid(&self) -> bool {
        match self {
            Self::Exact { handle } => bounded_resource(handle),
            Self::CreatedChild {
                create_operation_id,
                create_recipe_digest,
                parent_scope_id,
            } => {
                !create_operation_id.is_empty()
                    && create_operation_id.len() <= 128
                    && !create_operation_id.chars().any(char::is_control)
                    && canonical_digest(create_recipe_digest)
                    && canonical_digest(parent_scope_id)
            }
        }
    }

    fn admits_witness(&self, value: &str, branch: &AuthorizedBranch) -> bool {
        match self {
            Self::Exact { handle } => value == handle,
            Self::CreatedChild { .. } => {
                bounded_resource(value)
                    && branch.chain.iter().all(|grant| {
                        matches!(
                            grant.statement().action_constraint(),
                            auths_model::ActionConstraint::AnyBody
                        )
                    })
            }
        }
    }
}

fn bounded_resource(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_resource_witness(
    scope: &EnrollmentScopePins,
    command: &McpCommand,
    branch: &AuthorizedBranch,
) -> Result<(), ParticipantEnrollmentError> {
    if command
        .arguments()
        .get(&scope.resource_argument)
        .and_then(Value::as_str)
        .is_some_and(|value| scope.resource.admits_witness(value, branch))
    {
        Ok(())
    } else {
        Err(ParticipantEnrollmentError::ResourceAuthority)
    }
}

/// Trusted root-scope projection supplied by the operator/engagement store.
/// These values must come from installed recipe bindings, never agent input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentScopePins {
    /// Immutable root scope identifier.
    pub scope_id: String,
    /// Exact compiled recipe identity; it separates this native resource audience.
    pub recipe_digest: String,
    /// Parent's exact native resource grant for this scope.
    #[serde(with = "grant_encoding")]
    pub parent_grant: GrantId,
    /// Installed MCP service, whose audience is checked by native verification.
    pub service: String,
    /// Installed MCP tool, checked against the sealed action.
    pub tool: String,
    /// Installed exact-resource argument name.
    pub resource_argument: String,
    /// Exact signed resource or deferred verified-create lineage.
    pub resource: EnrollmentResourceBinding,
}

/// Operator-owned identity and process instance for one registered channel.
/// Channel transport resolution must preserve this binding at disclosure entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChannelPins {
    /// Native recipient identity authenticated by the channel.
    #[serde(with = "principal_encoding")]
    pub principal: PrincipalId,
    /// Exact commissioned process instance; zero and rounded epochs are refused.
    pub instance_generation: u64,
}

/// Authenticated parent snapshot plus separately installed channel/resource pins.
/// Success against this snapshot does not prove it is still current: durable
/// enrollment must compare its commitment and generation under the ledger lock.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentEnrollmentPins {
    /// Parent is live in the authenticated snapshot.
    pub active: bool,
    /// Immutable root engagement commitment.
    pub engagement_commitment: [u8; 32],
    /// Current authority partition generation.
    pub partition_generation: u64,
    /// Exact existing parent enrollment commitment.
    pub enrollment_commitment: [u8; 32],
    /// Parent's enrolled canonical native principal.
    #[serde(with = "principal_encoding")]
    pub principal: PrincipalId,
    /// Parent's enrolled instance generation.
    pub instance_generation: u64,
    /// Parent's enrolled native control grant, not its resource grant.
    #[serde(with = "grant_encoding")]
    pub control_grant: GrantId,
    /// Parent's validity start.
    pub not_before: u64,
    /// Parent's validity end.
    pub expires_at: u64,
    /// Remaining participant depth.
    pub remaining_depth: u16,
    /// Parent ceilings; actual remaining usage is checked by the transaction.
    pub ceilings: ParticipantCeilings,
    /// Operator-approved child delivery channels inside this engagement.
    pub permitted_channels: BTreeMap<String, EnrollmentChannelPins>,
    /// Root scope pins, at most sixteen, with unique identifiers.
    pub scopes: Vec<EnrollmentScopePins>,
}

/// Bounded native proof and canonical action bytes, verified without execution.
#[derive(Clone, Copy)]
pub struct EnrollmentInvocation<'a> {
    /// Canonical native proof bundle.
    pub proof: &'a [u8],
    /// Exact canonical action encoded by the maintained codec.
    pub action: &'a [u8],
}

/// One child's proof of authority over one root resource scope.
pub struct EnrollmentResourceWitness<'a> {
    /// Scope selected from authenticated parent pins.
    pub scope_id: &'a str,
    /// Child-signed native action with the pinned exact resource argument.
    pub invocation: EnrollmentInvocation<'a>,
}

/// Separate parent authorization, child acceptance and per-resource evidence.
pub struct ParticipantEnrollmentProofs<'a> {
    /// Fixed enrollment tool with arguments `{"enrollment": ...}`.
    pub parent: EnrollmentInvocation<'a>,
    /// Fixed acceptance tool with arguments `{"enrollment_commitment": ...}`.
    pub child: EnrollmentInvocation<'a>,
    /// Exactly one witness for every declared scope, in the same sorted order.
    pub resources: &'a [EnrollmentResourceWitness<'a>],
}

/// Enrollment failures preserve native denial details without leaking proof bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParticipantEnrollmentError {
    /// Input exceeded a bound or did not use the closed enrollment schema.
    #[error("invalid participant enrollment")]
    Invalid,
    /// Native verification refused or could not establish authority.
    #[error("participant native verification refused")]
    Native(GatewaySubmitResult),
    /// Snapshot, principal, channel, validity or attenuation differed.
    #[error("participant parent binding differs")]
    ParentBinding,
    /// A control action used the wrong tool, actor or native grant path.
    #[error("participant control authority differs")]
    ControlAuthority,
    /// Child did not accept this exact descriptor commitment.
    #[error("participant acceptance differs")]
    Acceptance,
    /// A resource witness did not match its scope, holder or parent grant.
    #[error("participant resource authority differs")]
    ResourceAuthority,
}

/// Native-verified proposal awaiting one atomic durable enrollment transaction.
#[derive(Debug)]
pub struct VerifiedParticipantEnrollment {
    enrollment: ParticipantEnrollment,
    commitment: [u8; 32],
}

impl VerifiedParticipantEnrollment {
    /// Exact descriptor covered by both parent authority and child acceptance.
    #[must_use]
    pub const fn enrollment(&self) -> &ParticipantEnrollment {
        &self.enrollment
    }
    /// Exact enrollment commitment to persist with its unique ID.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentArguments {
    enrollment: ParticipantEnrollment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceArguments {
    enrollment_commitment: [u8; 32],
}

fn native_invocation(
    context: &TrustedContext,
    now: u64,
    invocation: EnrollmentInvocation<'_>,
    service: &str,
    tool: &str,
) -> Result<(McpCommand, AuthorizedBranch), ParticipantEnrollmentError> {
    let audience = Audience::parse(&format!("mcp://{service}"))
        .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    native_invocation_for_audience(context, now, invocation, service, tool, audience)
}

fn native_invocation_for_audience(
    context: &TrustedContext,
    now: u64,
    invocation: EnrollmentInvocation<'_>,
    service: &str,
    tool: &str,
    audience: Audience,
) -> Result<(McpCommand, AuthorizedBranch), ParticipantEnrollmentError> {
    let sealed =
        verify_sealed_for_audience(context, audience, now, invocation.proof, invocation.action)
            .map_err(ParticipantEnrollmentError::Native)?;
    let action = authorized_action(&sealed).map_err(ParticipantEnrollmentError::Native)?;
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    let mut branches = authorized_chains(invocation.proof, action)
        .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    let bundle = auths_codec::decode_bundle(invocation.proof, &VerifierLimits::default())
        .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    if branches.len() != 1
        || bundle.actions().len() != 1
        || command.call().service() != service
        || command.name() != tool
        || !bundle.actions()[0]
            .envelope()
            .extensions()
            .as_slice()
            .is_empty()
    {
        return Err(ParticipantEnrollmentError::ControlAuthority);
    }
    let branch = branches.pop().ok_or(ParticipantEnrollmentError::Invalid)?;
    if branch.chain.is_empty()
        || branch.chain.len() > 16
        || branch.chain.iter().any(|grant| {
            !grant.statement().extensions().as_slice().is_empty()
                || grant.statement().budget_ceiling().is_some()
        })
    {
        return Err(ParticipantEnrollmentError::ControlAuthority);
    }
    Ok((command, branch))
}

fn grant_identifier(grant: &SignedGrant) -> Result<GrantId, ParticipantEnrollmentError> {
    auths_codec::grant_id(grant.statement()).map_err(|_| ParticipantEnrollmentError::Invalid)
}

fn child_link(
    branch: &AuthorizedBranch,
    enrollment: &ParticipantEnrollment,
    parent: &ParentEnrollmentPins,
    expected_child: &[u8; 32],
    expected_parent: GrantId,
) -> Result<(), ParticipantEnrollmentError> {
    let terminal = branch
        .chain
        .last()
        .ok_or(ParticipantEnrollmentError::ControlAuthority)?;
    let statement = terminal.statement();
    if branch.actor.as_str() != enrollment.child_principal
        || statement.subject() != &branch.actor
        || statement.issuer() != &parent.principal
        || statement.parent() != Some(expected_parent)
        || grant_identifier(terminal)?.as_bytes() != expected_child
        || statement.remaining_depth() < enrollment.remaining_depth
        || statement.validity().not_before().get() > enrollment.not_before
        || statement.validity().expires_at().get() < enrollment.expires_at
    {
        return Err(ParticipantEnrollmentError::ControlAuthority);
    }
    Ok(())
}

fn bounded_parent(parent: &ParentEnrollmentPins) -> Result<(), ParticipantEnrollmentError> {
    if parent.scopes.is_empty()
        || parent.scopes.len() > MAX_SCOPES
        || parent.permitted_channels.len() > MAX_PARTICIPANTS
        || parent.partition_generation == 0
        || parent.instance_generation == 0
        || usize::from(parent.remaining_depth) >= MAX_PARTICIPANTS
        || parent.not_before >= parent.expires_at
        || !parent.ceilings.within(parent.ceilings)
        || parent.permitted_channels.is_empty()
        || parent.permitted_channels.iter().any(|(id, channel)| {
            !identifier(id)
                || channel.instance_generation == 0
                || channel.instance_generation > MAX_JSON_INTEGER
        })
        || [
            parent.partition_generation,
            parent.instance_generation,
            parent.not_before,
            parent.expires_at,
        ]
        .into_iter()
        .any(|value| value > MAX_JSON_INTEGER)
        || parent.scopes.iter().any(|scope| {
            !identifier(&scope.scope_id)
                || !identifier(&scope.service)
                || crate::control_namespace::is_control_service(&scope.service)
                || !identifier(&scope.tool)
                || resource_audience(
                    &parent.engagement_commitment,
                    parent.partition_generation,
                    &scope.recipe_digest,
                )
                .is_err()
                || !identifier(&scope.resource_argument)
                || !scope.resource.valid()
        })
        || parent
            .scopes
            .iter()
            .map(|scope| &scope.scope_id)
            .collect::<BTreeSet<_>>()
            .len()
            != parent.scopes.len()
    {
        return Err(ParticipantEnrollmentError::Invalid);
    }
    Ok(())
}

fn bounded_inputs(
    parent: &ParentEnrollmentPins,
    proofs: &ParticipantEnrollmentProofs<'_>,
) -> Result<(), ParticipantEnrollmentError> {
    bounded_parent(parent)?;
    if proofs.resources.len() > MAX_SCOPES {
        return Err(ParticipantEnrollmentError::Invalid);
    }
    bounded_invocations(
        [proofs.parent, proofs.child]
            .into_iter()
            .chain(proofs.resources.iter().map(|resource| resource.invocation)),
    )
}

fn bounded_invocations<'a>(
    invocations: impl IntoIterator<Item = EnrollmentInvocation<'a>>,
) -> Result<(), ParticipantEnrollmentError> {
    let mut total = 0usize;
    for invocation in invocations {
        total = total
            .saturating_add(invocation.proof.len())
            .saturating_add(invocation.action.len());
        if invocation.proof.is_empty()
            || invocation.action.is_empty()
            || invocation.action.len() > MAX_ACTION_BYTES
            || total > MAX_PROOF_BYTES
        {
            return Err(ParticipantEnrollmentError::Invalid);
        }
    }
    Ok(())
}

/// Verify parent enrollment authority, child possession/acceptance and every
/// resource grant through the maintained native verifier. No effects occur.
///
/// Trust roots, accepted methods, challenge and policy come from `context`;
/// parent/resource/channel pins must come from authenticated operator state.
/// This does not check current usage, unique enrollment IDs or concurrent
/// revocation: the consuming transaction must revalidate the pinned snapshot.
///
/// # Errors
/// Refuses unsupported policy, oversized evidence, widened enrollment, wrong
/// ancestry, unauthenticated acceptance or a mismatched exact resource witness.
pub fn verify_participant_enrollment(
    context: &TrustedContext,
    parent: &ParentEnrollmentPins,
    now: u64,
    proofs: &ParticipantEnrollmentProofs<'_>,
) -> Result<VerifiedParticipantEnrollment, ParticipantEnrollmentError> {
    bounded_inputs(parent, proofs)?;
    let (command, branch) = native_invocation(
        context,
        now,
        proofs.parent,
        PARTICIPANT_SERVICE,
        ENROLL_PARTICIPANT_TOOL,
    )?;
    let arguments: EnrollmentArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    let enrollment = arguments.enrollment;
    enrollment.validate(parent, now)?;
    let terminal = branch
        .chain
        .last()
        .ok_or(ParticipantEnrollmentError::ControlAuthority)?;
    if branch.actor != parent.principal || grant_identifier(terminal)? != parent.control_grant {
        return Err(ParticipantEnrollmentError::ControlAuthority);
    }
    let commitment = enrollment.commitment()?;
    let (accepted, child) = native_invocation(
        context,
        now,
        proofs.child,
        PARTICIPANT_SERVICE,
        ACCEPT_PARTICIPANT_TOOL,
    )?;
    let acceptance: AcceptanceArguments =
        serde_json::from_value(Value::Object(accepted.arguments().clone()))
            .map_err(|_| ParticipantEnrollmentError::Acceptance)?;
    if acceptance.enrollment_commitment != commitment {
        return Err(ParticipantEnrollmentError::Acceptance);
    }
    child_link(
        &child,
        &enrollment,
        parent,
        &enrollment.control_grant,
        parent.control_grant,
    )?;
    verify_resources(context, parent, &enrollment, now, proofs.resources)?;
    Ok(VerifiedParticipantEnrollment {
        enrollment,
        commitment,
    })
}

fn require_exclusive_resource_audience(
    branch: &AuthorizedBranch,
    audience: &Audience,
) -> Result<(), ParticipantEnrollmentError> {
    if branch
        .chain
        .last()
        .is_none_or(|grant| grant.statement().audiences().as_slice() != [audience.clone()])
    {
        return Err(ParticipantEnrollmentError::ResourceAuthority);
    }
    Ok(())
}

fn verify_resources(
    context: &TrustedContext,
    parent: &ParentEnrollmentPins,
    enrollment: &ParticipantEnrollment,
    now: u64,
    resources: &[EnrollmentResourceWitness<'_>],
) -> Result<(), ParticipantEnrollmentError> {
    if resources.len() != enrollment.scopes.len() {
        return Err(ParticipantEnrollmentError::ResourceAuthority);
    }
    for (scope, witness) in enrollment.scopes.iter().zip(resources) {
        let pins = parent
            .scopes
            .iter()
            .find(|pin| pin.scope_id == scope.scope_id)
            .ok_or(ParticipantEnrollmentError::ResourceAuthority)?;
        if witness.scope_id != scope.scope_id {
            return Err(ParticipantEnrollmentError::ResourceAuthority);
        }
        let audience = resource_audience(
            &parent.engagement_commitment,
            parent.partition_generation,
            &pins.recipe_digest,
        )?;
        let (command, branch) = native_invocation_for_audience(
            context,
            now,
            witness.invocation,
            &pins.service,
            &pins.tool,
            audience.clone(),
        )?;
        require_exclusive_resource_audience(&branch, &audience)?;
        child_link(
            &branch,
            enrollment,
            parent,
            &scope.grant_id,
            pins.parent_grant,
        )
        .map_err(|_| ParticipantEnrollmentError::ResourceAuthority)?;
        require_resource_witness(pins, &command, &branch)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

// Storage projections preserve native semantic types. Deserialization is only
// representation validation; it cannot authenticate a trusted installation.
mod grant_encoding {
    use auths_model::GrantId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        grant: &GrantId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        grant.as_bytes().serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<GrantId, D::Error> {
        <[u8; 32]>::deserialize(deserializer).map(GrantId::new)
    }
}

mod principal_encoding {
    use auths_model::PrincipalId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        principal: &PrincipalId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        principal.as_str().serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PrincipalId, D::Error> {
        let value = String::deserialize(deserializer)?;
        PrincipalId::parse(&value)
            .map_err(|_| serde::de::Error::custom("invalid principal encoding"))
    }
}
