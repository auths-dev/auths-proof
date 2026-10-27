//! Native bootstrap of the immutable root enrollment binding.

use super::{
    EnrollmentInvocation, EnrollmentResourceWitness, EnrollmentScopePins, MAX_ACTION_BYTES,
    MAX_SCOPES, PARTICIPANT_SERVICE, ParentEnrollmentPins, ParticipantCeilings,
    ParticipantEnrollmentError, bounded_invocations, bounded_parent, grant_identifier,
    native_invocation,
};
use auths_model::{GrantId, TrustedContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Native participant-control operation that activates one exact root binding.
pub const ACTIVATE_ROOT_TOOL: &str = "activate_engagement_root_v1";

/// Root possession plus separate native authority for each installed scope.
pub struct RootEnrollmentProofs<'a> {
    /// Root-signed activation of its complete root enrollment commitment.
    pub activation: EnrollmentInvocation<'a>,
    /// One root-signed resource invocation per installed scope, in pin order.
    /// Verification witnesses only: bootstrap never sends these to a provider.
    pub resources: &'a [EnrollmentResourceWitness<'a>],
}

// The root's own ID and mutable active/revoked state are deliberately absent.
// This avoids a self-referential commitment and keeps revocation from changing
// the immutable parent ID used by every descendant.
#[derive(Serialize)]
struct RootCommitment<'a> {
    schema: &'static str,
    engagement_commitment: &'a [u8; 32],
    partition_generation: u64,
    principal: &'a str,
    instance_generation: u64,
    control_grant: &'a [u8; 32],
    not_before: u64,
    expires_at: u64,
    remaining_depth: u16,
    ceilings: ParticipantCeilings,
    permitted_channels: &'a BTreeMap<String, super::EnrollmentChannelPins>,
    scopes: &'a [EnrollmentScopePins],
}

/// Derive the root enrollment ID from all immutable authority and installation
/// pins. Set `pins.enrollment_commitment` to this result before root activation.
///
/// `active` and the existing `enrollment_commitment` are excluded: revocation
/// cannot change ancestry, and an ID cannot commit itself. Computing this value
/// authenticates nothing. Root pins must be independently installed and bound
/// to the signed engagement; native activation must then accept this commitment.
///
/// # Errors
/// Refuses invalid bounds, inexact JSON integers or canonical encoding failure.
pub fn root_enrollment_commitment(
    pins: &ParentEnrollmentPins,
) -> Result<[u8; 32], ParticipantEnrollmentError> {
    bounded_parent(pins)?;
    let body = RootCommitment {
        schema: "auths.engagement-root/1",
        engagement_commitment: &pins.engagement_commitment,
        partition_generation: pins.partition_generation,
        principal: pins.principal.as_str(),
        instance_generation: pins.instance_generation,
        control_grant: pins.control_grant.as_bytes(),
        not_before: pins.not_before,
        expires_at: pins.expires_at,
        remaining_depth: pins.remaining_depth,
        ceilings: pins.ceilings,
        permitted_channels: &pins.permitted_channels,
        scopes: &pins.scopes,
    };
    let bytes =
        serde_json_canonicalizer::to_vec(&body).map_err(|_| ParticipantEnrollmentError::Invalid)?;
    if bytes.len() > MAX_ACTION_BYTES {
        return Err(ParticipantEnrollmentError::Invalid);
    }
    auths_codec::domain_commitment("auths.engagement-root.v1", &bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| ParticipantEnrollmentError::Invalid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootActivationArguments {
    root_enrollment_commitment: [u8; 32],
}

fn bounded_proofs(
    root: &ParentEnrollmentPins,
    proofs: &RootEnrollmentProofs<'_>,
) -> Result<(), ParticipantEnrollmentError> {
    bounded_parent(root)?;
    if proofs.resources.len() > MAX_SCOPES || proofs.resources.len() != root.scopes.len() {
        return Err(ParticipantEnrollmentError::Invalid);
    }
    bounded_invocations(
        std::iter::once(proofs.activation)
            .chain(proofs.resources.iter().map(|resource| resource.invocation)),
    )
}

fn root_holder(
    branch: &crate::bounds::AuthorizedBranch,
    root: &ParentEnrollmentPins,
    grant: GrantId,
) -> Result<(), ParticipantEnrollmentError> {
    let terminal = branch
        .chain
        .last()
        .ok_or(ParticipantEnrollmentError::ControlAuthority)?;
    let statement = terminal.statement();
    if branch.actor != root.principal
        || statement.subject() != &root.principal
        || grant_identifier(terminal)? != grant
        || statement.remaining_depth() < root.remaining_depth
        || statement.validity().not_before().get() > root.not_before
        || statement.validity().expires_at().get() < root.expires_at
    {
        return Err(ParticipantEnrollmentError::ControlAuthority);
    }
    Ok(())
}

pub(super) fn verify_root(
    context: &TrustedContext,
    root: &ParentEnrollmentPins,
    now: u64,
    proofs: &RootEnrollmentProofs<'_>,
) -> Result<(), ParticipantEnrollmentError> {
    bounded_proofs(root, proofs)?;
    if !root.active
        || now < root.not_before
        || now >= root.expires_at
        || root.enrollment_commitment != root_enrollment_commitment(root)?
    {
        return Err(ParticipantEnrollmentError::ParentBinding);
    }
    let (command, branch) = native_invocation(
        context,
        now,
        proofs.activation,
        PARTICIPANT_SERVICE,
        ACTIVATE_ROOT_TOOL,
    )?;
    let arguments: RootActivationArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| ParticipantEnrollmentError::Invalid)?;
    if arguments.root_enrollment_commitment != root.enrollment_commitment {
        return Err(ParticipantEnrollmentError::Acceptance);
    }
    root_holder(&branch, root, root.control_grant)?;
    for (scope, witness) in root.scopes.iter().zip(proofs.resources) {
        if witness.scope_id != scope.scope_id {
            return Err(ParticipantEnrollmentError::ResourceAuthority);
        }
        let (command, branch) = native_invocation(
            context,
            now,
            witness.invocation,
            &scope.service,
            &scope.tool,
        )?;
        root_holder(&branch, root, scope.parent_grant)
            .map_err(|_| ParticipantEnrollmentError::ResourceAuthority)?;
        if command
            .arguments()
            .get(&scope.resource_argument)
            .and_then(Value::as_str)
            != Some(&scope.resource_handle)
        {
            return Err(ParticipantEnrollmentError::ResourceAuthority);
        }
    }
    Ok(())
}
