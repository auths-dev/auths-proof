//! Root projection from the activated card and exact compiled recipe set.
//!
//! Callers propose native grant IDs; they do not supply trusted root pins.
//! The native root activation must prove the resulting complete commitment.

use crate::participant_enrollment::{
    EnrollmentScopePins, EnrollmentTreeError, MAX_SCOPES, ParentEnrollmentPins,
    ParticipantCeilings, root_enrollment_commitment,
};
use crate::task_activation::{AgentTaskDescriptor, ApprovedAgentTask};
use crate::{CompiledRecipe, CompiledReleaseRecipe};
use auths_model::{GrantId, PrincipalId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Grant IDs proposed by the initial participant for its native root proofs.
/// IDs alone establish no authority. Keys are derived by the task scope API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRootAuthority {
    /// Native participant-control grant held by the signed card's initial agent.
    pub control_grant: [u8; 32],
    /// Exactly one native resource grant ID per derived task scope.
    pub resource_grants: BTreeMap<String, [u8; 32]>,
}

/// Operator-supplied compiled recipes used to project the signed task scopes.
/// Their digests must match the card exactly. Recipes cannot be supplied by a
/// participant as arbitrary metadata, URLs or resource-field names.
pub struct TaskEnrollmentRecipes<'a> {
    /// The distinct read recipes selected by the card, at most sixteen.
    pub reads: &'a [CompiledReleaseRecipe],
    /// The distinct write recipes selected by the card, at most sixteen.
    pub writes: &'a [CompiledRecipe],
}

/// Exact resource projection for authoring a native root witness. This is an
/// operator/participant preparation value, not a receipt or execution permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskEnrollmentScope {
    /// Domain-separated commitment of scope kind and every signed scope field.
    pub scope_id: String,
    /// Native MCP service fixed by the compiled recipe.
    pub service: String,
    /// Native tool fixed by the compiled recipe.
    pub tool: String,
    /// Native action argument fixed by the compiled recipe.
    pub resource_argument: String,
    /// Exact handle from the signed task scope.
    pub resource_handle: String,
}

fn scope_id(kind: &str, scope: &impl Serialize) -> Result<String, EnrollmentTreeError> {
    let bytes = serde_json_canonicalizer::to_vec(&(kind, scope))
        .map_err(|_| EnrollmentTreeError::Binding)?;
    auths_codec::domain_commitment("auths.engagement-resource-scope.v1", &bytes)
        .map(|digest| hex::encode(digest.as_bytes()))
        .map_err(|_| EnrollmentTreeError::Binding)
}

pub(crate) fn scopes(
    card: &AgentTaskDescriptor,
    recipes: &TaskEnrollmentRecipes<'_>,
) -> Result<Vec<TaskEnrollmentScope>, EnrollmentTreeError> {
    // A not-yet-observed child needs its profile-owned lineage projection.
    // Refuse rather than substituting its parent or guessing a future handle.
    if card.pending_child.is_some()
        || card.read_scopes.len() + card.write_scopes.len() > MAX_SCOPES
        || recipes.reads.len() > MAX_SCOPES
        || recipes.writes.len() > MAX_SCOPES
    {
        return Err(EnrollmentTreeError::Binding);
    }
    let reads: BTreeMap<_, _> = recipes.reads.iter().map(|r| (r.digest_hex(), r)).collect();
    let writes: BTreeMap<_, _> = recipes.writes.iter().map(|r| (r.digest_hex(), r)).collect();
    let expected_reads: BTreeSet<_> = card.read_scopes.iter().map(|s| &s.recipe_digest).collect();
    let expected_writes: BTreeSet<_> = card.write_scopes.iter().map(|s| &s.recipe_digest).collect();
    if reads.len() != recipes.reads.len()
        || writes.len() != recipes.writes.len()
        || reads.keys().collect::<BTreeSet<_>>() != expected_reads
        || writes.keys().collect::<BTreeSet<_>>() != expected_writes
    {
        return Err(EnrollmentTreeError::Binding);
    }
    let mut result = Vec::new();
    for scope in &card.read_scopes {
        let recipe = reads
            .get(&scope.recipe_digest)
            .ok_or(EnrollmentTreeError::Binding)?;
        let (tool, argument) = recipe.enrollment_binding();
        result.push(TaskEnrollmentScope {
            scope_id: scope_id("read", scope)?,
            service: recipe.service().into(),
            tool: tool.into(),
            resource_argument: argument.into(),
            resource_handle: scope.handle.clone(),
        });
    }
    for scope in &card.write_scopes {
        let recipe = writes
            .get(&scope.recipe_digest)
            .ok_or(EnrollmentTreeError::Binding)?;
        let (argument, verb) = recipe.task_binding().ok_or(EnrollmentTreeError::Binding)?;
        if verb != scope.verb {
            return Err(EnrollmentTreeError::Binding);
        }
        result.push(TaskEnrollmentScope {
            scope_id: scope_id("write", scope)?,
            service: recipe.service().into(),
            tool: recipe.enrollment_tool().into(),
            resource_argument: argument.into(),
            resource_handle: scope.handle.clone(),
        });
    }
    result.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
    if result.is_empty()
        || result
            .windows(2)
            .any(|pair| pair[0].scope_id == pair[1].scope_id)
    {
        return Err(EnrollmentTreeError::Binding);
    }
    Ok(result)
}

pub(crate) fn root_pins(
    task: &ApprovedAgentTask,
    recipes: &TaskEnrollmentRecipes<'_>,
    authority: &TaskRootAuthority,
) -> Result<ParentEnrollmentPins, EnrollmentTreeError> {
    let card = task.descriptor();
    let scopes = scopes(card, recipes)?;
    if authority.resource_grants.len() != scopes.len() {
        return Err(EnrollmentTreeError::Binding);
    }
    let scopes = scopes
        .into_iter()
        .map(|scope| {
            let grant = authority
                .resource_grants
                .get(&scope.scope_id)
                .ok_or(EnrollmentTreeError::Binding)?;
            Ok(EnrollmentScopePins {
                scope_id: scope.scope_id,
                parent_grant: GrantId::new(*grant),
                service: scope.service,
                tool: scope.tool,
                resource_argument: scope.resource_argument,
                resource_handle: scope.resource_handle,
            })
        })
        .collect::<Result<_, EnrollmentTreeError>>()?;
    let mut pins = ParentEnrollmentPins {
        active: true,
        engagement_commitment: *task.commitment(),
        partition_generation: card.delegation.partition_generation,
        enrollment_commitment: [0; 32],
        principal: PrincipalId::parse(&card.agent_principal)
            .map_err(|_| EnrollmentTreeError::Binding)?,
        instance_generation: card.delegation.root_instance_generation,
        control_grant: GrantId::new(authority.control_grant),
        not_before: card.not_before,
        expires_at: card.expires_at,
        remaining_depth: card.delegation.max_depth,
        ceilings: ParticipantCeilings {
            provider_reads: card.max_provider_calls,
            disclosures: card.max_releases,
            disclosure_bytes: card.max_release_bytes,
            writes: card.max_writes,
        },
        permitted_channels: card.delegation.permitted_channels.clone(),
        scopes,
    };
    pins.enrollment_commitment = root_enrollment_commitment(&pins)?;
    Ok(pins)
}

/// Recheck the immutable card-to-root association on protected journal restore.
/// Exact recipe metadata was admitted at bootstrap. Every scope ID commits its
/// full signed card scope, including recipe, connection generation and account.
pub(crate) fn root_matches_task(root: &ParentEnrollmentPins, task: &ApprovedAgentTask) -> bool {
    root_matches_card(root, task.descriptor(), task.commitment())
}

pub(crate) fn root_matches_card(
    root: &ParentEnrollmentPins,
    card: &AgentTaskDescriptor,
    commitment: &[u8; 32],
) -> bool {
    let expected: Result<BTreeSet<_>, _> = card
        .read_scopes
        .iter()
        .map(|scope| scope_id("read", scope))
        .chain(
            card.write_scopes
                .iter()
                .map(|scope| scope_id("write", scope)),
        )
        .collect();
    root.engagement_commitment == *commitment
        && card.pending_child.is_none()
        && root.partition_generation == card.delegation.partition_generation
        && root.principal.as_str() == card.agent_principal
        && root.instance_generation == card.delegation.root_instance_generation
        && root.not_before == card.not_before
        && root.expires_at == card.expires_at
        && root.remaining_depth == card.delegation.max_depth
        && root.ceilings
            == ParticipantCeilings {
                provider_reads: card.max_provider_calls,
                disclosures: card.max_releases,
                disclosure_bytes: card.max_release_bytes,
                writes: card.max_writes,
            }
        && root.permitted_channels == card.delegation.permitted_channels
        && expected.is_ok_and(|ids| {
            root.scopes
                .iter()
                .map(|scope| scope.scope_id.clone())
                .collect::<BTreeSet<_>>()
                == ids
        })
        && root_enrollment_commitment(root).is_ok_and(|id| id == root.enrollment_commitment)
}

#[cfg(test)]
mod tests;
