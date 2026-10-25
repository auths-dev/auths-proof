//! Authenticated acknowledgement of one exact agent-visible release. This
//! verifier does not send bytes; the installed channel must deliver the bytes
//! before it accepts a signature over the resulting message.

use crate::release_commitment::{ReleaseCommitmentContext, ReleaseCommitmentKey};
use crate::release_state::VerifiedAgentAcknowledgement;
use crate::task_activation::ApprovedAgentTask;
use auths_identity::{IdentityPacket, SignedIdentityMessage};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use auths_signature_ed25519::Ed25519Verifier;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

const ACK_SCHEMA: &str = "auths.agent-release-ack/1";
const MAX_IDENTITY_BYTES: usize = 4_096;

/// A channel acknowledgement is invalid or bound to a different release.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReleaseAckError {
    #[error("release acknowledgement binding is invalid")]
    Binding,
    #[error("registered agent signature is invalid")]
    Signature,
}

/// The exact private message the agent signs after receiving `content`.
/// Its plain SHA-256 is never exported as a receipt: only the keyed content
/// commitment is persisted by the release ledger.
pub(crate) fn acknowledgement_message(
    task: &ApprovedAgentTask,
    operation_id: &str,
    resource_handle: &str,
    content: &[u8],
    key: &ReleaseCommitmentKey,
) -> Result<Vec<u8>, ReleaseAckError> {
    if content.is_empty() || operation_id.is_empty() || operation_id.len() > 128 {
        return Err(ReleaseAckError::Binding);
    }
    let receipt_scope = ReleaseCommitmentContext::new(
        &task.descriptor().task_id,
        resource_handle,
        operation_id,
        "released",
    )
    .map_err(|_| ReleaseAckError::Binding)?;
    let commitment = key.commit(&receipt_scope, content);
    let message = json!({
        "schema": ACK_SCHEMA,
        "task_id": task.descriptor().task_id,
        "task_commitment": hex::encode(task.commitment()),
        "operation_id": operation_id,
        "resource_handle": resource_handle,
        "recipient": task.descriptor().agent_principal,
        "delivery_channel": task.descriptor().delivery_channel,
        "released_bytes": content.len(),
        "content_sha256": hex::encode(Sha256::digest(content)),
        "commitment_key_version": commitment.key_version(),
        "content_commitment": commitment.hex(),
    });
    serde_json_canonicalizer::to_vec(&message).map_err(|_| ReleaseAckError::Binding)
}

/// Verify an acknowledgement signature under the exact registered agent
/// identity packet pinned in the human-signed card. The packet is a public
/// key, not a provider credential. The returned evidence can only advance a
/// ledger operation that already entered release with matching bytes.
pub(crate) fn verify_agent_acknowledgement(
    task: &ApprovedAgentTask,
    operation_id: &str,
    resource_handle: &str,
    content: &[u8],
    key: &ReleaseCommitmentKey,
    agent_identity_packet: &[u8],
    signature: &[u8],
) -> Result<VerifiedAgentAcknowledgement, ReleaseAckError> {
    if agent_identity_packet.is_empty() || agent_identity_packet.len() > MAX_IDENTITY_BYTES {
        return Err(ReleaseAckError::Binding);
    }
    let expected_fingerprint = hex::decode(&task.descriptor().agent_key_fingerprint)
        .map_err(|_| ReleaseAckError::Binding)?;
    if expected_fingerprint.len() != 32
        || !bool::from(
            Sha256::digest(agent_identity_packet)
                .as_slice()
                .ct_eq(&expected_fingerprint),
        )
    {
        return Err(ReleaseAckError::Binding);
    }
    let IdentityPacket::PublicIdentity(identity) =
        IdentityPacket::decode(agent_identity_packet).map_err(|_| ReleaseAckError::Binding)?
    else {
        return Err(ReleaseAckError::Binding);
    };
    let principal = RawKeyDescriptor::new(RawKeyType::Ed25519, identity.public_key().to_vec())
        .map_err(|_| ReleaseAckError::Binding)?
        .principal()
        .map_err(|_| ReleaseAckError::Binding)?;
    if principal.as_str() != task.descriptor().agent_principal {
        return Err(ReleaseAckError::Binding);
    }
    let message = acknowledgement_message(task, operation_id, resource_handle, content, key)?;
    SignedIdentityMessage::new(identity, message, signature.to_vec())
        .and_then(|signed| signed.verify(&RawKeyIdentityMethod, &Ed25519Verifier))
        .map_err(|_| ReleaseAckError::Signature)?;
    let receipt_scope = ReleaseCommitmentContext::new(
        &task.descriptor().task_id,
        resource_handle,
        operation_id,
        "released",
    )
    .map_err(|_| ReleaseAckError::Binding)?;
    let commitment = key.commit(&receipt_scope, content);
    Ok(VerifiedAgentAcknowledgement {
        task_id: task.descriptor().task_id.clone(),
        task_commitment: hex::encode(task.commitment()),
        operation_id: operation_id.to_owned(),
        recipient: task.descriptor().agent_principal.clone(),
        released_bytes: u64::try_from(content.len()).map_err(|_| ReleaseAckError::Binding)?,
        commitment_key_version: commitment.key_version(),
        content_commitment: commitment.hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Signer;
    use crate::release_state::{ReleaseStage, ReleaseTaskState};
    use crate::task_activation::{AgentTaskDescriptor, ApprovedAgentTask};
    use ed25519_dalek::Signer as _;
    use zeroize::Zeroizing;

    fn task_and_identity(
        human: &Signer,
        agent: &Signer,
        recipe: &crate::CompiledReleaseRecipe,
    ) -> (ApprovedAgentTask, auths_identity::PublicIdentity, Vec<u8>) {
        let identity = RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            agent.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("agent identity")
        .into_public_identity();
        let packet = IdentityPacket::PublicIdentity(identity.clone())
            .encode()
            .expect("packet");
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/2",
            "task_id": "task-1",
            "company_id": "atlas",
            "human_principal": human.principal.as_str(),
            "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": hex::encode(Sha256::digest(&packet)),
            "connection_id": "jules-write",
            "connection_generation": 3,
            "connection_subject": "jules-subject",
            "read_scopes": [{
                "handle": "resource-1", "recipe_digest": recipe.digest_hex(),
                "connection_id": "jules-read", "connection_generation": 3,
                "connection_subject": "jules-subject"
            }],
            "write_scopes": [],
            "delivery_channel": "registered-agent-channel",
            "not_before": 100,
            "expires_at": 200,
            "max_provider_calls": 1,
            "max_releases": 1,
            "max_release_bytes": 128,
            "max_writes": 0,
            "write_approval_mode": "exact",
            "operator_policy_digest": "a".repeat(64),
            "purpose": "Read Project A"
        }))
        .expect("card");
        (
            ApprovedAgentTask::from_test_card(card, [1; 32]),
            identity,
            packet,
        )
    }

    fn entered_state(
        task: &ApprovedAgentTask,
        agent: &Signer,
        recipe: &crate::CompiledReleaseRecipe,
        content: &[u8],
        key: &ReleaseCommitmentKey,
    ) -> ReleaseTaskState {
        let mut state = ReleaseTaskState::from_test_policy(task.task_policy()).expect("task");
        let arguments = json!({
            "operator_namespace": "google-read-demo",
            "operation_id": "read-1",
            "recipe_digest": recipe.digest_hex(),
            "task_id": "task-1",
            "task_commitment": "01".repeat(32),
            "agent_principal": agent.principal.as_str(),
            "resource_id": "resource-1"
        });
        let request = recipe
            .test_closed_request(arguments.as_object().expect("arguments"))
            .expect("closed request");
        state
            .reserve_closed_request(
                &request,
                &[agent.principal.as_str().to_owned()],
                "jules-read",
                3,
                "jules-subject",
                150,
            )
            .expect("provider reservation");
        state
            .enter_release("read-1", content, key, 150)
            .expect("durable release charge");
        state
    }

    #[test]
    fn registered_agent_acknowledges_only_the_exact_entered_bytes() {
        let human = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let recipe = crate::CompiledReleaseRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/profile.lock.json"
            ),
        )
        .expect("recipe");
        let (task, identity, packet) = task_and_identity(&human, &agent, &recipe);
        let content = b"Project A update";
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32])).expect("key");
        let mut state = entered_state(&task, &agent, &recipe, content, &key);
        let message = acknowledgement_message(&task, "read-1", "resource-1", content, &key)
            .expect("ack message");
        let preimage =
            SignedIdentityMessage::signing_preimage(&identity, &message).expect("signing preimage");
        let signature = agent.key.sign(&preimage).to_bytes();
        assert_eq!(
            verify_agent_acknowledgement(
                &task,
                "read-1",
                "resource-1",
                b"changed content",
                &key,
                &packet,
                &signature,
            )
            .err(),
            Some(ReleaseAckError::Signature)
        );
        assert_eq!(
            verify_agent_acknowledgement(
                &task,
                "read-1",
                "resource-2",
                content,
                &key,
                &packet,
                &signature,
            )
            .err(),
            Some(ReleaseAckError::Signature)
        );
        let other = Signer::new(0x33);
        let other_packet = IdentityPacket::PublicIdentity(
            RawKeyIdentityMethod::identity(
                auths_signature_ed25519::ED25519_V1,
                other.key.verifying_key().to_bytes().to_vec(),
            )
            .expect("other identity")
            .into_public_identity(),
        )
        .encode()
        .expect("other packet");
        assert_eq!(
            verify_agent_acknowledgement(
                &task,
                "read-1",
                "resource-1",
                content,
                &key,
                &other_packet,
                &signature,
            )
            .err(),
            Some(ReleaseAckError::Binding)
        );
        let evidence = verify_agent_acknowledgement(
            &task,
            "read-1",
            "resource-1",
            content,
            &key,
            &packet,
            &signature,
        )
        .expect("registered agent signature");
        state
            .acknowledge(&evidence)
            .expect("ledger acknowledgement");
        assert_eq!(state.stage("read-1"), Some(ReleaseStage::AgentAcknowledged));
        assert_eq!(state.counts(), (1, 1, 16));
    }
}
