//! Authentication and exact acknowledgement share the journal's immutable
//! enrolled delivery binding. These functions never send private bytes.

use crate::release_commitment::{ReleaseCommitmentContext, ReleaseCommitmentKey};
use crate::release_state::{ReleaseDeliveryBinding, VerifiedAgentAcknowledgement};
use auths_identity::{IdentityDescriptor, SignatureVerifier as _};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use auths_signature_ed25519::Ed25519Verifier;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

const ACK_SCHEMA: &str = "auths.agent-release-ack/2";
const CHALLENGE_SCHEMA: &str = "auths.agent-release-channel-challenge/2";
const MAX_IDENTITY_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReleaseAckError {
    #[error("release acknowledgement binding is invalid")]
    Binding,
    #[error("registered agent signature is invalid")]
    Signature,
}

pub(crate) fn channel_challenge_message(
    binding: &ReleaseDeliveryBinding,
    nonce: &[u8; 32],
) -> Result<Vec<u8>, ReleaseAckError> {
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ReleaseAckError::Binding);
    }
    let mut message = binding
        .message_fields()
        .map_err(|_| ReleaseAckError::Binding)?;
    message.insert("schema".into(), json!(CHALLENGE_SCHEMA));
    message.insert("nonce".into(), json!(hex::encode(nonce)));
    serde_json_canonicalizer::to_vec(&message).map_err(|_| ReleaseAckError::Binding)
}

pub(crate) fn verify_agent_channel_challenge(
    binding: &ReleaseDeliveryBinding,
    nonce: &[u8; 32],
    agent_identity_packet: &[u8],
    signature: &[u8],
) -> Result<(), ReleaseAckError> {
    let message = channel_challenge_message(binding, nonce)?;
    verify_registered_agent_signature(binding, agent_identity_packet, &message, signature)
}

/// The same canonical public-identity check is used during operator channel
/// installation and challenge/ACK verification. Principal control does not prove
/// process isolation or that an enrolled key has not been copied.
pub(crate) fn registered_agent_identity(
    principal: &str,
    fingerprint: Option<&str>,
    packet: &[u8],
) -> Result<(IdentityDescriptor, Vec<u8>), ReleaseAckError> {
    if packet.is_empty() || packet.len() > MAX_IDENTITY_BYTES {
        return Err(ReleaseAckError::Binding);
    }
    if let Some(fingerprint) = fingerprint {
        let expected = hex::decode(fingerprint).map_err(|_| ReleaseAckError::Binding)?;
        if expected.len() != 32 || !bool::from(Sha256::digest(packet).as_slice().ct_eq(&expected)) {
            return Err(ReleaseAckError::Binding);
        }
    }
    let descriptor = IdentityDescriptor::decode(packet).map_err(|_| ReleaseAckError::Binding)?;
    let [relationship] = descriptor.relationships() else {
        return Err(ReleaseAckError::Binding);
    };
    let [material] = relationship.verification_material() else {
        return Err(ReleaseAckError::Binding);
    };
    if relationship.relationship_id() != "default-signing"
        || relationship.purpose() != "authentication"
        || relationship.suite_id().as_str() != auths_signature_ed25519::ED25519_V1
        || material.material_id().as_str() != "default-key"
    {
        return Err(ReleaseAckError::Binding);
    }
    let public = material.bytes().to_vec();
    let expected =
        RawKeyIdentityMethod::identity(auths_signature_ed25519::ED25519_V1, public.clone())
            .and_then(|identity| identity.into_public_identity().to_descriptor())
            .map_err(|_| ReleaseAckError::Binding)?;
    if descriptor != expected {
        return Err(ReleaseAckError::Binding);
    }
    let actual = RawKeyDescriptor::new(RawKeyType::Ed25519, public.clone())
        .map_err(|_| ReleaseAckError::Binding)?
        .principal()
        .map_err(|_| ReleaseAckError::Binding)?;
    if actual.as_str() != principal {
        return Err(ReleaseAckError::Binding);
    }
    Ok((descriptor, public))
}

fn verify_registered_agent_signature(
    binding: &ReleaseDeliveryBinding,
    packet: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ReleaseAckError> {
    let (descriptor, public) =
        registered_agent_identity(binding.recipient(), binding.identity_fingerprint(), packet)?;
    let preimage = descriptor
        .signing_preimage("default-signing", message)
        .map_err(|_| ReleaseAckError::Binding)?;
    Ed25519Verifier
        .verify(&public, &preimage, signature)
        .map_err(|_| ReleaseAckError::Signature)
}

pub(crate) fn acknowledgement_message(
    binding: &ReleaseDeliveryBinding,
    resource_handle: &str,
    content: &[u8],
    key: &ReleaseCommitmentKey,
) -> Result<Vec<u8>, ReleaseAckError> {
    if content.is_empty() {
        return Err(ReleaseAckError::Binding);
    }
    let receipt_scope = ReleaseCommitmentContext::new(
        binding.task_id(),
        resource_handle,
        binding.operation_id(),
        "released",
    )
    .map_err(|_| ReleaseAckError::Binding)?;
    let commitment = key.commit(&receipt_scope, content);
    let mut message = binding
        .message_fields()
        .map_err(|_| ReleaseAckError::Binding)?;
    message.extend(serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(json!({
        "schema": ACK_SCHEMA, "resource_handle": resource_handle, "released_bytes": content.len(),
        "content_sha256": hex::encode(Sha256::digest(content)),
        "commitment_key_version": commitment.key_version(), "content_commitment": commitment.hex(),
    })).map_err(|_| ReleaseAckError::Binding)?);
    serde_json_canonicalizer::to_vec(&message).map_err(|_| ReleaseAckError::Binding)
}

pub(crate) fn verify_agent_acknowledgement(
    binding: &ReleaseDeliveryBinding,
    resource_handle: &str,
    content: &[u8],
    key: &ReleaseCommitmentKey,
    packet: &[u8],
    signature: &[u8],
) -> Result<VerifiedAgentAcknowledgement, ReleaseAckError> {
    let message = acknowledgement_message(binding, resource_handle, content, key)?;
    verify_registered_agent_signature(binding, packet, &message, signature)?;
    let receipt_scope = ReleaseCommitmentContext::new(
        binding.task_id(),
        resource_handle,
        binding.operation_id(),
        "released",
    )
    .map_err(|_| ReleaseAckError::Binding)?;
    let commitment = key.commit(&receipt_scope, content);
    Ok(VerifiedAgentAcknowledgement {
        task_id: binding.task_id().to_owned(),
        task_commitment: binding.task_commitment().to_owned(),
        operation_id: binding.operation_id().to_owned(),
        recipient: binding.recipient().to_owned(),
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
    ) -> (ApprovedAgentTask, IdentityDescriptor, Vec<u8>) {
        let identity = RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            agent.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("agent identity")
        .into_public_identity();
        let descriptor = identity.to_descriptor().expect("descriptor");
        let packet = descriptor.encode().expect("packet");
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/4",
            "task_id": "task-1",
            "company_id": "atlas",
            "initiator_principal": human.principal.as_str(),
            "approver_principal": human.principal.as_str(),
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
            "delegation": crate::task_activation::TaskDelegationPolicy::single(&agent.principal, "registered-agent-channel"),
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
            descriptor,
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
    fn channel_challenge_authenticates_agent_before_content_entry() {
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
        let binding = ReleaseDeliveryBinding::initial_for_test(&task, "read-1");
        let nonce = [0x44; 32];
        let message = channel_challenge_message(&binding, &nonce).expect("challenge");
        let preimage = identity
            .signing_preimage("default-signing", &message)
            .expect("preimage");
        let signature = agent.key.sign(&preimage).to_bytes();
        assert_eq!(
            verify_agent_channel_challenge(&binding, &nonce, &packet, &signature),
            Ok(())
        );
        assert_eq!(
            verify_agent_channel_challenge(&binding, &[0x45; 32], &packet, &signature),
            Err(ReleaseAckError::Signature)
        );
        assert_eq!(
            verify_agent_channel_challenge(
                &ReleaseDeliveryBinding::initial_for_test(&task, "read-2"),
                &nonce,
                &packet,
                &signature
            ),
            Err(ReleaseAckError::Signature)
        );
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
        let binding = ReleaseDeliveryBinding::initial_for_test(&task, "read-1");
        let content = b"Project A update";
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32])).expect("key");
        let mut state = entered_state(&task, &agent, &recipe, content, &key);
        let message =
            acknowledgement_message(&binding, "resource-1", content, &key).expect("ack message");
        let preimage = identity
            .signing_preimage("default-signing", &message)
            .expect("signing preimage");
        let signature = agent.key.sign(&preimage).to_bytes();
        assert_eq!(
            verify_agent_acknowledgement(
                &binding,
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
                &binding,
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
        let other_packet = RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            other.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("other identity")
        .into_public_identity()
        .to_descriptor()
        .expect("other descriptor")
        .encode()
        .expect("other packet");
        assert_eq!(
            verify_agent_acknowledgement(
                &binding,
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
            &binding,
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
