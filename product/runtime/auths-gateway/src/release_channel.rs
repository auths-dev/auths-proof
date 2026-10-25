//! Local, bounded agent channel for one managed content release. It proves
//! possession of the registered agent key before sending private bytes, then
//! verifies an acknowledgement signed over the exact bytes after sending.

use crate::release_ack::{
    acknowledgement_message, channel_challenge_message, verify_agent_acknowledgement,
    verify_agent_channel_challenge,
};
use crate::release_commitment::ReleaseCommitmentKey;
use crate::release_state::{ProvenNoSend, VerifiedAgentAcknowledgement};
use crate::task_activation::ApprovedAgentTask;
use std::{
    fs,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    time::timeout,
};

const MAX_FRAME_BYTES: usize = 262_144;
const MAX_SIGNATURE_BYTES: usize = 256;
const PHASE_TIMEOUT: Duration = Duration::from_secs(5);

/// A release channel failed before content delivery was authorized.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReleaseChannelError {
    #[error("agent channel installation is unavailable")]
    Unavailable,
    #[error("agent channel binding is invalid")]
    Binding,
    #[error("agent channel signature is invalid")]
    Signature,
}

/// No-content proof is possible only before the first content-byte write.
/// Every failure after that point remains an unknown delivery outcome.
#[derive(Debug)]
pub(crate) enum ReleaseDeliveryError {
    NoContentSent(ProvenNoSend),
    DeliveryUnknown,
}

/// Operator-installed local socket and public agent identity. The human card
/// pins the logical channel name and identity-packet fingerprint separately.
pub(crate) struct UnixAgentReleaseChannel {
    socket: PathBuf,
    channel_name: String,
    agent_identity_packet: Vec<u8>,
    #[cfg(any(test, feature = "loopback-provider"))]
    fail_before_content: bool,
}

/// A socket peer that proved possession of the registered agent key under a
/// gateway-generated, operation-bound challenge. It has received no content.
pub(crate) struct AuthenticatedReleaseChannel {
    stream: UnixStream,
    agent_identity_packet: Vec<u8>,
    #[cfg(any(test, feature = "loopback-provider"))]
    fail_before_content: bool,
}

impl UnixAgentReleaseChannel {
    pub(crate) fn new(
        socket: impl Into<PathBuf>,
        channel_name: String,
        agent_identity_packet: Vec<u8>,
    ) -> Result<Self, ReleaseChannelError> {
        let socket = socket.into();
        if channel_name.is_empty()
            || channel_name.len() > 256
            || channel_name.chars().any(char::is_control)
            || agent_identity_packet.is_empty()
            || agent_identity_packet.len() > 4_096
            || !socket.is_absolute()
        {
            return Err(ReleaseChannelError::Binding);
        }
        Ok(Self {
            socket,
            channel_name,
            agent_identity_packet,
            #[cfg(any(test, feature = "loopback-provider"))]
            fail_before_content: false,
        })
    }

    #[cfg(any(test, feature = "loopback-provider"))]
    pub(crate) fn fail_before_content_for_test(&mut self) {
        self.fail_before_content = true;
    }

    /// Authenticate the peer before the caller charges or sends a release.
    pub(crate) async fn authenticate(
        &self,
        task: &ApprovedAgentTask,
        operation_id: &str,
    ) -> Result<AuthenticatedReleaseChannel, ReleaseChannelError> {
        if self.channel_name != task.descriptor().delivery_channel {
            return Err(ReleaseChannelError::Binding);
        }
        checked_socket(&self.socket)?;
        let mut stream = timeout(PHASE_TIMEOUT, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| ReleaseChannelError::Unavailable)?
            .map_err(|_| ReleaseChannelError::Unavailable)?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ReleaseChannelError::Unavailable)?;
        let challenge = channel_challenge_message(task, operation_id, &nonce)
            .map_err(|_| ReleaseChannelError::Binding)?;
        write_frame(&mut stream, &challenge, MAX_FRAME_BYTES).await?;
        let signature = read_frame(&mut stream, MAX_SIGNATURE_BYTES).await?;
        verify_agent_channel_challenge(
            task,
            operation_id,
            &nonce,
            &self.agent_identity_packet,
            &signature,
        )
        .map_err(|_| ReleaseChannelError::Signature)?;
        Ok(AuthenticatedReleaseChannel {
            stream,
            agent_identity_packet: self.agent_identity_packet.clone(),
            #[cfg(any(test, feature = "loopback-provider"))]
            fail_before_content: self.fail_before_content,
        })
    }
}

impl AuthenticatedReleaseChannel {
    /// Called only after `release-entered` is durable. A failure before the
    /// first content write proves no content was sent; later failures have an
    /// unknown delivery outcome. This method never retries.
    pub(crate) async fn deliver(
        mut self,
        task: &ApprovedAgentTask,
        operation_id: &str,
        resource_handle: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
    ) -> Result<VerifiedAgentAcknowledgement, ReleaseDeliveryError> {
        let no_content = || {
            ReleaseDeliveryError::NoContentSent(ProvenNoSend::before_content(
                &task.descriptor().task_id,
                operation_id,
            ))
        };
        let message = acknowledgement_message(task, operation_id, resource_handle, content, key)
            .map_err(|_| no_content())?;
        if content.is_empty() || content.len() > MAX_FRAME_BYTES {
            return Err(no_content());
        }
        let length = u32::try_from(content.len()).map_err(|_| no_content())?;
        #[cfg(any(test, feature = "loopback-provider"))]
        if self.fail_before_content {
            self.stream.shutdown().await.map_err(|_| no_content())?;
        }
        // A failed or partial frame header may expose length framing, but no
        // content bytes. Once write_all starts, a partial content
        // write is possible and the outcome must remain unknown.
        timeout(PHASE_TIMEOUT, self.stream.write_u32(length))
            .await
            .map_err(|_| no_content())?
            .map_err(|_| no_content())?;
        timeout(PHASE_TIMEOUT, self.stream.write_all(content))
            .await
            .map_err(|_| ReleaseDeliveryError::DeliveryUnknown)?
            .map_err(|_| ReleaseDeliveryError::DeliveryUnknown)?;
        write_frame(&mut self.stream, &message, MAX_FRAME_BYTES)
            .await
            .map_err(|_| ReleaseDeliveryError::DeliveryUnknown)?;
        let signature = read_frame(&mut self.stream, MAX_SIGNATURE_BYTES)
            .await
            .map_err(|_| ReleaseDeliveryError::DeliveryUnknown)?;
        verify_agent_acknowledgement(
            task,
            operation_id,
            resource_handle,
            content,
            key,
            &self.agent_identity_packet,
            &signature,
        )
        .map_err(|_| ReleaseDeliveryError::DeliveryUnknown)
    }
}

fn checked_socket(socket: &Path) -> Result<(), ReleaseChannelError> {
    let parent = socket.parent().ok_or(ReleaseChannelError::Binding)?;
    crate::check_private_directory(parent).map_err(|_| ReleaseChannelError::Unavailable)?;
    let metadata = fs::symlink_metadata(socket).map_err(|_| ReleaseChannelError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ReleaseChannelError::Unavailable);
    }
    Ok(())
}

async fn read_frame(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Vec<u8>, ReleaseChannelError> {
    let length = timeout(PHASE_TIMEOUT, stream.read_u32())
        .await
        .map_err(|_| ReleaseChannelError::Unavailable)?
        .map_err(|_| ReleaseChannelError::Unavailable)? as usize;
    if length == 0 || length > maximum {
        return Err(ReleaseChannelError::Binding);
    }
    let mut frame = vec![0_u8; length];
    timeout(PHASE_TIMEOUT, stream.read_exact(&mut frame))
        .await
        .map_err(|_| ReleaseChannelError::Unavailable)?
        .map_err(|_| ReleaseChannelError::Unavailable)?;
    Ok(frame)
}

async fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    maximum: usize,
) -> Result<(), ReleaseChannelError> {
    if frame.is_empty() || frame.len() > maximum {
        return Err(ReleaseChannelError::Binding);
    }
    let length = u32::try_from(frame.len()).map_err(|_| ReleaseChannelError::Binding)?;
    timeout(PHASE_TIMEOUT, async {
        stream.write_u32(length).await?;
        stream.write_all(frame).await
    })
    .await
    .map_err(|_| ReleaseChannelError::Unavailable)?
    .map_err(|_| ReleaseChannelError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Signer;
    use crate::task_activation::AgentTaskDescriptor;
    use auths_identity::IdentityDescriptor;
    use auths_identity_raw_key::RawKeyIdentityMethod;
    use ed25519_dalek::Signer as _;
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::net::UnixListener;
    use zeroize::Zeroizing;

    fn task_and_identity() -> (ApprovedAgentTask, Signer, IdentityDescriptor, Vec<u8>) {
        let human = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let identity = RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            agent.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("identity")
        .into_public_identity();
        let descriptor = identity.to_descriptor().expect("descriptor");
        let packet = descriptor.encode().expect("packet");
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/2", "task_id": "task-1",
            "company_id": "atlas", "human_principal": human.principal.as_str(),
            "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": hex::encode(Sha256::digest(&packet)),
            "connection_id": "jules-write", "connection_generation": 3,
            "connection_subject": "jules-subject",
            "read_scopes": [{"handle": "resource-1", "recipe_digest": "b".repeat(64),
                "connection_id": "jules-read", "connection_generation": 3,
                "connection_subject": "jules-subject"}],
            "write_scopes": [], "delivery_channel": "registered-agent-channel",
            "not_before": 100, "expires_at": 200, "max_provider_calls": 1,
            "max_releases": 1, "max_release_bytes": 128, "max_writes": 0,
            "write_approval_mode": "exact", "operator_policy_digest": "a".repeat(64),
            "purpose": "Read Project A"
        }))
        .expect("card");
        (
            ApprovedAgentTask::from_test_card(card, [1; 32]),
            agent,
            descriptor,
            packet,
        )
    }

    #[tokio::test]
    async fn signed_challenge_precedes_exact_byte_delivery_and_acknowledgement() {
        let (task, agent, identity, packet) = task_and_identity();
        let directory = tempfile::tempdir().expect("private directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let socket = fs::canonicalize(directory.path())
            .expect("canonical")
            .join("agent.sock");
        let listener = UnixListener::bind(&socket).expect("agent listener");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let challenge = read_frame(&mut stream, 4_096).await.expect("challenge");
            let preimage = identity
                .signing_preimage("default-signing", &challenge)
                .expect("challenge preimage");
            let signature = agent.key.sign(&preimage).to_bytes();
            write_frame(&mut stream, &signature, 256)
                .await
                .expect("challenge response");
            let content = read_frame(&mut stream, MAX_FRAME_BYTES)
                .await
                .expect("content");
            let message = read_frame(&mut stream, 4_096).await.expect("ack message");
            let payload: serde_json::Value = serde_json::from_slice(&message).expect("message");
            assert_eq!(
                payload["content_sha256"],
                hex::encode(Sha256::digest(&content))
            );
            let preimage = identity
                .signing_preimage("default-signing", &message)
                .expect("ack preimage");
            let signature = agent.key.sign(&preimage).to_bytes();
            write_frame(&mut stream, &signature, 256)
                .await
                .expect("ack response");
            content
        });
        let channel =
            UnixAgentReleaseChannel::new(socket, "registered-agent-channel".to_owned(), packet)
                .expect("channel");
        crate::check_private_directory(channel.socket.parent().expect("parent"))
            .expect("agent socket parent must be private");
        let metadata = fs::symlink_metadata(&channel.socket).expect("socket metadata");
        assert!(metadata.file_type().is_socket(), "must be a Unix socket");
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o077, 0);
        checked_socket(&channel.socket).expect("private agent socket");
        let authenticated = channel
            .authenticate(&task, "read-1")
            .await
            .expect("agent key");
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32])).expect("key");
        let content = b"Project A update";
        let acknowledgement = authenticated
            .deliver(&task, "read-1", "resource-1", content, &key)
            .await
            .expect("authenticated acknowledgement");
        assert_eq!(acknowledgement.released_bytes, 16);
        assert_eq!(server.await.expect("agent"), content);
    }

    #[tokio::test]
    async fn wrong_agent_key_cannot_open_a_content_channel() {
        let (task, _agent, identity, packet) = task_and_identity();
        let intruder = Signer::new(0x44);
        let directory = tempfile::tempdir().expect("private directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let socket = fs::canonicalize(directory.path())
            .expect("canonical")
            .join("agent.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let challenge = read_frame(&mut stream, 4_096).await.expect("challenge");
            let preimage = identity
                .signing_preimage("default-signing", &challenge)
                .expect("preimage");
            let signature = intruder.key.sign(&preimage).to_bytes();
            write_frame(&mut stream, &signature, 256)
                .await
                .expect("signature");
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.expect("closed channel"), 0);
        });
        let channel =
            UnixAgentReleaseChannel::new(socket, "registered-agent-channel".to_owned(), packet)
                .expect("channel");
        assert!(matches!(
            channel.authenticate(&task, "read-1").await,
            Err(ReleaseChannelError::Signature)
        ));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn closed_write_half_before_content_returns_no_send_proof() {
        let (task, _agent, _identity, packet) = task_and_identity();
        let (mut stream, peer) = UnixStream::pair().expect("local socket pair");
        stream
            .shutdown()
            .await
            .expect("close write half before delivery");
        drop(peer);
        let channel = AuthenticatedReleaseChannel {
            stream,
            agent_identity_packet: packet,
            fail_before_content: false,
        };
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([0x55; 32])).expect("key");
        let result = channel
            .deliver(&task, "read-1", "resource-1", b"private content", &key)
            .await;
        assert!(matches!(
            result,
            Err(ReleaseDeliveryError::NoContentSent(_))
        ));
    }
}
