//! Capability-free Ed25519 public identity exchange over Iroh.
//!
//! This crate exchanges self-certifying public identities and optionally
//! signed application messages. It does not evaluate grants, capabilities,
//! approvals, policy, lifecycle state, or authorization. An authenticated
//! Iroh connection and a valid Ed25519 signature remain authentication facts,
//! never an authorization verdict.

#![forbid(unsafe_code)]

use std::{fmt, time::Duration};

use auths_model::PrincipalId;
use auths_ports::{SignatureInput, SignatureSuite as _};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use auths_signature::Ed25519Suite;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream},
};
use tokio::time::timeout;

/// Dedicated ALPN for the capability-free identity protocol.
pub const IDENTITY_ALPN_V1: &[u8] = b"/auths/identity/1";
/// Maximum application message accepted by the identity protocol.
pub const MAX_IDENTITY_MESSAGE_BYTES: usize = 64 * 1024;

const WIRE_MAGIC: &[u8] = b"AUTHS-IROH-IDENTITY\0\x01";
const SIGNING_DOMAIN: &[u8] = b"AUTHS-IDENTITY-MESSAGE\0\x01";
const PUBLIC_IDENTITY_TAG: u8 = 1;
const SIGNED_MESSAGE_TAG: u8 = 2;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_DESCRIPTOR_BYTES: usize = 256;
const MAX_FRAME_BYTES: usize =
    WIRE_MAGIC.len() + 1 + 2 + MAX_DESCRIPTOR_BYTES + 4 + MAX_IDENTITY_MESSAGE_BYTES + 64;

/// Canonical self-certifying Ed25519 public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIdentity {
    descriptor: RawKeyDescriptor,
    principal: PrincipalId,
    public_key: [u8; 32],
}

impl PublicIdentity {
    /// Constructs an identity from an Ed25519 verification key.
    ///
    /// # Errors
    ///
    /// Returns a typed identity error if the canonical raw-key principal
    /// cannot be represented.
    pub fn from_ed25519(public_key: [u8; 32]) -> Result<Self, IdentityError> {
        let descriptor = RawKeyDescriptor::new(RawKeyType::Ed25519, public_key.to_vec())
            .map_err(|_| IdentityError::InvalidIdentity)?;
        Self::from_descriptor(descriptor)
    }

    fn from_descriptor(descriptor: RawKeyDescriptor) -> Result<Self, IdentityError> {
        if descriptor.suite() != auths_signature::ED25519_V1 || descriptor.public_key().len() != 32
        {
            return Err(IdentityError::InvalidIdentity);
        }
        let principal = descriptor
            .principal()
            .map_err(|_| IdentityError::InvalidIdentity)?;
        let public_key = descriptor
            .public_key()
            .try_into()
            .map_err(|_| IdentityError::InvalidIdentity)?;
        Ok(Self {
            descriptor,
            principal,
            public_key,
        })
    }

    /// Returns the self-certifying Auths principal identifier.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the exact 32-byte Ed25519 verification key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn descriptor_bytes(&self) -> Vec<u8> {
        self.descriptor.encode()
    }
}

/// One exact message signed by the exchanged Ed25519 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIdentityMessage {
    identity: PublicIdentity,
    message: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_BYTES],
}

impl SignedIdentityMessage {
    /// Constructs a bounded signed-message carrier.
    ///
    /// This constructor does not claim that the supplied signature is valid;
    /// call [`Self::verify`] at the trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidMessage`] for an empty or oversized
    /// application message.
    pub fn new(
        identity: PublicIdentity,
        message: Vec<u8>,
        signature: [u8; ED25519_SIGNATURE_BYTES],
    ) -> Result<Self, IdentityError> {
        validate_message(&message)?;
        Ok(Self {
            identity,
            message,
            signature,
        })
    }

    /// Constructs the exact domain-separated bytes that custody must sign.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidMessage`] for an empty or oversized
    /// message.
    pub fn signing_preimage(
        identity: &PublicIdentity,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_message(message)?;
        let descriptor = identity.descriptor_bytes();
        let descriptor_length =
            u16::try_from(descriptor.len()).map_err(|_| IdentityError::InvalidIdentity)?;
        let message_length =
            u32::try_from(message.len()).map_err(|_| IdentityError::InvalidMessage)?;
        let mut output =
            Vec::with_capacity(SIGNING_DOMAIN.len() + 2 + descriptor.len() + 4 + message.len());
        output.extend_from_slice(SIGNING_DOMAIN);
        output.extend_from_slice(&descriptor_length.to_be_bytes());
        output.extend_from_slice(&descriptor);
        output.extend_from_slice(&message_length.to_be_bytes());
        output.extend_from_slice(message);
        Ok(output)
    }

    /// Verifies the exact message with the canonical Ed25519 suite.
    ///
    /// A successful result authenticates these bytes to this public identity.
    /// It does not authorize an application action or provide freshness or
    /// replay protection.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSignature`] when verification fails.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let preimage = Self::signing_preimage(&self.identity, &self.message)?;
        let suite = Ed25519Suite::new().map_err(|_| IdentityError::InvalidSignature)?;
        suite
            .verify(SignatureInput {
                verification_key: self.identity.public_key(),
                signing_preimage: &preimage,
                signature: &self.signature,
            })
            .map_err(|_| IdentityError::InvalidSignature)
    }

    /// Returns the identity that signed the message.
    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// Returns the exact application message bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the Ed25519 signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; ED25519_SIGNATURE_BYTES] {
        &self.signature
    }
}

/// Closed capability-free identity message family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityPacket {
    /// Exchange a canonical public identity without an application signature.
    PublicIdentity(PublicIdentity),
    /// Exchange one application message signed by the carried identity.
    SignedMessage(SignedIdentityMessage),
}

impl IdentityPacket {
    /// Returns the public identity carried by either packet form.
    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        match self {
            Self::PublicIdentity(identity) => identity,
            Self::SignedMessage(message) => message.identity(),
        }
    }
}

/// Bounded I/O configuration for one request-response identity exchange.
#[derive(Clone, Copy, Debug)]
pub struct IrohIdentityConfig {
    io_timeout: Duration,
}

impl IrohIdentityConfig {
    /// Constructs a deadline between one nanosecond and sixty seconds.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Configuration`] outside that range.
    pub fn new(io_timeout: Duration) -> Result<Self, IdentityError> {
        if io_timeout.is_zero() || io_timeout > Duration::from_mins(1) {
            return Err(IdentityError::Configuration);
        }
        Ok(Self { io_timeout })
    }

    /// Returns the per-operation I/O deadline.
    #[must_use]
    pub const fn io_timeout(self) -> Duration {
        self.io_timeout
    }
}

impl Default for IrohIdentityConfig {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(10),
        }
    }
}

/// Direct/relay information observed while connecting to the Iroh peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathObservation {
    /// Target advertised only a direct socket address.
    Direct,
    /// Target advertised only a relay URL.
    Relayed,
    /// Target advertised both forms or neither form.
    MixedOrUnknown,
}

/// Decoded packet paired with the independently authenticated Iroh endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedPacket {
    peer_endpoint_id: [u8; 32],
    packet: IdentityPacket,
}

impl ReceivedPacket {
    /// Returns the remote Iroh endpoint identifier.
    #[must_use]
    pub const fn peer_endpoint_id(&self) -> &[u8; 32] {
        &self.peer_endpoint_id
    }

    /// Returns the exchanged Ed25519 identity packet.
    #[must_use]
    pub const fn packet(&self) -> &IdentityPacket {
        &self.packet
    }

    /// Consumes the observation and returns the packet.
    #[must_use]
    pub fn into_packet(self) -> IdentityPacket {
        self.packet
    }
}

/// Client side of one bounded identity request-response exchange.
pub struct IrohIdentityClient {
    _connection: Connection,
    peer_endpoint_id: [u8; 32],
    send: SendStream,
    recv: RecvStream,
    config: IrohIdentityConfig,
    path: PathObservation,
}

impl IrohIdentityClient {
    /// Connects using only the identity ALPN and opens the request stream.
    ///
    /// # Errors
    ///
    /// Returns a typed transport error for connection, ALPN, or stream
    /// failures.
    pub async fn connect(
        endpoint: &Endpoint,
        target: EndpointAddr,
        config: IrohIdentityConfig,
    ) -> Result<Self, IdentityError> {
        let path = classify_target(&target);
        let connection = endpoint
            .connect(target, IDENTITY_ALPN_V1)
            .await
            .map_err(|_| IdentityError::Connection)?;
        if connection.alpn() != IDENTITY_ALPN_V1 {
            return Err(IdentityError::Protocol);
        }
        let peer_endpoint_id = *connection.remote_id().as_bytes();
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|_| IdentityError::Connection)?;
        Ok(Self {
            _connection: connection,
            peer_endpoint_id,
            send,
            recv,
            config,
            path,
        })
    }

    /// Returns whether the target was direct, relayed, or mixed.
    #[must_use]
    pub const fn path_observation(&self) -> PathObservation {
        self.path
    }

    /// Sends exactly one packet and receives exactly one response.
    ///
    /// # Errors
    ///
    /// Returns a typed error for framing, timeout, transport, or codec
    /// failures. The transport does not manufacture an authorization result.
    pub async fn exchange(
        mut self,
        packet: &IdentityPacket,
    ) -> Result<ReceivedPacket, IdentityError> {
        write_frame(
            &mut self.send,
            &encode_packet(packet)?,
            self.config.io_timeout,
        )
        .await?;
        self.send.finish().map_err(|_| IdentityError::Connection)?;
        let encoded = read_frame(&mut self.recv, self.config.io_timeout).await?;
        Ok(ReceivedPacket {
            peer_endpoint_id: self.peer_endpoint_id,
            packet: decode_packet(&encoded)?,
        })
    }
}

/// Server side of one bounded identity request-response exchange.
pub struct IrohIdentityServer {
    _connection: Connection,
    peer_endpoint_id: [u8; 32],
    send: SendStream,
    recv: RecvStream,
    config: IrohIdentityConfig,
    received: bool,
}

impl IrohIdentityServer {
    /// Accepts one fully handshaken connection and its request stream.
    ///
    /// # Errors
    ///
    /// Returns a typed transport error for endpoint, ALPN, or stream failures.
    pub async fn accept(
        endpoint: &Endpoint,
        config: IrohIdentityConfig,
    ) -> Result<Self, IdentityError> {
        let incoming = endpoint.accept().await.ok_or(IdentityError::Connection)?;
        let connection = incoming.await.map_err(|_| IdentityError::Connection)?;
        if connection.alpn() != IDENTITY_ALPN_V1 {
            return Err(IdentityError::Protocol);
        }
        let peer_endpoint_id = *connection.remote_id().as_bytes();
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|_| IdentityError::Connection)?;
        Ok(Self {
            _connection: connection,
            peer_endpoint_id,
            send,
            recv,
            config,
            received: false,
        })
    }

    /// Receives the single request packet.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Sequence`] on a second receive and typed
    /// framing or codec errors for malformed input.
    pub async fn receive(&mut self) -> Result<ReceivedPacket, IdentityError> {
        if self.received {
            return Err(IdentityError::Sequence);
        }
        let encoded = read_frame(&mut self.recv, self.config.io_timeout).await?;
        self.received = true;
        Ok(ReceivedPacket {
            peer_endpoint_id: self.peer_endpoint_id,
            packet: decode_packet(&encoded)?,
        })
    }

    /// Sends the single response packet and closes the response stream.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Sequence`] if called before receiving the
    /// request, or a typed transport/framing error.
    pub async fn respond(mut self, packet: &IdentityPacket) -> Result<(), IdentityError> {
        if !self.received {
            return Err(IdentityError::Sequence);
        }
        write_frame(
            &mut self.send,
            &encode_packet(packet)?,
            self.config.io_timeout,
        )
        .await?;
        self.send.finish().map_err(|_| IdentityError::Connection)?;
        timeout(self.config.io_timeout, self.send.stopped())
            .await
            .map_err(|_| IdentityError::Timeout)?
            .map(|_| ())
            .map_err(|_| IdentityError::Connection)
    }
}

fn validate_message(message: &[u8]) -> Result<(), IdentityError> {
    if message.is_empty() || message.len() > MAX_IDENTITY_MESSAGE_BYTES {
        return Err(IdentityError::InvalidMessage);
    }
    Ok(())
}

fn encode_packet(packet: &IdentityPacket) -> Result<Vec<u8>, IdentityError> {
    let descriptor = packet.identity().descriptor_bytes();
    let descriptor_length =
        u16::try_from(descriptor.len()).map_err(|_| IdentityError::InvalidIdentity)?;
    let mut output = Vec::with_capacity(MAX_DESCRIPTOR_BYTES + 128);
    output.extend_from_slice(WIRE_MAGIC);
    output.push(match packet {
        IdentityPacket::PublicIdentity(_) => PUBLIC_IDENTITY_TAG,
        IdentityPacket::SignedMessage(_) => SIGNED_MESSAGE_TAG,
    });
    output.extend_from_slice(&descriptor_length.to_be_bytes());
    output.extend_from_slice(&descriptor);
    if let IdentityPacket::SignedMessage(message) = packet {
        validate_message(message.message())?;
        let message_length =
            u32::try_from(message.message().len()).map_err(|_| IdentityError::InvalidMessage)?;
        output.extend_from_slice(&message_length.to_be_bytes());
        output.extend_from_slice(message.message());
        output.extend_from_slice(message.signature());
    }
    Ok(output)
}

fn decode_packet(input: &[u8]) -> Result<IdentityPacket, IdentityError> {
    if !input.starts_with(WIRE_MAGIC) {
        return Err(IdentityError::Codec);
    }
    let mut cursor = WIRE_MAGIC.len();
    let tag = take(input, &mut cursor, 1)?[0];
    let descriptor_length = usize::from(u16::from_be_bytes(
        take(input, &mut cursor, 2)?
            .try_into()
            .map_err(|_| IdentityError::Codec)?,
    ));
    if descriptor_length == 0 || descriptor_length > MAX_DESCRIPTOR_BYTES {
        return Err(IdentityError::Limit);
    }
    let descriptor_bytes = take(input, &mut cursor, descriptor_length)?;
    let descriptor =
        RawKeyDescriptor::decode(descriptor_bytes).map_err(|_| IdentityError::InvalidIdentity)?;
    if descriptor.encode() != descriptor_bytes {
        return Err(IdentityError::Codec);
    }
    let identity = PublicIdentity::from_descriptor(descriptor)?;
    match tag {
        PUBLIC_IDENTITY_TAG => {
            if cursor != input.len() {
                return Err(IdentityError::Codec);
            }
            Ok(IdentityPacket::PublicIdentity(identity))
        }
        SIGNED_MESSAGE_TAG => {
            let message_length = usize::try_from(u32::from_be_bytes(
                take(input, &mut cursor, 4)?
                    .try_into()
                    .map_err(|_| IdentityError::Codec)?,
            ))
            .map_err(|_| IdentityError::Limit)?;
            if message_length == 0 || message_length > MAX_IDENTITY_MESSAGE_BYTES {
                return Err(IdentityError::Limit);
            }
            let message = take(input, &mut cursor, message_length)?.to_vec();
            let signature: [u8; ED25519_SIGNATURE_BYTES] =
                take(input, &mut cursor, ED25519_SIGNATURE_BYTES)?
                    .try_into()
                    .map_err(|_| IdentityError::Codec)?;
            if cursor != input.len() {
                return Err(IdentityError::Codec);
            }
            Ok(IdentityPacket::SignedMessage(SignedIdentityMessage::new(
                identity, message, signature,
            )?))
        }
        _ => Err(IdentityError::Protocol),
    }
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], IdentityError> {
    let end = cursor.checked_add(length).ok_or(IdentityError::Limit)?;
    let value = input.get(*cursor..end).ok_or(IdentityError::Codec)?;
    *cursor = end;
    Ok(value)
}

async fn write_frame(
    send: &mut SendStream,
    payload: &[u8],
    deadline: Duration,
) -> Result<(), IdentityError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(IdentityError::Limit);
    }
    let length = u32::try_from(payload.len()).map_err(|_| IdentityError::Limit)?;
    timeout(deadline, async {
        send.write_all(&length.to_be_bytes())
            .await
            .map_err(|_| IdentityError::Connection)?;
        send.write_all(payload)
            .await
            .map_err(|_| IdentityError::Connection)
    })
    .await
    .map_err(|_| IdentityError::Timeout)?
}

async fn read_frame(recv: &mut RecvStream, deadline: Duration) -> Result<Vec<u8>, IdentityError> {
    timeout(deadline, async {
        let mut length = [0_u8; 4];
        recv.read_exact(&mut length)
            .await
            .map_err(|_| IdentityError::Connection)?;
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| IdentityError::Limit)?;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(IdentityError::Limit);
        }
        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload)
            .await
            .map_err(|_| IdentityError::Connection)?;
        Ok(payload)
    })
    .await
    .map_err(|_| IdentityError::Timeout)?
}

fn classify_target(target: &EndpointAddr) -> PathObservation {
    match (
        target.ip_addrs().next().is_some(),
        target.relay_urls().next().is_some(),
    ) {
        (true, false) => PathObservation::Direct,
        (false, true) => PathObservation::Relayed,
        _ => PathObservation::MixedOrUnknown,
    }
}

/// Typed identity model, wire, signature, sequence, and transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// I/O deadline is zero or exceeds sixty seconds.
    Configuration,
    /// Public identity is malformed or is not Ed25519.
    InvalidIdentity,
    /// Application message is empty or exceeds its hard bound.
    InvalidMessage,
    /// Ed25519 verification failed.
    InvalidSignature,
    /// Wire message is malformed or non-canonical.
    Codec,
    /// Declared or actual input exceeds a hard bound.
    Limit,
    /// Iroh discovery, handshake, or stream I/O failed.
    Connection,
    /// I/O deadline elapsed.
    Timeout,
    /// Protocol version, ALPN, or packet tag is unsupported.
    Protocol,
    /// The one-request/one-response sequence was violated.
    Sequence,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid identity transport configuration",
            Self::InvalidIdentity => "invalid Ed25519 public identity",
            Self::InvalidMessage => "invalid identity message length",
            Self::InvalidSignature => "identity message signature is invalid",
            Self::Codec => "invalid canonical identity message",
            Self::Limit => "identity message resource limit exceeded",
            Self::Connection => "Iroh identity transport failed",
            Self::Timeout => "Iroh identity transport timed out",
            Self::Protocol => "unsupported identity transport protocol",
            Self::Sequence => "invalid identity exchange sequence",
        })
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signed(message: &[u8]) -> SignedIdentityMessage {
        let key = SigningKey::from_bytes(&[7; 32]);
        let identity = PublicIdentity::from_ed25519(key.verifying_key().to_bytes()).unwrap();
        let preimage = SignedIdentityMessage::signing_preimage(&identity, message).unwrap();
        SignedIdentityMessage::new(identity, message.to_vec(), key.sign(&preimage).to_bytes())
            .unwrap()
    }

    #[test]
    fn public_identity_round_trip_is_canonical() {
        let identity = PublicIdentity::from_ed25519([3; 32]).unwrap();
        let packet = IdentityPacket::PublicIdentity(identity);
        assert_eq!(
            decode_packet(&encode_packet(&packet).unwrap()).unwrap(),
            packet
        );
    }

    #[test]
    fn signed_message_round_trip_verifies_and_binds_every_byte() {
        let signed = signed(b"hello over iroh");
        signed.verify().unwrap();
        let packet = IdentityPacket::SignedMessage(signed.clone());
        assert_eq!(
            decode_packet(&encode_packet(&packet).unwrap()).unwrap(),
            packet
        );

        let tampered = SignedIdentityMessage::new(
            signed.identity().clone(),
            b"hello over iroH".to_vec(),
            *signed.signature(),
        )
        .unwrap();
        assert_eq!(tampered.verify(), Err(IdentityError::InvalidSignature));
    }

    #[test]
    fn decoder_rejects_trailing_and_oversized_input() {
        let mut encoded = encode_packet(&IdentityPacket::SignedMessage(signed(b"hello"))).unwrap();
        encoded.push(0);
        assert_eq!(decode_packet(&encoded), Err(IdentityError::Codec));
        assert_eq!(
            SignedIdentityMessage::signing_preimage(
                &PublicIdentity::from_ed25519([1; 32]).unwrap(),
                &vec![0; MAX_IDENTITY_MESSAGE_BYTES + 1],
            ),
            Err(IdentityError::InvalidMessage)
        );
    }
}
