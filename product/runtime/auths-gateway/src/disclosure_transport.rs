//! Local recipient authentication and one-use disclosure transport. UID checks
//! rely on host isolation; proof, approval and durable entry remain independent.
pub use crate::effect::UnixDisclosurePolicy;
use crate::effect::disclosure_auth::{
    AUTH_SCHEMA, Challenge, MAX_AUTH_BYTES, RecipientAuthentication, Response, bounded, decode,
};
use crate::effect::{
    DisclosureAcknowledgement, DisclosureAcknowledgementRequest, EffectBinding, EffectId,
};
use ed25519_dalek::{Signer as _, SigningKey};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    time::{Duration, Instant, timeout_at},
};
use zeroize::Zeroizing;
const MAX_CONTENT_BYTES: usize = 65_536;
const AUTH_SECONDS: u64 = 5;
const SESSION_SECONDS: u64 = 15;

impl UnixDisclosurePolicy {
    fn server_peer(&self, stream: &UnixStream) -> Result<(), &'static str> {
        self.peer(stream, self.gateway_uid(), self.recipient_uid())
    }
    pub(crate) fn recipient_peer(&self, stream: &UnixStream) -> Result<(), &'static str> {
        self.peer(stream, self.recipient_uid(), self.gateway_uid())
    }
    fn peer(&self, stream: &UnixStream, local: u32, remote: u32) -> Result<(), &'static str> {
        if rustix::process::geteuid().as_raw() != local
            || stream
                .peer_cred()
                .map_err(|_| "gateway.disclosure.peer")?
                .uid()
                != remote
        {
            return Err("gateway.disclosure.peer");
        }
        Ok(())
    }
}

/// An unchecked owned local connection and proposed channel policy. Constructing
/// this cannot authenticate the peer or grant access to retained content.
pub struct DisclosureConnection {
    stream: UnixStream,
    policy: UnixDisclosurePolicy,
    deadline: Option<Instant>,
}
impl DisclosureConnection {
    /// Transfers the stream into the closed disclosure protocol.
    #[must_use]
    pub fn new(stream: UnixStream, policy: UnixDisclosurePolicy) -> Self {
        Self {
            stream,
            policy,
            deadline: None,
        }
    }
    pub(crate) fn within(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

pub(crate) struct AuthenticatedDisclosureChannel {
    stream: UnixStream,
    authentication: RecipientAuthentication,
    effect: EffectId,
    deadline: Instant,
}

impl AuthenticatedDisclosureChannel {
    pub(crate) async fn authenticate(
        connection: DisclosureConnection,
        binding: &EffectBinding,
        bytes: u64,
        key: [u8; 32],
    ) -> Result<Self, &'static str> {
        let DisclosureConnection {
            mut stream,
            policy,
            deadline: session_deadline,
        } = connection;
        policy.matches(binding)?;
        policy.server_peer(&stream)?;
        let start = Instant::now();
        let deadline = session_deadline
            .map_or(start + Duration::from_secs(SESSION_SECONDS), |limit| {
                limit.min(start + Duration::from_secs(SESSION_SECONDS))
            });
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "gateway.disclosure.authentication")?;
        let challenge = Challenge {
            schema: AUTH_SCHEMA.to_owned(),
            nonce,
            delivery: DisclosureAcknowledgementRequest::for_delivery(binding, bytes, key)
                .map_err(|_| "gateway.disclosure.authentication")?,
        };
        let response = timeout_at(
            deadline.min(start + Duration::from_secs(AUTH_SECONDS)),
            async {
                write_frame(&mut stream, &bounded(&challenge)?, MAX_AUTH_BYTES).await?;
                decode::<Response>(&read_frame(&mut stream, MAX_AUTH_BYTES).await?)
            },
        )
        .await
        .map_err(|_| "gateway.disclosure.timeout")??;
        let authentication = RecipientAuthentication {
            policy,
            challenge,
            response,
        };
        authentication.validate(binding, bytes, key)?;
        Ok(Self {
            stream,
            authentication,
            effect: binding.id(),
            deadline,
        })
    }
    pub(crate) fn validate(
        &self,
        binding: &EffectBinding,
        bytes: u64,
        key: [u8; 32],
    ) -> Result<(), &'static str> {
        if self.effect != binding.id() || Instant::now() >= self.deadline {
            return Err("gateway.disclosure.timeout");
        }
        self.authentication.policy.server_peer(&self.stream)?;
        self.authentication.validate(binding, bytes, key)
    }
    pub(crate) fn evidence(&self) -> RecipientAuthentication {
        self.authentication.clone()
    }
    async fn deliver(mut self, content: Zeroizing<Vec<u8>>) -> Option<DisclosureAcknowledgement> {
        timeout_at(self.deadline, async {
            write_frame(&mut self.stream, &content, MAX_CONTENT_BYTES).await?;
            let bytes = read_frame(&mut self.stream, MAX_AUTH_BYTES).await?;
            DisclosureAcknowledgement::from_private_bytes(&bytes)
                .map_err(|_| "gateway.disclosure.acknowledgement")
        })
        .await
        .ok()?
        .ok()
    }
}

/// Recipient-side result from an authenticated local gateway. Only this client
/// API exposes the received plaintext; gateway journal/review APIs do not.
pub struct ReceivedDisclosure {
    content: Zeroizing<Vec<u8>>,
    stream: UnixStream,
    statement: DisclosureAcknowledgementRequest,
    deadline: Instant,
    recipient_key: [u8; 32],
}

impl ReceivedDisclosure {
    /// Exact received bytes, including a valid empty projection.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
    /// Produces private historical evidence after receipt. Retain it privately
    /// for late acknowledgement if the channel is lost; it grants no redelivery.
    ///
    /// # Errors
    /// Refuses a signing failure or a key inconsistent with the received statement.
    pub fn acknowledgement(
        &self,
        key: &SigningKey,
    ) -> Result<DisclosureAcknowledgement, &'static str> {
        if key.verifying_key().to_bytes() != self.recipient_key {
            return Err("gateway.disclosure.acknowledgement");
        }
        let message = self
            .statement
            .signing_message()
            .map_err(|_| "gateway.disclosure.acknowledgement")?;
        Ok(self
            .statement
            .clone()
            .with_signature(key.sign(&message).to_bytes()))
    }
    /// Sends the exact native ACK. Failure leaves delivery uncertain at the
    /// gateway and does not authorize sending content again.
    ///
    /// # Errors
    /// Returns a bounded transport/encoding failure.
    pub async fn acknowledge(mut self, key: &SigningKey) -> Result<(), &'static str> {
        let ack = self
            .acknowledgement(key)?
            .to_private_bytes()
            .map_err(|_| "gateway.disclosure.acknowledgement")?;
        timeout_at(
            self.deadline,
            write_frame(&mut self.stream, &ack, MAX_AUTH_BYTES),
        )
        .await
        .map_err(|_| "gateway.disclosure.timeout")?
    }
}

/// Authenticates the local gateway UID and exact expected effect, proves fresh
/// recipient key possession, then receives exactly the approved number of bytes.
/// The caller supplies its trusted expected binding/policy, never values copied
/// uncritically from the incoming challenge. No ACK is sent until requested.
///
/// # Errors
/// Refuses peer, channel, binding, malformed/oversized frames, wrong length and
/// bounded deadline failures. No partial content is returned on failure.
pub async fn receive_disclosure(
    connection: DisclosureConnection,
    binding: &EffectBinding,
    bytes: u64,
    key: &SigningKey,
) -> Result<ReceivedDisclosure, &'static str> {
    let DisclosureConnection {
        mut stream,
        policy,
        deadline: session_deadline,
    } = connection;
    policy.matches(binding)?;
    policy.recipient_peer(&stream)?;
    let expected = DisclosureAcknowledgementRequest::for_delivery(
        binding,
        bytes,
        key.verifying_key().to_bytes(),
    )
    .map_err(|_| "gateway.disclosure.authentication")?;
    let start = Instant::now();
    let deadline = session_deadline.map_or(start + Duration::from_secs(SESSION_SECONDS), |limit| {
        limit.min(start + Duration::from_secs(SESSION_SECONDS))
    });
    let challenge = timeout_at(
        deadline.min(start + Duration::from_secs(AUTH_SECONDS)),
        async {
            let challenge: Challenge = decode(&read_frame(&mut stream, MAX_AUTH_BYTES).await?)?;
            if challenge.delivery != expected {
                return Err("gateway.disclosure.authentication");
            }
            let response = Response::sign(&challenge, key)?;
            write_frame(&mut stream, &bounded(&response)?, MAX_AUTH_BYTES).await?;
            Ok::<_, &'static str>(challenge)
        },
    )
    .await
    .map_err(|_| "gateway.disclosure.timeout")??;
    let content = timeout_at(
        deadline,
        read_frame(
            &mut stream,
            usize::try_from(bytes).map_err(|_| "gateway.disclosure.length")?,
        ),
    )
    .await
    .map_err(|_| "gateway.disclosure.timeout")??;
    if content.len() as u64 != bytes {
        return Err("gateway.disclosure.length");
    }
    Ok(ReceivedDisclosure {
        content,
        stream,
        statement: challenge.delivery,
        deadline,
        recipient_key: key.verifying_key().to_bytes(),
    })
}

async fn read_frame(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "gateway.disclosure.read")? as usize;
    if maximum > MAX_CONTENT_BYTES || length > maximum {
        return Err("gateway.disclosure.frame");
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "gateway.disclosure.read")?;
    Ok(bytes)
}
async fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), &'static str> {
    if bytes.len() > maximum || maximum > MAX_CONTENT_BYTES {
        return Err("gateway.disclosure.frame");
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| "gateway.disclosure.frame")?)
        .await
        .map_err(|_| "gateway.disclosure.write")?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| "gateway.disclosure.write")
}

/// The only production content send accepts a newly granted one-use permit.
pub(crate) async fn deliver(
    permit: crate::store::DisclosureEntryPermit,
) -> Option<DisclosureAcknowledgement> {
    let (channel, content) = permit.into_delivery();
    channel.deliver(content).await
}
