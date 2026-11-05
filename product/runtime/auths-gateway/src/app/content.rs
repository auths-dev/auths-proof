//! Closed content application envelopes. These carry native authority or history;
//! they never interpret resources, count capacity, hash effects or decide retries.
use super::*;
use crate::effect::{DisclosureAcknowledgement, UnixDisclosurePolicy};

/// Independently approved content acquisition from the signed action itself.
pub const APP_CONTENT_SCHEMA: &str = "auths.gateway-content/1";
/// Separate recipient disclosure with an owned local channel.
pub const APP_DISCLOSURE_SCHEMA: &str = "auths.gateway-disclose/1";
/// Redacted local content/disclosure history without external I/O.
pub const APP_CONTENT_HISTORY_SCHEMA: &str = "auths.gateway-content-history/1";
/// Historical recipient evidence; never a new delivery request.
pub const APP_DISCLOSURE_ACK_SCHEMA: &str = "auths.gateway-disclosure-acknowledge/1";

/// No second resource map accompanies the signed native action.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppContent {
    /// Must equal `APP_CONTENT_SCHEMA`.
    pub schema: String,
    /// Independently verified read authority and exact approval.
    pub submission: AppSubmission,
}
impl AppContent {
    /// Decodes bounded transport data; no authority is inferred here.
    ///
    /// # Errors
    /// Refuses obsolete schemas and malformed native envelopes.
    pub fn decode(&self) -> Result<DecodedSubmission, &'static str> {
        if self.schema != APP_CONTENT_SCHEMA {
            return Err("gateway.submit.invalid-frame");
        }
        self.submission.decode()
    }
}

/// Proposed recipient address. The native target/compiler binds it to the
/// retained source and exact proof/approval before entry.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppDisclosureTarget {
    /// Retained acquisition in the installed recipe/partition.
    pub source_operation: String,
    /// Raw Ed25519 public key, never a credential or signing seed.
    pub recipient_key: [u8; 32],
    /// Exact UID/channel policy committed by the approved effect.
    pub channel: UnixDisclosurePolicy,
    /// Explicit delivery instance committed by the approved effect.
    pub delivery_instance: [u8; 32],
}
impl AppDisclosureTarget {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        crate::LogicalOperationId::parse(&self.source_operation)
            .map_err(|_| "gateway.submit.invalid-frame")?;
        self.channel.commitment()?;
        Ok(())
    }
    /// Loads native retained provenance for this proposal. This establishes no
    /// release authority, approval or live recipient authentication.
    ///
    /// # Errors
    /// Refuses invalid/foreign/unavailable content and invalid channel or key.
    pub async fn resolve(
        &self,
        engine: &GatewayEngine,
    ) -> Result<crate::effect::DisclosureTarget, GatewaySubmitResult> {
        engine
            .disclosure_target(
                &self.source_operation,
                self.recipient_key,
                self.channel
                    .commitment()
                    .map_err(|code| GatewaySubmitResult::NotEntered {
                        code: code.to_owned(),
                    })?,
                self.delivery_instance,
            )
            .await
    }
}

/// After admission this request switches the owned socket to native disclosure
/// authentication/content/ACK frames. `Ready` is not a delivery grant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppDisclosure {
    /// Must equal `APP_DISCLOSURE_SCHEMA`.
    pub schema: String,
    /// Proposed exact recipient/source identity, checked against native authority.
    pub target: AppDisclosureTarget,
    /// Independent disclosure proof and exact approval.
    pub submission: AppSubmission,
}
impl AppDisclosure {
    /// Decodes closed bounded transport data without authenticating a peer.
    ///
    /// # Errors
    /// Refuses malformed address, schema or native envelope.
    pub fn decode(&self) -> Result<DecodedSubmission, &'static str> {
        if self.schema != APP_DISCLOSURE_SCHEMA {
            return Err("gateway.submit.invalid-frame");
        }
        self.target.validate()?;
        self.submission.decode()
    }
}

/// Local redacted history. This carries no provider or disclosure permission.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppContentHistory {
    /// Must equal `APP_CONTENT_HISTORY_SCHEMA`.
    pub schema: String,
    /// Logical operation in the installed recipe/partition.
    pub operation: String,
}
impl AppContentHistory {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.schema != APP_CONTENT_HISTORY_SCHEMA
            || crate::LogicalOperationId::parse(&self.operation).is_err()
        {
            return Err("gateway.submit.invalid-frame");
        }
        Ok(())
    }
}

/// Exact late recipient evidence. A valid signature alone cannot invent a grant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppDisclosureAcknowledgement {
    /// Must equal `APP_DISCLOSURE_ACK_SCHEMA`.
    pub schema: String,
    /// Original disclosure operation in this installation.
    pub operation: String,
    /// Canonical native ACK, unpadded base64url, at most 4,096 decoded bytes.
    pub acknowledgement_b64: String,
}
impl AppDisclosureAcknowledgement {
    /// Decodes bounded evidence; retained native binding/grant checks remain required.
    ///
    /// # Errors
    /// Refuses malformed schema, operation, encoding or native ACK.
    pub fn decode(&self) -> Result<DisclosureAcknowledgement, &'static str> {
        if self.schema != APP_DISCLOSURE_ACK_SCHEMA
            || crate::LogicalOperationId::parse(&self.operation).is_err()
            || self.acknowledgement_b64.len() > (4096 * 4_usize).div_ceil(3)
        {
            return Err("gateway.submit.invalid-frame");
        }
        let bytes = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&self.acknowledgement_b64)
                .map_err(|_| "gateway.disclosure.acknowledgement")?,
        );
        DisclosureAcknowledgement::from_private_bytes(&bytes)
            .map_err(|_| "gateway.disclosure.acknowledgement")
    }
}
impl Drop for AppDisclosureAcknowledgement {
    fn drop(&mut self) {
        self.acknowledgement_b64.zeroize();
    }
}

/// Native redacted result, or permission to begin authentication only.
#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AppContentResult {
    /// The stream is switching to native authentication; no grant or bytes yet.
    Ready,
    /// Retained native facts, with acquisition and disclosure kept distinct.
    History {
        /// Redacted history. Decoding never creates a runtime capability.
        history: crate::ContentHistory,
    },
    /// Native refusal or unavailable state, never permission to retry a grant.
    Refused {
        /// Original native stage and stable code.
        result: GatewaySubmitResult,
    },
}
impl AppContentResult {
    pub(super) fn refused(code: &'static str) -> Self {
        Self::Refused {
            result: GatewaySubmitResult::NotEntered {
                code: code.to_owned(),
            },
        }
    }
}

pub(super) async fn acquire(request: AppContent, application: &impl GatewayApplication) -> Vec<u8> {
    let result = match request.decode() {
        Ok(decoded) => application.acquire_content(decoded).await,
        Err(code) => AppContentResult::refused(code),
    };
    serde_json::to_vec(&result).unwrap_or_default()
}
pub(super) async fn history(
    request: AppContentHistory,
    application: &impl GatewayApplication,
) -> Vec<u8> {
    let result = match request.validate() {
        Ok(()) => application.content_history(&request.operation).await,
        Err(code) => AppContentResult::refused(code),
    };
    serde_json::to_vec(&result).unwrap_or_default()
}
pub(super) async fn acknowledge(
    request: AppDisclosureAcknowledgement,
    application: &impl GatewayApplication,
) -> Vec<u8> {
    let result = match request.decode() {
        Ok(ack) => {
            application
                .acknowledge_disclosure(&request.operation, ack)
                .await
        }
        Err(code) => AppContentResult::refused(code),
    };
    serde_json::to_vec(&result).unwrap_or_default()
}

pub(super) async fn disclose(
    request: AppDisclosure,
    stream: UnixStream,
    application: &impl GatewayApplication,
    clock: SessionClock,
) {
    match request.decode() {
        Ok(decoded) => {
            application
                .disclose_content(request.target, decoded, stream, clock)
                .await;
        }
        Err(code) => {
            let mut stream = stream;
            if let Ok(bytes) = serde_json::to_vec(&AppContentResult::refused(code)) {
                let _ = clock.write_frame(&mut stream, &bytes).await;
            }
        }
    }
}

pub(super) async fn engine_disclose(
    engine: &GatewayEngine,
    target: AppDisclosureTarget,
    decoded: DecodedSubmission,
    stream: UnixStream,
    clock: SessionClock,
) {
    // Admission is an existing native operation, not an application decision.
    // It returns only a reservation/history; the later engine call repeats all
    // current checks and owns the unique authenticated grant.
    let prepare = async {
        let native = target.resolve(engine).await?;
        let snapshot = engine
            .admit_disclosure(
                &native,
                &decoded.proof,
                &decoded.action,
                decoded.approval.clone(),
            )
            .await?;
        Ok::<_, GatewaySubmitResult>((native, snapshot))
    };
    let Some((mut stream, prepared)) = clock.complete(stream, prepare).await else {
        return;
    };
    let (native, response) = match prepared {
        Ok((native, snapshot)) if snapshot.stage == crate::DisclosureStage::Reserved => {
            (Some(native), AppContentResult::Ready)
        }
        Ok((_, snapshot)) => (
            None,
            AppContentResult::History {
                history: crate::ContentHistory::Disclosure(snapshot),
            },
        ),
        Err(result) => (None, AppContentResult::Refused { result }),
    };
    let Ok(bytes) = serde_json::to_vec(&response) else {
        return;
    };
    if clock.write_frame(&mut stream, &bytes).await.is_err() {
        return;
    }
    let Some(native) = native else {
        return;
    };
    let connection = crate::disclosure_transport::DisclosureConnection::new(stream, target.channel)
        .within(clock.deadline);
    // Once handed over, the transport owns framing and the finite deadline.
    // ACK submission is not a persistence acknowledgement; callers use a fresh
    // history query after completion/loss, never an implicit redelivery request.
    let _ = engine
        .disclose(
            &native,
            &decoded.proof,
            &decoded.action,
            decoded.approval,
            connection,
        )
        .await;
}

/// Result of the native application client. A retained history/refusal contains
/// no received bytes and never authorizes automatic redelivery.
pub enum AppDisclosureReception {
    /// Exact plaintext received through the authenticated native transport.
    Received(Box<crate::disclosure_transport::ReceivedDisclosure>),
    /// The operation already has retained history; no handshake/send occurred.
    History(crate::DisclosureSnapshot),
    /// Native pre-handshake refusal.
    Refused(GatewaySubmitResult),
}

/// Sends a disclosure request only after checking the pinned gateway UID, then
/// handles the closed protocol switch. `expected` comes from the trusted private
/// approval channel, never from the server's Ready response. ACK is explicit on
/// the returned received value. After channel loss, query history or record a
/// retained exact ACK; do not automatically repeat delivery.
///
/// # Errors
/// Refuses mismatched channel/key, invalid envelope/control frames, deadlines and
/// the native recipient protocol's errors. Returns no partial plaintext.
pub async fn receive_content_disclosure(
    mut stream: UnixStream,
    request: &AppDisclosure,
    expected: &crate::effect::EffectBinding,
    bytes: u64,
    key: &ed25519_dalek::SigningKey,
) -> Result<AppDisclosureReception, &'static str> {
    request.target.channel.matches(expected)?;
    request.target.channel.recipient_peer(&stream)?;
    if request.target.recipient_key != key.verifying_key().to_bytes() {
        return Err("gateway.disclosure.authentication");
    }
    request.decode()?;
    let clock = SessionClock::start(APP_SESSION_LIMITS);
    let encoded =
        Zeroizing::new(serde_json::to_vec(request).map_err(|_| "gateway.submit.invalid-frame")?);
    clock.write_frame(&mut stream, &encoded).await?;
    let response = Zeroizing::new(
        timeout_at(
            clock
                .deadline
                .min(Instant::now() + clock.limits.result_wait),
            super::read_frame_limited(&mut stream, 4096),
        )
        .await
        .map_err(|_| "gateway.ipc.read-timeout")??,
    );
    let response: AppContentResult =
        serde_json::from_slice(&response).map_err(|_| "gateway.submit.invalid-response")?;
    match response {
        AppContentResult::Ready => crate::disclosure_transport::receive_disclosure(
            crate::disclosure_transport::DisclosureConnection::new(
                stream,
                request.target.channel.clone(),
            )
            .within(clock.deadline),
            expected,
            bytes,
            key,
        )
        .await
        .map(Box::new)
        .map(AppDisclosureReception::Received),
        AppContentResult::History {
            history: crate::ContentHistory::Disclosure(snapshot),
        } => Ok(AppDisclosureReception::History(snapshot)),
        AppContentResult::History { .. } => Err("gateway.submit.invalid-response"),
        AppContentResult::Refused { result } => Ok(AppDisclosureReception::Refused(result)),
    }
}
