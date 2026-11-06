//! Participant control is native evidence transport, never a second enrollment
//! authority. The app cannot install roots, trust, clocks or capacities.
use super::*;
use crate::{EngagementControlEvidence, ParticipantControlOutcome};

/// Signed enrollment or subtree withdrawal under the independently installed root.
pub const APP_PARTICIPANT_SCHEMA: &str = "auths.gateway-participant-control/1";

/// Original native control bytes; client JSON serialization defines no identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppParticipantControl {
    /// Must equal `APP_PARTICIPANT_SCHEMA`.
    pub schema: String,
    /// Native canonical control evidence, unpadded base64url. No root pins,
    /// verifier context, approval key or clock is accepted through this field.
    pub evidence_b64: String,
}
impl Drop for AppParticipantControl {
    fn drop(&mut self) {
        self.evidence_b64.zeroize();
    }
}
impl AppParticipantControl {
    /// Decodes bounded transport data and checks the operator-only root boundary.
    /// # Errors
    /// Refuses obsolete frames, malformed evidence and root bootstrap requests.
    pub fn decode(&self) -> Result<EngagementControlEvidence, &'static str> {
        if self.schema != APP_PARTICIPANT_SCHEMA {
            return Err("gateway.submit.invalid-frame");
        }
        if self.evidence_b64.len() > crate::MAX_ENGAGEMENT_CONTROL_BYTES.div_ceil(3) * 4 {
            return Err("gateway.engagement.invalid-frame");
        }
        let bytes = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&self.evidence_b64)
                .map_err(|_| "gateway.engagement.invalid-frame")?,
        );
        if Base64UrlUnpadded::encode_string(&bytes) != self.evidence_b64 {
            return Err("gateway.engagement.invalid-frame");
        }
        let evidence = EngagementControlEvidence::from_private_bytes(&bytes)
            .map_err(|_| "gateway.engagement.invalid-frame")?;
        if evidence.is_root() {
            return Err("gateway.engagement.operator-required");
        }
        Ok(evidence)
    }
}

pub(super) async fn control(
    request: AppParticipantControl,
    application: &impl GatewayApplication,
) -> Vec<u8> {
    let outcome = match request.decode() {
        Ok(evidence) => application.participant_control(evidence).await,
        Err(code) => ParticipantControlOutcome::refused(code),
    };
    serde_json::to_vec(&outcome).unwrap_or_default()
}
