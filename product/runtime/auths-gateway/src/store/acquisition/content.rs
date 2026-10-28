//! Private deterministic projection and hiding commitment over retained content.
//! This module cannot obtain credentials, fetch bytes or grant disclosure.
use super::*;
use crate::recipe::ContentProjectionError;
use hmac::{Hmac, Mac as _};
use zeroize::{Zeroize as _, Zeroizing};

type ContentMac = Hmac<sha2::Sha256>;
pub(crate) const PROTECTED_CONTENT_SCHEMA: &str = "auths.gateway-protected-content/1";

/// Public response interpretation without plaintext, key or correlation digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ContentProjectionStatus {
    /// Exact projected bytes are reconstructible from private retained evidence.
    Ready { bytes: u64 },
    /// The complete response was retained, but cannot be disclosed as content.
    Rejected { code: String },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ContentResult {
    Ready(ProtectedContent),
    Rejected(ContentProjectionError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectedContent {
    schema: String,
    key: [u8; 32],
    commitment: [u8; 32],
    bytes: u64,
}

impl Drop for ProtectedContent {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ContentResult {
    pub(super) fn create(
        binding: &EffectBinding,
        plan: &crate::effect::ContentPlan,
        response: &AcquisitionResponse,
        metadata: &crate::transport::ContentResponseMetadata,
    ) -> Result<Self, GatewayAttemptError> {
        match project(plan, response, metadata)? {
            Ok(bytes) => {
                let mut key = Zeroizing::new([0; 32]);
                getrandom::fill(key.as_mut()).map_err(|_| GatewayAttemptError::Unavailable)?;
                let message = message(binding, plan, &bytes)?;
                let mut mac = ContentMac::new_from_slice(key.as_ref())
                    .map_err(|_| GatewayAttemptError::Corrupt)?;
                mac.update(&message);
                Ok(Self::Ready(ProtectedContent {
                    schema: PROTECTED_CONTENT_SCHEMA.to_owned(),
                    key: *key,
                    commitment: mac.finalize().into_bytes().into(),
                    bytes: bytes.len() as u64,
                }))
            }
            Err(reason) => Ok(Self::Rejected(reason)),
        }
    }

    pub(super) fn validate(
        &self,
        binding: &EffectBinding,
        plan: &crate::effect::ContentPlan,
        response: &AcquisitionResponse,
        metadata: &crate::transport::ContentResponseMetadata,
    ) -> Result<(), GatewayAttemptError> {
        match (self, project(plan, response, metadata)?) {
            (Self::Rejected(expected), Err(actual)) if *expected == actual => Ok(()),
            (Self::Ready(stored), Ok(bytes))
                if stored.schema == PROTECTED_CONTENT_SCHEMA
                    && stored.bytes == bytes.len() as u64 =>
            {
                let mut mac = ContentMac::new_from_slice(&stored.key)
                    .map_err(|_| GatewayAttemptError::Corrupt)?;
                mac.update(&message(binding, plan, &bytes)?);
                mac.verify_slice(&stored.commitment)
                    .map_err(|_| GatewayAttemptError::Corrupt)
            }
            _ => Err(GatewayAttemptError::Corrupt),
        }
    }

    pub(super) fn status(&self) -> ContentProjectionStatus {
        match self {
            Self::Ready(value) => ContentProjectionStatus::Ready { bytes: value.bytes },
            Self::Rejected(reason) => ContentProjectionStatus::Rejected {
                code: reason.code().to_owned(),
            },
        }
    }
}

fn project(
    plan: &crate::effect::ContentPlan,
    response: &AcquisitionResponse,
    metadata: &crate::transport::ContentResponseMetadata,
) -> Result<Result<Zeroizing<Vec<u8>>, ContentProjectionError>, GatewayAttemptError> {
    let capacity = plan.capacity().map_err(|_| GatewayAttemptError::Corrupt)?;
    let body = response.body(&capacity)?;
    let projection = plan
        .projection()
        .map_err(|_| GatewayAttemptError::Corrupt)?;
    if !response.version_ok {
        return Ok(Err(ContentProjectionError::Version));
    }
    let media = match metadata.projection_media_type() {
        Ok(media) => media,
        Err(error) => return Ok(Err(error)),
    };
    Ok(projection.project(response.status, media, &body))
}

/// The plain digest is private input to the keyed commitment and is never a
/// public content identifier. Fixed-size native canonical inputs also support
/// the full 65,536-byte content bound without JSON byte-array expansion.
fn message(
    binding: &EffectBinding,
    plan: &crate::effect::ContentPlan,
    bytes: &[u8],
) -> Result<[u8; 32], GatewayAttemptError> {
    let private_digest = auths_codec::domain_commitment("auths.gateway-content-bytes/1", bytes)
        .map_err(|_| GatewayAttemptError::Corrupt)?;
    let payload = Zeroizing::new(canonical(&(
        binding.id().as_bytes(),
        plan.projection_commitment()
            .map_err(|_| GatewayAttemptError::Corrupt)?,
        bytes.len() as u64,
        private_digest.as_bytes(),
    ))?);
    auths_codec::domain_commitment(PROTECTED_CONTENT_SCHEMA, &payload)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| GatewayAttemptError::Corrupt)
}
