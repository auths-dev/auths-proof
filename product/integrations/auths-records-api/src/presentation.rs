//! Short-lived presenter-bound proof presentation.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    RecordsError,
    canonical::{canonical_json, sha256},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationInputV1 {
    pub presentation_version: String,
    pub proof_digest: String,
    pub presenter_principal: String,
    pub executor_audience: String,
    pub operation_id: String,
    pub canonical_action_digest: String,
    pub challenge: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub presentation_nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsPresentationV1 {
    pub input: PresentationInputV1,
    pub presenter_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationClaimsV1 {
    pub operation_id: String,
    pub canonical_action_digest: String,
    pub challenge: [u8; 32],
    pub executor_audience: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub presentation_nonce: String,
}

impl RecordsPresentationV1 {
    pub fn sign(
        signing_key: &SigningKey,
        proof: &[u8],
        claims: &PresentationClaimsV1,
    ) -> Result<Self, RecordsError> {
        let public_key = signing_key.verifying_key().to_bytes();
        let presenter_principal = format!("key:ed25519:{}", hex::encode(public_key));
        let input = PresentationInputV1 {
            presentation_version: "auths.records-presentation/1".into(),
            proof_digest: sha256(proof),
            presenter_principal,
            executor_audience: claims.executor_audience.clone(),
            operation_id: claims.operation_id.clone(),
            canonical_action_digest: claims.canonical_action_digest.clone(),
            challenge: hex::encode(claims.challenge),
            created_at: claims.created_at,
            expires_at: claims.expires_at,
            presentation_nonce: claims.presentation_nonce.clone(),
        };
        let signature = signing_key.sign(&canonical_json(&input)?);
        Ok(Self {
            input,
            presenter_public_key: hex::encode(public_key),
            signature: hex::encode(signature.to_bytes()),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every semantic presentation commitment is checked explicitly"
    )]
    pub fn verify(
        &self,
        proof: &[u8],
        operation_id: &str,
        action_digest: &str,
        challenge: [u8; 32],
        executor_audience: &str,
        now: u64,
        maximum_lifetime: u64,
        required_presenter: &str,
    ) -> Result<(), RecordsError> {
        if self.input.presentation_version != "auths.records-presentation/1"
            || self.input.proof_digest != sha256(proof)
            || self.input.operation_id != operation_id
            || self.input.canonical_action_digest != action_digest
            || self.input.challenge != hex::encode(challenge)
            || self.input.executor_audience != executor_audience
            || self.input.presenter_principal != required_presenter
            || self.input.created_at > now
            || self.input.expires_at < now
            || self.input.expires_at.saturating_sub(self.input.created_at) > maximum_lifetime
        {
            return Err(RecordsError::MeaningMismatch);
        }
        let key_bytes: [u8; 32] = hex::decode(&self.presenter_public_key)
            .map_err(|_| RecordsError::Malformed)?
            .try_into()
            .map_err(|_| RecordsError::Malformed)?;
        if self.input.presenter_principal != format!("key:ed25519:{}", self.presenter_public_key) {
            return Err(RecordsError::MeaningMismatch);
        }
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| RecordsError::Malformed)?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature).map_err(|_| RecordsError::Malformed)?,
        )
        .map_err(|_| RecordsError::Malformed)?;
        key.verify(&canonical_json(&self.input)?, &signature)
            .map_err(|_| RecordsError::MeaningMismatch)
    }
}
