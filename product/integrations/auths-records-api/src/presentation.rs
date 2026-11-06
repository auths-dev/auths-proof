//! Short-lived presenter-bound proof presentation.

use auths_signature_core::verify_ed25519;
use ed25519_dalek::{Signer as _, SigningKey};
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

/// Exact authoring preimage for a signature held outside this process. This is
/// unverified presentation data; it grants no authority, admission or disclosure.
pub struct PreparedRecordsPresentation {
    input: PresentationInputV1,
    public_key: [u8; 32],
    message: Vec<u8>,
}
impl PreparedRecordsPresentation {
    /// Complete canonical bytes the external signer must sign without alteration.
    #[must_use]
    pub fn signing_message(&self) -> &[u8] {
        &self.message
    }

    /// Attach an external Ed25519 signature. Verification remains mandatory at
    /// the resource; attaching bytes cannot establish signer control.
    #[must_use]
    pub fn complete(self, signature: [u8; 64]) -> RecordsPresentationV1 {
        RecordsPresentationV1 {
            input: self.input,
            presenter_public_key: hex::encode(self.public_key),
            signature: hex::encode(signature),
        }
    }
}

impl RecordsPresentationV1 {
    /// Identifier used by the records presentation wire contract. It identifies
    /// its signing key in this domain; it is not a core principal-method ID.
    #[must_use]
    pub fn signer_principal(public_key: &[u8; 32]) -> String {
        format!("key:ed25519:{}", hex::encode(public_key))
    }

    pub fn sign(
        signing_key: &SigningKey,
        proof: &[u8],
        claims: &PresentationClaimsV1,
    ) -> Result<Self, RecordsError> {
        let public_key = signing_key.verifying_key().to_bytes();
        let prepared = Self::prepare(public_key, proof, claims)?;
        let signature = signing_key.sign(prepared.signing_message()).to_bytes();
        Ok(prepared.complete(signature))
    }

    /// Prepare the same canonical presentation for an external signer. The
    /// resource must independently verify all claims and the completed signature.
    /// No private key bytes, request-selected trust context, or execution permit is used.
    ///
    /// # Errors
    /// Returns a typed error if the claims cannot be canonically encoded.
    pub fn prepare(
        public_key: [u8; 32],
        proof: &[u8],
        claims: &PresentationClaimsV1,
    ) -> Result<PreparedRecordsPresentation, RecordsError> {
        let presenter_principal = Self::signer_principal(&public_key);
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
        let message = canonical_json(&input)?;
        Ok(PreparedRecordsPresentation {
            input,
            public_key,
            message,
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
        let signature = hex::decode(&self.signature).map_err(|_| RecordsError::Malformed)?;
        verify_ed25519(&key_bytes, &canonical_json(&self.input)?, &signature)
            .map_err(|_| RecordsError::MeaningMismatch)
    }
}

#[cfg(test)]
mod external_authoring_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_records_presentation_authoring_fixture_is_current() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let proof = b"public-opaque-proof-presentation-fixture";
        let claims = PresentationClaimsV1 {
            operation_id: "records.create.v1".into(),
            canonical_action_digest: "ab".repeat(32),
            challenge: [7; 32],
            executor_audience: "https://native-records.example.invalid".into(),
            created_at: 100,
            expires_at: 200,
            presentation_nonce: "presentation-public-fixture".into(),
        };
        let prepared =
            RecordsPresentationV1::prepare(key.verifying_key().to_bytes(), proof, &claims).unwrap();
        let message = prepared.signing_message().to_vec();
        let signature = key.sign(&message).to_bytes();
        let complete = prepared.complete(signature);
        assert_eq!(
            complete,
            RecordsPresentationV1::sign(&key, proof, &claims).unwrap()
        );
        let presenter = complete.input.presenter_principal.clone();
        let verify = |value: &RecordsPresentationV1, now| {
            value.verify(
                proof,
                &claims.operation_id,
                &claims.canonical_action_digest,
                claims.challenge,
                &claims.executor_audience,
                now,
                120,
                &presenter,
            )
        };
        assert!(verify(&complete, 150).is_ok());
        let mut cases = Vec::new();
        for name in [
            "version",
            "proof",
            "presenter",
            "audience",
            "operation",
            "action",
            "challenge",
            "created-at",
            "expiry",
            "nonce",
            "public-key",
            "signature",
        ] {
            let mut changed = complete.clone();
            match name {
                "version" => changed.input.presentation_version.push('x'),
                "proof" => changed.input.proof_digest = "cd".repeat(32),
                "presenter" => changed.input.presenter_principal.push('x'),
                "audience" => changed.input.executor_audience.push('x'),
                "operation" => changed.input.operation_id = "records.read.v1".into(),
                "action" => changed.input.canonical_action_digest = "cd".repeat(32),
                "challenge" => changed.input.challenge = "08".repeat(32),
                "created-at" => changed.input.created_at += 1,
                "expiry" => changed.input.expires_at -= 1,
                "nonce" => changed.input.presentation_nonce.push('x'),
                "public-key" => {
                    changed.presenter_public_key =
                        hex::encode(SigningKey::from_bytes(&[18; 32]).verifying_key().to_bytes());
                }
                "signature" => changed.signature = "00".repeat(64),
                _ => unreachable!("closed fixture cases"),
            }
            assert!(
                verify(&changed, 150).is_err(),
                "substituted presentation accepted: {name}"
            );
            cases.push(name);
        }
        assert!(verify(&complete, 201).is_err());
        assert!(verify(&complete, 99).is_err());
        let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-records-presentation-vectors/1",
            "message_hex":hex::encode(message),"presentation":complete,"substitution_refusals":cases,
            "external_signature_matches_local_convenience":true,"future_and_stale_refused":true,
            "not_established":["proof-authorization","resource-execution","process-key-custody","human-presence"]})).unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/gateway/native-records-presentation.json");
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
