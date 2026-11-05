//! Retained preimage of the existing native authority commitment. This is
//! private historical evidence, never a verifier result that can grant entry.
use super::{EffectBindingError, MAX_EFFECT_BYTES, commitment};
use auths_model::{
    PortableVerificationResult, Timestamp, TrustedContext, VerificationDecision,
    VerificationResources,
};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct NativeAuthority {
    canonical: Zeroizing<Vec<u8>>,
    commitment: [u8; 32],
}

impl fmt::Debug for NativeAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeAuthority { private: [redacted] }")
    }
}

impl NativeAuthority {
    /// Time and work counters are not authority identities. Preserve the exact
    /// native branch/evidence selection and installed trust, with only those
    /// two evaluation-specific inputs normalized as before.
    pub(crate) fn verified(
        result: &PortableVerificationResult,
        context: &TrustedContext,
    ) -> Result<Self, EffectBindingError> {
        let normalized = context
            .for_request(
                context.expected_audience().clone(),
                context.expected_challenge(),
                Timestamp::new(0),
            )
            .map_err(|_| EffectBindingError::Invalid)?;
        let context_digest =
            auths_codec::context_digest(&normalized).map_err(|_| EffectBindingError::Invalid)?;
        let projection = PortableVerificationResult::new(
            result.decision(),
            result.stage(),
            result.code(),
            result.proof_digest(),
            result.action_digest(),
            context_digest,
            result.plan_id(),
            result.authorized_branches().to_vec(),
            result.assurance().to_vec(),
            result.assurance_satisfactions().to_vec(),
            VerificationResources::new(0, 0, 0, 0, 0, 0, 0),
            result.registry_manifest(),
            result.required_configuration(),
            result.local_configuration(),
        )
        .with_observation_satisfactions(result.observation_satisfactions().to_vec())
        .with_approval_satisfactions(result.approval_satisfactions().to_vec());
        Self::from_result(&projection)
    }

    fn from_result(result: &PortableVerificationResult) -> Result<Self, EffectBindingError> {
        let result = result.clone().with_result_digest(
            auths_codec::verification_result_digest(result)
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        let bytes = Zeroizing::new(
            auths_codec::encode_verification_result(&result)
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        Self::from_private_bytes(&bytes)
    }

    pub(crate) fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let result = auths_codec::decode_verification_result(bytes)
            .map_err(|_| EffectBindingError::Invalid)?;
        if result.decision() != VerificationDecision::Authorized
            || result.resources() != VerificationResources::new(0, 0, 0, 0, 0, 0, 0)
        {
            return Err(EffectBindingError::Invalid);
        }
        // The existing binding commitment encodes the normalized projection
        // before its portable self-digest is attached. Retain a valid canonical
        // report, and reconstruct that exact preimage through the native codec.
        // This preserves EffectId while making the history input digests usable.
        let preimage = Zeroizing::new(
            auths_codec::encode_verification_result(
                &result.with_result_digest(auths_model::VerificationResultDigest::new([0; 32])),
            )
            .map_err(|_| EffectBindingError::Invalid)?,
        );
        Ok(Self {
            canonical: Zeroizing::new(bytes.to_vec()),
            commitment: commitment("auths.effect-native-authority/1", &preimage)?,
        })
    }

    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub(crate) fn private_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub(crate) fn matches_inputs(&self, proof: &[u8], action: &[u8]) -> bool {
        auths_codec::decode_verification_result(&self.canonical).is_ok_and(|result| {
            result.proof_digest() == auths_codec::body_digest(proof)
                && result.action_digest() == auths_codec::body_digest(action)
        })
    }

    /// Explicit post-verification reference data. No installed engine uses it.
    #[cfg(test)]
    pub(crate) fn oracle(proof: [u8; 32]) -> Self {
        use auths_model::{
            ContextDigest, Digest, RegistryManifestId, VerificationCode, VerificationStage,
            VerifierConfigurationId,
        };
        Self::from_result(&PortableVerificationResult::new(
            VerificationDecision::Authorized,
            VerificationStage::Complete,
            VerificationCode::Authorized,
            Digest::new(proof),
            Digest::new([0; 32]),
            ContextDigest::new([0; 32]),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            VerificationResources::new(0, 0, 0, 0, 0, 0, 0),
            RegistryManifestId::new([0; 32]),
            None,
            VerifierConfigurationId::new([0; 32]),
        ))
        .expect("post-verification oracle authority")
    }
}
