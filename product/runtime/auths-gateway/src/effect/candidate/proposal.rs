//! Private candidate persistence for explicit operator review and restart.
//! Decoding reconstructs proposed data only; it grants no custody or I/O.

use super::{
    CandidateCredentialTarget, CompiledRecipe, ConnectionRecord, Deserialize, EffectBindingError,
    MAX_EFFECT_BYTES, Serialize, Zeroizing, canonical, decode_connection,
};

const SCHEMA: &str = "auths.gateway-credential-candidate/1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    schema: String,
    recipe: String,
    candidate: String,
    previous: Option<String>,
}

impl CandidateCredentialTarget {
    /// Encodes the exact proposed connection, predecessor/absence and recipe
    /// commitment as canonical private JSON, bounded by `MAX_EFFECT_BYTES`.
    /// It contains private connection data, never the provider secret. Store
    /// these bytes on the operator plane, separate from public activity output.
    ///
    /// # Errors
    /// Refuses an encoding failure or an oversized proposal.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        let encode = |record: &ConnectionRecord| {
            record
                .to_canonical_cbor()
                .map(hex::encode)
                .map_err(|_| EffectBindingError::Invalid)
        };
        canonical(&Proposal {
            schema: SCHEMA.to_owned(),
            recipe: hex::encode(self.recipe),
            candidate: encode(&self.candidate)?,
            previous: self.previous.as_ref().map(encode).transpose()?,
        })
    }

    /// Decodes bounded canonical private proposal bytes against the exact
    /// installed recipe and reconstructs its closed check plan. This is data,
    /// not verified authority. Callers still need native proof, exact approval,
    /// staged custody and current predecessor checks before any acquisition;
    /// publication separately requires operator authority and retained evidence.
    /// No obsolete-schema decoder or caller-supplied check plan is accepted.
    ///
    /// # Errors
    /// Refuses malformed, duplicate, noncanonical, oversized, wrong-schema or
    /// wrong-recipe data, invalid records and invalid first-install/rotation
    /// relationships. No provider, credential or shared store is accessed.
    pub fn from_private_bytes(
        recipe: &CompiledRecipe,
        bytes: &[u8],
    ) -> Result<Self, EffectBindingError> {
        if bytes.is_empty() || bytes.len() > MAX_EFFECT_BYTES {
            return Err(EffectBindingError::Invalid);
        }
        let proposal: Proposal =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        if proposal.schema != SCHEMA || proposal.recipe != hex::encode(recipe.digest()) {
            return Err(EffectBindingError::Invalid);
        }
        let candidate = decode_connection(&proposal.candidate)?;
        let previous = proposal
            .previous
            .as_deref()
            .map(decode_connection)
            .transpose()?;
        let target = Self::new(recipe, &candidate, previous.as_ref())?;
        if target.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(target)
    }
}
