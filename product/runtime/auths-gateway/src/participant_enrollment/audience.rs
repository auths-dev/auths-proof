//! Native audience separation for engagement resources. The existing kernel
//! checks this audience on every grant and invocation; ordinary recipe entry
//! continues to require its ordinary MCP audience and cannot reuse these grants.

use super::{MAX_JSON_INTEGER, ParticipantEnrollmentError};
use auths_model::Audience;

/// Derive the sole native audience allowed on a participant's resource grant.
/// The inputs come from the signed task and installed compiled recipe. Computing
/// this identifier authenticates nothing and does not reserve execution capacity.
///
/// # Errors
/// Refuses zero/inexact partition generations or a noncanonical recipe digest.
pub fn resource_audience(
    engagement_commitment: &[u8; 32],
    partition_generation: u64,
    recipe_digest: &str,
) -> Result<Audience, ParticipantEnrollmentError> {
    if partition_generation == 0
        || partition_generation > MAX_JSON_INTEGER
        || recipe_digest.len() != 64
        || !recipe_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ParticipantEnrollmentError::Invalid);
    }
    Audience::parse(&format!(
        "auths-engagement://v1/{}/{partition_generation}/{recipe_digest}",
        hex::encode(engagement_commitment)
    ))
    .map_err(|_| ParticipantEnrollmentError::Invalid)
}
