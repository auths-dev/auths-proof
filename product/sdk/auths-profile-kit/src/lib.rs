//! Fixture and mutation tooling for application-profile authors.

#![forbid(unsafe_code)]

use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Language-neutral fixture emitted by a profile's canonicalization contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileFixture {
    /// Exact canonical action CBOR used by the engine boundary.
    pub canonical_action_cbor: Vec<u8>,
    /// SHA-256 of the canonical profile body.
    pub canonical_body_sha256: String,
    /// Human-reviewable profile display.
    pub approval: FixtureApproval,
}

/// Serializable approval display included in generated fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureApproval {
    /// Profile-owned display title.
    pub title: String,
    /// Ordered profile-owned display fields.
    pub fields: Vec<(String, String)>,
    /// Digest the display claims to represent.
    pub canonical_digest_hex: String,
}

impl From<&ApprovalDisplay> for FixtureApproval {
    fn from(display: &ApprovalDisplay) -> Self {
        Self {
            title: display.title().to_owned(),
            fields: display.fields().to_vec(),
            canonical_digest_hex: display.canonical_digest_hex().to_owned(),
        }
    }
}

/// Builds a reproducible cross-language fixture for one profile input.
///
/// The input is canonicalized twice and both complete actions must be equal.
/// The approval display must bind the SHA-256 digest of the canonical body.
///
/// # Errors
///
/// Returns a profile error or a conformance error if deterministic
/// canonicalization/display binding is violated.
pub fn build_fixture<P: ActionProfile>(
    profile: &P,
    input: &[u8],
) -> Result<ProfileFixture, ProfileKitError> {
    let first = profile.canonicalize(input)?;
    let second = profile.canonicalize(input)?;
    if first != second {
        return Err(ProfileKitError::NondeterministicCanonicalization);
    }
    let display = profile.approval_display(&first)?;
    let body_digest = hex_digest(first.body());
    if display.canonical_digest_hex() != body_digest {
        return Err(ProfileKitError::DisplayDigestMismatch);
    }
    Ok(ProfileFixture {
        canonical_action_cbor: auths_codec::encode_canonical_action(&first)?,
        canonical_body_sha256: body_digest,
        approval: FixtureApproval::from(&display),
    })
}

/// Serializes a fixture using deterministic compact JSON for other language
/// runners.
///
/// # Errors
///
/// Returns an error only if the serializable fixture cannot be encoded.
pub fn fixture_json(fixture: &ProfileFixture) -> Result<Vec<u8>, ProfileKitError> {
    Ok(serde_json::to_vec(fixture)?)
}

/// Produces bounded generic hostile-input mutations for a profile test suite.
#[must_use]
pub fn hostile_mutations(input: &[u8]) -> Vec<Vec<u8>> {
    let mut mutations = vec![Vec::new()];
    if !input.is_empty() {
        mutations.push(input[..input.len() - 1].to_vec());
        let mut flipped = input.to_vec();
        flipped[input.len() / 2] ^= 0x80;
        mutations.push(flipped);
    }
    let mut suffixed = input.to_vec();
    suffixed.push(0);
    mutations.push(suffixed);
    mutations
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Profile-development contract failure.
#[derive(Debug, Error)]
pub enum ProfileKitError {
    /// Selected profile rejected or could not decode the input.
    #[error("profile contract failed: {0}")]
    Profile(#[from] ProfileContractError),
    /// Repeated canonicalization returned different complete actions.
    #[error("profile canonicalization is nondeterministic")]
    NondeterministicCanonicalization,
    /// Approval display did not bind the canonical body digest.
    #[error("approval display digest does not bind the canonical action body")]
    DisplayDigestMismatch,
    /// Canonical action CBOR encoding failed.
    #[error("canonical action encoding failed: {0}")]
    Codec(#[from] auths_codec::CodecError),
    /// Cross-language fixture JSON encoding failed.
    #[error("profile fixture JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef, ResourceId,
    };
    use auths_verifier::VerifiedAction;
    use std::cell::Cell;

    struct TestProfile {
        calls: Cell<u8>,
        nondeterministic: bool,
    }

    impl ActionProfile for TestProfile {
        type Command = ();

        fn canonicalize(&self, _untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
            let call = self.calls.get();
            self.calls.set(call.saturating_add(1));
            let body = if self.nondeterministic && call > 0 {
                b"{\"value\":2}".to_vec()
            } else {
                b"{\"value\":1}".to_vec()
            };
            CanonicalAction::new(
                ProfileRef::new(ProfileId::parse("auths.test").unwrap(), 1).unwrap(),
                MediaType::parse("application/json").unwrap(),
                body,
                Permission::new(
                    CapabilityId::parse("test/run").unwrap(),
                    ResourceId::parse("test://fixture").unwrap(),
                ),
                None,
            )
            .map_err(|_| ProfileContractError::MeaningMismatch)
        }

        fn approval_display(
            &self,
            action: &CanonicalAction,
        ) -> Result<ApprovalDisplay, ProfileContractError> {
            Ok(ApprovalDisplay::new(
                "Test",
                Vec::new(),
                hex_digest(action.body()),
            ))
        }

        fn decode_verified(
            &self,
            _action: &VerifiedAction,
        ) -> Result<Self::Command, ProfileContractError> {
            Ok(())
        }
    }

    #[test]
    fn fixture_binds_canonical_bytes_and_display() {
        let fixture = build_fixture(
            &TestProfile {
                calls: Cell::new(0),
                nondeterministic: false,
            },
            b"input",
        )
        .unwrap();
        assert!(!fixture.canonical_action_cbor.is_empty());
        assert_eq!(
            fixture.canonical_body_sha256,
            fixture.approval.canonical_digest_hex
        );
    }

    #[test]
    fn fixture_rejects_nondeterministic_profile() {
        let error = build_fixture(
            &TestProfile {
                calls: Cell::new(0),
                nondeterministic: true,
            },
            b"input",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProfileKitError::NondeterministicCanonicalization
        ));
    }
}
