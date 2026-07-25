//! Supported embedded API for Auths Proof Protocol V1.
//!
//! Most applications need only [`Engine::verify_cbor`]. Lower-level model,
//! registry, and authoring APIs remain available through the re-exported
//! modules when an integration needs explicit control.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub use auths_author as author;
pub use auths_codec as codec;
pub use auths_model as model;
pub use auths_ports as ports;
pub use auths_registries as registries;
pub use auths_verifier::{VerificationOutcome, VerifiedAction};

use auths_codec::{decode_verification_result, CodecError};
use auths_model::{
    CanonicalAction, PortableVerificationResult, Requirement, VerificationCode,
    VerificationDecision, VerificationResources, VerificationStage, VerifierContext,
};
use auths_registries::ImmutableRegistries;

/// Immutable embedded verifier with explicitly supplied implementations.
///
/// The engine performs no I/O and has no ambient configuration. Registry
/// implementations are fixed at construction and each request supplies all
/// proof, action, and trusted-context bytes.
pub struct Engine<'a> {
    registries: ImmutableRegistries<'a>,
}

impl<'a> Engine<'a> {
    /// Constructs an embedded verifier from an exact immutable registry.
    #[must_use]
    pub const fn new(registries: ImmutableRegistries<'a>) -> Self {
        Self { registries }
    }

    /// Returns the immutable executable registry.
    #[must_use]
    pub const fn registries(&self) -> &ImmutableRegistries<'a> {
        &self.registries
    }

    /// Executes the complete three-input portable V1 operation.
    ///
    /// All protocol verdicts, including malformed input, are returned as a
    /// [`VerificationResult`]. An error means only that the engine could not
    /// encode or decode its own canonical result.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an internal canonical-result codec failure.
    pub fn verify_cbor(
        &self,
        proof_cbor: &[u8],
        canonical_action_cbor: &[u8],
        trusted_context_cbor: &[u8],
    ) -> Result<VerificationResult, CodecError> {
        let cbor = auths_verifier::verify_v1(
            proof_cbor,
            canonical_action_cbor,
            trusted_context_cbor,
            &self.registries,
        )?;
        let portable = decode_verification_result(&cbor)?;
        Ok(VerificationResult { portable, cbor })
    }

    /// Executes the sealed native verifier for Rust profile decoders.
    #[must_use]
    pub fn verify_typed(
        &self,
        proof_cbor: &[u8],
        canonical_action: &CanonicalAction,
        context: &VerifierContext,
    ) -> VerificationOutcome {
        auths_verifier::verify(proof_cbor, canonical_action, context, &self.registries)
    }
}

/// Native verdict class shared by idiomatic language wrappers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Verification completed and established exact authority.
    Authorized,
    /// Available trustworthy facts established a stable denial.
    Denied,
    /// A trustworthy required fact or supported capability was unavailable.
    Indeterminate,
}

/// Actionable, stable explanation for one verification result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Explanation {
    verdict: Verdict,
    stage: VerificationStage,
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl Explanation {
    /// Returns the three-way verdict class.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        self.verdict
    }

    /// Returns the last completed verification stage.
    #[must_use]
    pub const fn stage(self) -> VerificationStage {
        self.stage
    }

    /// Returns the stable language-neutral V1 code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns a non-sensitive operator-facing summary.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Reports whether obtaining fresh trusted facts or adding explicit
    /// implementation support may change the result.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }
}

/// Canonical portable result plus its exact wire bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    portable: PortableVerificationResult,
    cbor: Vec<u8>,
}

impl VerificationResult {
    /// Returns the idiomatic three-way verdict.
    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        match self.portable.decision() {
            VerificationDecision::Authorized => Verdict::Authorized,
            VerificationDecision::Denied => Verdict::Denied,
            VerificationDecision::Indeterminate => Verdict::Indeterminate,
        }
    }

    /// Returns the stable V1 reason or requirement code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.portable.code().code()
    }

    /// Returns an actionable non-sensitive explanation.
    #[must_use]
    pub const fn explanation(&self) -> Explanation {
        let code = self.portable.code();
        Explanation {
            verdict: self.verdict(),
            stage: self.portable.stage(),
            code: code.code(),
            message: explanation_message(code),
            retryable: matches!(code, VerificationCode::Indeterminate(_)),
        }
    }

    /// Returns deterministic input and work metrics.
    #[must_use]
    pub const fn resources(&self) -> VerificationResources {
        self.portable.resources()
    }

    /// Returns the complete language-neutral result.
    #[must_use]
    pub const fn portable(&self) -> &PortableVerificationResult {
        &self.portable
    }

    /// Returns exact canonical result bytes for receipts and cross-language
    /// comparison.
    #[must_use]
    pub fn as_cbor(&self) -> &[u8] {
        &self.cbor
    }

    /// Consumes the wrapper into exact canonical result bytes.
    #[must_use]
    pub fn into_cbor(self) -> Vec<u8> {
        self.cbor
    }
}

const fn explanation_message(code: VerificationCode) -> &'static str {
    match code {
        VerificationCode::Authorized => "the proof establishes exact authority for this action",
        VerificationCode::Denied(reason) => denial_message(reason),
        VerificationCode::Indeterminate(requirement) => requirement_message(requirement),
    }
}

const fn denial_message(reason: auths_model::DenialReason) -> &'static str {
    use auths_model::DenialReason as D;
    match reason {
        D::MalformedProof | D::NonCanonicalProof => {
            "supply a bounded, canonical Auths Proof Protocol V1 object"
        }
        D::ResourceLimitExceeded => "reduce the proof or raise an explicit bounded local limit",
        D::InvalidSignature
        | D::PrincipalMethodMismatch
        | D::VerificationMethodMismatch
        | D::SignatureSuiteMismatch => {
            "the supplied principal-control proof does not match the signed statement"
        }
        D::UntrustedRoot => "configure the intended root explicitly or use a trusted proof chain",
        D::AudienceMismatch | D::ChallengeMismatch | D::ActionOutsideValidity => {
            "issue a proof for this exact audience, challenge, and validity window"
        }
        D::PermissionNotGranted
        | D::ActionConstraintMismatch
        | D::BudgetCeilingExceeded
        | D::DelegationExpanded => "narrow the requested action or issue sufficient authority",
        D::PrincipalRevoked
        | D::GrantRevoked
        | D::StatusSequenceRollback
        | D::StatusMethodMismatch
        | D::StatusIssuerUntrusted => "replace the proof with valid trusted lifecycle evidence",
        D::RegistryManifestMismatch
        | D::ResourceNamespaceMismatch
        | D::CriticalExtensionUnknown
        | D::LocalPolicyDenied => "align the request with the service's explicit local policy",
        _ => "the proof and action failed a stable fail-closed authorization check",
    }
}

const fn requirement_message(requirement: Requirement) -> &'static str {
    use Requirement as R;
    match requirement {
        R::MissingPrincipalEvidence | R::MissingPrincipalStatus | R::MissingGrantStatus => {
            "supply the missing trusted evidence or status snapshot and retry"
        }
        R::StaleStatus | R::HistoricalStateUnavailable | R::ExternalFactUnavailable => {
            "obtain a fresh or historically trustworthy fact and retry"
        }
        R::AssuranceRequirementNotMet => {
            "supply evidence satisfying the configured assurance requirement"
        }
        _ => "install and explicitly accept support for the required V1 identifier",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_ports::{PrincipalMethod, SignatureSuite};

    #[test]
    fn facade_returns_native_and_canonical_results() {
        let fixture = auths_testkit::raw_key_chain();
        let method = auths_raw_key::RawKeyMethod::new().unwrap();
        let suite = auths_signature::Ed25519Suite::new().unwrap();
        let methods: [&dyn PrincipalMethod; 1] = [&method];
        let suites: [&dyn SignatureSuite; 1] = [&suite];
        let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
        let engine = Engine::new(registries);
        let action = auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
        let result = engine
            .verify_cbor(fixture.proof_bytes(), &action, fixture.context_bytes())
            .unwrap();
        assert_eq!(result.verdict(), Verdict::Authorized);
        assert_eq!(result.code(), "authorized");
        assert_eq!(
            auths_codec::decode_verification_result(result.as_cbor()).unwrap(),
            *result.portable()
        );
    }
}
