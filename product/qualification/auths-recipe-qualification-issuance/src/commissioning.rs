//! Release-side closure of a finite commissioning proposal. Provider-specific
//! resource/oracle expansion remains in the reviewed family harness, never in
//! the gateway or this shared artifact verifier.

use crate::IssuanceError;
use auths_recipe_qualification::{
    ClosureFault, CommissioningBinding, EvidenceMemberKind, QualificationEvidence, Scenario,
};

/// Immutable reviewed run bindings and the offline evidence they name.
///
/// Only [`Self::assemble`] constructs this value. It rederives both evidence
/// digests, source/tuple identity and all required offline scenarios. The
/// protected workflow must separately derive resources and allowed actions
/// from its reviewed reference before calling it; candidate results cannot
/// supply an expected request or evidence commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissioningProposal {
    binding: CommissioningBinding,
    conformance: QualificationEvidence,
    differential: QualificationEvidence,
}

impl CommissioningProposal {
    /// Re-verifies the two canonical offline artifacts and the finite bindings.
    ///
    /// This is evidence closure, not a provider qualification. The live wall
    /// does not exist yet and this value cannot enter a release index.
    ///
    /// # Errors
    ///
    /// Returns [`IssuanceError::Closure`] for a changed artifact, missing
    /// required offline scenario or another candidate/member, and
    /// [`IssuanceError::Format`] for nonproduction, empty, excessive or
    /// unordered authority. Inputs are not sorted or silently repaired.
    pub fn assemble(
        binding: CommissioningBinding,
        conformance: QualificationEvidence,
        differential: QualificationEvidence,
    ) -> Result<Self, IssuanceError> {
        binding.validate()?;
        let tuple_digest = binding.tuple.digest()?;
        for (artifact, member, expected_digest) in [
            (
                &conformance,
                EvidenceMemberKind::Conformance,
                binding.offline_evidence.conformance_sha256,
            ),
            (
                &differential,
                EvidenceMemberKind::Differential,
                binding.offline_evidence.differential_sha256,
            ),
        ] {
            let body = artifact.body();
            if body.member != member {
                return Err(ClosureFault::MemberSet.into());
            }
            if artifact.digest() != expected_digest {
                return Err(ClosureFault::Digest.into());
            }
            if body.commit != binding.source_commit || body.tuple_sha256 != tuple_digest {
                return Err(ClosureFault::Candidate.into());
            }
            if body
                .cases
                .iter()
                .any(|case| case.unauthorized_provider_entries != 0)
            {
                return Err(IssuanceError::CaseFailed);
            }
            for scenario in Scenario::ALL {
                if scenario.always_required()
                    && scenario.member() == member
                    && !body.cases.iter().any(|case| case.scenario == scenario)
                {
                    return Err(ClosureFault::Scenario.into());
                }
            }
        }
        Ok(Self {
            binding,
            conformance,
            differential,
        })
    }

    /// Exact bindings checked by this proposal's constructor.
    #[must_use]
    pub const fn binding(&self) -> &CommissioningBinding {
        &self.binding
    }

    /// Re-verified conformance and differential evidence, in member order.
    #[must_use]
    pub const fn offline_evidence(&self) -> [&QualificationEvidence; 2] {
        [&self.conformance, &self.differential]
    }
}
