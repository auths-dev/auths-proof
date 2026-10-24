import Auths.Codec.PolicyConstructors
import Auths.Codec.ProtocolEquality
import Auths.Crypto.BoundedPolicyCommitments

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyCanonical
open Auths.Codec.Refinement Auths.Crypto
open Auths.Crypto.SigningObjectWriters

/- Actual opening check over the supplied complete policy bytes. A valid
model value earns framing/native space; only the explicit SHA function/output
contract remains cryptographic. No successful digest/constructor, accepted
opening flag or repaired commitment is an input premise. -/
variable [primitive : Sha256Primitives]

theorem checked_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) :
    canonical_value.checked_bounded_policy value =
      ok (if PolicyValidity.Opening sha256 value then .Ok ⟨value⟩ else .Err .DigestMismatch) := by
  have digestRun := BoundedPolicyCommitments.policy_bounded_exact sha256 contract
    (alloc.vec.Vec.deref value.policy) (by simpa only [alloc.vec.deref_exact] using valid.2.2)
  unfold canonical_value.checked_bounded_policy
  simp only [auths_model.bounded_policy.BoundedPolicyCommitment.impl.policy,
    core.ops.deref.DerefVec, digestRun, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.bounded_policy.BoundedPolicyCommitment.impl.commitment,
    auths_model.bounded_policy.PolicyCommitment.impl.policy_digest,
    core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
    ProtocolEquality.digest_exact, bind_tc_ok]
  by_cases opened : PolicyValidity.Opening sha256 value
  · simp_all [PolicyValidity.Opening, BoundedPolicyCommitments.policyFrame, alloc.vec.deref_exact]
  · simp_all [PolicyValidity.Opening, BoundedPolicyCommitments.policyFrame, alloc.vec.deref_exact]

theorem checked_accepts (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) (opened : PolicyValidity.Opening sha256 value) :
    canonical_value.checked_bounded_policy value = ok (.Ok ⟨value⟩) := by
  rw [checked_exact sha256 contract value valid]
  simp only [if_pos opened]

theorem checked_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) (unopened : ¬ PolicyValidity.Opening sha256 value) :
    canonical_value.checked_bounded_policy value = ok (.Err .DigestMismatch) := by
  rw [checked_exact sha256 contract value valid]
  simp only [if_neg unopened]

@[step] theorem checked_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) :
    canonical_value.checked_bounded_policy value ⦃ result =>
      match result with
      | .Err reason => reason = .DigestMismatch ∧ ¬ PolicyValidity.Opening sha256 value
      | .Ok carrier => canonical_value.Canonical.as_value carrier = ok value ∧
          PolicyValidity.Body value ∧ PolicyValidity.Opening sha256 value ∧
          (bounded_policy.encode_bounded_policy_commitment carrier ⦃ encoded =>
            Encodes (BoundedPolicyObjects.body value) encoded ⦄) ⦄ := by
  rw [checked_exact sha256 contract value valid]
  by_cases opened : PolicyValidity.Opening sha256 value
  · simp only [if_pos opened, spec_ok]
    refine ⟨rfl, valid, opened, ?_⟩
    obtain ⟨space, native, length⟩ := PolicyConstructors.body_resources value valid
    exact BoundedPolicyWriters.canonical_encoder ⟨value⟩ value rfl
      (PolicyConstructors.fields_valid value.commitment valid.1) space native
  · simp [opened, spec_ok]

end Auths.Codec.PolicyCanonical
