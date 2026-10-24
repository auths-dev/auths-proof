import Auths.Codec.PolicyIdentifiers
import Auths.Crypto.BoundedPolicyWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyConstructors
open Auths.Codec.Refinement Auths.Crypto
open Auths.Crypto.SigningObjectWriters

/- Exact actual model constructors, with their error precedence. Prototype
records abbreviate input fields; no successful constructor, expected output
value, valid-carrier flag or cryptographic opening is an input assumption. -/
theorem commitment_exact (value : auths_model.bounded_policy.PolicyCommitment)
    (carriers : BoundedPolicyWriters.Fields value) :
    auths_model.bounded_policy.PolicyCommitment.new value.policy_type value.policy_version
      value.canonicalization_id value.policy_digest value.evaluator_semantic_id =
      ok (if PolicyValidity.CommitmentDimensions value then .Ok value else .Err .InvalidBoundedPolicy) := by
  have typeLength : (toStr value.policy_type carriers.policy_type).val.length = value.policy_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  have canonicalizationLength : (toStr value.canonicalization_id carriers.canonicalization).val.length =
      value.canonicalization_id.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  have evaluatorLength : (toStr value.evaluator_semantic_id carriers.evaluator).val.length =
      value.evaluator_semantic_id.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  unfold auths_model.bounded_policy.PolicyCommitment.new
  simp only [auths_model.bounded_policy.PolicyIdentifier.as_str,
    StringRefinement.string_borrow_exact value.policy_type carriers.policy_type,
    StringRefinement.string_borrow_exact value.canonicalization_id carriers.canonicalization,
    StringRefinement.string_borrow_exact value.evaluator_semantic_id carriers.evaluator,
    core.str.Str.len, bind_tc_ok, UScalar.lt_equiv, typeLength, canonicalizationLength, evaluatorLength,
    auths_model.bounded_policy.MAX_POLICY_IDENTIFIER_BYTES,
    auths_model.bounded_policy.MAX_POLICY_CANONICALIZATION_BYTES]
  by_cases dimensions : PolicyValidity.CommitmentDimensions value
  · simp_all [PolicyValidity.CommitmentDimensions, Nat.pos_iff_ne_zero]
  · simp_all [PolicyValidity.CommitmentDimensions, Nat.pos_iff_ne_zero]

theorem commitment_output_valid (input output : auths_model.bounded_policy.PolicyCommitment)
    (carriers : BoundedPolicyWriters.Fields input) (language : PolicyValidity.CommitmentLanguage input)
    (accepted : auths_model.bounded_policy.PolicyCommitment.new input.policy_type input.policy_version
      input.canonicalization_id input.policy_digest input.evaluator_semantic_id = ok (.Ok output)) :
    output = input ∧ PolicyValidity.Commitment output := by
  rw [commitment_exact input carriers] at accepted
  split at accepted
  · rename_i dimensions
    have same : input = output := by simpa using accepted
    subst output
    exact ⟨rfl, language, dimensions⟩
  · simp at accepted

theorem body_exact (value : auths_model.bounded_policy.BoundedPolicyCommitment) :
    auths_model.bounded_policy.BoundedPolicyCommitment.new value.commitment value.policy value.parent =
      ok (if value.policy.val = [] then .Err .InvalidBoundedPolicy
        else if value.policy.val.length ≤ 4096 then .Ok value else .Err .CollectionLimitExceeded) := by
  unfold auths_model.bounded_policy.BoundedPolicyCommitment.new
  simp [alloc.vec.Vec.is_empty, alloc.vec.Vec.len, auths_model.bounded_policy.MAX_BOUNDED_POLICY_BYTES,
    alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.toBase,
    alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.val, UScalar.lt_equiv, List.isEmpty_iff]

theorem body_output_valid (input output : auths_model.bounded_policy.BoundedPolicyCommitment)
    (commitment : PolicyValidity.Commitment input.commitment)
    (accepted : auths_model.bounded_policy.BoundedPolicyCommitment.new input.commitment input.policy input.parent = ok (.Ok output)) :
    output = input ∧ PolicyValidity.Body output := by
  rw [body_exact input] at accepted
  split at accepted
  · simp at accepted
  · rename_i nonempty
    split at accepted
    · rename_i bounded
      have same : input = output := by simpa using accepted
      subst output
      exact ⟨rfl, commitment, nonempty, bounded⟩
    · simp at accepted

theorem fields_valid (value : auths_model.bounded_policy.PolicyCommitment)
    (valid : PolicyValidity.Commitment value) : BoundedPolicyWriters.Fields value := by
  rcases valid.2 with ⟨version, typeBound, canonicalizationBound, evaluatorBound⟩
  constructor <;> scalar_tac

theorem commitment_valid_exact (value : auths_model.bounded_policy.PolicyCommitment)
    (valid : PolicyValidity.Commitment value) :
    auths_model.bounded_policy.PolicyCommitment.new value.policy_type value.policy_version
      value.canonicalization_id value.policy_digest value.evaluator_semantic_id = ok (.Ok value) := by
  rw [commitment_exact value (fields_valid value valid)]
  simp only [if_pos valid.2]

theorem body_valid_exact (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) :
    auths_model.bounded_policy.BoundedPolicyCommitment.new value.commitment value.policy value.parent = ok (.Ok value) := by
  rw [body_exact value]
  simp only [if_neg valid.2.1, if_pos valid.2.2]

theorem commitment_cost_valid (value : auths_model.bounded_policy.PolicyCommitment)
    (valid : PolicyValidity.Commitment value) : BoundedPolicyObjects.commitmentCost value ≤ 451 := by
  rcases valid.2 with ⟨version, typeBound, canonicalizationBound, evaluatorBound⟩
  simp only [BoundedPolicyObjects.commitmentCost]
  omega

theorem body_cost_valid (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) : BoundedPolicyObjects.bodyCost value ≤ 4633 := by
  have commitment := commitment_cost_valid value.commitment valid.1
  have policy := valid.2.2
  simp only [BoundedPolicyObjects.bodyCost]
  omega

theorem body_resources (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) :
    BoundedPolicyObjects.bodyCost value ≤ Usize.max ∧
      (2 * BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max ∧
      (BoundedPolicyObjects.body value).length ≤ 65536 := by
  have cost := body_cost_valid value valid
  have length := BoundedPolicyWriters.body_length value
  constructor
  · scalar_tac
  constructor
  · scalar_tac
  · omega

@[step] theorem body_encoder_valid (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) :
    bounded_policy.encode_bounded_policy_commitment_value value ⦃ result =>
      Encodes (BoundedPolicyObjects.body value) result ⦄ := by
  obtain ⟨space, native, length⟩ := body_resources value valid
  exact BoundedPolicyWriters.body_encoder value (fields_valid value.commitment valid.1) space native

end Auths.Codec.PolicyConstructors
