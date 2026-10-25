import Auths.Crypto.BoundedPolicyObjects
import Auths.Crypto.CommitmentFrames

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Codec.PolicyValidity
open Auths.Codec.Refinement Auths.Crypto

/- Independent closed-ASCII policy representation. Ordinary protocol strings
have a different grammar; a policy identifier cannot inherit their broader
Unicode vocabulary. None of these predicates is source-constructor success,
an encoder result, a trusted validity flag or evaluator acceptance. -/
def allowed (byte : Nat) : Prop :=
  (48 ≤ byte ∧ byte ≤ 57) ∨ (65 ≤ byte ∧ byte ≤ 90) ∨
    (97 ≤ byte ∧ byte ≤ 122) ∨ byte = 46 ∨ byte = 47 ∨ byte = 58 ∨ byte = 95 ∨ byte = 45

def invalid : List Nat → Bool
  | [] => false
  | first :: rest => !decide (allowed first) || invalid rest

def accepts (value : String) (maximum : Nat) : Bool :=
  !(UnsignedObjects.utf8 value).isEmpty && decide (value.toByteArray.size ≤ maximum) &&
    !invalid (UnsignedObjects.utf8 value)

def Language (value : String) : Prop :=
  value.toByteArray.size ≠ 0 ∧ ∀ byte ∈ UnsignedObjects.utf8 value, allowed byte

def Identifier (value : String) (maximum : Nat) : Prop := Language value ∧ value.toByteArray.size ≤ maximum

def CommitmentDimensions (value : auths_model.bounded_policy.PolicyCommitment) : Prop :=
  0 < value.policy_version.val ∧ value.policy_type.toByteArray.size ≤ 128 ∧
    value.canonicalization_id.toByteArray.size ≤ 64 ∧ value.evaluator_semantic_id.toByteArray.size ≤ 128

def CommitmentLanguage (value : auths_model.bounded_policy.PolicyCommitment) : Prop :=
  Language value.policy_type ∧ Language value.canonicalization_id ∧ Language value.evaluator_semantic_id

def Commitment (value : auths_model.bounded_policy.PolicyCommitment) : Prop :=
  CommitmentLanguage value ∧ CommitmentDimensions value

def BodyDimensions (value : auths_model.bounded_policy.BoundedPolicyCommitment) : Prop :=
  value.policy.val ≠ [] ∧ value.policy.val.length ≤ 4096

def Body (value : auths_model.bounded_policy.BoundedPolicyCommitment) : Prop :=
  Commitment value.commitment ∧ BodyDimensions value

def Opening (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.bounded_policy.BoundedPolicyCommitment) : Prop :=
  sha256 (CommitmentFrames.application
    ⟨UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain, byteList value.policy.val⟩) =
      value.commitment.policy_digest

theorem invalid_false (values : List Nat) :
    invalid values = false ↔ ∀ byte ∈ values, allowed byte := by
  induction values with
  | nil => simp [invalid]
  | cons first rest ih => simp [invalid, ih, Bool.or_eq_false_iff]

theorem accepts_iff (value : String) (maximum : Nat) : accepts value maximum = true ↔ Identifier value maximum := by
  have empty : (UnsignedObjects.utf8 value).isEmpty = false ↔ value.toByteArray.size ≠ 0 := by
    rw [List.isEmpty_eq_false_iff, List.ne_nil_iff_length_pos, UnsignedLeaves.utf8_length]
    omega
  simp only [accepts, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, empty, invalid_false]
  exact ⟨fun ⟨⟨nonempty, bound⟩, alphabet⟩ => ⟨⟨nonempty, alphabet⟩, bound⟩,
    fun ⟨⟨nonempty, alphabet⟩, bound⟩ => ⟨⟨nonempty, bound⟩, alphabet⟩⟩

end Auths.Codec.PolicyValidity
