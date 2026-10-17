import Mathlib.Tactic
namespace Auths.Product.SemanticId
abbrev Bytes := List Nat
def head (value : Nat) : Prop := (97 ≤ value ∧ value ≤ 122) ∨ (65 ≤ value ∧ value ≤ 90) ∨ (48 ≤ value ∧ value ≤ 57)
def tail (value : Nat) : Prop := head value ∨ value = 46 ∨ value = 95 ∨ value = 58 ∨ value = 47 ∨ value = 45
instance (value : Nat) : Decidable (head value) := by unfold head; infer_instance
instance (value : Nat) : Decidable (tail value) := by unfold tail; infer_instance
def valid (value : Bytes) (maximum : Nat) : Prop :=
  value ≠ [] ∧ value.length ≤ maximum ∧ head value[0]! ∧ ∀ byte ∈ value, tail byte
instance (value : Bytes) (maximum : Nat) : Decidable (valid value maximum) := by unfold valid; infer_instance

theorem valid_has_no_nul (value : Bytes) (maximum : Nat) (accepted : valid value maximum) : 0 ∉ value := by
  intro member
  have permitted := accepted.2.2.2 0 member
  simp [tail, head] at permitted

theorem valid_is_ascii (value : Bytes) (maximum : Nat) (accepted : valid value maximum) :
    ∀ byte ∈ value, byte < 128 := by
  intro byte member
  have permitted := accepted.2.2.2 byte member
  simp only [tail, head] at permitted
  omega
end Auths.Product.SemanticId
