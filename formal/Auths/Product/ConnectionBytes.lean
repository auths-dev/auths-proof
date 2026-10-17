import Mathlib.Tactic
namespace Auths.Product.ConnectionBytes
abbrev Bytes := List Nat
def lowerHead (value : Nat) : Prop := 97 ≤ value ∧ value ≤ 122
def lowerTail (value : Nat) : Prop := lowerHead value ∨ (48 ≤ value ∧ value ≤ 57) ∨ value = 45
def graphic (value : Nat) : Prop := 33 ≤ value ∧ value ≤ 126
instance (value : Nat) : Decidable (lowerHead value) := by unfold lowerHead; infer_instance
instance (value : Nat) : Decidable (lowerTail value) := by unfold lowerTail; infer_instance
instance (value : Nat) : Decidable (graphic value) := by unfold graphic; infer_instance

def lowerValid (value : Bytes) (maximum : Nat) : Prop :=
  value ≠ [] ∧ value.length ≤ maximum ∧ lowerHead value[0]! ∧ ∀ byte ∈ value, lowerTail byte
def graphicValid (value : Bytes) (maximum : Nat) : Prop :=
  value ≠ [] ∧ value.length ≤ maximum ∧ ∀ byte ∈ value, graphic byte
instance (value : Bytes) (maximum : Nat) : Decidable (lowerValid value maximum) := by unfold lowerValid; infer_instance
instance (value : Bytes) (maximum : Nat) : Decidable (graphicValid value maximum) := by unfold graphicValid; infer_instance

theorem lower_has_no_nul (value : Bytes) (maximum : Nat) (valid : lowerValid value maximum) : 0 ∉ value := by
  intro member
  have allowed := valid.2.2.2 0 member
  simp [lowerTail, lowerHead] at allowed

theorem graphic_has_no_nul (value : Bytes) (maximum : Nat) (valid : graphicValid value maximum) : 0 ∉ value := by
  intro member
  have allowed := valid.2.2 0 member
  simp [graphic] at allowed
end Auths.Product.ConnectionBytes
