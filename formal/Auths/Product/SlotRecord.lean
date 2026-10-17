import Auths.Product.RequestConstruction
import Mathlib.Tactic
namespace Auths.Product.SlotRecord
open Auths.Product.RequestConstruction
abbrev Bytes := List Nat

def pairsMatch (stored counter : Bytes) (processed : Nat) : Prop :=
  ∀ index, index < processed →
    stored[2 * index]? = some (hexLower (counter[index]! / 16)) ∧
      stored[2 * index + 1]? = some (hexLower (counter[index]! % 16))

def hexMatches (stored counter : Bytes) : Prop :=
  stored.length = 2 * counter.length ∧ pairsMatch stored counter counter.length

instance (stored counter : Bytes) : Decidable (hexMatches stored counter) := by
  unfold hexMatches pairsMatch
  exact inferInstanceAs (Decidable (_ ∧ ∀ index, index < counter.length → _))

structure Values where
  slot : Nat
  amount : Nat
  cumulative : Nat
  deriving DecidableEq

def valid (schema expectedSchema stored counter : Bytes) (expectedSlot : Nat) (values : Values) : Prop :=
  schema = expectedSchema ∧ hexMatches stored counter ∧
    values.slot = expectedSlot ∧ values.amount ≤ values.cumulative

instance (schema expectedSchema stored counter : Bytes) (expectedSlot : Nat) (values : Values) :
    Decidable (valid schema expectedSchema stored counter expectedSlot values) := by
  unfold valid
  infer_instance

def validate (schema expectedSchema stored counter : Bytes) (expectedSlot : Nat) (values : Values) : Option Nat :=
  if valid schema expectedSchema stored counter expectedSlot values then some values.cumulative else none

theorem accepted_iff (schema expectedSchema stored counter : Bytes) (expectedSlot : Nat) (values : Values) :
    validate schema expectedSchema stored counter expectedSlot values = some values.cumulative ↔
      valid schema expectedSchema stored counter expectedSlot values := by simp [validate]

theorem accepted_binds_slot (schema expectedSchema stored counter : Bytes) (expectedSlot value : Nat) (values : Values)
    (accepted : validate schema expectedSchema stored counter expectedSlot values = some value) :
    schema = expectedSchema ∧ hexMatches stored counter ∧ values.slot = expectedSlot ∧
      values.amount ≤ value ∧ value = values.cumulative := by
  unfold validate at accepted
  split at accepted <;> simp_all [valid]
private theorem hex_lower_injective (left right : Nat) (leftBound : left < 16) (rightBound : right < 16)
    (same : hexLower left = hexLower right) : left = right := by
  unfold hexLower at same
  split at same <;> split at same <;> omega

theorem hex_matches_injective (stored left right : Bytes)
    (leftBytes : ∀ value ∈ left, value < 256) (rightBytes : ∀ value ∈ right, value < 256)
    (leftMatches : hexMatches stored left) (rightMatches : hexMatches stored right) : left = right := by
  have lengths : left.length = right.length := by have := leftMatches.1; have := rightMatches.1; omega
  apply List.ext_getElem lengths
  intro index leftInside rightInside
  have leftPair := leftMatches.2 index leftInside
  have rightPair := rightMatches.2 index rightInside
  rw [getElem!_pos left index leftInside] at leftPair
  rw [getElem!_pos right index rightInside] at rightPair
  have leftByte := leftBytes left[index] (List.getElem_mem leftInside)
  have rightByte := rightBytes right[index] (List.getElem_mem rightInside)
  have highEq : left[index] / 16 = right[index] / 16 :=
    hex_lower_injective _ _ (by omega) (by omega) (Option.some.inj (leftPair.1.symm.trans rightPair.1))
  have lowEq : left[index] % 16 = right[index] % 16 :=
    hex_lower_injective _ _ (by omega) (by omega) (Option.some.inj (leftPair.2.symm.trans rightPair.2))
  omega
end Auths.Product.SlotRecord
