import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

/-!
Independent original-slice cursor meaning of serde_json 1.0.151's end check.
The exact four JSON whitespace bytes are skipped; the first other byte is
peeked and retained on refusal. This module does not parse a JSON prefix or
claim that a supplied cursor came from an actual serde execution.
-/
namespace Auths.Product.JsonDocumentEnd

abbrev Bytes := List Nat

structure Reader where
  input : Bytes
  position : Nat
  deriving DecidableEq

def Valid (reader : Reader) : Prop := reader.position ≤ reader.input.length
instance (reader : Reader) : Decidable (Valid reader) := inferInstanceAs (Decidable (_ ≤ _))

def whitespace (byte : Nat) : Bool := decide (byte = 32 ∨ byte = 9 ∨ byte = 10 ∨ byte = 13)

def skip : Bytes → Nat
  | [] => 0
  | byte :: rest => if whitespace byte then 1 + skip rest else 0

inductive Error where
  | invalidCursor
  | trailingCharacters
  deriving DecidableEq

def advanced (reader : Reader) : Reader :=
  {reader with position := reader.position + skip (reader.input.drop reader.position)}

def finish (reader : Reader) : Except Error Unit × Reader :=
  if Valid reader then
    let next := advanced reader
    (if next.position = reader.input.length then .ok () else .error .trailingCharacters, next)
  else (.error .invalidCursor, reader)

theorem skip_bound (input : Bytes) : skip input ≤ input.length := by
  induction input with
  | nil => simp [skip]
  | cons byte rest ih => simp only [skip]; split <;> simp_all <;> omega

theorem skip_complete_exact (input : Bytes) :
    skip input = input.length ↔ ∀ byte ∈ input, whitespace byte = true := by
  induction input with
  | nil => simp [skip]
  | cons byte rest ih =>
      cases spaceAt : whitespace byte <;> simp [skip, spaceAt, ih, Nat.add_comm]

theorem skipped_prefix_is_whitespace (input : Bytes) :
    ∀ byte ∈ input.take (skip input), whitespace byte = true := by
  induction input with
  | nil => simp [skip]
  | cons byte rest ih =>
      cases spaceAt : whitespace byte
      · simp [skip, spaceAt]
      · simpa [skip, spaceAt, Nat.add_comm] using And.intro spaceAt ih

theorem skip_stops_at_first_other (input : Bytes) :
    (input.drop (skip input)).head? = none ∨
      ∃ byte, (input.drop (skip input)).head? = some byte ∧ whitespace byte = false := by
  induction input with
  | nil => exact Or.inl rfl
  | cons byte rest ih =>
      cases spaceAt : whitespace byte
      · exact Or.inr ⟨byte, by simp [skip, spaceAt], spaceAt⟩
      · simpa [skip, spaceAt, Nat.add_comm] using ih

theorem advanced_keeps_original_bytes (reader : Reader) : (advanced reader).input = reader.input := rfl

theorem advanced_cursor_bounds (reader : Reader) (valid : Valid reader) :
    reader.position ≤ (advanced reader).position ∧ (advanced reader).position ≤ reader.input.length := by
  have bounded := skip_bound (reader.input.drop reader.position)
  have count : (reader.input.drop reader.position).length = reader.input.length - reader.position := by simp
  unfold advanced
  unfold Valid at valid
  simp only []
  omega

theorem finish_keeps_original_bytes (reader : Reader) : (finish reader).2.input = reader.input := by
  unfold finish
  split <;> rfl

theorem finish_acceptance_exact (reader : Reader) : (finish reader).1 = .ok () ↔
    Valid reader ∧ ∀ byte ∈ reader.input.drop reader.position, whitespace byte = true := by
  by_cases valid : Valid reader
  · have bounded := skip_bound (reader.input.drop reader.position)
    have remaining : (reader.input.drop reader.position).length = reader.input.length - reader.position := by simp
    have full : (advanced reader).position = reader.input.length ↔
        skip (reader.input.drop reader.position) = (reader.input.drop reader.position).length := by
      unfold advanced Valid at *
      simp only [] at *
      omega
    simp [finish, valid, full, skip_complete_exact]
  · simp [finish, valid]

theorem finish_refusal_retains_first_other (reader : Reader) (valid : Valid reader)
    (refused : (finish reader).1 = .error .trailingCharacters) :
    ∃ byte, (reader.input.drop (finish reader).2.position).head? = some byte ∧ whitespace byte = false := by
  have notEmpty : (reader.input.drop (advanced reader).position).head? ≠ none := by
    intro empty
    have ended : reader.input.length ≤ (advanced reader).position := by
      have nil : reader.input.drop (advanced reader).position = [] := List.head?_eq_none_iff.mp empty
      exact List.drop_eq_nil_iff.mp nil
    have bounded := (advanced_cursor_bounds reader valid).2
    have same : (advanced reader).position = reader.input.length := by omega
    simp [finish, valid, same] at refused
  have suffix : reader.input.drop (advanced reader).position =
      (reader.input.drop reader.position).drop (skip (reader.input.drop reader.position)) := by
    simp [advanced, List.drop_drop]
  rcases skip_stops_at_first_other (reader.input.drop reader.position) with ended | stopped
  · exact False.elim (notEmpty (by simpa only [suffix] using ended))
  · simpa [finish, valid, suffix] using stopped

end Auths.Product.JsonDocumentEnd
