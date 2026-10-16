import Auths.Verifier.StatusAdequacy
namespace Auths.StatusSelection.Algebra
open Model

theorem maximum_foldl {α : Type} (rows : List α) (value : α → Nat) (initial : Nat) :
    rows.foldl (fun maximum row => max maximum (value row)) initial =
      max initial (rows.foldr (fun row maximum => max (value row) maximum) 0) := by
  induction rows generalizing initial with
  | nil => simp
  | cons row rest ih => simp [ih, Nat.max_assoc]

theorem minimum_foldr_seed {α : Type} (rows : List α) (value : α → Nat) (left right : Nat) :
    rows.foldr (fun row horizon => min (value row) horizon) (min left right) =
      min left (rows.foldr (fun row horizon => min (value row) horizon) right) := by
  induction rows with
  | nil => rfl
  | cons row rest ih => simp [ih, Nat.min_left_comm]

theorem minimum_foldl {α : Type} (rows : List α) (value : α → Nat) (initial : Nat) :
    rows.foldl (fun horizon row => min horizon (value row)) initial =
      rows.foldr (fun row horizon => min (value row) horizon) initial := by
  induction rows generalizing initial with
  | nil => rfl
  | cons row rest ih =>
    simp only [List.foldl_cons, List.foldr_cons, ih]
    rw [Nat.min_comm initial, minimum_foldr_seed]

theorem capped_minimum {Subject : Type} (rows : List (Statement Subject × Nat))
    (cap age : Nat) :
    rows.foldr (fun pair horizon => min (min cap (deadline age pair.1.observed pair.1.expiresAt)) horizon) cap =
      rows.foldr (fun pair horizon => min (deadline age pair.1.observed pair.1.expiresAt) horizon) cap := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
    simp only [List.foldr_cons]
    rw [ih, Nat.min_assoc, Nat.min_left_comm cap]
    rw [← minimum_foldr_seed rest (fun pair => deadline age pair.1.observed pair.1.expiresAt) cap cap]
    simp only [Nat.min_self]

end Auths.StatusSelection.Algebra
