import Auths.Crypto.Encoding.Digits
open Aeneas Aeneas.Std
namespace Auths.Crypto.ByteLex

def value (bytes : List Std.U8) : Nat := Nat.ofDigits 256 (bytes.map UScalar.val).reverse

def le : List Std.U8 → List Std.U8 → Bool
  | [], _ => true
  | _ :: _, [] => false
  | left :: restLeft, right :: restRight =>
      if left.val < right.val then true
      else if right.val < left.val then false
      else le restLeft restRight

theorem value_bound (bytes : List Std.U8) : value bytes < 256 ^ bytes.length := by
  have bounded : ∀ byte ∈ (bytes.map UScalar.val).reverse, byte < 256 := by
    intro byte member
    rcases List.mem_map.mp (List.mem_reverse.mp member) with ⟨original, _, rfl⟩
    scalar_tac
  simpa [value] using Auths.Crypto.Encoding.Digits.value_bound (bytes.map UScalar.val).reverse bounded

theorem value_cons (head : Std.U8) (tail : List Std.U8) :
    value (head :: tail) = head.val * 256 ^ tail.length + value tail := by
  simp [value, Nat.ofDigits_append, Nat.mul_comm, Nat.add_comm]

theorem weighted_le_iff (left right tailLeft tailRight place : Nat)
    (positive : 0 < place) (leftBound : tailLeft < place) (rightBound : tailRight < place) :
    left * place + tailLeft ≤ right * place + tailRight ↔
      left < right ∨ left = right ∧ tailLeft ≤ tailRight := by
  by_cases less : left < right
  · have gap := Nat.mul_le_mul_right place (Nat.succ_le_of_lt less)
    simp only [Nat.succ_mul] at gap
    constructor
    · intro _; exact Or.inl less
    · intro _; omega
  · by_cases greater : right < left
    · have gap := Nat.mul_le_mul_right place (Nat.succ_le_of_lt greater)
      simp only [Nat.succ_mul] at gap
      have different : left ≠ right := by omega
      have cannot : ¬ left * place + tailLeft ≤ right * place + tailRight := by omega
      simp [less, different, cannot]
    · have equal : left = right := by omega
      subst right
      simp

theorem le_numeric (left right : List Std.U8) (same : left.length = right.length) :
    le left right = true ↔ value left ≤ value right := by
  induction left generalizing right with
  | nil => cases right <;> simp_all [le, value]
  | cons head tail ih =>
    cases right with
    | nil => simp at same
    | cons other rest =>
      have lengths : tail.length = rest.length := by simpa using same
      rw [value_cons, value_cons, ← lengths]
      rw [weighted_le_iff _ _ _ _ _ (by positivity) (value_bound tail) (lengths ▸ value_bound rest)]
      have tails := ih rest lengths
      by_cases less : head.val < other.val
      · simp [le, less]
      · by_cases greater : other.val < head.val
        · have different : head.val ≠ other.val := by omega
          simp [le, less, greater, different]
        · have equal : head.val = other.val := by omega
          simp [le, less, greater, equal, tails]

end Auths.Crypto.ByteLex
