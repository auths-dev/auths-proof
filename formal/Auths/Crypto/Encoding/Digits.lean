import Aeneas
import Mathlib.Data.Nat.Digits.Defs
namespace Auths.Crypto.Encoding.Digits
set_option maxHeartbeats 2000000

theorem maximum_digits (length : Nat) :
    Nat.ofDigits 256 (List.replicate length 255) = 256 ^ length - 1 := by
  induction length with
  | zero => simp
  | succ length ih =>
    have positive : 0 < 256 ^ length := Nat.pow_pos (by decide)
    simp only [List.replicate_succ, Nat.ofDigits_cons, ih, Nat.pow_succ]
    omega

theorem value_bound (digits : List Nat) (bounded : ∀ byte ∈ digits, byte < 256) :
    Nat.ofDigits 256 digits < 256 ^ digits.length :=
  Nat.ofDigits_lt_base_pow_length (by decide) bounded

theorem maximum_iff (digits : List Nat) (bounded : ∀ byte ∈ digits, byte < 256) :
    Nat.ofDigits 256 digits = 256 ^ digits.length - 1 ↔
      digits = List.replicate digits.length 255 := by
  rw [← maximum_digits]
  constructor
  · exact Nat.ofDigits_inj_of_len_eq (by decide) (by simp) bounded
      (by intro byte member; simp only [List.mem_replicate] at member; omega)
  · exact congrArg (Nat.ofDigits 256)


theorem zero_iff (digits : List Nat) (bounded : ∀ byte ∈ digits, byte < 256) :
    Nat.ofDigits 256 digits = 0 ↔ digits = List.replicate digits.length 0 := by
  nth_rw 1 [← Nat.ofDigits_replicate_zero (b := 256) (k := digits.length)]
  constructor
  · exact Nat.ofDigits_inj_of_len_eq (by decide) (by simp) bounded
      (by intro byte member; simp only [List.mem_replicate] at member; omega)
  · exact congrArg (Nat.ofDigits 256)


end Auths.Crypto.Encoding.Digits
