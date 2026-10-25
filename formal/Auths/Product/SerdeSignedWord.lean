import Auths.Product.JsonNumberPlan

/-!
Closed two's-complement mathematics for serde's original u64 significand,
i64 cast and wrapping negation. The single-wrap function is used only on
the earned negated-cast range and is compared to full modulo-2^64 signed
interpretation. Floating fallback retains the original UNSIGNED magnitude,
not the wrapped signed result. Native cast/wrapping/f64 primitive adequacy
and parser/visitor call correspondence remain outer obligations.
-/
namespace Auths.Product.SerdeSignedWord

def word : Int := 18446744073709551616
def half : Int := 9223372036854775808

def signedCast (value : Nat) : Int :=
  if value < 9223372036854775808 then Int.ofNat value else Int.ofNat value - word

def singleWrap (value : Int) : Int :=
  if value < -half then value + word else if half ≤ value then value - word else value

def wrappingNegation (value : Nat) : Int := singleWrap (-signedCast value)

def modularSigned (value : Int) : Int :=
  let bits := value % word
  if bits < half then bits else bits - word

theorem original_unsigned_cast_has_signed_range (value : Nat) (bounded : value ≤ 18446744073709551615) :
    -9223372036854775808 ≤ signedCast value ∧ signedCast value ≤ 9223372036854775807 := by
  unfold signedCast word
  split <;> omega

theorem wrapping_negation_matches_modular_word (value : Nat) (bounded : value ≤ 18446744073709551615) :
    wrappingNegation value = modularSigned (-signedCast value) := by
  have castRange := original_unsigned_cast_has_signed_range value bounded
  unfold wrappingNegation singleWrap modularSigned word half
  repeat' split <;> omega

theorem lower_half_negation_keeps_original_magnitude (value : Nat) (lower : value < 9223372036854775808) :
    wrappingNegation value = -Int.ofNat value := by
  unfold wrappingNegation signedCast singleWrap word half
  rw [if_pos lower]
  repeat' split <;> omega

theorem minimum_signed_word_wraps_to_itself : wrappingNegation 9223372036854775808 = -9223372036854775808 := by decide

theorem upper_half_negation_keeps_wrapped_residue (value : Nat)
    (bounded : 9223372036854775808 < value ∧ value ≤ 18446744073709551615) :
    wrappingNegation value = word - Int.ofNat value := by
  unfold wrappingNegation signedCast singleWrap word half
  rw [if_neg (by omega : ¬ value < 9223372036854775808)]
  repeat' split <;> omega

theorem negative_branch_is_exact_original_domain (value : Nat) (bounded : value ≤ 18446744073709551615) :
    wrappingNegation value < 0 ↔ 0 < value ∧ value ≤ 9223372036854775808 := by
  by_cases lower : value < 9223372036854775808
  · rw [lower_half_negation_keeps_original_magnitude value lower]
    omega
  · by_cases middle : value = 9223372036854775808
    · subst value
      rw [minimum_signed_word_wraps_to_itself]
      decide
    · rw [upper_half_negation_keeps_wrapped_residue value ⟨by omega, bounded⟩]
      unfold word
      omega

theorem negative_branch_keeps_original_integer (value : Nat)
    (bounded : 0 < value ∧ value ≤ 9223372036854775808) : wrappingNegation value = -Int.ofNat value := by
  by_cases lower : value < 9223372036854775808
  · exact lower_half_negation_keeps_original_magnitude value lower
  · have same : value = 9223372036854775808 := by omega
    subst value
    exact minimum_signed_word_wraps_to_itself

inductive Decision where
  | signed (value : Int)
  | floatingMagnitude (original : Nat)
  deriving DecidableEq

def dispatch (original : Nat) : Decision :=
  let negative := wrappingNegation original
  if negative < 0 then .signed negative else .floatingMagnitude original

def plan (originalToken : List Nat) : Decision → JsonNumberPlan.Plan
  | .signed value => .signed value
  | .floatingMagnitude _ => .floating originalToken

theorem dispatch_signed_exact (original : Nat) (bounded : original ≤ 18446744073709551615)
    (accepted : 0 < original ∧ original ≤ 9223372036854775808) : dispatch original = .signed (-Int.ofNat original) := by
  unfold dispatch
  rw [if_pos ((negative_branch_is_exact_original_domain original bounded).mpr accepted),
    negative_branch_keeps_original_integer original accepted]

theorem dispatch_floating_keeps_unsigned_magnitude (original value : Nat)
    (selected : dispatch original = .floatingMagnitude value) : value = original := by
  unfold dispatch at selected
  split at selected
  · cases selected
  · cases selected; rfl

theorem floating_branch_is_zero_or_signed_underflow (original : Nat) (bounded : original ≤ 18446744073709551615) :
    dispatch original = .floatingMagnitude original ↔ original = 0 ∨ 9223372036854775808 < original := by
  unfold dispatch
  rw [negative_branch_is_exact_original_domain original bounded]
  split <;> simp_all <;> omega

theorem original_negative_token_dispatch_matches_preparation (input : List Nat) (original : Nat)
    (minus : input.head? = some 45) (read : JcsIntegerDecimal.readUnsigned input.tail = some original)
    (bounded : original ≤ 18446744073709551615) : plan input (dispatch original) = JsonNumberPlan.classify input := by
  by_cases accepted : 0 < original ∧ original ≤ 9223372036854775808
  · rw [dispatch_signed_exact original bounded accepted]
    simp [plan, JsonNumberPlan.classify, minus, read, accepted]
  · have floating : dispatch original = .floatingMagnitude original :=
      (floating_branch_is_zero_or_signed_underflow original bounded).mpr (by omega)
    rw [floating]
    simp [plan, JsonNumberPlan.classify, minus, read, accepted]

theorem original_negative_word_dispatch_matches_preparation (original : Nat) (bounded : original ≤ 18446744073709551615) :
    plan (45 :: JcsIntegerDecimal.unsigned original) (dispatch original) =
      JsonNumberPlan.classify (45 :: JcsIntegerDecimal.unsigned original) :=
  original_negative_token_dispatch_matches_preparation _ original rfl
    (by simpa only [List.tail_cons] using JcsIntegerDecimal.unsigned_roundtrip original) bounded

end Auths.Product.SerdeSignedWord
