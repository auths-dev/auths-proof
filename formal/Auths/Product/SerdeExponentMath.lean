import Auths.Product.SerdeExponentDigits

/-!
Exact mathematical saturation for the native starting_exp.saturating_add/sub
continuation. These laws do not identify native i32 primitives with the model;
that binding remains an ordinary-library/primitive adequacy obligation.
-/
namespace Auths.Product.SerdeExponentMath

def clamp (value : Int) : Int := max (-2147483648) (min 2147483647 value)
def combine (starting : Int) (positiveExponent : Bool) (magnitude : Nat) : Int :=
  clamp (if positiveExponent then starting + Int.ofNat magnitude else starting - Int.ofNat magnitude)

theorem clamped_exponent_has_i32_range (value : Int) : -2147483648 ≤ clamp value ∧ clamp value ≤ 2147483647 := by
  unfold clamp
  omega

theorem in_range_exponent_is_unchanged (value : Int) (bounded : -2147483648 ≤ value ∧ value ≤ 2147483647) : clamp value = value := by
  unfold clamp
  omega

theorem positive_exponent_saturates_at_maximum (starting : Int) (magnitude : Nat)
    (bounded : -2147483648 ≤ starting) (overflowed : 2147483647 < starting + Int.ofNat magnitude) :
    combine starting true magnitude = 2147483647 := by
  unfold combine clamp
  simp only [↓reduceIte]
  omega

theorem negative_exponent_saturates_at_minimum (starting : Int) (magnitude : Nat)
    (bounded : starting ≤ 2147483647) (underflowed : starting - Int.ofNat magnitude < -2147483648) :
    combine starting false magnitude = -2147483648 := by
  unfold combine clamp
  simp only [Bool.false_eq_true, ↓reduceIte]
  omega

theorem combined_exponent_always_has_i32_range (starting : Int) (positiveExponent : Bool) (magnitude : Nat) :
    -2147483648 ≤ combine starting positiveExponent magnitude ∧ combine starting positiveExponent magnitude ≤ 2147483647 :=
  clamped_exponent_has_i32_range _

end Auths.Product.SerdeExponentMath
