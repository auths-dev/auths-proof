import qualification.aeneas.generated.signature.Funs
import Auths.Crypto.Strict.CoordinateContract
open Aeneas Aeneas.Std Result
open Auths.Crypto.Encoding.Encoded
namespace Auths.Crypto.WeakContract

def orderEightY : Nat := 55188659117513257062467267217118295137698188065244968500265048394206261417927

def WeakCoordinate (ordinate : Nat) : Prop :=
  ordinate = 0 ∨ ordinate = 1 ∨ ordinate = Encoding.Coordinate.prime - 1 ∨
    ordinate = orderEightY ∨ ordinate = Encoding.Coordinate.prime - orderEightY

instance (ordinate : Nat) : Decidable (WeakCoordinate ordinate) := inferInstanceAs
  (Decidable (ordinate = 0 ∨ ordinate = 1 ∨ ordinate = Encoding.Coordinate.prime - 1 ∨
    ordinate = orderEightY ∨ ordinate = Encoding.Coordinate.prime - orderEightY))

theorem zero_value : ordinate auths_signature_core.ED25519_WEAK_ZERO = 0 := by
  unfold ordinate first middle topValue last auths_signature_core.ED25519_WEAK_ZERO
  decide

theorem one_value : ordinate auths_signature_core.ED25519_WEAK_ONE = 1 := by
  unfold ordinate first middle topValue last auths_signature_core.ED25519_WEAK_ONE
  decide

theorem minus_one_value : ordinate auths_signature_core.ED25519_WEAK_MINUS_ONE = Encoding.Coordinate.prime - 1 := by
  unfold ordinate first middle topValue last auths_signature_core.ED25519_WEAK_MINUS_ONE Encoding.Coordinate.prime
  decide

theorem order_eight_a_value : ordinate auths_signature_core.ED25519_WEAK_ORDER_EIGHT_A = orderEightY := by
  unfold ordinate first middle topValue last auths_signature_core.ED25519_WEAK_ORDER_EIGHT_A orderEightY
  decide

theorem order_eight_b_value : ordinate auths_signature_core.ED25519_WEAK_ORDER_EIGHT_B = Encoding.Coordinate.prime - orderEightY := by
  unfold ordinate first middle topValue last auths_signature_core.ED25519_WEAK_ORDER_EIGHT_B Encoding.Coordinate.prime orderEightY
  decide

theorem guard_refines (input : Input) :
    auths_signature_core.ed25519_has_small_order_coordinate input = ok (decide (WeakCoordinate (ordinate input))) := by
  unfold auths_signature_core.ed25519_has_small_order_coordinate
  simp only [CoordinateContract.guard_refines, zero_value, one_value, minus_one_value,
    order_eight_a_value, order_eight_b_value, bind_tc_ok]
  by_cases zero : ordinate input = 0 <;> by_cases one : ordinate input = 1 <;>
    by_cases minusOne : ordinate input = Encoding.Coordinate.prime - 1 <;>
    by_cases firstEight : ordinate input = orderEightY <;>
    simp [zero, one, minusOne, firstEight, WeakCoordinate]

end Auths.Crypto.WeakContract
