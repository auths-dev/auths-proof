import Auths.Crypto.Encoding.Digits
namespace Auths.Crypto.Encoding.Coordinate
set_option maxHeartbeats 2000000

def prime : Nat := 2 ^ 255 - 19

def upperMaximum : Nat := 128 * 256 ^ 30 - 1

theorem prime_frame : prime = 256 * upperMaximum + 237 := by decide

theorem upper_bound (middle top : Nat) (middleBound : middle < 256 ^ 30) (topBound : top < 128) :
    middle + 256 ^ 30 * top ≤ upperMaximum := by
  norm_num only [upperMaximum, Nat.reducePow, Nat.reduceMul, Nat.reduceSub] at *
  omega

theorem upper_maximum_iff (middle top : Nat) (middleBound : middle < 256 ^ 30) :
    middle + 256 ^ 30 * top = upperMaximum ↔ middle = 256 ^ 30 - 1 ∧ top = 127 := by
  norm_num only [upperMaximum, Nat.reducePow, Nat.reduceMul, Nat.reduceSub] at *
  omega

theorem upper_zero_iff (middle top : Nat) :
    middle + 256 ^ 30 * top = 0 ↔ middle = 0 ∧ top = 0 := by
  norm_num only [Nat.reducePow]
  omega

theorem field_iff (first upper : Nat) (firstBound : first < 256) (upperBound : upper ≤ upperMaximum) :
    first + 256 * upper < prime ↔ ¬ (upper = upperMaximum ∧ 237 ≤ first) := by
  rw [prime_frame]
  omega

theorem identity_iff (first upper : Nat) (firstBound : first < 256) :
    first + 256 * upper = 1 ↔ first = 1 ∧ upper = 0 := by omega

theorem order_two_iff (first upper : Nat) (firstBound : first < 256) :
    first + 256 * upper = prime - 1 ↔ first = 236 ∧ upper = upperMaximum := by
  rw [prime_frame]
  omega

/-- RFC 8032's field range and negative-zero restrictions, independently
    stated on the decoded ordinate and the sign bit. Curve validity is separate. -/
def Encoding (ordinate : Nat) (negative : Prop) : Prop :=
  ordinate < prime ∧ (negative → ordinate ≠ 1 ∧ ordinate ≠ prime - 1)

theorem encoding_criterion (first upper : Nat) (negative : Prop)
    (firstBound : first < 256) (upperBound : upper ≤ upperMaximum) :
    Encoding (first + 256 * upper) negative ↔
      ¬ (upper = upperMaximum ∧ 237 ≤ first) ∧
        ¬ (negative ∧ ((upper = 0 ∧ first = 1) ∨ (upper = upperMaximum ∧ first = 236))) := by
  simp only [Encoding, ne_eq, field_iff first upper firstBound upperBound,
    identity_iff first upper firstBound, order_two_iff first upper firstBound]
  tauto

end Auths.Crypto.Encoding.Coordinate
