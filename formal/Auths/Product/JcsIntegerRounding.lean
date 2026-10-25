import Mathlib.Data.Int.Basic
import Lean.Elab.Tactic.Omega

/-!
Independent mathematical integer-to-binary64 rounding specification for the
native i64/u64 input domains used by the pinned JCS formatter before ryu-js
decimal formatting. The arithmetic functions are total outside that domain;
they do not specify native floating overflow there. Precision is 53
bits and ties round to an even significand. This does NOT prove the native
Rust cast, bit representation, ryu formatting or the canonicalizer's code.
The output is the exact integral value of the rounded binary64 number, not
necessarily the integer denoted by its shortest printed decimal string.
-/
namespace Auths.Product.JcsIntegerRounding

def precisionLimit : Nat := 9007199254740992

/-- Grid spacing in the binade of a nonnegative integral input. Recursive
halving gives logarithmic-depth equations without evaluating a large unary
recursion bound in Nat.log2's logical implementation. -/
def quantum (value : Nat) : Nat :=
  if value < precisionLimit then 1 else 2 * quantum (value / 2)
termination_by value
decreasing_by
  have positive : 0 < value := by unfold precisionLimit at *; omega
  exact Nat.div_lt_self positive (by decide)

def magnitude (value : Nat) : Nat :=
  let spacing := quantum value
  let base := value / spacing
  let remainder := value % spacing
  if 2 * remainder < spacing then base * spacing
  else if spacing < 2 * remainder then (base + 1) * spacing
  else if base % 2 = 0 then base * spacing else (base + 1) * spacing

def integer (value : Int) : Int :=
  if value < 0 then -Int.ofNat (magnitude value.natAbs) else Int.ofNat (magnitude value.natAbs)

theorem quantum_positive (value : Nat) : 0 < quantum value := by
  rw [quantum]
  split
  · decide
  · have previous := quantum_positive (value / 2)
    omega
termination_by value
decreasing_by
  have positive : 0 < value := by unfold precisionLimit at *; omega
  exact Nat.div_lt_self positive (by decide)

theorem quantum_one_below_precision (value : Nat) (small : value < precisionLimit) : quantum value = 1 := by
  rw [quantum, if_pos small]

theorem magnitude_exact_below_precision (value : Nat) (small : value < precisionLimit) : magnitude value = value := by
  simp [magnitude, quantum_one_below_precision value small]

theorem magnitude_exact_on_grid (value : Nat) (aligned : value % quantum value = 0) : magnitude value = value := by
  have positive := quantum_positive value
  have roundsDown : 2 * (value % quantum value) < quantum value := by omega
  simp only [magnitude, if_pos roundsDown]
  have divided := Nat.mod_add_div value (quantum value)
  rw [aligned] at divided
  simpa only [Nat.zero_add, Nat.mul_comm] using divided

theorem magnitude_is_grid_multiple (value : Nat) : magnitude value % quantum value = 0 := by
  unfold magnitude
  repeat' split <;> simp [Nat.mul_mod]

theorem integer_exact_in_safe_range (value : Int)
    (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) : integer value = value := by
  have absolute : value.natAbs < precisionLimit := by
    cases value with
    | ofNat magnitude =>
        change magnitude < precisionLimit
        unfold precisionLimit
        omega
    | negSucc magnitude =>
        change magnitude + 1 < precisionLimit
        unfold precisionLimit
        omega
  unfold integer
  simp only [magnitude_exact_below_precision value.natAbs absolute]
  split
  · rename_i negative
    simp [Int.natCast_natAbs, abs_of_neg negative]
  · rename_i nonnegative
    simp [Int.natCast_natAbs, abs_of_nonneg (by omega : 0 ≤ value)]

theorem integer_zero : integer 0 = 0 := by simp [integer, magnitude, quantum, precisionLimit]

end Auths.Product.JcsIntegerRounding
