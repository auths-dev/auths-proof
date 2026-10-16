import Aeneas
import Mathlib.Tactic.IntervalCases
open Aeneas Aeneas.Std
namespace Auths.Crypto.Encoding.Byte

theorem lower_seven (byte : Std.U8) : (byte &&& 127#u8).val = byte.val % 128 := by
  rw [UScalar.val_and]
  change byte.val &&& 127 = byte.val % 128
  exact Nat.and_two_pow_sub_one_eq_mod byte.val 7

/-- All 256 cases are checked by the kernel; there is no native-evaluation axiom. -/
theorem sign_bit (byte : Std.U8) :
    ((byte &&& 128#u8) != 0#u8) = decide (128 ≤ byte.val) := by
  apply Bool.eq_iff_iff.mpr
  simp only [bne_iff_ne, ne_eq, UScalar.eq_equiv, UScalar.val_and, decide_eq_true_eq]
  change ¬ (byte.val &&& 128 = 0) ↔ 128 ≤ byte.val
  have bounded : byte.val < 256 := by scalar_tac
  generalize byte.val = value at *
  interval_cases value <;> decide

end Auths.Crypto.Encoding.Byte
