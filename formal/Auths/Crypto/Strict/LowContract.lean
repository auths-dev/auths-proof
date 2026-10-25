import Auths.Crypto.Strict.LowScan
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.LowContract

-- SEC 2 secp256r1 prime subgroup order, as an independent natural number.
def order : Nat := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

theorem half_order_exact : ByteLex.value auths_signature_core.P256_HALF_ORDER.val = order / 2 := by
  unfold ByteLex.value auths_signature_core.P256_HALF_ORDER order
  decide

theorem guard_refines (input : LowScan.Input) :
    auths_signature_core.p256_signature_is_low_s input =
      ok (decide (ByteLex.value (input.val.drop 32) ≤ order / 2)) := by
  obtain ⟨result, executes, meaning⟩ := spec_imp_exists
    (LowScan.loop_refines input 32 0#usize (by scalar_tac))
  have exactSource : auths_signature_core.p256_signature_is_low_s input =
      ok (ByteLex.le (input.val.drop 32) auths_signature_core.P256_HALF_ORDER.val) := by
    simpa only [auths_signature_core.p256_signature_is_low_s, meaning,
      UScalar.ofNatCore_val_eq, Nat.add_zero, List.drop_zero] using executes
  rw [exactSource]
  congr 1
  apply Bool.eq_iff_iff.mpr
  have sizes : (input.val.drop 32).length = auths_signature_core.P256_HALF_ORDER.val.length := by
    simp only [List.length_drop, LowScan.input_length, LowScan.half_length]
  simpa only [half_order_exact, decide_eq_true_eq] using
    ByteLex.le_numeric (input.val.drop 32) auths_signature_core.P256_HALF_ORDER.val sizes

theorem r_bytes_irrelevant (left right : LowScan.Input)
    (sameScalar : left.val.drop 32 = right.val.drop 32) :
    auths_signature_core.p256_signature_is_low_s left = auths_signature_core.p256_signature_is_low_s right := by
  rw [guard_refines, guard_refines, sameScalar]

end Auths.Crypto.LowContract
