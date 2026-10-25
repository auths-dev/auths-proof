import Auths.Crypto.Strict.CoordinateScan
import Auths.Crypto.Strict.CoordinateModel
import Auths.Crypto.Encoding.RootFlags
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Auths.Crypto.Encoding.Encoded Auths.Crypto.Encoding.RootFlags
namespace Auths.Crypto.CoordinateContract

theorem guard_refines (input expected : Input) :
    auths_signature_core.ed25519_same_coordinate input expected = ok (decide (ordinate input = ordinate expected)) := by
  obtain ⟨result, runs, meaning⟩ := spec_imp_exists
    (CoordinateScan.loop_refines input expected 31 0#usize (by scalar_tac))
  have exactLoop : auths_signature_core.ed25519_same_coordinate_loop input expected 0#usize =
      ok (decide (input.val.take 31 = expected.val.take 31)) := by
    simpa only [meaning, UScalar.ofNatCore_val_eq, List.drop_zero] using runs
  have masks : ((last input &&& 127#u8) = (last expected &&& 127#u8)) ↔
      (last input).val % 128 = (last expected).val % 128 := by
    rw [UScalar.eq_equiv, Auths.Crypto.Encoding.Byte.lower_seven, Auths.Crypto.Encoding.Byte.lower_seven]
  unfold auths_signature_core.ed25519_same_coordinate
  rw [read_last]
  simp only [lift, bind_tc_ok]
  rw [read_last]
  simp only [lift, bind_tc_ok]
  by_cases same : (last input &&& 127#u8) = (last expected &&& 127#u8)
  · simp only [same, bne_self_eq_false, Bool.false_eq_true, ite_false]
    rw [exactLoop]
    congr 1
    apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq, CoordinateModel.ordinate_eq_iff, masks.mp same, and_true]
  · have different : (last input).val % 128 ≠ (last expected).val % 128 := by simpa only [masks] using same
    simp [same, CoordinateModel.ordinate_eq_iff, different]

end Auths.Crypto.CoordinateContract
