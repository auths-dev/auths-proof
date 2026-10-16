import Auths.Crypto.Encoding.Encoded
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Auths.Crypto.Encoding.Encoded Auths.Crypto.Encoding.Coordinate
namespace Auths.Crypto.Encoding.RootFlags

theorem read_first (input : Input) : Array.index_usize input 0#usize = ok (first input) := by
  obtain ⟨byte, executes, same⟩ := spec_imp_exists (Array.index_usize_spec input 0#usize (by scalar_tac))
  have index : (0#usize).val = 0 := by scalar_tac
  simpa only [same, first, index] using executes

theorem read_last (input : Input) : Array.index_usize input 31#usize = ok (last input) := by
  obtain ⟨byte, executes, same⟩ := spec_imp_exists (Array.index_usize_spec input 31#usize (by scalar_tac))
  have index : (31#usize).val = 31 := by scalar_tac
  simpa only [same, last, index] using executes

theorem root_flags (input : Input) :
    auths_signature_core.ed25519_point_encoding_is_canonical_loop
      ⟨1#usize, 31#usize⟩ input
      (decide ((last input &&& 127#u8) = 127#u8)) (decide ((last input &&& 127#u8) = 0#u8))
      ⦃ result => (result.1 = true ↔ upperValue input = upperMaximum) ∧
        (result.2 = true ↔ upperValue input = 0) ⦄ := by
  have run := Auths.Crypto.Encoding.Scan.loop_refines input 30 ⟨1#usize, 31#usize⟩
    (decide ((last input &&& 127#u8) = 127#u8)) (decide ((last input &&& 127#u8) = 0#u8))
    (by scalar_tac) (by scalar_tac)
  apply spec_mono run
  intro result meaning
  change result = Auths.Crypto.Encoding.Scan.scan (middle input) _ _ at meaning
  rw [meaning, Auths.Crypto.Encoding.Flags.scan_flags]
  simp only [Bool.and_eq_true, decide_eq_true_eq, Auths.Crypto.Encoding.Flags.maximum_value,
    Auths.Crypto.Encoding.Flags.zero_value, middle_length]
  have value127 : (127#u8).val = 127 := by scalar_tac
  have value0 : (0#u8).val = 0 := by scalar_tac
  simp only [UScalar.eq_equiv, Auths.Crypto.Encoding.Byte.lower_seven, value127, value0]
  constructor
  · simpa only [upperValue, middleValue, topValue, and_comm] using
      (upper_maximum_iff (middleValue input) (topValue input) (middle_bound input)).symm
  · simpa only [upperValue, middleValue, topValue, and_comm] using
      (upper_zero_iff (middleValue input) (topValue input)).symm

end Auths.Crypto.Encoding.RootFlags
