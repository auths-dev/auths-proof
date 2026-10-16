import Auths.Crypto.Encoding.RootFlags
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Auths.Crypto.Encoding.Encoded Auths.Crypto.Encoding.Coordinate Auths.Crypto.Encoding.RootFlags
namespace Auths.Crypto.Encoding.Ed25519
set_option maxHeartbeats 2000000

theorem guard_refines (input : Input) :
    auths_signature_core.ed25519_point_encoding_is_canonical input = ok (decide (Encoding input)) := by
  suffices contract : auths_signature_core.ed25519_point_encoding_is_canonical input
      ⦃ result => result = decide (Encoding input) ⦄ by
    obtain ⟨result, executes, rfl⟩ := spec_imp_exists contract
    exact executes
  unfold auths_signature_core.ed25519_point_encoding_is_canonical
  rw [read_last]
  simp only [lift, bind_tc_ok]
  apply spec_bind (root_flags input)
  rintro ⟨maximum, zero⟩ ⟨maximumMeaning, zeroMeaning⟩
  simp only [uncurry, read_first, read_last, lift, bind_tc_ok, Auths.Crypto.Encoding.Byte.sign_bit]
  have firstBound : (first input).val < 256 := by scalar_tac
  have topBound : topValue input < 128 := Nat.mod_lt _ (by decide)
  have upperBound : upperValue input ≤ upperMaximum :=
    Auths.Crypto.Encoding.Coordinate.upper_bound (middleValue input) (topValue input)
      (middle_bound input) topBound
  have semantic : Encoding input ↔
      ¬ (maximum = true ∧ 237 ≤ (first input).val) ∧
      ¬ (128 ≤ (last input).val ∧ ((zero = true ∧ (first input).val = 1) ∨
        (maximum = true ∧ (first input).val = 236))) := by
    unfold Auths.Crypto.Encoding.Encoded.Encoding
    rw [ordinate_frame, Auths.Crypto.Encoding.Coordinate.encoding_criterion _ _ _ firstBound upperBound]
    rw [← maximumMeaning, ← zeroMeaning]
  have v237 : (237#u8).val = 237 := by scalar_tac
  have v236 : (236#u8).val = 236 := by scalar_tac
  have v1 : (1#u8).val = 1 := by scalar_tac
  cases maximum <;> cases zero <;>
    simp only [Bool.false_eq_true, ↓reduceIte]
  all_goals
    repeat' first
      | split
      | simp_all (failIfUnchanged := true) [spec_ok, UScalar.eq_equiv, UScalar.le_equiv]

end Auths.Crypto.Encoding.Ed25519
