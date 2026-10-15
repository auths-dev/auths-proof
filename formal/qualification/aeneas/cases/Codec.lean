import Auths.Codec.Encoder
import Auths.Codec.Refinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open Auths.Codec Auths.Codec.Refinement

namespace qualification.aeneas.cases

private def inlineInput : Slice Std.U8 := ⟨[23#u8], by scalar_tac⟩

-- A useful positive witness runs the translated production reader.
example : auths_codec.cbor.read_head inlineInput 0#usize ⦃ result =>
    ∃ head, result = .Ok head ∧ head.argument.val = 23 ∧ head.next.val = 1 ⦄ := by
  apply spec_mono (read_head_inline inlineInput 0#usize 23#u8 (by rfl) (by decide))
  rintro _ ⟨head, rfl, _, argumentEq, nextEq⟩
  exact ⟨head, rfl, by simpa using argumentEq, by simpa using nextEq⟩

-- Missing input is a typed primitive refusal, including an adversarial cursor.
example : auths_codec.cbor.read_head inlineInput 65535#usize =
    ok (.Err ()) := by
  apply read_head_absent
  simp [inlineInput]

private def truncatedInput : Slice Std.U8 := ⟨[26#u8, 0#u8], by scalar_tac⟩

example : auths_codec.cbor.read_tail truncatedInput 1#usize 4#u8 0#u64
    ⦃ result => result = .Err () ⦄ := by
  apply spec_mono (read_tail_bounded truncatedInput 1#usize 4#u8 (by decide) (by decide))
  intro result contract
  cases result with
  | Err error => cases error; rfl
  | Ok pair =>
    obtain ⟨decoded, next⟩ := pair
    have := contract.1
    simp [truncatedInput] at this

example : auths_codec.cbor.encode_head 8#u8 0#u64 = ok (core.result.Result.Err ()) := rfl

private theorem encoding_case (major : Std.U8) (argument : Std.U64)
    (expected : List Nat) (valid : major.val < 8)
    (bytes : encodeHead ⟨major.val, argument.val⟩ = expected) :
    auths_codec.cbor.encode_head major argument ⦃ result =>
      ∃ output, result = .Ok output ∧ byteList output.val = expected ⦄ := by
  apply spec_mono (Auths.Codec.Refinement.Encoder.encode_head_refines major argument)
  intro result refines
  cases result with
  | Err =>
    simp only [Auths.Codec.Refinement.Encoder.EncodingRefines] at refines
    omega
  | Ok output => exact ⟨output, rfl, refines.2.trans bytes⟩

example : auths_codec.cbor.encode_head 0#u8 23#u64 ⦃ result =>
    ∃ output, result = .Ok output ∧ byteList output.val = [23] ⦄ := by
  apply encoding_case <;> decide

example : auths_codec.cbor.encode_head 7#u8 18446744073709551615#u64 ⦃ result =>
    ∃ output, result = .Ok output ∧
      byteList output.val = [251, 255, 255, 255, 255, 255, 255, 255, 255] ⦄ := by
  apply encoding_case <;> decide

end qualification.aeneas.cases
