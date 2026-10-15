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

end qualification.aeneas.cases
