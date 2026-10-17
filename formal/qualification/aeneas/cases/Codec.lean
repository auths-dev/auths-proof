import Auths.Crypto.Examples
import Auths.Codec.Examples
import Auths.Codec.ActionValidity
import Auths.Codec.Encoder
import Auths.Codec.String
import Auths.Refinement.Identifier
import Auths.Codec.Refinement
import Auths.Codec.Cursor

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

-- These exercise the exact models used by the full action extraction.
example : alloc.string.String.Insts.CoreConvertFromShared0Str.from
    (toStr "auths" (by change 5 ≤ U32.max; scalar_tac)) = ok "auths" := by
  apply Auths.Codec.StringRefinement.string_copy_exact

example : core.str.converts.from_utf8 (toStr "λ" (by change 2 ≤ U32.max; scalar_tac)) =
    ok (.Ok (toStr "λ" (by change 2 ≤ U32.max; scalar_tac))) := by
  apply Auths.Codec.StringRefinement.utf8_accepts_string

private def overlongUtf8 : Slice Std.U8 := ⟨[192#u8, 128#u8], by scalar_tac⟩

example : core.str.converts.from_utf8 overlongUtf8 = ok (.Err ()) := by
  rfl

private def surrogateUtf8 : Slice Std.U8 := ⟨[237#u8, 160#u8, 128#u8], by scalar_tac⟩

example : core.str.converts.from_utf8 surrogateUtf8 = ok (.Err ()) := by
  rfl

-- Full-object witnesses exercise the same production decoder as the claims.
example : auths_codec.decode.decode_canonical_action
    Auths.Codec.Examples.minimalInput Auths.Codec.Examples.minimalLimits =
      ok (.Ok Auths.Codec.Examples.minimalAction) :=
  Auths.Codec.Examples.minimal_action_accepted

example : auths_codec.decode.decode_canonical_action
    Auths.Codec.Examples.nonminimalIntegerInput Auths.Codec.Examples.minimalLimits =
      ok (.Err auths_codec.error.CodecError.NonCanonical) :=
  Auths.Codec.Examples.nonminimal_integer_refused

example : auths_codec.hash.signing_preimage .Grant
    (toStr "t" (by change 1 ≤ U32.max; scalar_tac)) 1#u16
    (⟨[1#u8], by scalar_tac⟩ : Slice Std.U8) =
      ok (.Ok Auths.Crypto.Examples.minimalPreimage) :=
  Auths.Crypto.Examples.minimal_preimage_exact


-- These cases exercise the translated decoder and its actual cursor. A wide
-- integer consumes its head before narrowing fails; a wrong major/truncated
-- head refuses before committing the cursor.
private def cursorInput (bytes : List Std.U8) (bounded : bytes.length ≤ Usize.max) :
    auths_codec.cbor.Decoder := ⟨⟨bytes, bounded⟩, 0#usize⟩

example : auths_codec.cbor.Decoder.u8 (cursorInput [24#u8, 255#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (some 255, 2) ⦄ := by
  apply spec_mono (Cursor.u8_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

example : auths_codec.cbor.Decoder.u8 (cursorInput [25#u8, 1#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (none, 3) ⦄ := by
  apply spec_mono (Cursor.u8_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  norm_num [Cursor.narrowHead, Cursor.typedHead, cursorInput, byteList,
    readHead, readArgument, unsigned, Option.filter] at meaning
  simpa only [Prod.mk.injEq] using meaning

example : auths_codec.cbor.Decoder.u16
    (cursorInput [26#u8, 0#u8, 1#u8, 0#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (none, 5) ⦄ := by
  apply spec_mono (Cursor.u16_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  norm_num [Cursor.narrowHead, Cursor.typedHead, cursorInput, byteList,
    readHead, readArgument, unsigned, Option.filter] at meaning
  simpa only [Prod.mk.injEq] using meaning

example : auths_codec.cbor.Decoder.u64 (cursorInput [65#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (none, 0) ⦄ := by
  apply spec_mono (Cursor.u64_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

example : auths_codec.cbor.Decoder.u16 (cursorInput [25#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (none, 0) ⦄ := by
  apply spec_mono (Cursor.u16_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

example : auths_codec.cbor.Decoder.null (cursorInput [246#u8] (by scalar_tac))
    ⦃ actual => (Cursor.unitView actual.1, actual.2.position.val) = (true, 1) ⦄ := by
  apply spec_mono (Cursor.null_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

example : auths_codec.cbor.Decoder.null (cursorInput [0#u8] (by scalar_tac))
    ⦃ actual => (Cursor.unitView actual.1, actual.2.position.val) = (false, 0) ⦄ := by
  apply spec_mono (Cursor.null_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

-- A type peek is not a successful parse: this U16 has no payload.
example : auths_codec.cbor.Decoder.datatype (cursorInput [25#u8] (by scalar_tac))
    ⦃ actual => actual = .Ok .U16 ⦄ := by
  apply spec_mono (Cursor.datatype_exact _)
  intro actual meaning
  exact meaning

example : auths_codec.cbor.Decoder.u16 (cursorInput [25#u8] (by scalar_tac))
    ⦃ actual => (Cursor.wordView actual.1, actual.2.position.val) = (none, 0) ⦄ := by
  apply spec_mono (Cursor.u16_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning

example : auths_codec.cbor.Decoder.datatype (cursorInput [95#u8] (by scalar_tac))
    ⦃ actual => actual = .Ok .Other ⦄ := by
  apply spec_mono (Cursor.datatype_exact _)
  intro actual meaning
  exact meaning

-- This helper compares lengths only. Binding the supplied input to the
-- decoder's input is a separate caller obligation, made visible here.
example : auths_codec.decode.ensure_complete
    ⟨⟨[1#u8], by scalar_tac⟩, 1#usize⟩ ⟨[2#u8], by scalar_tac⟩
    ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (Cursor.ensure_complete_exact _ _)
  intro actual meaning
  simpa using meaning

end qualification.aeneas.cases
