import Auths.Codec.CanonicalMatch
import Auths.Codec.CursorBounds
import Auths.Codec.ActionAssurance
import Auths.Codec.AttachmentInverse
import Auths.Codec.SourceFieldRoundtrip
import Auths.Codec.ActionTotal
import Auths.Codec.AttachmentDecodeSafety
import Auths.Codec.WireInverse
import Auths.Codec.ActionEncode
import Auths.Codec.Payload
import Auths.Codec.Collection
import Auths.Codec.Fields
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

-- Source-composed payload and protocol-field cases. These deliberately
-- distinguish borrowed payload success from complete-object canonicality,
-- raw indefinite collection heads from protocol acceptance, and the cursor
-- already consumed before a payload/UTF-8/size refusal.
example : auths_codec.cbor.Decoder.bytes (cursorInput [66#u8, 1#u8, 2#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (some [1, 2], 3) ⦄ := by
  apply spec_mono (Payload.bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.bytes (cursorInput [66#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (none, 1) ⦄ := by
  apply spec_mono (Payload.bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.bytes (cursorInput [64#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (some [], 1) ⦄ := by
  apply spec_mono (Payload.bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.bytes (cursorInput [0#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (none, 0) ⦄ := by
  apply spec_mono (Payload.bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.bytes (cursorInput [91#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (none, 9) ⦄ := by
  apply spec_mono (Payload.bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.str (cursorInput [98#u8, 194#u8, 163#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (some [194, 163], 3) ⦄ := by
  apply spec_mono (Payload.str_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.str (cursorInput [98#u8, 192#u8, 128#u8] (by scalar_tac))
    ⦃ actual => (Payload.bytesView actual.1, actual.2.position.val) = (none, 3) ⦄ := by
  apply spec_mono (Payload.str_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.array (cursorInput [159#u8] (by scalar_tac))
    ⦃ actual => (Collection.collectionView actual.1, actual.2.position.val) = (some none, 1) ⦄ := by
  apply spec_mono (Collection.array_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.map (cursorInput [191#u8] (by scalar_tac))
    ⦃ actual => (Collection.collectionView actual.1, actual.2.position.val) = (some none, 1) ⦄ := by
  apply spec_mono (Collection.map_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.array (cursorInput [130#u8] (by scalar_tac))
    ⦃ actual => (Collection.collectionView actual.1, actual.2.position.val) = (some (some 2), 1) ⦄ := by
  apply spec_mono (Collection.array_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.cbor.Decoder.array (cursorInput [255#u8] (by scalar_tac))
    ⦃ actual => (Collection.collectionView actual.1, actual.2.position.val) = (none, 0) ⦄ := by
  apply spec_mono (Collection.array_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.array (cursorInput [159#u8] (by scalar_tac)) 10#usize
    ⦃ actual => (Fields.sizeView actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (Fields.array_exact _ 10#usize)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.array (cursorInput [130#u8] (by scalar_tac)) 1#usize
    ⦃ actual => (Fields.sizeView actual.1, actual.2.position.val) = (.Err .LimitExceeded, 1) ⦄ := by
  apply spec_mono (Fields.array_exact _ 1#usize)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.array (cursorInput [130#u8] (by scalar_tac)) 2#usize
    ⦃ actual => (Fields.sizeView actual.1, actual.2.position.val) = (.Ok 2, 1) ⦄ := by
  apply spec_mono (Fields.array_exact _ 2#usize)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.map (cursorInput [162#u8] (by scalar_tac)) 2#u64
    ⦃ actual => (actual.1, actual.2.position.val) = (.Ok (), 1) ⦄ := by
  apply spec_mono (Fields.map_exact _ 2#u64)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.map (cursorInput [162#u8] (by scalar_tac)) 3#u64
    ⦃ actual => (actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (Fields.map_exact _ 3#u64)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.map (cursorInput [191#u8] (by scalar_tac)) 2#u64
    ⦃ actual => (actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (Fields.map_exact _ 2#u64)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.key (cursorInput [0#u8] (by scalar_tac)) 1#u8
    ⦃ actual => (actual.1, actual.2.position.val) = (.Err .NonCanonical, 1) ⦄ := by
  apply spec_mono (Fields.key_exact _ 1#u8)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.key (cursorInput [24#u8, 0#u8] (by scalar_tac)) 0#u8
    ⦃ actual => (actual.1, actual.2.position.val) = (.Ok (), 2) ⦄ := by
  apply spec_mono (Fields.key_exact _ 0#u8)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.key (cursorInput [25#u8, 1#u8, 0#u8] (by scalar_tac)) 0#u8
    ⦃ actual => (actual.1, actual.2.position.val) = (.Err .Malformed, 3) ⦄ := by
  apply spec_mono (Fields.key_exact _ 0#u8)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.bounded_bytes (cursorInput [64#u8] (by scalar_tac)) 0#usize false
    ⦃ actual => (Fields.vecView actual.1, actual.2.position.val) = (.Ok [], 1) ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact _ 0#usize false)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.bounded_bytes (cursorInput [64#u8] (by scalar_tac)) 0#usize true
    ⦃ actual => (Fields.vecView actual.1, actual.2.position.val) = (.Err .LimitExceeded, 1) ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact _ 0#usize true)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.bounded_bytes (cursorInput [66#u8, 1#u8, 2#u8] (by scalar_tac)) 1#usize false
    ⦃ actual => (Fields.vecView actual.1, actual.2.position.val) = (.Err .LimitExceeded, 3) ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact _ 1#usize false)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.bounded_bytes (cursorInput [66#u8, 1#u8, 2#u8] (by scalar_tac)) 2#usize true
    ⦃ actual => (Fields.vecView actual.1, actual.2.position.val) = (.Ok [1, 2], 3) ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact _ 2#usize true)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.bounded_bytes (cursorInput [66#u8, 1#u8] (by scalar_tac)) 2#usize false
    ⦃ actual => (Fields.vecView actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact _ 2#usize false)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.digest_bytes (cursorInput ([88#u8, 32#u8] ++ List.replicate 32 0#u8) (by scalar_tac))
    ⦃ actual => (Fields.digestView actual.1, actual.2.position.val) = (.Ok (List.replicate 32 0), 34) ⦄ := by
  apply spec_mono (Fields.digest_bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.digest_bytes (cursorInput ([88#u8, 31#u8] ++ List.replicate 31 0#u8) (by scalar_tac))
    ⦃ actual => (Fields.digestView actual.1, actual.2.position.val) = (.Err .Malformed, 33) ⦄ := by
  apply spec_mono (Fields.digest_bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.digest_bytes (cursorInput ([88#u8, 33#u8] ++ List.replicate 33 0#u8) (by scalar_tac))
    ⦃ actual => (Fields.digestView actual.1, actual.2.position.val) = (.Err .Malformed, 35) ⦄ := by
  apply spec_mono (Fields.digest_bytes_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.is_null (cursorInput [246#u8] (by scalar_tac))
    ⦃ actual => actual = (.Ok true) ⦄ := by
  apply spec_mono (Fields.is_null_exact _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.is_null (cursorInput [25#u8] (by scalar_tac))
    ⦃ actual => actual = (.Ok false) ⦄ := by
  apply spec_mono (Fields.is_null_exact _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.is_null (cursorInput [] (by scalar_tac))
    ⦃ actual => actual = (.Err .Malformed) ⦄ := by
  apply spec_mono (Fields.is_null_exact _)
  intro actual meaning
  exact meaning.trans (by cbv)

-- Object helpers: exact typed refusals, cursor behavior and valid zero budget.

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Ok ([97], 1), 6) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err (.Model .InvalidProfile), 6) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [161#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [191#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .Malformed, 1) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .NonCanonical, 2) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 96#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err (.Model .InvalidProfile), 3) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 32#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err (.Model .InvalidProfile), 4) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 98#u8, 192#u8, 128#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .Malformed, 5) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .Malformed, 5) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 26#u8, 0#u8, 1#u8, 0#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Err .Malformed, 10) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [184#u8, 2#u8, 0#u8, 97#u8, 97#u8, 1#u8, 1#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Ok ([97], 1), 7) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.profile_ref (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 1#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (ProfileDecode.profileView actual.1, actual.2.position.val) = (.Ok ([97], 1), 6) ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.permission (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 97#u8, 98#u8] (by scalar_tac))
    ⦃ actual => (PermissionDecode.permissionView actual.1, actual.2.position.val) = (.Ok ([97], [98]), 7) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.permission (cursorInput [162#u8, 0#u8, 96#u8] (by scalar_tac))
    ⦃ actual => (PermissionDecode.permissionView actual.1, actual.2.position.val) = (.Err (.Model .InvalidCapability), 3) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.permission (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 96#u8] (by scalar_tac))
    ⦃ actual => (PermissionDecode.permissionView actual.1, actual.2.position.val) = (.Err (.Model .InvalidResource), 6) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.permission (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (PermissionDecode.permissionView actual.1, actual.2.position.val) = (.Err .NonCanonical, 5) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.permission (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 98#u8, 237#u8, 160#u8] (by scalar_tac))
    ⦃ actual => (PermissionDecode.permissionView actual.1, actual.2.position.val) = (.Err .Malformed, 8) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.budget (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.budgetView actual.1, actual.2.position.val) = (.Ok ([97], 0), 6) ⦄ := by
  apply spec_mono (BudgetDecode.budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.budget (cursorInput [162#u8, 0#u8, 96#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.budgetView actual.1, actual.2.position.val) = (.Err (.Model .InvalidRegistryId), 3) ⦄ := by
  apply spec_mono (BudgetDecode.budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.budget (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 27#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.budgetView actual.1, actual.2.position.val) = (.Ok ([97], 18446744073709551615), 14) ⦄ := by
  apply spec_mono (BudgetDecode.budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.optional_budget (cursorInput [246#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.optionalView actual.1, actual.2.position.val) = (.Ok none, 1) ⦄ := by
  apply spec_mono (BudgetDecode.optional_budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.optional_budget (cursorInput [162#u8, 0#u8, 97#u8, 97#u8, 1#u8, 0#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.optionalView actual.1, actual.2.position.val) = (.Ok (some ([97], 0)), 6) ⦄ := by
  apply spec_mono (BudgetDecode.optional_budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.optional_budget (cursorInput [] (by scalar_tac))
    ⦃ actual => (BudgetDecode.optionalView actual.1, actual.2.position.val) = (.Err .Malformed, 0) ⦄ := by
  apply spec_mono (BudgetDecode.optional_budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

example : auths_codec.decode.optional_budget (cursorInput [244#u8] (by scalar_tac))
    ⦃ actual => (BudgetDecode.optionalView actual.1, actual.2.position.val) = (.Err .Malformed, 0) ⦄ := by
  apply spec_mono (BudgetDecode.optional_budget_exact _)
  rintro ⟨result, next⟩ ⟨meaning, _⟩
  exact meaning.trans (by cbv)

-- Prefix helpers deliberately allow a suffix. The inverse proof does not
-- accidentally establish standalone acceptance for that suffix.
example : WireInverse.Consumes ProfileDecode.profileAt
    (ObjectEncode.profileEncoding [97] 1) ([97], 1) := by
  apply WireInverse.profile_roundtrip <;> cbv

example : WireInverse.Consumes BudgetDecode.budgetAt
    (ObjectEncode.budgetEncoding [97] 0) ([97], 0) := by
  apply WireInverse.budget_roundtrip <;> cbv

example : WireInverse.Consumes PermissionDecode.permissionAt
    (ObjectEncode.permissionEncoding [97] [98]) ([97], [98]) := by
  apply WireInverse.permission_roundtrip <;> cbv

private def initialEncoder : auths_codec.cbor.Encoder := ⟨alloc.vec.Vec.new Std.U8⟩

example : auths_codec.encode.encode_profile_ref initialEncoder ⟨"a", 1#u16⟩
    ⦃ actual => actual.1 = .Ok () ∧ byteList actual.2.output.val = [162, 0, 97, 97, 1, 1] ⦄ := by
  apply spec_mono (ObjectEncode.profile_exact initialEncoder ⟨"a", 1#u16⟩
    (by cbv; scalar_tac) (by cbv; scalar_tac))
  rintro ⟨result, next⟩ ⟨success, written⟩
  exact ⟨success, written.trans (by cbv)⟩

example : auths_codec.encode.encode_budget initialEncoder ⟨"a", 0#u64⟩
    ⦃ actual => actual.1 = .Ok () ∧ byteList actual.2.output.val = [162, 0, 97, 97, 1, 0] ⦄ := by
  apply spec_mono (ObjectEncode.budget_exact initialEncoder ⟨"a", 0#u64⟩
    (by cbv; scalar_tac) (by cbv; scalar_tac))
  rintro ⟨result, next⟩ ⟨success, written⟩
  exact ⟨success, written.trans (by cbv)⟩

example : auths_codec.encode.encode_optional_budget initialEncoder none
    ⦃ actual => actual.1 = .Ok () ∧ byteList actual.2.output.val = [246] ⦄ := by
  apply spec_mono (ObjectEncode.optional_budget_exact initialEncoder none
    (by simp [ObjectEncode.optionalBudgetStringsBounded]) (by cbv; scalar_tac))
  rintro ⟨result, next⟩ ⟨success, written⟩
  exact ⟨success, written.trans (by cbv)⟩

example : auths_codec.encode.encode_canonical_action Auths.Codec.Examples.minimalAction
    ⦃ actual => ActionEncode.resultView actual = .Ok (byteList Auths.Codec.Examples.minimalInput.val) ⦄ := by
  apply spec_mono (ActionEncode.action_exact Auths.Codec.Examples.minimalAction
    (by constructor <;> cbv <;> scalar_tac) (by cbv; scalar_tac))
  intro actual written
  exact written.trans (by cbv)

private def attachmentLimits : auths_codec.auths_model.VerifierLimits :=
  {Auths.Codec.Examples.minimalLimits with attachments := 3#usize, attachment_bytes := 1#usize}

private def singletonAttachmentInput : Slice Std.U8 :=
  ⟨[162#u8, 0#u8, 88#u8, 32#u8] ++ List.replicate 32 0#u8 ++ [1#u8, 65#u8, 7#u8], by scalar_tac⟩

example : auths_codec.decode.attachment_batch singletonAttachmentInput attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Ok
      ⟨[(List.replicate 32 0, [7])], 1, 39⟩ ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

-- An empty batch consumes no attachment bytes. The outer public decoder
-- must reject a suffix; a zero-count prefix helper does not discard it.
example : auths_codec.decode.attachment_batch singletonAttachmentInput attachmentLimits 0#usize 0#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Ok ⟨[], 0, 0⟩ ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch singletonAttachmentInput attachmentLimits 65535#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .Malformed ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

private def twoAttachmentInput : Slice Std.U8 :=
  ⟨singletonAttachmentInput.val ++ singletonAttachmentInput.val, by scalar_tac⟩

-- Each item fits one byte but their aggregate exceeds the one-byte limit.
example : auths_codec.decode.attachment_batch twoAttachmentInput attachmentLimits 0#usize 2#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .LimitExceeded ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

-- A later loop iteration cannot overwrite the original typed failure.
example : auths_codec.decode.attachment_batch twoAttachmentInput attachmentLimits 0#usize 3#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .LimitExceeded ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch
    (⟨[161#u8], by scalar_tac⟩ : Slice Std.U8) attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .Malformed ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch
    (⟨[162#u8, 1#u8], by scalar_tac⟩ : Slice Std.U8) attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .NonCanonical ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch
    (⟨[162#u8, 0#u8, 88#u8, 31#u8] ++ List.replicate 31 0#u8, by scalar_tac⟩ : Slice Std.U8) attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .Malformed ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch
    (⟨[162#u8, 0#u8, 88#u8, 32#u8] ++ List.replicate 32 0#u8 ++ [1#u8, 64#u8], by scalar_tac⟩ : Slice Std.U8) attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .LimitExceeded ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.attachment_batch
    (⟨[162#u8, 0#u8, 88#u8, 32#u8] ++ List.replicate 32 0#u8 ++ [1#u8, 66#u8, 7#u8], by scalar_tac⟩ : Slice Std.U8) attachmentLimits 0#usize 1#usize
    ⦃ actual => AttachmentDecode.resultView actual = .Err .Malformed ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact _ _ _ _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.auths_model.VerifierLimits.validate Auths.Codec.Examples.minimalLimits
    ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (Limits.validate_exact _)
  intro actual meaning
  exact meaning.trans (by cbv)

-- A relevant-looking action limit cannot make an invalid unrelated context
-- limit disappear from validation of the complete operator record.
example : auths_codec.auths_model.VerifierLimits.validate
    {Auths.Codec.Examples.minimalLimits with context_bytes := 16777217#usize}
    ⦃ actual => actual = .Err .CollectionLimitExceeded ⦄ := by
  apply spec_mono (Limits.validate_exact _)
  intro actual meaning
  exact meaning.trans (by cbv)

example : auths_codec.decode.decode_canonical_action
    Auths.Codec.Examples.minimalInput Auths.Codec.Examples.minimalLimits ⦃ _ => True ⦄ :=
  ActionTotal.decode_total _ _

private def prefixedEncoder : auths_codec.cbor.Encoder := ⟨⟨[7#u8], by scalar_tac⟩⟩

-- These quantify over the real encoder result and pass its actual buffer
-- to the real decoder, starting after the pre-existing output byte.
example : auths_codec.encode.encode_profile_ref prefixedEncoder ⟨"a", 1#u16⟩
    ⦃ encoded => encoded.1 = .Ok () ∧
      auths_codec.decode.profile_ref ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len prefixedEncoder.output⟩
        ⦃ decoded => decoded.1 = .Ok ⟨"a", 1#u16⟩ ∧ decoded.2.position.val = 7 ⦄ ⦄ := by
  simpa [prefixedEncoder, ObjectEncode.profileEncoding, EncoderState.payloadEncoding,
    ProtocolEncode.stringBytes, encodeHead, additionalTag, argumentWidth, bigEndian] using
    SourceFieldRoundtrip.profile_roundtrip prefixedEncoder ⟨"a", 1#u16⟩
      (by cbv) (by cbv; scalar_tac)

example : auths_codec.encode.encode_budget prefixedEncoder ⟨"a", 0#u64⟩
    ⦃ encoded => encoded.1 = .Ok () ∧
      auths_codec.decode.budget ⟨alloc.vec.Vec.deref encoded.2.output, alloc.vec.Vec.len prefixedEncoder.output⟩
        ⦃ decoded => decoded.1 = .Ok ⟨"a", 0#u64⟩ ∧ decoded.2.position.val = 7 ⦄ ⦄ := by
  simpa [prefixedEncoder, ObjectEncode.budgetEncoding, EncoderState.payloadEncoding,
    ProtocolEncode.stringBytes, encodeHead, additionalTag, argumentWidth, bigEndian] using
    SourceFieldRoundtrip.budget_roundtrip prefixedEncoder ⟨"a", 0#u64⟩
      (by cbv) (by cbv; scalar_tac)

private def inverseAttachment : auths_codec.auths_model.DetachedAttachment :=
  ⟨⟨List.replicate 32 0#u8, by simp⟩, ⟨[7#u8], by scalar_tac⟩⟩

example : auths_codec.decode.attachment_batch singletonAttachmentInput attachmentLimits 0#usize 1#usize
    ⦃ actual => ∃ batch, actual = .Ok batch ∧ batch.attachments.val = [inverseAttachment] ∧
      batch.attachment_bytes.val = 1 ∧ batch.position.val = 39 ⦄ := by
  simpa [inverseAttachment, AttachmentResources.byteSum, AttachmentEncode.attachmentsEncoding,
    AttachmentEncode.attachmentEncoding, EncoderState.payloadEncoding, byteList,
    encodeHead, additionalTag, argumentWidth, bigEndian] using
    AttachmentInverse.source_batch_inverse singletonAttachmentInput attachmentLimits 0#usize 1#usize
      [inverseAttachment] [] [] (by cbv) (by rfl) (by rfl)
      (by intro value member; simp [inverseAttachment] at member; subst value; simp)
      (by cbv)

-- Complete native action codec witnesses exercise the actual writer output
-- and actual public reader, including every constructor and final comparison.
example := ActionInverseExamples.minimal_source_roundtrip
example := ActionInverseExamples.zero_budget_source_roundtrip
example := ActionInverseExamples.attached_source_roundtrip

end qualification.aeneas.cases

namespace qualification.aeneas.cases.cursorBounds

private def invalidText : Slice Std.U8 := ⟨[98#u8, 192#u8, 128#u8], by scalar_tac⟩
private def invalidTextStart : auths_codec.cbor.Decoder := ⟨invalidText, 0#usize⟩

-- UTF-8 refusal happens after consuming the payload, so error framing must
-- retain that advanced cursor rather than pretend all errors leave it at zero.
example : auths_codec.decode.text invalidTextStart
    ⦃ actual => Auths.Codec.CursorBounds.Frame invalidTextStart actual.2 ⦄ := by
  apply Auths.Codec.CursorBounds.source_text
  decide

example : auths_codec.decode.text invalidTextStart =
    ok (.Err auths_codec.error.CodecError.Malformed, ⟨invalidText, 3#usize⟩) := by
  cbv

private def wrongMajor : Slice Std.U8 := ⟨[65#u8, 0#u8], by scalar_tac⟩

example : auths_codec.decode.text ⟨wrongMajor, 0#usize⟩ =
    ok (.Err auths_codec.error.CodecError.Malformed, ⟨wrongMajor, 0#usize⟩) := by
  cbv

private def overflowingPayload : Slice Std.U8 :=
  ⟨[91#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8], by scalar_tac⟩

example : auths_codec.decode.bounded_bytes ⟨overflowingPayload, 0#usize⟩ 512#usize true
    ⦃ actual => Auths.Codec.CursorBounds.Frame ⟨overflowingPayload, 0#usize⟩ actual.2 ⦄ := by
  apply Auths.Codec.CursorBounds.source_bounded_bytes
  decide

example : auths_codec.decode.bounded_bytes ⟨overflowingPayload, 0#usize⟩ 512#usize true =
    ok (.Err auths_codec.error.CodecError.Malformed, ⟨overflowingPayload, 9#usize⟩) := by
  cbv

end qualification.aeneas.cases.cursorBounds

namespace qualification.aeneas.cases.canonicalMatch
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec

private def first : Slice Std.U8 := ⟨[1#u8], by scalar_tac⟩
private def same : alloc.vec.Vec Std.U8 := ⟨[1#u8], by scalar_tac⟩
private def other : alloc.vec.Vec Std.U8 := ⟨[2#u8], by scalar_tac⟩

example : canonical.accept first same (7 : Nat) ⦃ result => result = .Ok 7 ⦄ := by
  simpa [first, same] using Auths.Codec.CanonicalMatch.accept_exact first same (7 : Nat)

example : canonical.accept first other (7 : Nat) ⦃ result => result = .Err .NonCanonical ⦄ := by
  simpa [first, other] using Auths.Codec.CanonicalMatch.accept_exact first other (7 : Nat)

example : canonical.accept_with_error first other (7 : Nat) .DigestMismatch
    ⦃ result => result = .Err .DigestMismatch ⦄ := by
  simpa [first, other] using Auths.Codec.CanonicalMatch.with_error_exact first other (7 : Nat) .DigestMismatch

end qualification.aeneas.cases.canonicalMatch
